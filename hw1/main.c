#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <regex.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

const char row_format[] = "%-5s %-23s %-23s %s\n";
const char _column0[] = "Proto";
const char _column1[] = "Local Address";
const char _column2[] = "Foreign Address";
const char _column3[] = "PID/Program name and arguments";

void fatal(const char *format, ...) {
    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
    exit(2);
}

#define DECL_ARRAY(elementType, arrayType, initialLength)                      \
    struct arrayType {                                                         \
        struct elementType *data;                                              \
        size_t length;                                                         \
        size_t allocatedLength;                                                \
    };                                                                         \
    struct arrayType arrayType##New() {                                        \
        struct arrayType r = {                                                 \
            malloc(sizeof(struct elementType) * initialLength), 0,             \
            initialLength};                                                    \
        if (!r.data)                                                           \
            fatal("cannot allocate memory for " #arrayType "\n");              \
        return r;                                                              \
    }                                                                          \
    struct elementType *arrayType##Append(struct arrayType *self) {            \
        if (self->length == self->allocatedLength) {                           \
            self->allocatedLength *= 2;                                        \
            self->data = realloc(self->data, sizeof(struct Process) *          \
                                                 self->allocatedLength);       \
            if (!self->data) {                                                 \
                fatal("cannot allocate memory for" #arrayType "\n");           \
            }                                                                  \
        }                                                                      \
        return &self->data[self->length++];                                    \
    }

struct Process {
    int pid;
    char cmdline[4096];
};

DECL_ARRAY(Process, ProcessArray, 128)

struct InodeProcEntry {
    int inode;
    int processIndex;
};

DECL_ARRAY(InodeProcEntry, InodeProcMap, 128)

// skips 1 line
// returns 1 on unexpected EOF
int skipline(FILE *file) {
    char c;
    while ((c = fgetc(file)) != EOF) {
        if (c == '\n') {
            return 0;
        }
    }
    return 1;
}

void h2b(unsigned char *out, const char *in, int outlen) {
    for (int i = 0; i < outlen; i += 4) {
        sscanf(in + i * 2, "%2hhx%2hhx%2hhx%2hhx", out + i, out + i + 1,
               out + i + 2, out + i + 3);
        *(uint32_t *)(out + i) = htonl(*(uint32_t *)(out + i));
    }
}

#define ADDR_AND_PORT_LEN (INET6_ADDRSTRLEN + 6)
// ":65536": 1 + 5 = 6
// (null): 1
void format_address(char out[ADDR_AND_PORT_LEN], const char *hexaddr, int port,
                    int af) {
    unsigned char binaddr[16];
    h2b(binaddr, hexaddr, af == AF_INET ? 4 : 16);
    char txtaddr[INET6_ADDRSTRLEN];
    const char *p = inet_ntop(af, binaddr, txtaddr, INET6_ADDRSTRLEN);
    if (!p) {
        fatal("cannot convert address %s to text: %s\n", hexaddr,
              strerror(errno));
    }
    snprintf(out, ADDR_AND_PORT_LEN, "%s:%d", txtaddr, port);
}

void process_family(const char *family, int af, struct ProcessArray pa,
                    struct InodeProcMap inodeMap, int filter,
                    const regex_t *filter_regex) {
    char filename[] = "/proc/net/tcp6";
    strncpy(filename + 10, family, 4);
    FILE *file = fopen(filename, "r");
    if (!file) {
        fatal("error opening %s\n", filename);
    }
    if (skipline(file)) {
        fatal("unexpected EOF processing %s\n", filename);
    }
    char local_addr[40];
    int local_port;
    char remote_addr[40];
    int remote_port;
    int inode;
    while (
        fscanf(file,
               "%*s %[0-9A-Fa-f]:%x %[0-9A-Fa-f]:%x %*s %*s %*s %*s %*d %*d %d",
               local_addr, &local_port, remote_addr, &remote_port,
               &inode) != EOF) {
        if (skipline(file)) {
            fatal("unexpected EOF processing %s\n", filename);
        }
        char fla[ADDR_AND_PORT_LEN];
        char fra[ADDR_AND_PORT_LEN];
        format_address(fla, local_addr, local_port, af);
        format_address(fra, remote_addr, remote_port, af);
        int processIndex = -1;
        for (int i = 0; i < inodeMap.length; i++) {
            if (inodeMap.data[i].inode == inode) {
                processIndex = inodeMap.data[i].processIndex;
                break;
            }
        }
        char processInfo[4096 + 5] = "-";
        if (processIndex != -1) {
            snprintf(processInfo, sizeof(processInfo) - 1, "%d/%s",
                     pa.data[processIndex].pid, pa.data[processIndex].cmdline);
        }
        printf(row_format, family, fla, fra, processInfo);
    }
    fclose(file);
}

int main(int argc, char **argv) {
    regex_t sock_regexs[2];
    if (regcomp(&sock_regexs[0], "socket:\\[([0-9]+)\\]", REG_EXTENDED)) {
        fatal("failed to compile regular expression");
    }
    if (regcomp(&sock_regexs[1], "\\[0000\\]:([0-9]+)", REG_EXTENDED)) {
        fatal("failed to compile regular expression");
    }

    regex_t filter_regex;
    int filter = 0;

    struct InodeProcMap inodes = InodeProcMapNew();
    struct ProcessArray processes = ProcessArrayNew();

    DIR *dir = opendir("/proc");
    if (!dir) {
        fatal("failed to open /proc: %s\n", strerror(errno));
    }
    struct dirent *ent;
    while ((ent = readdir(dir))) {
        for (char *c = ent->d_name; *c; c++) {
            if (!isdigit(*c))
                goto nextpid;
        }

        int pid = atoi(ent->d_name);

        int hasOpenSocket = 0;

        char pidpath[32];
        snprintf(pidpath, 31, "/proc/%d/fd", pid);
        DIR *piddir = opendir(pidpath);
        if (!piddir)
            goto nextpid;
        struct dirent *fdent;
        int pidfd = open(pidpath, O_DIRECTORY);
        if (pidfd == -1)
            goto nextpid;
        while ((fdent = readdir(piddir))) {
            char fdlink[32];
            ssize_t linklen;
            if ((linklen = readlinkat(pidfd, fdent->d_name, fdlink, 31)) ==
                -1) {
                continue;
            }
            fdlink[linklen] = 0;
            regmatch_t match[2];
            int regerr = regexec(&sock_regexs[0], fdlink, 2, match, 0);
            if (regerr)
                regexec(&sock_regexs[1], fdlink, 2, match, 0);
            if (regerr)
                continue;
            fdlink[match[1].rm_eo] = 0;
            hasOpenSocket = 1;
            struct InodeProcEntry *inodeent = InodeProcMapAppend(&inodes);
            inodeent->inode = atoi(fdlink + match[1].rm_so);
            inodeent->processIndex = processes.length;
        }
        if (hasOpenSocket) {
            struct Process *proc = ProcessArrayAppend(&processes);
            proc->pid = pid;
            memcpy(proc->cmdline, "-", 2);
        }
        closedir(piddir);
    nextpid:;
    }
    closedir(dir);

    puts("List of TCP connections:");
    printf(row_format, _column0, _column1, _column2, _column3);
    process_family("tcp", AF_INET, processes, inodes, filter, &filter_regex);
    process_family("tcp6", AF_INET6, processes, inodes, filter, &filter_regex);
    putchar('\n');
    puts("List of UDP connections:");
    printf(row_format, _column0, _column1, _column2, _column3);
    process_family("udp", AF_INET, processes, inodes, filter, &filter_regex);
    process_family("udp6", AF_INET6, processes, inodes, filter, &filter_regex);
}
