#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char row_format[] = "%-5s %-23s %-23s %s\n";
const char _column0[] = "Proto";
const char _column1[] = "Local Address";
const char _column2[] = "Foreign Address";
const char _column3[] = "PID/Program name and arguments";

struct Connection {
    int inode;
    struct Process *proc;
};

struct Process {
    int pid;
    char *exe;
    char *cmdline;
};

void fatal(const char *format, ...) {
    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
    exit(2);
}

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

void format_address(char out[45], const char *addr, int port) {
    snprintf(out, 45, "%s:%d", addr, port);
}

void process_family(const char *family) {
    char filename[] = "/proc/net/tcp6";
    strncpy(filename + 10, family, 4);
    FILE *file = fopen(filename, "r");
    if (!file) {
        fatal("error opening %s", filename);
    }
    if (skipline(file)) {
        fatal("unexpected EOF processing %s", filename);
    }
    char local_addr[33];
    int local_port;
    char remote_addr[33];
    int remote_port;
    int inode;
    while (
        fscanf(file,
               "%*s %[0-9A-Fa-f]:%x %[0-9A-Fa-f]:%x %*s %*s %*s %*s %*d %*d %d",
               local_addr, &local_port, remote_addr, &remote_port,
               &inode) != EOF) {
        if (skipline(file)) {
            fatal("unexpected EOF processing %s", filename);
        }
        char fla[45];
        char fra[45];
        format_address(fla, local_addr, local_port);
        format_address(fra, remote_addr, remote_port);
        printf(row_format, family, fla, fra, "?/?");
    }
    fclose(file);
}

int main(int argc, char **argv) {
    puts("List of TCP connections:");
    printf(row_format, _column0, _column1, _column2, _column3);
    process_family("tcp");
    process_family("tcp6");
    putchar('\n');
    puts("List of UDP connections:");
    printf(row_format, _column0, _column1, _column2, _column3);
    process_family("udp");
    process_family("udp6");
}
