#include <arpa/inet.h>
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

void process_family(const char *family, int af) {
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
        printf(row_format, family, fla, fra, "?/?");
    }
    fclose(file);
}

int main(int argc, char **argv) {
    puts("List of TCP connections:");
    printf(row_format, _column0, _column1, _column2, _column3);
    process_family("tcp", AF_INET);
    process_family("tcp6", AF_INET6);
    putchar('\n');
    puts("List of UDP connections:");
    printf(row_format, _column0, _column1, _column2, _column3);
    process_family("udp", AF_INET);
    process_family("udp6", AF_INET6);
}
