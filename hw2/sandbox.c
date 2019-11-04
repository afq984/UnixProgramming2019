#include <asm-generic/errno-base.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>

static int eprintf(const char *fmt, ...) {
    static int fd;
    if (!fd) {
        fd = open("/dev/tty", O_WRONLY);
        if (fd == -1) {
            fd = 2;
            dprintf(2, "failed to open /dev/tty, falling back to fd 2.");
        }
    }
    va_list ap;
    va_start(ap, fmt);
    int r = vdprintf(fd, fmt, ap);
    va_end(ap);
    return r;
}

int execve(const char *file, char *const argv[], char* const envp[]) {
    eprintf("[sandbox] execve(%s): not allowed\n", file);
    errno = EACCES;
    return -1;
}
