#include <assert.h>
#include <cstdlib>
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <stdexcept>

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

static const char *basedir;
static int basedir_len;

static int validate(const char *hint, const char *path) {
    char resolved_path[PATH_MAX];
    if (realpath(path, resolved_path)) {
        if (strncmp(basedir, resolved_path, basedir_len)) {
            if (strcmp(path, resolved_path)) {
                eprintf("[sandbox] %s: access to %s -> %s is not allowed\n",
                        hint, path, resolved_path);
            } else {
                eprintf("[sandbox] %s: access to %s is not allowed\n", hint, path);
            }
            errno = EACCES;
            return -1;
        }
        return 0;
    }
    eprintf("[sandbox] %s: could not resolve %s\n", hint, path);
    return -1;
}

static void *findfunc(const char *name) {
    void *f = dlsym(RTLD_NEXT, name);
    if (!f) {
        char str[128];
        eprintf("dlsym(%s) failed: %s", name, dlerror());
    }
    return f;
}

__attribute__((constructor)) static void init() {
    basedir = strdup(getenv("SANDBOX_BASEDIR"));
    basedir_len = strlen(basedir);
    eprintf("using basedir: %s\n", basedir);
}

#define declfunc(name)                                                         \
    decltype(&name) libc_##name =                                              \
        reinterpret_cast<decltype(&name)>(findfunc(#name))

declfunc(chdir);
declfunc(chmod);
declfunc(chown);
declfunc(creat);
declfunc(fopen);
declfunc(link);
declfunc(mkdir);
declfunc(open);
declfunc(openat);
declfunc(opendir);
declfunc(readlink);
declfunc(remove);
declfunc(rename);
declfunc(rmdir);
declfunc(__xstat);
declfunc(symlink);
declfunc(unlink);
declfunc(creat64);
declfunc(fopen64);
declfunc(open64);
declfunc(openat64);
declfunc(__xstat64);

extern "C" {

int execve(const char *file, char *const argv[], char *const envp[]) {
    eprintf("[sandbox] execve(%s): not allowed\n", file);
    errno = EACCES;
    return -1;
}

int chdir(const char *path) {
    if (validate(__func__, path)) {
        return -1;
    }
    return libc_chdir(path);
}

int chmod(const char* path, mode_t mode) {
    if (validate(__func__, path)) {
        return -1;
    }
    return libc_chmod(path, mode);
}

int chown(const char* path, uid_t owner, gid_t group) {
    if (validate(__func__, path)) {
        return -1;
    }
    return libc_chown(path, owner, group);
}
}
