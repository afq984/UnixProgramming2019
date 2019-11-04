#include <assert.h>
#include <cstdlib>
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
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

static int deny1(const char *hint, const char *path) {
    int oerrno = errno;
    char resolved_path[PATH_MAX];
    if (realpath(path, resolved_path)) {
        if (strncmp(basedir, resolved_path, basedir_len)) {
            if (strcmp(path, resolved_path)) {
                eprintf("[sandbox] %s: access to %s -> %s is not allowed\n",
                        hint, path, resolved_path);
            } else {
                eprintf("[sandbox] %s: access to %s is not allowed\n", hint,
                        path);
            }
            errno = EACCES;
            return -1;
        }
        errno = oerrno;
        return 0;
    }
    if (errno == ENOENT) {
        // I think this may trigger SIGSEGV...
        const char *base = basename(strdupa(path));
        const char *dir = dirname(strdupa(path));
        if (realpath(dir, resolved_path)) {
            if (strncmp(basedir, resolved_path, basedir_len)) {
                if (strcmp(dir, resolved_path)) {
                    eprintf("[sandbox] %s: access to %s -> %s/%s is not "
                            "allowed\n",
                            hint, path, resolved_path, base);
                } else {
                    eprintf("[sandbox] %s: access to %s is not allowed\n", hint,
                            path);
                }
                errno = EACCES;
                return -1;
            } else {
                errno = oerrno;
                return 0;
            }
        }
    }
    eprintf("[sandbox] %s: could not resolve %s\n", hint, path);
    return -1;
}

#define deny(name) deny1(__func__, name)

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

#define libc_decl(name)                                                        \
    decltype(&name) libc_##name =                                              \
        reinterpret_cast<decltype(&name)>(findfunc(#name))

libc_decl(chdir);
libc_decl(chmod);
libc_decl(chown);
libc_decl(creat);
libc_decl(fopen);
libc_decl(link);
libc_decl(mkdir);
libc_decl(open);
libc_decl(openat);
libc_decl(opendir);
libc_decl(readlink);
libc_decl(remove);
libc_decl(rename);
libc_decl(rmdir);
libc_decl(__xstat);
libc_decl(symlink);
libc_decl(unlink);
libc_decl(creat64);
libc_decl(fopen64);
libc_decl(open64);
libc_decl(openat64);
libc_decl(__xstat64);

extern "C" {

int execve(const char *file, char *const argv[], char *const envp[]) {
    eprintf("[sandbox] execve(%s): not allowed\n", file);
    errno = EACCES;
    return -1;
}

int chdir(const char *path) {
    if (deny(path)) {
        return -1;
    }
    return libc_chdir(path);
}

int chmod(const char *path, mode_t mode) {
    if (deny(path)) {
        return -1;
    }
    return libc_chmod(path, mode);
}

int chown(const char *path, uid_t owner, gid_t group) {
    if (deny(path)) {
        return -1;
    }
    return libc_chown(path, owner, group);
}

int creat(const char *path, mode_t mode) {
    if (deny(path)) {
        return -1;
    }
    return libc_creat(path, mode);
}

FILE *fopen(const char *pathname, const char *mode) {
    if (deny(pathname)) {
        return NULL;
    }
    return libc_fopen(pathname, mode);
}

int link(const char *path1, const char *path2) {
    if (deny(path1) || deny(path2)) {
        return -1;
    }
    return libc_link(path1, path2);
}

int mkdir(const char *path, mode_t mode) {
    if (deny(path)) {
        return -1;
    }
    return libc_mkdir(path, mode);
}

DIR *opendir(const char *name) {
    if (deny(name)) {
        return NULL;
    }
    return libc_opendir(name);
}

ssize_t readlink(const char *path, char *buf, size_t bufsize) {
    if (deny(path)) {
        return -1;
    }
    return libc_readlink(path, buf, bufsize);
}

int remove(const char *pathname) {
    if (deny(pathname)) {
        return -1;
    }
    return libc_remove(pathname);
}

int rename(const char *old, const char *new_) {
    if (deny(old) || deny(new_)) {
        return -1;
    }
    return libc_rename(old, new_);
}

int rmdir(const char *path) {
    if (deny(path)) {
        return -1;
    }
    return libc_rmdir(path);
}

int __xstat(int __ver, const char *__filename, struct stat *__stat_buf) {
    if (deny(__filename)) {
        return -1;
    }
    return libc___xstat(__ver, __filename, __stat_buf);
}

int symlink(const char *path1, const char *path2) {
    if (deny(path2)) {
        return -1;
    }
    return libc_symlink(path1, path2);
}

int unlink(const char *path) {
    if (deny(path)) {
        return -1;
    }
    return libc_unlink(path);
}
}
