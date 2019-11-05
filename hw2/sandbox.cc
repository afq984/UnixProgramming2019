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

static const char *basedir;
static int basedir_len;
static int errfd = 2;

static int eprintf(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int r = vdprintf(errfd, fmt, ap);
    va_end(ap);
    return r;
}

static void *findfunc(const char *name) {
    void *f = dlsym(RTLD_NEXT, name);
    if (!f) {
        char str[128];
        eprintf("dlsym(%s) failed: %s", name, dlerror());
    }
    return f;
}

#define libc(name) reinterpret_cast<decltype(&name)>(findfunc(#name))
#define libc_decl(name) decltype(&name) libc_##name = libc(name)

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

__attribute__((constructor)) static void init() {
    basedir = strdup(getenv("SANDBOX_BASEDIR"));
    basedir_len = strlen(basedir);
    int fd = libc(open)("/dev/tty", O_WRONLY);
    if (fd == -1) {
        dprintf(2, "failed to open /dev/tty, falling back to fd 2.");
    } else {
        errfd = fd;
    }
}

// func(path)
// O_CREAT?
// |	func follows links?
// |	|	path is a link?
// |	|	|	deny condition
// N	Y	*	realpath(path) out of basedir
// N	N	*	realpath(dirname(path)) out of basedir
// Y	*	Y	realpath(path) out of basedir
// Y	*	N	realpath(dirname(path)) out of basedir
static int deny1(int dirfd, const char *path, bool parent, const char *hint) {
    int oerrno = errno;
    const char *target_path;
    if (parent) {
        target_path = dirname(strdupa(path));
    } else {
        target_path = path;
    }
    char resolved_path[PATH_MAX];
    int fd = libc_openat(dirfd, target_path, O_PATH);
    if (fd == -1) {
        eprintf("[sandbox] %s: cannot resolve %s\n", hint, target_path);
        return -1;
    }
    char procpath[PATH_MAX];
    snprintf(procpath, PATH_MAX, "/proc/self/fd/%d", fd);
    ssize_t linksize = libc_readlink(procpath, resolved_path, PATH_MAX);
    close(fd);
    if (-1 == linksize || linksize >= PATH_MAX) {
        eprintf("[sandbox] %s: cannot resolve(long) %s\n", hint, target_path);
        return -1;
    }
    resolved_path[linksize] = 0;
    if (strncmp(basedir, resolved_path, basedir_len)) {
        if (dirfd == AT_FDCWD && strcmp(target_path, resolved_path)) {
            eprintf("[sandbox] %s: access to %s -> %s is not allowed\n", hint,
                    target_path, resolved_path);
        } else {
            eprintf("[sandbox] %s: access to %s is not allowed\n", hint,
                    resolved_path);
        }
        errno = EACCES;
        return -1;
    }
    errno = oerrno;
    return 0;
}

static bool islink(const char *path, int at = AT_FDCWD) {
    int oerrno = errno;
    struct stat st;
    if (-1 == fstatat(at, path, &st, AT_SYMLINK_NOFOLLOW)) {
        errno = oerrno;
        return false;
    }
    return S_ISLNK(st.st_mode);
}

#define deny(name, parent) deny1(AT_FDCWD, name, parent, __func__)

#define denyexec()                                                             \
    do {                                                                       \
        eprintf("[sandbox] %s(%s): not allowed\n", __func__, arg0);            \
        errno = EACCES;                                                        \
        return -1;                                                             \
    } while (0)

extern "C" {

int execl(const char *arg0, const char *, ...) { denyexec(); }

int execle(const char *arg0, const char *, ...) { denyexec(); }

int execlp(const char *arg0, const char *, ...) { denyexec(); }

int execv(const char *arg0, char *const[]) { denyexec(); }

int execvp(const char *arg0, char *const[]) { denyexec(); }

int execve(const char *arg0, char *const[], char *const[]) { denyexec(); }

int system(const char *arg0) { denyexec(); }

int chdir(const char *path) {
    if (deny(path, false)) {
        return -1;
    }
    return libc_chdir(path);
}

int chmod(const char *path, mode_t mode) {
    if (deny(path, false)) {
        return -1;
    }
    return libc_chmod(path, mode);
}

int chown(const char *path, uid_t owner, gid_t group) {
    if (deny(path, false)) {
        return -1;
    }
    return libc_chown(path, owner, group);
}

int creat(const char *path, mode_t mode) {
    if (deny(path, !islink(path))) {
        return -1;
    }
    return libc_creat(path, mode);
}

bool fopen_tp(const char* pathname, const char* mode) {
    if (mode[0] == 'w' or mode[0] == 'a') {
        return !islink(pathname);
    }
    return false;
}

FILE *fopen(const char *pathname, const char *mode) {
    if (deny(pathname, fopen_tp(pathname, mode))) {
        return NULL;
    }
    return libc_fopen(pathname, mode);
}

int link(const char *path1, const char *path2) {
    // If path1 names a symbolic link, it  is  implementation-defined  whether
    // link() follows the symbolic link, or creates a new link to the symbolic
    // link itself.
    if (deny(path1, false) || deny(path2, false)) {
        return -1;
    }
    return libc_link(path1, path2);
}

int mkdir(const char *path, mode_t mode) {
    // If path names a symbolic link, mkdir() shall  fail  and  set  errno  to
    // [EEXIST].
    if (deny(path, true)) {
        return -1;
    }
    return libc_mkdir(path, mode);
}

static bool openat_tp(int at, const char *pathname, int flags) {
    if (flags & O_NOFOLLOW) {
        return true;
    }
    if (flags & O_CREAT) {
        return !islink(pathname, at);
    }
    return false;
}

static int _open(const char *pathname, int flags, mode_t mode) {
    if (deny1(AT_FDCWD, pathname, openat_tp(AT_FDCWD, pathname, flags), "open")) {
        return -1;
    }
    return libc_open(pathname, flags, mode);
}
int open(const char *pathame, int flags, ...)
    __attribute__((weak, alias("_open")));
// The compiler rejects to have a different declaration of open()
// but I'm too lazy to deal with variable length parameters.
// this and -Wno-attribute-alias just work

static int _openat(int dirfd, const char *pathname, int flags, mode_t mode) {
    if (deny1(dirfd, pathname, openat_tp(dirfd, pathname, flags), "openat")) {
        return -1;
    }
    return libc_openat(dirfd, pathname, flags, mode);
}
int openat(int fd, const char *path, int oflag, ...)
    __attribute__((weak, alias("_openat")));

DIR *opendir(const char *name) {
    if (deny(name, false)) {
        return NULL;
    }
    return libc_opendir(name);
}

ssize_t readlink(const char *path, char *buf, size_t bufsize) {
    if (deny(path, true)) {
        return -1;
    }
    return libc_readlink(path, buf, bufsize);
}

int remove(const char *pathname) {
    // If the name referred to a symbolic link, the link is removed.
    if (deny(pathname, true)) {
        return -1;
    }
    return libc_remove(pathname);
}

int rename(const char *old, const char *new_) {
    // If either the old or new argument names a symbolic link, rename() shall
    // operate on the symbolic link itself, and shall  not  resolve  the  last
    // component of the argument.
    if (deny(old, true) || deny(new_, true)) {
        return -1;
    }
    return libc_rename(old, new_);
}

int rmdir(const char *path) {
    // If path names a symbolic link, then rmdir() shall fail and set errno to
    // [ENOTDIR].
    if (deny(path, true)) {
        return -1;
    }
    return libc_rmdir(path);
}

int __xstat(int __ver, const char *__filename, struct stat *__stat_buf) {
    if (deny1(AT_FDCWD, __filename, false, "stat")) {
        return -1;
    }
    return libc___xstat(__ver, __filename, __stat_buf);
}

int symlink(const char *path1, const char *path2) {
    if (deny(path2, true)) {
        return -1;
    }
    return libc_symlink(path1, path2);
}

int unlink(const char *path) {
    if (deny(path, true)) {
        return -1;
    }
    return libc_unlink(path);
}

int creat64(const char *pathname, mode_t mode) {
    if (deny(pathname, true)) {
        return -1;
    }
    return libc_creat64(pathname, mode);
}

FILE *fopen64(const char *pathname, const char *mode) {
    if (deny(pathname, fopen_tp(pathname, mode))) {
        return NULL;
    }
    return libc_fopen64(pathname, mode);
}

static int _open64(const char *pathname, int flags, mode_t mode) {
    if (deny1(AT_FDCWD, pathname, openat_tp(AT_FDCWD, pathname, flags), "open64")) {
        return -1;
    }
    return libc_open(pathname, flags, mode);
}
int open64(const char *pathame, int flags, ...)
    __attribute__((weak, alias("_open64")));

static int _openat64(int dirfd, const char *pathname, int flags, mode_t mode) {
    if (deny1(dirfd, pathname, openat_tp(dirfd, pathname, flags), "openat")) {
        return -1;
    }
    return libc_openat(dirfd, pathname, flags, mode);
}
int openat64(int fd, const char *path, int oflag, ...)
    __attribute__((weak, alias("_openat64")));

int __xstat64(int __ver, const char *__filename, struct stat64 *__stat_buf) {
    if (deny1(AT_FDCWD, __filename, false, "stat64")) {
        return -1;
    }
    return libc___xstat64(__ver, __filename, __stat_buf);
}
}
