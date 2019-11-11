#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

#include <iomanip>
#include <stdexcept>
#include <string>

#include <gtest/gtest.h>

// the errno the sandbox should set when denying function calls
const int ESBX = EACCES;

std::runtime_error rtef(const char *fmt, ...) {
    char *errcstr;
    va_list ap;
    va_start(ap, fmt);
    vasprintf(&errcstr, fmt, ap);
    va_end(ap);
    std::runtime_error r(errcstr);
    free(errcstr);
    return r;
}

static void *findfunc(const char *name) {
    static void *libc = 0;
    if (!libc) {
        libc = dlopen("libc.so.6", RTLD_LAZY);
        if (!libc) {
            throw rtef("dlopen(libc.so.6) failed: %s", dlerror());
        }
    }
    void *f = dlsym(libc, name);
    if (!f) {
        throw rtef("dlsym(%s) failed: %s", name, dlerror());
    }
    return f;
}

#define libc(name) reinterpret_cast<decltype(&name)>(findfunc(#name))
#define libc_decl(name) decltype(&name) libc_##name = libc(name)

libc_decl(getcwd);
libc_decl(unlink);
libc_decl(open);
libc_decl(write);
libc_decl(close);
libc_decl(symlink);
libc_decl(chdir);
libc_decl(mkdir);
libc_decl(rmdir);

class SandboxTest : public ::testing::Test {
  protected:
    char basedir[PATH_MAX];

    void SetUp() override {
        ASSERT_TRUE(libc_getcwd(basedir, PATH_MAX));
        int fd;
        ASSERT_NE(-1, fd = libc_open("f0", O_WRONLY | O_CREAT | O_EXCL, 0644));
        ASSERT_EQ(2, libc_write(fd, "a\n", 2));
        ASSERT_EQ(0, libc_close(fd));

        ASSERT_EQ(0, libc_mkdir("dempty", 0755));
        ASSERT_EQ(0, libc_mkdir("dhasfile", 0755));

        ASSERT_NE(-1, fd = libc_open("dhasfile/f1", O_WRONLY | O_CREAT | O_EXCL,
                                     0644));
        ASSERT_EQ(2, libc_write(fd, "b\n", 2));
        ASSERT_EQ(0, libc_close(fd));

        ASSERT_EQ(0, libc_symlink("f0", "l0"));
        ASSERT_EQ(0, libc_symlink("dhasfile/f1", "l1"));
        ASSERT_EQ(0, libc_symlink("dempty", "ldempty"));
        ASSERT_EQ(0, libc_symlink("dhasfile", "ldhasfile"));
        ASSERT_EQ(0, libc_symlink("/bin/sh", "lsh"));
        ASSERT_EQ(0, libc_symlink("/", "lroot"));
        ASSERT_EQ(0, libc_symlink(".", "l."));
        ASSERT_EQ(0, libc_symlink("..", "l.."));
        ASSERT_EQ(0, libc_symlink("/broken-symlink", "loutbroken"));
        ASSERT_EQ(0, libc_symlink("broken-symlink", "lbroken"));
        errno = 0;
    }

    void TearDown() override {
        ASSERT_EQ(0, libc_chdir(basedir));
        ASSERT_EQ(0, libc_unlink("f0"));
        ASSERT_EQ(0, libc_rmdir("dempty"));
        ASSERT_EQ(0, libc_unlink("dhasfile/f1"));
        ASSERT_EQ(0, libc_rmdir("dhasfile"));

        ASSERT_EQ(0, libc_unlink("l0"));
        ASSERT_EQ(0, libc_unlink("l1"));
        ASSERT_EQ(0, libc_unlink("ldempty"));
        ASSERT_EQ(0, libc_unlink("ldhasfile"));
        ASSERT_EQ(0, libc_unlink("lsh"));
        ASSERT_EQ(0, libc_unlink("lroot"));
        ASSERT_EQ(0, libc_unlink("l."));
        ASSERT_EQ(0, libc_unlink("l.."));
        ASSERT_EQ(0, libc_unlink("loutbroken"));
        ASSERT_EQ(0, libc_unlink("lbroken"));
        libc_unlink("x");
        libc_unlink("y");
        libc_unlink("z");
    }
};

class Chdir : public SandboxTest {};

#define EXPECT_ERRNO(e, r, op)                                                 \
    do {                                                                       \
        int oerrno = errno;                                                    \
        auto ret = op;                                                         \
        EXPECT_TRUE(ret == r and e == errno)                                   \
            << #op "\n"                                                        \
            << "         retval / errno\n"                                     \
            << "expected " << std::setw(6) << r << " / " << e << ": "          \
            << strerror(e) << "\n"                                             \
            << "     got " << std::setw(6) << ret << " / " << errno << ": "    \
            << strerror(errno);                                                \
        errno = oerrno;                                                        \
    } while (0)

TEST_F(Chdir, ParentDirectory) {
    EXPECT_EQ(-1, chdir(".."));
    EXPECT_EQ(ESBX, errno);
}

TEST_F(Chdir, SParentDirectory) {
    EXPECT_EQ(-1, chdir("l.."));
    EXPECT_EQ(ESBX, errno);
}

TEST_F(Chdir, Root) {
    EXPECT_EQ(-1, chdir("/"));
    EXPECT_EQ(ESBX, errno);
}

TEST_F(Chdir, SRoot) {
    EXPECT_EQ(-1, chdir("lroot"));
    EXPECT_EQ(ESBX, errno);
}

TEST_F(Chdir, Here) {
    EXPECT_EQ(0, chdir("."));
    EXPECT_EQ(0, errno);
}

TEST_F(Chdir, SHere) {
    EXPECT_EQ(0, chdir("."));
    EXPECT_EQ(0, errno);
}

TEST_F(Chdir, File) {
    EXPECT_EQ(-1, chdir("f0"));
    EXPECT_EQ(ENOTDIR, errno);
}

TEST_F(Chdir, SFile) {
    EXPECT_EQ(-1, chdir("l0"));
    EXPECT_EQ(ENOTDIR, errno);
}

TEST_F(Chdir, EmptyString) {
    EXPECT_EQ(-1, chdir(""));
    EXPECT_EQ(ENOENT, errno);
}

TEST_F(Chdir, NoSuchFile) {
    EXPECT_EQ(-1, chdir("does-not-exist"));
    EXPECT_EQ(ENOENT, errno);
}

TEST_F(Chdir, BrokenSymlink) {
    EXPECT_EQ(-1, chdir("lbroken"));
    EXPECT_EQ(ENOENT, errno);
}

TEST_F(Chdir, BrokenSymlinkOutside) {
    EXPECT_EQ(-1, chdir("loutbroken"));
    EXPECT_EQ(ENOENT, errno);
}

TEST_F(Chdir, Inside) {
    EXPECT_ERRNO(0, 0, chdir("dempty"));
    EXPECT_ERRNO(0, 0, chdir(".."));
}

class Chmod : public SandboxTest {};

TEST_F(Chmod, Inside) {
    EXPECT_ERRNO(0, 0, chmod("dhasfile", 0755));
    EXPECT_ERRNO(0, 0, chmod("dempty", 0755));
    EXPECT_ERRNO(0, 0, chmod("dhasfile/f1", 0644));
    EXPECT_ERRNO(0, 0, chmod("f0", 0644));
}

TEST_F(Chmod, SInside) {
    EXPECT_ERRNO(0, 0, chmod("l0", 0644));
    EXPECT_ERRNO(0, 0, chmod("l1", 0644));
    EXPECT_ERRNO(0, 0, chmod("ldempty", 0755));
    EXPECT_ERRNO(0, 0, chmod("ldhasfile", 0755));
}

TEST_F(Chmod, Outside) {
    EXPECT_ERRNO(ESBX, -1, chmod("..", 0755));
    EXPECT_ERRNO(ESBX, -1, chmod("/", 0755));
    EXPECT_ERRNO(ESBX, -1, chmod("/dev/null", 0755));
}

TEST_F(Chmod, SOutside) {
    EXPECT_ERRNO(ESBX, -1, chmod("lroot", 0755));
    EXPECT_ERRNO(ESBX, -1, chmod("l..", 0755));
}

TEST_F(Chmod, NoSuchFileOrDirectory) {
    EXPECT_ERRNO(ENOENT, -1, chmod("missing", 0755));
    EXPECT_ERRNO(ENOENT, -1, chmod("lbroken", 0755));
}

TEST_F(Chmod, NoSuchFileOrDirectoryOutside) {
    EXPECT_ERRNO(ENOENT, -1, chmod("/does/not/exist", 0755));
    EXPECT_ERRNO(ENOENT, -1, chmod("loutbroken", 0755));
}

class Chown : public SandboxTest {};

TEST_F(Chown, Inside) {
    EXPECT_ERRNO(0, 0, chown("dhasfile", getuid(), getgid()));
    EXPECT_ERRNO(0, 0, chown("dempty", getuid(), getgid()));
    EXPECT_ERRNO(0, 0, chown("dhasfile/f1", getuid(), getgid()));
    EXPECT_ERRNO(0, 0, chown("f0", getuid(), getgid()));
}

TEST_F(Chown, SInside) {
    EXPECT_ERRNO(0, 0, chown("l0", getuid(), getgid()));
    EXPECT_ERRNO(0, 0, chown("l1", getuid(), getgid()));
    EXPECT_ERRNO(0, 0, chown("ldempty", getuid(), getgid()));
    EXPECT_ERRNO(0, 0, chown("ldhasfile", getuid(), getgid()));
}

TEST_F(Chown, Outside) {
    EXPECT_ERRNO(ESBX, -1, chown("..", getuid(), getgid()));
    EXPECT_ERRNO(ESBX, -1, chown("/", getuid(), getgid()));
    EXPECT_ERRNO(ESBX, -1, chown("/dev/null", getuid(), getgid()));
}

TEST_F(Chown, SOutside) {
    EXPECT_ERRNO(ESBX, -1, chown("lroot", getuid(), getgid()));
    EXPECT_ERRNO(ESBX, -1, chown("l..", getuid(), getgid()));
}

TEST_F(Chown, NoSuchFileOrDirectory) {
    EXPECT_ERRNO(ENOENT, -1, chown("missing", getuid(), getgid()));
    EXPECT_ERRNO(ENOENT, -1, chown("lbroken", getuid(), getgid()));
}

TEST_F(Chown, NoSuchFileOrDirectoryOutside) {
    EXPECT_ERRNO(ENOENT, -1, chown("/does/not/exist", getuid(), getgid()));
    EXPECT_ERRNO(ENOENT, -1, chown("loutbroken", getuid(), getgid()));
}

class Exec : public SandboxTest {};

char fail_msg[] = "ERROR: EXEC BYPASSED SANDBOX";
char binecho[] = "/bin/echo";
char *exec_args[] = {binecho, fail_msg, 0};

TEST_F(Exec, Execl) {
    EXPECT_ERRNO(ESBX, -1, execl("/bin/echo", "echo", fail_msg, 0));
}

TEST_F(Exec, Execle) {
    EXPECT_ERRNO(ESBX, -1, execle("/bin/echo", "echo", fail_msg, 0, environ));
}

TEST_F(Exec, Execlp) {
    EXPECT_ERRNO(ESBX, -1, execlp("echo", "echo", fail_msg, 0));
    EXPECT_ERRNO(ESBX, -1, execlp("/bin/echo", "echo", fail_msg, 0));
}

TEST_F(Exec, Execv) { EXPECT_ERRNO(ESBX, -1, execv(binecho, exec_args)); }

TEST_F(Exec, Execve) {
    EXPECT_ERRNO(ESBX, -1, execve("/bin/echo", exec_args, environ));
}

TEST_F(Exec, Execvp) {
    EXPECT_ERRNO(ESBX, -1, execvp("echo", exec_args));
    EXPECT_ERRNO(ESBX, -1, execvp("/bin/echo", exec_args));
}

TEST_F(Exec, System) {
    EXPECT_ERRNO(ESBX, -1, system("echo ERROR: EXEC BYPASSED SANDBOX"));
}
