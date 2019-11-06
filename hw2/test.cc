#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

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
    void *f = dlsym(RTLD_NEXT, name);
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

class SandboxTest : public ::testing::Test {
  protected:
    char basedir[PATH_MAX];

    void SetUp() override {
        ASSERT_TRUE(libc_getcwd(basedir, PATH_MAX));
        int fd;
        ASSERT_NE(-1, fd = libc_open("fa", O_WRONLY | O_CREAT | O_EXCL, 0644));
        ASSERT_EQ(2, libc_write(fd, "a\n", 2));
        ASSERT_EQ(0, libc_close(fd));

        ASSERT_EQ(0, libc_symlink("fa", "la"));
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
        ASSERT_EQ(0, libc_unlink("fa"));
        ASSERT_EQ(0, libc_unlink("la"));
        ASSERT_EQ(0, libc_unlink("lsh"));
        ASSERT_EQ(0, libc_unlink("lroot"));
        ASSERT_EQ(0, libc_unlink("l."));
        ASSERT_EQ(0, libc_unlink("l.."));
        ASSERT_EQ(0, libc_unlink("loutbroken"));
        ASSERT_EQ(0, libc_unlink("lbroken"));

    }
};

class Chdir : public SandboxTest {};

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
    EXPECT_EQ(-1, chdir("fa"));
    EXPECT_EQ(ENOTDIR, errno);
}

TEST_F(Chdir, SFile) {
    EXPECT_EQ(-1, chdir("la"));
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
