#include <gtest/gtest.h>
#include <stdio.h>

#include "webserver.cc"

#define EXPECT_PATH(before, expPath, expQuery)                                 \
    do {                                                                       \
        char *path = strdupa(before);                                          \
        char *query = cleanupPath(path, strlen(path));                         \
        EXPECT_STREQ(path, expPath);                                           \
        EXPECT_STREQ(query, expQuery);                                         \
    } while (0)

TEST(CleanupPathTest, Basic) {
    EXPECT_PATH("/a", "a", "");
    EXPECT_PATH("/a/b", "a/b", "");
    EXPECT_PATH("/a//b", "a/b", "");
    EXPECT_PATH("/a///b", "a/b", "");
    EXPECT_PATH("/a/", "a/", "");
    EXPECT_PATH("/a/b/..", "a", "");
    EXPECT_PATH("/a/b//..", "a", "");
    EXPECT_PATH("/a/b/../", "a/", "");
    EXPECT_PATH("/a/b/../c", "a/c", "");
    EXPECT_PATH("/a/b/../c/", "a/c/", "");
    EXPECT_PATH("a/../..", "", "");
    EXPECT_PATH("/..", "", "");
    EXPECT_PATH("..", "", "");
}

TEST(CleanupPathTest, WithQuery) {
    EXPECT_PATH("/a?q=w", "a", "q=w");
    EXPECT_PATH("/a/b?q=w", "a/b", "q=w");
    EXPECT_PATH("/a//b?q=w", "a/b", "q=w");
    EXPECT_PATH("/a///b?q=w", "a/b", "q=w");
    EXPECT_PATH("/a/?q=w", "a/", "q=w");
    EXPECT_PATH("/a/b/..?q=w", "a", "q=w");
    EXPECT_PATH("/a/b//..?q=w", "a", "q=w");
    EXPECT_PATH("/a/b/../?q=w", "a/", "q=w");
    EXPECT_PATH("/a/b/../c?q=w", "a/c", "q=w");
    EXPECT_PATH("/a/b/../c/?q=w", "a/c/", "q=w");
    EXPECT_PATH("a/../..?q=w", "", "q=w");
    EXPECT_PATH("/..?q=w", "", "q=w");
    EXPECT_PATH("..?q=w", "", "q=w");
}
