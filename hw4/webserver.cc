#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <pthread.h>
#include <spawn.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static const char *StatusOK = "200 OK";
static const char *StatusMovedPermanently = "301 Moved Permanently";
static const char *StatusBadRequest = "400 Bad Request";
static const char *StatusForbidden = "403 Forbidden";
static const char *StatusNotFound = "404 Not Found";
static const char *StatusInternalServerError = "500 Internal Server Error";

static int toClose;
void handleAlarm(int signum) {
    close(toClose);
    dprintf(2, "  timeout reached\n");
}

void statusResponse(int csock, const char *status, const char *description = "",
                    bool useerrno = true) {
    dprintf(csock,
            "HTTP/1.1 %s\r\nContent-Type: text/plain\r\nConnection: "
            "close\r\n\r\n%s\r\n%s\r\n",
            status, status, description);
    if (useerrno) {
        dprintf(csock, "errno %d: %s\r\n", errno, strerror(errno));
    }
}

void writeHeader(int csock, const char *status, const char *etc = "",
                 const char *end = "\r\n") {
    dprintf(csock, "HTTP/1.1 %s\r\nConnection: close\r\n%s%s", status, etc,
            end);
}

char *cleanupPath(char *path, ssize_t len) {
    ssize_t o = 0;
    ssize_t last_slash = -1;
    char *query = path + strlen(path);
    for (ssize_t i = 0; i < len; i++) {
        if (path[i] == '?') {
            query = path + i + 1;
            break;
        }
        if (last_slash + 1 == i) {
            if (path[i] == '.') {
                if (path[i + 1] == '.') {
                    if (path[i + 2] == 0 or path[i + 2] == '?' or
                        path[i + 2] == '/') {
                        for (o -= 2; o > 0; o--) {
                            if (path[o] == '/') {
                                break;
                            }
                        }
                        i++;
                        continue;
                    }
                }
            }
        }
        if (path[i] == '/') {
            last_slash = i;
            if (o > 0) {
                if (path[o - 1] == '/') {
                    continue;
                }
            }
            if (o == 0) {
                continue;
            }
        }
        path[o] = path[i];
        o++;
    }
    if (o < 0) {
        o = 0;
    }
    if (o < len) {
        path[o] = 0;
    }
    return query;
}

void handleDirListing(int csock, char *path) {
    DIR *d = opendir(path);
    if (d == NULL) {
        statusResponse(csock, StatusNotFound, "directory not readable");
        return;
    }
    writeHeader(csock, StatusOK, "Content-Type: text/html; charset=utf-8\r\n");
    struct dirent *entry;
    dprintf(csock, "<h1>%s</h1>\n<ul>\n", path);
    while ((entry = readdir(d))) {
        dprintf(csock, "<li><a href=\"/%s%s\">%s</a></li>\n", path,
                entry->d_name, entry->d_name);
    }
    closedir(d);
    dprintf(csock, "</ul>\n");
}

void handleDirRedirect(int csock, char *path) {
    char *hdr;
    asprintf(&hdr, "Location: /%s/\r\n", path);
    writeHeader(csock, StatusMovedPermanently, hdr);
    free(hdr);
}

int spliceN(int ifd, int ofd, ssize_t n) {
    while (n > 0) {
        ssize_t r = splice(ifd, 0, ofd, 0, n, 0);
        if (r < 0) {
            return -1;
        }
        n -= r;
    }
    return 0;
}

void handleCGI(int csock, const char *method, char *path, const char *query, int contentLength) {
    pid_t pid;
    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    char *argv[] = {path, 0};
    char *envp[3] = {0, 0, 0};
    asprintf(&envp[0], "REQUEST_METHOD=%s", method);
    asprintf(&envp[1], "QUERY_STRING=%s", query);
    int pipefd[2];
    posix_spawn_file_actions_adddup2(&actions, csock, STDOUT_FILENO);
    if (contentLength >= 0) {
        if (-1 == pipe(pipefd)) {
            perror("pipe() failed");
            goto cleanup;
        }
        posix_spawn_file_actions_adddup2(&actions, pipefd[0], STDIN_FILENO);
        posix_spawn_file_actions_addclose(&actions, pipefd[0]);
        posix_spawn_file_actions_addclose(&actions, pipefd[1]);
    } else {
        posix_spawn_file_actions_addclose(&actions, STDIN_FILENO);
    }
    writeHeader(csock, StatusOK, "", "");
    if (-1 == posix_spawn(&pid, path, &actions, 0, argv, envp)) {
        statusResponse(csock, StatusInternalServerError,
                       "posix_spawn() failed");
        goto cleanup;
    }
    if (contentLength >= 0) {
        close(pipefd[0]);
        toClose = pipefd[1];
        alarm(5);
        if (-1 == spliceN(csock, pipefd[1], contentLength)) {
            perror("splice failed");
        } else {
            alarm(0);
            fprintf(stderr, "  splice() completed\n");
        }
        close(pipefd[1]);
    }
    int status;
    if (-1 == waitpid(pid, &status, 0)) {
        perror("waitpid failed");
    } else if (WIFEXITED(status)) {
        fprintf(stderr, "  CGI exit status %d\n", WEXITSTATUS(status));
    } else if (WIFSIGNALED(status)) {
        fprintf(stderr, "  CGI exit signal %d: %s\n", WTERMSIG(status),
                strsignal(WTERMSIG(status)));
    } else {
        fprintf(stderr, "  CGI unknown status %d\n", status);
    }
cleanup:
    free(envp[0]);
    free(envp[1]);
}

void handleStatic(int csock, char *path) {
    int fd = open(path, O_RDONLY);
    if (fd == -1) {
        if (errno == ENOENT) {
            statusResponse(csock, StatusForbidden);
        } else {
            statusResponse(csock, StatusNotFound);
        }
    } else {
        writeHeader(csock, StatusOK);
        sendfile(csock, fd, 0, 0x7ffff000);
        close(fd);
    }
}

int readHeader(FILE *r, char **buf, size_t *buflen, char **value) {
    ssize_t nread = getline(buf, buflen, r);
    if (nread <= 0) {
        return -1;
    }
    if (nread == 2) {
        if (**buf == '\r') {
            return 1;
        }
    }
    int i = 0;
    for (; i < nread; i++) {
        if ((*buf)[i] == ':') {
            break;
        }
    }
    if (i == nread) {
        return -1;
    }
    (*buf)[i] = 0;
    for (i++; i < nread; i++) {
        if ((*buf)[i] != ' ') {
            break;
        }
    }
    *value = *buf + i;
    for (int j = nread - 1; j > i; j--) {
        if ((*buf)[j] != '\r' and (*buf)[j] != '\n') {
            break;
        }
        (*buf)[j] = 0;
    }
    return 0;
}

void handle(int csock, sockaddr_in caddr) {
    char *method;
    ssize_t nread;
    char *query;
    char localDir[] = "./";
    FILE *r = fdopen(csock, "r");
    ssize_t contentLength = -1;
    setbuf(r, 0);
    {
        size_t mlen = 0;
        if (-1 == (nread = getdelim(&method, &mlen, ' ', r))) {
            if (!mlen) {
                free(method);
            }
            statusResponse(csock, StatusBadRequest, "", false);
            goto cleanup;
        }
    }
    method[nread - 1] = 0; // clear the delimeter
    char *pathbuf;
    char *path;
    path = (char *)malloc(2);
    {
        size_t plen = 0;
        if (-1 == (nread = getdelim(&pathbuf, &plen, ' ', r))) {
            if (plen) {
                free(pathbuf);
            }
            free(pathbuf);
            statusResponse(csock, StatusBadRequest, "", false);
            goto cleanup;
        }
        path = pathbuf;
    }
    {
        char *buf = 0;
        size_t buflen = 0;
        char *value;
        if (-1 != getline(&buf, &buflen, r)) {
            while (true) {
                int status = readHeader(r, &buf, &buflen, &value);
                if (status) {
                    free(buf);
                    break;
                }
                if (0 == strcmp(buf, "Content-Length")) {
                    errno = 0;
                    contentLength = strtol(value, 0, 10);
                    if (errno or contentLength < 0) {
                        statusResponse(csock, StatusBadRequest, "invalid Content-Length header");
                        goto cleanup;
                    }
                }
                // fprintf(stderr, "%s: %s\n", buf, value);
            }
        }
    }
    if (0 == strcmp("POST", method) and contentLength == -1) {
        statusResponse(csock, StatusBadRequest, "POST without Content-Length header unsupported");
        goto cleanup;
    }
    path[nread - 1] = 0; // clear the delimeter
    query = cleanupPath(path, nread);
    if (strlen(path) == 0) {
        path = localDir;
    }
    fprintf(stderr, "%s %s\n", method, path);
    {
        struct stat st;
        if (-1 == stat(path, &st)) {
            if (errno == ENOENT) {
                statusResponse(csock, StatusForbidden);
            } else {
                statusResponse(csock, StatusNotFound);
            }
            goto cleanup;
        }
        if (S_ISDIR(st.st_mode)) {
            if (path[strlen(path) - 1] == '/') {
                char *indexHtml;
                asprintf(&indexHtml, "%sindex.html", path);
                int ifd = open(indexHtml, O_RDONLY);
                if (ifd != -1) {
                    writeHeader(csock, StatusOK);
                    sendfile(csock, ifd, 0, 0x7ffff000);
                    close(ifd);
                } else {
                    if (errno == ENOENT) {
                        handleDirListing(csock, path);
                    } else {
                        statusResponse(csock, StatusForbidden,
                                       "index.html not readable");
                    }
                }
                free(indexHtml);
            } else {
                handleDirRedirect(csock, path);
            }
        } else {
            if (0 == access(path, X_OK)) {
                handleCGI(csock, method, path, query, contentLength);
            } else {
                handleStatic(csock, path);
            }
        }
    }
    shutdown(csock, SHUT_RD);
cleanup:
    shutdown(csock, SHUT_WR);
    close(csock);
}
