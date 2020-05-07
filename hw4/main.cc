#include "webserver.cc"

int main(int argc, char **argv) {
    assert(argc == 3 && "usage: ./webserver PORT DOCROOT");
    if (signal(SIGALRM, handleAlarm) == SIG_ERR) {
        perror("signal() failed");
        return 1;
    }
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (-1 == chdir(argv[2])) {
        perror("chdir() failed");
        return 2;
    }
    if (sock == -1) {
        perror("socket() failed");
        return 3;
    }
    {
        int yes = 1;
        if (-1 ==
            setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes)) {
            perror("setsockopt() failed");
            return 5;
        }
    }
    struct sockaddr_in saddr;
    saddr.sin_family = AF_INET;
    saddr.sin_port = htons(atoi(argv[1]));
    saddr.sin_addr.s_addr = 0;
    if (-1 == bind(sock, (struct sockaddr *)&saddr, sizeof saddr)) {
        perror("bind() failed");
        return 5;
    }
    if (-1 == listen(sock, 5)) {
        perror("listen() failed");
        return 6;
    }
    while (true) {
        struct sockaddr_in caddr;
        socklen_t caddr_len = sizeof caddr;
        int csock = accept(sock, (struct sockaddr *)&caddr, &caddr_len);
        if (csock == -1) {
            perror("accept() failed");
            continue;
        }
        handle(csock, caddr);
    }
}
