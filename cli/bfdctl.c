#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define BFD_CLI_SOCK "/tmp/bfd.sock"

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr,
            "Usage:\n"
            "  %s show sessions\n"
            "  %s show session <disc>\n"
            "  %s add v4|v6 <ip> <disc> <min_tx_us> <min_rx_us> <mult> [echo_us]\n"
            "  %s del <disc>\n"
            "  %s down <disc>\n"
            "  %s up <disc>\n",
            argv[0], argv[0], argv[0], argv[0], argv[0], argv[0]);
        return 1;
    }

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return 1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, BFD_CLI_SOCK);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect");
        close(fd);
        return 1;
    }

    char cmd[512] = {0};
    for (int i = 1; i < argc; i++) {
        strcat(cmd, argv[i]);
        if (i + 1 < argc)
            strcat(cmd, " ");
    }
    strcat(cmd, "\n");

    write(fd, cmd, strlen(cmd));

    char buf[512];
    ssize_t n;
    while ((n = read(fd, buf, sizeof(buf))) > 0) {
        fwrite(buf, 1, n, stdout);
    }

    close(fd);
    return 0;
}
