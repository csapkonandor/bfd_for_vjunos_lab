#include "bfd_cli.h"
#include "bfd_session.h"

#include <sys/socket.h>
#include <sys/un.h>
#include <sys/epoll.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>


#define BFD_CLI_SOCK "/tmp/bfd.sock"

static int cli_listen_fd = -1;

static void send_str(int fd, const char *s)
{
    write(fd, s, strlen(s));
}

static void show_all_sessions(int fd)
{
    char buf[256];

    send_str(fd, "=== BFD Sessions ===\n");

    for (int i = 0; i < BFD_MAX_SESSIONS; i++) {
        if (!sessions[i].used)
            continue;

        bfd_session_t *s = &sessions[i];

        const char *state =
            (s->state == BFD_STATE_UP) ? "UP" :
            (s->state == BFD_STATE_INIT) ? "INIT" :
            (s->state == BFD_STATE_DOWN) ? "DOWN" :
            "ADMIN_DOWN";

        char addrbuf[INET6_ADDRSTRLEN];
        uint16_t port = 0;

        if (s->peer_addr.ss_family == AF_INET) {
            struct sockaddr_in *p = (struct sockaddr_in *)&s->peer_addr;
            inet_ntop(AF_INET, &p->sin_addr, addrbuf, sizeof(addrbuf));
            port = ntohs(p->sin_port);
        } else {
            struct sockaddr_in6 *p = (struct sockaddr_in6 *)&s->peer_addr;
            inet_ntop(AF_INET6, &p->sin6_addr, addrbuf, sizeof(addrbuf));
            port = ntohs(p->sin6_port);
        }

        snprintf(buf, sizeof(buf),
                 "disc=%u peer=%s:%u state=%s tx=%uµs rx=%uµs mult=%u echo=%s\n",
                 s->my_disc, addrbuf, port, state,
                 s->min_tx, s->min_rx, s->detect_mult,
                 (s->echo_enabled ? "on" : "off"));

        send_str(fd, buf);
    }
}

static void show_one_session(int fd, uint32_t disc)
{
    bfd_session_t *s = bfd_session_find_by_my_disc(disc);
    if (!s) {
        send_str(fd, "No such session\n");
        return;
    }

    char buf[256];
    const char *state =
        (s->state == BFD_STATE_UP) ? "UP" :
        (s->state == BFD_STATE_INIT) ? "INIT" :
        (s->state == BFD_STATE_DOWN) ? "DOWN" :
        "ADMIN_DOWN";

    snprintf(buf, sizeof(buf),
             "Session %u\n"
             "  State: %s\n"
             "  My Disc: %u\n"
             "  Your Disc: %u\n"
             "  Min TX: %uµs\n"
             "  Min RX: %uµs\n"
             "  Calc Min TX: %uµs\n"
             "  Calc Min RX: %uµs\n"
             "  Detect Mult: %u\n"
             "  Echo: %s (min_echo=%uµs)\n",
             s->my_disc, state, s->my_disc, s->your_disc,
             s->min_tx, s->min_rx,  s->calculated_min_tx, s->calculated_min_rx, s->detect_mult,
             s->echo_enabled ? "on" : "off", s->min_echo);

    send_str(fd, buf);
}

static void cmd_add(int fd, char *line)
{
    char type[8], ip[64];
    unsigned disc;
    unsigned min_tx, min_rx;
    unsigned mult;
    unsigned echo_us = 0;

    int n = sscanf(line, "%7s %63s %u %u %u %u %u",
                   type, ip, &disc, &min_tx, &min_rx, &mult, &echo_us);
    if (n < 6) {
        send_str(fd, "Usage: add v4|v6 <ip> <disc> <min_tx_us> <min_rx_us> <mult> [echo_us]\n");
        return;
    }

    if (bfd_engine_mode == BFD_MODE_MULTIHOP && echo_us > 0) {
        send_str(fd, "Echo mode is not allowed in multihop BFD\n");
        return;
    }

    struct sockaddr_storage ss;
    socklen_t slen = 0;
    memset(&ss, 0, sizeof(ss));

    if (!strcmp(type, "v4")) {
        struct sockaddr_in sa;
        memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        sa.sin_port = htons(bfd_engine_mode == BFD_MODE_SINGLEHOP ?
                            BFD_PORT_SINGLEHOP : BFD_PORT_MULTIHOP);
        if (inet_pton(AF_INET, ip, &sa.sin_addr) != 1) {
            send_str(fd, "Invalid IPv4\n");
            return;
        }
        memcpy(&ss, &sa, sizeof(sa));
        slen = sizeof(sa);
    } else if (!strcmp(type, "v6")) {
        struct sockaddr_in6 sa6;
        memset(&sa6, 0, sizeof(sa6));
        sa6.sin6_family = AF_INET6;
        sa6.sin6_port = htons(bfd_engine_mode == BFD_MODE_SINGLEHOP ?
                              BFD_PORT_SINGLEHOP : BFD_PORT_MULTIHOP);
        if (inet_pton(AF_INET6, ip, &sa6.sin6_addr) != 1) {
            send_str(fd, "Invalid IPv6\n");
            return;
        }
        memcpy(&ss, &sa6, sizeof(sa6));
        slen = sizeof(sa6);
    } else {
        send_str(fd, "Type must be v4 or v6\n");
        return;
    }


    bfd_session_t *s = bfd_session_find_by_my_disc(disc);
    if (s) {
        send_str(fd, "Failed to create session, disc already exists.\n");
        return;
    }

    s = bfd_session_find_by_peer(&ss, slen);
    if (s) {
        send_str(fd, "Failed to create session, peer already exists.\n");
        return;
    }

    s = bfd_session_create(&ss, slen,
                                          disc,
                                          min_tx,
                                          min_rx,
                                          (uint8_t)mult,
                                          1);
    if (!s) {
        send_str(fd, "Failed to create session\n");
        return;
    }

    if (bfd_engine_mode == BFD_MODE_SINGLEHOP &&
        n == 7 && echo_us > 0) {
        s->echo_enabled = 1;
        s->min_echo = echo_us;
        s->next_echo_ns = bfd_now_ns() + (uint64_t)echo_us * 1000ULL;
    }

    send_str(fd, "Session added\n");
}

static void cmd_del(int fd, char *line)
{
    unsigned disc;
    if (sscanf(line, "%u", &disc) != 1) {
        send_str(fd, "Usage: del <disc>\n");
        return;
    }
    bfd_session_delete(disc);
    send_str(fd, "Session deleted (if it existed)\n");
}

static void cmd_down(int fd, char *line)
{
    unsigned disc;
    if (sscanf(line, "%u", &disc) != 1) {
        send_str(fd, "Usage: down <disc>\n");
        return;
    }
    bfd_session_down(disc);
    send_str(fd, "Session down (if it existed)\n");
}

static void cmd_up(int fd, char *line)
{
    unsigned disc;
    if (sscanf(line, "%u", &disc) != 1) {
        send_str(fd, "Usage: up <disc>\n");
        return;
    }
    bfd_session_up(disc);
    send_str(fd, "Session up (if it existed)\n");
}

void bfd_cli_handle(int fd, int epfd, int listen_fd)
{
    (void)epfd;
    (void)listen_fd;

    char buf[256];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    if (n <= 0) {
        close (fd);
        return;
    }
    buf[n] = 0;

    if (!strncmp(buf, "show sessions", 13)) {
        show_all_sessions(fd);
    } else if (!strncmp(buf, "show session", 12)) {
        unsigned disc = atoi(buf + 12);
        show_one_session(fd, disc);
    } else if (!strncmp(buf, "add ", 4)) {
        cmd_add(fd, buf + 4);
    } else if (!strncmp(buf, "del ", 4)) {
        cmd_del(fd, buf + 4); 
    } else if (!strncmp(buf, "down ", 5)) {
        cmd_down(fd, buf + 5);    
    } else if (!strncmp(buf, "up ", 3)) {
        cmd_up(fd, buf + 3);       
    } else {
        send_str(fd, "Commands:\n");
        send_str(fd, "  show sessions\n");
        send_str(fd, "  show session <disc>\n");
        send_str(fd, "  add v4|v6 <ip> <disc> <min_tx_us> <min_rx_us> <mult> [echo_us]\n");
        send_str(fd, "  del <disc>\n");
        send_str(fd, "  down <disc>\n");
        send_str(fd, "  up <disc>\n");
    }

    close (fd);
}

int bfd_cli_init(int epfd)
{
    unlink(BFD_CLI_SOCK);

    cli_listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (cli_listen_fd < 0) {
        perror("cli socket");
        return -1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, BFD_CLI_SOCK);

    if (bind(cli_listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("cli bind");
        close(cli_listen_fd);
        cli_listen_fd = -1;
        return -1;
    }

    if (listen(cli_listen_fd, 5) < 0) {
        perror("cli listen");
        close(cli_listen_fd);
        cli_listen_fd = -1;
        return -1;
    }

    struct epoll_event ev = {
        .events = EPOLLIN,
        .data.fd = cli_listen_fd
    };

    if (epoll_ctl(epfd, EPOLL_CTL_ADD, cli_listen_fd, &ev) < 0) {
        perror("cli epoll_ctl");
        close(cli_listen_fd);
        cli_listen_fd = -1;
        return -1;
    }

    printf("CLI ready at %s\n", BFD_CLI_SOCK);
    return cli_listen_fd;
}
