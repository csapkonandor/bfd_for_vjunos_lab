#include "bfd_engine.h"
#include "bfd_session.h"
#include "bfd_cli.h"

#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <ifaddrs.h>
#include <net/if.h>

#define MAX_EVENTS 64

int is_initiator = 0;

static int create_ctrl_socket(int mode)
{
    int sock = socket(AF_INET6, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return -1;
    }

    int v6only = 0;
    setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only));

    int ttl = 255;
    setsockopt(sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
    setsockopt(sock, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &ttl, sizeof(ttl));

    /* Enable receiving TTL / HopLimit */
    int enable = 1;
    setsockopt(sock, IPPROTO_IP, IP_RECVTTL, &enable, sizeof(enable));
    setsockopt(sock, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &enable, sizeof(enable));

    uint16_t port = (mode == BFD_MODE_SINGLEHOP)
        ? BFD_PORT_SINGLEHOP
        : BFD_PORT_MULTIHOP;

    struct sockaddr_in6 addr6;
    memset(&addr6, 0, sizeof(addr6));
    addr6.sin6_family = AF_INET6;
    addr6.sin6_addr = in6addr_any;
    addr6.sin6_port = htons(port);

    if (bind(sock, (struct sockaddr *)&addr6, sizeof(addr6)) < 0) {
        perror("bind");
        close(sock);
        return -1;
    }

    return sock;
}

static int create_echo_socket(void)
{
    /* Create a packet socket to send/receive full Ethernet frames */
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        perror("echo packet socket");
        return -1;
    }

    /* Enable receiving on the socket for all interfaces */
    return sock;
}

static int bfd_alloc_local_disc()
{
    static int local_disc = 1000;
    local_disc++;
    return local_disc;
}

int bfd_engine_run(int mode)
{
    bfd_engine_mode = mode;

    int ctrl_sock = create_ctrl_socket(mode);
    if (ctrl_sock < 0)
        return 1;

    int echo_sock = -1;
    if (mode == BFD_MODE_SINGLEHOP) {
        echo_sock = create_echo_socket();
        if (echo_sock < 0) {
            close(ctrl_sock);
            return 1;
        }
        bfd_echo_sock_fd = echo_sock;
    }

    int epfd = epoll_create1(0);
    if (epfd < 0) {
        perror("epoll_create1");
        close(ctrl_sock);
        if (echo_sock >= 0) close(echo_sock);
        return 1;
    }

    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLIN;
    ev.data.fd = ctrl_sock;
    epoll_ctl(epfd, EPOLL_CTL_ADD, ctrl_sock, &ev);

    if (echo_sock >= 0) {
        struct epoll_event ev2;
        memset(&ev2, 0, sizeof(ev2));
        ev2.events = EPOLLIN;
        ev2.data.fd = echo_sock;
        epoll_ctl(epfd, EPOLL_CTL_ADD, echo_sock, &ev2);
    }

    bfd_session_init();
    int cli_listen_fd = bfd_cli_init(epfd);

    printf("BFD engine running in %s mode on UDP port %d\n",
           mode == BFD_MODE_SINGLEHOP ? "single-hop" : "multihop",
           mode == BFD_MODE_SINGLEHOP ? BFD_PORT_SINGLEHOP : BFD_PORT_MULTIHOP);

    while (1) {
        struct epoll_event events[MAX_EVENTS];
        //int n = epoll_wait(epfd, events, MAX_EVENTS, 50);
        
        int n;
        do {
            n = epoll_wait(epfd, events, MAX_EVENTS, 50);
        } while (n < 0 && errno == EINTR);

        if (n < 0) {
            perror("epoll_wait");
            break;
        }

        for (int i = 0; i < n; i++) {
            int fd = events[i].data.fd;

            if (!(events[i].events & EPOLLIN))
                continue;

            /* ---------------- CONTROL PACKET ---------------- */
            if (fd == ctrl_sock) {

                struct sockaddr_storage src;
                socklen_t srclen = sizeof(src);
                struct bfd_ctrl pkt;
                char cbuf[128];

                struct iovec iov = {
                    .iov_base = &pkt,
                    .iov_len  = sizeof(pkt)
                };

                struct msghdr msg;
                memset(&msg, 0, sizeof(msg));
                msg.msg_name       = &src;
                msg.msg_namelen    = srclen;
                msg.msg_iov        = &iov;
                msg.msg_iovlen     = 1;
                msg.msg_control    = cbuf;
                msg.msg_controllen = sizeof(cbuf);

                ssize_t r = recvmsg(ctrl_sock, &msg, 0);
                if (r < (ssize_t)sizeof(struct bfd_ctrl))
                    continue;

                /* TTL / HopLimit validation */
                int ttl_ok = 0;

                for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
                     cmsg != NULL;
                     cmsg = CMSG_NXTHDR(&msg, cmsg))
                {
                    if (cmsg->cmsg_level == IPPROTO_IP &&
                        cmsg->cmsg_type == IP_TTL)
                    {
                        int ttl = *(int *)CMSG_DATA(cmsg);
                        if (ttl == 255)
                            ttl_ok = 1;
                    }

                    if (cmsg->cmsg_level == IPPROTO_IPV6 &&
                        cmsg->cmsg_type == IPV6_HOPLIMIT)
                    {
                        int hop = *(int *)CMSG_DATA(cmsg);
                        if (hop == 255)
                            ttl_ok = 1;
                    }
                }

                if (mode == BFD_MODE_SINGLEHOP && !ttl_ok)
                    continue;

                /* Session lookup */
                uint32_t my_disc = ntohl(pkt.your_disc);
                uint32_t your_disc = ntohl(pkt.my_disc);

                bfd_session_t *sess = NULL;

                if (my_disc)
                    sess = bfd_session_find_by_my_disc(my_disc);
                if (!sess && your_disc)
                    sess = bfd_session_find_by_your_disc(your_disc);
                if (!sess)
                    sess = bfd_session_find_by_peer(&src, srclen);


                /* 2. If still no session, create a new one */
                if (!is_initiator && !sess) {
                    /* Only create a session if the packet is valid and has a peer discriminator */
                    if (my_disc == 0) {
                        my_disc = bfd_alloc_local_disc();
                    }

                    /* Peer does not yet know our discriminator — discovery phase */
                    sess = bfd_session_create(&src, srclen, my_disc, BFD_DEFAULT_MIN_TX, BFD_DEFAULT_MIN_RX, BFD_DEFAULT_DETECT, 0);
                    if (!sess)
                        continue;
                
                    /* Store peer discriminator (may be zero) */
                    sess->your_disc = your_disc;
                }
                

                if (!sess) {
                    continue;
                }

                bfd_session_handle_rx(ctrl_sock, sess, &src, srclen, &pkt);

            }
            /* ---------------- ECHO PACKET ---------------- */
            else if (mode == BFD_MODE_SINGLEHOP && echo_sock >= 0 && fd == echo_sock) {

                unsigned char buf[2048];
                struct sockaddr_ll from_ll;
                socklen_t slen = sizeof(from_ll);

                ssize_t r = recvfrom(echo_sock, buf, sizeof(buf), 0,
                                     (struct sockaddr *)&from_ll, &slen);
                if (r <= 0)
                    continue;

                /* Parse Ethernet frame */
                if ((size_t)r < sizeof(struct ether_header))
                    continue;

                struct ether_header *eh = (struct ether_header *)buf;
                uint16_t ethertype = ntohs(eh->ether_type);

                struct sockaddr_storage src_ss;
                socklen_t src_len = 0;
                memset(&src_ss, 0, sizeof(src_ss));

                if (ethertype == ETH_P_IP) {
                    if ((size_t)r < sizeof(struct ether_header) + sizeof(struct iphdr))
                        continue;
                    struct iphdr *iph = (struct iphdr *)(buf + sizeof(struct ether_header));
                    src_ss.ss_family = AF_INET;
                    struct sockaddr_in *sin = (struct sockaddr_in *)&src_ss;
                    sin->sin_family = AF_INET;
                    sin->sin_addr.s_addr = iph->saddr;
                    sin->sin_port = htons(BFD_ECHO_PORT);
                    src_len = sizeof(struct sockaddr_in);
                    /* Check UDP and port */
                    if (iph->protocol != IPPROTO_UDP)
                        continue;
                    size_t iphdr_len = iph->ihl * 4;
                    if ((size_t)r < sizeof(struct ether_header) + iphdr_len + sizeof(struct udphdr))
                        continue;
                    struct udphdr *udph = (struct udphdr *)(buf + sizeof(struct ether_header) + iphdr_len);
                    if (ntohs(udph->dest) != BFD_ECHO_PORT)
                        continue;

                } else if (ethertype == ETH_P_IPV6) {
                    if ((size_t)r < sizeof(struct ether_header) + sizeof(struct ip6_hdr))
                        continue;
                    struct ip6_hdr *ip6h = (struct ip6_hdr *)(buf + sizeof(struct ether_header));
                    src_ss.ss_family = AF_INET6;
                    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&src_ss;
                    sin6->sin6_family = AF_INET6;
                    memcpy(&sin6->sin6_addr, &ip6h->ip6_src, sizeof(struct in6_addr));
                    sin6->sin6_port = htons(BFD_ECHO_PORT);
                    src_len = sizeof(struct sockaddr_in6);
                    /* Only handle UDP */
                    if (ip6h->ip6_nxt != IPPROTO_UDP)
                        continue;
                    /* Very basic check for UDP dest port */
                    size_t ip6hdr_len = sizeof(struct ip6_hdr);
                    if ((size_t)r < sizeof(struct ether_header) + ip6hdr_len + sizeof(struct udphdr))
                        continue;
                    struct udphdr *udph = (struct udphdr *)(buf + sizeof(struct ether_header) + ip6hdr_len);
                    if (ntohs(udph->dest) != BFD_ECHO_PORT)
                        continue;
                } else {
                    continue;
                }

                bfd_session_t *s = bfd_session_find_by_peer(&src_ss, src_len);
                if (s && s->echo_enabled) {
                    s->detect_time_ns = bfd_now_ns() +
                        (uint64_t)s->min_rx * s->detect_mult * 1000ULL;
                }

            }
            /* ---------------- CLI LISTEN SOCKET ---------------- */
            else if (cli_listen_fd >= 0 && fd == cli_listen_fd) {

                int client = accept(cli_listen_fd, NULL, NULL);
                if (client >= 0) {
                    struct epoll_event cev;
                    memset(&cev, 0, sizeof(cev));
                    cev.events  = EPOLLIN;
                    cev.data.fd = client;
                    if (epoll_ctl(epfd, EPOLL_CTL_ADD, client, &cev) < 0) {
                        perror("epoll_ctl cli client");
                        close(client);
                    }
                }
            }
            /* ---------------- CLI CLIENT SOCKET ---------------- */
            else if (cli_listen_fd >= 0) {
                /* Anything that's not ctrl/echo/cli_listen is treated as CLI client */
                bfd_cli_handle(fd, epfd, cli_listen_fd);
            }
            else {
            }
        }

        bfd_session_check_timers(ctrl_sock);
    }

    close(epfd);
    close(ctrl_sock);
    if (echo_sock >= 0) close(echo_sock);
    return 0;
}

