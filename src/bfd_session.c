#include "bfd_session.h"
#include <string.h>
#include <stdio.h>
#include <time.h>
//#include <linux/time.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <fcntl.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ip6.h>
#include <stdlib.h>

bfd_session_t sessions[BFD_MAX_SESSIONS];
int bfd_engine_mode = BFD_MODE_MULTIHOP;
int bfd_echo_sock_fd = -1;

static int hash_table[BFD_HASH_SIZE];

static uint32_t bfd_hash_disc(uint32_t disc)
{
    return (disc * 2654435761u) % BFD_HASH_SIZE;
}

/* Helper: compute IPv4 header checksum */
static uint16_t ip_checksum(void *vdata, size_t length)
{
    char *data = (char *)vdata;
    uint64_t acc = 0xffff;

    for (size_t i = 0; i + 1 < length; i += 2) {
        uint16_t word;
        memcpy(&word, data + i, 2);
        acc += ntohs(word);
        if (acc > 0xffff) acc -= 0xffff;
    }
    if (length & 1) {
        uint16_t word = (uint8_t)data[length - 1] << 8;
        acc += ntohs(word);
        if (acc > 0xffff) acc -= 0xffff;
    }
    return htons(~acc & 0xffff);
}

/* Parse /proc/net/arp for IPv4 MAC for given ip string. Returns 0 on success */
static int arp_lookup_ipv4(const char *ipstr, unsigned char out_mac[6], char *out_iface, size_t iface_len)
{
    FILE *f = fopen("/proc/net/arp", "r");
    if (!f)
        return -1;
    char line[256];
    /* skip header */
    fgets(line, sizeof(line), f);
    while (fgets(line, sizeof(line), f)) {
        char ip[64], hw_type[64], flags[64], mac[64], mask[64], device[64];
        if (sscanf(line, "%63s %63s %63s %63s %63s %63s",
                   ip, hw_type, flags, mac, mask, device) != 6)
            continue;
        if (strcmp(ip, ipstr) == 0) {
            if (strcmp(mac, "00:00:00:00:00:00") == 0) {
                fclose(f);
                return -1;
            }
            int vals[6];
            if (sscanf(mac, "%x:%x:%x:%x:%x:%x",
                       &vals[0], &vals[1], &vals[2], &vals[3], &vals[4], &vals[5]) != 6)
            {
                fclose(f);
                return -1;
            }
            for (int i = 0; i < 6; i++)
                out_mac[i] = (unsigned char)vals[i];
            strncpy(out_iface, device, iface_len - 1);
            out_iface[iface_len - 1] = '\0';
            fclose(f);
            return 0;
        }
    }
    fclose(f);
    return -1;
}

/* Very small helper to lookup IPv6 neighbor from /proc/net/ndisc_cache (best-effort) */
static int ndisc_lookup_ipv6(const char *ipstr, unsigned char out_mac[6], char *out_iface, size_t iface_len)
{
    FILE *f = fopen("/proc/net/ndisc_cache", "r");
    if (!f)
        return -1;
    char line[512];
    /* Try to find a matching IPv6 entry */
    while (fgets(line, sizeof(line), f)) {
        char iface[128];
        char ip[128];
        char mac[64];
        if (sscanf(line, "%127s %127s %63s", iface, ip, mac) < 3)
            continue;
        if (strcmp(ip, ipstr) == 0) {
            int vals[6];
            if (sscanf(mac, "%x:%x:%x:%x:%x:%x",
                       &vals[0], &vals[1], &vals[2], &vals[3], &vals[4], &vals[5]) != 6)
            {
                fclose(f);
                return -1;
            }
            for (int i = 0; i < 6; i++)
                out_mac[i] = (unsigned char)vals[i];
            strncpy(out_iface, iface, iface_len - 1);
            out_iface[iface_len - 1] = '\0';
            fclose(f);
            return 0;
        }
    }
    fclose(f);
    return -1;
}

int bfd_send_echo(bfd_session_t *s)
{
    if (!s)
        return -1;

    char peer_str[INET6_ADDRSTRLEN];
    char local_ip_str[INET6_ADDRSTRLEN];
    char iface[IFNAMSIZ] = {0};
    unsigned char peer_mac[6] = {0};
    unsigned char local_mac[6] = {0};
    int ifindex = 0;
    int packet_sock = bfd_echo_sock_fd;

    /* Build peer address string */
    if (s->peer_addr.ss_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)&s->peer_addr;
        inet_ntop(AF_INET, &sin->sin_addr, peer_str, sizeof(peer_str));
    } else if (s->peer_addr.ss_family == AF_INET6) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&s->peer_addr;
        inet_ntop(AF_INET6, &sin6->sin6_addr, peer_str, sizeof(peer_str));
    } else {
        return -1;
    }

    /* Lookup peer MAC from ARP/ND */
    int have_mac = -1;
    if (s->peer_mac[0] != 0) {
        /* Use cached MAC */
        have_mac = 1;
        memcpy(peer_mac, s->peer_mac, 6);
        strncpy(iface, s->iface, sizeof(iface) - 1);
        iface[sizeof(iface) - 1] = '\0';
    } else {
        if (s->peer_addr.ss_family == AF_INET) {
            have_mac = (arp_lookup_ipv4(peer_str, peer_mac, iface, sizeof(iface)) == 0);
        } else {
            have_mac = (ndisc_lookup_ipv6(peer_str, peer_mac, iface, sizeof(iface)) == 0);
        }
        if (!have_mac) {
            /* Try to force ARP update with ping */
            char ping_cmd[256];
            if (s->peer_addr.ss_family == AF_INET) {
                snprintf(ping_cmd, sizeof(ping_cmd), "ping -c 1 -W 1 %s >/dev/null 2>&1", peer_str);
            } else {
                snprintf(ping_cmd, sizeof(ping_cmd), "ping6 -c 1 -W 1 %s >/dev/null 2>&1", peer_str);
            }
            system(ping_cmd);
            usleep(100000); /* Wait 100ms for ARP table update */
            /* Retry lookup */
            if (s->peer_addr.ss_family == AF_INET) {
                have_mac = (arp_lookup_ipv4(peer_str, peer_mac, iface, sizeof(iface)) == 0);
            } else {
                have_mac = (ndisc_lookup_ipv6(peer_str, peer_mac, iface, sizeof(iface)) == 0);
            }
            if (!have_mac) {
                /* Can't send echo without L2 address */
                return -1;
            }
        }
        /* Cache the MAC and iface */
        memcpy(s->peer_mac, peer_mac, 6);
        strncpy(s->iface, iface, sizeof(s->iface) - 1);
        s->iface[sizeof(s->iface) - 1] = '\0';
    }

    /* Determine local interface and MAC by creating a UDP socket and connecting */
    if (s->peer_addr.ss_family == AF_INET) {
        int ud = socket(AF_INET, SOCK_DGRAM, 0);
        if (ud < 0) return -1;
        /* connect to peer to get outgoing interface/IP */
        if (connect(ud, (struct sockaddr *)&s->peer_addr, s->peer_len) < 0) {
            close(ud);
            return -1;
        }
        struct sockaddr_in local;
        socklen_t l = sizeof(local);
        if (getsockname(ud, (struct sockaddr *)&local, &l) < 0) {
            close(ud);
            return -1;
        }
        inet_ntop(AF_INET, &local.sin_addr, local_ip_str, sizeof(local_ip_str));
        close(ud);
    } else {
        int ud = socket(AF_INET6, SOCK_DGRAM, 0);
        if (ud < 0) return -1;
        if (connect(ud, (struct sockaddr *)&s->peer_addr, s->peer_len) < 0) {
            close(ud);
            return -1;
        }
        struct sockaddr_in6 local6;
        socklen_t l = sizeof(local6);
        if (getsockname(ud, (struct sockaddr *)&local6, &l) < 0) {
            close(ud);
            return -1;
        }
        inet_ntop(AF_INET6, &local6.sin6_addr, local_ip_str, sizeof(local_ip_str));
        close(ud);
    }

    /* Use getifaddrs to find interface index and local MAC */
    struct ifaddrs *ifap, *ifa;
    if (getifaddrs(&ifap) != 0)
        return -1;
    for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr)
            continue;
        if (ifa->ifa_addr->sa_family == AF_PACKET) {
            struct sockaddr_ll *sll = (struct sockaddr_ll *)ifa->ifa_addr;
            if (strcmp(ifa->ifa_name, iface) == 0 || iface[0] == '\0') {
                ifindex = sll->sll_ifindex;
                if (sll->sll_halen >= 6)
                    memcpy(local_mac, sll->sll_addr, 6);
                strncpy(iface, ifa->ifa_name, sizeof(iface)-1);
                break;
            }
        }
    }
    freeifaddrs(ifap);

    if (ifindex == 0)
        return -1;

    /* Ensure we have a packet socket */
    if (packet_sock < 0) {
        packet_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if (packet_sock < 0)
            return -1;
    }

    /* Build Ethernet + IP + UDP + payload (IPv4 only for now; IPv6 basic support fallback)
     * Payload same as before: 8 bytes
     */
    unsigned char payload[8] = { 'B','F','D','E','C','H','O','!' };

    if (s->peer_addr.ss_family == AF_INET) {
        unsigned char sendbuf[1500];
        struct ether_header *eh = (struct ether_header *)sendbuf;
        memcpy(eh->ether_dhost, peer_mac, 6);
        memcpy(eh->ether_shost, local_mac, 6);
        eh->ether_type = htons(ETH_P_IP);

        struct ip *iph = (struct ip *)(sendbuf + sizeof(struct ether_header));
        struct udphdr *udph = (struct udphdr *)((unsigned char *)iph + sizeof(struct ip));
        size_t ip_len = sizeof(struct ip);
        size_t udp_len = sizeof(struct udphdr) + sizeof(payload);
        size_t total_len = sizeof(struct ether_header) + ip_len + udp_len;

        iph->ip_hl = 5;
        iph->ip_v = 4;
        iph->ip_tos = 0;
        iph->ip_len = htons(ip_len + udp_len);
        iph->ip_id = htons(0);
        iph->ip_off = 0;
        iph->ip_ttl = 255;
        iph->ip_p = IPPROTO_UDP;

        struct sockaddr_in *sin = (struct sockaddr_in *)&s->peer_addr;
        /* Determine source address (local_ip_str) */
        struct in_addr src_addr;
        inet_pton(AF_INET, local_ip_str, &src_addr);
        iph->ip_src = src_addr;
        iph->ip_dst = sin->sin_addr;
        iph->ip_sum = 0;
        iph->ip_sum = ip_checksum(iph, sizeof(struct ip));

        udph->uh_sport = htons(BFD_ECHO_PORT);
        udph->uh_dport = htons(BFD_ECHO_PORT);
        udph->uh_ulen = htons((uint16_t)udp_len);
        udph->uh_sum = 0; /* skip UDP checksum for IPv4 */

        unsigned char *p = (unsigned char *)udph + sizeof(struct udphdr);
        memcpy(p, payload, sizeof(payload));

        struct sockaddr_ll dst;
        memset(&dst, 0, sizeof(dst));
        dst.sll_family = AF_PACKET;
        dst.sll_ifindex = ifindex;
        dst.sll_halen = ETH_ALEN;
        memcpy(dst.sll_addr, peer_mac, 6);

        ssize_t sent = sendto(packet_sock, sendbuf, total_len, 0,
                              (struct sockaddr *)&dst, sizeof(dst));
        if (sent < 0) {
            if (packet_sock != bfd_echo_sock_fd)
                close(packet_sock);
            return -1;
        }

        if (packet_sock != bfd_echo_sock_fd)
            close(packet_sock);
        return 0;
    } else if (s->peer_addr.ss_family == AF_INET6) {
        /* IPv6: build IPv6 + UDP + payload and send over AF_PACKET (if neighbor found)
         * For brevity, we craft IPv6 header with no extension headers and compute UDP checksum.
         */
        unsigned char sendbuf[1500];
        struct ether_header *eh = (struct ether_header *)sendbuf;
        memcpy(eh->ether_dhost, peer_mac, 6);
        memcpy(eh->ether_shost, local_mac, 6);
        eh->ether_type = htons(ETH_P_IPV6);

        struct ip6_hdr *ip6h = (struct ip6_hdr *)(sendbuf + sizeof(struct ether_header));
        struct udphdr *udph = (struct udphdr *)((unsigned char *)ip6h + sizeof(struct ip6_hdr));
        size_t udp_len = sizeof(struct udphdr) + sizeof(payload);
        size_t total_len = sizeof(struct ether_header) + sizeof(struct ip6_hdr) + udp_len;

        ip6h->ip6_flow = 0;
        ip6h->ip6_vfc = 6 << 4;
        ip6h->ip6_plen = htons((uint16_t)udp_len);
        ip6h->ip6_nxt = IPPROTO_UDP;
        ip6h->ip6_hlim = 255;

        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&s->peer_addr;
        /* source addr */
        inet_pton(AF_INET6, local_ip_str, &ip6h->ip6_src);
        memcpy(&ip6h->ip6_dst, &sin6->sin6_addr, sizeof(struct in6_addr));

        udph->uh_sport = htons(BFD_ECHO_PORT);
        udph->uh_dport = htons(BFD_ECHO_PORT);
        udph->uh_ulen = htons((uint16_t)udp_len);
        udph->uh_sum = 0; /* will compute below */

        unsigned char *p = (unsigned char *)udph + sizeof(struct udphdr);
        memcpy(p, payload, sizeof(payload));

        /* Compute UDP checksum for IPv6 pseudo-header */
        struct {
            struct in6_addr src;
            struct in6_addr dst;
            uint32_t len;
            uint8_t zero[3];
            uint8_t nxt;
        } pseudo;
        memcpy(&pseudo.src, &ip6h->ip6_src, sizeof(pseudo.src));
        memcpy(&pseudo.dst, &ip6h->ip6_dst, sizeof(pseudo.dst));
        pseudo.len = htonl((uint32_t)udp_len);
        memset(pseudo.zero, 0, sizeof(pseudo.zero));
        pseudo.nxt = IPPROTO_UDP;

        size_t csum_len = sizeof(pseudo) + udp_len;
        unsigned char *csum_buf = malloc(csum_len);
        if (!csum_buf) {
            if (packet_sock != bfd_echo_sock_fd)
                close(packet_sock);
            return -1;
        }
        memcpy(csum_buf, &pseudo, sizeof(pseudo));
        memcpy(csum_buf + sizeof(pseudo), udph, udp_len);
        uint16_t sum = ip_checksum(csum_buf, csum_len);
        free(csum_buf);
        udph->uh_sum = sum;

        struct sockaddr_ll dst;
        memset(&dst, 0, sizeof(dst));
        dst.sll_family = AF_PACKET;
        dst.sll_ifindex = ifindex;
        dst.sll_halen = ETH_ALEN;
        memcpy(dst.sll_addr, peer_mac, 6);

        ssize_t sent = sendto(packet_sock, sendbuf, total_len, 0,
                              (struct sockaddr *)&dst, sizeof(dst));
        if (sent < 0) {
            if (packet_sock != bfd_echo_sock_fd)
                close(packet_sock);
            return -1;
        }

        if (packet_sock != bfd_echo_sock_fd)
            close(packet_sock);
        return 0;
    }

    return -1;
}

static void bfd_hash_init(void)
{
    for (int i = 0; i < BFD_HASH_SIZE; i++)
        hash_table[i] = -1;
}

uint64_t bfd_now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static void bfd_hash_insert(uint32_t disc, int idx)
{
    uint32_t h = bfd_hash_disc(disc);
    for (int i = 0; i < BFD_HASH_SIZE; i++) {
        uint32_t pos = (h + i) % BFD_HASH_SIZE;
        if (hash_table[pos] == -1) {
            hash_table[pos] = idx;
            return;
        }
    }
}

bfd_session_t *bfd_session_find_by_my_disc(uint32_t disc)
{
    uint32_t h = bfd_hash_disc(disc);
    for (int i = 0; i < BFD_HASH_SIZE; i++) {
        uint32_t pos = (h + i) % BFD_HASH_SIZE;
        int idx = hash_table[pos];
        if (idx == -1)
            return NULL;
        if (sessions[idx].used && sessions[idx].my_disc == disc)
            return &sessions[idx];
    }
    return NULL;
}

bfd_session_t *bfd_session_find_by_your_disc(uint32_t your_disc)
{
    if (!your_disc)
        return NULL;
    for (int i = 0; i < BFD_MAX_SESSIONS; i++) {
        if (sessions[i].used && sessions[i].your_disc == your_disc)
            return &sessions[i];
    }
    return NULL;
}

static int addr_equal(const struct sockaddr_storage *a, socklen_t alen,
                      const struct sockaddr_storage *b, socklen_t blen)
{
    if (a->ss_family != b->ss_family || alen != blen)
        return 0;
    if (a->ss_family == AF_INET) {
        const struct sockaddr_in *ia = (const struct sockaddr_in *)a;
        const struct sockaddr_in *ib = (const struct sockaddr_in *)b;
        return ia->sin_addr.s_addr == ib->sin_addr.s_addr &&
               ia->sin_port == ib->sin_port;
    } else if (a->ss_family == AF_INET6) {
        const struct sockaddr_in6 *ia = (const struct sockaddr_in6 *)a;
        const struct sockaddr_in6 *ib = (const struct sockaddr_in6 *)b;
        return memcmp(&ia->sin6_addr, &ib->sin6_addr,
                      sizeof(struct in6_addr)) == 0 &&
               ia->sin6_port == ib->sin6_port;
    }
    return 0;
}

bfd_session_t *bfd_session_find_by_peer(const struct sockaddr_storage *peer,
                                        socklen_t peer_len)
{
    for (int i = 0; i < BFD_MAX_SESSIONS; i++) {
        if (sessions[i].used &&
            addr_equal(&sessions[i].peer_addr, sessions[i].peer_len,
                       peer, peer_len)) {
            return &sessions[i];
        }
    }
    return NULL;
}

void bfd_session_init()
{

    static int initialized = 0;
    if (!initialized) {
        bfd_hash_init();
        memset(sessions, 0, sizeof(sessions));
        initialized = 1;
    }
}

bfd_session_t *bfd_session_create(const struct sockaddr_storage *peer,
                                  socklen_t peer_len,
                                  uint32_t my_disc,
                                  uint32_t min_tx,
                                  uint32_t min_rx,
                                  uint8_t detect_mult,
                                  int is_initiator)
{
    bfd_session_init();

    for (int i = 0; i < BFD_MAX_SESSIONS; i++) {
        if (!sessions[i].used) {
            bfd_session_t *s = &sessions[i];
            memset(s, 0, sizeof(*s));
            s->used = 1;
            s->is_initiator = is_initiator;
            memcpy(&s->peer_addr, peer, peer_len);
            s->peer_len = peer_len;
            s->my_disc = my_disc;
            s->state = is_initiator ? BFD_STATE_INIT : BFD_STATE_DOWN;
            s->detect_mult = detect_mult ? detect_mult : BFD_DEFAULT_DETECT;
            s->min_tx = min_tx;
            s->min_rx = min_rx;
            s->calculated_min_tx = min_tx;
            s->calculated_min_rx = min_rx;

            // Echo only allowed in single-hop; default off here.
            s->echo_enabled = 0;
            s->min_echo = 0;

            uint64_t now = bfd_now_ns();
            s->next_tx_ns = now + (uint64_t)min_tx * 1000ULL;
            s->detect_time_ns = now +
                (uint64_t)min_rx * s->detect_mult * 1000ULL;

            bfd_hash_insert(my_disc, i);

            char buf[INET6_ADDRSTRLEN];
            void *addr_ptr = NULL;
            uint16_t port = 0;

            if (peer->ss_family == AF_INET) {
                const struct sockaddr_in *p =
                    (const struct sockaddr_in *)peer;
                addr_ptr = (void *)&p->sin_addr;
                port = ntohs(p->sin_port);
            } else if (peer->ss_family == AF_INET6) {
                const struct sockaddr_in6 *p =
                    (const struct sockaddr_in6 *)peer;
                addr_ptr = (void *)&p->sin6_addr;
                port = ntohs(p->sin6_port);
            }

            if (addr_ptr) {
                inet_ntop(peer->ss_family, addr_ptr, buf, sizeof(buf));
                printf("Created session disc=%u peer=%s:%u tx=%uµs rx=%uµs mult=%u mode=%s\n",
                       my_disc, buf, port, min_tx, min_rx, s->detect_mult,
                       bfd_engine_mode == BFD_MODE_SINGLEHOP ? "single-hop" : "multihop");
            }

            return s;
        }
    }
    fprintf(stderr, "No free BFD session slots\n");
    return NULL;
}

void bfd_session_delete(uint32_t disc)
{
    bfd_session_t *s = bfd_session_find_by_my_disc(disc);
    if (!s)
        return;
    //printf("Deleting session %u\n", disc);
    memset(s, 0, sizeof(*s));
    // hash table not cleaned for simplicity in this demo
}

void bfd_session_down(uint32_t disc)
{
    bfd_session_t *s = bfd_session_find_by_my_disc(disc);
    if (!s)
        return;
    //printf("Admin down session %u\n", disc);
    s->state = BFD_STATE_ADMIN_DOWN;
    s->admin_down_by_command = 1;
}

void bfd_session_up(uint32_t disc)
{
    bfd_session_t *s = bfd_session_find_by_my_disc(disc);
    if (!s)
        return;
    if (!(s->admin_down_by_command))
        return;
    //printf("Resume session %u\n", disc);
    s->state = s->is_initiator ? BFD_STATE_INIT : BFD_STATE_DOWN;
    s->admin_down_sent = 0;
    s->admin_down_by_command = 0;
    s->your_disc = 0;
}

void bfd_session_trigger_poll(bfd_session_t *s)
{
    s->poll_pending = 1;
}

void bfd_session_send_ctrl(int sockfd, bfd_session_t *s)
{
    struct bfd_ctrl pkt;
    memset(&pkt, 0, sizeof(pkt));

    bfd_set_version_diag(&pkt, 0);
    bfd_set_state(&pkt, s->state);
    pkt.detect_mult = s->detect_mult;
    pkt.length = 24;
    pkt.my_disc = htonl(s->my_disc);
    pkt.your_disc = htonl(s->your_disc);
    pkt.min_tx = htonl(s->min_tx);
    pkt.min_rx = htonl(s->min_rx);
    pkt.echo_rx = htonl(s->min_echo);

    if (s->poll_pending)
        pkt.flags |= BFD_FLAG_POLL;

    if (bfd_engine_mode == BFD_MODE_MULTIHOP)
        pkt.flags |= BFD_FLAG_MULTIHOP;

    sendto(sockfd, &pkt, sizeof(pkt), 0,
           (struct sockaddr *)&s->peer_addr, s->peer_len);

    s->next_tx_ns = bfd_now_ns() + (uint64_t)s->calculated_min_tx * 1000ULL;
}


#define max(a,b) \
   ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
     _a > _b ? _a : _b; })


void bfd_session_handle_rx(int sockfd,
                           bfd_session_t *sess,
                           const struct sockaddr_storage *src,
                           socklen_t srclen,
                           const struct bfd_ctrl *pkt)
{
    (void)src;
    (void)srclen;

    uint8_t rstate = bfd_get_state(pkt);
    uint32_t r_my_disc = ntohl(pkt->my_disc);
    uint32_t r_your_disc = ntohl(pkt->your_disc);
    uint8_t flags = pkt->flags;

    if (r_your_disc && r_your_disc != sess->my_disc)
        return;

    if (!sess->your_disc)
        sess->your_disc = r_my_disc;

    // calculeted min_rx/tx should be set so that neither party should be forced to be faster 
    uint32_t pkt_min_tx = ntohl(pkt->min_tx);
    uint32_t pkt_min_rx = ntohl(pkt->min_rx);
    sess->calculated_min_rx = max (sess->min_rx, pkt_min_tx);
    sess->calculated_min_tx = max (sess->min_tx, pkt_min_rx); 

    sess->detect_time_ns = bfd_now_ns() +
        (uint64_t)sess->calculated_min_rx * sess->detect_mult * 1000ULL;

    if (flags & BFD_FLAG_POLL) {
        struct bfd_ctrl reply = *pkt;
        reply.flags |= BFD_FLAG_FINAL;
        reply.flags &= ~BFD_FLAG_POLL;
        reply.my_disc = htonl(sess->my_disc);
        reply.your_disc = htonl(sess->your_disc);
        sendto(sockfd, &reply, sizeof(reply), 0,
               (struct sockaddr *)&sess->peer_addr, sess->peer_len);
    }

    if (flags & BFD_FLAG_FINAL) {
        sess->poll_pending = 0;
        printf("Session %u: Poll complete (Final received)\n", sess->my_disc);
    }

    uint8_t old = sess->state;

    switch (sess->state) {
    case BFD_STATE_DOWN:
        if (rstate == BFD_STATE_INIT || rstate == BFD_STATE_UP) {
            sess->state = BFD_STATE_UP;
        } else if (rstate == BFD_STATE_DOWN) {
            sess->state = BFD_STATE_INIT;
        
        } else if (rstate == BFD_STATE_ADMIN_DOWN) {
            sess->state = BFD_STATE_ADMIN_DOWN; 
        } 
        else {
        }
        break;
    case BFD_STATE_INIT:
        if (rstate == BFD_STATE_INIT || rstate == BFD_STATE_UP) {
            sess->state = BFD_STATE_UP;
        } else if (rstate == BFD_STATE_ADMIN_DOWN) {
            sess->state = BFD_STATE_ADMIN_DOWN;
        }
        break;
    case BFD_STATE_UP:
        if (rstate == BFD_STATE_ADMIN_DOWN) {
            sess->state = rstate;
        }
        break;
    case BFD_STATE_ADMIN_DOWN:
        if (!(sess->admin_down_by_command))
        {
            //Handle as regular down if the admin down is due to the peer
            if (rstate == BFD_STATE_INIT) {
                sess->state = BFD_STATE_UP;
            } else if (rstate == BFD_STATE_DOWN) {
                sess->state = BFD_STATE_INIT;
            } else if (rstate == BFD_STATE_ADMIN_DOWN) {
                sess->state = BFD_STATE_ADMIN_DOWN; 
            } 
            else {
            }
        }
        break;
    default:
        break;
    }

    if (sess->state != old) {
        printf("Session %u state %u -> %u\n",
               sess->my_disc, old, sess->state);
        if (sess->state == BFD_STATE_UP) {
            bfd_session_trigger_poll(sess);
            bfd_session_send_ctrl(sockfd, sess);
        }
    }
}

void bfd_session_check_timers(int ctrl_sock)
{
    uint64_t now = bfd_now_ns();

    for (int i = 0; i < BFD_MAX_SESSIONS; i++) {
        if (!sessions[i].used)
            continue;
        bfd_session_t *s = &sessions[i];

        if (s->state == BFD_STATE_ADMIN_DOWN && s->admin_down_sent >= BFD_MAX_ADMIN_DOWN_SEND) {
            continue;
        }

        if (now >= s->next_tx_ns) {
            if (s->state == BFD_STATE_ADMIN_DOWN)
            {
                s->admin_down_sent += 1; 
            }
            bfd_session_send_ctrl(ctrl_sock, s);
        }
        if (bfd_engine_mode == BFD_MODE_SINGLEHOP &&
            s->echo_enabled &&
            s->min_echo &&
            now >= s->next_echo_ns) {

            if (bfd_send_echo(s) == 0) {
                s->next_echo_ns = now + (uint64_t)s->min_echo * 1000ULL;
            }
        }

        if (now >= s->detect_time_ns) {
            if (s->state == BFD_STATE_UP || s->state == BFD_STATE_INIT) {
                s->state = BFD_STATE_DOWN;
                printf("Session %u DOWN (detection timeout)\n", s->my_disc);
            }
            s->detect_time_ns = now +
                (uint64_t)s->calculated_min_rx * s->detect_mult * 1000ULL;
        }
    }
}
