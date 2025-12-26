#include "bfd_session.h"
#include <string.h>
#include <stdio.h>
#include <time.h>
//#include <linux/time.h>
#include <arpa/inet.h>
#include <unistd.h>

bfd_session_t sessions[BFD_MAX_SESSIONS];
int bfd_engine_mode = BFD_MODE_MULTIHOP;
int bfd_echo_sock_fd = -1;

static int hash_table[BFD_HASH_SIZE];

static uint32_t bfd_hash_disc(uint32_t disc)
{
    return (disc * 2654435761u) % BFD_HASH_SIZE;
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
            bfd_echo_sock_fd >= 0 &&
            s->min_echo &&
            now >= s->next_echo_ns) {

            char echo_payload[8] = { 'B','F','D','E','C','H','O','!' };
            sendto(bfd_echo_sock_fd, echo_payload, sizeof(echo_payload), 0,
                   (struct sockaddr *)&s->peer_addr, s->peer_len);
            s->next_echo_ns = now + (uint64_t)s->min_echo * 1000ULL;
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
