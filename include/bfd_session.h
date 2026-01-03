#ifndef BFD_SESSION_H
#define BFD_SESSION_H

#include "bfd.h"
#include <stdint.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <net/if.h>

#define BFD_MAX_SESSIONS   256
#define BFD_HASH_SIZE      257
#define BFD_DEFAULT_DETECT 3
#define BFD_DEFAULT_MIN_RX 100000
#define BFD_DEFAULT_MIN_TX 100000

typedef struct {
    int used;
    int is_initiator;

    struct sockaddr_storage peer_addr;
    socklen_t peer_len;

    uint32_t my_disc;
    uint32_t your_disc;

    uint8_t state;

    uint8_t detect_mult;
    uint32_t min_tx;     // µs
    uint32_t min_rx;     // µs
    uint32_t min_echo;   // echo interval µs (single-hop only)
    uint32_t calculated_min_tx;
    uint32_t calculated_min_rx;

    uint8_t demand_mode;
    uint8_t poll_pending;
    uint8_t echo_enabled;

    uint64_t next_tx_ns;
    uint64_t detect_time_ns;
    uint64_t next_echo_ns;
    uint8_t admin_down_sent;
    uint8_t admin_down_by_command;

    // Cached peer MAC and interface for echo packets
    unsigned char peer_mac[6];
    char iface[IFNAMSIZ];
} bfd_session_t;

// Global engine mode (set by engine)
extern int bfd_engine_mode;

// Echo socket FD (set by engine, used by timers)
extern int bfd_echo_sock_fd;

// Expose sessions for CLI
extern bfd_session_t sessions[BFD_MAX_SESSIONS];

// Time helper
uint64_t bfd_now_ns(void);

// Session management
bfd_session_t *bfd_session_create(const struct sockaddr_storage *peer,
                                  socklen_t peer_len,
                                  uint32_t my_disc,
                                  uint32_t min_tx,
                                  uint32_t min_rx,
                                  uint8_t detect_mult,
                                  int is_initiator);

bfd_session_t *bfd_session_find_by_my_disc(uint32_t my_disc);
bfd_session_t *bfd_session_find_by_your_disc(uint32_t your_disc);
bfd_session_t *bfd_session_find_by_peer(const struct sockaddr_storage *peer,
                                        socklen_t peer_len);
bfd_session_t *bfd_session_find_by_peer_mac(const unsigned char *mac);

void bfd_session_delete(uint32_t disc);
void bfd_session_down(uint32_t disc);
void bfd_session_up(uint32_t disc);

// Poll trigger
void bfd_session_trigger_poll(bfd_session_t *s);

// RX/TX handling
void bfd_session_send_ctrl(int sockfd, bfd_session_t *sess);
void bfd_session_handle_rx(int sockfd,
                           bfd_session_t *sess,
                           const struct sockaddr_storage *src,
                           socklen_t srclen,
                           const struct bfd_ctrl *pkt);

// Timer scan
void bfd_session_check_timers(int ctrl_sock);

// Get next timer expiration time in ns
uint64_t bfd_session_get_next_timer_ns(void);

void bfd_session_init();
 
/* Send a raw Ethernet echo for single-hop sessions (returns 0 on success) */
int bfd_send_echo(bfd_session_t *s);

#endif
