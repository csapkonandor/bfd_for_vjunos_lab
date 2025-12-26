#ifndef BFD_H
#define BFD_H

#include <stdint.h>

// Ports
#define BFD_PORT_SINGLEHOP 3784
#define BFD_PORT_MULTIHOP  4784

// Echo port for single-hop echo mode (toy)
#define BFD_ECHO_PORT      6784

// Modes
#define BFD_MODE_SINGLEHOP 1
#define BFD_MODE_MULTIHOP  2

// Version
#define BFD_VERSION 1

// BFD states (RFC 5880)
#define BFD_STATE_ADMIN_DOWN 0
#define BFD_STATE_DOWN       1
#define BFD_STATE_INIT       2
#define BFD_STATE_UP         3

// Flags (bit positions in 'flags' byte)
#define BFD_FLAG_POLL       0x20
#define BFD_FLAG_FINAL      0x10
#define BFD_FLAG_CPI        0x08
#define BFD_FLAG_AUTH       0x04
#define BFD_FLAG_DEMAND     0x02
#define BFD_FLAG_MULTIHOP   0x01

#define BFD_MAX_ADMIN_DOWN_SEND 3

// RFC 5880 BFD control packet (24 bytes)
struct __attribute__((packed)) bfd_ctrl {
    uint8_t vers_diag;      // Version (3 bits) + Diagnostic (5 bits)
    uint8_t flags;          // State (2 bits) + flags (6 bits)
    uint8_t detect_mult;    // Detection multiplier
    uint8_t length;         // Length = 24

    uint32_t my_disc;       // My discriminator
    uint32_t your_disc;     // Your discriminator

    uint32_t min_tx;        // Desired Min TX Interval (µs)
    uint32_t min_rx;        // Required Min RX Interval (µs)
    uint32_t echo_rx;       // Required Min Echo RX Interval (µs)
};

static inline void bfd_set_version_diag(struct bfd_ctrl *p, uint8_t diag)
{
    p->vers_diag = (BFD_VERSION << 5) | (diag & 0x1F);
}

static inline void bfd_set_state(struct bfd_ctrl *p, uint8_t state)
{
    p->flags = (p->flags & 0x3F) | (state << 6);
}

static inline uint8_t bfd_get_state(const struct bfd_ctrl *p)
{
    return p->flags >> 6;
}

#endif
