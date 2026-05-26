#ifndef __EVENTS_H__
#define __EVENTS_H__

#include "vmlinux.h"

// packet_event is written to the perf ring buffer by the XDP program and
// consumed by the userspace collector.  The layout must stay in sync with
// parseEvent() in internal/collector/collector.go.
//
// Total size: 8 + 16 + 16 + 2 + 2 + 2 + 1 + 1 + 1 + 1 + 2 = 52 bytes.
struct packet_event {
    __u64 ts_ns;            // ktime_get_ns() at intercept
    __u8  src_addr[16];     // Source address.  IPv4: first 4 bytes, rest zero.
                            // IPv6: all 16 bytes (network byte order).
    __u8  dst_addr[16];     // Destination address (same layout).
    __u16 src_port;         // Source port (0 if not TCP/UDP or fragmented)
    __u16 dst_port;         // Destination port
    __u16 pkt_len;          // IP total length (IPv4) / payload length (IPv6)
    __u8  protocol;         // IPPROTO_TCP / IPPROTO_UDP / etc.
    __u8  tcp_flags;        // TCP flags byte (0 for non-TCP)
    __u8  flags;            // Internal: bit0 = coarse_rate_exceeded
    __u8  ip_version;       // 4 or 6
    __u8  _pad[2];          // Explicit alignment padding
} __attribute__((packed));

#endif // __EVENTS_H__
