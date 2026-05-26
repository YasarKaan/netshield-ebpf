#ifndef __MAPS_H__
#define __MAPS_H__

#include <bpf/bpf_helpers.h>
#include "vmlinux.h"

// ── IPv4 blocklist: src IPv4 → block reason (written from userspace) ─────────
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);          // IPv4 address (network byte order)
    __type(value, __u8);         // block reason: 1=manual, 2=rate, 3=portscan
} blocklist_map SEC(".maps");

// ── IPv6 blocklist: src IPv6 → block reason ───────────────────────────────────
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct in6_addr); // 16-byte IPv6 address
    __type(value, __u8);          // block reason: 1=manual, 2=rate, 3=portscan
} blocklist_v6_map SEC(".maps");

// ── Per-IP packet counters for rate tracking (kernel-side coarse gate) ────────
// LRU_HASH is intentional here so old/idle sources are evicted automatically
// instead of the map growing until it blocks new inserts.
struct rate_entry {
    __u64 last_ts_ns;
    __u64 pkt_count;
};

// IPv4 rate map
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 131072);
    __type(key, __u32);
    __type(value, struct rate_entry);
} rate_map SEC(".maps");

// IPv6 rate map
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct in6_addr);
    __type(value, struct rate_entry);
} rate_v6_map SEC(".maps");

// Perf Event Array for userspace event delivery
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

// ── Config map (userspace-writable) ─────────────────────────────────────────
struct ns_config {
    __u32 coarse_pps_limit;      // Kernel-side coarse rate gate (pps)
    __u32 sample_every_n;        // Ring buffer sampling rate (1 = all)
    __u8  enabled;               // Master kill switch
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct ns_config);
} config_map SEC(".maps");

// ── Stat counters ─────────────────────────────────────────────────────────────
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);          // 0=total, 1=passed, 2=dropped, 3=sampled
    __type(value, __u64);
} stats_map SEC(".maps");

#endif // __MAPS_H__
