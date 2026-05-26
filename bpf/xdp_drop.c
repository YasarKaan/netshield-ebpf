// +build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "events.h"
#include "maps.h"

// ── Helpers ───────────────────────────────────────────────────────────────────

// Copy 4 IPv4 bytes into the first 4 bytes of a 16-byte addr field.
static __always_inline void fill_ipv4_addr(__u8 dst[16], __u32 addr_be)
{
    __builtin_memcpy(dst, &addr_be, 4);
    // bytes [4..15] are already zero (ev is zero-initialised)
}

// Copy a full 16-byte IPv6 address.
static __always_inline void fill_ipv6_addr(__u8 dst[16], const __u8 src[16])
{
    __builtin_memcpy(dst, src, 16);
}

// ── XDP Program ──────────────────────────────────────────────────────────────

SEC("xdp")
int netshield_xdp(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // ── Parse Ethernet header ────────────────────────────────────────────────
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u16 eth_proto = bpf_ntohs(eth->h_proto);

    // ── Read config (shared by both IPv4 and IPv6 paths) ────────────────────
    __u32 cfg_key = 0;
    struct ns_config *cfg = bpf_map_lookup_elem(&config_map, &cfg_key);
    if (!cfg || !cfg->enabled)
        return XDP_PASS;

    // ── Stat: total packets ──────────────────────────────────────────────────
    __u32 stat_total = 0;
    __u64 *total = bpf_map_lookup_elem(&stats_map, &stat_total);
    if (total) __sync_fetch_and_add(total, 1);

    // ════════════════════════════════════════════════════════════════════════
    //  IPv4 path
    // ════════════════════════════════════════════════════════════════════════
    if (eth_proto == ETH_P_IP) {
        struct iphdr *ip = (void *)(eth + 1);
        if ((void *)(ip + 1) > data_end)
            return XDP_PASS;

        __u32 src_ip = ip->saddr;

        // ── Blocklist lookup ─────────────────────────────────────────────────
        __u8 *blocked = bpf_map_lookup_elem(&blocklist_map, &src_ip);
        if (blocked) {
            __u32 stat_drop = 2;
            __u64 *drops = bpf_map_lookup_elem(&stats_map, &stat_drop);
            if (drops) __sync_fetch_and_add(drops, 1);
            return XDP_DROP;
        }

        // ── Coarse kernel-side rate gate ─────────────────────────────────────
        struct rate_entry *re = bpf_map_lookup_elem(&rate_map, &src_ip);
        __u64 now = bpf_ktime_get_ns();

        if (re) {
            __u64 elapsed = now - re->last_ts_ns;
            if (elapsed < 1000000000ULL) { // within 1-second window
                re->pkt_count++;
                if (cfg->coarse_pps_limit > 0 &&
                    re->pkt_count > cfg->coarse_pps_limit)
                    goto emit_v4;
            } else {
                re->last_ts_ns = now;
                re->pkt_count  = 1;
            }
        } else {
            struct rate_entry new_re = { .last_ts_ns = now, .pkt_count = 1 };
            bpf_map_update_elem(&rate_map, &src_ip, &new_re, BPF_ANY);
        }

        // ── Sampling ─────────────────────────────────────────────────────────
        if (cfg->sample_every_n <= 1)
            goto emit_v4;

        __u32 stat_pass = 1;
        __u64 *passed = bpf_map_lookup_elem(&stats_map, &stat_pass);
        if (passed && (*passed % cfg->sample_every_n) == 0)
            goto emit_v4;

        if (passed) __sync_fetch_and_add(passed, 1);
        return XDP_PASS;

emit_v4: {
        struct packet_event ev = {};
        ev.ts_ns      = bpf_ktime_get_ns();
        ev.ip_version = 4;
        fill_ipv4_addr(ev.src_addr, ip->saddr);
        fill_ipv4_addr(ev.dst_addr, ip->daddr);
        ev.protocol   = ip->protocol;
        ev.pkt_len    = bpf_ntohs(ip->tot_len);

        // Parse TCP/UDP for port info.
        // Fragmented IPv4 packets may not carry L4 headers in non-initial
        // fragments, so those can legitimately remain with port 0.
        if (ip->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = (void *)((__u8 *)ip + (ip->ihl * 4));
            if ((void *)(tcp + 1) <= data_end) {
                ev.src_port  = bpf_ntohs(tcp->source);
                ev.dst_port  = bpf_ntohs(tcp->dest);
                ev.tcp_flags = ((__u8 *)tcp)[13];
            }
        } else if (ip->protocol == IPPROTO_UDP) {
            struct udphdr *udp = (void *)((__u8 *)ip + (ip->ihl * 4));
            if ((void *)(udp + 1) <= data_end) {
                ev.src_port = bpf_ntohs(udp->source);
                ev.dst_port = bpf_ntohs(udp->dest);
            }
        }

        __u32 stat_sampled = 3;
        __u64 *sampled = bpf_map_lookup_elem(&stats_map, &stat_sampled);
        if (sampled) __sync_fetch_and_add(sampled, 1);

        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &ev, sizeof(ev));

        __u32 stat_pass_v4 = 1;
        __u64 *pf = bpf_map_lookup_elem(&stats_map, &stat_pass_v4);
        if (pf) __sync_fetch_and_add(pf, 1);
        return XDP_PASS;
    }

    // ════════════════════════════════════════════════════════════════════════
    //  IPv6 path
    // ════════════════════════════════════════════════════════════════════════
    } else if (eth_proto == ETH_P_IPV6) {
        struct ipv6hdr *ip6 = (void *)(eth + 1);
        if ((void *)(ip6 + 1) > data_end)
            return XDP_PASS;

        // ── Blocklist lookup ─────────────────────────────────────────────────
        __u8 *blocked6 = bpf_map_lookup_elem(&blocklist_v6_map, &ip6->saddr);
        if (blocked6) {
            __u32 stat_drop = 2;
            __u64 *drops = bpf_map_lookup_elem(&stats_map, &stat_drop);
            if (drops) __sync_fetch_and_add(drops, 1);
            return XDP_DROP;
        }

        // ── Coarse kernel-side rate gate ─────────────────────────────────────
        struct rate_entry *re6 = bpf_map_lookup_elem(&rate_v6_map, &ip6->saddr);
        __u64 now6 = bpf_ktime_get_ns();

        if (re6) {
            __u64 elapsed = now6 - re6->last_ts_ns;
            if (elapsed < 1000000000ULL) {
                re6->pkt_count++;
                if (cfg->coarse_pps_limit > 0 &&
                    re6->pkt_count > cfg->coarse_pps_limit)
                    goto emit_v6;
            } else {
                re6->last_ts_ns = now6;
                re6->pkt_count  = 1;
            }
        } else {
            struct rate_entry new_re6 = { .last_ts_ns = now6, .pkt_count = 1 };
            bpf_map_update_elem(&rate_v6_map, &ip6->saddr, &new_re6, BPF_ANY);
        }

        // ── Sampling ─────────────────────────────────────────────────────────
        if (cfg->sample_every_n <= 1)
            goto emit_v6;

        __u32 stat_pass6 = 1;
        __u64 *passed6 = bpf_map_lookup_elem(&stats_map, &stat_pass6);
        if (passed6 && (*passed6 % cfg->sample_every_n) == 0)
            goto emit_v6;

        if (passed6) __sync_fetch_and_add(passed6, 1);
        return XDP_PASS;

emit_v6: {
        struct packet_event ev6 = {};
        ev6.ts_ns      = now6;
        ev6.ip_version = 6;
        fill_ipv6_addr(ev6.src_addr, (__u8 *)&ip6->saddr);
        fill_ipv6_addr(ev6.dst_addr, (__u8 *)&ip6->daddr);
        ev6.protocol   = ip6->nexthdr;
        ev6.pkt_len    = bpf_ntohs(ip6->payload_len);

        // Port parsing: only when nexthdr is directly TCP or UDP.
        // IPv6 extension headers (Routing, Fragment, Hop-by-Hop, etc.) are
        // not traversed in Phase 1 — those packets are emitted with port 0.
        if (ip6->nexthdr == IPPROTO_TCP) {
            struct tcphdr *tcp6 = (void *)(ip6 + 1);
            if ((void *)(tcp6 + 1) <= data_end) {
                ev6.src_port  = bpf_ntohs(tcp6->source);
                ev6.dst_port  = bpf_ntohs(tcp6->dest);
                ev6.tcp_flags = ((__u8 *)tcp6)[13];
            }
        } else if (ip6->nexthdr == IPPROTO_UDP) {
            struct udphdr *udp6 = (void *)(ip6 + 1);
            if ((void *)(udp6 + 1) <= data_end) {
                ev6.src_port = bpf_ntohs(udp6->source);
                ev6.dst_port = bpf_ntohs(udp6->dest);
            }
        }

        __u32 stat_sampled6 = 3;
        __u64 *sampled6 = bpf_map_lookup_elem(&stats_map, &stat_sampled6);
        if (sampled6) __sync_fetch_and_add(sampled6, 1);

        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &ev6, sizeof(ev6));

        __u32 stat_pass_v6 = 1;
        __u64 *pf6 = bpf_map_lookup_elem(&stats_map, &stat_pass_v6);
        if (pf6) __sync_fetch_and_add(pf6, 1);
        return XDP_PASS;
    }

    // ── Non-IP traffic (VLAN, ARP, etc.) — pass through uninspected ──────────
    // VLAN-tagged traffic (ETH_P_8021Q / ETH_P_8021AD) is currently not
    // inspected. Dual-tagged (QinQ) frames are also passed through.
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
