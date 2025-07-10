/*
 * tcp_monitor.bpf.c - eBPF program for TCP flow monitoring
 *
 * Tracks TCP socket lifecycle events and captures per-flow statistics.
 */

#include "vmlinux_dev.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

/* Include constants not in vmlinux */
#define AF_INET		2	/* Internet IP Protocol */
#define AF_INET6	10	/* IPv6 */
#define IPPROTO_TCP	6	/* Transmission Control Protocol */

/* Flow key structure - using socket pointer as unique key
 *
 * Design rationale: Using the socket pointer as a flow key is safe because:
 * 1. Socket pointers are unique during the socket's lifetime
 * 2. We properly handle socket lifecycle events (creation, state changes, destruction)
 * 3. We delete entries from our map when sockets are destroyed, preventing stale references
 * 4. The kernel guarantees that socket pointers won't be reused while our handlers are running
 *
 * Alternative approaches like using bpf_get_socket_cookie() would add overhead without
 * providing additional safety in our use case, since we properly track socket lifecycle.
 */
struct flow_key {
    void *sk;        /* Socket pointer - unique during socket lifetime */
};

/* Flow record structure for tracking TCP connections */
struct flow_record {
    __u32 saddr;      /* Source IPv4 address */
    __u32 daddr;      /* Destination IPv4 address */
    __u16 sport;      /* Source port (network byte order) */
    __u16 dport;      /* Destination port (network byte order) */
    __u8  protocol;   /* IP protocol (should be IPPROTO_TCP) */
    __u8  dscp;       /* DSCP value extracted from TOS field */
    __u16 _pad;       /* Padding for alignment */
    __u64 start_ns;   /* Connection start timestamp (ns) */
    __u64 end_ns;     /* Connection end timestamp (ns) */
    __u64 bytes_sent; /* Total bytes sent */
    __u64 bytes_recv; /* Total bytes received */
};

/* Statistics counters */
enum stat_types {
    STAT_FLOW_CREATED = 0,
    STAT_FLOW_COMPLETED,
    STAT_FLOW_DESTROYED,
    STAT_MAP_FULL,
    STAT_RINGBUF_FULL,
    STAT_INVALID_SK,
    STAT_IPV6_SKIPPED,  /* Track IPv6 connections we're not handling yet */
    STAT_FAILED_CONN,   /* Count failed handshakes without storing flow records */
    __STAT_MAX
};

char LICENSE[] SEC("license") = "GPL";

/* Hash map to track active flows by socket */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct flow_key);
    __type(value, struct flow_record);
} active_flows SEC(".maps");

/* Ring buffer for completed flows */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); /* 16MB */
} flow_events SEC(".maps");

/* Per-CPU statistics */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, __STAT_MAX);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

static __always_inline void increment_stat(__u32 stat_type)
{
    __u64 *counter = bpf_map_lookup_elem(&stats, &stat_type);
    if (counter) {
        /* Simple increment for percpu maps - each CPU has its own counter
         * No need for atomic operations */
        *counter += 1;
    }
}

static __always_inline int is_ipv4_tcp(struct sock *sk)
{
    /* Check if this is an IPv4 TCP socket
     * IMPORTANT: inet_sock_set_state fires for ALL INET protocols (TCP, UDP, DCCP, etc.)
     * We must verify this is actually TCP to avoid polluting our maps with non-TCP traffic */
    __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    __u8 protocol = BPF_CORE_READ(sk, sk_protocol);

    /* Track IPv6 TCP connections that we're skipping */
    if (family == AF_INET6 && protocol == IPPROTO_TCP) {
        increment_stat(STAT_IPV6_SKIPPED);
    }

    return family == AF_INET && protocol == IPPROTO_TCP;
}

static __always_inline void extract_flow_tuple(struct sock *sk, struct flow_record *rec)
{
    /* Extract 5-tuple from socket */
    rec->saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    rec->daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    /* Port handling: skc_num is in host order, skc_dport is in network order
     * We store both in network order for consistency */
    rec->sport = bpf_htons(BPF_CORE_READ(sk, __sk_common.skc_num));  /* Convert to network order */
    rec->dport = BPF_CORE_READ(sk, __sk_common.skc_dport);  /* Already in network order */
    rec->protocol = IPPROTO_TCP;

    /* Extract DSCP from TOS field
     * TOS byte layout: DSCP (6 bits) | ECN (2 bits)
     * We need to mask out ECN bits before shifting */
    struct inet_sock *inet = (struct inet_sock *)sk;
    __u8 tos = BPF_CORE_READ(inet, tos);
    rec->dscp = (tos & 0xfc) >> 2;
}

static __always_inline void read_tcp_stats(struct sock *sk, struct flow_record *rec)
{
    /* Cast to tcp_sock to access byte counters */
    struct tcp_sock *tp = (struct tcp_sock *)sk;

    /* Read byte counters using CO-RE
     * bytes_sent exists in all supported kernels */
    rec->bytes_sent = BPF_CORE_READ(tp, bytes_sent);

    /* bytes_received may not exist in older kernels
     * Use field existence check for compatibility */
    if (bpf_core_field_exists(tp->bytes_received)) {
        rec->bytes_recv = BPF_CORE_READ(tp, bytes_received);
    } else {
        rec->bytes_recv = 0;  /* Older kernel without this field */
    }
}

SEC("tracepoint/sock/inet_sock_set_state")
int trace_inet_sock_set_state(struct trace_event_raw_inet_sock_set_state *ctx)
{
    struct sock *sk = (struct sock *)ctx->skaddr;
    __u16 oldstate = ctx->oldstate;
    __u16 newstate = ctx->newstate;

    if (!sk || !is_ipv4_tcp(sk))
        return 0;

    /* Handle transition TO ESTABLISHED
     * This captures the beginning of a connection when the 3-way handshake completes */
    if (newstate == TCP_ESTABLISHED) {
        struct flow_key key = {};
        struct flow_record rec = {};

        /* Zero-initialize the record */
        __builtin_memset(&rec, 0, sizeof(rec));

        /* Create flow key with socket pointer */
        key.sk = sk;

        /* Extract flow tuple and DSCP */
        extract_flow_tuple(sk, &rec);
        rec.start_ns = bpf_ktime_get_ns();

        /* Insert into active flows map */
        if (bpf_map_update_elem(&active_flows, &key, &rec, BPF_ANY) < 0) {
            increment_stat(STAT_MAP_FULL);
        } else {
            increment_stat(STAT_FLOW_CREATED);
        }
    }
    /* Handle transition FROM ESTABLISHED
     * Just mark the end timestamp - we'll collect final stats and submit in tcp_destroy_sock
     * This ensures we capture all bytes including those sent during FIN-WAIT states */
    else if (oldstate == TCP_ESTABLISHED && newstate != TCP_ESTABLISHED) {
        struct flow_key key = {};
        struct flow_record *rec;

        key.sk = sk;

        /* Look up the flow record */
        rec = bpf_map_lookup_elem(&active_flows, &key);

        if (rec && rec->end_ns == 0) {
            /* Only update end timestamp, don't submit or delete yet
             * The socket is still alive and may transmit more data */
            rec->end_ns = bpf_ktime_get_ns();
        }
    }
    /* Count failed handshakes without creating flow records
     * These don't contribute to workload estimation but are useful for health monitoring */
    else if (oldstate == TCP_SYN_SENT && newstate != TCP_ESTABLISHED && newstate != TCP_SYN_RECV) {
        increment_stat(STAT_FAILED_CONN);
    }

    return 0;
}

SEC("tracepoint/tcp/tcp_destroy_sock")
int trace_tcp_destroy_sock(struct trace_event_raw_tcp_event_sk *ctx)
{
    struct sock *sk = (struct sock *)ctx->skaddr;

    if (!sk || !is_ipv4_tcp(sk))
        return 0;

    /* Clean up any remaining entry */
    struct flow_key key = {};
    key.sk = sk;

    /* Submit and cleanup any flow record
     * This is the single point where all flows are finalized and submitted
     * This captures:
     * 1. Flows that completed normally (went through ESTABLISHED)
     * 2. Flows that never reached ESTABLISHED (RST during handshake, timeouts)
     * 3. All final bytes including those sent during FIN-WAIT states */
    struct flow_record *rec = bpf_map_lookup_elem(&active_flows, &key);
    if (rec) {
        /* Read final TCP stats first - this captures all bytes including FIN-WAIT */
        read_tcp_stats(sk, rec);
        
        /* If end_ns wasn't set (flow never left ESTABLISHED or never reached it),
         * set it now AFTER reading final byte counters */
        if (rec->end_ns == 0) {
            rec->end_ns = bpf_ktime_get_ns();
        }

        /* Submit to ring buffer */
        struct flow_record *rb_rec;
        rb_rec = bpf_ringbuf_reserve(&flow_events, sizeof(*rb_rec), 0);
        if (rb_rec) {
            __builtin_memcpy(rb_rec, rec, sizeof(*rb_rec));
            bpf_ringbuf_submit(rb_rec, 0);
            increment_stat(STAT_FLOW_COMPLETED);
        } else {
            increment_stat(STAT_RINGBUF_FULL);
        }

        /* Delete the entry */
        bpf_map_delete_elem(&active_flows, &key);
        increment_stat(STAT_FLOW_DESTROYED);
    }

    return 0;
}
