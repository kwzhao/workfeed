/*
 * tcp_monitor.h - Shared definitions between eBPF and user-space
 */

#ifndef __TCP_MONITOR_H
#define __TCP_MONITOR_H

/* Flow key structure - using socket pointer as unique key */
struct flow_key {
    void *sk;        /* Socket pointer */
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

#endif /* __TCP_MONITOR_H */