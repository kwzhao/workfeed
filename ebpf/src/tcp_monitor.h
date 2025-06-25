/*
 * tcp_monitor.h - Shared structures between eBPF and user-space
 */

#ifndef __TCP_MONITOR_H
#define __TCP_MONITOR_H

/* Flow information structure */
struct flow_info {
    /* 5-tuple */
    __u32 saddr;    /* Source IP */
    __u32 daddr;    /* Dest IP */
    __u16 sport;    /* Source port */
    __u16 dport;    /* Dest port */
    __u8  protocol; /* TCP = 6 */
    
    /* DSCP and timing */
    __u8  dscp;     /* DSCP value */
    __u64 start_time_ns;
    __u64 end_time_ns;
    
    /* Flow size */
    __u64 bytes_sent;
};

#endif /* __TCP_MONITOR_H */