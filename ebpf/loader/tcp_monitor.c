/*
 * tcp_monitor.c - User-space loader for TCP monitoring eBPF program
 * 
 * Handles:
 * - Loading the eBPF program into kernel
 * - Setting up ring buffers for data collection
 * - Processing flow events from kernel
 * - Forwarding to Workfeed sampling layer
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/types.h>
#include "tcp_monitor.h"
#include "tcp_monitor.skel.h"

#ifndef AF_INET
#define AF_INET 2
#endif

static volatile bool running = true;
static bool verbose = false;

static void sig_handler(int sig)
{
    running = false;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    if (verbose || level == LIBBPF_WARN || level == LIBBPF_INFO)
        return vfprintf(stderr, format, args);
    return 0;
}

static void print_flow_record(const struct flow_record *flow)
{
    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    struct in_addr src_addr = {.s_addr = flow->saddr};
    struct in_addr dst_addr = {.s_addr = flow->daddr};
    
    inet_ntop(AF_INET, &src_addr, src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, &dst_addr, dst_ip, sizeof(dst_ip));
    
    /* Convert ports from network to host byte order for display */
    __u16 sport = ntohs(flow->sport);
    __u16 dport = ntohs(flow->dport);
    
    __u64 duration_ms = (flow->end_ns - flow->start_ns) / 1000000;
    
    printf("Flow: %s:%d -> %s:%d | DSCP=%d | Duration=%llums | Sent=%llu Recv=%llu\n",
           src_ip, sport, dst_ip, dport, flow->dscp, duration_ms, 
           flow->bytes_sent, flow->bytes_recv);
}

static int handle_flow_event(void *ctx, void *data, size_t data_sz)
{
    const struct flow_record *flow = data;
    
    if (data_sz < sizeof(*flow)) {
        fprintf(stderr, "Invalid flow record size\n");
        return 0;
    }
    
    print_flow_record(flow);
    return 0;
}

static void print_stats(struct tcp_monitor_bpf *skel)
{
    __u32 key;
    __u64 values[__STAT_MAX];
    
    /* Initialize to zero */
    memset(values, 0, sizeof(values));
    
    /* Aggregate per-CPU values */
    for (key = 0; key < __STAT_MAX; key++) {
        __u64 percpu_values[libbpf_num_possible_cpus()];
        memset(percpu_values, 0, sizeof(percpu_values));
        
        if (bpf_map_lookup_elem(bpf_map__fd(skel->maps.stats), 
                                &key, percpu_values) == 0) {
            for (int i = 0; i < libbpf_num_possible_cpus(); i++) {
                values[key] += percpu_values[i];
            }
        }
    }
    
    printf("\n=== Statistics ===\n");
    printf("Flows created:    %llu\n", values[STAT_FLOW_CREATED]);
    printf("Flows completed:  %llu\n", values[STAT_FLOW_COMPLETED]);
    printf("Flows destroyed:  %llu\n", values[STAT_FLOW_DESTROYED]);
    printf("Map full errors:  %llu\n", values[STAT_MAP_FULL]);
    printf("Ring buf full:    %llu\n", values[STAT_RINGBUF_FULL]);
    printf("Invalid sockets:  %llu\n", values[STAT_INVALID_SK]);
    printf("IPv6 skipped:     %llu\n", values[STAT_IPV6_SKIPPED]);
    printf("Failed connects:  %llu\n", values[STAT_FAILED_CONN]);
}

int main(int argc, char **argv)
{
    struct tcp_monitor_bpf *skel;
    struct ring_buffer *rb = NULL;
    int err = 0;
    __u64 ipv6_skipped = 0;
    __u32 ipv6_key = STAT_IPV6_SKIPPED;
    
    /* Parse arguments */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--verbose") == 0 || strcmp(argv[i], "-v") == 0) {
            verbose = true;
        }
    }
    
    /* Set up libbpf errors and debug info callback */
    libbpf_set_print(libbpf_print_fn);
    
    /* Set up signal handler */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    
    /* Open BPF skeleton */
    skel = tcp_monitor_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }
    
    /* Load BPF object */
    err = tcp_monitor_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF object: %d\n", err);
        goto cleanup;
    }
    
    /* Attach tracepoints */
    err = tcp_monitor_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF programs: %d\n", err);
        goto cleanup;
    }
    
    /* Set up ring buffer */
    rb = ring_buffer__new(bpf_map__fd(skel->maps.flow_events), 
                          handle_flow_event, NULL, NULL);
    if (!rb) {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }
    
    /* Initialize stats to 0 - for per-CPU maps, need to initialize all CPUs */
    for (__u32 key = 0; key < __STAT_MAX; key++) {
        __u64 zeros[libbpf_num_possible_cpus()];
        memset(zeros, 0, sizeof(zeros));
        bpf_map_update_elem(bpf_map__fd(skel->maps.stats), &key, zeros, BPF_ANY);
    }
    
    printf("Successfully started TCP flow monitor!\n");
    if (verbose) {
        printf("Running in verbose mode - showing all events\n");
    }
    printf("Press Ctrl-C to stop.\n\n");
    
    /* Main loop */
    while (running) {
        err = ring_buffer__poll(rb, 100 /* timeout_ms */);
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }
    }
    
    /* Print final statistics */
    print_stats(skel);
    
    /* Check if IPv6 connections were skipped */
    {
        __u64 percpu_ipv6[libbpf_num_possible_cpus()];
        if (bpf_map_lookup_elem(bpf_map__fd(skel->maps.stats), 
                                &ipv6_key, percpu_ipv6) == 0) {
            for (int i = 0; i < libbpf_num_possible_cpus(); i++) {
                ipv6_skipped += percpu_ipv6[i];
            }
        }
        
        if (ipv6_skipped > 0) {
            printf("\n");
            printf("Note: %llu IPv6 TCP connections were skipped.\n", ipv6_skipped);
            printf("To capture IPv6 traffic, the program needs to be updated.\n");
            printf("For now, use 'curl -4' or similar flags to force IPv4.\n");
        }
    }

cleanup:
    ring_buffer__free(rb);
    tcp_monitor_bpf__destroy(skel);
    return err < 0 ? -err : 0;
}