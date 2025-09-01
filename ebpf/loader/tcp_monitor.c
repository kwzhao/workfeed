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
#include <stdbool.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <getopt.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/types.h>
#include "tcp_monitor.h"
#include "tcp_monitor.skel.h"

#ifndef AF_INET
#define AF_INET 2
#endif

#define DEFAULT_UDP_HOST "127.0.0.1"
#define DEFAULT_UDP_PORT 5001
#define DEFAULT_BATCH_SIZE 128
#define DEFAULT_FLUSH_MS 200
#define MAX_BATCH_SIZE 256

/* Operating modes */
enum op_mode {
    MODE_NONE = 0,
    MODE_DEBUG,
    MODE_DAEMON
};

/* Configuration for daemon mode */
struct daemon_config {
    char udp_host[INET_ADDRSTRLEN];
    __u16 udp_port;
    __u32 batch_size;
    __u32 flush_ms;
};

/* Batch structure for accumulating flow records */
struct batch {
    struct flow_record records[MAX_BATCH_SIZE];
    __u16 count;
    __u64 first_timestamp_ns;
};

static volatile bool running = true;
static bool verbose = false;
static enum op_mode mode = MODE_NONE;  /* Require explicit mode selection */
static struct daemon_config daemon_cfg = {
    .udp_host = DEFAULT_UDP_HOST,
    .udp_port = DEFAULT_UDP_PORT,
    .batch_size = DEFAULT_BATCH_SIZE,
    .flush_ms = DEFAULT_FLUSH_MS
};
static struct batch current_batch = {0};
static int udp_sock = -1;
static struct sockaddr_in rack_addr;

/* User-space only statistics */
static __u64 us_batch_sent = 0;
static __u64 us_udp_send_fail = 0;

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

static __u64 get_monotonic_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000000000ULL + ts.tv_nsec;
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

static int init_udp_socket(void)
{
    udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_sock < 0) {
        fprintf(stderr, "Failed to create UDP socket: %s\n", strerror(errno));
        return -1;
    }
    
    /* Set up destination address */
    memset(&rack_addr, 0, sizeof(rack_addr));
    rack_addr.sin_family = AF_INET;
    rack_addr.sin_port = htons(daemon_cfg.udp_port);
    if (inet_pton(AF_INET, daemon_cfg.udp_host, &rack_addr.sin_addr) != 1) {
        fprintf(stderr, "Invalid UDP host address: %s\n", daemon_cfg.udp_host);
        close(udp_sock);
        return -1;
    }
    
    /* Set socket buffer to handle bursts */
    int sndbuf = daemon_cfg.batch_size * sizeof(struct flow_record) + 1024;
    if (setsockopt(udp_sock, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf)) < 0) {
        fprintf(stderr, "Warning: failed to set UDP send buffer size\n");
    }
    
    return 0;
}

static void send_batch(struct tcp_monitor_bpf *skel)
{
    if (current_batch.count == 0)
        return;
    
    /* Use static buffer to avoid malloc/free on every batch */
    static char packet[sizeof(__u16) + MAX_BATCH_SIZE * sizeof(struct flow_record)];
    
    /* Pack count in network byte order */
    *((__u16 *)packet) = htons(current_batch.count);
    
    /* Copy flow records */
    size_t records_size = current_batch.count * sizeof(struct flow_record);
    memcpy(packet + sizeof(__u16), current_batch.records, records_size);
    
    /* Send to rack sampler */
    size_t packet_size = sizeof(__u16) + records_size;
    ssize_t sent = sendto(udp_sock, packet, packet_size, 0,
                          (struct sockaddr *)&rack_addr, sizeof(rack_addr));
    
    if (sent < 0) {
        if (verbose)
            fprintf(stderr, "Failed to send batch: %s\n", strerror(errno));
        us_udp_send_fail++;
    } else {
        us_batch_sent++;
        if (verbose)
            printf("Sent batch with %u flows\n", current_batch.count);
    }
    
    /* Reset batch */
    current_batch.count = 0;
    current_batch.first_timestamp_ns = 0;
}

static void add_to_batch(const struct flow_record *flow, struct tcp_monitor_bpf *skel)
{
    /* Record timestamp on first flow */
    if (current_batch.count == 0) {
        current_batch.first_timestamp_ns = get_monotonic_ns();
    }
    
    /* Add flow to batch */
    current_batch.records[current_batch.count++] = *flow;
    
    /* Send if batch is full */
    if (current_batch.count >= daemon_cfg.batch_size) {
        send_batch(skel);
    }
}

static bool should_filter_flow(const struct flow_record *flow)
{
    /* Filter out 1-byte flows (typically FIN-only control flows without application data) */
    return flow->bytes_sent == 1;
}

static int handle_flow_event(void *ctx, void *data, size_t data_sz)
{
    const struct flow_record *flow = data;
    struct tcp_monitor_bpf *skel = ctx;
    
    if (data_sz < sizeof(*flow)) {
        fprintf(stderr, "Invalid flow record size\n");
        return 0;
    }
    
    if (should_filter_flow(flow)) {
        return 0;
    }
    
    if (mode == MODE_DEBUG) {
        print_flow_record(flow);
    } else if (mode == MODE_DAEMON) {
        add_to_batch(flow, skel);
    }
    
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
    
    if (mode == MODE_DAEMON) {
        printf("Batches sent:     %llu\n", us_batch_sent);
        printf("UDP send fails:   %llu\n", us_udp_send_fail);
    }
}

static void print_usage(const char *prog)
{
    printf("Usage: %s [OPTIONS]\n", prog);
    printf("\nOperating Modes (mutually exclusive):\n");
    printf("  --debug             Print flows to stdout (default if no mode specified)\n");
    printf("  --daemon            Run as batch collector, send via UDP\n");
    printf("\nDaemon Mode Options:\n");
    printf("  --udp-host HOST     Rack sampler IP address (default: %s)\n", DEFAULT_UDP_HOST);
    printf("  --udp-port PORT     Rack sampler UDP port (default: %d)\n", DEFAULT_UDP_PORT);
    printf("  --batch-size N      Records per batch (default: %d, max: %d)\n", DEFAULT_BATCH_SIZE, MAX_BATCH_SIZE);
    printf("  --flush-ms MS       Max time before flush (default: %d)\n", DEFAULT_FLUSH_MS);
    printf("\nGeneral Options:\n");
    printf("  -v, --verbose       Enable verbose output\n");
    printf("  -h, --help          Show this help message\n");
}

int main(int argc, char **argv)
{
    struct tcp_monitor_bpf *skel;
    struct ring_buffer *rb = NULL;
    int err = 0;
    __u64 ipv6_skipped = 0;
    __u32 ipv6_key = STAT_IPV6_SKIPPED;
    
    /* Force line buffering for stdout/stderr to ensure logs appear when redirected */
    setvbuf(stdout, NULL, _IOLBF, 0);
    setvbuf(stderr, NULL, _IOLBF, 0);
    
    /* Command-line options */
    static struct option long_opts[] = {
        {"debug", no_argument, 0, 'd'},
        {"daemon", no_argument, 0, 'D'},
        {"udp-host", required_argument, 0, 'H'},
        {"udp-port", required_argument, 0, 'P'},
        {"batch-size", required_argument, 0, 'B'},
        {"flush-ms", required_argument, 0, 'F'},
        {"verbose", no_argument, 0, 'v'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    
    /* Parse arguments */
    int opt;
    while ((opt = getopt_long(argc, argv, "vhd", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'd':
            if (mode != MODE_NONE) {
                fprintf(stderr, "Error: --debug and --daemon are mutually exclusive\n");
                return 1;
            }
            mode = MODE_DEBUG;
            break;
        case 'D':
            if (mode != MODE_NONE) {
                fprintf(stderr, "Error: --debug and --daemon are mutually exclusive\n");
                return 1;
            }
            mode = MODE_DAEMON;
            break;
        case 'H':
            strncpy(daemon_cfg.udp_host, optarg, INET_ADDRSTRLEN - 1);
            daemon_cfg.udp_host[INET_ADDRSTRLEN - 1] = '\0';
            break;
        case 'P':
            daemon_cfg.udp_port = atoi(optarg);
            if (daemon_cfg.udp_port == 0) {
                fprintf(stderr, "Error: Invalid UDP port\n");
                return 1;
            }
            break;
        case 'B':
            daemon_cfg.batch_size = atoi(optarg);
            if (daemon_cfg.batch_size == 0 || daemon_cfg.batch_size > MAX_BATCH_SIZE) {
                fprintf(stderr, "Error: Batch size must be between 1 and %d\n", MAX_BATCH_SIZE);
                return 1;
            }
            break;
        case 'F':
            daemon_cfg.flush_ms = atoi(optarg);
            if (daemon_cfg.flush_ms == 0) {
                fprintf(stderr, "Error: Flush interval must be > 0\n");
                return 1;
            }
            break;
        case 'v':
            verbose = true;
            break;
        case 'h':
            print_usage(argv[0]);
            return 0;
        default:
            print_usage(argv[0]);
            return 1;
        }
    }
    
    /* If no mode specified, print usage */
    if (mode == MODE_NONE) {
        fprintf(stderr, "Error: Must specify either --debug or --daemon mode\n\n");
        print_usage(argv[0]);
        return 1;
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
    
    /* Set up ring buffer - pass skeleton as context for stats access */
    rb = ring_buffer__new(bpf_map__fd(skel->maps.flow_events), 
                          handle_flow_event, skel, NULL);
    if (!rb) {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }
    
    /* Initialize UDP socket for daemon mode */
    if (mode == MODE_DAEMON) {
        if (init_udp_socket() < 0) {
            err = -1;
            goto cleanup;
        }
        printf("Daemon mode: sending batches to %s:%d\n", 
               daemon_cfg.udp_host, daemon_cfg.udp_port);
    }
    
    /* Initialize stats to 0 - for per-CPU maps, need to initialize all CPUs */
    for (__u32 key = 0; key < __STAT_MAX; key++) {
        __u64 zeros[libbpf_num_possible_cpus()];
        memset(zeros, 0, sizeof(zeros));
        bpf_map_update_elem(bpf_map__fd(skel->maps.stats), &key, zeros, BPF_ANY);
    }
    
    printf("Successfully started TCP flow monitor in %s mode!\n", 
           mode == MODE_DEBUG ? "debug" : "daemon");
    if (verbose) {
        printf("Running in verbose mode\n");
    }
    if (mode == MODE_DAEMON) {
        printf("Batch size: %u, Flush interval: %ums\n", 
               daemon_cfg.batch_size, daemon_cfg.flush_ms);
    }
    printf("Press Ctrl-C to stop.\n\n");
    
    /* Main loop */
    while (running) {
        /* Use shorter poll timeout in daemon mode for timer-based flush */
        int poll_timeout_ms = mode == MODE_DAEMON ? 50 : 100;
        
        err = ring_buffer__poll(rb, poll_timeout_ms);
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }
        
        /* Check for timer-based flush in daemon mode */
        if (mode == MODE_DAEMON && current_batch.count > 0) {
            __u64 now = get_monotonic_ns();
            __u64 elapsed_ms = (now - current_batch.first_timestamp_ns) / 1000000;
            
            if (elapsed_ms >= daemon_cfg.flush_ms) {
                if (verbose) {
                    printf("Timer flush: %u flows after %llums\n", 
                           current_batch.count, elapsed_ms);
                }
                send_batch(skel);
            }
        }
    }
    
    /* Send any remaining batch before exit */
    if (mode == MODE_DAEMON && current_batch.count > 0) {
        printf("Sending final batch with %u flows\n", current_batch.count);
        send_batch(skel);
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
    if (udp_sock >= 0) {
        close(udp_sock);
    }
    ring_buffer__free(rb);
    tcp_monitor_bpf__destroy(skel);
    return err < 0 ? -err : 0;
}