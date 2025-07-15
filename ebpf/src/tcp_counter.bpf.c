#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

// Simple counter map - single entry to count TCP connections
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} conn_count SEC(".maps");

SEC("tracepoint/sock/inet_sock_set_state")
int count_tcp_connections(struct trace_event_raw_inet_sock_set_state *ctx)
{
    // Only count transitions TO established state
    if (ctx->newstate == TCP_ESTABLISHED) {
        __u32 key = 0;
        __u64 *count = bpf_map_lookup_elem(&conn_count, &key);
        if (count) {
            __sync_fetch_and_add(count, 1);
        }
    }
    return 0;
}
