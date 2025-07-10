#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "tcp_counter.skel.h"

static volatile bool running = true;

static void sig_handler(int sig)
{
    running = false;
}

int main(int argc, char **argv)
{
    struct tcp_counter_bpf *skel;
    int err;

    /* Set up signal handler */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    /* Keep default libbpf printing to see errors */
    /* libbpf_set_print(NULL); */

    /* Open BPF skeleton */
    skel = tcp_counter_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    /* Load BPF object */
    err = tcp_counter_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF object: %d\n", err);
        tcp_counter_bpf__destroy(skel);
        return 1;
    }

    /* Attach tracepoint */
    err = tcp_counter_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    /* Initialize counter to 0 */
    __u32 key = 0;
    __u64 initial = 0;
    bpf_map_update_elem(bpf_map__fd(skel->maps.conn_count), &key, &initial, BPF_ANY);

    printf("Successfully started! Tracking TCP connections...\n");
    printf("Press Ctrl-C to stop.\n\n");

    /* Main loop - print counter every second */
    while (running) {
        __u32 key = 0;
        __u64 count = 0;
        
        err = bpf_map_lookup_elem(bpf_map__fd(skel->maps.conn_count), 
                                  &key, &count);
        if (!err) {
            printf("\rTotal TCP connections established: %llu", count);
            fflush(stdout);
        }
        
        sleep(1);
    }
    printf("\n");

cleanup:
    tcp_counter_bpf__destroy(skel);
    return err < 0 ? 1 : 0;
}