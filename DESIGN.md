# Workfeed Design

## Overview

Workfeed is a distributed workload collection system that captures real-time network traffic patterns and transforms them into traces suitable for Polyphony's performance simulators. It bridges the gap between Polyphony's need for workload information and the practical constraints of monitoring large-scale networks.

## Problem Statement

Polyphony's prediction models (Parsimon, m3) require per-class workload characteristics as input:
- Flow arrival rates
- Flow size distributions
- DSCP class breakdowns

However, collecting every flow in a large datacenter is prohibitively expensive:
- Millions of flows per second across thousands of hosts
- Would overwhelm any centralized collection point
- Most flows are tiny mice that individually don't affect tail latency

## Architecture

Workfeed uses a three-stage pipeline to balance accuracy with efficiency:

### 1. Per-Host Collection (eBPF)
- Lightweight eBPF probes attached to TCP socket events
- Zero-copy collection via ring buffers
- Captures: 5-tuple, DSCP, bytes, start/end times
- Minimal overhead (~50ns per flow)

### 2. Per-Rack Sampling
- Deterministic sampling based on flow size
  - Example configuration might sample large flows (e.g., >1MB) at higher rates
  - Medium and small flows sampled at progressively lower rates
  - Exact thresholds and rates are configurable via JSON rules
- Hash-based decisions ensure consistency (hash of 5-tuple + DSCP)
- Each sampled flow gets a weight = 1/sampling_rate for reconstruction
- Batched transmission to controller via UDP

### 3. Controller-Side Expansion (Planned)
- Statistical reconstruction of full workload:
  - Poisson replication based on sampling weights
  - Exponential inter-arrival time jittering
  - Source port variation for ECMP diversity
- Outputs simulator-ready flow lists
- Note: Not yet implemented in current sampler

## Design Decisions

### Why eBPF?
- In-kernel execution avoids context switches
- Safe: verified programs can't crash the kernel
- Ubiquitous: available in modern Linux kernels
- Efficient: near-zero overhead for high-speed networks

### Why Size-Based Sampling?
- Large flows dominate bytes and queue occupancy
- Small flows are numerous but individually insignificant
- Size-aware sampling preserves tail behavior while reducing volume 100x

### Why Statistical Reconstruction?
- Simulators expect complete flow lists, not samples
- Poisson/exponential models match real traffic patterns
- Preserves statistical properties needed for accurate prediction

## Integration with Polyphony

Workfeed runs as a shim between the network and Polyphony's controller:

```
Network → Workfeed → Flow Traces → Simulators → Predictions → Controller
```

The controller queries Workfeed once per epoch (e.g., every 30 seconds) to get the latest workload snapshot. This replaces the static workload files used in initial experiments.

## Implementation Plan

See timeline in Chapter 5 of the thesis for detailed milestones.

### Implementation Decisions

#### Unified tcp_monitor Binary

Rather than separate binaries for debugging and production, we implement a single `tcp_monitor` executable with multiple modes:

- `tcp_monitor --debug` (or no flags): Current behavior - prints flows to stdout for debugging
- `tcp_monitor --daemon --udp-host <host> --udp-port <port>`: Production mode - batches flows and sends via UDP

This approach:
- Avoids code duplication for eBPF loading and ring buffer handling
- Keeps probe updates immediately testable in both modes
- Simplifies packaging and deployment (single binary)
- Makes future enhancements (sampling rates, etc.) easy to add

#### Per-Host Collector Architecture

The daemon mode implements batching with:
- Fixed-size batches (default 128 flows, max 256, configurable via `--batch-size`)
- Timer-based partial flush (default 200ms via `--flush-ms`)
- Drop-on-error for UDP failures (avoids blocking)
- Extended statistics for monitoring batch performance
- Per-CPU statistics to avoid lock contention

#### Component Separation

The complete pipeline consists of:
1. **eBPF probe** (kernel space): Captures TCP lifecycle events
2. **tcp_monitor** (per-host): Collects and batches flow records
3. **Per-rack sampler** (separate process): Applies size-based sampling
4. **Controller shim** (at controller): Expands samples into full workload

Each component can be developed and tested independently.

## Implementation Details

### Flow Record Format
Each flow record is 48 bytes containing:
- IPv4 addresses (saddr, daddr) - host byte order
- Ports (sport, dport) - network byte order
- Protocol (always 6 for TCP)
- DSCP value (extracted from TOS field)
- Timestamps (start_ns, end_ns) - nanosecond precision
- Byte counters (bytes_sent, bytes_recv)

### Packet Protocol
UDP packets contain:
- 2-byte count header (network byte order)
- N flow records (48 bytes each)
- Maximum ~9000 bytes per packet (MTU safe)

### Configuration Format
```json
{
  "sampling": {
    "rules": [
      {"max_bytes": 10240, "rate": 0.03125},      // ≤10KB: 3.125%
      {"max_bytes": 1048576, "rate": 0.25},       // ≤1MB: 25%
      {"max_bytes": null, "rate": 1.0}            // >1MB: 100%
    ]
  },
  "batching": {
    "max_batch_size": 128,
    "timeout_ms": 100
  },
  "controller": {
    "address": "10.0.0.1:5000"
  }
}
```

### Current Limitations
- IPv4 only (IPv6 connections counted but not captured)
- TCP only (no UDP flow tracking)
- No per-DSCP quotas (pure size-based sampling)
- Controller-side expansion not yet implemented

## Future Extensions

- **Per-DSCP quotas**: Prevent traffic class starvation
- **IPv6 support**: Extend eBPF probe for IPv6 flows
- **Sketch-based summaries**: Use count-min sketches for even lower overhead
- **ML-based interpolation**: Learn patterns to improve reconstruction accuracy
- **Multi-tier sampling**: Add ToR-level aggregation for larger scale
- **Application awareness**: Correlate flows with job IDs for better classification
