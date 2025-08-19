# Workfeed Design

## Overview

Workfeed is a distributed workload collection system that captures real-time network traffic patterns for Polyphony's performance simulators. It efficiently monitors large-scale networks while maintaining the accuracy needed for tail latency prediction.

## Problem Statement

### Requirements
Polyphony's prediction models (Parsimon, m3) require per-class workload characteristics:
- Flow arrival rates by traffic class
- Flow size distributions
- DSCP class breakdowns

### Challenges
Complete flow collection in datacenters is infeasible due to:
- **Scale**: Millions of flows per second across thousands of hosts
- **Bandwidth**: Centralized collection would create network bottlenecks
- **Relevance**: Most flows are small mice with negligible impact on tail latency

## Architecture

Workfeed employs a three-stage pipeline that balances measurement accuracy with collection efficiency:

### Stage 1: Per-Host Collection (eBPF)
**Purpose**: Capture all TCP flows with minimal overhead

- **Technology**: eBPF probes on TCP socket lifecycle events
- **Performance**: ~50ns overhead per flow via zero-copy ring buffers
- **Data captured**:
  - Network 5-tuple (source/dest IP:port, protocol)
  - DSCP marking for traffic classification
  - Byte counters (sent/received)
  - Precise timestamps (nanosecond resolution)

### Stage 2: Per-Rack Sampling
**Purpose**: Reduce data volume while preserving statistical properties

- **Sampling strategy**: Size-based deterministic sampling
  - Large flows (>1MB): 100% sampling rate
  - Medium flows (10KB-1MB): 25% sampling rate
  - Small flows (<10KB): 3.125% sampling rate
  - Rates fully configurable via JSON rules
- **Consistency**: Hash-based decisions using (5-tuple + DSCP)
- **Reconstruction**: Each sample carries weight = 1/sampling_rate
- **Transport**: Batched UDP transmission to controller

### Stage 3: Controller-Side Expansion (Planned)
**Purpose**: Reconstruct complete workload from samples

- **Statistical methods**:
  - Poisson process replication using sampling weights
  - Exponential distribution for inter-arrival times
  - Source port randomization for ECMP path diversity
- **Output**: Simulator-ready flow traces
- **Status**: Design complete, implementation pending

## Design Rationale

### eBPF for Host-Level Collection
eBPF provides the ideal balance of safety, performance, and deployability:
- **Performance**: In-kernel execution eliminates context switches
- **Safety**: Verified programs cannot crash or compromise the kernel
- **Availability**: Standard in Linux 4.x+ kernels
- **Efficiency**: Near-zero overhead enables line-rate monitoring

### Size-Based Sampling Strategy
This approach leverages the empirical observation that flow impact correlates with size:
- **Large flows** (elephants): Dominate queue occupancy and tail latency
- **Small flows** (mice): Numerous but individually negligible for tail metrics
- **Result**: 100× data reduction while preserving tail behavior accuracy

### Statistical Reconstruction Methodology
Reconstruction transforms samples back into complete workloads:
- **Requirement**: Simulators need complete flow lists, not statistical summaries
- **Approach**: Well-established traffic models (Poisson arrivals, exponential sizes)
- **Benefit**: Maintains statistical properties critical for accurate prediction

## Integration with Polyphony

Workfeed seamlessly integrates into Polyphony's control loop:

```
Network Traffic → Workfeed Collection → Flow Traces → Simulators → Predictions → Controller
```

**Operation**: The controller queries Workfeed every epoch (typically 30 seconds) for updated workload snapshots, replacing static trace files from initial experiments.

## Implementation Strategy

### Unified tcp_monitor Binary

A single executable supports both development and production use cases:

**Operating Modes**:
- `tcp_monitor --debug`: Interactive debugging (prints to stdout)
- `tcp_monitor --daemon --udp-host <host> --udp-port <port>`: Production mode (UDP batching)

**Benefits**:
- Eliminates code duplication between debug and production paths
- Enables immediate testing of probe modifications
- Simplifies deployment with single-binary distribution
- Facilitates incremental feature additions

### Per-Host Collector Design

The daemon mode optimizes for efficiency and reliability:

**Batching Configuration**:
- Batch size: 128 flows default, 256 max (`--batch-size`)
- Flush interval: 200ms default (`--flush-ms`)
- Failure handling: Drop-on-error prevents blocking
- Performance monitoring: Extended batch statistics
- Concurrency: Per-CPU statistics eliminate lock contention

### Component Architecture

The pipeline separates concerns across four independent components:

1. **eBPF Probe** (kernel space)
   - Intercepts TCP socket lifecycle events
   - Extracts flow metadata with minimal overhead
   
2. **tcp_monitor** (per-host userspace)
   - Consumes eBPF ring buffer events
   - Batches and forwards flow records
   
3. **Sampler** (per-rack aggregation)
   - Applies configurable size-based sampling
   - Maintains per-class statistics
   
4. **Controller Shim** (centralized)
   - Expands samples into complete workloads
   - Feeds simulators with reconstructed traces

This modular design enables independent development, testing, and deployment of each component.

## Technical Specifications

### Flow Record Structure
Each flow record occupies exactly 48 bytes:

| Field | Size | Type | Description |
|-------|------|------|-------------|
| `saddr` | 4B | uint32 | Source IPv4 (host byte order) |
| `daddr` | 4B | uint32 | Destination IPv4 (host byte order) |
| `sport` | 2B | uint16 | Source port (network byte order) |
| `dport` | 2B | uint16 | Destination port (network byte order) |
| `protocol` | 1B | uint8 | Protocol (always 6 for TCP) |
| `dscp` | 1B | uint8 | DSCP value from TOS field |
| `start_ns` | 8B | uint64 | Flow start (nanoseconds) |
| `end_ns` | 8B | uint64 | Flow end (nanoseconds) |
| `bytes_sent` | 8B | uint64 | Bytes sent by source |
| `bytes_recv` | 8B | uint64 | Bytes received by source |

### Wire Protocol
UDP packet structure for flow transmission:

```
[Header: 2 bytes] [Flow Records: N × 48 bytes]
```
- **Header**: Flow count (uint16, network byte order)
- **Payload**: Consecutive flow records
- **MTU Safety**: Maximum ~9000 bytes per packet

### Configuration Schema

```json
{
  "sampling": {
    "rules": [
      {"max_bytes": 10240, "rate": 0.03125},      // Small: ≤10KB @ 3.125%
      {"max_bytes": 1048576, "rate": 0.25},       // Medium: ≤1MB @ 25%
      {"max_bytes": null, "rate": 1.0}            // Large: >1MB @ 100%
    ]
  },
  "batching": {
    "max_batch_size": 128,                        // Flows per batch
    "timeout_ms": 100                             // Flush interval
  },
  "controller": {
    "address": "10.0.0.1:5000"                    // Destination endpoint
  }
}
```

## Known Limitations

| Limitation | Impact | Workaround |
|------------|--------|------------|
| IPv4 only | IPv6 flows counted but not captured | IPv6 support planned |
| TCP only | No UDP flow visibility | UDP tracking in roadmap |
| No per-DSCP quotas | Potential class starvation | Manual rate tuning |
| Controller expansion pending | No automatic workload reconstruction | Use raw samples |

## Roadmap

### Near-term Enhancements
- **Per-DSCP quotas**: Ensure fair sampling across traffic classes
- **IPv6 support**: Full dual-stack flow capture
- **Controller expansion**: Complete statistical reconstruction implementation

### Long-term Evolution
- **Sketch-based compression**: Count-min sketches for extreme efficiency
- **ML-driven reconstruction**: Learning-based workload interpolation
- **Hierarchical aggregation**: Multi-tier sampling for hyperscale deployments
- **Application integration**: Job-aware flow classification via metadata correlation
