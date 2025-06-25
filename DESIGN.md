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
- Deterministic sampling based on flow size:
  - Large flows (>1MB): Keep 100%
  - Medium flows: Keep ~10%
  - Small flows: Keep ~3%
- Hash-based decisions ensure consistency
- Per-DSCP quotas prevent class starvation
- Batched transmission to controller

### 3. Controller-Side Expansion
- Statistical reconstruction of full workload:
  - Poisson replication based on sampling weights
  - Exponential inter-arrival time jittering
  - Source port variation for ECMP diversity
- Outputs simulator-ready flow lists

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

## Future Extensions

- **Sketch-based summaries**: Use count-min sketches for even lower overhead
- **ML-based interpolation**: Learn patterns to improve reconstruction accuracy  
- **Multi-tier sampling**: Add ToR-level aggregation for larger scale
- **Application awareness**: Correlate flows with job IDs for better classification