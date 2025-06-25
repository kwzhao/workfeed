# Workfeed eBPF Development Environment

This directory contains the eBPF-based TCP flow monitoring system for the Polyphony project's Workfeed component.

## Overview

Workfeed uses eBPF (Extended Berkeley Packet Filter) to monitor TCP socket lifecycle events in the Linux kernel, collecting flow statistics without modifying application code or impacting performance.

## Prerequisites

### Required Packages

```bash
# Core eBPF development tools
sudo apt update
sudo apt install -y \
    linux-headers-$(uname -r) \
    libbpf-dev \
    llvm \
    clang \
    gcc-multilib \
    build-essential \
    linux-tools-$(uname -r) \
    linux-tools-common \
    linux-tools-generic

# Additional dependencies
sudo apt install -y \
    libelf-dev \
    zlib1g-dev \
    libbfd-dev \
    libcap-dev \
    pahole
```

### Version Requirements

- **Kernel**: 5.15+ with BTF support (check `/sys/kernel/btf/vmlinux`)
- **libbpf**: v1.0+ (v1.3+ recommended for full BTF support)
- **bpftool**: v5.15+ (v7.1+ for autoattach support)
- **clang**: 11+ with BPF target support

## Project Structure

```
ebpf/
├── Makefile              # Build system
├── README.md            # This file
├── src/                 # eBPF programs (kernel space)
│   ├── tcp_counter.bpf.c # TCP connection counter
│   └── tcp_monitor.bpf.c # Full flow monitor (TODO)
├── loader/              # User-space loaders
│   ├── tcp_counter.c
│   └── tcp_monitor.c    # TODO
├── include/             # Headers
│   └── vmlinux_dev.h    # BTF header for kernel types
└── build/               # Build artifacts (generated)
```

## Building

The Makefile automatically handles eBPF compilation and user-space loader building:

```bash
# Build everything
make

# Build specific programs
make build/tcp_counter

# Clean build artifacts
make clean
```

### Build Configuration

The Makefile includes important flags:
- `-mcpu=v3`: Targets BPF ISA v3 to avoid unsupported instructions on older kernels
- `-O2`: Required optimization level for BPF programs
- `-target bpf`: Compiles for BPF target architecture
- `-D__TARGET_ARCH_x86_64`: Sets target architecture

## Common Issues and Solutions

### 1. Unsupported BTF_KIND Error

**Symptom**: `Unsupported BTF_KIND:19` error when loading BPF programs

**Cause**: Kernel BTF contains types not supported by older libbpf versions

**Solution**: Update libbpf to v1.0+ or use the no-BTF variant of programs

### 2. Unknown Opcode 0x8d Error

**Symptom**: `unknown opcode 8d` error from BPF verifier

**Cause**: Newer clang emits CALLX instruction not supported by kernel < 6.8

**Solution**: Already fixed in Makefile with `-mcpu=v3` flag

### 3. libbpf Version Mismatch

**Symptom**: Programs fail to load despite having newer libbpf installed

**Cause**: Binary linked against system's older libbpf.so

**Solution**: Makefile configured to use static linking or rpath for newer libbpf

## Testing Programs

### TCP Connection Counter

Counts TCP connections transitioning to ESTABLISHED state:

```bash
# Build and run
make build/tcp_counter
sudo ./build/tcp_counter

# In another terminal, create TCP connections
curl https://www.google.com
nc localhost 22

# Counter should increment with each new connection
```

## Development Workflow

1. **Write eBPF program** in `src/` directory
   - Include `vmlinux_dev.h` for kernel types
   - Use BPF helpers from `<bpf/bpf_helpers.h>`
   - Define maps and programs with appropriate SEC() macros

2. **Create user-space loader** in `loader/` directory
   - Use skeleton pattern with bpftool-generated headers
   - Handle program lifecycle: open, load, attach, cleanup

3. **Build and test** locally
   - Use `make` to build
   - Test with sudo (eBPF requires CAP_SYS_ADMIN)
   - Monitor `/sys/kernel/debug/tracing/trace_pipe` for bpf_printk output

4. **Deploy to production**
   - Generate vmlinux header from production kernel if different
   - Test on target system before deployment
   - Consider using systemd service for persistent monitoring

## Debugging

### Enable Debug Output

```bash
# Mount debugfs if not already mounted
sudo mount -t debugfs none /sys/kernel/debug

# Enable tracing
echo 1 | sudo tee /sys/kernel/debug/tracing/tracing_on

# View BPF program output
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

### Check Loaded Programs

```bash
# List all BPF programs
sudo bpftool prog list

# Show detailed program info
sudo bpftool prog show id <ID>

# List all BPF maps
sudo bpftool map list

# Dump map contents
sudo bpftool map dump id <ID>
```

### Verify BTF Support

```bash
# Check kernel BTF availability
ls -la /sys/kernel/btf/vmlinux

# Verify BTF can be dumped
bpftool btf dump file /sys/kernel/btf/vmlinux format c | head -20
```

## Next Steps

1. **TASK-002**: Implement full TCP socket lifecycle tracking
2. **TASK-003**: Add ring buffer for efficient flow record collection
3. **TASK-004**: Build daemon for continuous monitoring
4. **TASK-005**: Extract and track DSCP values for QoS analysis

## References

- [Linux eBPF Documentation](https://docs.kernel.org/bpf/)
- [libbpf Documentation](https://libbpf.readthedocs.io/)
- [BPF CO-RE (Compile Once, Run Everywhere)](https://nakryiko.com/posts/bpf-portability-and-co-re/)
- [bpftool Manual](https://man7.org/linux/man-pages/man8/bpftool.8.html)