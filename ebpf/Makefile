# Makefile for Workfeed eBPF programs

# Compiler settings
CLANG ?= clang
CC ?= gcc
LLVM_STRIP ?= llvm-strip
BPFTOOL ?= bpftool

# Directories
SRC_DIR := src
LOADER_DIR := loader
INCLUDE_DIR := include
BUILD_DIR := build

# Create build directory
$(shell mkdir -p $(BUILD_DIR))

# Flags
CFLAGS := -g -O2 -Wall
BPF_CFLAGS := -target bpf -mcpu=v3 -D__TARGET_ARCH_x86_64 -I$(INCLUDE_DIR) -O2
LOADER_CFLAGS := $(CFLAGS) -I$(INCLUDE_DIR)

# Check for newer libbpf in /usr/local
ifneq ($(wildcard /usr/local/lib/libbpf.a),)
    # Option A: Static linking (recommended)
    LDFLAGS := /usr/local/lib/libbpf.a -lelf -lz
    LOADER_CFLAGS += -I/usr/local/include
else
    # Option B: Dynamic linking with rpath
    LDFLAGS := -L/usr/local/lib -Wl,-rpath=/usr/local/lib -lbpf -lelf -lz
    LOADER_CFLAGS += -I/usr/local/include
endif

# Source files
BPF_SRCS := $(wildcard $(SRC_DIR)/*.bpf.c)
BPF_OBJS := $(patsubst $(SRC_DIR)/%.bpf.c,$(BUILD_DIR)/%.bpf.o,$(BPF_SRCS))
LOADER_SRCS := $(wildcard $(LOADER_DIR)/*.c)
LOADER_BINS := $(patsubst $(LOADER_DIR)/%.c,$(BUILD_DIR)/%,$(LOADER_SRCS))

# Default target
all: $(BPF_OBJS) $(LOADER_BINS)

# Build eBPF programs
$(BUILD_DIR)/%.bpf.o: $(SRC_DIR)/%.bpf.c
	$(CLANG) $(BPF_CFLAGS) -g -c $< -o $@

# Generate skeleton headers
$(BUILD_DIR)/%.skel.h: $(BUILD_DIR)/%.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

# Build user-space loaders
$(BUILD_DIR)/%: $(LOADER_DIR)/%.c $(BUILD_DIR)/%.skel.h
	$(CC) $(LOADER_CFLAGS) -I$(BUILD_DIR) $< -o $@ $(LDFLAGS)

# Clean build artifacts
clean:
	rm -rf $(BUILD_DIR)

# Install (TBD - will add install targets later)
install:
	@echo "Install target not yet implemented"

.PHONY: all clean install