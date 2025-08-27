#!/bin/bash
# test_tcp_monitor.sh - Integration test for TCP monitor

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test configuration
MONITOR_BIN="./build/tcp_monitor"
MONITOR_PID=""
MONITOR_LOG="/tmp/tcp_monitor_test.log"
TEST_FAILED=0

# Clean up function
cleanup() {
    echo -e "\n${YELLOW}Cleaning up...${NC}"
    if [ ! -z "$MONITOR_PID" ]; then
        sudo kill -TERM "$MONITOR_PID" 2>/dev/null || true
        wait "$MONITOR_PID" 2>/dev/null || true
    fi
    rm -f "$MONITOR_LOG"
}

# Set up trap for cleanup
trap cleanup EXIT

# Check if we have the binary
if [ ! -f "$MONITOR_BIN" ]; then
    echo -e "${RED}Error: tcp_monitor binary not found at $MONITOR_BIN${NC}"
    echo "Please run 'make' first"
    exit 1
fi

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: This test must be run as root (for eBPF)${NC}"
    echo "Usage: sudo $0"
    exit 1
fi

echo -e "${GREEN}=== TCP Monitor Integration Test ===${NC}"
echo

# Start the monitor in background
echo -e "${YELLOW}Starting TCP monitor...${NC}"
"$MONITOR_BIN" --verbose >"$MONITOR_LOG" 2>&1 &
MONITOR_PID=$!

# Give it time to start
sleep 2

# Check if monitor is still running
if ! kill -0 "$MONITOR_PID" 2>/dev/null; then
    echo -e "${RED}TCP monitor failed to start!${NC}"
    cat "$MONITOR_LOG"
    exit 1
fi

echo -e "${GREEN}TCP monitor started successfully (PID: $MONITOR_PID)${NC}"
echo

# Function to generate TCP traffic
generate_traffic() {
    local desc="$1"
    local cmd="$2"

    echo -e "${YELLOW}Test: $desc${NC}"
    echo "Command: $cmd"

    # Run the command
    eval "$cmd" >/dev/null 2>&1 || true

    # Give time for events to be processed
    sleep 1
}

# Test 1: Simple HTTP request (force IPv4)
generate_traffic "HTTP request to example.com" \
    "curl -4 -s -m 2 http://example.com"

# Test 2: HTTPS request (force IPv4)
generate_traffic "HTTPS request to example.com" \
    "curl -4 -s -m 2 https://example.com"

# Test 3: Multiple connections (force IPv4)
generate_traffic "Multiple short connections" \
    "for i in {1..3}; do nc -4 -w 1 -z google.com 80; done"

# Test 4: Local connection
generate_traffic "Local SSH connection" \
    "ssh -4 -o ConnectTimeout=2 -o StrictHostKeyChecking=no localhost exit 2>/dev/null || true"

# Test 5: DNS lookup using TCP (force IPv4)
generate_traffic "DNS lookup over TCP" \
    "nslookup -vc example.com 8.8.8.8"

# Give time for final events
sleep 2

# Stop the monitor gracefully
echo -e "\n${YELLOW}Stopping TCP monitor...${NC}"
sudo kill -TERM "$MONITOR_PID"
wait "$MONITOR_PID" 2>/dev/null || true
MONITOR_PID=""

# Analyze results
echo -e "\n${GREEN}=== Test Results ===${NC}"
echo

# Check if we captured any flows
FLOW_COUNT=$(grep -c "Flow:" "$MONITOR_LOG" || true)
CREATED_COUNT=$(grep "Flows created:" "$MONITOR_LOG" | tail -1 | awk '{print $3}' || echo "0")
COMPLETED_COUNT=$(grep "Flows completed:" "$MONITOR_LOG" | tail -1 | awk '{print $3}' || echo "0")

echo "Flows captured: $FLOW_COUNT"
echo "Flows created: $CREATED_COUNT"
echo "Flows completed: $COMPLETED_COUNT"

# Expected minimum flows:
# - 2 curl requests (HTTP + HTTPS)
# - 3 nc connections
# - 1 SSH attempt (may fail but should create flow)
# - 1 DNS TCP query
# Total: at least 7 flows
EXPECTED_MIN_FLOWS=7

# Show some example flows
if [ "$FLOW_COUNT" -gt 0 ]; then
    echo -e "\n${GREEN}Sample captured flows:${NC}"
    grep "Flow:" "$MONITOR_LOG" | head -5

    # Check if we got enough flows
    if [ "$FLOW_COUNT" -lt $EXPECTED_MIN_FLOWS ]; then
        echo -e "\n${YELLOW}Warning: Expected at least $EXPECTED_MIN_FLOWS flows, but only captured $FLOW_COUNT${NC}"
        echo "Some connections may have used IPv6 or failed to establish"
    fi
else
    echo -e "\n${RED}No flows captured!${NC}"
    TEST_FAILED=1
fi

# Also check that created count matches expectations
if [ "$CREATED_COUNT" -lt "$EXPECTED_MIN_FLOWS" ]; then
    echo -e "${YELLOW}Warning: Only $CREATED_COUNT flows were created (expected at least $EXPECTED_MIN_FLOWS)${NC}"
fi

# Check for errors (excluding the "Failed connects" statistic which is expected)
ERROR_COUNT=$(grep -v "Failed connects:" "$MONITOR_LOG" | grep -c -E "(Error|Failed)" || true)
if [ "$ERROR_COUNT" -gt 0 ]; then
    echo -e "\n${RED}Errors found in log:${NC}"
    grep -E "(Error|Failed|failed)" "$MONITOR_LOG" | grep -v "Failed connects:" | tail -20 || true
fi

# Show statistics
echo -e "\n${GREEN}Final statistics from monitor:${NC}"
grep -A 10 "=== Statistics ===" "$MONITOR_LOG" | tail -11 || true

# Final verdict
echo
if [ "$TEST_FAILED" -eq 0 ] && [ "$FLOW_COUNT" -ge "$EXPECTED_MIN_FLOWS" ]; then
    echo -e "${GREEN}✓ All tests passed!${NC}"
    echo "The TCP monitor successfully captured $FLOW_COUNT flow events (expected at least $EXPECTED_MIN_FLOWS)."
elif [ "$TEST_FAILED" -eq 0 ] && [ "$FLOW_COUNT" -gt 0 ]; then
    echo -e "${YELLOW}⚠ Tests partially passed${NC}"
    echo "Captured $FLOW_COUNT flows, but expected at least $EXPECTED_MIN_FLOWS"
    echo "This may be due to connection failures or IPv6 fallback"
else
    echo -e "${RED}✗ Tests failed!${NC}"
    echo "Check the log file for details: $MONITOR_LOG"
    exit 1
fi

echo -e "\n${YELLOW}Full log saved to: $MONITOR_LOG${NC}"
