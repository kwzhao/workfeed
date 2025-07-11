#!/bin/bash
# test_daemon_mode.sh - Test tcp_monitor daemon mode

set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}=== TCP Monitor Daemon Mode Test ===${NC}"
echo

# Start netcat UDP listener in background
echo -e "${YELLOW}Starting UDP listener on port 5001...${NC}"
nc -u -l -p 5001 > /tmp/daemon_test_output.bin &
NC_PID=$!
echo "Listener PID: $NC_PID"

# Give it time to start
sleep 1

# Start tcp_monitor in daemon mode with small batch size for testing
echo -e "${YELLOW}Starting tcp_monitor in daemon mode...${NC}"
sudo ./build/tcp_monitor --daemon --batch-size 5 --flush-ms 1000 -v &
MONITOR_PID=$!
echo "Monitor PID: $MONITOR_PID"

# Give it time to initialize
sleep 2

# Generate some test traffic
echo -e "${YELLOW}Generating test traffic...${NC}"
curl -4 -s http://example.com > /dev/null
curl -4 -s https://google.com > /dev/null
for i in {1..3}; do
    nc -4 -w 1 -z google.com 80
done

# Wait for flush
echo -e "${YELLOW}Waiting for batch flush...${NC}"
sleep 2

# Stop tcp_monitor
echo -e "${YELLOW}Stopping tcp_monitor...${NC}"
sudo kill -TERM $MONITOR_PID 2>/dev/null || true
wait $MONITOR_PID 2>/dev/null || true

# Stop netcat
kill $NC_PID 2>/dev/null || true
wait $NC_PID 2>/dev/null || true

# Check if we received data
echo -e "\n${GREEN}=== Results ===${NC}"
if [ -s /tmp/daemon_test_output.bin ]; then
    SIZE=$(stat -c%s /tmp/daemon_test_output.bin)
    echo -e "${GREEN}✓ Received UDP data: $SIZE bytes${NC}"

    # Decode the first batch
    echo -e "\n${YELLOW}First batch header:${NC}"
    od -t u2 -N 2 /tmp/daemon_test_output.bin | head -1

    # Show first few bytes in hex
    echo -e "\n${YELLOW}First 64 bytes (hex):${NC}"
    xxd -l 64 /tmp/daemon_test_output.bin
else
    echo -e "${RED}✗ No UDP data received!${NC}"
fi

# Cleanup
rm -f /tmp/daemon_test_output.bin

echo -e "\n${GREEN}Test complete!${NC}"
