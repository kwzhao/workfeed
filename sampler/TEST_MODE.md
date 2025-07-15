# Testing the Sampler

## Test Output Mode

The sampler includes a `--test-output` flag that writes sampled flows to a file instead of forwarding them to the controller. This is useful for:

1. Testing the sampler without a controller
2. Debugging sampling decisions
3. Collecting sample data for analysis
4. Integration testing with tcp_monitor

## Usage

```bash
# Start sampler in test mode (config is required)
sampler --config myconfig.json --test-output /tmp/sampled_flows.jsonl

# Example with all common options
sampler --config examples/config.json \
        --listen 0.0.0.0:5001 \
        --test-output /tmp/sampled_flows.jsonl
```

## Output Format

The output file contains one JSON object per line (JSON Lines format). Each object has:

```json
{
  "flow": {
    "saddr": 167772161,      // Source IP (10.0.0.1 as u32)
    "daddr": 167772162,      // Dest IP
    "sport": 45678,          // Source port
    "dport": 80,             // Dest port
    "protocol": 6,           // TCP
    "dscp": 10,              // Traffic class
    "start_time_ns": 1234567890,
    "end_time_ns": 1234567990,
    "bytes_sent": 102400     // 100KB
  },
  "weight": 4.0,             // Sampling weight (1/rate)
  "sampling_bucket": "medium" // Which rule matched
}
```

## Integration Testing

To test the full pipeline:

1. Start the sampler in test mode:
   ```bash
   sampler --config examples/config.json --test-output /tmp/sampled_flows.jsonl
   ```

2. In another terminal, run tcp_monitor to send flows:
   ```bash
   # Default settings
   sudo tcp_monitor --daemon --udp-host 127.0.0.1 --udp-port 5001
   
   # Or with custom batch settings
   sudo tcp_monitor --daemon --udp-host 127.0.0.1 --udp-port 5001 \
                    --batch-size 256 --flush-ms 100
   ```

3. Generate some test traffic (e.g., using curl, iperf, etc.)

4. Stop both processes and examine the output file:
   ```bash
   # Count sampled flows
   wc -l /tmp/sampled_flows.jsonl
   
   # View first few flows
   head -5 /tmp/sampled_flows.jsonl | jq
   
   # Analyze by DSCP class
   jq '.flow.dscp' /tmp/sampled_flows.jsonl | sort | uniq -c
   ```

## Analyzing Results

You can use jq to analyze the sampled flows:

```bash
# Average flow size by sampling bucket
jq -s 'group_by(.sampling_bucket) | 
       map({bucket: .[0].sampling_bucket, 
            avg_size: (map(.flow.bytes_sent) | add / length)})' \
       /tmp/sampled_flows.jsonl

# Distribution of sampling weights
jq '.weight' /tmp/sampled_flows.jsonl | sort -n | uniq -c

# Flows by DSCP class
jq -s 'group_by(.flow.dscp) | 
       map({dscp: .[0].flow.dscp, count: length})' \
       /tmp/sampled_flows.jsonl
```

## Notes

- The test output file is written in append mode
- Flows are flushed to disk every 100 records for real-time visibility
- If the controller address is specified with --test-output, it will be ignored
- File I/O errors are logged but don't stop the sampler
- tcp_monitor requires sudo/root privileges since it uses eBPF
- Default UDP port for both tcp_monitor and sampler is 5001