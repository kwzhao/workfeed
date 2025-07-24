use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::net::Ipv4Addr;

/// Helper module for serializing IPs as strings
mod ip_serde {
    use super::*;

    pub fn serialize<S>(ip: &u32, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let addr = Ipv4Addr::from(*ip);
        serializer.serialize_str(&addr.to_string())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<u32, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct IpVisitor;

        impl<'de> Visitor<'de> for IpVisitor {
            type Value = u32;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("an IPv4 address string")
            }

            fn visit_str<E>(self, value: &str) -> Result<u32, E>
            where
                E: de::Error,
            {
                value
                    .parse::<Ipv4Addr>()
                    .map(u32::from)
                    .map_err(de::Error::custom)
            }
        }

        deserializer.deserialize_str(IpVisitor)
    }
}

/// TCP flow information - matches eBPF flow_record structure exactly
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FlowInfo {
    /// Source IP address
    #[serde(with = "ip_serde")]
    pub saddr: u32,
    /// Destination IP address
    #[serde(with = "ip_serde")]
    pub daddr: u32,
    /// Source port
    pub sport: u16,
    /// Destination port
    pub dport: u16,
    /// Protocol (always 6 for TCP)
    pub protocol: u8,
    /// DSCP value (6 bits, 0-63)
    pub dscp: u8,
    /// Padding for alignment (matches _pad in eBPF struct)
    #[serde(skip)]
    pub _pad: u16,
    /// Flow start time in nanoseconds
    pub start_time_ns: u64,
    /// Flow end time in nanoseconds
    pub end_time_ns: u64,
    /// Total bytes sent
    pub bytes_sent: u64,
    /// Total bytes received (not used by sampler, but part of eBPF struct)
    #[serde(skip)]
    pub bytes_recv: u64,
}

impl FlowInfo {
    /// Get the total flow size (currently just bytes_sent)
    pub fn size(&self) -> u64 {
        self.bytes_sent
    }

    /// Get the 5-tuple for hashing
    pub fn five_tuple(&self) -> (u32, u32, u16, u16, u8) {
        (
            self.saddr,
            self.daddr,
            self.sport,
            self.dport,
            self.protocol,
        )
    }

    /// Convert IPs to readable format for logging
    pub fn source_ip(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.saddr)
    }

    pub fn dest_ip(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.daddr)
    }

    /// Get flow duration in milliseconds
    pub fn duration_ms(&self) -> f64 {
        (self.end_time_ns - self.start_time_ns) as f64 / 1_000_000.0
    }
}

/// Sampled flow with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SampledFlow {
    /// Original flow information
    pub flow: FlowInfo,
    /// Sampling weight (1/rate) for statistical reconstruction
    pub weight: f64,
    /// Which sampling bucket this flow fell into
    pub sampling_bucket: String,
}

impl SampledFlow {
    pub fn new(flow: FlowInfo, weight: f64, bucket: &str) -> Self {
        Self {
            flow,
            weight,
            sampling_bucket: bucket.to_string(),
        }
    }
}

/// Packet format for receiving flows from hosts
#[repr(C)]
#[derive(Debug)]
pub struct FlowPacket {
    /// Number of flows in this packet
    pub count: u16,
    // Flow records follow immediately after
}

impl FlowPacket {
    /// Parse a UDP packet into flow records
    pub fn parse(data: &[u8]) -> anyhow::Result<Vec<FlowInfo>> {
        if data.len() < 2 {
            anyhow::bail!("Packet too small: {} bytes", data.len());
        }

        // Read count (network byte order)
        let count = u16::from_be_bytes([data[0], data[1]]) as usize;
        let flow_size = std::mem::size_of::<FlowInfo>();
        let expected_size = 2 + (count * flow_size);

        if data.len() < expected_size {
            anyhow::bail!(
                "Packet size mismatch: expected {} bytes, got {}",
                expected_size,
                data.len()
            );
        }

        let mut flows = Vec::with_capacity(count);
        let mut offset = 2;

        for _ in 0..count {
            // Safety: We verified the size above
            let flow_bytes = &data[offset..offset + flow_size];
            let flow = unsafe { std::ptr::read_unaligned(flow_bytes.as_ptr() as *const FlowInfo) };

            // Convert byte order:
            // - IPs are in host byte order (from kernel socket struct)
            // - Ports are in network byte order (from eBPF conversion)
            // - Timestamps and bytes are in host byte order
            let flow = FlowInfo {
                saddr: flow.saddr,               // Already in host order
                daddr: flow.daddr,               // Already in host order
                sport: u16::from_be(flow.sport), // Convert from network order
                dport: u16::from_be(flow.dport), // Convert from network order
                protocol: flow.protocol,
                dscp: flow.dscp,
                _pad: flow._pad,
                start_time_ns: flow.start_time_ns, // Already in host order
                end_time_ns: flow.end_time_ns,     // Already in host order
                bytes_sent: flow.bytes_sent,       // Already in host order
                bytes_recv: flow.bytes_recv,       // Already in host order
            };

            flows.push(flow);
            offset += flow_size;
        }

        Ok(flows)
    }

    /// Serialize sampled flows for transmission to controller
    pub fn serialize(flows: &[SampledFlow]) -> anyhow::Result<Vec<u8>> {
        // For now, just send the flow info with same format
        // TODO: Could enhance to include weights
        let count = flows.len() as u16;
        let flow_size = std::mem::size_of::<FlowInfo>();
        let mut buffer = Vec::with_capacity(2 + flows.len() * flow_size);

        // Write count
        buffer.extend_from_slice(&count.to_be_bytes());

        // Write flows
        for sampled in flows {
            let flow = sampled.flow;

            // Convert to same format as tcp_monitor expects:
            // - IPs in host byte order
            // - Ports in network byte order
            // - Timestamps and bytes in host byte order
            let net_flow = FlowInfo {
                saddr: flow.saddr,         // Keep in host order
                daddr: flow.daddr,         // Keep in host order
                sport: flow.sport.to_be(), // Convert to network order
                dport: flow.dport.to_be(), // Convert to network order
                protocol: flow.protocol,
                dscp: flow.dscp,
                _pad: 0,
                start_time_ns: flow.start_time_ns, // Keep in host order
                end_time_ns: flow.end_time_ns,     // Keep in host order
                bytes_sent: flow.bytes_sent,       // Keep in host order
                bytes_recv: 0,                     // Not used, set to 0
            };

            let bytes = unsafe {
                std::slice::from_raw_parts(&net_flow as *const FlowInfo as *const u8, flow_size)
            };
            buffer.extend_from_slice(bytes);
        }

        Ok(buffer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flow_size() {
        // FlowInfo struct size must match eBPF flow_record:
        // saddr: 4, daddr: 4, sport: 2, dport: 2, protocol: 1, dscp: 1,
        // _pad: 2, start_time_ns: 8, end_time_ns: 8, bytes_sent: 8, bytes_recv: 8
        // Total: 4+4+2+2+1+1+2+8+8+8+8 = 48 bytes
        assert_eq!(std::mem::size_of::<FlowInfo>(), 48);
    }

    #[test]
    fn test_packet_parsing() {
        // Create test packet with 2 flows
        let mut data = vec![0, 2]; // count = 2

        let flow1 = FlowInfo {
            saddr: 0x0a000001u32,   // 10.0.0.1 in host order
            daddr: 0x0a000002u32,   // 10.0.0.2 in host order
            sport: 1234u16.to_be(), // Port in network order
            dport: 80u16.to_be(),   // Port in network order
            protocol: 6,
            dscp: 10,
            _pad: 0,
            start_time_ns: 1000u64, // Host order
            end_time_ns: 2000u64,   // Host order
            bytes_sent: 1024u64,    // Host order
            bytes_recv: 512u64,     // Host order
        };

        let flow_bytes = unsafe {
            std::slice::from_raw_parts(
                &flow1 as *const FlowInfo as *const u8,
                std::mem::size_of::<FlowInfo>(),
            )
        };
        data.extend_from_slice(flow_bytes);
        data.extend_from_slice(flow_bytes); // Add same flow twice

        let flows = FlowPacket::parse(&data).unwrap();
        assert_eq!(flows.len(), 2);
        assert_eq!(flows[0].saddr, 0x0a000001);
        assert_eq!(flows[0].bytes_sent, 1024);
    }
}
