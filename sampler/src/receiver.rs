use crate::flow::{FlowInfo, FlowPacket};
use anyhow::Result;
use std::net::SocketAddr;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

/// UDP receiver for flow records from hosts
pub struct FlowReceiver {
    socket: UdpSocket,
    buffer_size: usize,
}

impl FlowReceiver {
    /// Create a new receiver listening on the specified address
    pub async fn new(listen_addr: SocketAddr, buffer_size: usize) -> Result<Self> {
        let socket = UdpSocket::bind(listen_addr).await?;
        info!("Flow receiver listening on {}", listen_addr);

        Ok(Self {
            socket,
            buffer_size,
        })
    }

    /// Run the receiver, sending flows to the provided channel
    pub async fn run(self, tx: mpsc::Sender<Vec<FlowInfo>>) -> Result<()> {
        let mut buf = vec![0u8; self.buffer_size];
        let mut total_packets = 0u64;
        let mut total_flows = 0u64;
        let mut error_count = 0u64;

        loop {
            match self.socket.recv_from(&mut buf).await {
                Ok((len, addr)) => {
                    total_packets += 1;

                    match FlowPacket::parse(&buf[..len]) {
                        Ok(flows) => {
                            let flow_count = flows.len();
                            total_flows += flow_count as u64;

                            debug!(
                                "Received {} flows from {} (packet {})",
                                flow_count, addr, total_packets
                            );

                            // Send flows for processing
                            if let Err(e) = tx.send(flows).await {
                                error!("Failed to send flows to processor: {}", e);
                                break;
                            }
                        }
                        Err(e) => {
                            error_count += 1;
                            warn!("Failed to parse packet from {} (len={}): {}", addr, len, e);

                            // Log periodic stats
                            if error_count % 1000 == 0 {
                                warn!(
                                    "Receiver stats: {} packets, {} flows, {} errors",
                                    total_packets, total_flows, error_count
                                );
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("UDP receive error: {}", e);
                    // Continue on transient errors
                    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                }
            }

            // Periodic stats logging
            if total_packets % 10000 == 0 && total_packets > 0 {
                info!(
                    "Receiver stats: {} packets, {} flows, {} errors ({:.2}% error rate)",
                    total_packets,
                    total_flows,
                    error_count,
                    (error_count as f64 / total_packets as f64) * 100.0
                );
            }
        }

        Ok(())
    }
}

/// Statistics for the receiver
#[derive(Debug, Default, Clone)]
pub struct ReceiverStats {
    pub packets_received: u64,
    pub flows_received: u64,
    pub parse_errors: u64,
    pub channel_errors: u64,
}

/// Receiver with statistics tracking
pub struct StatefulReceiver {
    receiver: FlowReceiver,
    stats: ReceiverStats,
}

impl StatefulReceiver {
    pub async fn new(listen_addr: SocketAddr, buffer_size: usize) -> Result<Self> {
        let receiver = FlowReceiver::new(listen_addr, buffer_size).await?;
        Ok(Self {
            receiver,
            stats: ReceiverStats::default(),
        })
    }

    /// Run with statistics tracking
    pub async fn run_with_stats(
        mut self,
        tx: mpsc::Sender<Vec<FlowInfo>>,
        stats_tx: mpsc::Sender<ReceiverStats>,
    ) -> Result<()> {
        let mut buf = vec![0u8; self.receiver.buffer_size];
        let mut last_stats_time = tokio::time::Instant::now();

        loop {
            match self.receiver.socket.recv_from(&mut buf).await {
                Ok((len, addr)) => {
                    self.stats.packets_received += 1;

                    match FlowPacket::parse(&buf[..len]) {
                        Ok(flows) => {
                            self.stats.flows_received += flows.len() as u64;

                            if let Err(e) = tx.send(flows).await {
                                self.stats.channel_errors += 1;
                                error!("Channel send error: {}", e);
                                break;
                            }
                        }
                        Err(e) => {
                            self.stats.parse_errors += 1;
                            debug!("Parse error from {}: {}", addr, e);
                        }
                    }
                }
                Err(e) => {
                    error!("UDP receive error: {}", e);
                    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                }
            }

            // Send stats periodically
            if last_stats_time.elapsed() > tokio::time::Duration::from_secs(10) {
                let _ = stats_tx.try_send(self.stats.clone());
                last_stats_time = tokio::time::Instant::now();
            }
        }

        Ok(())
    }

    pub fn stats(&self) -> &ReceiverStats {
        &self.stats
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow::FlowInfo;

    #[tokio::test]
    async fn test_receiver_creation() {
        let addr = "127.0.0.1:0".parse().unwrap();
        let receiver = FlowReceiver::new(addr, 65536).await.unwrap();

        // Should bind successfully
        let local_addr = receiver.socket.local_addr().unwrap();
        assert_eq!(
            local_addr.ip(),
            "127.0.0.1".parse::<std::net::IpAddr>().unwrap()
        );
        assert_ne!(local_addr.port(), 0); // Should get assigned port
    }

    #[tokio::test]
    async fn test_flow_transmission() {
        // Create receiver
        let receiver_addr = "127.0.0.1:0".parse().unwrap();
        let receiver = FlowReceiver::new(receiver_addr, 65536).await.unwrap();
        let actual_addr = receiver.socket.local_addr().unwrap();

        // Create channel for flows
        let (tx, mut rx) = mpsc::channel(100);

        // Run receiver in background
        let receiver_handle = tokio::spawn(async move { receiver.run(tx).await });

        // Send test packet
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        // Create test flow
        let flow = FlowInfo {
            saddr: 0x0a000001,
            daddr: 0x0a000002,
            sport: 1234,
            dport: 80,
            protocol: 6,
            dscp: 10,
            _pad: 0,
            start_time_ns: 1000,
            end_time_ns: 2000,
            bytes_sent: 1024,
            bytes_recv: 512,
        };

        // Build packet - simulate what tcp_monitor sends
        let mut packet = vec![0, 1]; // count = 1
        let flow_be = FlowInfo {
            saddr: flow.saddr,      // Host order
            daddr: flow.daddr,      // Host order
            sport: 1234u16.to_be(), // Network order
            dport: 80u16.to_be(),   // Network order
            protocol: flow.protocol,
            dscp: flow.dscp,
            _pad: 0,
            start_time_ns: flow.start_time_ns, // Host order
            end_time_ns: flow.end_time_ns,     // Host order
            bytes_sent: flow.bytes_sent,       // Host order
            bytes_recv: flow.bytes_recv,       // Host order
        };

        let flow_bytes = unsafe {
            std::slice::from_raw_parts(
                &flow_be as *const FlowInfo as *const u8,
                std::mem::size_of::<FlowInfo>(),
            )
        };
        packet.extend_from_slice(flow_bytes);

        sender.send_to(&packet, actual_addr).await.unwrap();

        // Receive flows
        let flows = rx.recv().await.unwrap();
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].saddr, 0x0a000001);
        assert_eq!(flows[0].bytes_sent, 1024);

        // Clean up
        receiver_handle.abort();
    }
}
