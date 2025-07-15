use crate::flow::{FlowPacket, SampledFlow};
use anyhow::Result;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::{interval, Interval};
use tracing::{debug, error, info, warn};

/// Batch forwarder for sampled flows
pub struct BatchForwarder {
    socket: UdpSocket,
    controller_addr: SocketAddr,
    max_batch_size: usize,
    timeout: Duration,
}

impl BatchForwarder {
    /// Create a new forwarder
    pub async fn new(
        controller_addr: SocketAddr,
        max_batch_size: usize,
        timeout_ms: u64,
    ) -> Result<Self> {
        // Bind to any available port
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        info!(
            "Batch forwarder created, will send to {} (batch_size={}, timeout={}ms)",
            controller_addr, max_batch_size, timeout_ms
        );

        Ok(Self {
            socket,
            controller_addr,
            max_batch_size,
            timeout: Duration::from_millis(timeout_ms),
        })
    }

    /// Send a batch of flows
    async fn send_batch(&self, batch: &[SampledFlow]) -> Result<()> {
        if batch.is_empty() {
            return Ok(());
        }

        let data = FlowPacket::serialize(batch)?;

        match self.socket.send_to(&data, self.controller_addr).await {
            Ok(sent) => {
                debug!(
                    "Sent batch of {} flows ({} bytes) to {}",
                    batch.len(),
                    sent,
                    self.controller_addr
                );
                Ok(())
            }
            Err(e) => {
                error!("Failed to send batch: {}", e);
                Err(e.into())
            }
        }
    }

    /// Run the forwarder, consuming flows from the channel
    pub async fn run(self, mut rx: mpsc::Receiver<SampledFlow>) -> Result<()> {
        let mut batch = Vec::with_capacity(self.max_batch_size);
        let mut timer = interval(self.timeout);
        timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        let mut total_sent = 0u64;
        let mut total_batches = 0u64;
        let mut send_errors = 0u64;

        loop {
            tokio::select! {
                // Receive sampled flows
                Some(flow) = rx.recv() => {
                    batch.push(flow);

                    // Send if batch is full
                    if batch.len() >= self.max_batch_size {
                        if let Err(e) = self.send_batch(&batch).await {
                            send_errors += 1;
                            warn!("Batch send error: {}", e);
                        } else {
                            total_sent += batch.len() as u64;
                            total_batches += 1;
                        }
                        batch.clear();
                    }
                }

                // Timeout - send partial batch
                _ = timer.tick() => {
                    if !batch.is_empty() {
                        if let Err(e) = self.send_batch(&batch).await {
                            send_errors += 1;
                            warn!("Timeout batch send error: {}", e);
                        } else {
                            total_sent += batch.len() as u64;
                            total_batches += 1;
                        }
                        batch.clear();
                    }
                }
            }

            // Periodic stats
            if total_batches % 100 == 0 && total_batches > 0 {
                info!(
                    "Forwarder stats: {} flows in {} batches, {} errors",
                    total_sent, total_batches, send_errors
                );
            }
        }
    }
}

/// Statistics for the forwarder
#[derive(Debug, Default, Clone)]
pub struct ForwarderStats {
    pub flows_sent: u64,
    pub batches_sent: u64,
    pub send_errors: u64,
    pub avg_batch_size: f64,
}

/// Forwarder with statistics tracking
pub struct StatefulForwarder {
    forwarder: BatchForwarder,
    stats: ForwarderStats,
}

impl StatefulForwarder {
    pub async fn new(
        controller_addr: SocketAddr,
        max_batch_size: usize,
        timeout_ms: u64,
    ) -> Result<Self> {
        let forwarder = BatchForwarder::new(controller_addr, max_batch_size, timeout_ms).await?;
        Ok(Self {
            forwarder,
            stats: ForwarderStats::default(),
        })
    }

    /// Send a batch and update stats
    async fn send_batch_with_stats(&mut self, batch: &[SampledFlow]) -> Result<()> {
        if batch.is_empty() {
            return Ok(());
        }

        match self.forwarder.send_batch(batch).await {
            Ok(()) => {
                self.stats.flows_sent += batch.len() as u64;
                self.stats.batches_sent += 1;
                self.update_avg_batch_size();
                Ok(())
            }
            Err(e) => {
                self.stats.send_errors += 1;
                Err(e)
            }
        }
    }

    fn update_avg_batch_size(&mut self) {
        if self.stats.batches_sent > 0 {
            self.stats.avg_batch_size =
                self.stats.flows_sent as f64 / self.stats.batches_sent as f64;
        }
    }

    /// Run with statistics tracking
    pub async fn run_with_stats(
        mut self,
        mut rx: mpsc::Receiver<SampledFlow>,
        stats_tx: mpsc::Sender<ForwarderStats>,
    ) -> Result<()> {
        let mut batch = Vec::with_capacity(self.forwarder.max_batch_size);
        let mut timer = interval(self.forwarder.timeout);
        timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        let mut last_stats_time = tokio::time::Instant::now();

        loop {
            tokio::select! {
                Some(flow) = rx.recv() => {
                    batch.push(flow);

                    if batch.len() >= self.forwarder.max_batch_size {
                        let _ = self.send_batch_with_stats(&batch).await;
                        batch.clear();
                    }
                }

                _ = timer.tick() => {
                    if !batch.is_empty() {
                        let _ = self.send_batch_with_stats(&batch).await;
                        batch.clear();
                    }
                }
            }

            // Send stats periodically
            if last_stats_time.elapsed() > Duration::from_secs(10) {
                let _ = stats_tx.try_send(self.stats.clone());
                last_stats_time = tokio::time::Instant::now();
            }
        }
    }

    pub fn stats(&self) -> &ForwarderStats {
        &self.stats
    }
}

/// Combined batch processor that handles both batching timer and flow processing
pub struct BatchProcessor {
    batch: Vec<SampledFlow>,
    max_batch_size: usize,
    timer: Interval,
    tx: mpsc::Sender<Vec<SampledFlow>>,
}

impl BatchProcessor {
    pub fn new(max_batch_size: usize, timeout_ms: u64, tx: mpsc::Sender<Vec<SampledFlow>>) -> Self {
        let mut timer = interval(Duration::from_millis(timeout_ms));
        timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        Self {
            batch: Vec::with_capacity(max_batch_size),
            max_batch_size,
            timer,
            tx,
        }
    }

    /// Add a flow to the batch
    pub async fn add_flow(&mut self, flow: SampledFlow) -> Result<()> {
        self.batch.push(flow);

        if self.batch.len() >= self.max_batch_size {
            self.flush().await?;
        }

        Ok(())
    }

    /// Flush the current batch
    pub async fn flush(&mut self) -> Result<()> {
        if !self.batch.is_empty() {
            let batch = std::mem::replace(&mut self.batch, Vec::with_capacity(self.max_batch_size));
            self.tx.send(batch).await?;
        }
        Ok(())
    }

    /// Check if timeout has elapsed and flush if needed
    pub async fn check_timeout(&mut self) -> Result<()> {
        // Use select! to check timer without blocking
        tokio::select! {
            _ = self.timer.tick() => {
                self.flush().await?;
            }
            else => {}
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow::FlowInfo;

    fn test_flow() -> FlowInfo {
        FlowInfo {
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
        }
    }

    #[tokio::test]
    async fn test_forwarder_creation() {
        let addr = "127.0.0.1:5000".parse().unwrap();
        let forwarder = BatchForwarder::new(addr, 128, 100).await.unwrap();

        // Should bind successfully
        let local_addr = forwarder.socket.local_addr().unwrap();
        assert_ne!(local_addr.port(), 0);
    }

    #[tokio::test]
    async fn test_batch_processor() {
        let (tx, mut rx) = mpsc::channel(10);
        let mut processor = BatchProcessor::new(3, 100, tx);

        // Add flows
        let flow = SampledFlow::new(test_flow(), 1.0, "test");
        processor.add_flow(flow.clone()).await.unwrap();
        processor.add_flow(flow.clone()).await.unwrap();

        // Should not send yet (batch size is 3)
        assert!(rx.try_recv().is_err());

        // Third flow should trigger send
        processor.add_flow(flow.clone()).await.unwrap();

        let batch = rx.recv().await.unwrap();
        assert_eq!(batch.len(), 3);
    }

    #[tokio::test]
    async fn test_timeout_flush() {
        let (tx, mut rx) = mpsc::channel(10);
        let mut processor = BatchProcessor::new(10, 50, tx); // 50ms timeout

        // Add one flow
        let flow = SampledFlow::new(test_flow(), 1.0, "test");
        processor.add_flow(flow).await.unwrap();

        // Wait for timeout
        tokio::time::sleep(Duration::from_millis(60)).await;
        processor.check_timeout().await.unwrap();

        // Should have flushed
        let batch = rx.recv().await.unwrap();
        assert_eq!(batch.len(), 1);
    }
}
