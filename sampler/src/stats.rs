use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{info, warn};

/// DSCP class statistics
#[derive(Debug, Default, Clone)]
pub struct DscpStats {
    /// Total flows seen
    pub total_flows: u64,
    /// Sampled flows
    pub sampled_flows: u64,
    /// Total bytes
    pub total_bytes: u64,
    /// Last seen timestamp
    pub last_seen: Option<Instant>,
}

impl DscpStats {
    pub fn record_flow(&mut self, sampled: bool, bytes: u64) {
        self.total_flows += 1;
        self.total_bytes += bytes;
        self.last_seen = Some(Instant::now());

        if sampled {
            self.sampled_flows += 1;
        }
    }

    pub fn sampling_rate(&self) -> f64 {
        if self.total_flows > 0 {
            self.sampled_flows as f64 / self.total_flows as f64
        } else {
            0.0
        }
    }
}

/// Overall sampler statistics
#[derive(Debug, Default, Clone)]
pub struct SamplerStats {
    /// Start time
    pub start_time: Option<Instant>,
    /// Total flows processed
    pub total_flows: u64,
    /// Total flows sampled
    pub total_sampled: u64,
    /// Total bytes processed
    pub total_bytes: u64,
    /// Per-DSCP statistics
    pub dscp_stats: HashMap<u8, DscpStats>,
    /// Flows by sampling rule
    pub flows_by_rule: HashMap<String, u64>,
}

impl SamplerStats {
    pub fn new() -> Self {
        Self {
            start_time: Some(Instant::now()),
            ..Default::default()
        }
    }

    /// Record a processed flow
    pub fn record_flow(&mut self, dscp: u8, bytes: u64, sampled: bool, rule_name: Option<&str>) {
        self.total_flows += 1;
        self.total_bytes += bytes;

        if sampled {
            self.total_sampled += 1;
            if let Some(rule) = rule_name {
                *self.flows_by_rule.entry(rule.to_string()).or_insert(0) += 1;
            }
        }

        self.dscp_stats
            .entry(dscp)
            .or_default()
            .record_flow(sampled, bytes);
    }

    /// Get overall sampling rate
    pub fn overall_sampling_rate(&self) -> f64 {
        if self.total_flows > 0 {
            self.total_sampled as f64 / self.total_flows as f64
        } else {
            0.0
        }
    }

    /// Get runtime duration
    pub fn runtime(&self) -> Duration {
        self.start_time
            .map(|start| start.elapsed())
            .unwrap_or_default()
    }

    /// Check for empty DSCP classes and generate warnings
    pub fn check_empty_classes(&self, window: Duration) -> Vec<String> {
        let mut warnings = Vec::new();
        let now = Instant::now();

        // Common DSCP values to check
        let common_dscp = [0, 10, 18, 26, 34, 46]; // BE, AF11, AF21, AF31, AF41, EF

        for &dscp in &common_dscp {
            if let Some(stats) = self.dscp_stats.get(&dscp) {
                // Check if we have flows but no samples
                if stats.total_flows > 0 && stats.sampled_flows == 0 {
                    warnings.push(format!(
                        "DSCP {} has {} flows but none sampled (rate: {:.2}%)",
                        dscp,
                        stats.total_flows,
                        stats.sampling_rate() * 100.0
                    ));
                }

                // Check if class has been inactive
                if let Some(last_seen) = stats.last_seen {
                    if now.duration_since(last_seen) > window {
                        warnings.push(format!(
                            "DSCP {} has been inactive for {:?}",
                            dscp,
                            now.duration_since(last_seen)
                        ));
                    }
                }
            }
        }

        warnings
    }

    /// Generate a summary report
    pub fn summary(&self) -> String {
        let runtime = self.runtime();
        let rate = self.overall_sampling_rate();

        let mut report = format!("Sampler Statistics (runtime: {runtime:?})\n");
        report.push_str(&format!(
            "Total flows: {} (sampled: {}, rate: {:.2}%)\n",
            self.total_flows,
            self.total_sampled,
            rate * 100.0
        ));
        report.push_str(&format!(
            "Total bytes: {} ({:.2} GB)\n",
            self.total_bytes,
            self.total_bytes as f64 / 1_073_741_824.0
        ));

        // Per-DSCP breakdown
        report.push_str("\nPer-DSCP breakdown:\n");
        let mut dscp_vec: Vec<_> = self.dscp_stats.iter().collect();
        dscp_vec.sort_by_key(|(dscp, _)| *dscp);

        for (dscp, stats) in dscp_vec {
            report.push_str(&format!(
                "  DSCP {}: {} flows ({} sampled, {:.2}% rate)\n",
                dscp,
                stats.total_flows,
                stats.sampled_flows,
                stats.sampling_rate() * 100.0
            ));
        }

        // Per-rule breakdown
        if !self.flows_by_rule.is_empty() {
            report.push_str("\nFlows by sampling rule:\n");
            let mut rule_vec: Vec<_> = self.flows_by_rule.iter().collect();
            rule_vec.sort_by_key(|(name, _)| name.as_str());

            for (rule, count) in rule_vec {
                report.push_str(&format!("  {rule}: {count} flows\n"));
            }
        }

        report
    }
}

/// Thread-safe statistics collector
#[derive(Clone)]
pub struct StatsCollector {
    stats: Arc<RwLock<SamplerStats>>,
    monitoring_window: Duration,
    warn_on_empty: bool,
}

impl StatsCollector {
    pub fn new(monitoring_window: Duration, warn_on_empty: bool) -> Self {
        Self {
            stats: Arc::new(RwLock::new(SamplerStats::new())),
            monitoring_window,
            warn_on_empty,
        }
    }

    /// Record a flow
    pub async fn record_flow(&self, dscp: u8, bytes: u64, sampled: bool, rule_name: Option<&str>) {
        let mut stats = self.stats.write().await;
        stats.record_flow(dscp, bytes, sampled, rule_name);
    }

    /// Get a snapshot of current statistics
    pub async fn snapshot(&self) -> SamplerStats {
        self.stats.read().await.clone()
    }

    /// Run periodic monitoring
    pub async fn run_monitoring(&self, interval_secs: u64) {
        let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            interval.tick().await;

            let stats = self.stats.read().await;

            // Log summary
            info!(
                "Sampler stats: {} flows, {:.2}% sampled, {:.2} MB processed",
                stats.total_flows,
                stats.overall_sampling_rate() * 100.0,
                stats.total_bytes as f64 / 1_048_576.0
            );

            // Check for empty classes
            if self.warn_on_empty {
                let warnings = stats.check_empty_classes(self.monitoring_window);
                for warning in warnings {
                    warn!("{}", warning);
                }
            }
        }
    }

    /// Print detailed statistics
    pub async fn print_summary(&self) {
        let stats = self.stats.read().await;
        println!("{}", stats.summary());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dscp_stats() {
        let mut stats = DscpStats::default();

        stats.record_flow(true, 1000);
        stats.record_flow(false, 500);
        stats.record_flow(true, 2000);

        assert_eq!(stats.total_flows, 3);
        assert_eq!(stats.sampled_flows, 2);
        assert_eq!(stats.total_bytes, 3500);
        assert_eq!(stats.sampling_rate(), 2.0 / 3.0);
    }

    #[test]
    fn test_sampler_stats() {
        let mut stats = SamplerStats::new();

        // Record some flows
        stats.record_flow(10, 1000, true, Some("small"));
        stats.record_flow(10, 500, false, Some("small"));
        stats.record_flow(26, 1_000_000, true, Some("large"));

        assert_eq!(stats.total_flows, 3);
        assert_eq!(stats.total_sampled, 2);
        assert_eq!(stats.total_bytes, 1_001_500);

        // Check DSCP stats
        assert_eq!(stats.dscp_stats[&10].total_flows, 2);
        assert_eq!(stats.dscp_stats[&26].total_flows, 1);

        // Check rule stats
        assert_eq!(stats.flows_by_rule["small"], 1);
        assert_eq!(stats.flows_by_rule["large"], 1);
    }

    #[test]
    fn test_empty_class_detection() {
        let mut stats = SamplerStats::new();

        // Add flows for DSCP 10 but none sampled
        stats.record_flow(10, 1000, false, None);
        stats.record_flow(10, 2000, false, None);

        // Add sampled flow for DSCP 26
        stats.record_flow(26, 5000, true, Some("test"));

        let warnings = stats.check_empty_classes(Duration::from_secs(60));
        assert!(!warnings.is_empty());
        assert!(warnings[0].contains("DSCP 10"));
        assert!(warnings[0].contains("2 flows but none sampled"));
    }

    #[tokio::test]
    async fn test_stats_collector() {
        let collector = StatsCollector::new(Duration::from_secs(60), true);

        // Record some flows
        collector.record_flow(10, 1000, true, Some("small")).await;
        collector
            .record_flow(26, 1_000_000, true, Some("large"))
            .await;

        let snapshot = collector.snapshot().await;
        assert_eq!(snapshot.total_flows, 2);
        assert_eq!(snapshot.total_sampled, 2);
    }
}
