use crate::config::SamplingConfig;
use crate::flow::{FlowInfo, SampledFlow};
use ahash::AHasher;
use std::hash::{Hash, Hasher};

/// Core sampling logic
pub struct Sampler {
    config: SamplingConfig,
}

impl Sampler {
    /// Create a new sampler with the given configuration
    pub fn new(config: SamplingConfig) -> anyhow::Result<Self> {
        config.validate()?;
        Ok(Self { config })
    }

    /// Determine if a flow should be sampled based on its size and hash
    pub fn should_sample(&self, flow: &FlowInfo) -> Option<SampledFlow> {
        let size = flow.size();
        let (rule, rule_idx) = self.config.find_rule(size);

        // Compute deterministic hash of flow
        let hash = Self::compute_flow_hash(flow);

        // Map hash to [0, 1) range
        let hash_value = (hash as f64) / (u64::MAX as f64);

        // Sample if hash falls within rate
        if hash_value < rule.rate {
            let weight = 1.0 / rule.rate;
            let bucket = self.config.bucket_name(rule_idx);
            Some(SampledFlow::new(*flow, weight, &bucket))
        } else {
            None
        }
    }

    /// Compute deterministic hash of flow
    fn compute_flow_hash(flow: &FlowInfo) -> u64 {
        let mut hasher = AHasher::default();

        // Hash 5-tuple + DSCP for deterministic sampling
        flow.saddr.hash(&mut hasher);
        flow.daddr.hash(&mut hasher);
        flow.sport.hash(&mut hasher);
        flow.dport.hash(&mut hasher);
        flow.protocol.hash(&mut hasher);
        flow.dscp.hash(&mut hasher);

        hasher.finish()
    }

    /// Process a batch of flows, returning those that should be sampled
    pub fn process_flows(&self, flows: Vec<FlowInfo>) -> Vec<SampledFlow> {
        flows
            .into_iter()
            .filter_map(|flow| self.should_sample(&flow))
            .collect()
    }
}

/// Statistics for sampling decisions
#[derive(Debug)]
pub struct SamplingStats {
    /// Total flows seen
    pub total_flows: u64,
    /// Flows sampled per rule
    pub sampled_by_rule: Vec<u64>,
    /// Flows seen per DSCP class
    pub flows_by_dscp: [u64; 64], // DSCP is 6 bits
    /// Sampled flows per DSCP class
    pub sampled_by_dscp: [u64; 64],
}

impl Default for SamplingStats {
    fn default() -> Self {
        Self {
            total_flows: 0,
            sampled_by_rule: Vec::new(),
            flows_by_dscp: [0; 64],
            sampled_by_dscp: [0; 64],
        }
    }
}

impl SamplingStats {
    pub fn new(num_rules: usize) -> Self {
        Self {
            sampled_by_rule: vec![0; num_rules],
            ..Default::default()
        }
    }

    /// Update stats for a processed flow
    pub fn record_flow(&mut self, flow: &FlowInfo, sampled: bool, rule_idx: Option<usize>) {
        self.total_flows += 1;
        self.flows_by_dscp[flow.dscp as usize] += 1;

        if sampled {
            if let Some(idx) = rule_idx {
                self.sampled_by_rule[idx] += 1;
            }
            self.sampled_by_dscp[flow.dscp as usize] += 1;
        }
    }

    /// Get effective sampling rate
    pub fn sampling_rate(&self) -> f64 {
        let total_sampled: u64 = self.sampled_by_rule.iter().sum();
        if self.total_flows > 0 {
            total_sampled as f64 / self.total_flows as f64
        } else {
            0.0
        }
    }

    /// Check for empty DSCP classes and return warnings
    pub fn check_empty_classes(&self) -> Vec<String> {
        let mut warnings = Vec::new();

        // Common DSCP values to check
        let common_dscp = [0, 10, 18, 26, 34, 46]; // BE, AF11, AF21, AF31, AF41, EF

        for &dscp in &common_dscp {
            if self.flows_by_dscp[dscp as usize] > 0 && self.sampled_by_dscp[dscp as usize] == 0 {
                warnings.push(format!(
                    "DSCP class {} has {} flows but none were sampled",
                    dscp, self.flows_by_dscp[dscp as usize]
                ));
            }
        }

        warnings
    }
}

/// Extended sampler with statistics tracking
pub struct StatefulSampler {
    sampler: Sampler,
    stats: SamplingStats,
}

impl StatefulSampler {
    pub fn new(config: SamplingConfig) -> anyhow::Result<Self> {
        let num_rules = config.rules.len();
        let sampler = Sampler::new(config)?;
        let stats = SamplingStats::new(num_rules);
        Ok(Self { sampler, stats })
    }

    /// Process a flow and update statistics
    pub fn process_flow(&mut self, flow: FlowInfo) -> Option<SampledFlow> {
        let size = flow.size();
        let (_, rule_idx) = self.sampler.config.find_rule(size);

        let sampled = self.sampler.should_sample(&flow);
        self.stats
            .record_flow(&flow, sampled.is_some(), Some(rule_idx));

        sampled
    }

    /// Process multiple flows
    pub fn process_flows(&mut self, flows: Vec<FlowInfo>) -> Vec<SampledFlow> {
        flows
            .into_iter()
            .filter_map(|flow| self.process_flow(flow))
            .collect()
    }

    /// Get current statistics
    pub fn stats(&self) -> &SamplingStats {
        &self.stats
    }

    /// Reset statistics
    pub fn reset_stats(&mut self) {
        let num_rules = self.sampler.config.rules.len();
        self.stats = SamplingStats::new(num_rules);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SamplingRule;

    fn test_config() -> SamplingConfig {
        SamplingConfig {
            rules: vec![
                SamplingRule {
                    max_bytes: Some(1000),
                    rate: 0.1,
                },
                SamplingRule {
                    max_bytes: None,
                    rate: 1.0,
                },
            ],
        }
    }

    fn test_flow(size: u64, dscp: u8) -> FlowInfo {
        FlowInfo {
            saddr: 0x0a000001,
            daddr: 0x0a000002,
            sport: 1234,
            dport: 80,
            protocol: 6,
            dscp,
            _pad: 0,
            start_time_ns: 1000,
            end_time_ns: 2000,
            bytes_sent: size,
            bytes_recv: size / 2,
        }
    }

    #[test]
    fn test_deterministic_sampling() {
        let sampler = Sampler::new(test_config()).unwrap();

        // Same flow should always get same decision
        let flow = test_flow(500, 10);
        let result1 = sampler.should_sample(&flow);
        let result2 = sampler.should_sample(&flow);

        assert_eq!(result1.is_some(), result2.is_some());
    }

    #[test]
    fn test_sampling_weights() {
        let sampler = Sampler::new(test_config()).unwrap();

        // Small flow - 10% sampling
        if let Some(sampled) = sampler.should_sample(&test_flow(500, 10)) {
            assert_eq!(sampled.weight, 10.0);
        }

        // Large flow - 100% sampling
        if let Some(sampled) = sampler.should_sample(&test_flow(5000, 10)) {
            assert_eq!(sampled.weight, 1.0);
        }
    }

    #[test]
    fn test_stats_tracking() {
        let mut sampler = StatefulSampler::new(test_config()).unwrap();

        // Process some flows
        for i in 0..100 {
            sampler.process_flow(test_flow(500, (i % 3) as u8));
        }

        let stats = sampler.stats();
        assert_eq!(stats.total_flows, 100);

        // Check DSCP distribution
        assert!(stats.flows_by_dscp[0] > 0);
        assert!(stats.flows_by_dscp[1] > 0);
        assert!(stats.flows_by_dscp[2] > 0);
    }
}
