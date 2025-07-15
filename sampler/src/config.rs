use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

/// Main configuration structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Sampling configuration
    pub sampling: SamplingConfig,
    /// Batching configuration
    pub batching: BatchingConfig,
    /// Controller endpoint
    pub controller: ControllerConfig,
    /// Monitoring configuration
    #[serde(default)]
    pub monitoring: MonitoringConfig,
}

/// Sampling rule definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamplingRule {
    /// Upper bound of this rule (None means infinity)
    pub max_bytes: Option<u64>,
    /// Sampling rate (0.0 to 1.0)
    pub rate: f64,
}

/// Sampling configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamplingConfig {
    /// Sampling rules ordered by max_bytes
    pub rules: Vec<SamplingRule>,
}

impl SamplingConfig {
    /// Validate sampling configuration
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.rules.is_empty() {
            anyhow::bail!("At least one sampling rule required");
        }

        // Check rates are valid
        for (i, rule) in self.rules.iter().enumerate() {
            if rule.rate <= 0.0 || rule.rate > 1.0 {
                anyhow::bail!("Rule {}: rate must be in (0, 1], got {}", i, rule.rate);
            }
        }

        // Check ordering and no gaps
        let mut last_max = 0u64;
        let mut has_catchall = false;

        for (i, rule) in self.rules.iter().enumerate() {
            match rule.max_bytes {
                Some(max) => {
                    if max <= last_max {
                        anyhow::bail!(
                            "Rule {}: max_bytes must be increasing, got {} after {}",
                            i,
                            max,
                            last_max
                        );
                    }
                    last_max = max;
                }
                None => {
                    if i != self.rules.len() - 1 {
                        anyhow::bail!("Only the last rule can have max_bytes: null");
                    }
                    has_catchall = true;
                }
            }
        }

        if !has_catchall {
            anyhow::bail!("Last rule must have max_bytes: null as catch-all");
        }

        Ok(())
    }

    /// Find the sampling rule for a given flow size
    pub fn find_rule(&self, size: u64) -> (&SamplingRule, usize) {
        for (i, rule) in self.rules.iter().enumerate() {
            match rule.max_bytes {
                Some(max) if size <= max => return (rule, i),
                None => return (rule, i),
                _ => continue,
            }
        }
        // Should never reach here if validation passed
        panic!("No sampling rule found for size {}", size);
    }

    /// Get a human-readable bucket name for a rule
    pub fn bucket_name(&self, rule_index: usize) -> String {
        let rule = &self.rules[rule_index];
        let prev_max = if rule_index > 0 {
            self.rules[rule_index - 1].max_bytes.unwrap_or(0)
        } else {
            0
        };

        match rule.max_bytes {
            Some(max) => format!("{}B-{}B", prev_max, max),
            None => format!("{}B+", prev_max),
        }
    }
}

/// Batching configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchingConfig {
    /// Maximum flows per batch
    pub max_batch_size: usize,
    /// Timeout in milliseconds before sending partial batch
    pub timeout_ms: u64,
}

impl Default for BatchingConfig {
    fn default() -> Self {
        Self {
            max_batch_size: 128,
            timeout_ms: 100,
        }
    }
}

/// Controller configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControllerConfig {
    /// Controller address
    pub address: String,
}

impl ControllerConfig {
    /// Parse the address into a SocketAddr
    pub fn socket_addr(&self) -> anyhow::Result<SocketAddr> {
        self.address
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid controller address: {}", e))
    }
}

/// Monitoring configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoringConfig {
    /// Window size in seconds for DSCP class monitoring
    pub window_seconds: u64,
    /// Log warning if a DSCP class has no flows
    pub warn_on_empty_class: bool,
}

impl Default for MonitoringConfig {
    fn default() -> Self {
        Self {
            window_seconds: 60,
            warn_on_empty_class: true,
        }
    }
}

impl Config {
    /// Load configuration from a JSON file
    pub fn from_file(path: &str) -> anyhow::Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        let config: Config = serde_json::from_str(&contents)?;
        config.validate()?;
        Ok(config)
    }

    /// Create default configuration for testing
    pub fn default_for_testing() -> Self {
        Self {
            sampling: SamplingConfig {
                rules: vec![
                    SamplingRule {
                        max_bytes: Some(10240),
                        rate: 0.03125, // 1/32
                    },
                    SamplingRule {
                        max_bytes: Some(1048576),
                        rate: 0.25, // 1/4
                    },
                    SamplingRule {
                        max_bytes: None,
                        rate: 1.0,
                    },
                ],
            },
            batching: BatchingConfig::default(),
            controller: ControllerConfig {
                address: "127.0.0.1:5000".to_string(),
            },
            monitoring: MonitoringConfig::default(),
        }
    }

    /// Validate the entire configuration
    pub fn validate(&self) -> anyhow::Result<()> {
        self.sampling.validate()?;
        self.controller.socket_addr()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_config() {
        let config = Config::default_for_testing();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_find_rule() {
        let config = Config::default_for_testing();

        // Small flow
        let (rule, idx) = config.sampling.find_rule(1000);
        assert_eq!(rule.rate, 0.03125);
        assert_eq!(idx, 0);

        // Medium flow
        let (rule, idx) = config.sampling.find_rule(100_000);
        assert_eq!(rule.rate, 0.25);
        assert_eq!(idx, 1);

        // Large flow
        let (rule, idx) = config.sampling.find_rule(10_000_000);
        assert_eq!(rule.rate, 1.0);
        assert_eq!(idx, 2);
    }

    #[test]
    fn test_invalid_rate() {
        let mut config = Config::default_for_testing();
        config.sampling.rules[0].rate = 0.0;
        assert!(config.validate().is_err());

        config.sampling.rules[0].rate = 1.5;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_bucket_names() {
        let config = Config::default_for_testing();
        assert_eq!(config.sampling.bucket_name(0), "0B-10240B");
        assert_eq!(config.sampling.bucket_name(1), "10240B-1048576B");
        assert_eq!(config.sampling.bucket_name(2), "1048576B+");
    }
}
