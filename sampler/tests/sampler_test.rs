use sampler::{config::Config, flow::FlowInfo, sampler::Sampler};

#[test]
fn test_config_loading() {
    // Test loading example config
    // Note: When running tests from cargo, the working directory is the crate root
    let config_path = if std::path::Path::new("examples/config.json").exists() {
        "examples/config.json"
    } else if std::path::Path::new("workfeed/sampler/examples/config.json").exists() {
        "workfeed/sampler/examples/config.json"
    } else {
        // Skip test if config file not found
        println!("Skipping test - config file not found");
        return;
    };

    let config = Config::from_file(config_path).unwrap();
    assert_eq!(config.sampling.rules.len(), 3);
    assert_eq!(config.batching.max_batch_size, 128);
}

#[test]
fn test_deterministic_sampling() {
    let config = Config::default_for_testing();
    let sampler = Sampler::new(config.sampling).unwrap();

    // Create test flows
    let flow1 = FlowInfo {
        saddr: 0x0a000001,
        daddr: 0x0a000002,
        sport: 1234,
        dport: 80,
        protocol: 6,
        dscp: 10,
        _pad: 0,
        start_time_ns: 1000,
        end_time_ns: 2000,
        bytes_sent: 500, // Small flow
        bytes_recv: 250,
    };

    let flow2 = flow1;

    // Same flow should always get same decision
    let result1 = sampler.should_sample(&flow1);
    let result2 = sampler.should_sample(&flow2);

    assert_eq!(result1.is_some(), result2.is_some());
}

#[test]
fn test_sampling_rates() {
    let config = Config::default_for_testing();
    let sampler = Sampler::new(config.sampling).unwrap();

    let mut sampled_small = 0;
    let mut sampled_medium = 0;
    let mut sampled_large = 0;

    // Test many flows to verify sampling rates
    for i in 0..10000 {
        let small_flow = FlowInfo {
            saddr: i,
            daddr: 0x0a000002,
            sport: 1234,
            dport: 80,
            protocol: 6,
            dscp: 10,
            _pad: 0,
            start_time_ns: 1000,
            end_time_ns: 2000,
            bytes_sent: 1000, // Small
            bytes_recv: 500,
        };

        let medium_flow = FlowInfo {
            bytes_sent: 100_000, // Medium
            ..small_flow
        };

        let large_flow = FlowInfo {
            bytes_sent: 10_000_000, // Large
            ..small_flow
        };

        if sampler.should_sample(&small_flow).is_some() {
            sampled_small += 1;
        }
        if sampler.should_sample(&medium_flow).is_some() {
            sampled_medium += 1;
        }
        if sampler.should_sample(&large_flow).is_some() {
            sampled_large += 1;
        }
    }

    // Check sampling rates are approximately correct
    let small_rate = sampled_small as f64 / 10000.0;
    let medium_rate = sampled_medium as f64 / 10000.0;
    let large_rate = sampled_large as f64 / 10000.0;

    println!("Small flow sampling rate: {small_rate:.4}");
    println!("Medium flow sampling rate: {medium_rate:.4}");
    println!("Large flow sampling rate: {large_rate:.4}");

    // Allow 10% variance
    assert!((small_rate - 0.03125).abs() < 0.01);
    assert!((medium_rate - 0.25).abs() < 0.02);
    assert!((large_rate - 1.0).abs() < 0.01);
}

#[test]
fn test_packet_parsing_and_serialization() {
    // Create test flows
    let flows = [
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
        },
        FlowInfo {
            saddr: 0x0a000003,
            daddr: 0x0a000004,
            sport: 5678,
            dport: 443,
            protocol: 6,
            dscp: 26,
            _pad: 0,
            start_time_ns: 3000,
            end_time_ns: 4000,
            bytes_sent: 2048,
            bytes_recv: 1024,
        },
    ];

    // Convert to sampled flows
    let sampled: Vec<_> = flows
        .iter()
        .map(|f| sampler::flow::SampledFlow::new(*f, 1.0, "test"))
        .collect();

    // Test JSON serialization for TCP transmission
    let json = serde_json::to_vec(&sampled).unwrap();

    // Deserialize back to verify integrity
    let deserialized: Vec<sampler::flow::SampledFlow> = serde_json::from_slice(&json).unwrap();

    // Verify data integrity
    assert_eq!(sampled.len(), deserialized.len());
    assert_eq!(sampled[0].weight, deserialized[0].weight);
    assert_eq!(sampled[0].sampling_bucket, deserialized[0].sampling_bucket);
    assert_eq!(sampled[0].flow.bytes_sent, deserialized[0].flow.bytes_sent);
}
