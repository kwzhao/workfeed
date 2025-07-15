use anyhow::Result;
use clap::Parser;
use sampler::{
    batching::BatchForwarder,
    config::Config,
    flow::{FlowInfo, SampledFlow},
    receiver::FlowReceiver,
    sampler::StatefulSampler,
    stats::StatsCollector,
};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;
use tracing::{error, info, warn};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

#[derive(Parser, Debug)]
#[command(name = "sampler")]
#[command(about = "TCP flow sampler for workfeed")]
struct Args {
    /// UDP listen address for receiving flows
    #[arg(short, long, default_value = "0.0.0.0:5001")]
    listen: SocketAddr,

    /// Controller address for forwarding sampled flows
    #[arg(short, long)]
    controller: Option<SocketAddr>,

    /// Configuration file path
    #[arg(short = 'f', long, required = true)]
    config: String,

    /// Maximum batch size
    #[arg(long, default_value = "128")]
    batch_size: usize,

    /// Batch timeout in milliseconds
    #[arg(long, default_value = "100")]
    batch_timeout: u64,

    /// Monitoring interval in seconds
    #[arg(long, default_value = "60")]
    monitor_interval: u64,

    /// Buffer size for UDP reception
    #[arg(long, default_value = "65536")]
    buffer_size: usize,

    /// Test output file path (writes sampled flows as JSON Lines)
    #[arg(long)]
    test_output: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    let args = Args::parse();

    info!("Starting workfeed sampler");
    info!("Listen address: {}", args.listen);

    // Load configuration
    info!("Loading configuration from: {}", args.config);
    let config = Config::from_file(&args.config)?;

    // Override controller address if provided via CLI
    let controller_addr = match args.controller {
        Some(addr) => addr,
        None => config.controller.socket_addr()?,
    };

    // Log mode information
    if args.test_output.is_some() {
        info!(
            "TEST MODE: Writing sampled flows to file: {}",
            args.test_output.as_ref().unwrap()
        );
        if args.controller.is_some() {
            warn!("Controller address ignored in test mode");
        }
    } else {
        info!("Controller address: {}", controller_addr);
    }
    info!("Sampling rules: {} configured", config.sampling.rules.len());

    // Create components
    let receiver = FlowReceiver::new(args.listen, args.buffer_size).await?;
    let mut sampler = StatefulSampler::new(config.sampling.clone())?;

    let stats_collector = StatsCollector::new(
        Duration::from_secs(config.monitoring.window_seconds),
        config.monitoring.warn_on_empty_class,
    );

    // Create channels
    let (flow_tx, mut flow_rx) = mpsc::channel::<Vec<FlowInfo>>(1000);
    let (sampled_tx, sampled_rx) = mpsc::channel::<SampledFlow>(1000);

    // Spawn receiver task
    let receiver_task = tokio::spawn(async move {
        if let Err(e) = receiver.run(flow_tx).await {
            error!("Receiver error: {}", e);
        }
    });

    // Spawn forwarder task or file writer based on test_output flag
    let forwarder_task = if let Some(test_output_path) = args.test_output.clone() {
        // Test mode: write to file instead of forwarding
        tokio::spawn(async move {
            if let Err(e) = write_sampled_flows_to_file(sampled_rx, &test_output_path).await {
                error!("Test output writer error: {}", e);
            }
        })
    } else {
        // Normal mode: create forwarder and forward to controller
        let forwarder =
            BatchForwarder::new(controller_addr, args.batch_size, args.batch_timeout).await?;
        tokio::spawn(async move {
            if let Err(e) = forwarder.run(sampled_rx).await {
                error!("Forwarder error: {}", e);
            }
        })
    };

    // Spawn monitoring task
    let stats_collector_clone = stats_collector.clone();
    let monitor_task = tokio::spawn(async move {
        stats_collector_clone
            .run_monitoring(args.monitor_interval)
            .await;
    });

    // Main processing loop
    info!("Sampler running, press Ctrl+C to stop");

    while let Some(flows) = flow_rx.recv().await {
        // Process each flow
        for flow in flows {
            let bytes = flow.size();
            let dscp = flow.dscp;

            // Check if should sample
            if let Some(sampled_flow) = sampler.process_flow(flow) {
                let rule_name = sampled_flow.sampling_bucket.clone();

                // Record stats
                stats_collector
                    .record_flow(dscp, bytes, true, Some(&rule_name))
                    .await;

                // Send to forwarder
                if let Err(e) = sampled_tx.send(sampled_flow).await {
                    error!("Failed to send sampled flow: {}", e);
                    break;
                }
            } else {
                // Record stats for non-sampled flow
                stats_collector.record_flow(dscp, bytes, false, None).await;
            }
        }
    }

    // Print final statistics
    info!("Shutting down sampler");
    stats_collector.print_summary().await;

    // Cancel tasks
    receiver_task.abort();
    forwarder_task.abort();
    monitor_task.abort();

    Ok(())
}

/// Write sampled flows to a file in JSON Lines format
async fn write_sampled_flows_to_file(
    mut rx: mpsc::Receiver<SampledFlow>,
    path: &str,
) -> Result<()> {
    let mut file = File::create(path).await?;
    info!("Created test output file: {}", path);

    let mut total_written = 0u64;
    let mut write_errors = 0u64;

    while let Some(flow) = rx.recv().await {
        // Serialize to JSON with newline
        let json = match serde_json::to_string(&flow) {
            Ok(json) => json + "\n",
            Err(e) => {
                write_errors += 1;
                warn!("Failed to serialize flow: {}", e);
                continue;
            }
        };

        // Write to file
        if let Err(e) = file.write_all(json.as_bytes()).await {
            write_errors += 1;
            error!("Failed to write to file: {}", e);
            // Continue writing other flows even if one fails
        } else {
            total_written += 1;
        }

        // Flush periodically for real-time visibility
        if total_written % 100 == 0 {
            if let Err(e) = file.flush().await {
                warn!("Failed to flush file: {}", e);
            }
            info!("Written {} sampled flows to file", total_written);
        }
    }

    // Final flush
    file.flush().await?;
    info!(
        "Test output complete: {} flows written, {} errors",
        total_written, write_errors
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_args_parsing() {
        let args = Args::parse_from([
            "sampler",
            "--config",
            "config.json",
            "--listen",
            "0.0.0.0:6000",
            "--controller",
            "10.0.0.1:5000",
            "--batch-size",
            "256",
        ]);

        assert_eq!(args.config, "config.json");
        assert_eq!(args.listen.to_string(), "0.0.0.0:6000");
        assert_eq!(args.controller.unwrap().to_string(), "10.0.0.1:5000");
        assert_eq!(args.batch_size, 256);
    }

    #[test]
    fn test_args_with_test_output() {
        let args = Args::parse_from([
            "sampler",
            "--config",
            "config.json",
            "--test-output",
            "/tmp/sampled_flows.jsonl",
        ]);

        assert_eq!(args.config, "config.json");
        assert_eq!(
            args.test_output,
            Some("/tmp/sampled_flows.jsonl".to_string())
        );
    }
}
