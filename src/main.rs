//! TLDR: a continuously updated historical DNS zone-transfer archive.

mod config;
mod notify;
mod scan;

use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;
use tracing_subscriber::EnvFilter;

use crate::config::Config;

#[derive(Debug, Parser)]
#[command(
    name = "tldr",
    version,
    about = "Continuously updated historical DNS zone-transfer archive"
)]
struct Cli {
    /// Path to the configuration file.
    #[arg(long, default_value = "config.toml", global = true)]
    config: PathBuf,

    /// Run one cycle and exit (default).
    #[arg(long)]
    once: bool,

    /// Run continuously, sleeping `interval_secs` between cycles.
    #[arg(long)]
    daemon: bool,

    /// Seconds between daemon cycles (default: hourly).
    #[arg(long, default_value_t = 3600)]
    interval_secs: u64,

    /// Send a single test notification and exit.
    #[arg(long)]
    test_notification: bool,

    /// Validate configuration and discovery without transferring.
    #[arg(long)]
    dry_run: bool,

    /// Emit a JSON run report on stdout.
    #[arg(long)]
    json: bool,

    /// Override the archive directory.
    #[arg(long)]
    archive: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| {
            EnvFilter::new("info,hickory_net=error,hickory_net::h2=error,hickory_proto=warn")
        }))
        .init();

    let cli = Cli::parse();
    let mut config = Config::load(&cli.config)?;
    if let Some(archive) = cli.archive {
        config.archive.path = archive;
    }
    if cli.dry_run {
        config.notify.dry_run = true;
        config.scan.discovery_only = true;
    }

    if cli.test_notification {
        let status = notify::send_test(&config.notify).await?;
        tracing::info!("{status}");
        return Ok(());
    }

    if cli.daemon {
        daemon(config, cli.interval_secs, cli.json).await
    } else {
        run_once(&config, cli.json).await
    }
}

async fn run_once(config: &Config, json: bool) -> Result<()> {
    let report = scan::run(config).await?;
    finish(&report, json);
    Ok(())
}

async fn daemon(config: Config, interval_secs: u64, json: bool) -> Result<()> {
    let interval = std::time::Duration::from_secs(interval_secs.max(60));
    loop {
        match scan::run(&config).await {
            Ok(report) => finish(&report, json),
            Err(error) => tracing::error!(%error, "scan cycle failed"),
        }
        tracing::info!(seconds = interval.as_secs(), "sleeping until next cycle");
        tokio::select! {
            _ = tokio::time::sleep(interval) => {}
            _ = shutdown_signal() => {
                tracing::info!("shutdown signal received; exiting");
                break;
            }
        }
    }
    Ok(())
}

fn finish(report: &scan::RunReport, json: bool) {
    if json {
        match serde_json::to_string_pretty(&report.to_json()) {
            Ok(text) => println!("{text}"),
            Err(error) => tracing::error!(%error, "failed to serialize report"),
        }
    } else {
        tracing::info!(
            attempted = report.zones_attempted,
            transferred = report.zones_transferred,
            refused = report.zones_refused,
            failed = report.zones_failed,
            new = report.new_zones.len(),
            changed = report.changed.len(),
            notified = report.notifications_sent,
            "run complete"
        );
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut signal) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            signal.recv().await;
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
}
