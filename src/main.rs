//! TLDR: a continuously updated historical DNS zone-transfer archive.

mod config;
mod health;
mod notify;
mod scan;

use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;
use tracing_subscriber::EnvFilter;

use crate::config::Config;

/// Version reported by `--version`: a release stamp when CI provided one,
/// otherwise the Cargo.toml version.
const VERSION: &str = match option_env!("TLDR_VERSION") {
    Some(version) => version,
    None => env!("CARGO_PKG_VERSION"),
};

#[derive(Debug, Parser)]
#[command(
    name = "tldr",
    version = VERSION,
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

    /// Check the heartbeat and alert if the last cycle is stale, then exit.
    #[arg(long)]
    check_health: bool,

    /// Maximum heartbeat age before `--check-health` reports failure.
    /// Overrides `[health] max_age` when set.
    #[arg(long)]
    max_age: Option<String>,

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
    // We build with the pure-Rust ring TLS provider (not aws-lc-rs) so the
    // binary links statically for the scratch image. reqwest 0.13 (used by
    // pushover-rs) requires a process-default provider to be installed before a
    // client is built, or it panics. Installing ring here covers every TLS
    // client in the process (reqwest 0.12/0.13 and hickory's DoH resolver).
    let _ = rustls::crypto::ring::default_provider().install_default();

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

    if cli.check_health {
        let max_age_text = cli.max_age.unwrap_or(config.health.max_age.clone());
        let max_age = health::parse_duration(&max_age_text)?;
        let path = health::path_for(&config.archive.path);
        let code = health::run_check(&path, max_age, &config.notify).await;
        std::process::exit(code);
    }

    if cli.daemon {
        daemon(config, cli.interval_secs, cli.json).await
    } else {
        run_once(&config, cli.json).await
    }
}

async fn run_once(config: &Config, json: bool) -> Result<()> {
    let report = scan::run(config).await?;
    write_heartbeat(config, &report);
    finish(&report, json);
    Ok(())
}

/// Record that a cycle completed so the health checker knows TLDR is alive.
fn write_heartbeat(config: &Config, report: &scan::RunReport) {
    let heartbeat = health::Heartbeat {
        finished: report.finished.unwrap_or_else(chrono::Utc::now),
        zones_transferred: report.zones_transferred,
        zones_failed: report.zones_failed,
        notifications_sent: report.notifications_sent,
    };
    let path = health::path_for(&config.archive.path);
    if let Err(error) = health::write(&path, &heartbeat) {
        tracing::error!(%error, "failed to write heartbeat");
    }
}

async fn daemon(config: Config, interval_secs: u64, json: bool) -> Result<()> {
    let interval = std::time::Duration::from_secs(interval_secs.max(60));
    loop {
        match scan::run(&config).await {
            Ok(report) => {
                write_heartbeat(&config, &report);
                finish(&report, json);
            }
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

#[cfg(test)]
mod tests {
    #[test]
    fn ring_crypto_provider_installs() {
        // Guards the scratch-image TLS setup: reqwest 0.13 panics when no
        // process-default rustls provider is installed, so startup must install
        // ring. This asserts a provider is present after installation.
        let _ = rustls::crypto::ring::default_provider().install_default();
        assert!(rustls::crypto::CryptoProvider::get_default().is_some());
    }
}
