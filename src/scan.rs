//! One scan cycle: discover zones, transfer them, archive results, notify.
//!
//! The cycle is a straight line of three phases so it stays easy to follow:
//!
//! 1. [`plan`] — learn the zone list and resolve every nameserver address.
//! 2. [`transfer`] — attempt each (zone, server) pair with bounded concurrency.
//! 3. [`record`] — archive the successes, diff against the previous snapshot,
//!    and collect the changes worth notifying about.

use std::collections::BTreeMap;
use std::fs::File;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use tldr_core::archive::{Archive, SnapshotEntry};
use tldr_core::axfr::{transfer_axfr, TransferOutcome};
use tldr_core::diff::{diff, DiffPolicy, Significance, ZoneDiff};
use tldr_core::discovery::{
    doh_resolver, fetch_iana_tlds, lookup_addresses, lookup_nameservers, ROOT_SERVERS,
};
use tldr_core::zone::{fqdn, Zone};
use tokio::sync::Semaphore;

use crate::config::Config;
use crate::notify;

/// Per-zone result of a scan.
#[derive(Debug)]
pub struct ZoneResult {
    pub origin: String,
    pub server: String,
    pub outcome: Outcome,
    pub significance: Significance,
    pub diff: Option<ZoneDiff>,
    pub entry: Option<SnapshotEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Transferred,
    Failed(String),
}

/// Aggregate report for one run.
#[derive(Debug, Default)]
pub struct RunReport {
    pub started: Option<DateTime<Utc>>,
    pub finished: Option<DateTime<Utc>>,
    pub zones_attempted: usize,
    pub zones_transferred: usize,
    pub zones_refused: usize,
    pub zones_failed: usize,
    pub new_zones: Vec<String>,
    pub changed: Vec<ZoneResult>,
    /// Zones that transferred, with the serving nameserver.
    pub executed: Vec<ZoneResult>,
    /// True when the archive was empty at the start of this run (first run).
    pub is_initial: bool,
    pub notifications_sent: usize,
}

impl RunReport {
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "started": self.started,
            "finished": self.finished,
            "zones_attempted": self.zones_attempted,
            "zones_transferred": self.zones_transferred,
            "zones_refused": self.zones_refused,
            "zones_failed": self.zones_failed,
            "new_zones": self.new_zones,
            "notifications_sent": self.notifications_sent,
            "is_initial": self.is_initial,
            "executed": self.executed.iter().map(|r| serde_json::json!({
                "origin": r.origin,
                "server": r.server,
                "outcome": match &r.outcome {
                    Outcome::Transferred => "transferred".to_string(),
                    Outcome::Failed(e) => format!("failed: {e}"),
                },
                "records": r.entry.as_ref().map(|e| e.records),
            })).collect::<Vec<_>>(),
            "changes": self.changed.iter().map(|r| serde_json::json!({
                "origin": r.origin,
                "server": r.server,
                "significance": r.significance.as_str(),
                "diff": r.diff,
            })).collect::<Vec<_>>(),
        })
    }
}

/// A single (zone, nameserver) attempt with the addresses to try in order.
#[derive(Debug)]
struct Attempt {
    origin: String,
    server: String,
    addresses: Vec<IpAddr>,
}

/// The work for one cycle: which zones exist and which servers to try.
#[derive(Debug, Default)]
struct Plan {
    zone_count: usize,
    attempts: Vec<Attempt>,
}

/// A successful transfer, ready to archive.
#[derive(Debug)]
struct Transfer {
    origin: String,
    server: String,
    zone: Zone,
}

/// Run one full scan cycle.
pub async fn run(config: &Config) -> Result<RunReport> {
    let started = Utc::now();

    // Refuse to run two cycles at once (a slow cycle overlapping the next
    // interval, or a manual run during a scheduled one). The lock is released
    // automatically when `_lock` drops at the end of this function.
    std::fs::create_dir_all(&config.archive.path).ok();
    let _lock = acquire_lock(&config.archive.path)?;

    let mut archive = Archive::open(&config.archive.path)?;
    let is_initial = archive.manifest().snapshots.is_empty();

    let plan = plan(config).await?;
    let mut report = RunReport {
        started: Some(started),
        zones_attempted: plan.zone_count,
        is_initial,
        ..Default::default()
    };

    if config.scan.discovery_only {
        report.finished = Some(Utc::now());
        tracing::info!(
            zones = plan.zone_count,
            nameservers = plan.attempts.len(),
            "discovery complete (dry run, no transfers)"
        );
        return Ok(report);
    }

    let transfers = transfer(config, plan, &mut report).await;
    record(config, &mut archive, started, transfers, &mut report).await;

    report.finished = Some(Utc::now());
    Ok(report)
}

/// Phase 1: find the zones and resolve every nameserver address.
async fn plan(config: &Config) -> Result<Plan> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent("tldr/0.1 (+https://github.com/tweedge/tldr)")
        .build()?;

    // The zone list: root plus every IANA TLD (or a fixed list for testing).
    let mut zones: Vec<String> = Vec::new();
    if config.scan.include_root {
        zones.push(".".to_string());
    }
    match &config.scan.tlds {
        Some(tlds) => zones.extend(tlds.iter().map(|tld| fqdn(tld))),
        None => zones.extend(fetch_iana_tlds(&client).await?.iter().map(|t| fqdn(t))),
    }
    let exclude: std::collections::BTreeSet<String> =
        config.scan.exclude.iter().map(|z| fqdn(z)).collect();
    zones.retain(|origin| !exclude.contains(origin));

    // Discovery uses DoH, so it works even where plain port 53 is filtered.
    let resolver = match doh_resolver() {
        Ok(resolver) => resolver,
        Err(error) => {
            tracing::warn!(%error, "no DoH resolver; cannot discover nameservers");
            return Ok(Plan {
                zone_count: zones.len(),
                attempts: Vec::new(),
            });
        }
    };

    // Nameserver names per zone, resolved concurrently.
    let mut servers_by_zone: Vec<(String, Vec<String>)> = Vec::new();
    let mut tasks = Vec::new();
    for origin in &zones {
        // The root zone is tried against all 13 root servers by name.
        if origin == "." {
            continue;
        }
        let origin = origin.clone();
        let resolver = resolver.clone();
        tasks.push(tokio::spawn(async move {
            let servers = lookup_nameservers(&resolver, &origin).await;
            (origin, servers)
        }));
    }
    for task in tasks {
        match task.await {
            Ok((origin, Ok(mut servers))) => {
                servers.sort();
                servers.dedup();
                servers.truncate(config.scan.max_servers_per_zone.max(1));
                servers_by_zone.push((origin, servers));
            }
            Ok((origin, Err(error))) => tracing::debug!(%origin, %error, "no nameservers"),
            Err(error) => tracing::debug!(%error, "nameserver lookup task failed"),
        }
    }

    // Every distinct server name, including the root servers.
    let mut all_servers: std::collections::BTreeSet<String> = servers_by_zone
        .iter()
        .flat_map(|(_, servers)| servers.iter().cloned())
        .collect();
    if config.scan.include_root {
        all_servers.extend(ROOT_SERVERS.iter().map(|s| s.to_string()));
    }

    // Resolve addresses per server: DoH first, then the system resolver.
    let mut addresses_by_server: BTreeMap<String, Vec<IpAddr>> = BTreeMap::new();
    let mut tasks = Vec::new();
    for server in all_servers {
        let resolver = resolver.clone();
        tasks.push(tokio::spawn(async move {
            let via_doh = lookup_addresses(&resolver, &server)
                .await
                .unwrap_or_default();
            let addresses = if via_doh.is_empty() {
                tldr_core::axfr::resolve_host(&server)
                    .await
                    .unwrap_or_default()
            } else {
                via_doh
            };
            (server, addresses)
        }));
    }
    for task in tasks {
        if let Ok((server, addresses)) = task.await {
            addresses_by_server.insert(server, addresses);
        }
    }

    // Build the attempt list.
    let mut attempts = Vec::new();
    let mut push =
        |origin: &str, server: &str, addresses_by_server: &BTreeMap<String, Vec<IpAddr>>| {
            if let Some(addresses) = addresses_by_server.get(server) {
                if !addresses.is_empty() {
                    attempts.push(Attempt {
                        origin: origin.to_string(),
                        server: server.to_string(),
                        addresses: addresses.clone(),
                    });
                }
            }
        };
    if config.scan.include_root {
        for server in ROOT_SERVERS {
            push(".", server, &addresses_by_server);
        }
    }
    for (origin, servers) in &servers_by_zone {
        for server in servers {
            push(origin, server, &addresses_by_server);
        }
    }

    Ok(Plan {
        zone_count: zones.len(),
        attempts,
    })
}

/// Phase 2: attempt every transfer with bounded concurrency.
async fn transfer(config: &Config, plan: Plan, report: &mut RunReport) -> Vec<Transfer> {
    tracing::info!(
        zones = plan.zone_count,
        attempts = plan.attempts.len(),
        concurrency = config.scan.concurrency,
        "starting transfers"
    );

    let semaphore = Arc::new(Semaphore::new(config.scan.concurrency.max(1)));
    let timeout = Duration::from_secs(config.scan.timeout_secs.max(1));
    let pacing = Duration::from_millis(config.scan.pacing_ms);

    let mut handles = Vec::new();
    for attempt in plan.attempts {
        let permit = match semaphore.clone().acquire_owned().await {
            Ok(permit) => permit,
            Err(_) => break,
        };
        if !pacing.is_zero() {
            tokio::time::sleep(pacing).await;
        }
        handles.push(tokio::spawn(async move {
            let _permit = permit;
            let mut last = TransferOutcome::Failed("no addresses".to_string());
            for address in attempt.addresses {
                let outcome = transfer_axfr(&attempt.origin, address, timeout).await;
                // Stop on success or a definite refusal; only retry other
                // addresses when the connection/answer failed outright.
                let answered = matches!(
                    outcome,
                    TransferOutcome::Success(_) | TransferOutcome::Refused
                );
                last = outcome;
                if answered {
                    break;
                }
            }
            (attempt.origin, attempt.server, last)
        }));
    }

    let mut transfers = Vec::new();
    for handle in handles {
        let (origin, server, outcome) = match handle.await {
            Ok(value) => value,
            Err(error) => {
                tracing::warn!(%error, "transfer task panicked");
                continue;
            }
        };
        match outcome {
            TransferOutcome::Success(zone) => {
                report.zones_transferred += 1;
                transfers.push(Transfer {
                    origin,
                    server,
                    zone,
                });
            }
            TransferOutcome::Refused => report.zones_refused += 1,
            TransferOutcome::Failed(error) => {
                report.zones_failed += 1;
                tracing::debug!(%origin, %server, %error, "transfer failed");
                report.executed.push(ZoneResult {
                    origin,
                    server,
                    outcome: Outcome::Failed(error),
                    significance: Significance::None,
                    diff: None,
                    entry: None,
                });
            }
        }
    }
    transfers
}

/// Phase 3: archive successes, diff, prune, notify.
async fn record(
    config: &Config,
    archive: &mut Archive,
    started: DateTime<Utc>,
    transfers: Vec<Transfer>,
    report: &mut RunReport,
) {
    let policy = DiffPolicy {
        delegation_min_count: config.diff.delegation_min_count,
        delegation_min_fraction: config.diff.delegation_min_fraction,
        record_min_fraction: config.diff.record_min_fraction,
        medium_delegation_min: config.diff.medium_delegation_min,
        ignore_rtypes: config.diff.ignore_rtypes.clone(),
    };

    // Keep the first successful server per zone (all should serve the same zone).
    let mut by_origin: BTreeMap<String, Transfer> = BTreeMap::new();
    for transfer in transfers {
        by_origin.entry(transfer.origin.clone()).or_insert(transfer);
    }

    for transfer in by_origin.values() {
        let previous = archive.previous(&transfer.origin, started).cloned();
        let is_new = archive.latest(&transfer.origin).is_none();

        let zone_diff = previous.as_ref().and_then(|previous| {
            match archive
                .get_blob(&previous.digest)
                .and_then(|text| Zone::from_text(&transfer.origin, &text))
            {
                Ok(previous_zone) => Some(diff(&previous_zone, &transfer.zone)),
                Err(error) => {
                    // A corrupt/missing previous blob must not abort the run.
                    tracing::warn!(origin = %transfer.origin, %error, "cannot read previous snapshot");
                    None
                }
            }
        });

        let entry =
            match archive.record(&transfer.origin, started, &transfer.zone, &transfer.server) {
                Ok(entry) => entry,
                Err(error) => {
                    tracing::error!(origin = %transfer.origin, %error, "failed to archive zone");
                    continue;
                }
            };

        report.executed.push(ZoneResult {
            origin: transfer.origin.clone(),
            server: transfer.server.clone(),
            outcome: Outcome::Transferred,
            significance: Significance::None,
            diff: None,
            entry: Some(entry.clone()),
        });
        if is_new {
            report.new_zones.push(transfer.origin.clone());
        }

        let significance = match &zone_diff {
            Some(diff) => diff.significance(&policy),
            // A zone that was never seen before is a high-signal new zone.
            None => Significance::High,
        };
        if significance != Significance::None || is_new {
            report.changed.push(ZoneResult {
                origin: transfer.origin.clone(),
                server: transfer.server.clone(),
                outcome: Outcome::Transferred,
                significance,
                diff: zone_diff,
                entry: Some(entry),
            });
        }
    }

    if let Err(error) = archive.prune(config.archive.retention_days, Utc::now()) {
        tracing::error!(%error, "retention pruning failed");
    }
    if let Err(error) = archive.flush() {
        tracing::error!(%error, "writing archive manifest failed");
    }

    if let Some(path) = &config.report.zones_md {
        if let Err(error) = write_zones_md(path, &by_origin, archive) {
            tracing::error!(%error, "writing ZONES.md failed");
        }
    }

    // Notify after the archive is safely on disk.
    match notify::deliver(
        config,
        report,
        parse_significance(&config.diff.notify_floor),
    )
    .await
    {
        Ok(delivery) => {
            report.notifications_sent = delivery.sent;
            for error in &delivery.errors {
                tracing::error!(%error, "notification delivery error");
            }
        }
        Err(error) => tracing::error!(%error, "notification delivery failed"),
    }
}

/// Take an exclusive advisory lock on the archive so two cycles cannot overlap.
fn acquire_lock(archive_root: &std::path::Path) -> Result<File> {
    let path = archive_root.join(".tldr.lock");
    let file = File::create(&path).with_context(|| format!("opening {}", path.display()))?;
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(_) => anyhow::bail!(
            "another TLDR cycle is already running (lock {} is held)",
            path.display()
        ),
    }
}

fn parse_significance(text: &str) -> Significance {
    match text.trim().to_ascii_lowercase().as_str() {
        "none" => Significance::None,
        "low" => Significance::Low,
        "medium" => Significance::Medium,
        "high" => Significance::High,
        other => {
            tracing::warn!(value = %other, "unknown notify_floor; defaulting to high");
            Significance::High
        }
    }
}

fn write_zones_md(
    path: &std::path::Path,
    by_origin: &BTreeMap<String, Transfer>,
    archive: &Archive,
) -> Result<()> {
    let mut text = String::from("# Transferable zones\n\n");
    text.push_str("Generated by TLDR from the latest archive snapshot.\n\n");
    for origin in by_origin.keys() {
        let count = archive
            .latest(origin)
            .map(|e| e.records)
            .unwrap_or_default();
        text.push_str(&format!("- `{origin}` ({count} records)\n"));
    }
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    std::fs::write(path, text).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_lock_is_exclusive() {
        let dir = tempfile::tempdir().unwrap();
        let first = acquire_lock(dir.path()).unwrap();
        assert!(acquire_lock(dir.path()).is_err());
        drop(first);
        assert!(acquire_lock(dir.path()).is_ok());
    }
}
