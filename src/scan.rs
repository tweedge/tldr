//! Run orchestration: discovery, transfer, archiving, diffing, and reporting.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use tldr_core::archive::{Archive, SnapshotEntry};
use tldr_core::axfr::{transfer_axfr, TransferOutcome, Transport};
use tldr_core::diff::{diff, DiffPolicy, Significance, ZoneDiff};
use tldr_core::discovery::{doh_resolver, fetch_iana_tlds, lookup_addresses, lookup_nameservers};
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
    pub top_servers: Vec<(String, usize)>,
    /// Zones that transferred, grouped by serving nameserver.
    pub executed: Vec<ZoneResult>,
    /// True when the archive was empty at the start of this run (first run).
    pub is_initial: bool,
    pub expired: usize,
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
            "expired": self.expired,
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

fn transport_for(config: &Config) -> Transport {
    match config.scan.transport.as_str() {
        "socks5" | "auto" => {
            if let Some(proxy) = &config.scan.socks5_proxy {
                if let Ok(addr) = proxy.parse() {
                    return Transport::Socks5 { addr };
                }
            }
            Transport::Direct
        }
        _ => Transport::Direct,
    }
}

/// Run one full scan cycle.
pub async fn run(config: &Config) -> Result<RunReport> {
    let started = Utc::now();
    let policy = DiffPolicy {
        delegation_min_count: config.diff.delegation_min_count,
        delegation_min_fraction: config.diff.delegation_min_fraction,
        record_min_fraction: config.diff.record_min_fraction,
        medium_delegation_min: config.diff.medium_delegation_min,
        ignore_rtypes: config.diff.ignore_rtypes.clone(),
    };
    let floor = parse_significance(&config.diff.notify_floor);

    let mut archive = Archive::open(&config.archive.path)?;
    let retention = config.archive.retention_days;
    let is_initial = archive.manifest().snapshots.is_empty();

    // Refresh mirror on disk before mutating (in case a previous run left it dirty).
    archive.flush()?;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent("tldr/0.1 (+https://github.com/tweedge/tldr)")
        .build()?;

    let mut zones: Vec<(String, bool)> = Vec::new();
    if config.scan.include_root {
        zones.push((".".to_string(), true));
    }
    if let Some(tlds) = &config.scan.tlds {
        for tld in tlds {
            zones.push((fqdn(tld), false));
        }
    } else {
        let tlds = fetch_iana_tlds(&client).await?;
        for tld in tlds {
            zones.push((fqdn(&tld), false));
        }
    }
    let exclude: std::collections::BTreeSet<String> =
        config.scan.exclude.iter().map(|z| fqdn(z)).collect();
    zones.retain(|(origin, _)| !exclude.contains(origin));

    let mut report = RunReport {
        started: Some(started),
        zones_attempted: zones.len(),
        is_initial,
        ..Default::default()
    };

    // Limit total concurrency across all zones.
    let semaphore = Arc::new(Semaphore::new(config.scan.concurrency.max(1)));
    let transport = transport_for(config);
    if let Transport::Socks5 { addr } = transport {
        match tokio::time::timeout(Duration::from_secs(5), tokio::net::TcpStream::connect(addr))
            .await
        {
            Ok(Ok(_)) => tracing::info!(%addr, "SOCKS5 proxy reachable"),
            Ok(Err(error)) => {
                tracing::warn!(%addr, %error, "SOCKS5 proxy unreachable; transfers will fail until the tunnel is up")
            }
            Err(_) => tracing::warn!(%addr, "SOCKS5 proxy connection timed out"),
        }
    }
    let timeout = Duration::from_secs(config.scan.timeout_secs.max(1));
    let pacing = Duration::from_millis(config.scan.pacing_ms);

    // Root zone is special: try every root server, since some may refuse.
    let mut handles = Vec::new();

    // Resolve root server names up front once.
    let root_names: Vec<String> = tldr_core::discovery::ROOT_SERVERS
        .iter()
        .map(|s| s.to_string())
        .collect();

    // Build a discovery resolver for NS lookups.
    let resolver = match doh_resolver() {
        Ok(r) => Some(r),
        Err(error) => {
            tracing::warn!(%error, "no DoH resolver; skipping zone discovery");
            None
        }
    };

    let mut schedule: Vec<(String, String)> = Vec::new();

    // Root servers are always scheduled by name.
    for server in &root_names {
        if config.scan.include_root {
            schedule.push((".".to_string(), server.clone()));
        }
    }

    // Resolve TLD nameservers concurrently; 1.4k zones serially is far too slow.
    if let Some(resolver) = &resolver {
        let resolver = resolver.clone();
        let mut ns_tasks = Vec::new();
        for (origin, is_root) in &zones {
            if *is_root {
                continue;
            }
            let origin = origin.clone();
            let resolver = resolver.clone();
            ns_tasks.push(tokio::spawn(async move {
                let servers = lookup_nameservers(&resolver, &origin).await;
                (origin, servers)
            }));
        }
        for task in ns_tasks {
            match task.await {
                Ok((origin, Ok(mut servers))) => {
                    // Only some authoritative servers answer AXFR; cap attempts so a
                    // full IANA sweep stays bounded.
                    servers.sort();
                    servers.dedup();
                    servers.truncate(config.scan.max_servers_per_zone.max(1));
                    for server in servers {
                        schedule.push((origin.clone(), server));
                    }
                }
                Ok((origin, Err(error))) => {
                    tracing::debug!(%origin, %error, "no nameservers discovered");
                }
                Err(error) => tracing::debug!(%error, "nameserver lookup task failed"),
            }
        }
    }

    tracing::info!(
        zones = zones.len(),
        attempts = schedule.len(),
        concurrency = config.scan.concurrency,
        "starting transfers"
    );

    // Resolve every distinct server name once.
    let mut server_ips: BTreeMap<String, Vec<std::net::IpAddr>> = BTreeMap::new();
    if let Some(resolver) = &resolver {
        let distinct: std::collections::BTreeSet<String> =
            schedule.iter().map(|(_, s)| s.clone()).collect();
        let mut address_tasks = Vec::new();
        for server in distinct {
            let resolver = resolver.clone();
            address_tasks.push(tokio::spawn(async move {
                let addrs = lookup_addresses(&resolver, &server).await;
                (server, addrs)
            }));
        }
        for task in address_tasks {
            match task.await {
                Ok((server, Ok(addrs))) => {
                    server_ips.insert(server, addrs);
                }
                Ok((server, Err(error))) => {
                    tracing::debug!(%server, %error, "could not resolve server addresses");
                }
                Err(error) => tracing::debug!(%error, "address lookup task failed"),
            }
        }
    }
    // Fall back to the system resolver for any server DoH could not resolve.
    let mut unresolved: Vec<String> = schedule
        .iter()
        .map(|(_, s)| s.clone())
        .filter(|s| !server_ips.contains_key(s))
        .collect();
    unresolved.sort();
    unresolved.dedup();
    let mut fallback_tasks = Vec::new();
    for server in unresolved {
        fallback_tasks.push(tokio::spawn(async move {
            let addrs = tldr_core::axfr::resolve_host(&server).await;
            (server, addrs)
        }));
    }
    for task in fallback_tasks {
        if let Ok((server, Ok(addrs))) = task.await {
            server_ips.insert(server, addrs);
        }
    }

    if config.scan.discovery_only {
        report.finished = Some(Utc::now());
        report.top_servers = Vec::new();
        // Report discovered servers without transferring.
        for (_, server) in &schedule {
            let entry = report
                .top_servers
                .iter_mut()
                .find(|(name, _)| name == server);
            match entry {
                Some((_, count)) => *count += 1,
                None => report.top_servers.push((server.clone(), 1)),
            }
        }
        report.top_servers.sort_by(|a, b| b.1.cmp(&a.1));
        report.top_servers.truncate(10);
        tracing::info!(
            zones = zones.len(),
            nameservers = schedule.len(),
            "discovery complete (dry run, no transfers)"
        );
        return Ok(report);
    }

    for (origin, server) in &schedule {
        let permit = semaphore.clone().acquire_owned().await?;
        if !pacing.is_zero() {
            tokio::time::sleep(pacing).await;
        }

        let ips = server_ips.get(server).cloned().unwrap_or_default();
        let origin = origin.clone();
        let server = server.clone();
        let transport = transport.clone();
        let handle = tokio::spawn(async move {
            let _permit = permit;
            if ips.is_empty() {
                return (
                    origin,
                    server,
                    TransferOutcome::Failed("no addresses for server".to_string()),
                );
            }
            // Try each address until one answers.
            let mut last = TransferOutcome::Failed("no addresses for server".to_string());
            for ip in ips {
                let outcome = transfer_axfr(&origin, ip, &transport, timeout).await;
                let done = matches!(
                    outcome,
                    TransferOutcome::Success(_) | TransferOutcome::Refused
                );
                last = outcome;
                if done {
                    break;
                }
            }
            (origin, server, last)
        });
        handles.push(handle);
    }

    let mut results: Vec<(String, String, Option<Zone>)> = Vec::new();

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
                results.push((origin, server, Some(zone)));
            }
            TransferOutcome::Refused => {
                // Most servers refuse AXFR; recording each one would bloat the
                // report without adding signal. The count is sufficient.
                report.zones_refused += 1;
            }
            TransferOutcome::Failed(error) => {
                report.zones_failed += 1;
                tracing::debug!(%origin, %server, %error, "transfer failed");
                report.executed.push(ZoneResult {
                    origin: origin.clone(),
                    server: server.clone(),
                    outcome: Outcome::Failed(error),
                    significance: Significance::None,
                    diff: None,
                    entry: None,
                });
            }
        }
    }

    // Group transfers by origin: keep the first, note the server.
    let mut by_origin: BTreeMap<String, (String, Zone)> = BTreeMap::new();
    for (origin, server, zone) in results {
        if let Some(zone) = zone {
            by_origin.entry(origin).or_insert((server, zone));
        }
    }

    // Record snapshots, compute diffs.
    let mut changed = Vec::new();
    for (origin, (server, zone)) in &by_origin {
        let previous_entry = archive.previous(origin, started).cloned();
        let is_new = archive.latest(origin).is_none();

        let diff_report = if let Some(previous) = &previous_entry {
            let previous_text = archive.get_blob(&previous.digest)?;
            let previous_zone = Zone::from_text(origin, &previous_text)?;
            Some(diff(&previous_zone, zone))
        } else {
            None
        };

        let entry = archive.record(origin, started, zone, server)?;
        report.executed.push(ZoneResult {
            origin: origin.clone(),
            server: server.clone(),
            outcome: Outcome::Transferred,
            significance: Significance::None,
            diff: None,
            entry: Some(entry.clone()),
        });

        if is_new {
            report.new_zones.push(origin.clone());
        }

        if let Some(diff_report) = diff_report {
            let significance = diff_report.significance(&policy);
            if significance != Significance::None {
                changed.push(ZoneResult {
                    origin: origin.clone(),
                    server: server.clone(),
                    outcome: Outcome::Transferred,
                    significance,
                    diff: Some(diff_report),
                    entry: Some(entry),
                });
            }
        } else if is_new {
            // Newly transferable zone: always high.
            changed.push(ZoneResult {
                origin: origin.clone(),
                server: server.clone(),
                outcome: Outcome::Transferred,
                significance: Significance::High,
                diff: None,
                entry: Some(entry),
            });
        }
    }

    report.changed = changed;
    archive.prune(retention, Utc::now())?;
    archive.flush()?;

    // Write ZONES.md if configured.
    if let Some(path) = &config.report.zones_md {
        let zones = by_origin.keys().cloned().collect::<Vec<_>>();
        write_zones_md(path, &zones, &archive)?;
    }

    // Notify. Notification failures must never discard a completed scan or its
    // archive: log and continue so the next cycle (or a manual read) still works.
    match notify::deliver(config, &mut report, floor).await {
        Ok(notified) => report.notifications_sent = notified,
        Err(error) => tracing::error!(%error, "notification delivery failed"),
    }

    report.finished = Some(Utc::now());
    report.top_servers = by_origin
        .values()
        .map(|(server, _)| server.clone())
        .filter(|_| true)
        .fold(BTreeMap::new(), |mut acc, server| {
            *acc.entry(server).or_insert(0) += 1;
            acc
        })
        .into_iter()
        .collect::<Vec<_>>();
    report.top_servers.sort_by(|a, b| b.1.cmp(&a.1));
    report.top_servers.truncate(10);

    Ok(report)
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

fn write_zones_md(path: &std::path::Path, zones: &[String], archive: &Archive) -> Result<()> {
    let mut text = String::from("# Transferable zones\n\n");
    text.push_str("Generated by TLDR from the latest archive snapshot.\n\n");
    let mut sorted = zones.to_vec();
    sorted.sort();
    for origin in sorted {
        let count = archive
            .latest(&origin)
            .map(|e| e.records)
            .unwrap_or_default();
        text.push_str(&format!("- `{}` ({} records)\n", origin, count));
    }
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    std::fs::write(path, text).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}
