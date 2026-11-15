//! Runtime configuration.

use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::Deserialize;

/// Top-level configuration, loaded from TOML.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub archive: ArchiveConfig,
    pub scan: ScanConfig,
    pub diff: DiffConfig,
    pub notify: NotifyConfig,
    pub report: ReportConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ArchiveConfig {
    /// Directory holding the archive.
    pub path: PathBuf,
    /// Days of history to retain.
    pub retention_days: u32,
    /// zstd compression level for blobs (1-22).
    pub compression_level: i32,
}

impl Default for ArchiveConfig {
    fn default() -> Self {
        Self {
            path: PathBuf::from("/data/archive"),
            retention_days: 30,
            compression_level: 19,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ScanConfig {
    /// Maximum concurrent zone-transfer attempts.
    pub concurrency: usize,
    /// Per-transfer timeout in seconds.
    pub timeout_secs: u64,
    /// Delay between starting transfers, in milliseconds, to be gentle on servers.
    pub pacing_ms: u64,
    /// Maximum nameservers to try per zone (AXFR is only offered by some).
    pub max_servers_per_zone: usize,
    /// Whether to attempt root-zone transfers.
    pub include_root: bool,
    /// Optional override of the IANA TLD list (for deterministic testing).
    pub tlds: Option<Vec<String>>,
    /// Do not transfer these zones.
    pub exclude: Vec<String>,
    /// Discover zones and nameservers but skip all transfers (dry run).
    pub discovery_only: bool,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            concurrency: 12,
            timeout_secs: 20,
            pacing_ms: 0,
            max_servers_per_zone: 6,
            include_root: true,
            tlds: None,
            exclude: Vec::new(),
            discovery_only: false,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DiffConfig {
    /// Minimum significance that is notified ("none", "low", "medium", "high").
    pub notify_floor: String,
    /// Minimum changed delegations for a "mass change".
    pub delegation_min_count: usize,
    /// Minimum changed-delegation fraction for a "mass change".
    pub delegation_min_fraction: f64,
    /// Minimum changed-record fraction for a major rewrite.
    pub record_min_fraction: f64,
    /// Minimum changed delegations to rate Medium.
    pub medium_delegation_min: usize,
    /// Additional record types to treat as noise (on top of the built-in
    /// DNSSEC/ZONEMD/TXT-generation-time filters).
    pub ignore_rtypes: Vec<String>,
}

impl Default for DiffConfig {
    fn default() -> Self {
        Self {
            notify_floor: "high".to_string(),
            delegation_min_count: 25,
            delegation_min_fraction: 0.01,
            record_min_fraction: 0.05,
            medium_delegation_min: 5,
            ignore_rtypes: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NotifyConfig {
    pub enabled: bool,
    pub app_token_env: String,
    pub user_token_env: String,
    pub title: String,
    /// Optional Pushover device name to target a single device.
    pub device: Option<String>,
    /// Optional Pushover priority (-2..=2). Unset uses the app default (0).
    pub priority: Option<i8>,
    /// Maximum characters per Pushover message before splitting.
    pub message_max_chars: usize,
    /// Suppress all notifications for a dry run.
    pub dry_run: bool,
}

impl Default for NotifyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            app_token_env: "PUSHOVER_APP_TOKEN".to_string(),
            user_token_env: "PUSHOVER_USER_TOKEN".to_string(),
            title: "TLDR".to_string(),
            device: None,
            priority: None,
            message_max_chars: 1000,
            dry_run: false,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ReportConfig {
    /// Write a human-readable ZONES.md summary here (optional).
    pub zones_md: Option<PathBuf>,
}

impl Config {
    pub fn load(path: &std::path::Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading config {}", path.display()))?;
        let config: Config =
            toml::from_str(&text).with_context(|| format!("parsing config {}", path.display()))?;
        Ok(config)
    }
}
