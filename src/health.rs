//! Heartbeat and dead-man's-switch.
//!
//! The scan only ever *reports* when it runs. If the process dies, hangs, or is
//! silently failing to transfer anything, nothing is sent, which looks exactly
//! like "no news is good news". To catch that, every completed cycle writes a
//! small heartbeat file, and a separate `tldr --check-health` invocation (run by
//! a systemd timer) screams via Pushover if the heartbeat has gone stale.
//!
//! This is deliberately tiny: one JSON file plus one check. No daemon, no
//! database. If the checker itself never runs, the host's own monitoring (or the
//! absence of the weekly "still alive" message) is the backstop.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::config::NotifyConfig;

/// What a completed cycle leaves behind for the health checker.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Heartbeat {
    /// When the cycle finished.
    pub finished: DateTime<Utc>,
    pub zones_transferred: usize,
    pub zones_failed: usize,
    pub notifications_sent: usize,
}

/// Write the heartbeat file after a completed cycle.
///
/// Uses write-temp-then-rename so a crash mid-write never leaves a truncated
/// file that would confuse the checker.
pub fn write(path: &Path, heartbeat: &Heartbeat) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(heartbeat)?)
        .with_context(|| format!("writing {}", tmp.display()))?;
    std::fs::rename(&tmp, path).with_context(|| format!("renaming into {}", path.display()))?;
    Ok(())
}

/// Read the heartbeat, if it exists.
pub fn read(path: &Path) -> Result<Option<Heartbeat>> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(
            serde_json::from_slice(&bytes).context("parsing heartbeat file")?,
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("reading {}", path.display())),
    }
}

/// Compute the heartbeat path next to the archive.
pub fn path_for(archive_root: &Path) -> PathBuf {
    archive_root.join("heartbeat.json")
}

/// Exit status used by `--check-health` when the heartbeat is stale.
pub const UNHEALTHY_EXIT: i32 = 75;

/// Why a health check failed, if it did.
#[derive(Debug)]
pub struct Unhealthy {
    pub message: String,
}

/// Decide whether the heartbeat is acceptable.
///
/// Unhealthy when: the file is missing (never completed a cycle), it cannot be
/// read, or its `finished` timestamp is older than `max_age`.
pub fn check(path: &Path, max_age: Duration, now: DateTime<Utc>) -> Result<(), Unhealthy> {
    let heartbeat = match read(path) {
        Ok(Some(heartbeat)) => heartbeat,
        Ok(None) => {
            return Err(Unhealthy {
                message: format!(
                    "TLDR has no heartbeat at {} — it has never completed a cycle",
                    path.display()
                ),
            })
        }
        Err(error) => {
            return Err(Unhealthy {
                message: format!("TLDR heartbeat is unreadable: {error:#}"),
            })
        }
    };

    let age = now.signed_duration_since(heartbeat.finished);
    let age = age.to_std().unwrap_or(Duration::ZERO);
    if age > max_age {
        return Err(Unhealthy {
            message: format!(
                "TLDR has not completed a cycle since {} ({} ago, limit {}). Last run: {} transferred, {} failed.",
                heartbeat.finished.to_rfc3339(),
                humanize(age),
                humanize(max_age),
                heartbeat.zones_transferred,
                heartbeat.zones_failed,
            ),
        });
    }

    Ok(())
}

fn humanize(duration: Duration) -> String {
    let secs = duration.as_secs();
    if secs >= 86_400 {
        format!("{}d", secs / 86_400)
    } else if secs >= 3_600 {
        format!("{}h", secs / 3_600)
    } else if secs >= 60 {
        format!("{}m", secs / 60)
    } else {
        format!("{secs}s")
    }
}

/// Run the health check and, when unhealthy, alert and report failure.
///
/// Returns the process exit code: `0` when healthy, [`UNHEALTHY_EXIT`] when
/// stale (after attempting to send a Pushover alert).
pub async fn run_check(path: &Path, max_age: Duration, notify: &NotifyConfig) -> i32 {
    match check(path, max_age, Utc::now()) {
        Ok(()) => {
            tracing::info!("health check OK: heartbeat is fresh");
            0
        }
        Err(unhealthy) => {
            tracing::error!("{}", unhealthy.message);
            if notify.enabled && !notify.dry_run {
                if let Err(error) = crate::notify::send_alert(notify, &unhealthy.message).await {
                    tracing::error!(%error, "failed to send health alert");
                }
            }
            UNHEALTHY_EXIT
        }
    }
}

/// Parse a max-age flag like `2h`, `90m`, or a bare number of seconds.
pub fn parse_duration(text: &str) -> Result<Duration> {
    let text = text.trim();
    if let Some(value) = text.strip_suffix('h') {
        return Ok(Duration::from_secs(value.trim().parse::<u64>()? * 3600));
    }
    if let Some(value) = text.strip_suffix('m') {
        return Ok(Duration::from_secs(value.trim().parse::<u64>()? * 60));
    }
    if let Some(value) = text.strip_suffix('s') {
        return Ok(Duration::from_secs(value.trim().parse::<u64>()?));
    }
    match text.parse::<u64>() {
        Ok(secs) => Ok(Duration::from_secs(secs)),
        Err(_) => bail!("invalid duration {text:?}; use e.g. 90m, 2h, or 7200"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration as ChronoDuration;

    fn heartbeat(finished: DateTime<Utc>) -> Heartbeat {
        Heartbeat {
            finished,
            zones_transferred: 14,
            zones_failed: 3,
            notifications_sent: 0,
        }
    }

    #[test]
    fn write_then_read_roundtrips() {
        let dir = tempfile::tempdir().unwrap();
        let path = path_for(dir.path());
        let now = Utc::now();
        write(&path, &heartbeat(now)).unwrap();
        let read_back = read(&path).unwrap().unwrap();
        assert_eq!(read_back.zones_transferred, 14);
    }

    #[test]
    fn fresh_heartbeat_is_healthy() {
        let now = Utc::now();
        let dir = tempfile::tempdir().unwrap();
        let path = path_for(dir.path());
        write(&path, &heartbeat(now - ChronoDuration::minutes(10))).unwrap();
        assert!(check(&path, Duration::from_secs(2 * 3600), now).is_ok());
    }

    #[test]
    fn stale_heartbeat_is_unhealthy() {
        let now = Utc::now();
        let dir = tempfile::tempdir().unwrap();
        let path = path_for(dir.path());
        write(&path, &heartbeat(now - ChronoDuration::hours(5))).unwrap();
        let result = check(&path, Duration::from_secs(2 * 3600), now);
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("has not completed"));
    }

    #[test]
    fn missing_heartbeat_is_unhealthy() {
        let dir = tempfile::tempdir().unwrap();
        let path = path_for(dir.path());
        let result = check(&path, Duration::from_secs(3600), Utc::now());
        assert!(result.is_err());
    }

    #[test]
    fn parses_durations() {
        assert_eq!(parse_duration("90m").unwrap(), Duration::from_secs(5400));
        assert_eq!(parse_duration("2h").unwrap(), Duration::from_secs(7200));
        assert_eq!(parse_duration("45s").unwrap(), Duration::from_secs(45));
        assert_eq!(parse_duration("300").unwrap(), Duration::from_secs(300));
        assert!(parse_duration("soon").is_err());
    }
}
