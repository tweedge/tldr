//! Archive storage with zstd compression, content-addressed blobs, and
//! retention pruning.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use chrono::{DateTime, Duration, NaiveDate, Utc};
use serde::{Deserialize, Serialize};

use crate::zone::Zone;

/// One stored snapshot, keyed by zone and capture time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotEntry {
    /// Zone origin as an FQDN (`"."` for the root zone).
    pub origin: String,
    /// Capture timestamp (UTC), used to order snapshots within a day.
    #[serde(default = "epoch")]
    pub captured: DateTime<Utc>,
    /// Capture date (UTC), derived from `captured`; used for daily summaries.
    pub date: NaiveDate,
    /// Content digest of the canonical zone text.
    pub digest: String,
    /// Number of records excluding the SOA.
    pub records: usize,
    /// SOA serial observed at capture time.
    pub serial: u32,
    /// Nameserver that served the transfer.
    pub server: String,
}

fn epoch() -> DateTime<Utc> {
    DateTime::<Utc>::from_timestamp(0, 0).unwrap_or_default()
}

/// Manifest describing the archive's snapshots and blob store.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Manifest {
    #[serde(default)]
    pub snapshots: Vec<SnapshotEntry>,
}

/// Filesystem layout:
///
/// ```text
/// <root>/
///   manifest.json
///   blobs/ab/abcdef...zst     # content-addressed zstd blobs of canonical zone text
///   daily/<date>/<zone>.json  # per-day summary of captured zones
/// ```
pub struct Archive {
    root: PathBuf,
    manifest: Manifest,
}

impl Archive {
    /// Open (or create) an archive rooted at `root`.
    pub fn open(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        std::fs::create_dir_all(root.join("blobs"))?;
        std::fs::create_dir_all(root.join("daily"))?;
        let manifest_path = root.join("manifest.json");
        let manifest = if manifest_path.exists() {
            let text = std::fs::read_to_string(&manifest_path)
                .with_context(|| format!("reading {}", manifest_path.display()))?;
            serde_json::from_str(&text).with_context(|| "parsing archive manifest")?
        } else {
            Manifest::default()
        };
        Ok(Self { root, manifest })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    fn blob_path(&self, digest: &str) -> PathBuf {
        let (prefix, rest) = digest.split_at(2.min(digest.len()));
        self.root
            .join("blobs")
            .join(prefix)
            .join(format!("{rest}.zst"))
    }

    /// Store zone bytes as a compressed, content-addressed blob. Returns the digest.
    pub fn put_blob(&self, text: &str) -> Result<String> {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(text.as_bytes());
        let digest = format!("{:x}", hasher.finalize());
        let path = self.blob_path(&digest);
        if path.exists() {
            return Ok(digest);
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let compressed =
            zstd::encode_all(text.as_bytes(), 19).context("compressing zone blob with zstd")?;
        let tmp = path.with_extension("zst.tmp");
        std::fs::write(&tmp, &compressed).with_context(|| format!("writing {}", tmp.display()))?;
        std::fs::rename(&tmp, &path)?;
        Ok(digest)
    }

    /// Read and decompress a blob by digest.
    pub fn get_blob(&self, digest: &str) -> Result<String> {
        let path = self.blob_path(digest);
        let compressed =
            std::fs::read(&path).with_context(|| format!("reading blob {}", path.display()))?;
        let bytes = zstd::decode_all(compressed.as_slice()).context("decompressing zone blob")?;
        String::from_utf8(bytes).context("zone blob is not valid UTF-8")
    }

    /// Record a snapshot captured at `captured`. Stores the blob
    /// unconditionally (deduplicated) and appends a manifest entry. Multiple
    /// snapshots per zone per day are allowed and kept in capture order.
    pub fn record(
        &mut self,
        origin: &str,
        captured: DateTime<Utc>,
        zone: &Zone,
        server: &str,
    ) -> Result<SnapshotEntry> {
        let text = zone.to_text();
        let digest = self.put_blob(&text)?;
        let entry = SnapshotEntry {
            origin: origin.to_string(),
            captured,
            date: captured.date_naive(),
            digest,
            records: zone.records.len(),
            serial: zone.soa.serial,
            server: server.to_string(),
        };
        self.manifest.snapshots.push(entry.clone());
        self.manifest
            .snapshots
            .sort_by(|a, b| (&a.origin, a.captured).cmp(&(&b.origin, b.captured)));
        Ok(entry)
    }

    /// Write the manifest and per-day summaries to disk.
    pub fn flush(&self) -> Result<()> {
        let manifest_path = self.root.join("manifest.json");
        let text = serde_json::to_string_pretty(&self.manifest)?;
        std::fs::write(&manifest_path, text)
            .with_context(|| format!("writing {}", manifest_path.display()))?;

        let mut by_day: BTreeMap<NaiveDate, Vec<&SnapshotEntry>> = BTreeMap::new();
        for entry in &self.manifest.snapshots {
            by_day.entry(entry.date).or_default().push(entry);
        }
        for (date, entries) in by_day {
            let dir = self.root.join("daily").join(date.to_string());
            std::fs::create_dir_all(&dir)?;
            let mut map = serde_json::Map::new();
            for entry in entries {
                map.insert(
                    entry.origin.clone(),
                    serde_json::json!({
                        "digest": entry.digest,
                        "records": entry.records,
                        "serial": entry.serial,
                        "server": entry.server,
                    }),
                );
            }
            let path = dir.join("zones.json");
            std::fs::write(path, serde_json::to_string_pretty(&map)?)?;
        }
        Ok(())
    }

    /// Most recent snapshot for a zone strictly before `before`.
    pub fn previous(&self, origin: &str, before: DateTime<Utc>) -> Option<&SnapshotEntry> {
        self.manifest
            .snapshots
            .iter()
            .filter(|e| e.origin == origin && e.captured < before)
            .max_by_key(|e| e.captured)
    }

    /// Latest snapshot for a zone, regardless of date.
    pub fn latest(&self, origin: &str) -> Option<&SnapshotEntry> {
        self.manifest
            .snapshots
            .iter()
            .filter(|e| e.origin == origin)
            .max_by_key(|e| e.captured)
    }

    /// All distinct origins ever captured.
    pub fn origins(&self) -> std::collections::BTreeSet<&str> {
        self.manifest
            .snapshots
            .iter()
            .map(|e| e.origin.as_str())
            .collect()
    }

    /// Most recent snapshot for a zone on a specific date.
    pub fn lookup(&self, origin: &str, date: NaiveDate) -> Option<&SnapshotEntry> {
        self.manifest
            .snapshots
            .iter()
            .filter(|e| e.origin == origin && e.date == date)
            .max_by_key(|e| e.captured)
    }

    /// Prune snapshots and blobs older than `retention_days`.
    pub fn prune(&mut self, retention_days: u32, now: DateTime<Utc>) -> Result<usize> {
        let cutoff = now.date_naive() - Duration::days(retention_days as i64);
        let before = self.manifest.snapshots.len();
        self.manifest.snapshots.retain(|e| e.date >= cutoff);
        let removed = before - self.manifest.snapshots.len();

        // Remove blobs no longer referenced by any snapshot.
        let referenced: std::collections::HashSet<&str> = self
            .manifest
            .snapshots
            .iter()
            .map(|e| e.digest.as_str())
            .collect();
        let blobs = self.root.join("blobs");
        if blobs.exists() {
            for prefix in std::fs::read_dir(&blobs)? {
                let prefix = prefix?;
                if !prefix.file_type()?.is_dir() {
                    continue;
                }
                for entry in std::fs::read_dir(prefix.path())? {
                    let entry = entry?;
                    let name = entry.file_name();
                    let name = name.to_string_lossy();
                    let Some(stem) = name.strip_suffix(".zst") else {
                        continue;
                    };
                    let digest = format!("{}{}", prefix.file_name().to_string_lossy(), stem);
                    if !referenced.contains(digest.as_str()) {
                        let _ = std::fs::remove_file(entry.path());
                    }
                }
            }
        }

        // Remove empty daily directories.
        let daily = self.root.join("daily");
        if daily.exists() {
            for entry in std::fs::read_dir(&daily)? {
                let entry = entry?;
                if let Some(stem) = entry.file_name().to_str().map(str::to_string) {
                    if let Ok(date) = stem.parse::<NaiveDate>() {
                        if date < cutoff {
                            let _ = std::fs::remove_dir_all(entry.path());
                        }
                    }
                }
            }
        }

        Ok(removed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zone::{SoaInfo, ZoneRecord};

    fn zone(serial: u32) -> Zone {
        Zone {
            origin: "example.".into(),
            soa: SoaInfo {
                mname: "ns1.example.".into(),
                rname: "hostmaster.example.".into(),
                serial,
                refresh: 3600,
                retry: 600,
                expire: 604800,
                minimum: 300,
            },
            records: vec![ZoneRecord {
                name: "www.example.".into(),
                ttl: 300,
                rtype: "A".into(),
                rdata: "192.0.2.1".into(),
            }],
        }
    }

    fn at(y: i32, m: u32, d: u32) -> DateTime<Utc> {
        DateTime::<Utc>::from_naive_utc_and_offset(
            chrono::NaiveDate::from_ymd_opt(y, m, d)
                .unwrap()
                .and_hms_opt(12, 0, 0)
                .unwrap(),
            Utc,
        )
    }

    #[test]
    fn record_and_dedup_blobs() {
        let dir = tempfile::tempdir().unwrap();
        let mut archive = Archive::open(dir.path()).unwrap();
        let entry = archive
            .record("example.", at(2026, 1, 1), &zone(1), "ns1")
            .unwrap();
        let blob_count = std::fs::read_dir(dir.path().join("blobs"))
            .unwrap()
            .filter_map(|p| p.ok())
            .filter(|p| p.file_type().map(|t| t.is_dir()).unwrap_or(false))
            .count();
        assert!(blob_count <= 1);
        archive
            .record("example.", at(2026, 1, 2), &zone(1), "ns1")
            .unwrap();
        let text = archive.get_blob(&entry.digest).unwrap();
        assert!(text.contains("www.example."));
    }

    #[test]
    fn previous_returns_prior_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let mut archive = Archive::open(dir.path()).unwrap();
        let d1 = at(2026, 1, 1);
        let d2 = at(2026, 1, 2);
        archive.record("example.", d1, &zone(1), "ns1").unwrap();
        archive.record("example.", d2, &zone(2), "ns1").unwrap();
        let prev = archive.previous("example.", d2).unwrap();
        assert_eq!(prev.serial, 1);
    }

    #[test]
    fn previous_is_timestamp_precise_within_a_day() {
        let dir = tempfile::tempdir().unwrap();
        let mut archive = Archive::open(dir.path()).unwrap();
        let morning = at(2026, 1, 1);
        let evening = morning + Duration::hours(6);
        archive
            .record("example.", morning, &zone(1), "ns1")
            .unwrap();
        archive
            .record("example.", evening, &zone(2), "ns1")
            .unwrap();
        let prev = archive.previous("example.", evening).unwrap();
        assert_eq!(prev.serial, 1);
        assert_eq!(archive.latest("example.").unwrap().serial, 2);
    }

    #[test]
    fn prune_removes_old_and_unreferenced_blobs() {
        let dir = tempfile::tempdir().unwrap();
        let mut archive = Archive::open(dir.path()).unwrap();
        let old = at(2020, 1, 1);
        let now = Utc::now();
        archive.record("old.", old, &zone(1), "ns1").unwrap();
        archive.record("new.", now, &zone(2), "ns2").unwrap();
        let removed = archive.prune(30, now).unwrap();
        assert_eq!(removed, 1);
        assert!(archive.lookup("old.", old.date_naive()).is_none());
        assert!(archive.latest("new.").is_some());
    }
}
