//! Canonical zone representation, serialization, and hashing.

use std::collections::BTreeSet;
use std::fmt;

use anyhow::{bail, Context, Result};
use hickory_proto::rr::{RData, Record};

/// Normalize a zone name to a lowercase FQDN (`"."` for the root zone).
pub fn fqdn(name: &str) -> String {
    let trimmed = name.trim();
    if trimmed.is_empty() || trimmed == "." {
        return ".".to_string();
    }
    let lower = trimmed.trim_end_matches('.').to_ascii_lowercase();
    let mut out = String::with_capacity(lower.len() + 1);
    out.push_str(&lower);
    out.push('.');
    out
}

/// Lowercase the domain-name portions of RDATA for the record types whose
/// RDATA is (or ends in) a domain name. DNS names are case-insensitive, and
/// archives captured by different tools preserve different case, so this
/// normalization is required for stable diffing.
fn normalize_rdata(rtype: &str, rdata: &str) -> String {
    match rtype {
        // Entire RDATA is a single domain name.
        "NS" | "CNAME" | "PTR" | "DNAME" | "ANAME" => rdata.trim().to_ascii_lowercase(),
        // RDATA ends in a domain name preceded by numeric fields.
        "MX" | "SRV" => {
            let mut parts: Vec<&str> = rdata.split_whitespace().collect();
            if let Some(last) = parts.last_mut() {
                let lowered = last.to_ascii_lowercase();
                let owned: String = lowered;
                let idx = parts.len() - 1;
                let mut owned_parts: Vec<String> = parts.iter().map(|p| (*p).to_string()).collect();
                owned_parts[idx] = owned;
                return owned_parts.join(" ");
            }
            rdata.trim().to_string()
        }
        _ => rdata.trim().to_string(),
    }
}

/// SOA contents that are semantically interesting for change detection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SoaInfo {
    pub mname: String,
    pub rname: String,
    pub serial: u32,
    pub refresh: i32,
    pub retry: i32,
    pub expire: i32,
    pub minimum: u32,
}

/// One resource record in a zone. `rdata` is the presentation form of the RDATA.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ZoneRecord {
    pub name: String,
    pub ttl: u32,
    pub rtype: String,
    pub rdata: String,
}

impl ZoneRecord {
    /// A key that ignores the TTL, used for change detection.
    pub fn identity(&self) -> (&str, &str, &str) {
        (&self.name, &self.rtype, &self.rdata)
    }

    /// Canonical presentation line.
    pub fn line(&self) -> String {
        format!(
            "{}\t{}\tIN\t{}\t{}",
            self.name, self.ttl, self.rtype, self.rdata
        )
    }
}

/// A complete zone snapshot.
#[derive(Debug, Clone)]
pub struct Zone {
    pub origin: String,
    pub soa: SoaInfo,
    pub records: Vec<ZoneRecord>,
}

impl Zone {
    /// Build a zone from AXFR answer records.
    pub fn from_records(origin: &str, records: &[Record]) -> Result<Self> {
        let origin = fqdn(origin);
        let mut soa: Option<SoaInfo> = None;
        let mut out: BTreeSet<ZoneRecord> = BTreeSet::new();

        for record in records {
            let record_type = record.record_type();
            // hickory's Display renders every unsupported type as "Unknown",
            // discarding the numeric code. Preserve the code so unsupported
            // types stay distinguishable (and diffable) in the archive.
            let rtype = match record_type {
                hickory_proto::rr::RecordType::Unknown(code) => format!("TYPE{code}"),
                other => other.to_string(),
            };
            if rtype == "OPT" || rtype == "TSIG" {
                continue;
            }
            let name = fqdn(&record.name.to_ascii());
            let rdata = normalize_rdata(&rtype, &record.data.to_string());
            if rtype == "SOA" {
                if let RData::SOA(ref value) = record.data {
                    soa.get_or_insert_with(|| SoaInfo {
                        mname: fqdn(&value.mname.to_ascii()),
                        rname: fqdn(&value.rname.to_ascii()),
                        serial: value.serial,
                        refresh: value.refresh,
                        retry: value.retry,
                        expire: value.expire,
                        minimum: value.minimum,
                    });
                }
                // The SOA is tracked separately and never treated as a normal record.
                continue;
            }
            out.insert(ZoneRecord {
                name,
                ttl: record.ttl,
                rtype,
                rdata,
            });
        }

        let soa = soa.context("zone transfer did not contain an SOA record")?;
        Ok(Self {
            origin,
            soa,
            records: out.into_iter().collect(),
        })
    }

    /// Canonical, sorted zone text suitable for archiving.
    pub fn to_text(&self) -> String {
        let mut lines = Vec::with_capacity(self.records.len() + 1);
        lines.push(format!(
            "{}\t{}\tIN\tSOA\t{} {} {} {} {} {} {}",
            self.origin,
            self.records.first().map(|r| r.ttl).unwrap_or(0),
            self.soa.mname,
            self.soa.rname,
            self.soa.serial,
            self.soa.refresh,
            self.soa.retry,
            self.soa.expire,
            self.soa.minimum
        ));
        for record in &self.records {
            lines.push(record.line());
        }
        lines.sort();
        let mut text = lines.join("\n");
        text.push('\n');
        text
    }

    /// Parse the canonical text produced by [`Zone::to_text`].
    pub fn from_text(origin: &str, text: &str) -> Result<Self> {
        let origin = fqdn(origin);
        let mut soa: Option<SoaInfo> = None;
        let mut records = Vec::new();

        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with(';') {
                continue;
            }
            // Split into the first four whitespace-delimited fields, then keep
            // the remainder verbatim as RDATA. This tolerates the multiple
            // tabs produced by `dig` as well as our own single-tab output.
            let mut fields = line.split_whitespace();
            let name = fields.next().context("record is missing a name")?;
            let _ttl = fields.next().context("record is missing a TTL")?;
            let _class = fields.next().context("record is missing a class")?;
            let rtype = fields.next().context("record is missing a type")?;
            let rdata_offset = line
                .find(rtype)
                .map(|idx| idx + rtype.len())
                .unwrap_or(line.len());
            let rdata = line[rdata_offset..].trim();
            let name = fqdn(name);
            if rtype == "SOA" {
                let tokens: Vec<&str> = rdata.split_whitespace().collect();
                if tokens.len() < 7 {
                    bail!("malformed SOA record in archived zone: {line}");
                }
                soa = Some(SoaInfo {
                    mname: fqdn(tokens[0]),
                    rname: fqdn(tokens[1]),
                    serial: tokens[2].parse().context("invalid SOA serial")?,
                    refresh: tokens[3].parse().context("invalid SOA refresh")?,
                    retry: tokens[4].parse().context("invalid SOA retry")?,
                    expire: tokens[5].parse().context("invalid SOA expire")?,
                    minimum: tokens[6].parse().context("invalid SOA minimum")?,
                });
                continue;
            }
            records.push(ZoneRecord {
                name,
                ttl: _ttl.parse().unwrap_or(0),
                rtype: rtype.to_string(),
                rdata: normalize_rdata(rtype, rdata),
            });
        }

        let soa = soa.with_context(|| format!("archived zone {origin} has no SOA"))?;
        records.sort();
        Ok(Self {
            origin,
            soa,
            records,
        })
    }

    /// SHA-256 of the canonical zone text, used for blob deduplication.
    pub fn digest(&self) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(self.to_text().as_bytes());
        let digest = hasher.finalize();
        let mut out = String::with_capacity(64);
        for byte in digest {
            use fmt::Write as _;
            let _ = write!(out, "{byte:02x}");
        }
        out
    }

    /// Look up records by type.
    pub fn of_type<'a>(&'a self, rtype: &'a str) -> impl Iterator<Item = &'a ZoneRecord> + 'a {
        self.records.iter().filter(move |r| r.rtype == rtype)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fqdn_normalizes() {
        assert_eq!(fqdn("ARPA"), "arpa.");
        assert_eq!(fqdn("."), ".");
        assert_eq!(fqdn(""), ".");
        assert_eq!(fqdn("example.com."), "example.com.");
    }

    fn sample() -> Zone {
        Zone {
            origin: "example.".into(),
            soa: SoaInfo {
                mname: "ns1.example.".into(),
                rname: "hostmaster.example.".into(),
                serial: 42,
                refresh: 3600,
                retry: 600,
                expire: 604800,
                minimum: 300,
            },
            records: vec![
                ZoneRecord {
                    name: "example.".into(),
                    ttl: 3600,
                    rtype: "NS".into(),
                    rdata: "ns1.example.".into(),
                },
                ZoneRecord {
                    name: "www.example.".into(),
                    ttl: 300,
                    rtype: "A".into(),
                    rdata: "192.0.2.1".into(),
                },
            ],
        }
    }

    #[test]
    fn text_roundtrip() {
        let zone = sample();
        let text = zone.to_text();
        let parsed = Zone::from_text("example.", &text).unwrap();
        assert_eq!(parsed.origin, zone.origin);
        assert_eq!(parsed.soa, zone.soa);
        assert_eq!(parsed.records, zone.records);
    }

    #[test]
    fn digest_is_stable() {
        let zone = sample();
        assert_eq!(zone.digest(), zone.digest());
        assert_eq!(zone.digest().len(), 64);
    }

    #[test]
    fn digest_changes_with_content() {
        let mut zone = sample();
        let before = zone.digest();
        zone.records[1].rdata = "192.0.2.2".into();
        assert_ne!(before, zone.digest());
    }
}
