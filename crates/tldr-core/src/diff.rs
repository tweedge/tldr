//! Semantic zone diffing and significance classification.
//!
//! Raw zone transfers churn constantly: SOA serials tick, DNSSEC signatures
//! rotate, NSEC chains are re-derived, and TTLs wiggle. Almost none of that is
//! worth a notification. This module reduces two snapshots to the categories
//! that actually matter (apex nameservers, delegations, delegation security
//! records) and assigns a significance level driven by explicit thresholds.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::zone::{Zone, ZoneRecord};

/// Record types that are pure DNSSEC machinery or churn and never drive alerts.
const DNSSEC_TYPES: &[&str] = &[
    "ZONEMD",
    "RRSIG",
    "DNSKEY",
    "NSEC",
    "NSEC3",
    "NSEC3PARAM",
    "DS",
    "CDS",
    "CDNSKEY",
    "SIG",
    "KEY",
];

/// Numeric DNSSEC record types, in case hickory surfaces them as `TYPE<code>`
/// because the type is not in its supported set.
const DNSSEC_TYPE_CODES: &[u16] = &[24, 25, 43, 46, 47, 48, 50, 51, 59, 60, 63, 32769];

fn is_dnssec(rtype: &str) -> bool {
    if DNSSEC_TYPES.contains(&rtype) {
        return true;
    }
    rtype
        .strip_prefix("TYPE")
        .and_then(|code| code.parse::<u16>().ok())
        .map(|code| DNSSEC_TYPE_CODES.contains(&code))
        .unwrap_or(false)
}

/// Some TLDs publish a TXT record whose value is a monotonically-advancing
/// timestamp ("Generation Time"). It changes on every transfer (or every few
/// minutes) and carries no structural meaning, so it must never contribute to
/// significance. Match it case-insensitively on the RDATA prefix.
fn is_generation_time(rtype: &str, rdata: &str) -> bool {
    rtype == "TXT" && {
        let lower = rdata.to_ascii_lowercase();
        lower.contains("generation time")
    }
}

/// How interesting a diff is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Significance {
    /// Only SOA/DNSSEC/glue/TTL churn or trivial record movement.
    None,
    /// Small, routine delegation churn. Archived but not notified.
    Low,
    /// Noteworthy but below the "major change" bar.
    Medium,
    /// New/vanished zone, apex nameserver change, or a mass change.
    High,
}

impl Significance {
    pub fn as_str(self) -> &'static str {
        match self {
            Significance::None => "none",
            Significance::Low => "low",
            Significance::Medium => "medium",
            Significance::High => "high",
        }
    }

    /// Whether this at least meets the given notification floor.
    pub fn at_least(self, floor: Significance) -> bool {
        self >= floor
    }
}

/// Thresholds that turn a raw diff into a significance verdict.
#[derive(Debug, Clone)]
pub struct DiffPolicy {
    /// Minimum number of changed delegated names to consider a mass change.
    pub delegation_min_count: usize,
    /// Minimum changed-delegation fraction of the zone (0..=1) for a mass change.
    pub delegation_min_fraction: f64,
    /// Minimum changed-record fraction of the zone (0..=1) for a major rewrite.
    pub record_min_fraction: f64,
    /// Changed delegated names below the mass thresholds still rate Medium.
    pub medium_delegation_min: usize,
    /// Extra record types to ignore entirely, on top of the built-in noise list.
    pub ignore_rtypes: Vec<String>,
}

impl Default for DiffPolicy {
    fn default() -> Self {
        Self {
            delegation_min_count: 25,
            delegation_min_fraction: 0.01,
            record_min_fraction: 0.05,
            medium_delegation_min: 5,
            ignore_rtypes: Vec::new(),
        }
    }
}

/// A semantic diff between two zones.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ZoneDiff {
    pub origin: String,
    pub serial_from: u32,
    pub serial_to: u32,
    pub records_from: usize,
    pub records_to: usize,

    /// Apex NS rdata added/removed.
    pub apex_ns_added: Vec<String>,
    pub apex_ns_removed: Vec<String>,

    /// Delegated owner names (non-apex NS) that appeared or vanished.
    pub delegations_added: Vec<String>,
    pub delegations_removed: Vec<String>,

    /// Delegation NS records whose target changed for an existing owner.
    pub delegation_retargeted: Vec<String>,

    pub glue_changed: usize,
    pub dnssec_changed: usize,
    pub other_added: Vec<String>,
    pub other_removed: Vec<String>,

    pub added_total: usize,
    pub removed_total: usize,
}

impl ZoneDiff {
    pub fn is_empty(&self) -> bool {
        self.added_total == 0 && self.removed_total == 0
    }

    /// Number of distinct delegated names affected (added + removed + retargeted).
    pub fn delegations_changed(&self) -> usize {
        self.delegations_added.len()
            + self.delegations_removed.len()
            + self.delegation_retargeted.len()
    }

    /// Classify significance using the supplied policy.
    pub fn significance(&self, policy: &DiffPolicy) -> Significance {
        if self.is_empty() {
            return Significance::None;
        }

        // Apex nameserver change is always high.
        if !self.apex_ns_added.is_empty() || !self.apex_ns_removed.is_empty() {
            return Significance::High;
        }

        let zone_size = self.records_to.max(self.records_from).max(1);
        let changed = self.added_total + self.removed_total;

        // Mass delegation change: requires both an absolute floor and a fraction,
        // so huge zones need proportionate churn and tiny zones need real counts.
        let delegated = self.delegations_changed();
        let delegated_fraction = delegated as f64 / zone_size as f64;
        if delegated >= policy.delegation_min_count
            && delegated_fraction >= policy.delegation_min_fraction
        {
            return Significance::High;
        }

        // Major rewrite of the zone body, excluding DNSSEC/glue noise. This needs
        // both a meaningful fraction *and* an absolute floor: without the floor a
        // tiny zone would rate every single edit as a major change.
        let substantive = self.other_added.len() + self.other_removed.len() + delegated;
        let substantive_fraction = substantive as f64 / zone_size as f64;
        if substantive_fraction >= policy.record_min_fraction
            && substantive >= policy.delegation_min_count
        {
            return Significance::High;
        }

        let _ = changed;
        if delegated >= policy.medium_delegation_min || substantive >= policy.delegation_min_count {
            return Significance::Medium;
        }

        if delegated > 0 || !self.other_added.is_empty() || !self.other_removed.is_empty() {
            return Significance::Low;
        }

        // Only DNSSEC/glue/SOA churn remains.
        Significance::None
    }

    /// A one-line summary for logs and notifications.
    pub fn summary(&self) -> String {
        let mut parts = Vec::new();
        if !self.delegations_added.is_empty() {
            parts.push(format!("+{} delegations", self.delegations_added.len()));
        }
        if !self.delegations_removed.is_empty() {
            parts.push(format!("-{} delegations", self.delegations_removed.len()));
        }
        if !self.delegation_retargeted.is_empty() {
            parts.push(format!(
                "~{} delegations retargeted",
                self.delegation_retargeted.len()
            ));
        }
        if !self.apex_ns_added.is_empty() || !self.apex_ns_removed.is_empty() {
            parts.push(format!(
                "apex NS +{}/-{}",
                self.apex_ns_added.len(),
                self.apex_ns_removed.len()
            ));
        }
        if !self.other_added.is_empty() || !self.other_removed.is_empty() {
            parts.push(format!(
                "other +{}/-{}",
                self.other_added.len(),
                self.other_removed.len()
            ));
        }
        if parts.is_empty() {
            if self.added_total == 0 && self.removed_total == 0 {
                return "no change".to_string();
            }
            parts.push(format!(
                "+{}/-{} records",
                self.added_total, self.removed_total
            ));
        }
        parts.join(", ")
    }
}

/// Split a zone into the comparison buckets used by the diff.
struct Buckets {
    apex_ns: BTreeSet<String>,
    /// owner -> set of NS targets, for non-apex owners.
    delegations: std::collections::BTreeMap<String, BTreeSet<String>>,
    glue: BTreeSet<String>,
    other: BTreeSet<String>,
}

fn bucket(zone: &Zone, ignore: &std::collections::BTreeSet<&str>) -> Buckets {
    let mut buckets = Buckets {
        apex_ns: BTreeSet::new(),
        delegations: Default::default(),
        glue: BTreeSet::new(),
        other: BTreeSet::new(),
    };

    for record in &zone.records {
        let identity = format!("{}\t{}\t{}", record.name, record.rtype, record.rdata);
        if is_dnssec(&record.rtype) {
            continue;
        }
        if is_generation_time(&record.rtype, &record.rdata) {
            continue;
        }
        if ignore.contains(record.rtype.as_str()) {
            continue;
        }
        if record.rtype == "NS" {
            if record.name == zone.origin {
                buckets.apex_ns.insert(record.rdata.clone());
            } else {
                buckets
                    .delegations
                    .entry(record.name.clone())
                    .or_default()
                    .insert(record.rdata.clone());
            }
        } else if (record.rtype == "A" || record.rtype == "AAAA") && record.name != zone.origin {
            buckets.glue.insert(identity);
        } else {
            buckets.other.insert(identity);
        }
    }
    buckets
}

/// Compare two zone snapshots.
pub fn diff(previous: &Zone, current: &Zone) -> ZoneDiff {
    diff_with_policy(previous, current, &DiffPolicy::default())
}

/// Compare two zone snapshots using the supplied policy for ignorable types.
pub fn diff_with_policy(previous: &Zone, current: &Zone, policy: &DiffPolicy) -> ZoneDiff {
    let ignore: std::collections::BTreeSet<&str> =
        policy.ignore_rtypes.iter().map(|s| s.as_str()).collect();
    let old = bucket(previous, &ignore);
    let new = bucket(current, &ignore);

    let mut result = ZoneDiff {
        origin: current.origin.clone(),
        serial_from: previous.soa.serial,
        serial_to: current.soa.serial,
        records_from: previous.records.len(),
        records_to: current.records.len(),
        ..Default::default()
    };

    result.apex_ns_added = new.apex_ns.difference(&old.apex_ns).cloned().collect();
    result.apex_ns_removed = old.apex_ns.difference(&new.apex_ns).cloned().collect();

    let old_names: BTreeSet<&String> = old.delegations.keys().collect();
    let new_names: BTreeSet<&String> = new.delegations.keys().collect();
    result.delegations_added = new_names
        .difference(&old_names)
        .map(|s| (*s).clone())
        .collect();
    result.delegations_removed = old_names
        .difference(&new_names)
        .map(|s| (*s).clone())
        .collect();
    for name in old_names.intersection(&new_names) {
        if old.delegations[*name] != new.delegations[*name] {
            result.delegation_retargeted.push((*name).clone());
        }
    }

    result.glue_changed = old.glue.symmetric_difference(&new.glue).count();
    result.dnssec_changed = previous
        .records
        .iter()
        .filter(|r| is_dnssec(&r.rtype))
        .map(ZoneRecord::line)
        .collect::<BTreeSet<_>>()
        .symmetric_difference(
            &current
                .records
                .iter()
                .filter(|r| is_dnssec(&r.rtype))
                .map(ZoneRecord::line)
                .collect(),
        )
        .count();

    result.other_added = new.other.difference(&old.other).cloned().collect();
    result.other_removed = old.other.difference(&new.other).cloned().collect();

    let is_noise = |r: &ZoneRecord| is_dnssec(&r.rtype) || is_generation_time(&r.rtype, &r.rdata);
    let all_old: BTreeSet<String> = previous
        .records
        .iter()
        .filter(|r| !is_noise(r))
        .map(ZoneRecord::line)
        .collect();
    let all_new: BTreeSet<String> = current
        .records
        .iter()
        .filter(|r| !is_noise(r))
        .map(ZoneRecord::line)
        .collect();
    result.added_total = all_new.difference(&all_old).count();
    result.removed_total = all_old.difference(&all_new).count();

    result.delegations_added.sort();
    result.delegations_removed.sort();
    result.delegation_retargeted.sort();

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zone::{SoaInfo, ZoneRecord};

    fn base() -> Zone {
        let mut records = vec![
            ZoneRecord {
                name: "test.".into(),
                ttl: 3600,
                rtype: "NS".into(),
                rdata: "ns1.test.".into(),
            },
            ZoneRecord {
                name: "test.".into(),
                ttl: 3600,
                rtype: "NS".into(),
                rdata: "ns2.test.".into(),
            },
        ];
        for i in 0..100 {
            records.push(ZoneRecord {
                name: format!("d{i}.test."),
                ttl: 3600,
                rtype: "NS".into(),
                rdata: format!("ns{}.example.", i % 5),
            });
        }
        Zone {
            origin: "test.".into(),
            soa: SoaInfo {
                mname: "ns1.test.".into(),
                rname: "hostmaster.test.".into(),
                serial: 1,
                refresh: 3600,
                retry: 600,
                expire: 604800,
                minimum: 300,
            },
            records,
        }
    }

    #[test]
    fn soa_only_change_is_noise() {
        let previous = base();
        let mut current = base();
        current.soa.serial = 2;
        let d = diff(&previous, &current);
        assert_eq!(d.significance(&DiffPolicy::default()), Significance::None);
    }

    #[test]
    fn dnssec_churn_is_noise() {
        let mut previous = base();
        previous.records.push(ZoneRecord {
            name: "test.".into(),
            ttl: 3600,
            rtype: "RRSIG".into(),
            rdata: "NS 8 1 3600 20300101000000 20200101000000 1234 test. abc".into(),
        });
        let mut current = previous.clone();
        current.records.last_mut().unwrap().rdata =
            "NS 8 1 3600 20310101000000 20210101000000 1234 test. def".into();
        let d = diff(&previous, &current);
        assert_eq!(d.significance(&DiffPolicy::default()), Significance::None);
    }

    #[test]
    fn single_delegation_is_low() {
        let previous = base();
        let mut current = base();
        current.records.push(ZoneRecord {
            name: "new.test.".into(),
            ttl: 3600,
            rtype: "NS".into(),
            rdata: "ns.example.".into(),
        });
        let d = diff(&previous, &current);
        assert_eq!(d.significance(&DiffPolicy::default()), Significance::Low);
    }

    #[test]
    fn many_delegations_is_high() {
        let previous = base();
        let mut current = base();
        for i in 0..40 {
            current.records.push(ZoneRecord {
                name: format!("new{i}.test."),
                ttl: 3600,
                rtype: "NS".into(),
                rdata: "ns.example.".into(),
            });
        }
        let d = diff(&previous, &current);
        assert_eq!(d.significance(&DiffPolicy::default()), Significance::High);
    }

    #[test]
    fn generation_time_txt_is_noise() {
        let mut previous = base();
        previous.records.push(ZoneRecord {
            name: "test.".into(),
            ttl: 3600,
            rtype: "TXT".into(),
            rdata: "\"Generation Time ISO 8601: 2026-01-01 00:00:00\"".into(),
        });
        let mut current = previous.clone();
        current.records.last_mut().unwrap().rdata =
            "\"Generation Time ISO 8601: 2026-01-01 06:00:00\"".into();
        let d = diff(&previous, &current);
        assert_eq!(d.significance(&DiffPolicy::default()), Significance::None);
    }

    #[test]
    fn zonemd_is_noise() {
        let mut previous = base();
        previous.records.push(ZoneRecord {
            name: "test.".into(),
            ttl: 3600,
            rtype: "ZONEMD".into(),
            rdata: "1 1 1 AAAA".into(),
        });
        let mut current = previous.clone();
        current.records.last_mut().unwrap().rdata = "1 1 1 BBBB".into();
        let d = diff(&previous, &current);
        assert_eq!(d.significance(&DiffPolicy::default()), Significance::None);
    }

    #[test]
    fn numeric_dnssec_type_is_noise() {
        let mut previous = base();
        previous.records.push(ZoneRecord {
            name: "test.".into(),
            ttl: 3600,
            rtype: "TYPE48".into(),
            rdata: "257 3 8 AAAA".into(),
        });
        let mut current = previous.clone();
        current.records.last_mut().unwrap().rdata = "257 3 8 BBBB".into();
        let d = diff(&previous, &current);
        assert_eq!(d.significance(&DiffPolicy::default()), Significance::None);
    }

    #[test]
    fn apex_ns_change_is_high() {
        let previous = base();
        let mut current = base();
        for record in &mut current.records {
            if record.name == "test." && record.rtype == "NS" {
                record.rdata = "ns9.test.".into();
            }
        }
        let d = diff(&previous, &current);
        assert_eq!(d.significance(&DiffPolicy::default()), Significance::High);
    }
}
