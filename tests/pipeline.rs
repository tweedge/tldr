//! End-to-end tests for the archive + diff pipeline using synthetic zones.
//!
//! These do not touch the network; they validate the semantics that matter:
//! storing, reloading, and classifying changes across days.

use chrono::{DateTime, Duration, Utc};
use tldr_core::archive::Archive;
use tldr_core::diff::{diff, DiffPolicy, Significance};
use tldr_core::zone::{SoaInfo, Zone, ZoneRecord};

fn zone(serial: u32, extra: Vec<ZoneRecord>) -> Zone {
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
    records.extend(extra);
    Zone {
        origin: "test.".into(),
        soa: SoaInfo {
            mname: "ns1.test.".into(),
            rname: "hostmaster.test.".into(),
            serial,
            refresh: 3600,
            retry: 600,
            expire: 604800,
            minimum: 3600,
        },
        records,
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

fn delegation(name: &str) -> Vec<ZoneRecord> {
    vec![
        ZoneRecord {
            name: format!("{name}.test."),
            ttl: 3600,
            rtype: "NS".into(),
            rdata: "ns.example.".into(),
        },
        ZoneRecord {
            name: format!("{name}.test."),
            ttl: 3600,
            rtype: "NS".into(),
            rdata: "ns2.example.".into(),
        },
    ]
}

#[test]
fn archive_roundtrip_preserves_zone() {
    let dir = tempfile::tempdir().unwrap();
    let mut archive = Archive::open(dir.path()).unwrap();
    let today = zone(10, delegation("a"));
    let entry = archive
        .record("test.", at(2026, 5, 1), &today, "ns1.test.")
        .unwrap();
    archive.flush().unwrap();

    let reopened = Archive::open(dir.path()).unwrap();
    let stored = reopened.latest("test.").unwrap();
    assert_eq!(stored.digest, entry.digest);
    let text = reopened.get_blob(&stored.digest).unwrap();
    let parsed = Zone::from_text("test.", &text).unwrap();
    let mut expected = today.records.clone();
    expected.sort();
    assert_eq!(parsed.records, expected);
    assert_eq!(parsed.soa.serial, 10);
}

#[test]
fn day_over_day_small_change_is_quiet() {
    let dir = tempfile::tempdir().unwrap();
    let mut archive = Archive::open(dir.path()).unwrap();
    let d1 = at(2026, 5, 1);
    let d2 = at(2026, 5, 2);

    let yesterday = zone(10, delegation("a"));
    archive
        .record("test.", d1, &yesterday, "ns1.test.")
        .unwrap();

    // New day: serial ticks and one delegation is added.
    let today = zone(11, {
        let mut records = delegation("a");
        records.extend(delegation("b"));
        records
    });
    archive.record("test.", d2, &today, "ns1.test.").unwrap();

    let prev = archive.previous("test.", d2).unwrap();
    let prev_zone = Zone::from_text("test.", &archive.get_blob(&prev.digest).unwrap()).unwrap();
    let report = diff(&prev_zone, &today);
    assert_eq!(
        report.significance(&DiffPolicy::default()),
        Significance::Low
    );
}

#[test]
fn day_over_day_mass_change_is_loud() {
    let dir = tempfile::tempdir().unwrap();
    let mut archive = Archive::open(dir.path()).unwrap();
    let d1 = at(2026, 5, 1);
    let d2 = at(2026, 5, 2);

    let mut base = ZoneRecord {
        name: "test.".into(),
        ttl: 3600,
        rtype: "NS".into(),
        rdata: "ns1.test.".into(),
    };
    base.rdata = "ns2.test.".into();
    let yesterday = zone(10, Vec::new());
    archive
        .record("test.", d1, &yesterday, "ns1.test.")
        .unwrap();

    // 50 brand-new delegations on a 2-record zone is a major structural change.
    let mut extras = Vec::new();
    for i in 0..50 {
        extras.extend(delegation(&format!("host{i}")));
    }
    let today = zone(11, extras);
    archive.record("test.", d2, &today, "ns1.test.").unwrap();

    let prev = archive.previous("test.", d2).unwrap();
    let prev_zone = Zone::from_text("test.", &archive.get_blob(&prev.digest).unwrap()).unwrap();
    let report = diff(&prev_zone, &today);
    assert_eq!(
        report.significance(&DiffPolicy::default()),
        Significance::High
    );
}

#[test]
fn retention_prunes_and_keeps_recent() {
    let dir = tempfile::tempdir().unwrap();
    let mut archive = Archive::open(dir.path()).unwrap();
    let now = Utc::now();
    let old = now - Duration::days(45);
    let recent = now - Duration::days(3);

    archive
        .record("old.", old, &zone(1, vec![]), "ns1")
        .unwrap();
    archive
        .record("test.", recent, &zone(2, vec![]), "ns1")
        .unwrap();
    let pruned = archive.prune(30, now).unwrap();
    assert_eq!(pruned, 1);
    assert!(archive.latest("old.").is_none());
    assert!(archive.latest("test.").is_some());
}
