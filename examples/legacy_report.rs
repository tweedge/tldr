//! Compare the legacy (pre-rewrite) dig-format archive against the current
//! archive and print per-zone semantic changes.
//!
//! Usage:
//!   cargo run --example legacy_report -- <legacy_archive_dir> <new_archive_dir>

use std::path::Path;

use anyhow::{Context, Result};
use tldr_core::archive::Archive;
use tldr_core::diff::{diff, DiffPolicy};
use tldr_core::zone::{fqdn, Zone};

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let legacy = args.next().context("missing legacy dir")?;
    let current = args.next().context("missing current dir")?;

    let archive = Archive::open(&current)?;
    let policy = DiffPolicy::default();

    let mut zones: Vec<String> = std::fs::read_dir(&legacy)?
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();
    zones.sort();

    for dir_name in zones {
        let origin = if dir_name == "root" {
            ".".to_string()
        } else {
            fqdn(&dir_name)
        };
        let Some(latest) = archive.latest(&origin) else {
            println!("{origin}: no current snapshot");
            continue;
        };
        let current_text = archive.get_blob(&latest.digest)?;
        let current_zone = Zone::from_text(&origin, &current_text)?;

        let zone_dir = Path::new(&legacy).join(&dir_name);
        let mut best: Option<(String, Zone)> = None;
        for file in std::fs::read_dir(&zone_dir)? {
            let file = file?;
            let text = match std::fs::read_to_string(file.path()) {
                Ok(t) => t,
                Err(_) => continue,
            };
            if let Ok(zone) = Zone::from_text(&origin, &text) {
                let size = zone.records.len();
                if best.as_ref().map(|(_, z)| z.records.len()).unwrap_or(0) < size {
                    best = Some((file.file_name().to_string_lossy().to_string(), zone));
                }
            }
        }
        let Some((server, legacy_zone)) = best else {
            println!("{origin}: legacy unparsable");
            continue;
        };

        let d = diff(&legacy_zone, &current_zone);
        let sig = d.significance(&policy);
        println!(
            "== {} ({server} -> {}): {} -> {} records | significance {}",
            origin,
            latest.server,
            legacy_zone.records.len(),
            current_zone.records.len(),
            sig.as_str()
        );
        println!("   {}", d.summary());
        if !d.apex_ns_added.is_empty() || !d.apex_ns_removed.is_empty() {
            println!(
                "   apex NS: +{:?} -{:?}",
                d.apex_ns_added, d.apex_ns_removed
            );
        }
        if !d.delegations_added.is_empty() {
            let sample: Vec<_> = d.delegations_added.iter().take(5).cloned().collect();
            println!(
                "   delegations added ({}/{}): {:?}",
                d.delegations_added.len(),
                d.delegations_added.len(),
                sample
            );
        }
        if !d.delegations_removed.is_empty() {
            let sample: Vec<_> = d.delegations_removed.iter().take(5).cloned().collect();
            println!(
                "   delegations removed ({}/{}): {:?}",
                d.delegations_removed.len(),
                d.delegations_removed.len(),
                sample
            );
        }
        if !d.delegation_retargeted.is_empty() {
            let sample: Vec<_> = d.delegation_retargeted.iter().take(5).cloned().collect();
            println!(
                "   delegations retargeted ({}/{}): {:?}",
                d.delegation_retargeted.len(),
                d.delegation_retargeted.len(),
                sample
            );
        }
    }
    Ok(())
}
