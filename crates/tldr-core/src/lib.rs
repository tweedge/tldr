//! TLDR core: zone transfer, archive, diffing, and discovery building blocks.

pub mod archive;
pub mod axfr;
pub mod diff;
pub mod discovery;
pub mod zone;

pub use archive::{Archive, Manifest, SnapshotEntry};
pub use axfr::{transfer_axfr, TransferOutcome};
pub use diff::{diff, DiffPolicy, Significance, ZoneDiff};
pub use zone::{fqdn, SoaInfo, Zone, ZoneRecord};
