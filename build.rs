//! Stamp a release version into the binary.
//!
//! CI sets `TLDR_VERSION_OVERRIDE` (e.g. `v1.0.0`) when building a tagged
//! release so the binary reports the release tag. Local builds fall back to the
//! version in `Cargo.toml`.

fn main() {
    println!("cargo:rerun-if-env-changed=TLDR_VERSION_OVERRIDE");
    if let Ok(version) = std::env::var("TLDR_VERSION_OVERRIDE") {
        let version = version.trim().trim_start_matches('v');
        if !version.is_empty() {
            println!("cargo:rustc-env=TLDR_VERSION={version}");
        }
    }
}
