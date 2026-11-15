//! Zone discovery: the IANA TLD list and authoritative nameserver resolution.

use std::sync::Arc;

use anyhow::{Context, Result};
use hickory_proto::rr::{Name, RecordType};
use hickory_resolver::config::{NameServerConfig, ResolverConfig};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::TokioResolver;

/// Root servers that have historically served the root zone via AXFR.
pub const ROOT_SERVERS: &[&str] = &[
    "a.root-servers.net.",
    "b.root-servers.net.",
    "c.root-servers.net.",
    "d.root-servers.net.",
    "e.root-servers.net.",
    "f.root-servers.net.",
    "g.root-servers.net.",
    "h.root-servers.net.",
    "i.root-servers.net.",
    "j.root-servers.net.",
    "k.root-servers.net.",
    "l.root-servers.net.",
    "m.root-servers.net.",
];

/// A resolver that speaks DNS-over-HTTPS, so discovery still works on networks
/// that intercept port 53.
pub fn doh_resolver() -> Result<TokioResolver> {
    let config = ResolverConfig::from_name_servers(vec![
        NameServerConfig::https(
            "1.1.1.1".parse().unwrap(),
            Arc::from("cloudflare-dns.com"),
            Some(Arc::from("/dns-query")),
        ),
        NameServerConfig::https(
            "1.0.0.1".parse().unwrap(),
            Arc::from("cloudflare-dns.com"),
            Some(Arc::from("/dns-query")),
        ),
        NameServerConfig::https(
            "8.8.8.8".parse().unwrap(),
            Arc::from("dns.google"),
            Some(Arc::from("/resolve")),
        ),
    ]);
    TokioResolver::builder_with_config(config, TokioRuntimeProvider::default())
        .build()
        .context("building DoH resolver")
}

/// Fetch the IANA list of TLDs (lowercase, without trailing dots).
pub async fn fetch_iana_tlds(client: &reqwest::Client) -> Result<Vec<String>> {
    let text = client
        .get("https://data.iana.org/TLD/tlds-alpha-by-domain.txt")
        .send()
        .await
        .context("requesting IANA TLD list")?
        .error_for_status()
        .context("IANA TLD list returned an error status")?
        .text()
        .await
        .context("reading IANA TLD list body")?;
    let mut tlds = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        tlds.push(line.to_ascii_lowercase());
    }
    Ok(tlds)
}

/// Resolve the authoritative NS names for a zone via DoH.
pub async fn lookup_nameservers(resolver: &TokioResolver, zone: &str) -> Result<Vec<String>> {
    let name = Name::from_ascii(zone).with_context(|| format!("invalid zone name {zone}"))?;
    let lookup = resolver
        .lookup(name, RecordType::NS)
        .await
        .with_context(|| format!("resolving NS for {zone}"))?;
    let mut servers = Vec::new();
    for record in lookup.answers() {
        if record.record_type() == RecordType::NS {
            servers.push(record.data.to_string().to_ascii_lowercase());
        }
    }
    Ok(servers)
}

/// Resolve a hostname's addresses via DoH (A and AAAA).
pub async fn lookup_addresses(
    resolver: &TokioResolver,
    host: &str,
) -> Result<Vec<std::net::IpAddr>> {
    let name = Name::from_ascii(host).with_context(|| format!("invalid host {host}"))?;
    let mut addresses = Vec::new();
    if let Ok(lookup) = resolver.lookup(name.clone(), RecordType::A).await {
        for record in lookup.answers() {
            if let Some(ip) = record.data.ip_addr() {
                addresses.push(ip);
            }
        }
    }
    if let Ok(lookup) = resolver.lookup(name, RecordType::AAAA).await {
        for record in lookup.answers() {
            if let Some(ip) = record.data.ip_addr() {
                addresses.push(ip);
            }
        }
    }
    Ok(addresses)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_server_list_is_complete() {
        assert_eq!(ROOT_SERVERS.len(), 13);
        assert!(ROOT_SERVERS.iter().all(|s| s.ends_with('.')));
    }
}
