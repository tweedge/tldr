//! Zone transfer (AXFR) client.
//!
//! TLDR must run on a network with unfiltered DNS egress. Some networks
//! transparently intercept TCP/UDP port 53 and answer AXFR with an injected
//! `REFUSED`, which looks like "the zone is not transferable" when in fact the
//! transfer never reached the authoritative server. There is no in-process
//! workaround for that; deploy TLDR somewhere with a clean path to port 53.

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, Record, RecordType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::zone::Zone;

static NEXT_ID: AtomicU16 = AtomicU16::new(1);

fn next_id() -> u16 {
    NEXT_ID.fetch_add(1, Ordering::Relaxed)
}

/// Outcome of a single zone-transfer attempt.
#[derive(Debug)]
pub enum TransferOutcome {
    /// The transfer succeeded and produced a parsed zone.
    Success(Zone),
    /// The server answered but refused the transfer (typically REFUSED).
    Refused,
    /// The server did not answer or the connection failed.
    Failed(String),
}

/// Attempt an AXFR for `origin` against `server` and return a parsed zone.
pub async fn transfer_axfr(origin: &str, server: IpAddr, timeout: Duration) -> TransferOutcome {
    match tokio::time::timeout(timeout, axfr_inner(origin, server)).await {
        Ok(Ok(zone)) => TransferOutcome::Success(zone),
        Ok(Err(AxfrError::Refused(code))) => {
            tracing::debug!(%origin, %server, ?code, "zone transfer refused");
            TransferOutcome::Refused
        }
        Ok(Err(AxfrError::Other(message))) => TransferOutcome::Failed(message),
        Err(_) => TransferOutcome::Failed("transfer timed out".to_string()),
    }
}

#[derive(Debug)]
enum AxfrError {
    Refused(ResponseCode),
    Other(String),
}

impl std::fmt::Display for AxfrError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AxfrError::Refused(code) => write!(f, "transfer refused with {code}"),
            AxfrError::Other(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for AxfrError {}

async fn read_message(stream: &mut TcpStream) -> std::result::Result<Message, AxfrError> {
    let mut length = [0u8; 2];
    stream
        .read_exact(&mut length)
        .await
        .map_err(|e| AxfrError::Other(format!("reading message length: {e}")))?;
    let length = u16::from_be_bytes(length) as usize;
    if length == 0 {
        return Err(AxfrError::Other("empty DNS message".into()));
    }
    let mut buf = vec![0u8; length];
    stream
        .read_exact(&mut buf)
        .await
        .map_err(|e| AxfrError::Other(format!("reading message body: {e}")))?;
    let message = Message::from_vec(&buf)
        .map_err(|e| AxfrError::Other(format!("decoding DNS message: {e}")))?;
    Ok(message)
}

async fn axfr_inner(origin: &str, server: IpAddr) -> std::result::Result<Zone, AxfrError> {
    let name = Name::from_ascii(crate::zone::fqdn(origin))
        .map_err(|e| AxfrError::Other(format!("invalid zone name: {e}")))?;
    let target = SocketAddr::new(server, 53);
    let mut stream = TcpStream::connect(target)
        .await
        .map_err(|e| AxfrError::Other(format!("connecting to {target}: {e}")))?;

    let mut request = Message::new(next_id(), MessageType::Query, OpCode::Query);
    request.metadata.recursion_desired = false;
    request.add_query(Query::query(name.clone(), RecordType::AXFR));
    let wire = request
        .to_vec()
        .map_err(|e| AxfrError::Other(e.to_string()))?;

    let mut framed = Vec::with_capacity(wire.len() + 2);
    framed.extend_from_slice(&(wire.len() as u16).to_be_bytes());
    framed.extend_from_slice(&wire);
    stream
        .write_all(&framed)
        .await
        .map_err(|e| AxfrError::Other(format!("writing AXFR query: {e}")))?;
    stream
        .flush()
        .await
        .map_err(|e| AxfrError::Other(format!("flushing AXFR query: {e}")))?;

    let mut records: Vec<Record> = Vec::new();
    let mut soa_seen = 0usize;

    loop {
        let message = read_message(&mut stream).await?;
        let code = message.metadata.response_code;
        if code != ResponseCode::NoError {
            if records.is_empty() {
                return Err(AxfrError::Refused(code));
            }
            return Err(AxfrError::Other(format!("transfer aborted with {code}")));
        }
        if message.answers.is_empty() {
            if records.is_empty() {
                return Err(AxfrError::Other("empty AXFR response".into()));
            }
            break;
        }
        for record in &message.answers {
            if record.record_type() == RecordType::SOA {
                soa_seen += 1;
            }
            records.push(record.clone());
        }
        // A complete AXFR is framed by the initial SOA and a closing SOA.
        if soa_seen >= 2 {
            break;
        }
    }

    Zone::from_records(origin, &records).map_err(|e| AxfrError::Other(e.to_string()))
}

/// Resolve a hostname to IP addresses using the system resolver.
pub async fn resolve_host(host: &str) -> Result<Vec<IpAddr>> {
    let target = host.trim_end_matches('.');
    let addrs = tokio::net::lookup_host((target, 53))
        .await
        .with_context(|| format!("resolving {host}"))?
        .map(|addr| addr.ip())
        .collect::<Vec<_>>();
    if addrs.is_empty() {
        bail!("no addresses found for {host}");
    }
    Ok(addrs)
}
