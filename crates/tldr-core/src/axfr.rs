//! Zone transfer client: AXFR over direct TCP or a SOCKS5 proxy.
//!
//! Port 53 is frequently transparently intercepted by consumer/enterprise
//! networks, which makes zone transfers silently fail with injected REFUSED
//! responses. The transfer client therefore supports an optional SOCKS5 proxy
//! (for example an SSH dynamic forward) so a clean egress path can be used for
//! AXFR while NS discovery still uses DNS-over-HTTPS.

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, Record, RecordType};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::zone::Zone;

static NEXT_ID: AtomicU16 = AtomicU16::new(1);

fn next_id() -> u16 {
    NEXT_ID.fetch_add(1, Ordering::Relaxed)
}

/// How to reach an authoritative server's TCP port 53.
#[derive(Debug, Clone, Default)]
pub enum Transport {
    /// Connect directly to the server.
    #[default]
    Direct,
    /// Connect through a SOCKS5 proxy.
    Socks5 { addr: SocketAddr },
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
pub async fn transfer_axfr(
    origin: &str,
    server: IpAddr,
    transport: &Transport,
    timeout: Duration,
) -> TransferOutcome {
    match tokio::time::timeout(timeout, axfr_inner(origin, server, transport)).await {
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

#[derive(Debug)]
enum Stream {
    Tcp(TcpStream),
    Socks(tokio_socks::tcp::Socks5Stream<TcpStream>),
}

impl Stream {
    async fn connect(server: IpAddr, transport: &Transport) -> Result<Self> {
        let target = SocketAddr::new(server, 53);
        match transport {
            Transport::Direct => Ok(Stream::Tcp(
                TcpStream::connect(target)
                    .await
                    .with_context(|| format!("connecting to {target}"))?,
            )),
            Transport::Socks5 { addr } => Ok(Stream::Socks(
                tokio_socks::tcp::Socks5Stream::connect(*addr, target)
                    .await
                    .with_context(|| format!("connecting to {target} via SOCKS5 {addr}"))?,
            )),
        }
    }
}

impl AsyncRead for Stream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Stream::Tcp(stream) => std::pin::Pin::new(stream).poll_read(cx, buf),
            Stream::Socks(stream) => std::pin::Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Stream::Tcp(stream) => std::pin::Pin::new(stream).poll_write(cx, buf),
            Stream::Socks(stream) => std::pin::Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Stream::Tcp(stream) => std::pin::Pin::new(stream).poll_flush(cx),
            Stream::Socks(stream) => std::pin::Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Stream::Tcp(stream) => std::pin::Pin::new(stream).poll_shutdown(cx),
            Stream::Socks(stream) => std::pin::Pin::new(stream).poll_shutdown(cx),
        }
    }
}

async fn read_message(stream: &mut Stream) -> std::result::Result<Message, AxfrError> {
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

async fn axfr_inner(
    origin: &str,
    server: IpAddr,
    transport: &Transport,
) -> std::result::Result<Zone, AxfrError> {
    let name = Name::from_ascii(crate::zone::fqdn(origin))
        .map_err(|e| AxfrError::Other(format!("invalid zone name: {e}")))?;

    let mut stream = Stream::connect(server, transport)
        .await
        .map_err(|e| AxfrError::Other(e.to_string()))?;

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

/// Resolve a hostname to IP addresses using the system resolver, filtering to
/// usable addresses. Used for authoritative server lookups when DoH is not used.
pub async fn resolve_host(host: &str) -> Result<Vec<IpAddr>> {
    let target = if host.ends_with('.') {
        host.to_string()
    } else {
        format!("{host}.")
    };
    let addrs = tokio::net::lookup_host((target.trim_end_matches('.'), 53))
        .await
        .with_context(|| format!("resolving {host}"))?
        .map(|addr| addr.ip())
        .collect::<Vec<_>>();
    if addrs.is_empty() {
        bail!("no addresses found for {host}");
    }
    Ok(addrs)
}

/// Helper for callers that only need the first address.
pub async fn resolve_one(host: &str) -> Result<IpAddr> {
    resolve_host(host)
        .await?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("no address for {host}"))
}
