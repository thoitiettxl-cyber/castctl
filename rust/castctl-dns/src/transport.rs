// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! DNS transports: one DNS exchange against one server
//! (Go `adapter.DNSTransport`, the sing-box side, behind
//! a trait — there is no Rust sing-box yet).

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::error::DnsError;
use crate::server::{DnsServer, DnsServerKind};
use crate::wire::{QTYPE_A, QTYPE_AAAA, decode_message, encode_query};

/// One DNS exchange (Go `adapter.DNSTransport`): a
/// single question against one server. Object-safe (no
/// `async fn` in the trait, so no `async_trait` — the
/// workspace has no such dependency).
pub trait DnsTransport: Send + Sync {
    /// Server tag (Go `DNSTransport.Tag()`).
    fn tag(&self) -> &str;
    /// Exchange one question of the given type and
    /// return its addresses (empty when the server
    /// answers NOERROR with no records, e.g. AAAA for a
    /// v4-only name). NXDOMAIN and other RCODEs are
    /// errors.
    fn exchange(
        &self,
        domain: &str,
        qtype: u16,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<IpAddr>, DnsError>> + Send + '_>>;
}

/// Builds one transport per server (Go
/// `dns.TransportManager.Create`, the `tm.Create` call
/// in `client.go:154-163`).
pub trait DnsTransportFactory: Send + Sync {
    /// Build the transport for `server` (its tag is
    /// already assigned: empty means the index string).
    /// Errors are wrapped by the client as
    /// `dns: create transport %s[%s]: %w`.
    fn create(&self, server: &DnsServer) -> Result<Arc<dyn DnsTransport>, DnsError>;
}

/// DNS over TCP to one server (Go type `"tcp"`): one
/// TCP connection per exchange, 2-byte length-prefixed
/// DNS messages (RFC 1035 §4.2.2). A/AAAA only; the
/// query id comes from a per-transport counter.
pub struct TcpDnsTransport {
    tag: String,
    addr: SocketAddr,
    next_id: AtomicU16,
}

impl TcpDnsTransport {
    /// Build for a resolved server address.
    #[must_use]
    pub fn new(tag: String, addr: SocketAddr) -> Self {
        Self {
            tag,
            addr,
            // Start the id counter from the low bits of
            // the current time so two processes rarely
            // reuse the same first id.
            next_id: AtomicU16::new(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.subsec_nanos() as u16)
                    .unwrap_or(0),
            ),
        }
    }
}

impl DnsTransport for TcpDnsTransport {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn exchange(
        &self,
        domain: &str,
        qtype: u16,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<IpAddr>, DnsError>> + Send + '_>> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let query = encode_query(id, domain, qtype);
        let addr = self.addr;
        Box::pin(async move {
            let mut stream = tokio::net::TcpStream::connect(addr).await?;
            let mut framed = Vec::with_capacity(query.len() + 2);
            framed.extend_from_slice(&(query.len() as u16).to_be_bytes());
            framed.extend_from_slice(&query);
            stream.write_all(&framed).await?;
            let mut len_buf = [0u8; 2];
            stream.read_exact(&mut len_buf).await?;
            let len = u16::from_be_bytes(len_buf) as usize;
            let mut resp = vec![0u8; len];
            stream.read_exact(&mut resp).await?;
            let msg = decode_message(&resp)?;
            if msg.id != id {
                return Err(DnsError::Protocol(format!(
                    "mismatched response id {} (want {id})",
                    msg.id
                )));
            }
            match msg.rcode {
                0 => {}
                3 => return Err(DnsError::NxDomain),
                code => return Err(DnsError::ServerRcode(code)),
            }
            let mut out = Vec::new();
            for ans in &msg.answers {
                match (ans.rtype, ans.rdata.len()) {
                    (QTYPE_A, 4) => {
                        out.push(IpAddr::from([ans.rdata[0], ans.rdata[1], ans.rdata[2], ans.rdata[3]]));
                    }
                    (QTYPE_AAAA, 16) => {
                        let mut b = [0u8; 16];
                        b.copy_from_slice(&ans.rdata);
                        out.push(IpAddr::from(b));
                    }
                    _ => {}
                }
            }
            Ok(out)
        })
    }
}

/// Builds [`TcpDnsTransport`]s for plain TCP servers.
/// TLS / HTTPS / local / hosts / fakeip servers fail
/// closed at construction (`DnsError::Unsupported`):
/// the port refuses to build them rather than silently
/// downgrading to plaintext TCP or to the system
/// resolver.
pub struct TcpTransportFactory;

impl DnsTransportFactory for TcpTransportFactory {
    fn create(&self, server: &DnsServer) -> Result<Arc<dyn DnsTransport>, DnsError> {
        match &server.kind {
            DnsServerKind::Tcp { server, server_port } => {
                let ip: IpAddr = server.parse().map_err(|_| {
                    DnsError::Unsupported(format!(
                        "dns: server {server:?} is not an IP literal after bootstrap"
                    ))
                })?;
                Ok(Arc::new(TcpDnsTransport::new(
                    server.tag.clone(),
                    SocketAddr::new(ip, *server_port),
                )))
            }
            DnsServerKind::Tls { .. } | DnsServerKind::Https { .. } => {
                Err(DnsError::Unsupported(format!(
                    "dns: {} DNS servers are not implemented",
                    server.kind.type_name()
                )))
            }
            DnsServerKind::Local | DnsServerKind::Hosts | DnsServerKind::FakeIp => {
                Err(DnsError::Unsupported(format!(
                    "dns: {} DNS servers are not implemented",
                    server.kind.type_name()
                )))
            }
        }
    }
}
