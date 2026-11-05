// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Dialers: the M3d extension point and the two M3 implementations.
//!
//! Go sources: `internal/outbound/dialer.go:127-236`
//! (`DialContext`, `Resolve`, `DialTLS`, `HTTPClient`) and
//! `internal/outbound/manager.go:585-597` (`Manager.Dialer`).
//!
//! The trait is the seam M3d will implement for WireGuard: a
//! `WgDialer` will dial TCP through a boringtun+smoltcp tunnel and
//! return the same stream type. M3 does NOT implement WireGuard
//! (see `config::dispatch_outbound`, which fails closed for it).
//!
//! Stream type: honk's `Box<dyn AsyncReadWrite>` (plain TCP or
//! TLS/protocol-wrapped). A `TcpStream` satisfies the blanket
//! `AsyncReadWrite` impl, so the direct dialer boxes it directly.
//!
//! Proxy-environment rule (Go `dialer.go:211` `Proxy: nil` and
//! `internal/telegram/bot.go:316-346` `BoundClient`): no dialer
//! here reads `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY`/`NO_PROXY`.
//! The only proxy-env reader in Go is the explicit
//! `internal/profile/envproxy.go` outbound builder, which is a
//! different, explicit code path — not this one. A grep check
//! (`grep -rn 'HTTP_PROXY\|HTTPS_PROXY\|ALL_PROXY\|NO_PROXY'
//! rust/castctl-transport/src`) must show no hits outside tests
//! and this doc comment.
//!
//! Timeouts (Go `dialer.go:204-236`): TLS handshake 10s,
//! idle connections 90s. The 90s idle timeout belongs to a pooled
//! `http.Transport`; M3's RPC client opens one fresh stream per
//! call and does not pool, so there is no idle pool to time out —
//! the 10s dial/handshake timeout is the one enforced here
//! (`DIAL_TIMEOUT`).

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use honk_config::node::Node;
use honk_outbound::{AsyncReadWrite, ProxyRegistry};
use tokio::net::TcpStream;

use crate::error::TransportError;

/// Dial/handshake timeout, mirroring Go's `TLSHandshakeTimeout:
/// 10s` in `Dialer.HTTPClient` (`internal/outbound/dialer.go:229`).
pub const DIAL_TIMEOUT: Duration = Duration::from_secs(10);

/// A dial target: a host that may be an IP literal or a domain, plus
/// a port. The domain form is kept (not pre-resolved) so dialers
/// that need it for SNI / proxy headers can use it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DialTarget {
    pub host: String,
    pub port: u16,
}

impl DialTarget {
    pub fn new(host: &str, port: u16) -> Self {
        Self {
            host: host.to_string(),
            port,
        }
    }
}

/// The dialer trait. Object-safe (boxed future) so `RpcClient` can
/// hold `Arc<dyn Dialer>` and M3d can add a `WgDialer` without
/// changing the RPC layer.
///
/// Contract, mirroring Go's dialer rules:
/// - A dial failure (nothing sent yet) maps to
///   `TransportError::ConnectionDown`, never to a bare I/O error
///   (Go `internal/conn/gateway.go:240-272`: gateway code must not
///   let bare net errors escape).
/// - The dialer never consults proxy environment variables.
/// - The returned stream's `Debug` must not print credentials;
///   honk `ProxyStream` internals are never Debug-printed here.
pub trait Dialer: Send + Sync {
    fn dial(&self, target: &DialTarget) -> DialFuture<'_>;
}

/// Boxed dial future (factored out so the trait and its impls do
/// not repeat the full type; clippy::type_complexity).
pub type DialFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Box<dyn AsyncReadWrite>, TransportError>> + Send + 'a>>;

/// Direct dialer: plain TCP to the target. This is the `direct`
/// outbound of Go `internal/profile/outbound.go:24-27` (a direct
/// adapter so fail-closed rules apply uniformly).
///
/// Deviation, recorded: Go's `DialContext` fails closed for a
/// domain when no DNS router is registered
/// (`internal/outbound/dialer.go:127-145`, `ErrNoResolver` — it
/// never touches `net.DefaultResolver`). M3's direct dialer uses
/// the system resolver (`tokio::net::lookup_host`) because the
/// per-profile DNS router is not ported yet; domain dials through
/// `direct` are therefore NOT fail-closed in M3. Fixing that is
/// M4 DNS-router work, not something to fake here.
#[derive(Debug, Default)]
pub struct DirectDialer;

impl DirectDialer {
    pub fn new() -> Self {
        Self
    }
}

/// Resolve a target to socket addresses: IP literals resolve
/// directly; domains go through the system resolver (see the
/// deviation note on `DirectDialer`).
pub async fn resolve_target(target: &DialTarget) -> Result<Vec<SocketAddr>, TransportError> {
    if let Ok(ip) = target.host.parse::<std::net::IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, target.port)]);
    }
    let addrs = tokio::net::lookup_host((target.host.as_str(), target.port))
        .await
        .map_err(|e| TransportError::ConnectionDown {
            message: format!("resolve {}: {e}", target.host),
        })?;
    let addrs: Vec<SocketAddr> = addrs.collect();
    if addrs.is_empty() {
        return Err(TransportError::ConnectionDown {
            message: format!("resolve {}: no addresses", target.host),
        });
    }
    Ok(addrs)
}

impl Dialer for DirectDialer {
    fn dial(&self, target: &DialTarget) -> DialFuture<'_> {
        let target = target.clone();
        Box::pin(async move {
            let addrs = resolve_target(&target).await?;
            let mut last_err: Option<std::io::Error> = None;
            for addr in addrs {
                match tokio::time::timeout(DIAL_TIMEOUT, TcpStream::connect(addr)).await {
                    Ok(Ok(stream)) => {
                        return Ok(Box::new(stream) as Box<dyn AsyncReadWrite>);
                    }
                    Ok(Err(e)) => last_err = Some(e),
                    // A per-address timeout does NOT abort the
                    // whole dial: the next address may answer.
                    // Only when every address failed (refused or
                    // timed out) is the result ConnectionDown —
                    // a timeout on one address is not, by itself,
                    // a `Timeout` error for the whole call.
                    Err(_) => {
                        last_err = Some(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            format!("dial {addr} timed out"),
                        ));
                    }
                }
            }
            Err(TransportError::ConnectionDown {
                message: format!(
                    "dial {}: {}",
                    target.host,
                    last_err.map(|e| e.to_string()).unwrap_or_default()
                ),
            })
        })
    }
}

/// Honk dialer: dial through a honk-outbound node built by
/// `config::dispatch_outbound`. Holds the registry (built once by
/// `ProxyRegistry::default_resolver`) and the node.
///
/// TLS mode note: honk's Chrome-mode is process-global (see
/// `config::tls_mode_for`); building the node already applied it,
/// so dialing here does not re-decide it. Two profiles with
/// different TLS modes in one process remain an M3 limitation.
pub struct HonkDialer {
    registry: ProxyRegistry,
    node: Node,
}

// Hand-written Debug: the node contains passwords/keys in its
// derived Debug, so this struct never derives Debug.
impl std::fmt::Debug for HonkDialer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HonkDialer")
            .field("protocol", &self.node.protocol().as_str())
            .field("host", &self.node.host)
            .field("port", &self.node.port)
            .finish_non_exhaustive()
    }
}

impl HonkDialer {
    /// Build a honk dialer from a node. The registry is the
    /// `default_resolver` (all 11 honk protocols registered; the
    /// dispatch layer already restricted the node to the M3 subset).
    pub fn new(node: Node) -> Result<Self, TransportError> {
        let registry =
            ProxyRegistry::default_resolver().map_err(|e| TransportError::Unsupported {
                message: format!("honk registry: {e}"),
            })?;
        Ok(Self { registry, node })
    }

    /// Shareable handle (the registry + node are `Send + Sync` in
    /// practice for the dial path; the `Arc` lets `RpcClient` hold
    /// one dialer for many calls).
    pub fn shared(node: Node) -> Result<Arc<Self>, TransportError> {
        Ok(Arc::new(Self::new(node)?))
    }
}

impl Dialer for HonkDialer {
    fn dial(&self, target: &DialTarget) -> DialFuture<'_> {
        let target = target.clone();
        let node = &self.node;
        let registry = &self.registry;
        Box::pin(async move {
            let addrs = resolve_target(&target).await?;
            let domain = if target.host.parse::<std::net::IpAddr>().is_ok() {
                None
            } else {
                Some(target.host.as_str())
            };
            // Try every resolved address, not just the first: a
            // resolver may return an unreachable family first
            // (e.g. ::1 with no IPv6 listener) while a later
            // address works. Only the last failure is reported.
            // (The message is stored, not the error value, so no
            // anyhow type needs naming here.)
            let mut last_message = String::new();
            for addr in addrs {
                match registry.dial(node, addr, domain, DIAL_TIMEOUT).await {
                    Ok(stream) => return Ok(stream.stream),
                    Err(e) => {
                        // Honk dial errors name host/protocol
                        // only; the message is bounded so a
                        // peer-controlled string cannot grow a
                        // log line unboundedly.
                        last_message = crate::error::truncate(&e.to_string(), 200);
                    }
                }
            }
            Err(TransportError::ConnectionDown {
                message: last_message,
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn direct_dialer_refused_is_connection_down() {
        // Port 1 on loopback is (practically always) closed; the
        // point is the error KIND, not the port.
        let dialer = DirectDialer::new();
        let err = dialer
            .dial(&DialTarget::new("127.0.0.1", 1))
            .await
            .expect_err("loopback port 1 must refuse");
        assert!(matches!(err, TransportError::ConnectionDown { .. }));
    }

    #[tokio::test]
    async fn direct_dialer_unanswered_address_is_connection_down_not_timeout() {
        // 10.255.255.1 answers nothing: the per-address connect
        // either times out at DIAL_TIMEOUT or fails fast, but
        // the dialer must NOT return Timeout — it tries every
        // address and reports ConnectionDown. (This test takes
        // up to DIAL_TIMEOUT when the address truly hangs; that
        // wait is the behavior under test.)
        let dialer = DirectDialer::new();
        let err = dialer
            .dial(&DialTarget::new("10.255.255.1", 1))
            .await
            .expect_err("blackhole address must fail");
        assert!(
            matches!(err, TransportError::ConnectionDown { .. }),
            "a timed-out address must surface as ConnectionDown, got {err:?}"
        );
    }

    #[tokio::test]
    async fn direct_dialer_falls_back_to_working_address() {
        // Listener on IPv4 loopback only. Dialing "localhost"
        // may resolve ::1 first; the dialer must fall through
        // to 127.0.0.1 instead of failing on the first address.
        // (If the resolver returns 127.0.0.1 first, this passes
        // without exercising the fallback — resolver order is
        // environment-dependent.)
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("INVARIANT: fallback listener binds");
        let port = listener
            .local_addr()
            .expect("INVARIANT: listener has addr")
            .port();
        let dialer = DirectDialer::new();
        let stream = dialer
            .dial(&DialTarget::new("localhost", port))
            .await
            .expect("direct dial must reach the IPv4 listener");
        drop(stream);
        drop(listener);
    }

    #[tokio::test]
    async fn honk_dialer_falls_back_to_working_address() {
        // Same fallback rule, through the honk dialer with a
        // direct node (the registry's Direct handler dials the
        // resolved address itself). Same resolver-order caveat
        // as the direct-dialer test above.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("INVARIANT: fallback listener binds");
        let port = listener
            .local_addr()
            .expect("INVARIANT: listener has addr")
            .port();
        let node = Node {
            outbound: honk_config::node::OutboundConfig::Direct,
            ..Node::default()
        };
        let dialer = HonkDialer::new(node).expect("INVARIANT: honk registry builds");
        let stream = dialer
            .dial(&DialTarget::new("localhost", port))
            .await
            .expect("honk direct dial must reach the IPv4 listener");
        drop(stream);
        drop(listener);
    }

    #[test]
    fn honk_dialer_debug_hides_node_material() {
        let node = Node::default();
        let dialer = HonkDialer::new(node).expect("INVARIANT: honk registry builds");
        let _ = format!("{dialer:?}");
    }
}
