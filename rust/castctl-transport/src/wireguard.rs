// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Userspace WireGuard dialer (M3d): boringtun Noise/IK handshake +
//! smoltcp userspace TCP/IP stack on the tunnel.
//!
//! Go sources: `internal/outbound/wireguard_conf.go` (schema, port of
//! sing-box `option/wireguard.go:9-33`), `internal/outbound/manager.go:486-488`
//! (`CreateEndpoint` `system:true` rejection), `internal/profile/dns.go:167-260`
//! (`ResolveProfileDNS`, branch (2) WireGuard DNS), `internal/outbound/dialer.go:127-145`
//! (fail-closed `ErrNoResolver`), and the sing-box v1.14.4
//! `transport/wireguard/endpoint.go` construction rules (key decode,
//! `missing allowed ips`, MTU 1408 default, reserved exactly 3 bytes).
//!
//! The Noise_IKpsk2 key schedule and the TCP state machine are NOT
//! reimplemented here: boringtun owns the handshake/session keys and
//! smoltcp owns TCP/IP. This module only maps castctl config onto
//! those two libraries, drives them from one tokio pump task per
//! dialer, and exposes the result as a `Dialer`.
//!
//! Layout: one `WireGuardDialer` owns one tunnel (one boringtun
//! `Tunn`, one UDP socket to the peer, one smoltcp `Interface`).
//! The pump task is the ONLY code that touches the `Tunn` /
//! `Interface` / sockets; `dial()` and `WgStream` talk to it over
//! bounded channels (see `CtrlMsg`). No `unsafe` in this file.
//!
//! Key rules (each pinned by a test in this file or in
//! `tests/wireguard.rs`):
//! - `system:true` is rejected (Go runtime text verbatim).
//! - Keys are `[u8; 32]` after strict Std-base64 decode; key
//!   material never appears in any `Display`/`Debug`/error string.
//! - A domain peer endpoint fails closed at first dial (Go probe:
//!   with no DNS router sing-box NIL-dereferences at
//!   `protocol/wireguard/endpoint.go:117` instead of bootstrapping;
//!   see PORTING.md §M3d). Only `wireguard_dns` SERVER hostnames
//!   bootstrap once via the system resolver (Go `bootstrap.go` rule).
//! - A domain dial target resolves ONLY through `wireguard_dns`
//!   servers inside the tunnel; with no servers it fails closed
//!   (`ConnectionDown`), never via the system resolver.
//! - The dial target must lie inside the peer's `allowed_ips`
//!   (checked before any TCP packet is sent); boringtun enforces
//!   no AllowedIPs itself, so this module does.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, Ordering};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use base64::{Engine, engine::general_purpose::STANDARD as BASE64_STD};
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use bytes::Bytes;
use smoltcp::iface::{Config as IfaceConfig, Interface, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp as smol_tcp;
use smoltcp::socket::udp as smol_udp;
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, Notify, mpsc, oneshot, watch};

use crate::dialer::{DIAL_TIMEOUT, DialFuture, DialTarget, Dialer};
use crate::error::TransportError;

/// sing-box default tunnel MTU (`transport/wireguard/endpoint.go:103-105`:
/// `if options.MTU == 0 { options.MTU = 1408 }`).
pub const WIREGUARD_DEFAULT_MTU: u32 = 1408;

/// WireGuard data overhead per packet (type 4 + sender index 4 +
/// counter 8 + AEAD tag 16 = 32 bytes; `wireguard.com/protocol/`).
/// A UDP datagram carrying an inner IP packet of `mtu` bytes is at
/// most `mtu + 32` bytes; the outer IP/UDP headers ride outside the
/// boringtun buffer.
pub const WIREGUARD_DATA_OVERHEAD: usize = 32;

/// Minimum boringtun output buffer (handshake initiation size,
/// 148 bytes). `Tunn::encapsulate` formats a handshake initiation
/// into the SAME buffer when no session exists yet
/// (`noise/mod.rs:264-267`), so every encapsulate buffer must be
/// at least this big even for a 40-byte SYN — a smaller buffer
/// makes the first packet fail with `Err` instead of queuing.
pub const WIREGUARD_MIN_DATAGRAM: usize = 148;

/// Per-stream channel bounds. `app_to_net` carries at most
/// `WRITE_CHUNK` bytes per message, so the queued total is bounded
/// at 64 × 16 KiB = 1 MiB; `net_to_app` at 64 × 8 KiB = 512 KiB.
/// Neither queue may grow unboundedly (a slow peer must exert
/// backpressure through the TCP window, not through our memory).
const NET_CHANNEL_CAP: usize = 64;
/// Largest single write accepted per `poll_write` call (partial
/// writes are legal for `AsyncWrite`, so the caller retries).
const WRITE_CHUNK: usize = 16 * 1024;
/// Largest single read chunk the pump moves from smoltcp to a stream.
const READ_CHUNK: usize = 8 * 1024;
/// smoltcp TCP socket buffers (independent of the MTU; they bound
/// in-flight stream data, not the wire packet size).
const SOCKET_BUFFER_SIZE: usize = 64 * 1024;
/// Pump tick cap: the pump never sleeps longer than this without
/// re-driving `update_timers` (keepalive + handshake retransmit).
/// `poll_delay` may ask for longer; the cap is the smaller bound.
const PUMP_TICK_CAP: Duration = Duration::from_millis(100);

/// A CIDR prefix. `std` has no CIDR type, so this stays local (no
/// new dependency). Go: `netip.Prefix` (`option/wireguard.go`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Prefix {
    pub addr: IpAddr,
    pub prefix_len: u8,
}

impl Prefix {
    /// Does this prefix contain `ip`? Family-strict: a v4 target
    /// matches only v4 prefixes, a v6 target only v6 prefixes (Go
    /// `netip.Prefix.Contains` is family-strict the same way).
    pub fn contains(&self, ip: IpAddr) -> bool {
        // Direct construction can set any `prefix_len` (pub
        // fields); an out-of-range length matches nothing
        // instead of underflowing the shift below (debug panic
        // / release wrap).
        match (self.addr, ip) {
            (IpAddr::V4(..), IpAddr::V4(_)) if self.prefix_len > 32 => return false,
            (IpAddr::V6(..), IpAddr::V6(_)) if self.prefix_len > 128 => return false,
            _ => {}
        }
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(addr)) => {
                if self.prefix_len == 0 {
                    return true;
                }
                if self.prefix_len >= 32 {
                    return net == addr;
                }
                let mask = u32::MAX << (32 - self.prefix_len);
                (u32::from(net) & mask) == (u32::from(addr) & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(addr)) => {
                if self.prefix_len == 0 {
                    return true;
                }
                if self.prefix_len >= 128 {
                    return net == addr;
                }
                let mask = u128::MAX << (128 - self.prefix_len);
                (u128::from(net) & mask) == (u128::from(addr) & mask)
            }
            _ => false,
        }
    }
}

/// Parse a CIDR prefix the way sing-box JSON does: `netip.ParsePrefix`
/// ONLY — a bare IP (`"10.0.0.1"`) is rejected here. The bare-IP →
/// `/32`/`/128` rule exists only in castctl's wg-quick converter
/// (`internal/outbound/wireguard_conf.go:247`, `parsePrefixList`),
/// not in the JSON schema. `field` names the config field for the
/// error message.
fn parse_prefix(value: &str, field: &str) -> Result<Prefix, TransportError> {
    let validation = |msg: String| TransportError::Validation { message: msg };
    // Errors name the FIELD only, never the value: a key pasted
    // by mistake into an address/allowed_ips field must not be
    // echoed into an error string.
    let (addr_s, len_s) = value.split_once('/').ok_or_else(|| {
        validation(format!(
            "wireguard {field} is not a CIDR prefix (bare IP addresses are not accepted; use /32 for IPv4 or /128 for IPv6)"
        ))
    })?;
    let addr: IpAddr = addr_s
        .parse()
        .map_err(|_| validation(format!("wireguard {field} is not a valid CIDR prefix")))?;
    let prefix_len: u8 = len_s
        .parse()
        .map_err(|_| validation(format!("wireguard {field} is not a valid CIDR prefix")))?;
    let max = match addr {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    if prefix_len > max {
        return Err(validation(format!(
            "wireguard {field} has a prefix length larger than {max}"
        )));
    }
    Ok(Prefix { addr, prefix_len })
}

/// Strict Std-base64 (RFC 4648 §6, with padding) decode to exactly
/// 32 bytes. Go decodes keys with `base64.StdEncoding`
/// (`transport/wireguard/endpoint.go:49-52`); the `base64` crate's
/// `STANDARD` engine rejects bad characters, bad padding, and
/// non-zero trailing bits (`InvalidLastSymbol`). `field` names the
/// config field for the error message; the key value is never
/// included in any error.
fn decode_key_32(value: &str, field: &str) -> Result<[u8; 32], TransportError> {
    // No whitespace trim: Go's `base64.StdEncoding` rejects
    // surrounding whitespace, so M3d rejects it too.
    let decoded = BASE64_STD
        .decode(value)
        .map_err(|_| TransportError::Validation {
            message: format!("wireguard endpoint {field} is not valid base64"),
        })?;
    decoded.try_into().map_err(|_| TransportError::Validation {
        message: format!("wireguard endpoint {field} must decode to 32 bytes"),
    })
}

/// One WireGuard peer (sing-box `WireGuardPeer`,
/// `option/wireguard.go:25-33`). JSON names are the sing-box
/// spellings (`pre_shared_key`, `persistent_keepalive_interval`,
/// peer `address` + `port`); the wg-quick spellings are rejected
/// at the JSON layer (`dispatch_endpoint`), never here.
#[derive(Clone, PartialEq, Eq)]
pub struct WireGuardPeerConfig {
    /// Peer endpoint host (`address`: IP literal or domain).
    pub endpoint_host: String,
    /// Peer endpoint port (`port`).
    pub endpoint_port: u16,
    /// Peer public key (`public_key`, base64 StdEncoding).
    pub public_key: [u8; 32],
    /// Preshared key (`pre_shared_key`); `None` = absent.
    pub preshared_key: Option<[u8; 32]>,
    /// Allowed IPs (`allowed_ips`, non-empty).
    pub allowed_ips: Vec<Prefix>,
    /// Persistent keepalive seconds (`persistent_keepalive_interval`);
    /// 0 = disabled.
    pub persistent_keepalive: u16,
    /// Reserved bytes (`reserved`); default `[0, 0, 0]`.
    pub reserved: [u8; 3],
}

// Hand-written Debug: keys are byte arrays — a derived Debug would
// print 32 decimal bytes (reconstructable key material).
impl fmt::Debug for WireGuardPeerConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WireGuardPeerConfig")
            .field("endpoint_host", &self.endpoint_host)
            .field("endpoint_port", &self.endpoint_port)
            .field("public_key_len", &32)
            .field("has_preshared_key", &self.preshared_key.is_some())
            .field("allowed_ips_len", &self.allowed_ips.len())
            .field("persistent_keepalive", &self.persistent_keepalive)
            .field("reserved", &self.reserved)
            .finish_non_exhaustive()
    }
}

/// Parsed WireGuard endpoint configuration (typed form of the
/// sing-box endpoint JSON; Go: `internal/profile/outbound.go`
/// `parseEndpoint` + sing-box `option/wireguard.go:9-33`).
#[derive(Clone, PartialEq, Eq)]
pub struct WireGuardConfig {
    /// Endpoint tag (from `"tag"`; used in errors and as the
    /// `wireguard_dns` lookup key). Never a secret.
    pub tag: String,
    /// `system:true` from the endpoint JSON. `WireGuardDialer::new`
    /// rejects it (defence in depth: the config layer
    /// `check_endpoint_wireguard_system` already rejects it at
    /// parse time with the parse-layer text; the dialer enforces
    /// the runtime-layer text, Go `manager.go:486-488`).
    pub system: bool,
    /// Local tunnel addresses (endpoint `"address"`, e.g.
    /// `["10.0.0.2/32"]`). Required, non-empty (Go dial fails
    /// without one: `missing IPv4 local address`,
    /// `transport/wireguard/device_stack.go:113,119`).
    pub address: Vec<Prefix>,
    /// Private key bytes (endpoint `"private_key"`, base64 StdEncoding).
    pub private_key: [u8; 32],
    /// Endpoint MTU (0/absent = 1408, sing-box default).
    pub mtu: u32,
    /// UDP source port (`"listen_port"`); `None` = ephemeral.
    pub listen_port: Option<u16>,
    /// Peers (M3d: exactly one — see `WireGuardDialer::new`).
    pub peers: Vec<WireGuardPeerConfig>,
    /// DNS servers for this endpoint's tag, from top-level
    /// `"wireguard_dns"` (empty = none configured). NOT part of
    /// the endpoint JSON — supplied by the caller.
    pub dns_servers: Vec<String>,
    /// Dial budget; default `DIAL_TIMEOUT` (10 s). Test override only.
    pub dial_timeout: Duration,
}

impl Default for WireGuardConfig {
    fn default() -> Self {
        Self {
            tag: String::new(),
            system: false,
            address: Vec::new(),
            private_key: [0u8; 32],
            mtu: 0,
            listen_port: None,
            peers: Vec::new(),
            dns_servers: Vec::new(),
            dial_timeout: DIAL_TIMEOUT,
        }
    }
}

// Hand-written Debug: same rule as the peer config — lengths and
// presence only, never key bytes.
impl fmt::Debug for WireGuardConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WireGuardConfig")
            .field("tag", &self.tag)
            .field("system", &self.system)
            .field("address_len", &self.address.len())
            .field("private_key_len", &32)
            .field("mtu", &self.mtu)
            .field("listen_port", &self.listen_port)
            .field("peers_len", &self.peers.len())
            .field("dns_servers_len", &self.dns_servers.len())
            .field("dial_timeout", &self.dial_timeout)
            .finish_non_exhaustive()
    }
}

/// Normalised config held by a constructed dialer: every default
/// applied, every rule in `WireGuardDialer::new` already checked.
#[derive(Clone)]
struct EffectiveConfig {
    tag: String,
    address: Vec<Prefix>,
    private_key: [u8; 32],
    /// Effective tunnel MTU (0 in the input means 1408).
    mtu: u32,
    listen_port: Option<u16>,
    peer: WireGuardPeerConfig,
    dns_servers: Vec<String>,
    dial_timeout: Duration,
}

/// Control messages from `dial()` / `WgStream` to the pump task.
/// Data flows on per-stream channels instead (see `OpenTcp`):
/// one shared control channel for all streams keeps the pump's
/// `select!` over a fixed set of sources.
enum CtrlMsg {
    /// Open a TCP socket through the tunnel. The reply fires when
    /// the socket reaches Established (or fails closed); the
    /// `oneshot` is also the cancellation signal — dropping it
    /// aborts the pending open.
    OpenTcp {
        ip: IpAddr,
        port: u16,
        /// Stream → pump data channel (bounded). The pump owns
        /// the receiver end; the stream keeps the sender.
        data_rx: mpsc::Receiver<Bytes>,
        /// Pump → stream data channel (bounded).
        net_tx: mpsc::Sender<NetMsg>,
        /// Shared write-waker slot (stream stores its waker here
        /// when the data channel is full; the pump wakes it after
        /// draining).
        write_waker: Arc<Mutex<Option<Waker>>>,
        reply: oneshot::Sender<Result<smoltcp::iface::SocketHandle, TransportError>>,
    },
    /// Graceful half-close: the app finished writing; the pump
    /// calls `TcpSocket::close()` (FIN after queued data). The
    /// read side stays open.
    ShutdownWrite {
        handle: smoltcp::iface::SocketHandle,
    },
    /// Drop the socket now (RST). Sent from `WgStream::drop`.
    Close {
        handle: smoltcp::iface::SocketHandle,
    },
    /// Resolve `name` (A record when `qtype == 1`, AAAA when 28)
    /// via `server` through the tunnel.
    DnsQuery {
        server: IpAddr,
        qtype: u16,
        name: String,
        reply: oneshot::Sender<Result<Vec<IpAddr>, TransportError>>,
    },
}

/// Pump → stream messages, in order. `Eof` is sent exactly once,
/// after all queued `Data`; `Failed` likewise ends the stream
/// with a `ConnectionError` instead of a clean EOF.
enum NetMsg {
    Data(Bytes),
    Eof,
    Failed,
}

/// Shared tunnel handle: the pump task's control sender plus the
/// handshake signal and liveness flag. Held by the dialer and by
/// every live `WgStream`; the pump exits when the last handle is
/// dropped (its `ctrl_rx` then returns `None`).
struct Tunnel {
    ctrl_tx: mpsc::Sender<CtrlMsg>,
    /// Wakes the pump promptly when a stream queued data.
    kick: Arc<Notify>,
    /// `true` once boringtun reports a session established
    /// (`time_since_last_handshake().is_some()`).
    handshake: watch::Receiver<bool>,
    /// Set by the pump when it exits fatally (UDP/tunnel error);
    /// the dialer rebuilds the tunnel on the next dial.
    dead: Arc<AtomicBool>,
    /// Abort handle for the pump task (last `Arc<Tunnel>` drop
    /// aborts the pump; see `Drop`).
    abort: tokio::task::AbortHandle,
}

impl Drop for Tunnel {
    fn drop(&mut self) {
        // The last handle going away stops the pump (and with it
        // the keepalive timer — no keepalive without a live dialer
        // or stream). Aborting is safe here: the pump only ever
        // awaits at `select!` / channel points.
        self.abort.abort();
    }
}

/// A userspace WireGuard dialer: one tunnel, many TCP streams.
///
/// Construction (`new`) is pure/sync: it validates the config and
/// builds the boringtun key state. It does NOT bind UDP, spawn
/// tasks, or handshake — the tunnel starts lazily on the first
/// `dial()`, where a tokio runtime is guaranteed.
pub struct WireGuardDialer {
    cfg: EffectiveConfig,
    /// Lazily initialised tunnel, shared by all dials/streams.
    tunnel: Mutex<Option<Arc<Tunnel>>>,
    /// Bootstrapped DNS-server hostnames (Go `bootstrap.go` rule:
    /// a DNS server's own hostname resolves once via the system
    /// resolver, before that server can be used). This is the ONLY
    /// system-resolver use in this dialer; dial targets and the
    /// peer endpoint never go through it.
    dns_bootstrap: Mutex<HashMap<String, IpAddr>>,
}

// Hand-written Debug: the config holds key bytes; print the tag
// and peer endpoint only, like `HonkDialer`.
impl fmt::Debug for WireGuardDialer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WireGuardDialer")
            .field("tag", &self.cfg.tag)
            .field("peer_host", &self.cfg.peer.endpoint_host)
            .field("peer_port", &self.cfg.peer.endpoint_port)
            .finish_non_exhaustive()
    }
}

impl WireGuardDialer {
    /// Validate + build from a typed config. Pure/sync: parses keys,
    /// checks rules, applies defaults. Does NOT bind UDP, spawn
    /// tasks, or handshake (no runtime needed here).
    ///
    /// Fail-closed rules (Go citations in the error messages'
    /// doc comments; each pinned by a test):
    /// - `system:true` → `Unsupported`, Go runtime text verbatim
    ///   (`internal/outbound/manager.go:486-488`).
    /// - 0 peers → `Validation` (stricter than Go, which accepts
    ///   0 peers at creation and fails only at dial — a dialer
    ///   with no peer can never dial; see PORTING.md §M3d).
    /// - 2+ peers → `Unsupported` (single-peer only in M3d:
    ///   boringtun `Tunn` is a single-peer state machine).
    /// - non-zero `reserved` → `Unsupported` (boringtun rejects
    ///   non-zero reserved bytes on ingress — verified against
    ///   the 0.7.1 registry source — so patching them would break
    ///   the handshake against any boringtun peer).
    pub fn new(cfg: WireGuardConfig) -> Result<Self, TransportError> {
        if cfg.system {
            return Err(TransportError::Unsupported {
                message: "outbound: wireguard endpoint with system:true is rejected: userspace WireGuard only"
                    .to_string(),
            });
        }
        if cfg.tag.trim().is_empty() {
            return Err(TransportError::Validation {
                message: "endpoint in \"endpoints\" must have a tag".to_string(),
            });
        }
        if cfg.address.is_empty() {
            return Err(TransportError::Validation {
                message: "wireguard endpoint is missing \"address\"".to_string(),
            });
        }
        // A zero private key is the `Default` placeholder, not a
        // key: `new` takes typed bytes, so an all-zero key is the
        // only "missing" shape visible here (the JSON layer
        // rejects an absent/empty `private_key` string first).
        if cfg.private_key == [0u8; 32] {
            return Err(TransportError::Validation {
                message: "wireguard endpoint is missing \"private_key\"".to_string(),
            });
        }
        let mtu = if cfg.mtu == 0 {
            WIREGUARD_DEFAULT_MTU
        } else if cfg.mtu > 65535 {
            return Err(TransportError::Validation {
                message: format!("wireguard mtu {} is too large (maximum 65535)", cfg.mtu),
            });
        } else {
            cfg.mtu
        };
        if cfg.peers.is_empty() {
            return Err(TransportError::Validation {
                message: "wireguard endpoint has no peers".to_string(),
            });
        }
        if cfg.peers.len() > 1 {
            return Err(TransportError::Unsupported {
                message: format!(
                    "wireguard endpoint with {} peers is not supported in M3d (single peer only)",
                    cfg.peers.len()
                ),
            });
        }
        // smoltcp's interface address list is a fixed-capacity
        // array (IFACE_MAX_ADDR_COUNT = 8 in smoltcp 0.14.0,
        // `lib.rs:157`); it silently drops a 9th address, so the
        // dialer rejects longer lists fail-closed here.
        if cfg.address.len() > 8 {
            return Err(TransportError::Validation {
                message: "wireguard endpoint \"address\" has more than 8 entries (smoltcp interface limit)".to_string(),
            });
        }
        let peer = match cfg.peers.into_iter().next() {
            Some(p) => p,
            // Unreachable: the check above rejects 0 peers.
            None => {
                return Err(TransportError::Validation {
                    message: "wireguard endpoint requires exactly one peer".to_string(),
                });
            }
        };
        if peer.public_key == [0u8; 32] {
            return Err(TransportError::Validation {
                message: "wireguard peer 1 is missing \"public_key\"".to_string(),
            });
        }
        if peer.endpoint_host.trim().is_empty() {
            return Err(TransportError::Validation {
                message: "wireguard peer 1 is missing \"address\"".to_string(),
            });
        }
        if peer.endpoint_port == 0 {
            return Err(TransportError::Validation {
                message: "wireguard peer 1 is missing \"port\"".to_string(),
            });
        }
        if peer.allowed_ips.is_empty() {
            return Err(TransportError::Validation {
                message: "wireguard peer 1 is missing allowed_ips".to_string(),
            });
        }
        if peer.reserved != [0, 0, 0] {
            return Err(TransportError::Unsupported {
                message: "wireguard peer 1 reserved must be all zeros in M3d (boringtun rejects non-zero reserved bytes on ingress)".to_string(),
            });
        }
        Ok(Self {
            cfg: EffectiveConfig {
                tag: cfg.tag,
                address: cfg.address,
                private_key: cfg.private_key,
                mtu,
                listen_port: cfg.listen_port,
                peer,
                dns_servers: cfg.dns_servers,
                dial_timeout: cfg.dial_timeout,
            },
            tunnel: Mutex::new(None),
            dns_bootstrap: Mutex::new(HashMap::new()),
        })
    }

    /// Shareable handle (mirrors `HonkDialer::shared`).
    pub fn shared(cfg: WireGuardConfig) -> Result<Arc<Self>, TransportError> {
        Ok(Arc::new(Self::new(cfg)?))
    }

    /// Endpoint tag (never a secret; used by `Dispatch`'s Debug).
    pub fn tag(&self) -> &str {
        &self.cfg.tag
    }

    /// Peer endpoint host as configured (IP literal or domain;
    /// never a secret; used by `Dispatch`'s Debug).
    pub fn peer_host(&self) -> &str {
        &self.cfg.peer.endpoint_host
    }

    /// Peer endpoint port (used by `Dispatch`'s Debug).
    pub fn peer_port(&self) -> u16 {
        self.cfg.peer.endpoint_port
    }

    /// The dial target must lie inside the peer's `allowed_ips`
    /// (union, family-strict). Checked before any TCP packet is
    /// sent for this dial — the tunnel may already be up from an
    /// earlier dial; the check is per-target, not per-tunnel.
    fn check_allowed(&self, ip: IpAddr) -> Result<(), TransportError> {
        if self.cfg.peer.allowed_ips.iter().any(|p| p.contains(ip)) {
            Ok(())
        } else {
            Err(TransportError::ConnectionDown {
                message: format!("dial {ip}: not in wireguard allowed_ips"),
            })
        }
    }

    /// Resolve the peer endpoint to a socket address. IP literals
    /// only: a domain peer fails closed (D4 Go probe — with no DNS
    /// router sing-box nil-dereferences at
    /// `protocol/wireguard/endpoint.go:117` instead of
    /// bootstrapping, so Go never resolves a domain peer without
    /// a router; the M3d dialer has no router, only tunnel DNS
    /// that needs the tunnel to be up already).
    fn peer_endpoint(&self) -> Result<SocketAddr, TransportError> {
        match self.cfg.peer.endpoint_host.parse::<IpAddr>() {
            Ok(ip) => Ok(SocketAddr::new(ip, self.cfg.peer.endpoint_port)),
            Err(_) => Err(TransportError::ConnectionDown {
                message: format!(
                    "wireguard peer endpoint {} is a domain: domain peer endpoints are not resolved without a DNS router",
                    self.cfg.peer.endpoint_host
                ),
            }),
        }
    }

    /// Lazily build (or reuse) the tunnel: bind UDP, build the
    /// boringtun `Tunn` + smoltcp `Interface`, spawn the pump.
    async fn ensure_tunnel(&self) -> Result<Arc<Tunnel>, TransportError> {
        {
            let guard = self.tunnel.lock().await;
            if let Some(t) = guard.as_ref()
                && !t.dead.load(Ordering::SeqCst)
            {
                return Ok(Arc::clone(t));
            }
        }
        let peer = self.peer_endpoint()?;
        let bind_addr: SocketAddr = match (self.cfg.listen_port, peer.is_ipv4()) {
            (Some(port), true) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port),
            (Some(port), false) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port),
            (None, true) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            (None, false) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        };
        let udp = UdpSocket::bind(bind_addr)
            .await
            .map_err(|e| TransportError::ConnectionDown {
                message: format!("wireguard udp bind failed: {e}"),
            })?;
        let keepalive = if self.cfg.peer.persistent_keepalive == 0 {
            None
        } else {
            Some(self.cfg.peer.persistent_keepalive)
        };
        let tunn = Tunn::new(
            StaticSecret::from(self.cfg.private_key),
            PublicKey::from(self.cfg.peer.public_key),
            self.cfg.peer.preshared_key,
            keepalive,
            next_tunn_index(),
            None,
        );
        let (ctrl_tx, ctrl_rx) = mpsc::channel::<CtrlMsg>(NET_CHANNEL_CAP);
        let kick = Arc::new(Notify::new());
        let (hs_tx, hs_rx) = watch::channel(false);
        let dead = Arc::new(AtomicBool::new(false));
        let core = PumpCore::new(tunn, &self.cfg, peer, hs_tx, Arc::clone(&dead))?;
        let join = tokio::spawn(pump_loop(udp, core, ctrl_rx, Arc::clone(&kick), peer));
        let tunnel = Arc::new(Tunnel {
            ctrl_tx,
            kick,
            handshake: hs_rx,
            dead,
            abort: join.abort_handle(),
        });
        let mut guard = self.tunnel.lock().await;
        // A concurrent first-dial may have won the race; prefer
        // the existing live tunnel and drop ours (its `Drop`
        // aborts its pump).
        if let Some(existing) = guard.as_ref()
            && !existing.dead.load(Ordering::SeqCst)
        {
            return Ok(Arc::clone(existing));
        }
        *guard = Some(Arc::clone(&tunnel));
        Ok(tunnel)
    }

    /// Wait until boringtun reports a session established, within
    /// the caller's remaining budget (the outer `dial_timeout`
    /// bounds the whole dial; this only observes the signal).
    async fn wait_handshake(tunnel: &Tunnel) {
        let mut rx = tunnel.handshake.clone();
        if *rx.borrow() {
            return;
        }
        // `changed()` resolves when the pump sends `true`; a
        // dropped sender (dead pump) also resolves it with an
        // error, which is fine — the caller re-checks liveness
        // through the next step's failure.
        let _ = rx.changed().await;
    }

    /// Resolve a `wireguard_dns` server entry to an IP: bare IP
    /// (with optional `:port`, default 53) directly; a hostname
    /// bootstraps once via the system resolver (Go `bootstrap.go`
    /// rule) and is cached.
    ///
    /// The port in an entry is IGNORED, Go parity: Go's
    /// `buildWireGuardDNSOptions`
    /// (`internal/profile/dns.go:392-412`) hardcodes
    /// `server_port: 53` for every server regardless of the
    /// entry text, so M3d always queries port 53 (see PORTING
    /// §M3d.5). A hostname carrying a `:port` suffix still
    /// resolves by its hostname part.
    async fn dns_server_ip(&self, entry: &str) -> Result<IpAddr, TransportError> {
        let entry = entry.trim();
        if entry.is_empty() {
            return Err(TransportError::ConnectionDown {
                message: "wireguard_dns has an empty dns server".to_string(),
            });
        }
        if let Ok(addr) = entry.parse::<SocketAddr>() {
            return Ok(addr.ip());
        }
        if let Ok(ip) = entry.parse::<IpAddr>() {
            return Ok(ip);
        }
        // Hostname, optionally with a `:port` suffix (port
        // ignored, see above): strip one trailing `:digits`.
        let host = match entry.rsplit_once(':') {
            Some((h, p))
                if !h.is_empty() && !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) =>
            {
                h
            }
            _ => entry,
        };
        {
            let cache = self.dns_bootstrap.lock().await;
            if let Some(ip) = cache.get(host) {
                return Ok(*ip);
            }
        }
        let mut addrs = tokio::net::lookup_host((host, 53)).await.map_err(|_| {
            TransportError::ConnectionDown {
                message: "wireguard dns server hostname could not be resolved".to_string(),
            }
        })?;
        let found = addrs.next().map(|addr| addr.ip());
        match found {
            Some(ip) => {
                self.dns_bootstrap.lock().await.insert(host.to_string(), ip);
                Ok(ip)
            }
            None => Err(TransportError::ConnectionDown {
                message: "wireguard dns server hostname could not be resolved".to_string(),
            }),
        }
    }

    /// Resolve a domain dial target through the tunnel: A query,
    /// then AAAA if the A query answers nothing. Servers are tried
    /// in order; every failure is `ConnectionDown` (nothing was
    /// sent through the tunnel for this target yet).
    async fn resolve_via_tunnel(
        &self,
        tunnel: &Tunnel,
        host: &str,
    ) -> Result<IpAddr, TransportError> {
        if self.cfg.dns_servers.is_empty() {
            return Err(TransportError::ConnectionDown {
                message: format!(
                    "resolve {host}: no resolver (no wireguard_dns for this endpoint)"
                ),
            });
        }
        // The DNS query itself travels inside the tunnel, so the
        // handshake must be up first.
        Self::wait_handshake(tunnel).await;
        if tunnel.dead.load(Ordering::SeqCst) {
            return Err(TransportError::ConnectionDown {
                message: "wireguard tunnel is down".to_string(),
            });
        }
        for qtype in [1u16, 28u16] {
            for server in &self.cfg.dns_servers {
                let server_ip = match self.dns_server_ip(server).await {
                    Ok(ip) => ip,
                    Err(_) => continue,
                };
                let (reply_tx, reply_rx) = oneshot::channel();
                let sent = tunnel
                    .ctrl_tx
                    .send(CtrlMsg::DnsQuery {
                        server: server_ip,
                        qtype,
                        name: host.to_string(),
                        reply: reply_tx,
                    })
                    .await;
                if sent.is_err() {
                    return Err(TransportError::ConnectionDown {
                        message: "wireguard tunnel is down".to_string(),
                    });
                }
                match reply_rx.await {
                    Ok(Ok(ips)) => {
                        if let Some(ip) = ips.into_iter().next() {
                            return Ok(ip);
                        }
                        // No answer of this type from this server:
                        // try the next server, then the next qtype.
                    }
                    // A hard error from ONE server (dead server,
                    // no socket for its family, send failure) is
                    // NOT the answer: try the next server instead
                    // of failing the whole resolution. (A server
                    // that never answers at all still consumes
                    // the dial timeout — there is no per-query
                    // timeout by design, see PORTING §M3d.5.)
                    Ok(Err(_)) => continue,
                    Err(_) => {
                        return Err(TransportError::ConnectionDown {
                            message: "wireguard tunnel is down".to_string(),
                        });
                    }
                }
            }
        }
        Err(TransportError::ConnectionDown {
            message: format!("resolve {host}: no answer from wireguard dns"),
        })
    }

    /// Resolve a dial target to an IP: literals directly, domains
    /// only via in-tunnel DNS (never the system resolver).
    async fn resolve_target_ip(
        &self,
        tunnel: &Tunnel,
        target: &DialTarget,
    ) -> Result<IpAddr, TransportError> {
        if let Ok(ip) = target.host.parse::<IpAddr>() {
            return Ok(ip);
        }
        self.resolve_via_tunnel(tunnel, &target.host).await
    }

    async fn dial_inner(
        &self,
        target: &DialTarget,
    ) -> Result<Box<dyn honk_outbound::AsyncReadWrite>, TransportError> {
        // IP-literal targets get the allowed-IPs check before any
        // packet is sent; domain targets resolve first (which
        // needs the tunnel up), then the same check runs on the
        // resolved IP before the TCP open.
        let literal_ip = target.host.parse::<IpAddr>().ok();
        if let Some(ip) = literal_ip {
            self.check_allowed(ip)?;
        }
        let tunnel = self.ensure_tunnel().await?;
        let ip = match literal_ip {
            Some(ip) => ip,
            None => {
                let resolved = self.resolve_target_ip(&tunnel, target).await?;
                self.check_allowed(resolved)?;
                resolved
            }
        };
        let (data_tx, data_rx) = mpsc::channel::<Bytes>(NET_CHANNEL_CAP);
        let (net_tx, net_rx) = mpsc::channel::<NetMsg>(NET_CHANNEL_CAP);
        let write_waker: Arc<Mutex<Option<Waker>>> = Arc::new(Mutex::new(None));
        let (reply_tx, reply_rx) = oneshot::channel();
        tunnel
            .ctrl_tx
            .send(CtrlMsg::OpenTcp {
                ip,
                port: target.port,
                data_rx,
                net_tx,
                write_waker: Arc::clone(&write_waker),
                reply: reply_tx,
            })
            .await
            .map_err(|_| TransportError::ConnectionDown {
                message: "wireguard tunnel is down".to_string(),
            })?;
        let handle = reply_rx
            .await
            .map_err(|_| TransportError::ConnectionDown {
                message: "wireguard tunnel is down".to_string(),
            })??;
        Ok(Box::new(WgStream::new(
            handle,
            Arc::clone(&tunnel),
            tunnel.ctrl_tx.clone(),
            data_tx,
            Arc::clone(&tunnel.kick),
            write_waker,
            net_rx,
        )))
    }
}

/// Caller-supplied boringtun session-index seed. boringtun applies
/// `index << 8` internally; its own tests pass random `u32`s. A
/// process-wide atomic counter seeded from wall time is enough —
/// the index only needs to differ between tunnels in one process
/// (no crypto role: the session keys come from the Noise handshake).
static TUNN_INDEX: AtomicU32 = AtomicU32::new(0);

fn next_tunn_index() -> u32 {
    use std::sync::OnceLock;
    static SEED: OnceLock<u32> = OnceLock::new();
    let seed = *SEED.get_or_init(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0x9e3779b9)
    });
    TUNN_INDEX
        .fetch_add(1, Ordering::Relaxed)
        .wrapping_add(seed)
}

/// Next ephemeral source port (IANA range 49152–65535), for the
/// TCP sockets' local ports and the in-tunnel DNS sockets.
/// Process-wide counter: two dialers in one process must not
/// take the same port on their interfaces. Wraps back to 49152
/// after 65535; callers that can retry do, so a wrap collision
/// is a retry, not a failure.
///
/// NOTE: smoltcp 0.14's `TcpSocket::connect` does NOT assign an
/// ephemeral port — a local port of 0 is
/// `Err(ConnectError::Unaddressable)` (`socket/tcp.rs:1032-1034`);
/// the same holds for UDP `bind` (`socket/udp.rs:219-221`). The
/// dialer must always supply a real port from this counter.
static EPHEMERAL_PORT_NEXT: AtomicU16 = AtomicU16::new(49152);

/// Pure transition for the ephemeral-port counter: given the
/// stored value, the port to hand out and the value to store
/// next. The counter wraps 65535 → 49152; a stored value outside
/// the IANA range (only reachable right after the u16 wrap, see
/// below) restarts at 49152. Unit-tested directly — the old code
/// did the out-of-range reset with a racy load/store pair, so
/// two threads racing at the wrap both stored 49153 and both
/// returned 49152.
fn next_ephemeral_port_transition(stored: u16) -> (u16, u16) {
    if (49152..=65535).contains(&stored) {
        let next = if stored == 65535 { 49152 } else { stored + 1 };
        (stored, next)
    } else {
        (49152, 49153)
    }
}

fn next_ephemeral_port() -> u16 {
    // CAS loop: the load/compute/store is one atomic step, so
    // two threads can never observe the same out-of-range value
    // and hand out the same port.
    loop {
        let current = EPHEMERAL_PORT_NEXT.load(Ordering::Relaxed);
        let (port, next) = next_ephemeral_port_transition(current);
        match EPHEMERAL_PORT_NEXT.compare_exchange(
            current,
            next,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => return port,
            Err(_) => continue,
        }
    }
}

impl Dialer for WireGuardDialer {
    fn dial(&self, target: &DialTarget) -> DialFuture<'_> {
        let target = target.clone();
        // `dial_inner` borrows `self` for the whole dial; the
        // future must own the dialer, so callers hold the dialer
        // behind an `Arc` (as `RpcClient` does for every dialer).
        // The trait takes `&self`, so this body cannot move `self`
        // in — instead the future borrows `self` for `'a`, which
        // is exactly what `DialFuture<'a>` expresses.
        Box::pin(async move {
            let result =
                tokio::time::timeout(self.cfg.dial_timeout, self.dial_inner(&target)).await;
            match result {
                Ok(r) => r,
                Err(_) => Err(TransportError::ConnectionDown {
                    message: "wireguard dial timed out".to_string(),
                }),
            }
        })
    }
}

/// A TCP stream through the tunnel: `tokio::AsyncRead +
/// AsyncWrite` over the pump's channels, so hyper can drive it
/// exactly like a `TcpStream`.
pub struct WgStream {
    handle: smoltcp::iface::SocketHandle,
    /// The tunnel this stream runs on. Holding the `Arc` keeps
    /// the pump alive while any stream lives: dropping the
    /// dialer must NOT kill live streams (the `Dialer` trait
    /// promises nothing about the dialer outliving its
    /// streams, and `DirectDialer`/`HonkDialer` streams
    /// survive dialer drop). The pump stops only when the last
    /// `Arc<Tunnel>` — dialer's plus every live stream's —
    /// drops.
    #[allow(dead_code)] // Held, never read: keeping the `Arc`
    // alive IS the use (it keeps the pump task running).
    tunnel: Arc<Tunnel>,
    /// Plain control sender (used by `Drop` for `Close`).
    ctrl_tx: mpsc::Sender<CtrlMsg>,
    /// Data sender (stream → pump). `try_send` + the shared
    /// waker slot implement backpressure without a `PollSender`
    /// (tokio 1.48 has none in `mpsc`).
    data_tx: mpsc::Sender<Bytes>,
    kick: Arc<Notify>,
    write_waker: Arc<Mutex<Option<Waker>>>,
    net_rx: mpsc::Receiver<NetMsg>,
    /// Leftover bytes from a partially-consumed `Data` chunk.
    read_buf: Bytes,
    read_pos: usize,
    /// The app called `poll_shutdown` and the FIN was queued.
    write_shutdown: bool,
    /// The peer's FIN was delivered (`Eof` seen).
    read_eof: bool,
}

impl WgStream {
    fn new(
        handle: smoltcp::iface::SocketHandle,
        tunnel: Arc<Tunnel>,
        ctrl_tx: mpsc::Sender<CtrlMsg>,
        data_tx: mpsc::Sender<Bytes>,
        kick: Arc<Notify>,
        write_waker: Arc<Mutex<Option<Waker>>>,
        net_rx: mpsc::Receiver<NetMsg>,
    ) -> Self {
        Self {
            handle,
            tunnel,
            ctrl_tx,
            data_tx,
            kick,
            write_waker,
            net_rx,
            read_buf: Bytes::new(),
            read_pos: 0,
            write_shutdown: false,
            read_eof: false,
        }
    }
}

// Hand-written Debug: a stream holds no secrets, but keep the
// shape minimal (handle only) so no channel internals leak.
impl fmt::Debug for WgStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WgStream")
            .field("handle", &self.handle)
            .finish_non_exhaustive()
    }
}

impl Drop for WgStream {
    fn drop(&mut self) {
        // Best-effort: if the control channel is full the pump
        // still notices the drop — it checks `net_tx.is_closed()`
        // every cycle (the receiver end lives in this stream).
        let _ = self.ctrl_tx.try_send(CtrlMsg::Close {
            handle: self.handle,
        });
    }
}

impl AsyncRead for WgStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.read_pos < self.read_buf.len() {
            let rest = &self.read_buf[self.read_pos..];
            let n = rest.len().min(buf.remaining());
            buf.put_slice(&rest[..n]);
            self.read_pos += n;
            if self.read_pos >= self.read_buf.len() {
                self.read_buf = Bytes::new();
                self.read_pos = 0;
            }
            return Poll::Ready(Ok(()));
        }
        if self.read_eof {
            return Poll::Ready(Ok(()));
        }
        match self.net_rx.poll_recv(cx) {
            Poll::Ready(Some(NetMsg::Data(chunk))) => {
                let n = chunk.len().min(buf.remaining());
                buf.put_slice(&chunk[..n]);
                if n < chunk.len() {
                    self.read_buf = chunk;
                    self.read_pos = n;
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Some(NetMsg::Eof)) => {
                self.read_eof = true;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Some(NetMsg::Failed)) => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionReset,
                "wireguard tunnel connection failed",
            ))),
            Poll::Ready(None) => {
                // The pump dropped the sender WITHOUT sending
                // Eof/Failed: the pump died (fatal tunnel error
                // with a full channel, or an aborted pump). That
                // is a connection failure, not a clean EOF — the
                // clean paths always send Eof or Failed before
                // the sender is dropped.
                Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionReset,
                    "wireguard tunnel connection failed",
                )))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for WgStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if self.write_shutdown {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "wireguard stream is shut down for writing",
            )));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let n = buf.len().min(WRITE_CHUNK);
        match self.data_tx.try_send(Bytes::copy_from_slice(&buf[..n])) {
            Ok(()) => {
                // Wake the pump promptly (it may be sleeping on
                // `poll_delay`); the pump drains the channel on
                // its next cycle regardless.
                self.kick.notify_one();
                Poll::Ready(Ok(n))
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                // Backpressure: park until the pump drains. The
                // waker slot is shared with the pump, which wakes
                // it after consuming a chunk for this socket.
                // `try_lock` cannot block here (the pump never
                // holds the lock across an await); if it is
                // momentarily held, wake ourselves via the task
                // waker so we retry.
                match self.write_waker.try_lock() {
                    Ok(mut slot) => {
                        *slot = Some(cx.waker().clone());
                    }
                    Err(_) => {
                        cx.waker().wake_by_ref();
                    }
                }
                Poll::Pending
            }
            Err(mpsc::error::TrySendError::Closed(_)) => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionReset,
                "wireguard tunnel is down",
            ))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        // Bytes are handed to the pump synchronously by the
        // channel; there is no user-space write buffer to flush.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        if self.write_shutdown {
            return Poll::Ready(Ok(()));
        }
        // The control channel is bounded; if it is full, park on
        // the same waker slot the pump drains (the pump wakes all
        // pending control senders by draining — it processes the
        // control channel every cycle, so a full channel drains
        // within one cycle; register the waker so we are woken
        // rather than spinning).
        match self.ctrl_tx.try_send(CtrlMsg::ShutdownWrite {
            handle: self.handle,
        }) {
            Ok(()) => {
                self.write_shutdown = true;
                Poll::Ready(Ok(()))
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                match self.write_waker.try_lock() {
                    Ok(mut slot) => {
                        *slot = Some(cx.waker().clone());
                    }
                    Err(_) => {
                        cx.waker().wake_by_ref();
                    }
                }
                // Also kick the pump so the control channel drains.
                self.kick.notify_one();
                Poll::Pending
            }
            Err(mpsc::error::TrySendError::Closed(_)) => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionReset,
                "wireguard tunnel is down",
            ))),
        }
    }
}

/// In-memory smoltcp device: the tunnel's IP packets wait in two
/// queues. `receive` hands one queued packet to the interface (plus
/// a dummy transmit token — the interface only uses it if a reply
/// packet is generated, e.g. an ICMP response, which the pump
/// then encapsulates like any other egress packet); `transmit`
/// hands the interface a token to write one egress packet into
/// the tx queue. `Medium::Ip` means raw IP packets, no ARP/NDISC.
struct QueueDevice {
    rx_queue: VecDeque<Vec<u8>>,
    tx_queue: VecDeque<Vec<u8>>,
    mtu: usize,
}

impl QueueDevice {
    fn new(mtu: u32) -> Self {
        Self {
            rx_queue: VecDeque::new(),
            tx_queue: VecDeque::new(),
            mtu: mtu as usize,
        }
    }
}

struct QueueRxToken(Vec<u8>);
/// Transmit token borrowing the device's tx queue. The borrow is
/// the standard smoltcp device pattern: `transmit(&mut self)`
/// hands out a token tied to the `&mut self` borrow, the interface
/// consumes it within the same `poll` call, and nothing else
/// aliases the queue in between (single pump task).
struct QueueTxToken<'a> {
    queue: &'a mut VecDeque<Vec<u8>>,
}

impl RxToken for QueueRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0)
    }
}

impl TxToken for QueueTxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        // The interface only ever asks for at most the MTU; the
        // buffer is sized to the request and the queue stores
        // exactly `len` bytes.
        let mut buf = vec![0u8; len];
        let out = f(&mut buf);
        self.queue.push_back(buf);
        out
    }
}

impl Device for QueueDevice {
    type RxToken<'a> = QueueRxToken;
    type TxToken<'a> = QueueTxToken<'a>;

    fn receive(
        &mut self,
        _timestamp: SmolInstant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let packet = self.rx_queue.pop_front()?;
        Some((
            QueueRxToken(packet),
            QueueTxToken {
                queue: &mut self.tx_queue,
            },
        ))
    }

    fn transmit(&mut self, _timestamp: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(QueueTxToken {
            queue: &mut self.tx_queue,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps
    }
}

// Minimal DNS wire codec (hand-rolled, no new dependency): one
// query (A/AAAA), one response, no CNAME chasing, no EDNS. Go's
// `wireguard_dns` servers are plain UDP/53 servers
// (`internal/profile/dns.go:392-417`, one `udp` server per listed
// address, port 53).

/// Encode a DNS query: standard header (RD set), one question.
fn dns_encode_query(name: &str, qtype: u16, txid: u16) -> Option<Vec<u8>> {
    if name.is_empty() || name.len() > 253 {
        return None;
    }
    let mut out = Vec::with_capacity(name.len() + 18);
    out.extend_from_slice(&txid.to_be_bytes());
    out.extend_from_slice(&0x0100u16.to_be_bytes()); // RD
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    for label in name.trim_end_matches('.').split('.') {
        if label.is_empty()
            || label.len() > 63
            || !label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return None;
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN
    Some(out)
}

/// Read a DNS name at `pos`, following compression pointers.
/// Returns the new position after the name. Names are validated
/// loosely (labels + pointers only); the caller only needs the
/// position, not the name bytes.
fn dns_skip_name(buf: &[u8], mut pos: usize) -> Option<usize> {
    let mut jumped = false;
    let mut next = 0usize;
    let mut steps = 0usize;
    loop {
        steps += 1;
        if steps > 128 || pos >= buf.len() {
            return None;
        }
        let len = buf[pos] as usize;
        if len == 0 {
            return Some(if jumped { next } else { pos + 1 });
        }
        if len & 0xC0 == 0xC0 {
            if pos + 1 >= buf.len() {
                return None;
            }
            let target = ((len & 0x3F) << 8) | buf[pos + 1] as usize;
            if !jumped {
                next = pos + 2;
                jumped = true;
            }
            pos = target;
        } else if len & 0xC0 == 0 {
            pos += 1 + len;
        } else {
            return None;
        }
    }
}

/// Read a DNS name at `pos`, following compression pointers.
/// Returns the canonical (lowercase, dot-joined, no trailing
/// dot) name bytes and the position after the name.
fn dns_read_name(buf: &[u8], mut pos: usize) -> Option<(Vec<u8>, usize)> {
    let mut out = Vec::new();
    let mut jumped = false;
    let mut next = 0usize;
    let mut steps = 0usize;
    loop {
        steps += 1;
        if steps > 128 || pos >= buf.len() {
            return None;
        }
        let len = buf[pos] as usize;
        if len == 0 {
            return Some((out, if jumped { next } else { pos + 1 }));
        }
        if len & 0xC0 == 0xC0 {
            if pos + 1 >= buf.len() {
                return None;
            }
            let target = ((len & 0x3F) << 8) | buf[pos + 1] as usize;
            if !jumped {
                next = pos + 2;
                jumped = true;
            }
            pos = target;
        } else if len & 0xC0 == 0 {
            if pos + 1 + len > buf.len() {
                return None;
            }
            if !out.is_empty() {
                out.push(b'.');
            }
            out.extend(
                buf[pos + 1..pos + 1 + len]
                    .iter()
                    .map(|b| b.to_ascii_lowercase()),
            );
            pos += 1 + len;
        } else {
            return None;
        }
    }
}

/// Parse a DNS response: check the transaction id, QR bit and
/// rcode, the TC (truncated) bit, and that the question section
/// asks for `expected_name` with `qtype`; skip the question
/// section, collect A/AAAA rdata of the requested type. Returns
/// an empty vec when the response carries no answer of that type
/// (the caller then tries the next server / qtype). A CNAME
/// without a matching address record is NOT chased (documented
/// limitation, see PORTING.md §M3d). A truncated response
/// returns `None` (same as "no answer" to the caller — there is
/// no TCP fallback, see PORTING §M3d.5).
fn dns_parse_response(
    buf: &[u8],
    txid: u16,
    qtype: u16,
    expected_name: &str,
) -> Option<Vec<IpAddr>> {
    if buf.len() < 12 {
        return None;
    }
    let id = u16::from_be_bytes([buf[0], buf[1]]);
    if id != txid {
        return None;
    }
    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    if flags & 0x8000 == 0 || flags & 0x000F != 0 {
        return None; // not a response, or an error rcode
    }
    if flags & 0x0200 != 0 {
        return None; // truncated: no usable answer, no TCP fallback
    }
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let ancount = u16::from_be_bytes([buf[6], buf[7]]) as usize;
    let expected = expected_name.trim_end_matches('.').to_ascii_lowercase();
    let mut pos = 12usize;
    for qi in 0..qdcount {
        let (name, after) = dns_read_name(buf, pos)?;
        if qi == 0 && name != expected.as_bytes() {
            return None; // response is for a different question
        }
        pos = after;
        if pos + 4 > buf.len() {
            return None;
        }
        let q_qtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        if qi == 0 && q_qtype != qtype {
            return None; // response is for a different qtype
        }
        pos += 4;
    }
    let mut out = Vec::new();
    for _ in 0..ancount {
        pos = dns_skip_name(buf, pos)?;
        if pos + 10 > buf.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let rdlen = u16::from_be_bytes([buf[pos + 8], buf[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlen > buf.len() {
            return None;
        }
        if rtype == qtype {
            match (qtype, rdlen) {
                (1, 4) => out.push(IpAddr::V4(Ipv4Addr::new(
                    buf[pos],
                    buf[pos + 1],
                    buf[pos + 2],
                    buf[pos + 3],
                ))),
                (28, 16) => {
                    let mut b = [0u8; 16];
                    b.copy_from_slice(&buf[pos..pos + 16]);
                    out.push(IpAddr::V6(Ipv6Addr::from(b)));
                }
                _ => {}
            }
        }
        pos += rdlen;
    }
    Some(out)
}

/// Per-socket pump state for one TCP stream.
struct SockState {
    /// Stream → pump data channel.
    data_rx: mpsc::Receiver<Bytes>,
    /// Pump → stream channel.
    net_tx: mpsc::Sender<NetMsg>,
    /// Shared write-waker slot (see `WgStream::poll_write`).
    write_waker: Arc<Mutex<Option<Waker>>>,
    /// `Some` until the socket reaches Established (or fails).
    pending_open: Option<oneshot::Sender<Result<smoltcp::iface::SocketHandle, TransportError>>>,
    eof_sent: bool,
    /// The app asked for a graceful close (FIN sent).
    shutdown_sent: bool,
    /// The app asked for a graceful close, but data was still
    /// queued: the FIN is deferred until the queue drains.
    /// Closing immediately would stall the queued data forever:
    /// after `close()` smoltcp's `may_send()` is false, so the
    /// send loop below refuses to feed anything more into the
    /// socket (found by the EOF-after-full-channel test —
    /// shutdown right after a large write sent almost nothing).
    shutdown_pending: bool,
    peer_fin_seen: bool,
    /// Partially-sent chunk + offset (smoltcp `send_slice` may
    /// write fewer bytes than offered).
    pending_tx: Option<(Bytes, usize)>,
    /// Chunk already consumed from smoltcp by `recv_slice`
    /// (TCP-ACKed — the peer will NEVER retransmit it) that
    /// could not be delivered because `net_tx` was full.
    /// Retried on every cycle before any new `recv_slice`;
    /// NEVER dropped. Dropping it would punch a hole in the
    /// byte stream with no error (the loop-1 bug: the old code
    /// `break`s on `Full` and the chunk fell out of scope).
    pending_rx: Option<Bytes>,
    /// The peer's FIN was seen but `Eof` could not be
    /// delivered yet (channel full). Retried every cycle;
    /// `eof_sent` is set ONLY when the `Eof` actually lands —
    /// never before, or the stream hangs on `Pending` forever.
    pending_eof: bool,
    /// Same treatment for `Failed` (socket closed without FIN).
    pending_failed: bool,
    /// The smoltcp socket is gone (Closed state cleaned up)
    /// but undelivered messages remain; the state survives in
    /// the map until they land, then it is removed.
    socket_gone: bool,
    /// Set when this cycle drained data for this socket (drives
    /// the write-waker wakeup at the end of the cycle).
    data_drained: bool,
}

/// One outstanding in-tunnel DNS query: the reply channel plus
/// what the response must match (question name, qtype, and the
/// server it was sent to — a reply from any other source is
/// ignored, not parsed).
struct PendingDns {
    reply: oneshot::Sender<Result<Vec<IpAddr>, TransportError>>,
    name: String,
    qtype: u16,
    server: IpAddr,
}

/// First DNS transaction id for a new pump core: seeded from
/// wall time (plus a process-wide counter so two cores started
/// in the same nanosecond still differ). The old code started
/// every core at txid 1 — predictable; inside an authenticated
/// tunnel that is only defense-in-depth, but the seed is free.
static DNS_TXID_COUNTER: AtomicU16 = AtomicU16::new(0);

fn next_dns_txid_start() -> u16 {
    use std::sync::OnceLock;
    static SEED: OnceLock<u16> = OnceLock::new();
    let seed = *SEED.get_or_init(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| (d.as_nanos() as u16) ^ ((d.as_nanos() >> 16) as u16))
            .unwrap_or(0x5eed)
    });
    let start = seed.wrapping_add(DNS_TXID_COUNTER.fetch_add(1, Ordering::Relaxed));
    if start == 0 { 1 } else { start }
}
struct PumpCore {
    tunn: Tunn,
    device: QueueDevice,
    iface: Interface,
    sockets: SocketSet<'static>,
    /// Live TCP sockets by handle.
    tcp: HashMap<smoltcp::iface::SocketHandle, SockState>,
    /// DNS sockets by family (created lazily on first query).
    dns_v4: Option<smoltcp::iface::SocketHandle>,
    dns_v6: Option<smoltcp::iface::SocketHandle>,
    /// Outstanding DNS queries by transaction id.
    pending_dns: HashMap<u16, PendingDns>,
    dns_txid: u16,
    peer: SocketAddr,
    /// Max inner IP packet size (= config MTU).
    mtu: usize,
    /// First tunnel address per family. The DNS sockets bind to
    /// these (not 0.0.0.0): smoltcp's UDP egress sends with the
    /// BOUND address as the source, so a 0.0.0.0-bound socket
    /// emits queries with source 0.0.0.0 and no reply can ever
    /// come back (observed in the DNS test, 2026-11-05).
    v4_addr: Option<Ipv4Addr>,
    v6_addr: Option<Ipv6Addr>,
    handshake_tx: watch::Sender<bool>,
    handshake_done: bool,
    dead: Arc<AtomicBool>,
    /// Sockets aborted in the previous cycle, whose RST the
    /// poll at the top of this cycle emitted: retired at the
    /// end of this cycle (see `abort_socket`).
    closing_prev: HashSet<smoltcp::iface::SocketHandle>,
    /// Sockets aborted in this cycle: promoted to
    /// `closing_prev` at the end of the cycle.
    closing_next: HashSet<smoltcp::iface::SocketHandle>,
    /// Wall-clock base for smoltcp time (millis since pump start).
    started: std::time::Instant,
    last_timers: std::time::Instant,
}

/// Outcome of `PumpCore::flush_pending` (see its docs).
enum PendingFlush {
    /// Nothing pending, or everything pending landed.
    Delivered,
    /// The channel is still full; retry next cycle.
    Blocked,
    /// The stream is gone; drop the state.
    StreamGone,
}

impl PumpCore {
    /// Build the core. `cfg` is the dialer's normalised config
    /// (already validated by `WireGuardDialer::new`).
    fn new(
        tunn: Tunn,
        cfg: &EffectiveConfig,
        peer: SocketAddr,
        handshake_tx: watch::Sender<bool>,
        dead: Arc<AtomicBool>,
    ) -> Result<Self, TransportError> {
        let mut device = QueueDevice::new(cfg.mtu);
        let mut iface = Interface::new(
            IfaceConfig::new(HardwareAddress::Ip),
            &mut device,
            SmolInstant::from_millis(0),
        );
        // smoltcp's interface address list is a fixed-capacity
        // array (IFACE_MAX_ADDR_COUNT = 8 in smoltcp 0.14.0);
        // `WireGuardDialer::new` rejects longer lists, so every
        // push below succeeds.
        let addrs = cfg.address.clone();
        iface.update_ip_addrs(|list| {
            for p in &addrs {
                let cidr = IpCidr::new(IpAddress::from(p.addr), p.prefix_len);
                let _ = list.push(cidr);
            }
        });
        // Default routes: for Medium::Ip the gateway value is
        // inert — `dispatch_ip` never consults a neighbour cache
        // for this medium, it emits the IP packet to the device
        // as-is — so the first tunnel address of each family
        // serves as the placeholder gateway. The route only
        // needs to EXIST so `route()` finds the destination.
        let mut v4_gw = None;
        let mut v6_gw = None;
        for p in &cfg.address {
            match p.addr {
                IpAddr::V4(a) if v4_gw.is_none() => v4_gw = Some(a),
                IpAddr::V6(a) if v6_gw.is_none() => v6_gw = Some(a),
                _ => {}
            }
        }
        if let Some(gw) = v4_gw {
            let _ = iface.routes_mut().add_default_ipv4_route(gw);
        }
        if let Some(gw) = v6_gw {
            let _ = iface.routes_mut().add_default_ipv6_route(gw);
        }
        Ok(Self {
            tunn,
            device,
            iface,
            sockets: SocketSet::new(vec![]),
            tcp: HashMap::new(),
            dns_v4: None,
            dns_v6: None,
            pending_dns: HashMap::new(),
            dns_txid: next_dns_txid_start(),
            peer,
            mtu: cfg.mtu as usize,
            // The first tunnel address of each family doubles as
            // the default-route gateway placeholder (inert for
            // Medium::Ip) AND the DNS sockets' bind address.
            v4_addr: v4_gw,
            v6_addr: v6_gw,
            handshake_tx,
            handshake_done: false,
            dead,
            closing_prev: HashSet::new(),
            closing_next: HashSet::new(),
            started: std::time::Instant::now(),
            last_timers: std::time::Instant::now(),
        })
    }

    fn now(&self) -> SmolInstant {
        SmolInstant::from_millis(self.started.elapsed().as_millis() as i64)
    }

    /// `poll_delay` capped by the pump tick: the pump never
    /// sleeps longer than `PUMP_TICK_CAP` without re-driving
    /// `update_timers`.
    fn next_delay(&mut self) -> Duration {
        let d = self
            .iface
            .poll_delay(self.now(), &self.sockets)
            .map(|d| Duration::from_millis(d.total_millis()))
            .unwrap_or(PUMP_TICK_CAP);
        d.min(PUMP_TICK_CAP)
    }

    /// Mark the tunnel dead and fail everything pending. The
    /// pump exits after this; the dialer rebuilds on next dial.
    fn fatal(&mut self, message: &str) {
        self.dead.store(true, Ordering::SeqCst);
        for (_, mut st) in self.tcp.drain() {
            if let Some(reply) = st.pending_open.take() {
                let _ = reply.send(Err(TransportError::ConnectionDown {
                    message: message.to_string(),
                }));
            }
            let _ = st.net_tx.try_send(NetMsg::Failed);
        }
        for (_, pending) in self.pending_dns.drain() {
            let _ = pending.reply.send(Err(TransportError::ConnectionDown {
                message: message.to_string(),
            }));
        }
    }

    /// Feed one UDP datagram from the peer through boringtun.
    /// A bad datagram (garbage, truncated, replayed, wrong key)
    /// is DROPPED, never fatal: boringtun returns
    /// `TunnResult::Err` for it (`parse_incoming_packet`,
    /// `noise/mod.rs:128`, verified against the 0.7.1 registry
    /// source on cue), and WireGuard semantics drop invalid
    /// packets — one spoofed datagram must not kill every live
    /// stream. Returns `Err` only on a fatal tunnel error
    /// (none from decapsulation today; the signature is kept
    /// for the egress side).
    fn handle_udp(&mut self, datagram: &[u8], send: &mut dyn FnMut(&[u8])) -> Result<(), String> {
        // Drive the datagram through decapsulate, repeating with
        // an empty datagram until `Done` (boringtun's contract:
        // handshake responses and queued packets flush this way).
        let mut next: Option<Vec<u8>> = Some(datagram.to_vec());
        let mut wg_buf = vec![0u8; self.mtu + WIREGUARD_DATA_OVERHEAD];
        loop {
            let result = match &next {
                Some(d) => self.tunn.decapsulate(Some(self.peer.ip()), d, &mut wg_buf),
                None => self.tunn.decapsulate(None, &[], &mut wg_buf),
            };
            next = None;
            match result {
                TunnResult::Done => break,
                TunnResult::WriteToNetwork(bytes) => {
                    send(bytes);
                }
                TunnResult::WriteToTunnelV4(bytes, _) | TunnResult::WriteToTunnelV6(bytes, _) => {
                    self.device.rx_queue.push_back(bytes.to_vec());
                }
                TunnResult::Err(_) => {
                    // Drop this datagram and stop draining it:
                    // nothing it carried was valid, and the
                    // empty-datagram repeat would only re-drive
                    // the same failure. The tunnel and all live
                    // streams survive.
                    break;
                }
            }
        }
        Ok(())
    }

    /// Send one inner IP packet through boringtun to the peer.
    /// Returns `Err` only on a fatal tunnel error.
    fn send_ip_packet(&mut self, packet: &[u8], send: &mut dyn FnMut(&[u8])) -> Result<(), String> {
        // At least WIREGUARD_MIN_DATAGRAM: with no session yet
        // `encapsulate` formats a 148-byte handshake initiation
        // into this same buffer (see the const's docs).
        let mut wg_buf =
            vec![0u8; (packet.len() + WIREGUARD_DATA_OVERHEAD).max(WIREGUARD_MIN_DATAGRAM)];
        match self.tunn.encapsulate(packet, &mut wg_buf) {
            TunnResult::WriteToNetwork(bytes) => {
                send(bytes);
                Ok(())
            }
            TunnResult::Done => Ok(()),
            TunnResult::Err(e) => Err(format!("wireguard encapsulate failed: {e:?}")),
            TunnResult::WriteToTunnelV4(..) | TunnResult::WriteToTunnelV6(..) => {
                Err("wireguard encapsulate returned a tunnel packet".to_string())
            }
        }
    }

    /// Kick the handshake immediately (first packet out), so a
    /// DNS-first dial does not wait for a TCP SYN to trigger it.
    fn kick_handshake(&mut self, send: &mut dyn FnMut(&[u8])) {
        let mut wg_buf = vec![0u8; 148];
        if let TunnResult::WriteToNetwork(bytes) =
            self.tunn.format_handshake_initiation(&mut wg_buf, false)
        {
            send(bytes);
        }
    }

    /// Abort a socket AND get its RST out. smoltcp sends
    /// exactly one RST for a `Closed` socket (then clears its
    /// tuple), but only if the socket is still in the set when
    /// `poll` runs — removing it in the same cycle as `abort()`
    /// (the old code) meant the RST was never transmitted and
    /// the peer only learned the connection died via its own
    /// RTO, ~1 s later (observed in the keepalive test: the
    /// peer retransmitted the echo, and the RST that answered
    /// it came from the interface, not the socket). So an
    /// aborted socket stays in the set: it goes to
    /// `closing_next`, is promoted to `closing_prev` at the
    /// end of the cycle, the next cycle's `poll` emits the
    /// RST, and it is retired at the end of that cycle. The
    /// `TcpState` is dropped by the caller (the stream is
    /// gone); only the smoltcp socket lingers, and `poll`
    /// is a no-op for it once the RST is sent (tuple cleared).
    fn abort_socket(&mut self, handle: smoltcp::iface::SocketHandle) {
        let sock = self.sockets.get_mut::<smol_tcp::Socket>(handle);
        sock.abort();
        self.closing_next.insert(handle);
    }

    /// Drive boringtun timers (keepalive + handshake retransmit).
    /// Returns `Err` on `ConnectionExpired` (90 s unanswered).
    fn drive_timers(&mut self, send: &mut dyn FnMut(&[u8])) -> Result<(), String> {
        if self.last_timers.elapsed() < Duration::from_millis(100) {
            return Ok(());
        }
        self.last_timers = std::time::Instant::now();
        let mut wg_buf = vec![0u8; 148];
        match self.tunn.update_timers(&mut wg_buf) {
            TunnResult::WriteToNetwork(bytes) => {
                send(bytes);
                Ok(())
            }
            TunnResult::Done => Ok(()),
            TunnResult::Err(e) => Err(format!("wireguard timers failed: {e:?}")),
            TunnResult::WriteToTunnelV4(..) | TunnResult::WriteToTunnelV6(..) => Ok(()),
        }
    }

    /// Report handshake completion once (watch channel).
    fn check_handshake(&mut self) {
        if !self.handshake_done && self.tunn.time_since_last_handshake().is_some() {
            self.handshake_done = true;
            let _ = self.handshake_tx.send(true);
        }
    }

    /// Ensure a DNS UDP socket for `server`'s family, bound to an
    /// ephemeral port on the interface.
    fn dns_socket(&mut self, server: IpAddr) -> Option<smoltcp::iface::SocketHandle> {
        let slot = match server {
            IpAddr::V4(_) => &mut self.dns_v4,
            IpAddr::V6(_) => &mut self.dns_v6,
        };
        if let Some(h) = *slot {
            return Some(h);
        }
        // smoltcp's UDP `bind` rejects port 0
        // (`BindError::Unaddressable`, `socket/udp.rs:219-221`) —
        // there is no ephemeral-port assignment on bind, unlike
        // TCP `connect`. Take a port from the process-wide
        // ephemeral counter (IANA range) and retry a few times
        // in case the port is already taken on this interface.
        //
        // The socket binds to the tunnel address of the server's
        // family, NOT 0.0.0.0: smoltcp's UDP egress uses the
        // bound address as the packet source, so a 0.0.0.0-bound
        // socket emits queries with source 0.0.0.0 and the reply
        // can never come back. With no tunnel address of that
        // family, DNS to such a server is impossible — fail the
        // query fast instead of hanging until the dial timeout.
        let bind_addr = match server {
            IpAddr::V4(_) => IpAddress::from(self.v4_addr?),
            IpAddr::V6(_) => IpAddress::from(self.v6_addr?),
        };
        for _ in 0..8 {
            let rx = smol_udp::PacketBuffer::new(
                vec![smol_udp::PacketMetadata::EMPTY; 4],
                vec![0u8; 2048],
            );
            let tx = smol_udp::PacketBuffer::new(
                vec![smol_udp::PacketMetadata::EMPTY; 4],
                vec![0u8; 2048],
            );
            let mut socket = smol_udp::Socket::new(rx, tx);
            if socket.bind((bind_addr, next_ephemeral_port())).is_ok() {
                let handle = self.sockets.add(socket);
                *slot = Some(handle);
                return Some(handle);
            }
        }
        None
    }

    fn handle_ctrl(&mut self, msg: CtrlMsg) -> bool {
        // Returns true when a control message was consumed (the
        // pump wakes parked shutdown senders after such a cycle).
        match msg {
            CtrlMsg::OpenTcp {
                ip,
                port,
                data_rx,
                net_tx,
                write_waker,
                reply,
            } => {
                let rx = smol_tcp::SocketBuffer::new(vec![0u8; SOCKET_BUFFER_SIZE]);
                let tx = smol_tcp::SocketBuffer::new(vec![0u8; SOCKET_BUFFER_SIZE]);
                let mut socket = smol_tcp::Socket::new(rx, tx);
                let remote = IpEndpoint::new(IpAddress::from(ip), port);
                // Local port 0 is NOT ephemeral in smoltcp 0.14
                // (`connect` rejects it); take a real port from
                // the process-wide counter. The local address is
                // left `None` so smoltcp picks the interface
                // address that routes to the remote.
                match socket.connect(self.iface.context(), remote, next_ephemeral_port()) {
                    Ok(()) => {
                        let handle = self.sockets.add(socket);
                        self.tcp.insert(
                            handle,
                            SockState {
                                data_rx,
                                net_tx,
                                write_waker,
                                pending_open: Some(reply),
                                eof_sent: false,
                                shutdown_sent: false,
                                shutdown_pending: false,
                                peer_fin_seen: false,
                                pending_tx: None,
                                pending_rx: None,
                                pending_eof: false,
                                pending_failed: false,
                                socket_gone: false,
                                data_drained: false,
                            },
                        );
                    }
                    Err(_) => {
                        let _ = reply.send(Err(TransportError::ConnectionDown {
                            message: "wireguard tcp connect failed".to_string(),
                        }));
                    }
                }
            }
            CtrlMsg::ShutdownWrite { handle } => {
                // `SocketSet::get_mut` returns `&mut T` directly
                // (panics on a stale handle), so membership in
                // the pump's own map is the guard: a handle in
                // the map always has its socket in the set.
                if self.tcp.contains_key(&handle) {
                    // Defer the FIN while data is still queued:
                    // `close()` makes `may_send()` false, so a
                    // FIN now would strand the queued bytes in
                    // `data_rx`/`pending_tx` forever (nothing
                    // would ever feed them into the socket).
                    let should_defer = match self.tcp.get(&handle) {
                        Some(st) => st.pending_tx.is_some() || !st.data_rx.is_empty(),
                        None => false,
                    };
                    if should_defer {
                        if let Some(st) = self.tcp.get_mut(&handle) {
                            st.shutdown_pending = true;
                        }
                    } else {
                        let sock = self.sockets.get_mut::<smol_tcp::Socket>(handle);
                        sock.close();
                        if let Some(st) = self.tcp.get_mut(&handle) {
                            st.shutdown_sent = true;
                        }
                    }
                }
            }
            CtrlMsg::Close { handle } => {
                if self.tcp.contains_key(&handle) {
                    self.abort_socket(handle);
                    self.tcp.remove(&handle);
                }
            }
            CtrlMsg::DnsQuery {
                server,
                qtype,
                name,
                reply,
            } => {
                let Some(handle) = self.dns_socket(server) else {
                    let _ = reply.send(Err(TransportError::ConnectionDown {
                        message: "wireguard dns socket failed".to_string(),
                    }));
                    return true;
                };
                self.dns_txid = self.dns_txid.wrapping_add(1);
                // Avoid the reserved txid 0 (some servers treat
                // it as invalid); the counter alone is enough
                // uniqueness inside one tunnel (one query at a
                // time per dial, responses matched by id).
                if self.dns_txid == 0 {
                    self.dns_txid = 1;
                }
                let txid = self.dns_txid;
                let Some(query) = dns_encode_query(&name, qtype, txid) else {
                    let _ = reply.send(Err(TransportError::ConnectionDown {
                        message: format!("resolve {name}: invalid domain name"),
                    }));
                    return true;
                };
                let meta = smol_udp::UdpMetadata {
                    endpoint: IpEndpoint::new(IpAddress::from(server), 53),
                    local_address: None,
                    meta: smoltcp::phy::PacketMeta::default(),
                };
                // The handle was just created by `dns_socket`,
                // so the socket is in the set.
                let sock = self.sockets.get_mut::<smol_udp::Socket>(handle);
                let sent = sock.send_slice(&query, meta).is_ok();
                if sent {
                    self.pending_dns.insert(
                        txid,
                        PendingDns {
                            reply,
                            name,
                            qtype,
                            server,
                        },
                    );
                } else {
                    let _ = reply.send(Err(TransportError::ConnectionDown {
                        message: "wireguard dns query failed".to_string(),
                    }));
                }
            }
        }
        true
    }

    /// Retry delivering anything pending for this socket
    /// (`pending_rx`, then `Eof`, then `Failed`), in order.
    /// `Blocked` means the channel is still full — the caller
    /// must NOT consume more from smoltcp until the next cycle.
    /// `StreamGone` means the receiver is gone; the caller
    /// drops the state.
    fn flush_pending(st: &mut SockState) -> PendingFlush {
        if let Some(chunk) = st.pending_rx.take() {
            match st.net_tx.try_send(NetMsg::Data(chunk)) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(msg)) => {
                    // `Full` returns the message, so the chunk
                    // is recovered, not lost.
                    if let NetMsg::Data(bytes) = msg {
                        st.pending_rx = Some(bytes);
                    }
                    return PendingFlush::Blocked;
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    return PendingFlush::StreamGone;
                }
            }
        }
        if st.pending_eof {
            match st.net_tx.try_send(NetMsg::Eof) {
                Ok(()) => {
                    st.pending_eof = false;
                    st.eof_sent = true;
                }
                Err(mpsc::error::TrySendError::Full(_)) => {
                    return PendingFlush::Blocked;
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    return PendingFlush::StreamGone;
                }
            }
        }
        if st.pending_failed {
            match st.net_tx.try_send(NetMsg::Failed) {
                Ok(()) => {
                    st.pending_failed = false;
                }
                Err(mpsc::error::TrySendError::Full(_)) => {
                    return PendingFlush::Blocked;
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    return PendingFlush::StreamGone;
                }
            }
        }
        PendingFlush::Delivered
    }

    /// One synchronous pump cycle: poll smoltcp, service sockets,
    /// drain device egress, drive timers, check the handshake.
    /// Returns `Err` on a fatal tunnel error.
    fn cycle(&mut self, send: &mut dyn FnMut(&[u8])) -> Result<(), String> {
        let now = self.now();
        self.iface.poll(now, &mut self.device, &mut self.sockets);
        // Service TCP sockets. Handles are collected first; each
        // state is TAKEN out of the map for the iteration (owned
        // `st`) and re-inserted only if the socket survives, so
        // removals never fight a live borrow.
        use smoltcp::socket::tcp::State;
        let handles: Vec<smoltcp::iface::SocketHandle> = self.tcp.keys().copied().collect();
        for handle in handles {
            let Some(mut st) = self.tcp.remove(&handle) else {
                continue;
            };
            let mut keep = true;
            // The smoltcp socket is already gone but messages
            // remain undelivered: only retry the delivery, never
            // touch the (removed) socket. This branch runs
            // BEFORE the `is_closed` check below — that check
            // would `get_mut` a socket that no longer exists.
            if st.socket_gone {
                match Self::flush_pending(&mut st) {
                    PendingFlush::Delivered => continue, // drop the state
                    PendingFlush::Blocked => {
                        self.tcp.insert(handle, st);
                        continue;
                    }
                    PendingFlush::StreamGone => continue, // drop the state
                }
            }
            // The stream went away: abort + drop. (`net_tx` is
            // the pump→stream sender; dropping the stream drops
            // the receiver, so `is_closed` observes it even when
            // the explicit `Close` message was lost because the
            // control channel was full.)
            if st.net_tx.is_closed() {
                self.abort_socket(handle);
                continue;
            }
            // The handle came from the map, so its socket is in
            // the set (inserted together, removed together).
            let sock = self.sockets.get_mut::<smol_tcp::Socket>(handle);
            // Pending open: resolve it from the socket state.
            if st.pending_open.is_some() {
                match sock.state() {
                    State::Established => {
                        if let Some(reply) = st.pending_open.take() {
                            let _ = reply.send(Ok(handle));
                        }
                    }
                    State::Closed | State::TimeWait => {
                        if let Some(reply) = st.pending_open.take() {
                            let _ = reply.send(Err(TransportError::ConnectionDown {
                                message: "connection refused through wireguard tunnel".to_string(),
                            }));
                        }
                        self.sockets.remove(handle);
                        continue;
                    }
                    _ => {}
                }
            }
            if st.pending_open.is_some() {
                // Still handshaking/connecting: no data yet.
                self.tcp.insert(handle, st);
                continue;
            }
            // Retry anything pending from an earlier cycle
            // BEFORE consuming more from smoltcp. A blocked
            // flush means the stream channel is still full:
            // skip the receive drain this cycle (the send side
            // below still runs — it is independent).
            let mut rx_blocked = false;
            match Self::flush_pending(&mut st) {
                PendingFlush::Delivered => {}
                PendingFlush::Blocked => rx_blocked = true,
                PendingFlush::StreamGone => {
                    // `sock` is borrowed here, so the abort is
                    // inline: same contract as `abort_socket`
                    // (RST on the next poll, retired after).
                    sock.abort();
                    self.closing_next.insert(handle);
                    continue;
                }
            }
            // Receive: drain up to a bounded batch per cycle.
            // The extra state match is the prompt-EOF probe: once
            // the receive buffer drains, `may_recv()` is false in
            // CloseWait/FinWait2/TimeWait, so without it the loop
            // would never call `recv_slice` again and `Finished`
            // would only be observed when the 10 s TIME-WAIT
            // close timer fires (EOF delayed up to 10 s). In
            // those states `recv_slice` returns `Finished` on an
            // empty buffer (or the last bytes, if any), so the
            // probe costs one cheap call per cycle at most.
            let mut recv_chunks = 0;
            while !rx_blocked
                && recv_chunks < 4
                && (sock.may_recv()
                    || matches!(
                        sock.state(),
                        State::CloseWait | State::FinWait2 | State::TimeWait
                    ))
            {
                let mut buf = [0u8; READ_CHUNK];
                match sock.recv_slice(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        recv_chunks += 1;
                        match st
                            .net_tx
                            .try_send(NetMsg::Data(Bytes::copy_from_slice(&buf[..n])))
                        {
                            Ok(()) => {}
                            Err(mpsc::error::TrySendError::Full(msg)) => {
                                // Backpressure: `recv_slice`
                                // ALREADY consumed these bytes
                                // (ACKed — the peer will not
                                // retransmit), so the chunk is
                                // held in `pending_rx` and
                                // retried next cycle. Dropping
                                // it would corrupt the stream.
                                // (`Full` returns the message,
                                // so nothing is lost here.)
                                if let NetMsg::Data(bytes) = msg {
                                    st.pending_rx = Some(bytes);
                                }
                                break;
                            }
                            Err(mpsc::error::TrySendError::Closed(_)) => break,
                        }
                    }
                    Err(smol_tcp::RecvError::Finished) => {
                        st.peer_fin_seen = true;
                        if !st.eof_sent && !st.pending_eof {
                            match st.net_tx.try_send(NetMsg::Eof) {
                                Ok(()) => st.eof_sent = true,
                                Err(mpsc::error::TrySendError::Full(_)) => {
                                    // `eof_sent` stays false:
                                    // the EOF is retried until
                                    // it lands (see
                                    // `flush_pending`).
                                    st.pending_eof = true;
                                }
                                Err(mpsc::error::TrySendError::Closed(_)) => {}
                            }
                        }
                        break;
                    }
                    Err(smol_tcp::RecvError::InvalidState) => break,
                }
            }
            // Send: first finish a partial chunk, then drain the
            // channel (bounded per cycle).
            let mut send_chunks = 0;
            while send_chunks < 4 {
                if st.pending_tx.is_none() {
                    match st.data_rx.try_recv() {
                        Ok(chunk) => {
                            st.pending_tx = Some((chunk, 0));
                            st.data_drained = true;
                        }
                        Err(_) => break,
                    }
                }
                let Some((chunk, off)) = st.pending_tx.take() else {
                    break;
                };
                if !sock.may_send() {
                    st.pending_tx = Some((chunk, off));
                    break;
                }
                match sock.send_slice(&chunk[off..]) {
                    Ok(0) => {
                        st.pending_tx = Some((chunk, off));
                        break;
                    }
                    Ok(n) => {
                        send_chunks += 1;
                        if off + n < chunk.len() {
                            st.pending_tx = Some((chunk, off + n));
                        }
                    }
                    Err(_) => {
                        // Socket buffer full: keep the chunk
                        // and stop draining (backpressure).
                        st.pending_tx = Some((chunk, off));
                        break;
                    }
                }
            }
            // Deferred graceful close: the app asked to shut
            // down while data was queued; the queue is empty
            // now, so the FIN can go. (Only now — `close()`
            // flips `may_send()` off, so closing earlier would
            // strand the queued bytes.)
            if st.shutdown_pending && st.pending_tx.is_none() && st.data_rx.is_empty() {
                st.shutdown_pending = false;
                st.shutdown_sent = true;
                sock.close();
            }
            // Socket closed underneath us: clean EOF only when
            // the peer's FIN was seen (or we shut down); a reset
            // without FIN is a failure, not an EOF. The terminal
            // message is queued as pending and retried until it
            // lands; the state survives (with `socket_gone`) if
            // the channel is full, instead of dropping the
            // sender and turning a clean EOF into a
            // `ConnectionReset` on the stream.
            if sock.state() == State::Closed {
                if !st.eof_sent && !st.peer_fin_seen && !st.shutdown_sent {
                    st.pending_failed = true;
                } else if !st.eof_sent && !st.pending_eof {
                    st.pending_eof = true;
                }
                self.sockets.remove(handle);
                match Self::flush_pending(&mut st) {
                    PendingFlush::Delivered => keep = false,
                    PendingFlush::Blocked => {
                        st.socket_gone = true;
                    }
                    PendingFlush::StreamGone => keep = false,
                }
            }
            // Wake a parked writer whose channel gained space.
            if st.data_drained {
                st.data_drained = false;
                if let Ok(mut slot) = st.write_waker.try_lock()
                    && let Some(w) = slot.take()
                {
                    w.wake();
                }
            }
            if keep {
                self.tcp.insert(handle, st);
            }
        }
        // Service DNS sockets: match responses to pending queries.
        for family in [self.dns_v4, self.dns_v6] {
            let Some(handle) = family else { continue };
            // The slot is `Some` only after the socket was added
            // to the set (and DNS sockets are never removed).
            let sock = self.sockets.get_mut::<smol_udp::Socket>(handle);
            let mut buf = [0u8; 2048];
            while let Ok((n, meta)) = sock.recv_slice(&mut buf) {
                // The txid is the first two bytes; the
                // full parse validates it again, plus the
                // question name/qtype and the source.
                if n < 2 {
                    continue;
                }
                let txid = u16::from_be_bytes([buf[0], buf[1]]);
                let Some(pending) = self.pending_dns.get(&txid) else {
                    continue;
                };
                // A reply from any source other than the server
                // queried is ignored (the query stays pending —
                // the real reply may still arrive).
                let src_ip = IpAddr::from(meta.endpoint.addr);
                if src_ip != pending.server {
                    continue;
                }
                // The key was just checked present (single-threaded
                // pump: nothing removes it between the `get` and
                // this `remove`); the `else` is unreachable defence,
                // not an `expect()` on external input.
                let Some(pending) = self.pending_dns.remove(&txid) else {
                    continue;
                };
                let ips = dns_parse_response(&buf[..n], txid, pending.qtype, &pending.name)
                    .unwrap_or_default();
                let _ = pending.reply.send(Ok(ips));
            }
        }
        // Drop DNS queries whose dialer went away (overall
        // timeout fired): their oneshot receivers are closed.
        self.pending_dns
            .retain(|_, pending| !pending.reply.is_closed());
        // Drop pending opens whose dialer went away the same way.
        let mut dead_opens = Vec::new();
        for (handle, st) in self.tcp.iter() {
            if let Some(reply) = &st.pending_open
                && reply.is_closed()
            {
                dead_opens.push(*handle);
            }
        }
        for handle in dead_opens {
            // The handle came from the map, so its socket is in
            // the set (inserted together, removed together).
            self.abort_socket(handle);
            self.tcp.remove(&handle);
        }
        // Drain device egress: every emitted IP packet goes
        // through boringtun to the peer.
        while let Some(packet) = self.device.tx_queue.pop_front() {
            self.send_ip_packet(&packet, send)?;
        }
        // Retire sockets aborted in a previous cycle: the
        // `poll` at the top of this cycle already emitted
        // their RST (smoltcp clears the tuple after sending
        // it, so a further poll is a no-op for them). Sockets
        // aborted in THIS cycle move to `closing_prev` so
        // their RST goes out on the next cycle's poll.
        for handle in self.closing_prev.drain() {
            self.sockets.remove(handle);
        }
        std::mem::swap(&mut self.closing_prev, &mut self.closing_next);
        self.drive_timers(send)?;
        self.check_handshake();
        Ok(())
    }
}

/// The pump task: owns the UDP socket + `PumpCore`, drives both.
/// Exits when all `Tunnel` handles are dropped (the control
/// channel closes), when the tunnel dies fatally, or when the
/// dialer aborts it.
/// The pump task: owns the UDP socket + `PumpCore`, drives both.
/// Exits when all `Tunnel` handles are dropped (the control
/// channel closes), when the tunnel dies fatally, or when the
/// dialer aborts it.
///
/// Egress is split in two because `UdpSocket::send_to` is async
/// while `PumpCore::cycle` is synchronous: the core pushes egress
/// datagrams into `outbox` through a `&mut dyn FnMut` sink, and
/// the loop flushes the outbox with `send_outbox` after each
/// cycle. Inbound datagrams are NEVER drained with `try_recv`
/// (it reports no sender, and the socket is unconnected): every
/// datagram is taken through `recv_from` in the `select!` arm,
/// whose source check (`src == peer`) is the only gate before
/// boringtun sees it.
async fn pump_loop(
    udp: UdpSocket,
    mut core: PumpCore,
    mut ctrl_rx: mpsc::Receiver<CtrlMsg>,
    kick: Arc<Notify>,
    peer: SocketAddr,
) {
    let mut outbox: VecDeque<Vec<u8>> = VecDeque::new();
    // Kick the handshake before the first wait.
    {
        let mut send = |bytes: &[u8]| outbox.push_back(bytes.to_vec());
        core.kick_handshake(&mut send);
    }
    if !send_outbox(&udp, peer, &mut outbox).await {
        core.fatal("wireguard udp send failed");
        return;
    }
    loop {
        let delay = core.next_delay();
        let mut udp_buf = vec![0u8; core.mtu + WIREGUARD_DATA_OVERHEAD];
        let mut ctrl_consumed = false;
        tokio::select! {
            res = udp.recv_from(&mut udp_buf) => {
                match res {
                    Ok((n, src)) if src == peer => {
                        let mut send = |bytes: &[u8]| outbox.push_back(bytes.to_vec());
                        if let Err(e) = core.handle_udp(&udp_buf[..n], &mut send) {
                            core.fatal(&e);
                            break;
                        }
                    }
                    Ok(_) => {
                        // Datagrams from anyone but the peer are
                        // dropped: boringtun would reject them
                        // anyway (wrong key), and answering them
                        // would be an oracle.
                    }
                    Err(_) => {
                        core.fatal("wireguard udp recv failed");
                        break;
                    }
                }
            }
            msg = ctrl_rx.recv() => {
                match msg {
                    Some(m) => {
                        ctrl_consumed = core.handle_ctrl(m);
                    }
                    None => break, // last Tunnel handle dropped
                }
            }
            () = tokio::time::sleep(delay) => {}
            () = kick.notified() => {}
        }
        // Drain control bursts the same way (no source issue:
        // the channel is ours alone).
        while let Ok(m) = ctrl_rx.try_recv() {
            ctrl_consumed = core.handle_ctrl(m);
        }
        {
            let mut send = |bytes: &[u8]| outbox.push_back(bytes.to_vec());
            if let Err(e) = core.cycle(&mut send) {
                core.fatal(&e);
                break;
            }
        }
        // A consumed control message may have freed a parked
        // writer's `poll_shutdown` (which registered its waker
        // when the channel was full): wake every socket's
        // write waker once per cycle that consumed control.
        if ctrl_consumed {
            for st in core.tcp.values_mut() {
                if let Ok(mut slot) = st.write_waker.try_lock()
                    && let Some(w) = slot.take()
                {
                    w.wake();
                }
            }
        }
        if !send_outbox(&udp, peer, &mut outbox).await {
            core.fatal("wireguard udp send failed");
            break;
        }
        if core.dead.load(Ordering::SeqCst) {
            break;
        }
    }
    // On exit, fail everything still pending (the dialer's `dead`
    // flag is already set by `fatal`, or set here for the
    // clean-shutdown path so a later dial rebuilds).
    core.dead.store(true, Ordering::SeqCst);
    core.fatal("wireguard tunnel is down");
}

/// Flush queued egress datagrams to the peer. Returns `false`
/// when a send fails (fatal to the tunnel: the peer is
/// unreachable); the caller marks the tunnel dead. Remaining
/// datagrams are dropped on failure.
async fn send_outbox(udp: &UdpSocket, peer: SocketAddr, outbox: &mut VecDeque<Vec<u8>>) -> bool {
    while let Some(bytes) = outbox.pop_front() {
        if udp.send_to(&bytes, peer).await.is_err() {
            outbox.clear();
            return false;
        }
    }
    true
}

/// JSON helpers for the endpoint parser (the `serde_json::Value`
/// object shape is the sing-box flat endpoint JSON; Go:
/// `internal/profile/outbound.go` `parseEndpoint`).
///
/// Absent vs present-but-wrong-typed are distinguished: a field
/// present with the wrong JSON type is a `Validation` naming the
/// field, never a silent default (Go JSON-unmarshals into a typed
/// struct, so a wrong-typed field is a hard parse error there).
fn wg_json_str<'a>(
    obj: &'a serde_json::Value,
    key: &str,
) -> Result<Option<&'a str>, TransportError> {
    match obj.get(key) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(v) => match v.as_str() {
            Some(s) => Ok(Some(s)),
            None => Err(TransportError::Validation {
                message: format!("wireguard endpoint \"{key}\" must be a string"),
            }),
        },
    }
}

fn wg_json_u64(obj: &serde_json::Value, key: &str) -> Result<Option<u64>, TransportError> {
    match obj.get(key) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(v) => match v.as_u64() {
            Some(n) => Ok(Some(n)),
            None => Err(TransportError::Validation {
                message: format!("wireguard endpoint \"{key}\" must be a non-negative integer"),
            }),
        },
    }
}

fn wg_json_bool(obj: &serde_json::Value, key: &str) -> Result<Option<bool>, TransportError> {
    match obj.get(key) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(v) => match v.as_bool() {
            Some(b) => Ok(Some(b)),
            None => Err(TransportError::Validation {
                message: format!("wireguard endpoint \"{key}\" must be a boolean"),
            }),
        },
    }
}

/// sing-box `Listable[T]`: a bare string is a one-element list,
/// an array is a list; anything else (or a non-string element)
/// is a `Validation` naming the field. `peers` is NOT `Listable`
/// and stays array-only.
fn wg_json_str_array(
    obj: &serde_json::Value,
    key: &str,
) -> Result<Option<Vec<String>>, TransportError> {
    match obj.get(key) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::String(s)) => Ok(Some(vec![s.clone()])),
        Some(serde_json::Value::Array(arr)) => {
            let mut out = Vec::with_capacity(arr.len());
            for v in arr {
                match v.as_str() {
                    Some(s) => out.push(s.to_string()),
                    None => {
                        return Err(TransportError::Validation {
                            message: format!(
                                "wireguard endpoint \"{key}\" must be a string or an array of strings"
                            ),
                        });
                    }
                }
            }
            Ok(Some(out))
        }
        Some(_) => Err(TransportError::Validation {
            message: format!(
                "wireguard endpoint \"{key}\" must be a string or an array of strings"
            ),
        }),
    }
}

/// Parse a sing-box flat WireGuard endpoint JSON object into a
/// typed `WireGuardConfig` (Go: sing-box `option/wireguard.go:9-33`
/// as ported in `internal/outbound/wireguard_conf.go`).
///
/// The `wireguard_dns` servers are NOT part of the endpoint JSON;
/// the caller (`dispatch_endpoint`) supplies them separately.
///
/// wg-quick spellings are rejected with a "did you mean …"
/// `Validation` (D2): `preshared_key` → `pre_shared_key`,
/// `persistent_keepalive` → `persistent_keepalive_interval`,
/// a single `endpoint` string (endpoint or peer level) →
/// `address` + `port`. A non-empty `detour` is `Unsupported`,
/// never silently ignored (M3 rejects all detours). Field
/// validation that needs the typed invariants (exactly one peer,
/// non-empty address/allowed_ips, MTU range, key lengths) is
/// left to `WireGuardDialer::new`, which names the field.
pub fn parse_wireguard_endpoint(
    endpoint: &serde_json::Value,
    wireguard_dns: &[String],
) -> Result<WireGuardConfig, TransportError> {
    let validation = |message: String| TransportError::Validation { message };
    match wg_json_str(endpoint, "type")? {
        Some("wireguard") => {}
        Some(other) => {
            return Err(validation(format!(
                "endpoint type {other:?} is not \"wireguard\""
            )));
        }
        None => {
            return Err(validation("endpoint is missing \"type\"".to_string()));
        }
    }
    // wg-quick spellings, endpoint level (D2).
    if endpoint.get("preshared_key").is_some() {
        return Err(validation(
            "wireguard endpoint uses wg-quick spelling \"preshared_key\"; did you mean \"pre_shared_key\"".to_string(),
        ));
    }
    if endpoint.get("persistent_keepalive").is_some() {
        return Err(validation(
            "wireguard endpoint uses wg-quick spelling \"persistent_keepalive\"; did you mean \"persistent_keepalive_interval\"".to_string(),
        ));
    }
    if endpoint.get("endpoint").is_some() {
        return Err(validation(
            "wireguard endpoint uses wg-quick spelling \"endpoint\"; did you mean peer \"address\" + \"port\"".to_string(),
        ));
    }
    // A non-string `detour` is a Validation (wrong type), not
    // silently ignored; a non-empty string detour is Unsupported.
    if let Some(d) = wg_json_str(endpoint, "detour")?
        && !d.is_empty()
    {
        return Err(TransportError::Unsupported {
            message: "wireguard endpoint detour chains are not supported".to_string(),
        });
    }
    let tag = wg_json_str(endpoint, "tag")?.unwrap_or("").to_string();
    let system = wg_json_bool(endpoint, "system")?.unwrap_or(false);
    let mut address = Vec::new();
    for value in wg_json_str_array(endpoint, "address")?.unwrap_or_default() {
        address.push(parse_prefix(&value, "address")?);
    }
    let private_key = match wg_json_str(endpoint, "private_key")? {
        Some(s) => decode_key_32(s, "private_key")?,
        None => [0u8; 32], // `WireGuardDialer::new` names the field
    };
    let mtu = match wg_json_u64(endpoint, "mtu")? {
        Some(n) => u32::try_from(n)
            .map_err(|_| validation("wireguard endpoint \"mtu\" is out of range".to_string()))?,
        None => 0, // `WireGuardDialer::new` maps 0 → 1408
    };
    let listen_port = match wg_json_u64(endpoint, "listen_port")? {
        Some(n) => Some(u16::try_from(n).map_err(|_| {
            validation("wireguard endpoint \"listen_port\" is out of range".to_string())
        })?),
        None => None,
    };
    let mut peers = Vec::new();
    if let Some(arr) = endpoint.get("peers").and_then(|v| v.as_array()) {
        for (peer_idx, peer) in arr.iter().enumerate() {
            if !peer.is_object() {
                return Err(validation(format!(
                    "wireguard peer {} must be an object",
                    peer_idx + 1
                )));
            }
            // wg-quick spellings, peer level (D2).
            if peer.get("preshared_key").is_some() {
                return Err(validation(
                    "wireguard peer uses wg-quick spelling \"preshared_key\"; did you mean \"pre_shared_key\"".to_string(),
                ));
            }
            if peer.get("persistent_keepalive").is_some() {
                return Err(validation(
                    "wireguard peer uses wg-quick spelling \"persistent_keepalive\"; did you mean \"persistent_keepalive_interval\"".to_string(),
                ));
            }
            if peer.get("endpoint").is_some() {
                return Err(validation(
                    "wireguard peer uses wg-quick spelling \"endpoint\"; did you mean \"address\" + \"port\"".to_string(),
                ));
            }
            let endpoint_host = wg_json_str(peer, "address")?.unwrap_or("").to_string();
            let endpoint_port = match wg_json_u64(peer, "port")? {
                Some(n) => u16::try_from(n).map_err(|_| {
                    validation("wireguard peer \"port\" is out of range".to_string())
                })?,
                None => 0, // `WireGuardDialer::new` names the field
            };
            let public_key = match wg_json_str(peer, "public_key")? {
                Some(s) => decode_key_32(s, "public_key")?,
                None => [0u8; 32], // `WireGuardDialer::new` names it
            };
            let preshared_key = match wg_json_str(peer, "pre_shared_key")? {
                Some(s) => Some(decode_key_32(s, "pre_shared_key")?),
                None => None,
            };
            let mut allowed_ips = Vec::new();
            for value in wg_json_str_array(peer, "allowed_ips")?.unwrap_or_default() {
                allowed_ips.push(parse_prefix(&value, "allowed_ips")?);
            }
            let persistent_keepalive = match wg_json_u64(peer, "persistent_keepalive_interval")? {
                Some(n) => u16::try_from(n).map_err(|_| {
                    validation(
                        "wireguard peer \"persistent_keepalive_interval\" is out of range"
                            .to_string(),
                    )
                })?,
                None => 0,
            };
            let mut reserved = [0u8; 3];
            // Present-but-not-an-array is a Validation, not
            // silent zeros (same wrong-type rule as the rest).
            if let Some(v) = peer.get("reserved") {
                let arr = v.as_array().ok_or_else(|| {
                    validation(
                        "wireguard peer \"reserved\" must be an array of 3 byte values".to_string(),
                    )
                })?;
                if arr.len() != 3 {
                    return Err(validation(
                        "wireguard peer \"reserved\" must have exactly 3 bytes".to_string(),
                    ));
                }
                for (i, v) in arr.iter().enumerate() {
                    reserved[i] = u8::try_from(v.as_u64().ok_or_else(|| {
                        validation(
                            "wireguard peer \"reserved\" must be an array of 3 byte values"
                                .to_string(),
                        )
                    })?)
                    .map_err(|_| {
                        validation(
                            "wireguard peer \"reserved\" must be an array of 3 byte values"
                                .to_string(),
                        )
                    })?;
                }
            }
            peers.push(WireGuardPeerConfig {
                endpoint_host,
                endpoint_port,
                public_key,
                preshared_key,
                allowed_ips,
                persistent_keepalive,
                reserved,
            });
        }
    }
    Ok(WireGuardConfig {
        tag,
        system,
        address,
        private_key,
        mtu,
        listen_port,
        peers,
        dns_servers: wireguard_dns.to_vec(),
        dial_timeout: DIAL_TIMEOUT,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Valid fake config: keys are repeated-byte patterns
    /// ([0x11; 32] / [0x22; 32]), never real key material.
    fn fake_cfg() -> WireGuardConfig {
        WireGuardConfig {
            tag: "wg-fake".to_string(),
            system: false,
            address: vec![Prefix {
                addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                prefix_len: 32,
            }],
            private_key: [0x11; 32],
            mtu: 0,
            listen_port: None,
            peers: vec![WireGuardPeerConfig {
                endpoint_host: "127.0.0.1".to_string(),
                endpoint_port: 51820,
                public_key: [0x22; 32],
                preshared_key: None,
                allowed_ips: vec![Prefix {
                    addr: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
                    prefix_len: 0,
                }],
                persistent_keepalive: 0,
                reserved: [0, 0, 0],
            }],
            dns_servers: vec![],
            dial_timeout: DIAL_TIMEOUT,
        }
    }

    fn fake_json(s: &str) -> serde_json::Value {
        serde_json::from_str(s).expect("INVARIANT: test fixture parses")
    }

    fn validation_msg(err: TransportError) -> String {
        match err {
            TransportError::Validation { message } => message,
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    fn unsupported_msg(err: TransportError) -> String {
        match err {
            TransportError::Unsupported { message } => message,
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }

    // (a) Key schedule + handshake: two boringtun `Tunn`s in one
    // process, deterministic fake keys, packet exchange via
    // queues. Method source: boringtun's own two-`Tunn` test
    // shape (its `noise::tests` drive a client and a server
    // `Tunn` against each other the same way) for the
    // WireGuard Noise_IKpsk2 handshake. No fixed published
    // vector is usable here: handshake bytes contain ephemeral
    // keys and timestamps, so no byte-stable vector exists to
    // assert against (see PORTING.md §M3d); the deterministic-key
    // handshake + data round-trip IS the proof.
    #[test]
    fn fake_two_tunn_handshake_and_data_roundtrip() {
        let client_secret = StaticSecret::from([0x11u8; 32]);
        let server_secret = StaticSecret::from([0x22u8; 32]);
        let client_pub = PublicKey::from(&client_secret);
        let server_pub = PublicKey::from(&server_secret);
        let mut client = Tunn::new(client_secret, server_pub, None, None, 1, None);
        let mut server = Tunn::new(server_secret, client_pub, None, None, 2, None);

        // Drain one datagram through a `Tunn`, collecting what it
        // wants sent back (`out_net`) and what it delivers to its
        // tunnel (`out_tun`).
        fn drain(
            tunn: &mut Tunn,
            datagram: &[u8],
            out_net: &mut Vec<Vec<u8>>,
            out_tun: &mut Vec<Vec<u8>>,
        ) {
            let mut next: Option<Vec<u8>> = Some(datagram.to_vec());
            let mut buf = vec![0u8; 2048];
            loop {
                let r = match &next {
                    Some(d) => tunn.decapsulate(None, d, &mut buf),
                    None => tunn.decapsulate(None, &[], &mut buf),
                };
                next = None;
                match r {
                    TunnResult::Done => break,
                    TunnResult::WriteToNetwork(b) => out_net.push(b.to_vec()),
                    TunnResult::WriteToTunnelV4(b, _) | TunnResult::WriteToTunnelV6(b, _) => {
                        out_tun.push(b.to_vec())
                    }
                    TunnResult::Err(e) => panic!("fake decapsulate failed: {e:?}"),
                }
            }
        }

        // Kick: the client sends its handshake initiation.
        let mut buf = [0u8; 2048];
        let mut c2s: Vec<Vec<u8>> = match client.encapsulate(&[], &mut buf) {
            TunnResult::WriteToNetwork(b) => vec![b.to_vec()],
            other => panic!("fake initiation expected WriteToNetwork, got {other:?}"),
        };
        let mut s2c: Vec<Vec<u8>> = Vec::new();
        let mut handshook = false;
        for _ in 0..10 {
            let mut next_c2s = Vec::new();
            let mut next_s2c = Vec::new();
            for d in c2s.drain(..) {
                drain(&mut server, &d, &mut next_s2c, &mut Vec::new());
            }
            for d in s2c.drain(..) {
                drain(&mut client, &d, &mut next_c2s, &mut Vec::new());
            }
            c2s = next_c2s;
            s2c = next_s2c;
            if client.time_since_last_handshake().is_some()
                && server.time_since_last_handshake().is_some()
            {
                handshook = true;
                break;
            }
        }
        assert!(handshook, "fake handshake never completed");
        assert!(client.time_since_last_handshake().is_some());
        assert!(server.time_since_last_handshake().is_some());

        // Data round-trip: a minimal IPv4 packet (20-byte header,
        // no payload) client → server → client, bytes identical.
        let ip_packet: [u8; 20] = [
            0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 2, 10, 0, 0, 1,
        ];
        let mut out_net = Vec::new();
        match client.encapsulate(&ip_packet, &mut buf) {
            TunnResult::WriteToNetwork(b) => out_net.push(b.to_vec()),
            other => panic!("fake data encapsulate expected WriteToNetwork, got {other:?}"),
        }
        let mut delivered = Vec::new();
        for d in out_net {
            drain(&mut server, &d, &mut Vec::new(), &mut delivered);
        }
        assert_eq!(delivered.len(), 1, "server must deliver exactly one packet");
        assert_eq!(delivered[0], ip_packet.to_vec());
        let mut out_net = Vec::new();
        match server.encapsulate(&ip_packet, &mut buf) {
            TunnResult::WriteToNetwork(b) => out_net.push(b.to_vec()),
            other => panic!("fake data encapsulate expected WriteToNetwork, got {other:?}"),
        }
        let mut delivered = Vec::new();
        for d in out_net {
            drain(&mut client, &d, &mut Vec::new(), &mut delivered);
        }
        assert_eq!(delivered.len(), 1, "client must deliver exactly one packet");
        assert_eq!(delivered[0], ip_packet.to_vec());
    }

    // (c) system:true rejected via `new()` with the exact Go
    // runtime text (the `dispatch_endpoint` half is in
    // `config.rs` tests).
    #[test]
    fn fake_system_true_rejected_with_go_runtime_text() {
        let mut cfg = fake_cfg();
        cfg.system = true;
        let msg = unsupported_msg(WireGuardDialer::new(cfg).expect_err("system:true must fail"));
        assert_eq!(
            msg,
            "outbound: wireguard endpoint with system:true is rejected: userspace WireGuard only"
        );
    }

    // (d) Missing-field errors: one test per required field.
    #[test]
    fn fake_missing_private_key_is_validation() {
        let mut cfg = fake_cfg();
        cfg.private_key = [0u8; 32];
        let msg = validation_msg(WireGuardDialer::new(cfg).expect_err("missing key must fail"));
        assert!(
            msg.contains("private_key"),
            "message must name the field: {msg}"
        );
    }

    #[test]
    fn fake_missing_peer_public_key_is_validation() {
        let mut cfg = fake_cfg();
        cfg.peers[0].public_key = [0u8; 32];
        let msg = validation_msg(WireGuardDialer::new(cfg).expect_err("missing key must fail"));
        assert!(
            msg.contains("public_key"),
            "message must name the field: {msg}"
        );
    }

    #[test]
    fn fake_missing_peer_address_is_validation() {
        let mut cfg = fake_cfg();
        cfg.peers[0].endpoint_host = String::new();
        let msg = validation_msg(WireGuardDialer::new(cfg).expect_err("missing address must fail"));
        assert!(
            msg.contains("address"),
            "message must name the field: {msg}"
        );
    }

    #[test]
    fn fake_missing_peer_port_is_validation() {
        let mut cfg = fake_cfg();
        cfg.peers[0].endpoint_port = 0;
        let msg = validation_msg(WireGuardDialer::new(cfg).expect_err("missing port must fail"));
        assert!(msg.contains("port"), "message must name the field: {msg}");
    }

    #[test]
    fn fake_missing_address_is_validation() {
        let mut cfg = fake_cfg();
        cfg.address = Vec::new();
        let msg = validation_msg(WireGuardDialer::new(cfg).expect_err("missing address must fail"));
        assert!(
            msg.contains("address"),
            "message must name the field: {msg}"
        );
    }

    #[test]
    fn fake_missing_allowed_ips_is_validation() {
        let mut cfg = fake_cfg();
        cfg.peers[0].allowed_ips = Vec::new();
        let msg =
            validation_msg(WireGuardDialer::new(cfg).expect_err("missing allowed_ips must fail"));
        assert!(
            msg.contains("allowed_ips"),
            "message must name the field: {msg}"
        );
    }

    #[test]
    fn fake_malformed_base64_key_is_validation() {
        let cfg = fake_json(
            r#"{"type":"wireguard","tag":"wg-fake","private_key":"!!!not-base64!!!","address":["10.0.0.2/32"],"peers":[{"public_key":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=","address":"127.0.0.1","port":51820,"allowed_ips":["0.0.0.0/0"]}]}"#,
        );
        let msg =
            validation_msg(parse_wireguard_endpoint(&cfg, &[]).expect_err("bad base64 must fail"));
        assert!(
            msg.contains("private_key"),
            "message must name the field: {msg}"
        );
        assert!(msg.contains("base64"), "message must say base64: {msg}");
    }

    #[test]
    fn fake_wrong_length_key_is_validation() {
        // 31 zero bytes, valid base64, wrong length.
        let short = BASE64_STD.encode([0u8; 31]);
        let cfg = fake_json(&format!(
            r#"{{"type":"wireguard","tag":"wg-fake","private_key":"{short}","address":["10.0.0.2/32"],"peers":[{{"public_key":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=","address":"127.0.0.1","port":51820,"allowed_ips":["0.0.0.0/0"]}}]}}"#
        ));
        let msg =
            validation_msg(parse_wireguard_endpoint(&cfg, &[]).expect_err("short key must fail"));
        assert!(
            msg.contains("private_key"),
            "message must name the field: {msg}"
        );
        assert!(msg.contains("32 bytes"), "message must say 32 bytes: {msg}");
    }

    #[test]
    fn fake_zero_peers_is_validation() {
        let mut cfg = fake_cfg();
        cfg.peers = Vec::new();
        let err = WireGuardDialer::new(cfg).expect_err("0 peers must fail");
        assert!(
            matches!(err, TransportError::Validation { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn fake_two_peers_is_unsupported() {
        let mut cfg = fake_cfg();
        cfg.peers.push(cfg.peers[0].clone());
        let msg = unsupported_msg(WireGuardDialer::new(cfg).expect_err("2 peers must fail"));
        assert!(
            msg.contains("single peer"),
            "message must say single peer: {msg}"
        );
    }

    #[test]
    fn fake_nonzero_reserved_is_unsupported() {
        let mut cfg = fake_cfg();
        cfg.peers[0].reserved = [0, 0, 1];
        let err = WireGuardDialer::new(cfg).expect_err("non-zero reserved must fail");
        assert!(
            matches!(err, TransportError::Unsupported { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn fake_mtu_too_large_is_validation() {
        let mut cfg = fake_cfg();
        cfg.mtu = 65536;
        let msg = validation_msg(WireGuardDialer::new(cfg).expect_err("mtu must fail"));
        assert!(msg.contains("mtu"), "message must name the field: {msg}");
    }

    #[test]
    fn fake_nine_addresses_is_validation() {
        let mut cfg = fake_cfg();
        cfg.address = (2..=10)
            .map(|i| Prefix {
                addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, i)),
                prefix_len: 32,
            })
            .collect();
        let msg = validation_msg(WireGuardDialer::new(cfg).expect_err("9 addresses must fail"));
        assert!(
            msg.contains("address"),
            "message must name the field: {msg}"
        );
    }

    #[test]
    fn fake_empty_tag_is_validation() {
        let mut cfg = fake_cfg();
        cfg.tag = String::new();
        let err = WireGuardDialer::new(cfg).expect_err("empty tag must fail");
        assert!(
            matches!(err, TransportError::Validation { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn fake_mtu_zero_defaults_to_1408() {
        let dialer = WireGuardDialer::new(fake_cfg()).expect("fake cfg valid");
        assert_eq!(dialer.cfg.mtu, WIREGUARD_DEFAULT_MTU);
    }

    // D2: wg-quick spellings rejected with "did you mean".
    #[test]
    fn fake_wg_quick_preshared_key_spelling_is_validation() {
        let cfg = fake_json(
            r#"{"type":"wireguard","tag":"wg-fake","private_key":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=","address":["10.0.0.2/32"],"peers":[{"public_key":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=","address":"127.0.0.1","port":51820,"allowed_ips":["0.0.0.0/0"],"preshared_key":"AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM="}]}"#,
        );
        let msg = validation_msg(
            parse_wireguard_endpoint(&cfg, &[]).expect_err("wg-quick spelling must fail"),
        );
        assert!(
            msg.contains("did you mean"),
            "message must say did you mean: {msg}"
        );
        assert!(
            msg.contains("pre_shared_key"),
            "message must name the sing-box spelling: {msg}"
        );
    }

    #[test]
    fn fake_wg_quick_persistent_keepalive_spelling_is_validation() {
        let cfg = fake_json(
            r#"{"type":"wireguard","tag":"wg-fake","private_key":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=","address":["10.0.0.2/32"],"peers":[{"public_key":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=","address":"127.0.0.1","port":51820,"allowed_ips":["0.0.0.0/0"],"persistent_keepalive":25}]}"#,
        );
        let msg = validation_msg(
            parse_wireguard_endpoint(&cfg, &[]).expect_err("wg-quick spelling must fail"),
        );
        assert!(
            msg.contains("did you mean"),
            "message must say did you mean: {msg}"
        );
        assert!(
            msg.contains("persistent_keepalive_interval"),
            "message must name the sing-box spelling: {msg}"
        );
    }

    #[test]
    fn fake_wg_quick_single_endpoint_string_is_validation() {
        let cfg = fake_json(
            r#"{"type":"wireguard","tag":"wg-fake","private_key":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=","address":["10.0.0.2/32"],"peers":[{"public_key":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=","endpoint":"127.0.0.1:51820","allowed_ips":["0.0.0.0/0"]}]}"#,
        );
        let msg = validation_msg(
            parse_wireguard_endpoint(&cfg, &[]).expect_err("wg-quick spelling must fail"),
        );
        assert!(
            msg.contains("did you mean"),
            "message must say did you mean: {msg}"
        );
        assert!(msg.contains("address"), "message must name address: {msg}");
        assert!(msg.contains("port"), "message must name port: {msg}");
    }

    #[test]
    fn fake_endpoint_detour_is_unsupported() {
        let cfg = fake_json(
            r#"{"type":"wireguard","tag":"wg-fake","detour":"wg2","private_key":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=","address":["10.0.0.2/32"],"peers":[{"public_key":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=","address":"127.0.0.1","port":51820,"allowed_ips":["0.0.0.0/0"]}]}"#,
        );
        let err = parse_wireguard_endpoint(&cfg, &[]).expect_err("detour must fail");
        assert!(
            matches!(err, TransportError::Unsupported { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn fake_reserved_wrong_length_is_validation() {
        let cfg = fake_json(
            r#"{"type":"wireguard","tag":"wg-fake","private_key":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=","address":["10.0.0.2/32"],"peers":[{"public_key":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=","address":"127.0.0.1","port":51820,"allowed_ips":["0.0.0.0/0"],"reserved":[0,0]}]}"#,
        );
        let msg = validation_msg(
            parse_wireguard_endpoint(&cfg, &[]).expect_err("reserved len must fail"),
        );
        assert!(
            msg.contains("reserved"),
            "message must name the field: {msg}"
        );
    }

    // (f) No leakage: fake key strings appear NOWHERE in any
    // Display/Debug/error string. The fake keys are [0xAA; 32]
    // (private) and [0xBB; 32] (preshared), encoded with the same
    // Std base64 the config layer accepts.
    #[test]
    fn fake_debug_and_errors_never_print_fake_keys() {
        use base64::engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD};
        let priv_b64 = BASE64_STD.encode([0xAAu8; 32]);
        let psk_b64 = BASE64_STD.encode([0xBBu8; 32]);
        let pub_b64 = BASE64_STD.encode([0x22u8; 32]);
        // Other encodings of the same bytes: hex, URL-safe
        // base64 (padded and unpadded). No prod path produces
        // them today, but the catch must not depend on that.
        let hex_of = |key: [u8; 32]| -> String { key.iter().map(|b| format!("{b:02x}")).collect() };
        let priv_hex = hex_of([0xAAu8; 32]);
        let psk_hex = hex_of([0xBBu8; 32]);
        let pub_hex = hex_of([0x22u8; 32]);
        let priv_b64url = URL_SAFE.encode([0xAAu8; 32]);
        let psk_b64url = URL_SAFE.encode([0xBBu8; 32]);
        let priv_b64url_nopad = URL_SAFE_NO_PAD.encode([0xAAu8; 32]);
        let psk_b64url_nopad = URL_SAFE_NO_PAD.encode([0xBBu8; 32]);
        let mut cfg = fake_cfg();
        cfg.private_key = [0xAA; 32];
        cfg.peers[0].preshared_key = Some([0xBB; 32]);
        let dialer = WireGuardDialer::new(cfg.clone()).expect("fake cfg valid");
        let missing_key_err = WireGuardDialer::new(WireGuardConfig {
            private_key: [0u8; 32],
            ..cfg.clone()
        })
        .expect_err("missing key must fail");
        // A `system:true` error built from JSON that CARRIES the
        // fake keys must not echo them either.
        let sys_cfg = parse_wireguard_endpoint(
            &fake_json(&format!(
                r#"{{"type":"wireguard","tag":"wg-fake","system":true,"private_key":"{priv_b64}","address":["10.0.0.2/32"],"peers":[{{"public_key":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=","address":"127.0.0.1","port":51820,"allowed_ips":["0.0.0.0/0"],"pre_shared_key":"{psk_b64}"}}]}}"#
            )),
            &[],
        )
        .expect("parse ok; new() rejects system:true");
        let sys_err = WireGuardDialer::new(sys_cfg).expect_err("system:true must fail");
        for text in [
            format!("{cfg:?}"),
            format!("{:?}", cfg.peers[0]),
            format!("{dialer:?}"),
            format!("{missing_key_err}"),
            format!("{sys_err}"),
        ] {
            assert!(
                !text.contains(&priv_b64),
                "leaked fake private key in: {text}"
            );
            assert!(
                !text.contains(&psk_b64),
                "leaked fake preshared key in: {text}"
            );
            // A derived Debug would print the raw bytes as
            // decimals ("170, 170, ..." for [0xAA; 32],
            // "187, 187, ..." for [0xBB; 32], "34, 34, ..." for
            // the [0x22; 32] peer public key) — reconstructable
            // key material in another encoding, so the
            // string-catch covers that form too.
            assert!(
                !text.contains("170, 170"),
                "leaked fake private key bytes in: {text}"
            );
            assert!(
                !text.contains("187, 187"),
                "leaked fake preshared key bytes in: {text}"
            );
            assert!(
                !text.contains("34, 34"),
                "leaked fake peer public key bytes in: {text}"
            );
            for (label, form) in [
                ("private key base64url", priv_b64url.as_str()),
                ("preshared key base64url", psk_b64url.as_str()),
                ("private key base64url-nopad", priv_b64url_nopad.as_str()),
                ("preshared key base64url-nopad", psk_b64url_nopad.as_str()),
                ("private key hex", priv_hex.as_str()),
                ("preshared key hex", psk_hex.as_str()),
                ("peer public key hex", pub_hex.as_str()),
            ] {
                assert!(!text.contains(form), "leaked fake {label} in: {text}");
            }
            // The peer public key's Std-base64 form must not
            // appear either (it is not in the Debug output by
            // design — lengths only).
            assert!(
                !text.contains(&pub_b64),
                "leaked fake peer public key in: {text}"
            );
        }
        // The 0xAA/0xBB keys above encode identically in Std
        // and URL-safe base64 (no `+`/`/` appears), so the
        // URL-safe assertions above would be vacuous without a
        // key whose encodings differ: [0xFF; 32] encodes with
        // `/` in Std and `_` in URL-safe. Prove the two forms
        // differ first, then assert neither appears.
        let ff_std = BASE64_STD.encode([0xFFu8; 32]);
        let ff_url = URL_SAFE.encode([0xFFu8; 32]);
        let ff_url_nopad = URL_SAFE_NO_PAD.encode([0xFFu8; 32]);
        assert_ne!(ff_std, ff_url, "test setup: encodings must differ");
        assert_ne!(ff_std, ff_url_nopad, "test setup: encodings must differ");
        let mut cfg_ff = fake_cfg();
        cfg_ff.private_key = [0xFF; 32];
        let dialer_ff = WireGuardDialer::new(cfg_ff.clone()).expect("fake cfg valid");
        for text in [format!("{cfg_ff:?}"), format!("{dialer_ff:?}")] {
            for (label, form) in [
                ("0xFF key std base64", ff_std.as_str()),
                ("0xFF key base64url", ff_url.as_str()),
                ("0xFF key base64url-nopad", ff_url_nopad.as_str()),
                ("0xFF key hex", hex_of([0xFFu8; 32]).as_str()),
            ] {
                assert!(!text.contains(form), "leaked fake {label} in: {text}");
            }
            assert!(
                !text.contains("255, 255"),
                "leaked fake key bytes in: {text}"
            );
        }
    }

    // DNS codec: encode → hand-built response → parse.
    #[test]
    fn fake_dns_codec_roundtrip() {
        let query = dns_encode_query("echo.test", 1, 0x1234).expect("fake query encodes");
        // Response: same txid, QR + RD + RA, 1 question (copied
        // verbatim from the query), 1 A answer for 10.0.0.1.
        let mut resp = Vec::new();
        resp.extend_from_slice(&0x1234u16.to_be_bytes());
        resp.extend_from_slice(&0x8180u16.to_be_bytes());
        resp.extend_from_slice(&1u16.to_be_bytes());
        resp.extend_from_slice(&1u16.to_be_bytes());
        resp.extend_from_slice(&0u16.to_be_bytes());
        resp.extend_from_slice(&0u16.to_be_bytes());
        resp.extend_from_slice(&query[12..]);
        resp.extend_from_slice(&[0xC0, 0x0C]); // name pointer
        resp.extend_from_slice(&1u16.to_be_bytes()); // A
        resp.extend_from_slice(&1u16.to_be_bytes()); // IN
        resp.extend_from_slice(&60u32.to_be_bytes()); // TTL
        resp.extend_from_slice(&4u16.to_be_bytes());
        resp.extend_from_slice(&[10, 0, 0, 1]);
        let ips = dns_parse_response(&resp, 0x1234, 1, "echo.test").expect("fake response parses");
        assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))]);
    }

    #[test]
    fn fake_dns_parse_rejects_wrong_txid() {
        let query = dns_encode_query("echo.test", 1, 0x1234).expect("fake query encodes");
        let mut resp = Vec::new();
        resp.extend_from_slice(&0x1234u16.to_be_bytes());
        resp.extend_from_slice(&0x8180u16.to_be_bytes());
        resp.extend_from_slice(&1u16.to_be_bytes());
        resp.extend_from_slice(&0u16.to_be_bytes());
        resp.extend_from_slice(&0u16.to_be_bytes());
        resp.extend_from_slice(&0u16.to_be_bytes());
        resp.extend_from_slice(&query[12..]);
        assert!(
            dns_parse_response(&resp, 0x9999, 1, "echo.test").is_none(),
            "wrong txid must not parse"
        );
    }

    #[test]
    fn fake_dns_parse_cname_without_address_is_empty() {
        let query = dns_encode_query("echo.test", 1, 0x1234).expect("fake query encodes");
        let mut resp = Vec::new();
        resp.extend_from_slice(&0x1234u16.to_be_bytes());
        resp.extend_from_slice(&0x8180u16.to_be_bytes());
        resp.extend_from_slice(&1u16.to_be_bytes());
        resp.extend_from_slice(&1u16.to_be_bytes());
        resp.extend_from_slice(&0u16.to_be_bytes());
        resp.extend_from_slice(&0u16.to_be_bytes());
        resp.extend_from_slice(&query[12..]);
        resp.extend_from_slice(&[0xC0, 0x0C]);
        resp.extend_from_slice(&5u16.to_be_bytes()); // CNAME
        resp.extend_from_slice(&1u16.to_be_bytes());
        resp.extend_from_slice(&60u32.to_be_bytes());
        resp.extend_from_slice(&2u16.to_be_bytes());
        resp.extend_from_slice(&[0xC0, 0x0C]);
        let ips = dns_parse_response(&resp, 0x1234, 1, "echo.test").expect("fake response parses");
        assert!(
            ips.is_empty(),
            "CNAME without an address record must yield no IP (not chased)"
        );
    }

    #[test]
    fn fake_dns_encode_rejects_bad_names() {
        assert!(dns_encode_query("", 1, 1).is_none());
        assert!(dns_encode_query("bad name.test", 1, 1).is_none());
        assert!(dns_encode_query(&"a".repeat(64), 1, 1).is_none());
    }

    // Prefix parsing: sing-box JSON is CIDR-only.
    #[test]
    fn fake_parse_prefix_rules() {
        let p = parse_prefix("10.0.0.2/32", "address").expect("fake /32 parses");
        assert!(p.contains(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))));
        assert!(!p.contains(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3))));
        let err = parse_prefix("10.0.0.2", "address").expect_err("bare IP must fail");
        assert!(format!("{err}").contains("bare IP"), "got {err}");
        assert!(parse_prefix("10.0.0.2/33", "address").is_err());
        assert!(parse_prefix("2001:db8::1/128", "address").is_ok());
        assert!(
            !parse_prefix("0.0.0.0/0", "address")
                .expect("fake /0 parses")
                .contains(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)))
        );
    }

    // (S8) `Prefix::contains` with a directly-constructed
    // out-of-range length matches nothing instead of
    // underflowing the shift (debug panic / release wrap).
    #[test]
    fn fake_prefix_contains_rejects_oversize_len() {
        let v4_over = Prefix {
            addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
            prefix_len: 33,
        };
        assert!(!v4_over.contains(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        // The guard's load-bearing case: without it the `>= 32`
        // branch below would return `net == addr` (true) for an
        // out-of-range prefix, i.e. a /33 would "contain" its
        // own network address. An invalid prefix matches nothing.
        assert!(!v4_over.contains(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0))));
        let v6_over = Prefix {
            addr: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0)),
            prefix_len: 129,
        };
        assert!(!v6_over.contains(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))));
        assert!(!v6_over.contains(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0))));
        // And `/0` still contains its own family (the path the
        // old shift bug broke).
        let v4_zero = Prefix {
            addr: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            prefix_len: 0,
        };
        assert!(v4_zero.contains(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
    }

    // (S1) `parse_prefix` errors name the FIELD, never the
    // value: a distinctive value must not appear in the message.
    #[test]
    fn fake_parse_prefix_errors_name_field_not_value() {
        for bad in ["192.0.2.99", "192.0.2.99/99", "not-a-prefix"] {
            let err = parse_prefix(bad, "allowed_ips").expect_err("bad prefix must fail");
            let text = format!("{err}");
            assert!(text.contains("allowed_ips"), "got {text}");
            assert!(!text.contains("192.0.2.99"), "value leaked: {text}");
            assert!(!text.contains("not-a-prefix"), "value leaked: {text}");
        }
    }

    // (NB19) Go's `base64.StdEncoding` rejects surrounding
    // whitespace, so a padded key is a Validation here too.
    #[test]
    fn fake_decode_key_32_rejects_surrounding_whitespace() {
        let cfg = fake_json(
            r#"{"type":"wireguard","tag":"wg-fake","private_key":" AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE= ","address":["10.0.0.2/32"],"peers":[{"public_key":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=","address":"127.0.0.1","port":51820,"allowed_ips":["0.0.0.0/0"]}]}"#,
        );
        let msg =
            validation_msg(parse_wireguard_endpoint(&cfg, &[]).expect_err("padded key must fail"));
        assert!(msg.contains("private_key"), "got {msg}");
    }

    // (T3) sing-box `Listable` shorthand: a bare string is a
    // one-element list for `address` and `allowed_ips`.
    #[test]
    fn fake_listable_single_string_address_and_allowed_ips() {
        let cfg = fake_json(
            r#"{"type":"wireguard","tag":"wg-fake","private_key":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=","address":"10.0.0.2/32","peers":[{"public_key":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=","address":"127.0.0.1","port":51820,"allowed_ips":"0.0.0.0/0"}]}"#,
        );
        let parsed = parse_wireguard_endpoint(&cfg, &[]).expect("shorthand must parse");
        assert_eq!(parsed.address.len(), 1);
        assert_eq!(parsed.peers[0].allowed_ips.len(), 1);
        WireGuardDialer::new(parsed).expect("shorthand config must build a dialer");
        // The array form still works (regression guard).
        let cfg_arr = fake_json(
            r#"{"type":"wireguard","tag":"wg-fake","private_key":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=","address":["10.0.0.2/32"],"peers":[{"public_key":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=","address":"127.0.0.1","port":51820,"allowed_ips":["0.0.0.0/0"]}]}"#,
        );
        parse_wireguard_endpoint(&cfg_arr, &[]).expect("array form must still parse");
    }

    // (R-B3) Wrong-typed optional fields are `Validation`
    // naming the field, never silent defaults. One test per
    // field; each JSON differs from the valid shape in exactly
    // that field.
    fn fake_valid_endpoint_json() -> String {
        r#"{"type":"wireguard","tag":"wg-fake","private_key":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=","address":["10.0.0.2/32"],"peers":[{"public_key":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=","address":"127.0.0.1","port":51820,"allowed_ips":["0.0.0.0/0"]}]}"#.to_string()
    }

    #[test]
    fn fake_wrong_typed_mtu_is_validation() {
        for bad in [r#""9000""#, "-1", "1408.0", "true"] {
            let json = fake_valid_endpoint_json().replacen(
                r#""address":["10.0.0.2/32"]"#,
                &format!(r#""address":["10.0.0.2/32"],"mtu":{bad}"#),
                1,
            );
            let msg = validation_msg(
                parse_wireguard_endpoint(&fake_json(&json), &[])
                    .expect_err("wrong-typed mtu must fail"),
            );
            assert!(msg.contains("mtu"), "mtu={bad}: got {msg}");
        }
    }

    #[test]
    fn fake_wrong_typed_keepalive_is_validation() {
        let json = fake_valid_endpoint_json().replacen(
            r#""port":51820"#,
            r#""port":51820,"persistent_keepalive_interval":"25""#,
            1,
        );
        let msg = validation_msg(
            parse_wireguard_endpoint(&fake_json(&json), &[])
                .expect_err("wrong-typed keepalive must fail"),
        );
        assert!(msg.contains("persistent_keepalive_interval"), "got {msg}");
        let json = fake_valid_endpoint_json().replacen(
            r#""port":51820"#,
            r#""port":51820,"persistent_keepalive_interval":-1"#,
            1,
        );
        let msg = validation_msg(
            parse_wireguard_endpoint(&fake_json(&json), &[])
                .expect_err("negative keepalive must fail"),
        );
        assert!(msg.contains("persistent_keepalive_interval"), "got {msg}");
    }

    #[test]
    fn fake_wrong_typed_listen_port_and_system_is_validation() {
        let json = fake_valid_endpoint_json().replacen(
            r#""address":["10.0.0.2/32"]"#,
            r#""address":["10.0.0.2/32"],"listen_port":"51820""#,
            1,
        );
        let msg = validation_msg(
            parse_wireguard_endpoint(&fake_json(&json), &[])
                .expect_err("wrong-typed listen_port must fail"),
        );
        assert!(msg.contains("listen_port"), "got {msg}");
        let json = fake_valid_endpoint_json().replacen(
            r#""tag":"wg-fake""#,
            r#""tag":"wg-fake","system":"true""#,
            1,
        );
        let msg = validation_msg(
            parse_wireguard_endpoint(&fake_json(&json), &[])
                .expect_err("wrong-typed system must fail"),
        );
        assert!(msg.contains("system"), "got {msg}");
    }

    #[test]
    fn fake_wrong_typed_reserved_and_detour_is_validation() {
        let json = fake_valid_endpoint_json().replacen(
            r#""port":51820"#,
            r#""port":51820,"reserved":"abc""#,
            1,
        );
        let msg = validation_msg(
            parse_wireguard_endpoint(&fake_json(&json), &[])
                .expect_err("non-array reserved must fail"),
        );
        assert!(msg.contains("reserved"), "got {msg}");
        let json = fake_valid_endpoint_json().replacen(
            r#""tag":"wg-fake""#,
            r#""tag":"wg-fake","detour":123"#,
            1,
        );
        let msg = validation_msg(
            parse_wireguard_endpoint(&fake_json(&json), &[])
                .expect_err("non-string detour must fail"),
        );
        assert!(msg.contains("detour"), "got {msg}");
    }

    #[test]
    fn fake_non_string_array_element_is_validation() {
        let json = fake_valid_endpoint_json().replacen(
            r#""address":["10.0.0.2/32"]"#,
            r#""address":["10.0.0.2/32",123]"#,
            1,
        );
        let msg = validation_msg(
            parse_wireguard_endpoint(&fake_json(&json), &[])
                .expect_err("non-string address element must fail"),
        );
        assert!(msg.contains("address"), "got {msg}");
        let json = fake_valid_endpoint_json().replacen(
            r#""allowed_ips":["0.0.0.0/0"]"#,
            r#""allowed_ips":["0.0.0.0/0",true]"#,
            1,
        );
        let msg = validation_msg(
            parse_wireguard_endpoint(&fake_json(&json), &[])
                .expect_err("non-string allowed_ips element must fail"),
        );
        assert!(msg.contains("allowed_ips"), "got {msg}");
    }

    // (NB2) DNS response validation: a truncated response, a
    // response for a different question name, and a response
    // for a different qtype all parse to `None`.
    fn fake_dns_response(
        txid: u16,
        flags: u16,
        qname: &str,
        qtype: u16,
        answer_ip: [u8; 4],
    ) -> Vec<u8> {
        let query = dns_encode_query(qname, qtype, txid).expect("fake query encodes");
        let mut resp = Vec::new();
        resp.extend_from_slice(&txid.to_be_bytes());
        resp.extend_from_slice(&flags.to_be_bytes());
        resp.extend_from_slice(&1u16.to_be_bytes());
        resp.extend_from_slice(&1u16.to_be_bytes());
        resp.extend_from_slice(&0u16.to_be_bytes());
        resp.extend_from_slice(&0u16.to_be_bytes());
        resp.extend_from_slice(&query[12..]);
        resp.extend_from_slice(&[0xC0, 0x0C]);
        resp.extend_from_slice(&1u16.to_be_bytes());
        resp.extend_from_slice(&1u16.to_be_bytes());
        resp.extend_from_slice(&60u32.to_be_bytes());
        resp.extend_from_slice(&4u16.to_be_bytes());
        resp.extend_from_slice(&answer_ip);
        resp
    }

    #[test]
    fn fake_dns_parse_rejects_truncated_wrong_name_and_wrong_qtype() {
        // Truncated (TC bit set) with an otherwise valid answer.
        let resp = fake_dns_response(0x1234, 0x8380, "echo.test", 1, [10, 0, 0, 1]);
        assert!(
            dns_parse_response(&resp, 0x1234, 1, "echo.test").is_none(),
            "truncated response must not parse"
        );
        // Right txid/qtype, wrong question name.
        let resp = fake_dns_response(0x1234, 0x8180, "other.test", 1, [10, 0, 0, 1]);
        assert!(
            dns_parse_response(&resp, 0x1234, 1, "echo.test").is_none(),
            "response for another name must not parse"
        );
        // Right name, question asked for AAAA while we asked A.
        let resp = fake_dns_response(0x1234, 0x8180, "echo.test", 28, [10, 0, 0, 1]);
        assert!(
            dns_parse_response(&resp, 0x1234, 1, "echo.test").is_none(),
            "response for another qtype must not parse"
        );
        // Control: the same bytes with matching name/qtype and
        // no TC bit parse fine.
        let resp = fake_dns_response(0x1234, 0x8180, "echo.test", 1, [10, 0, 0, 1]);
        let ips = dns_parse_response(&resp, 0x1234, 1, "echo.test").expect("control parses");
        assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))]);
    }

    // (S6) A hostname DNS server entry with a `:port` suffix is
    // resolved by stripping the port first (the query port is
    // always 53 — Go parity). `localhost:5353` must resolve to a
    // loopback address; without the strip the bootstrap lookup of
    // "localhost:5353" fails. (`localhost` resolves via /etc/hosts
    // on any Linux; either family is accepted.)
    #[tokio::test]
    async fn fake_dns_server_ip_strips_port_for_hostname() {
        let dialer = WireGuardDialer::new(fake_cfg()).expect("fake cfg valid");
        let ip = dialer
            .dns_server_ip("localhost:5353")
            .await
            .expect("localhost:5353 must resolve after stripping the port");
        assert!(
            ip == IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)) || ip == IpAddr::V6(Ipv6Addr::LOCALHOST),
            "localhost must resolve to a loopback address, got {ip}"
        );
    }

    // (T-NB6) Ephemeral-port counter transitions, including the
    // u16 wrap: the pure transition is what the CAS loop
    // applies, so these cases pin the wrap behaviour exactly.
    #[test]
    fn fake_ephemeral_port_transition_at_wrap() {
        assert_eq!(next_ephemeral_port_transition(49152), (49152, 49153));
        assert_eq!(next_ephemeral_port_transition(49153), (49153, 49154));
        assert_eq!(next_ephemeral_port_transition(65534), (65534, 65535));
        assert_eq!(next_ephemeral_port_transition(65535), (65535, 49152));
        // Out-of-range stored values (only reachable transiently
        // at the wrap) restart at the bottom of the range.
        assert_eq!(next_ephemeral_port_transition(0), (49152, 49153));
        assert_eq!(next_ephemeral_port_transition(49151), (49152, 49153));
    }
}
