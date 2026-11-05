// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! M3d data-path tests: a REAL in-process WireGuard peer
//! (boringtun `Tunn` + smoltcp server stack + TCP echo) against
//! the production `WireGuardDialer`, over loopback UDP only.
//! No root, no TUN device, no real WireGuard peer outside the
//! process (see PORTING.md §M3d "Chưa kiểm chứng").
//!
//! All keys are fixed FAKE seeds (repeated bytes), never real
//! key material. Test names carry the `fake_` prefix so a grep
//! for key material finds them as test-only.

use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use smoltcp::iface::{Config as IfaceConfig, Interface, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp as smol_tcp;
use smoltcp::socket::udp as smol_udp;
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;

use castctl_transport::dialer::{DialTarget, Dialer};
use castctl_transport::error::TransportError;
use castctl_transport::wireguard::{
    Prefix, WIREGUARD_MIN_DATAGRAM, WireGuardConfig, WireGuardDialer, WireGuardPeerConfig,
};
use honk_outbound::AsyncReadWrite;

/// Fake tunnel addresses: server 10.0.0.1/32, client 10.0.0.2/32.
const FAKE_SERVER_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const FAKE_CLIENT_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
/// Fake key seeds (repeated bytes — obviously not real keys).
const FAKE_CLIENT_SECRET: [u8; 32] = [0x11; 32];
const FAKE_SERVER_SECRET: [u8; 32] = [0x22; 32];
const FAKE_PSK: [u8; 32] = [0x33; 32];

/// In-memory smoltcp device for the test server (mirrors the
/// dialer's `QueueDevice`; test-local copy so the test does not
/// depend on the dialer's private internals).
struct FakeTestDevice {
    rx_queue: VecDeque<Vec<u8>>,
    tx_queue: VecDeque<Vec<u8>>,
    mtu: usize,
}

struct FakeTestRxToken(Vec<u8>);
struct FakeTestTxToken<'a> {
    queue: &'a mut VecDeque<Vec<u8>>,
}

impl RxToken for FakeTestRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0)
    }
}

impl TxToken for FakeTestTxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buf = vec![0u8; len];
        let out = f(&mut buf);
        self.queue.push_back(buf);
        out
    }
}

impl Device for FakeTestDevice {
    type RxToken<'a> = FakeTestRxToken;
    type TxToken<'a> = FakeTestTxToken<'a>;

    fn receive(
        &mut self,
        _timestamp: SmolInstant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let packet = self.rx_queue.pop_front()?;
        Some((
            FakeTestRxToken(packet),
            FakeTestTxToken {
                queue: &mut self.tx_queue,
            },
        ))
    }

    fn transmit(&mut self, _timestamp: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(FakeTestTxToken {
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

/// The fake server: boringtun peer + smoltcp stack + TCP echo on
/// 10.0.0.1:80, optionally a minimal DNS responder on 10.0.0.1:53
/// (answers A → 10.0.0.1, AAAA → no records).
struct FakeWgServer {
    udp_addr: SocketAddr,
    datagrams: Arc<AtomicUsize>,
    tcp_accepts: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    join: JoinHandle<()>,
}

impl Drop for FakeWgServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        self.join.abort();
    }
}

struct FakeServerState {
    udp: UdpSocket,
    tunn: Tunn,
    device: FakeTestDevice,
    iface: Interface,
    sockets: SocketSet<'static>,
    tcp_handle: smoltcp::iface::SocketHandle,
    dns_handle: Option<smoltcp::iface::SocketHandle>,
    peer: Option<SocketAddr>,
    accepted_counted: bool,
    /// Echo bytes received but not yet queued into smoltcp
    /// (the socket buffer was full): retried next cycle, never
    /// dropped — dropping would corrupt the echo assertion.
    pending_echo: Vec<u8>,
    datagrams: Arc<AtomicUsize>,
    tcp_accepts: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    started: Instant,
    last_timers: Instant,
}

impl FakeWgServer {
    /// Start a server. `psk`: the server's preshared key
    /// (`None` = no PSK). `with_dns`: also answer DNS on
    /// 10.0.0.1:53.
    async fn start(psk: Option<[u8; 32]>, with_dns: bool) -> Self {
        let udp = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .expect("fake server udp bind");
        let udp_addr = udp.local_addr().expect("fake server local addr");
        let client_pub = PublicKey::from(&StaticSecret::from(FAKE_CLIENT_SECRET));
        let tunn = Tunn::new(
            StaticSecret::from(FAKE_SERVER_SECRET),
            client_pub,
            psk,
            None,
            2,
            None,
        );
        let mut device = FakeTestDevice {
            rx_queue: VecDeque::new(),
            tx_queue: VecDeque::new(),
            mtu: 1408,
        };
        let mut iface = Interface::new(
            IfaceConfig::new(HardwareAddress::Ip),
            &mut device,
            SmolInstant::from_millis(0),
        );
        iface.update_ip_addrs(|list| {
            let _ = list.push(IpCidr::new(IpAddress::from(FAKE_SERVER_IP), 32));
        });
        let _ = iface.routes_mut().add_default_ipv4_route(FAKE_SERVER_IP);
        let mut sockets = SocketSet::new(vec![]);
        let rx = smol_tcp::SocketBuffer::new(vec![0u8; 65536]);
        let tx = smol_tcp::SocketBuffer::new(vec![0u8; 65536]);
        let tcp_handle = sockets.add(smol_tcp::Socket::new(rx, tx));
        let dns_handle = if with_dns {
            let rx = smol_udp::PacketBuffer::new(
                vec![smol_udp::PacketMetadata::EMPTY; 4],
                vec![0u8; 2048],
            );
            let tx = smol_udp::PacketBuffer::new(
                vec![smol_udp::PacketMetadata::EMPTY; 4],
                vec![0u8; 2048],
            );
            let mut socket = smol_udp::Socket::new(rx, tx);
            socket
                .bind((IpAddress::from(FAKE_SERVER_IP), 53))
                .expect("fake dns bind");
            Some(sockets.add(socket))
        } else {
            None
        };
        let datagrams = Arc::new(AtomicUsize::new(0));
        let tcp_accepts = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let state = FakeServerState {
            udp,
            tunn,
            device,
            iface,
            sockets,
            tcp_handle,
            dns_handle,
            peer: None,
            accepted_counted: false,
            pending_echo: Vec::new(),
            datagrams: Arc::clone(&datagrams),
            tcp_accepts: Arc::clone(&tcp_accepts),
            stop: Arc::clone(&stop),
            started: Instant::now(),
            last_timers: Instant::now(),
        };
        let join = tokio::spawn(run_fake_server(state));
        Self {
            udp_addr,
            datagrams,
            tcp_accepts,
            stop,
            join,
        }
    }
}

async fn run_fake_server(mut st: FakeServerState) {
    let mut udp_buf = vec![0u8; 2048];
    let mut outbox: Vec<Vec<u8>> = Vec::new();
    loop {
        if st.stop.load(Ordering::SeqCst) {
            break;
        }
        let now = SmolInstant::from_millis(st.started.elapsed().as_millis() as i64);
        let delay = st
            .iface
            .poll_delay(now, &st.sockets)
            .map(|d| Duration::from_millis(d.total_millis().max(0) as u64))
            .unwrap_or(Duration::from_millis(100))
            .min(Duration::from_millis(100));
        tokio::select! {
            res = st.udp.recv_from(&mut udp_buf) => {
                match res {
                    Ok((n, src)) => {
                        st.datagrams.fetch_add(1, Ordering::SeqCst);
                        st.peer = Some(src);
                        // Decapsulate loop (same contract as the
                        // dialer: repeat with an empty datagram
                        // until `Done`).
                        let mut next: Option<Vec<u8>> = Some(udp_buf[..n].to_vec());
                        let mut wg_buf = vec![0u8; 2048];
                        loop {
                            let r = match &next {
                                Some(d) => st.tunn.decapsulate(None, d, &mut wg_buf),
                                None => st.tunn.decapsulate(None, &[], &mut wg_buf),
                            };
                            next = None;
                            match r {
                                TunnResult::Done => break,
                                TunnResult::WriteToNetwork(b) => outbox.push(b.to_vec()),
                                TunnResult::WriteToTunnelV4(b, _) | TunnResult::WriteToTunnelV6(b, _) => {
                                    st.device.rx_queue.push_back(b.to_vec());
                                }
                                TunnResult::Err(e) => panic!("fake server decapsulate: {e:?}"),
                            }
                        }
                    }
                    Err(_) => break,
                }
            }
            () = tokio::time::sleep(delay) => {}
        }
        // One synchronous service step: poll smoltcp, echo TCP,
        // answer DNS, drain device egress through boringtun.
        let now = SmolInstant::from_millis(st.started.elapsed().as_millis() as i64);
        st.iface.poll(now, &mut st.device, &mut st.sockets);
        // TCP echo.
        {
            use smoltcp::socket::tcp::State;
            let sock = st.sockets.get_mut::<smol_tcp::Socket>(st.tcp_handle);
            match sock.state() {
                State::Closed => {
                    st.accepted_counted = false;
                    let _ = sock.listen((IpAddress::from(FAKE_SERVER_IP), 80));
                }
                State::Established => {
                    if !st.accepted_counted {
                        st.accepted_counted = true;
                        st.tcp_accepts.fetch_add(1, Ordering::SeqCst);
                    }
                    // Flush previously-received echo bytes first.
                    if !st.pending_echo.is_empty() {
                        let n = sock.send_slice(&st.pending_echo).unwrap_or(0);
                        st.pending_echo.drain(..n);
                    }
                    // Then receive more (bounded per cycle).
                    let mut chunks = 0;
                    while chunks < 4 && sock.may_recv() && st.pending_echo.is_empty() {
                        let mut buf = [0u8; 8192];
                        match sock.recv_slice(&mut buf) {
                            Ok(0) => break,
                            Ok(n) => {
                                chunks += 1;
                                st.pending_echo.extend_from_slice(&buf[..n]);
                                let m = sock.send_slice(&st.pending_echo).unwrap_or(0);
                                st.pending_echo.drain(..m);
                            }
                            Err(smol_tcp::RecvError::Finished) => {
                                sock.close();
                                break;
                            }
                            Err(smol_tcp::RecvError::InvalidState) => break,
                        }
                    }
                }
                _ => {}
            }
        }
        // DNS responder (A → 10.0.0.1, AAAA → no records).
        if let Some(handle) = st.dns_handle {
            let sock = st.sockets.get_mut::<smol_udp::Socket>(handle);
            let mut buf = [0u8; 2048];
            loop {
                match sock.recv_slice(&mut buf) {
                    Ok((n, meta)) => {
                        if n < 16 {
                            continue;
                        }
                        let qtype = u16::from_be_bytes([buf[n - 4], buf[n - 3]]);
                        let txid = [buf[0], buf[1]];
                        let ancount: u16 = if qtype == 1 { 1 } else { 0 };
                        let mut resp = Vec::new();
                        resp.extend_from_slice(&txid);
                        resp.extend_from_slice(&0x8180u16.to_be_bytes());
                        resp.extend_from_slice(&1u16.to_be_bytes());
                        resp.extend_from_slice(&ancount.to_be_bytes());
                        resp.extend_from_slice(&0u16.to_be_bytes());
                        resp.extend_from_slice(&0u16.to_be_bytes());
                        resp.extend_from_slice(&buf[12..n]);
                        if qtype == 1 {
                            resp.extend_from_slice(&[0xC0, 0x0C]);
                            resp.extend_from_slice(&1u16.to_be_bytes());
                            resp.extend_from_slice(&1u16.to_be_bytes());
                            resp.extend_from_slice(&60u32.to_be_bytes());
                            resp.extend_from_slice(&4u16.to_be_bytes());
                            resp.extend_from_slice(&FAKE_SERVER_IP.octets());
                        }
                        let reply_meta = smol_udp::UdpMetadata {
                            endpoint: meta.endpoint,
                            local_address: None,
                            meta: smoltcp::phy::PacketMeta::default(),
                        };
                        let _ = sock.send_slice(&resp, reply_meta);
                    }
                    Err(_) => break,
                }
            }
        }
        // Drain device egress through boringtun. Same minimum as
        // the dialer: a session-less `encapsulate` formats a
        // 148-byte handshake initiation into this buffer.
        while let Some(packet) = st.device.tx_queue.pop_front() {
            let mut wg_buf = vec![0u8; (packet.len() + 32).max(WIREGUARD_MIN_DATAGRAM)];
            match st.tunn.encapsulate(&packet, &mut wg_buf) {
                TunnResult::WriteToNetwork(b) => outbox.push(b.to_vec()),
                TunnResult::Done => {}
                TunnResult::Err(e) => panic!("fake server encapsulate: {e:?}"),
                TunnResult::WriteToTunnelV4(..) | TunnResult::WriteToTunnelV6(..) => {
                    panic!("fake server encapsulate returned a tunnel packet")
                }
            }
        }
        // Boringtun timers (retransmit; no keepalive on the server).
        if st.last_timers.elapsed() >= Duration::from_millis(100) {
            st.last_timers = Instant::now();
            let mut wg_buf = vec![0u8; 148];
            if let TunnResult::WriteToNetwork(b) = st.tunn.update_timers(&mut wg_buf) {
                outbox.push(b.to_vec());
            }
        }
        // Flush egress to the client.
        if let Some(peer) = st.peer {
            for bytes in outbox.drain(..) {
                if st.udp.send_to(&bytes, peer).await.is_err() {
                    break;
                }
            }
        } else {
            outbox.clear();
        }
    }
}

/// Client config for the fake server: the peer public key is the
/// server secret's derived public key; `psk` must match the
/// server's (both `Some` with the same bytes, or both `None`).
fn fake_client_cfg(
    server: &FakeWgServer,
    psk: Option<[u8; 32]>,
    keepalive: u16,
    allowed_ips: Vec<Prefix>,
    dns_servers: Vec<String>,
) -> WireGuardConfig {
    let server_pub = PublicKey::from(&StaticSecret::from(FAKE_SERVER_SECRET));
    WireGuardConfig {
        tag: "wg-fake-test".to_string(),
        system: false,
        address: vec![Prefix {
            addr: IpAddr::V4(FAKE_CLIENT_IP),
            prefix_len: 32,
        }],
        private_key: FAKE_CLIENT_SECRET,
        mtu: 0,
        listen_port: None,
        peers: vec![WireGuardPeerConfig {
            endpoint_host: "127.0.0.1".to_string(),
            endpoint_port: server.udp_addr.port(),
            public_key: *server_pub.as_bytes(),
            preshared_key: psk,
            allowed_ips,
            persistent_keepalive: keepalive,
            reserved: [0, 0, 0],
        }],
        dns_servers,
        dial_timeout: Duration::from_secs(5),
    }
}

fn fake_allow_all() -> Vec<Prefix> {
    vec![Prefix {
        addr: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
        prefix_len: 0,
    }]
}

async fn fake_echo(stream: &mut Box<dyn AsyncReadWrite>, payload: &[u8]) {
    stream.write_all(payload).await.expect("fake write");
    let mut got = vec![0u8; payload.len()];
    stream.read_exact(&mut got).await.expect("fake read");
    assert_eq!(got, payload, "echo must return the exact bytes");
}

// (b) Data path REAL: boringtun server + smoltcp echo, client =
// the production dialer. Small echo + a 64 KiB payload across
// MTU 1408, bytes intact.
#[tokio::test]
async fn fake_wireguard_tcp_echo_small_and_64k() {
    let server = FakeWgServer::start(None, false).await;
    let dialer = WireGuardDialer::new(fake_client_cfg(&server, None, 0, fake_allow_all(), vec![]))
        .expect("fake client cfg valid");
    let mut stream = dialer
        .dial(&DialTarget::new("10.0.0.1", 80))
        .await
        .expect("fake dial works");
    fake_echo(&mut stream, b"hello-wireguard").await;
    let big: Vec<u8> = (0..65536).map(|i| (i % 251) as u8).collect();
    fake_echo(&mut stream, &big).await;
    drop(stream);
    assert!(
        server.datagrams.load(Ordering::SeqCst) > 0,
        "packets must flow"
    );
    assert_eq!(
        server.tcp_accepts.load(Ordering::SeqCst),
        1,
        "exactly one TCP connection"
    );
}

// (b) Keepalive: a short persistent_keepalive (1 s) keeps the
// tunnel alive across ~2.5 s idle — liveness only, NOT an exact
// packet count.
#[tokio::test]
async fn fake_wireguard_keepalive_survives_idle() {
    let server = FakeWgServer::start(None, false).await;
    let dialer = WireGuardDialer::new(fake_client_cfg(&server, None, 1, fake_allow_all(), vec![]))
        .expect("fake client cfg valid");
    let mut stream = dialer
        .dial(&DialTarget::new("10.0.0.1", 80))
        .await
        .expect("fake dial works");
    fake_echo(&mut stream, b"before-idle").await;
    drop(stream);
    tokio::time::sleep(Duration::from_millis(2500)).await;
    let mut stream = dialer
        .dial(&DialTarget::new("10.0.0.1", 80))
        .await
        .expect("fake dial after idle works");
    fake_echo(&mut stream, b"after-idle").await;
}

// (e) PSK present on both sides echoes; PSK absent on both sides
// echoes.
#[tokio::test]
async fn fake_wireguard_psk_present_and_absent_both_echo() {
    for psk in [Some(FAKE_PSK), None] {
        let server = FakeWgServer::start(psk, false).await;
        let dialer =
            WireGuardDialer::new(fake_client_cfg(&server, psk, 0, fake_allow_all(), vec![]))
                .expect("fake client cfg valid");
        let mut stream = dialer
            .dial(&DialTarget::new("10.0.0.1", 80))
            .await
            .expect("fake dial with matching PSK works");
        fake_echo(&mut stream, b"psk-echo").await;
    }
}

// (e) Negative: client PSK set, server PSK unset → the handshake
// never completes → dial fails closed (ConnectionDown on timeout).
// This is the proof the PSK is actually wired, not ignored.
#[tokio::test]
async fn fake_wireguard_psk_mismatch_fails_handshake() {
    let server = FakeWgServer::start(None, false).await;
    let mut cfg = fake_client_cfg(&server, Some(FAKE_PSK), 0, fake_allow_all(), vec![]);
    cfg.dial_timeout = Duration::from_secs(2);
    let dialer = WireGuardDialer::new(cfg).expect("fake client cfg valid");
    let started = Instant::now();
    let err = dialer
        .dial(&DialTarget::new("10.0.0.1", 80))
        .await
        .expect_err("PSK mismatch must fail the dial");
    assert!(
        matches!(err, TransportError::ConnectionDown { .. }),
        "got {err:?}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "dial must fail on timeout, not hang"
    );
}

// (g) Allowed-IPs dial-time rejection: target outside
// allowed_ips → ConnectionDown BEFORE any packet is sent (the
// server sees zero datagrams).
#[tokio::test]
async fn fake_wireguard_allowed_ips_rejects_before_any_packet() {
    let server = FakeWgServer::start(None, false).await;
    let allowed = vec![Prefix {
        addr: IpAddr::V4(Ipv4Addr::new(10, 0, 1, 0)),
        prefix_len: 24,
    }];
    let dialer = WireGuardDialer::new(fake_client_cfg(&server, None, 0, allowed, vec![]))
        .expect("fake client cfg valid");
    let err = dialer
        .dial(&DialTarget::new("10.0.0.1", 80))
        .await
        .expect_err("target outside allowed_ips must fail");
    assert!(
        matches!(err, TransportError::ConnectionDown { .. }),
        "got {err:?}"
    );
    assert!(format!("{err}").contains("allowed_ips"), "got {err}");
    assert_eq!(
        server.datagrams.load(Ordering::SeqCst),
        0,
        "no packet may be sent for a rejected target"
    );
}

// Target: domain targets resolve via `wireguard_dns` THROUGH the
// tunnel (the server answers A → 10.0.0.1 on its in-tunnel DNS).
#[tokio::test]
async fn fake_wireguard_dns_through_tunnel_resolves_domain() {
    let server = FakeWgServer::start(None, true).await;
    let dialer = WireGuardDialer::new(fake_client_cfg(
        &server,
        None,
        0,
        fake_allow_all(),
        vec!["10.0.0.1".to_string()],
    ))
    .expect("fake client cfg valid");
    let mut stream = dialer
        .dial(&DialTarget::new("echo.test", 80))
        .await
        .expect("fake domain dial via tunnel DNS works");
    fake_echo(&mut stream, b"dns-echo").await;
}

// No `wireguard_dns` + domain target → fail-closed
// ConnectionDown, never a system-resolver fallback.
#[tokio::test]
async fn fake_wireguard_domain_target_without_dns_fails_closed() {
    let server = FakeWgServer::start(None, false).await;
    let dialer = WireGuardDialer::new(fake_client_cfg(&server, None, 0, fake_allow_all(), vec![]))
        .expect("fake client cfg valid");
    let err = dialer
        .dial(&DialTarget::new("echo.test", 80))
        .await
        .expect_err("domain target without wireguard_dns must fail");
    assert!(
        matches!(err, TransportError::ConnectionDown { .. }),
        "got {err:?}"
    );
}

// D4: a domain PEER endpoint fails closed at first dial (Go
// nil-dereferences without a DNS router instead of bootstrapping;
// the M3d dialer never system-resolves the peer). The peer host
// is "localhost" — which the system resolver WOULD resolve to
// 127.0.0.1 — and a live server is listening on that port, so a
// dialer that system-resolved the peer would SUCCEED and this
// test would fail: the test pins fail-closed, not just "no
// server answered".
#[tokio::test]
async fn fake_wireguard_domain_peer_fails_closed() {
    let server = FakeWgServer::start(None, false).await;
    let mut cfg = fake_client_cfg(&server, None, 0, fake_allow_all(), vec![]);
    cfg.peers[0].endpoint_host = "localhost".to_string();
    cfg.dial_timeout = Duration::from_secs(2);
    let dialer = WireGuardDialer::new(cfg).expect("fake client cfg valid");
    let err = dialer
        .dial(&DialTarget::new("10.0.0.1", 80))
        .await
        .expect_err("domain peer must fail closed");
    assert!(
        matches!(err, TransportError::ConnectionDown { .. }),
        "got {err:?}"
    );
    assert_eq!(
        server.datagrams.load(Ordering::SeqCst),
        0,
        "no packet may be sent to a domain peer"
    );
}
