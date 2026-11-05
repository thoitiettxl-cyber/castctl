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
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::Mutex;
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
/// Fake IPv6 tunnel addresses: server fd00::1/128, client fd00::2/128.
const FAKE_SERVER_IP6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
const FAKE_CLIENT_IP6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);
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
/// 10.0.0.1:80 (or fd00::1:80 for the v6 server), optionally a
/// minimal DNS responder on :53 (v4 server: A → 10.0.0.1, AAAA →
/// no records; v6 server: A → no records, AAAA → fd00::1).
struct FakeWgServer {
    udp_addr: SocketAddr,
    datagrams: Arc<AtomicUsize>,
    tcp_accepts: Arc<AtomicUsize>,
    /// Largest UDP datagram received (payload bytes, no IP/UDP
    /// headers): pins the tunnel MTU observably — with MTU 1408
    /// no datagram may exceed 1408 + 32.
    max_datagram: Arc<AtomicUsize>,
    /// The client's UDP source port, as seen by the server
    /// (0 = no datagram received yet).
    peer_port: Arc<AtomicUsize>,
    /// Raw bytes the server task sends to the client from its
    /// own UDP socket (garbage-injection hook for the R-B4 test).
    inject_tx: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
    /// The last WireGuard DATA packet (type 4) the server sent
    /// to the client, if any — a genuine encrypted packet from
    /// this harness's own UDP traffic (NB-D replay test).
    captured_data: Arc<Mutex<Option<Vec<u8>>>>,
    stop: Arc<AtomicBool>,
    join: JoinHandle<()>,
}

impl FakeWgServer {
    /// Send raw bytes to the client from the server's UDP
    /// socket, so they arrive with the peer as their source.
    fn inject(&self, bytes: &[u8]) {
        let _ = self.inject_tx.send(bytes.to_vec());
    }

    /// The last WireGuard DATA packet the server sent to the
    /// client, if any (see `captured_data`).
    fn captured_data_packet(&self) -> Option<Vec<u8>> {
        self.captured_data.lock().ok().and_then(|g| g.clone())
    }

    /// The client's UDP socket address, as observed by the
    /// server (used to send a spoofed-source datagram at it).
    fn client_addr(&self) -> Option<SocketAddr> {
        let port = self.peer_port.load(Ordering::SeqCst);
        if port == 0 {
            None
        } else {
            Some(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                port as u16,
            ))
        }
    }
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
    /// This server's tunnel address (v4 or v6): TCP listen +
    /// DNS bind + DNS answers use it.
    server_ip: IpAddr,
    peer: Option<SocketAddr>,
    accepted_counted: bool,
    /// The peer's FIN was seen; the server closes only after
    /// `pending_echo` drains — closing immediately would strand
    /// echo bytes still queued (same stall as the dialer's
    /// deferred shutdown: after `close()` nothing more can be
    /// fed into the socket).
    peer_fin_seen: bool,
    /// Echo bytes received but not yet queued into smoltcp
    /// (the socket buffer was full): retried next cycle, never
    /// dropped — dropping would corrupt the echo assertion.
    pending_echo: Vec<u8>,
    datagrams: Arc<AtomicUsize>,
    tcp_accepts: Arc<AtomicUsize>,
    max_datagram: Arc<AtomicUsize>,
    peer_port: Arc<AtomicUsize>,
    inject_rx: tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
    /// Last server→client WireGuard DATA packet (type 4), for
    /// the NB-D replay test (recorded at flush, after a
    /// successful send, so it was genuinely delivered).
    captured_data: Arc<Mutex<Option<Vec<u8>>>>,
    stop: Arc<AtomicBool>,
    started: Instant,
    last_timers: Instant,
}

impl FakeWgServer {
    /// Start a server. `psk`: the server's preshared key
    /// (`None` = no PSK). `with_dns`: also answer DNS on :53.
    async fn start(psk: Option<[u8; 32]>, with_dns: bool) -> Self {
        Self::start_at(
            psk,
            with_dns,
            IpAddr::V4(FAKE_SERVER_IP),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
        )
        .await
    }

    /// Start an IPv6 server (fd00::1, loopback ::1).
    async fn start_v6(psk: Option<[u8; 32]>, with_dns: bool) -> Self {
        Self::start_at(
            psk,
            with_dns,
            IpAddr::V6(FAKE_SERVER_IP6),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        )
        .await
    }

    async fn start_at(
        psk: Option<[u8; 32]>,
        with_dns: bool,
        server_ip: IpAddr,
        loopback: IpAddr,
    ) -> Self {
        let udp = UdpSocket::bind(SocketAddr::new(loopback, 0))
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
        let prefix_len = match server_ip {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        iface.update_ip_addrs(|list| {
            let _ = list.push(IpCidr::new(IpAddress::from(server_ip), prefix_len));
        });
        match server_ip {
            IpAddr::V4(a) => {
                let _ = iface.routes_mut().add_default_ipv4_route(a);
            }
            IpAddr::V6(a) => {
                let _ = iface.routes_mut().add_default_ipv6_route(a);
            }
        }
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
                .bind((IpAddress::from(server_ip), 53))
                .expect("fake dns bind");
            Some(sockets.add(socket))
        } else {
            None
        };
        let datagrams = Arc::new(AtomicUsize::new(0));
        let tcp_accepts = Arc::new(AtomicUsize::new(0));
        let max_datagram = Arc::new(AtomicUsize::new(0));
        let peer_port = Arc::new(AtomicUsize::new(0));
        let (inject_tx, inject_rx) = tokio::sync::mpsc::unbounded_channel();
        let captured_data = Arc::new(Mutex::new(None));
        let stop = Arc::new(AtomicBool::new(false));
        let state = FakeServerState {
            udp,
            tunn,
            device,
            iface,
            sockets,
            tcp_handle,
            dns_handle,
            server_ip,
            peer: None,
            accepted_counted: false,
            peer_fin_seen: false,
            pending_echo: Vec::new(),
            datagrams: Arc::clone(&datagrams),
            tcp_accepts: Arc::clone(&tcp_accepts),
            max_datagram: Arc::clone(&max_datagram),
            peer_port: Arc::clone(&peer_port),
            inject_rx,
            captured_data: Arc::clone(&captured_data),
            stop: Arc::clone(&stop),
            started: Instant::now(),
            last_timers: Instant::now(),
        };
        let join = tokio::spawn(run_fake_server(state));
        Self {
            udp_addr,
            datagrams,
            tcp_accepts,
            max_datagram,
            peer_port,
            inject_tx,
            captured_data,
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
                        st.max_datagram.fetch_max(n, Ordering::SeqCst);
                        st.peer_port.store(src.port() as usize, Ordering::SeqCst);
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
            Some(bytes) = st.inject_rx.recv() => {
                // Raw bytes from the server's own UDP socket to
                // the client (garbage-injection hook): the
                // client sees them as coming from the peer.
                if let Some(peer) = st.peer {
                    let _ = st.udp.send_to(&bytes, peer).await;
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
                    let _ = sock.listen((IpAddress::from(st.server_ip), 80));
                }
                State::Established | State::CloseWait => {
                    if !st.accepted_counted {
                        st.accepted_counted = true;
                        st.tcp_accepts.fetch_add(1, Ordering::SeqCst);
                    }
                    if sock.state() == State::CloseWait {
                        st.peer_fin_seen = true;
                    }
                    // Flush previously-received echo bytes first.
                    if !st.pending_echo.is_empty() {
                        let n = sock.send_slice(&st.pending_echo).unwrap_or(0);
                        st.pending_echo.drain(..n);
                    }
                    // The peer's FIN was seen, every echo byte
                    // is queued, AND the receive buffer is drained:
                    // only now may the FIN go out. (Without the
                    // may_recv() gate the socket could close while
                    // bytes still sat unread in the receive buffer
                    // — the echo arm never runs again after close —
                    // silently losing the tail of the stream.)
                    if st.peer_fin_seen && st.pending_echo.is_empty() && !sock.may_recv() {
                        sock.close();
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
                                // Do NOT close here: echo bytes
                                // may still be queued (see above).
                                st.peer_fin_seen = true;
                                break;
                            }
                            Err(smol_tcp::RecvError::InvalidState) => break,
                        }
                    }
                }
                _ => {}
            }
        }
        // DNS responder: v4 server answers A → its own address
        // (AAAA → no records); v6 server answers AAAA → its own
        // address (A → no records).
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
                        let (ancount, answer): (u16, Vec<u8>) = match (qtype, st.server_ip) {
                            (1, IpAddr::V4(a)) => {
                                let mut ans = Vec::new();
                                ans.extend_from_slice(&[0xC0, 0x0C]);
                                ans.extend_from_slice(&1u16.to_be_bytes());
                                ans.extend_from_slice(&1u16.to_be_bytes());
                                ans.extend_from_slice(&60u32.to_be_bytes());
                                ans.extend_from_slice(&4u16.to_be_bytes());
                                ans.extend_from_slice(&a.octets());
                                (1, ans)
                            }
                            (28, IpAddr::V6(a)) => {
                                let mut ans = Vec::new();
                                ans.extend_from_slice(&[0xC0, 0x0C]);
                                ans.extend_from_slice(&28u16.to_be_bytes());
                                ans.extend_from_slice(&1u16.to_be_bytes());
                                ans.extend_from_slice(&60u32.to_be_bytes());
                                ans.extend_from_slice(&16u16.to_be_bytes());
                                ans.extend_from_slice(&a.octets());
                                (1, ans)
                            }
                            _ => (0, Vec::new()),
                        };
                        let mut resp = Vec::new();
                        resp.extend_from_slice(&txid);
                        resp.extend_from_slice(&0x8180u16.to_be_bytes());
                        resp.extend_from_slice(&1u16.to_be_bytes());
                        resp.extend_from_slice(&ancount.to_be_bytes());
                        resp.extend_from_slice(&0u16.to_be_bytes());
                        resp.extend_from_slice(&0u16.to_be_bytes());
                        resp.extend_from_slice(&buf[12..n]);
                        resp.extend_from_slice(&answer);
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
                // (NB-D) Record the last delivered server→client
                // WireGuard DATA packet (type 4) so the replay
                // test can re-send a genuine, already-delivered
                // packet verbatim at the client tunnel.
                if bytes.first() == Some(&4) {
                    if let Ok(mut slot) = st.captured_data.lock() {
                        *slot = Some(bytes);
                    }
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

fn fake_client_cfg_v6(
    server: &FakeWgServer,
    psk: Option<[u8; 32]>,
    keepalive: u16,
    allowed_ips: Vec<Prefix>,
    dns_servers: Vec<String>,
) -> WireGuardConfig {
    let server_pub = PublicKey::from(&StaticSecret::from(FAKE_SERVER_SECRET));
    WireGuardConfig {
        tag: "wg-fake-test-v6".to_string(),
        system: false,
        address: vec![Prefix {
            addr: IpAddr::V6(FAKE_CLIENT_IP6),
            prefix_len: 128,
        }],
        private_key: FAKE_CLIENT_SECRET,
        mtu: 0,
        listen_port: None,
        peers: vec![WireGuardPeerConfig {
            endpoint_host: "::1".to_string(),
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
    // (NB13) The MTU is pinned observably: no UDP datagram the
    // server received may exceed MTU + WireGuard overhead + the
    // outer IPv4/UDP headers (1408 + 32 + 28). If the device MTU
    // were larger (e.g. 65535), the 64 KiB payload would arrive
    // in far larger datagrams and this would fail.
    let max_dg = server.max_datagram.load(Ordering::SeqCst);
    assert!(
        max_dg <= 1408 + 32 + 28,
        "max UDP datagram {max_dg} exceeds MTU 1408 + overhead"
    );
    assert!(
        max_dg > 1408,
        "max datagram {max_dg} should exceed the bare MTU (data packets carry overhead)"
    );
    assert_eq!(
        server.tcp_accepts.load(Ordering::SeqCst),
        1,
        "exactly one TCP connection"
    );
}

// (b) Keepalive, pinned by COUNTING datagrams: with
// persistent_keepalive=1 the client pump must emit keepalive
// datagrams during an idle window (the server counts every UDP
// datagram it receives); with keepalive disabled it must emit
// none. The old shape of this test (sleep 2.5 s, re-dial) passed
// with keepalive completely disabled — a session lives 90–180 s
// without traffic — so it pinned nothing and is replaced.
#[tokio::test]
async fn fake_wireguard_keepalive_emits_datagrams_during_idle() {
    // Keepalive ON.
    let server = FakeWgServer::start(None, false).await;
    let dialer = WireGuardDialer::new(fake_client_cfg(&server, None, 1, fake_allow_all(), vec![]))
        .expect("fake client cfg valid");
    let mut stream = dialer
        .dial(&DialTarget::new("10.0.0.1", 80))
        .await
        .expect("fake dial works");
    fake_echo(&mut stream, b"before-idle").await;
    drop(stream);
    tokio::time::sleep(Duration::from_millis(300)).await;
    let before = server.datagrams.load(Ordering::SeqCst);
    tokio::time::sleep(Duration::from_secs(3)).await;
    let emitted = server.datagrams.load(Ordering::SeqCst) - before;
    assert!(
        emitted >= 2,
        "keepalive=1 must emit >=2 datagrams in 3 s idle, got {emitted}"
    );
    // Liveness: a re-dial after the idle window still works.
    let mut stream = dialer
        .dial(&DialTarget::new("10.0.0.1", 80))
        .await
        .expect("fake dial after idle works");
    fake_echo(&mut stream, b"after-idle").await;
    drop(stream);
    // Keepalive OFF control: no datagrams during idle.
    let server = FakeWgServer::start(None, false).await;
    let dialer = WireGuardDialer::new(fake_client_cfg(&server, None, 0, fake_allow_all(), vec![]))
        .expect("fake client cfg valid");
    let mut stream = dialer
        .dial(&DialTarget::new("10.0.0.1", 80))
        .await
        .expect("fake dial works");
    fake_echo(&mut stream, b"before-idle-off").await;
    drop(stream);
    tokio::time::sleep(Duration::from_millis(300)).await;
    let before = server.datagrams.load(Ordering::SeqCst);
    tokio::time::sleep(Duration::from_secs(3)).await;
    let emitted = server.datagrams.load(Ordering::SeqCst) - before;
    assert_eq!(
        emitted, 0,
        "keepalive=0 must emit no datagrams during idle, got {emitted}"
    );
}

// (T1/R-B1) Slow reader: the peer pushes 1 MiB (> the 512 KiB
// net_to_app channel) while the app does not read. Every byte
// already consumed from smoltcp is ACKed and will never be
// retransmitted, so the pump must hold the overflow in its
// pending buffer — the echo must come back byte-exact.
#[tokio::test]
async fn fake_wireguard_slow_reader_no_data_loss() {
    let server = FakeWgServer::start(None, false).await;
    let dialer = WireGuardDialer::new(fake_client_cfg(&server, None, 0, fake_allow_all(), vec![]))
        .expect("fake client cfg valid");
    let mut stream = dialer
        .dial(&DialTarget::new("10.0.0.1", 80))
        .await
        .expect("fake dial works");
    let payload: Vec<u8> = (0..1_048_576).map(|i| (i % 251) as u8).collect();
    stream.write_all(&payload).await.expect("fake write");
    // Do NOT read: the echo fills the 512 KiB channel and the
    // pump must hold the rest, not drop it.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let mut got = vec![0u8; payload.len()];
    tokio::time::timeout(Duration::from_secs(20), stream.read_exact(&mut got))
        .await
        .expect("slow-reader echo must finish, not hang")
        .expect("fake read");
    assert_eq!(got, payload, "slow-reader echo must be byte-exact");
}

// (T2) EOF after a full channel: the peer sends 576 KiB (>
// 512 KiB channel) then FINs. The EOF must be delivered after
// the drain — not lost while the channel is full (which hung
// `poll_read` on `Pending` forever), and not misreported as a
// reset.
#[tokio::test]
async fn fake_wireguard_eof_after_full_channel() {
    let server = FakeWgServer::start(None, false).await;
    let dialer = WireGuardDialer::new(fake_client_cfg(&server, None, 0, fake_allow_all(), vec![]))
        .expect("fake client cfg valid");
    let mut stream = dialer
        .dial(&DialTarget::new("10.0.0.1", 80))
        .await
        .expect("fake dial works");
    let payload: Vec<u8> = (0..589_824).map(|i| (i % 251) as u8).collect();
    stream.write_all(&payload).await.expect("fake write");
    stream.shutdown().await.expect("fake shutdown");
    // Let the echo fill the channel and the server's FIN arrive
    // while the channel is still full.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let mut got = Vec::new();
    let mut buf = [0u8; 8192];
    let drained = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            match stream.read(&mut buf).await.expect("fake read") {
                0 => break,
                n => {
                    got.extend_from_slice(&buf[..n]);
                    // Drain slowly — one 8 KiB read per 150 ms.
                    // The pump refills the freed slot within
                    // microseconds but runs at most one cycle per
                    // 100 ms (`PUMP_TICK_CAP`), so it is gated to
                    // one chunk per reader read: the last data
                    // chunk is delivered via `pending_rx` (filling
                    // the only free slot) and the FIN is processed
                    // in the same cycle, so the EOF `try_send`
                    // hits `Full` and must be retried
                    // (`pending_eof`), not lost. A 10 ms drain
                    // does NOT pin this: the reader frees several
                    // slots between pump cycles and the EOF lands
                    // on the first try.
                    tokio::time::sleep(Duration::from_millis(150)).await;
                }
            }
        }
    })
    .await;
    assert!(
        drained.is_ok(),
        "EOF must arrive after a full channel, not hang"
    );
    assert_eq!(
        got.len(),
        payload.len(),
        "echo length before EOF must match payload length"
    );
    assert_eq!(got, payload, "echo bytes must match the payload exactly");
}

// (R-B2) A live stream survives its dialer being dropped: the
// stream holds an `Arc<Tunnel>`, so the pump keeps running
// until the stream itself goes away.
#[tokio::test]
async fn fake_wireguard_stream_survives_dialer_drop() {
    let server = FakeWgServer::start(None, false).await;
    let dialer = Arc::new(
        WireGuardDialer::new(fake_client_cfg(&server, None, 0, fake_allow_all(), vec![]))
            .expect("fake client cfg valid"),
    );
    let mut stream = dialer
        .dial(&DialTarget::new("10.0.0.1", 80))
        .await
        .expect("fake dial works");
    drop(dialer);
    fake_echo(&mut stream, b"after-dialer-drop").await;
}

// (R-B4) Bad UDP datagrams are dropped, never fatal: garbage
// from the peer's address, an oversized datagram (truncated by
// the recv buffer), and garbage from a spoofed source must all
// leave the tunnel — and the live stream — working.
#[tokio::test]
async fn fake_wireguard_bad_datagram_does_not_kill_tunnel() {
    let server = FakeWgServer::start(None, false).await;
    let dialer = WireGuardDialer::new(fake_client_cfg(&server, None, 0, fake_allow_all(), vec![]))
        .expect("fake client cfg valid");
    let mut stream = dialer
        .dial(&DialTarget::new("10.0.0.1", 80))
        .await
        .expect("fake dial works");
    fake_echo(&mut stream, b"before-garbage").await;
    // Garbage from the peer's address (passes the src==peer
    // gate, fails boringtun decapsulation) + a 2000-byte
    // datagram (truncated by the mtu+32 recv buffer).
    let garbage: Vec<u8> = (0..64).map(|i| (0xDEu8.wrapping_add(i as u8))).collect();
    server.inject(&garbage);
    server.inject(&vec![0u8; 2000]);
    tokio::time::sleep(Duration::from_millis(300)).await;
    // Garbage from a spoofed source (another UDP socket aimed
    // at the client's UDP port): dropped by the src gate.
    if let Some(client_addr) = server.client_addr() {
        let spoof = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .expect("spoof socket binds");
        let _ = spoof.send_to(&garbage, client_addr).await;
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    fake_echo(&mut stream, b"after-garbage").await;
}

// (NB-D) Replayed-packet injection: a genuine server→client
// WireGuard DATA packet, captured from this harness's own UDP
// traffic and replayed verbatim, must be dropped as
// `DuplicateCounter` — never fatal to the tunnel. The packet is
// only replayed once it has been stable for 300 ms of idle, so
// it is certainly already delivered (and its counter already
// consumed): replaying a packet still in flight would be a
// first delivery, not a replay.
#[tokio::test]
async fn fake_wireguard_replayed_data_packet_does_not_kill_tunnel() {
    let server = FakeWgServer::start(None, false).await;
    let dialer = WireGuardDialer::new(fake_client_cfg(&server, None, 0, fake_allow_all(), vec![]))
        .expect("fake client cfg valid");
    let mut stream = dialer
        .dial(&DialTarget::new("10.0.0.1", 80))
        .await
        .expect("fake dial works");
    fake_echo(&mut stream, b"before-replay").await;
    // Settle: the captured packet must be stable across 300 ms
    // of idle, proving it was delivered (and consumed) long ago.
    let first = server
        .captured_data_packet()
        .expect("server must have sent a data packet during the echo");
    assert_eq!(
        first.first(),
        Some(&4),
        "captured packet must be a WireGuard data packet"
    );
    assert!(
        first.len() > 32,
        "captured packet must carry TCP payload, got {} bytes",
        first.len()
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    let replay = server
        .captured_data_packet()
        .expect("server must have sent a data packet during the echo");
    assert_eq!(
        replay, first,
        "no new data packet may appear during idle; otherwise the replay would not be of an already-delivered packet"
    );
    // Replay the genuine packet verbatim, from the peer's own
    // address (the inject hook sends from the server socket).
    server.inject(&replay);
    tokio::time::sleep(Duration::from_millis(300)).await;
    fake_echo(&mut stream, b"after-replay").await;
}

// (NB20) PSK control for the mismatch test: both sides use the
// SAME preshared key, but a different value from FAKE_PSK —
// echo must work, proving the mismatch failure is caused by
// the mismatch (not by "any non-default PSK breaks the dial").
#[tokio::test]
async fn fake_wireguard_psk_both_sides_same_nonstandard_psk_echoes() {
    let other_psk = [0x44u8; 32];
    let server = FakeWgServer::start(Some(other_psk), false).await;
    let dialer = WireGuardDialer::new(fake_client_cfg(
        &server,
        Some(other_psk),
        0,
        fake_allow_all(),
        vec![],
    ))
    .expect("fake client cfg valid");
    let mut stream = dialer
        .dial(&DialTarget::new("10.0.0.1", 80))
        .await
        .expect("fake dial with matching nonstandard PSK works");
    fake_echo(&mut stream, b"psk-control-echo").await;
}

// (NB1/T-NB7) DNS failover: the first server fails HARD (a v6
// address with a v4-only tunnel — no DNS socket for its
// family), so the dialer must try the next server instead of
// failing the whole resolution.
#[tokio::test]
async fn fake_wireguard_dns_failover_to_next_server() {
    let server = FakeWgServer::start(None, true).await;
    let dialer = WireGuardDialer::new(fake_client_cfg(
        &server,
        None,
        0,
        fake_allow_all(),
        vec!["fd00::99".to_string(), "10.0.0.1".to_string()],
    ))
    .expect("fake client cfg valid");
    let mut stream = dialer
        .dial(&DialTarget::new("echo.test", 80))
        .await
        .expect("failover dial works");
    fake_echo(&mut stream, b"failover-echo").await;
}

// (S6/T-NB4) A `wireguard_dns` entry carrying a port is queried
// on port 53 anyway — Go parity: Go's
// `buildWireGuardDNSOptions` hardcodes `server_port: 53` for
// every server.
#[tokio::test]
async fn fake_wireguard_dns_server_port_is_ignored_go_parity() {
    let server = FakeWgServer::start(None, true).await;
    let dialer = WireGuardDialer::new(fake_client_cfg(
        &server,
        None,
        0,
        fake_allow_all(),
        vec!["10.0.0.1:5353".to_string()],
    ))
    .expect("fake client cfg valid");
    let mut stream = dialer
        .dial(&DialTarget::new("echo.test", 80))
        .await
        .expect("dns entry with a port must still resolve on 53");
    fake_echo(&mut stream, b"port-echo").await;
}

// (NB14/NB15) IPv6 end-to-end: the v6 server answers A with no
// records and AAAA → fd00::1, so the client must exercise the
// AAAA path and then echo over a v6 TCP stream through the
// tunnel (fd00::2 → fd00::1:80).
#[tokio::test]
async fn fake_wireguard_ipv6_aaaa_and_tcp_echo() {
    let server = FakeWgServer::start_v6(None, true).await;
    let allowed = vec![Prefix {
        addr: IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0)),
        prefix_len: 120,
    }];
    let dialer = WireGuardDialer::new(fake_client_cfg_v6(
        &server,
        None,
        0,
        allowed,
        vec!["fd00::1".to_string()],
    ))
    .expect("fake v6 client cfg valid");
    let mut stream = dialer
        .dial(&DialTarget::new("v6.test", 80))
        .await
        .expect("v6 dial via AAAA works");
    fake_echo(&mut stream, b"v6-echo").await;
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
