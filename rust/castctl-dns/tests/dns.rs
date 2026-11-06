// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Port of Go `internal/dns/client_test.go` (9 fns) +
//! `helpers_test.go` (fake TCP DNS server).
//!
//! The other 23 Go DNS test fns (integration, gate2,
//! isolation, per-profile) need a Rust outbound manager
//! + router first; they are recorded as unported in the
//!   writer report, not here.
//!
//! The fake server mirrors Go's: it answers the
//! fake-only hostnames `gateway.test` and `proxy.test`
//! with A 127.0.0.1, AAAA empty NOERROR, everything else
//! NXDOMAIN. Counts queries and records question names
//! so tests can prove which names reached the configured
//! DNS path. UDP is not used (the VM blocks loopback UDP
//! sendto, EPERM, measured in the PR1 router probe).

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use castctl_dns::{
    BootstrapFn, Client, ClientOptions, DnsError, DnsOptions, DnsServer, DnsServerKind,
    TcpTransportFactory, decode_message,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex as TokioMutex;

// -- fake TCP DNS server (Go helpers_test.go) --

struct FakeDnsServer {
    addr: SocketAddr,
    queries: Arc<TokioMutex<usize>>,
    task: tokio::task::JoinHandle<()>,
}

impl FakeDnsServer {
    async fn start() -> Self {
        let ln = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake DNS server");
        let addr = ln.local_addr().expect("listener addr");
        let queries = Arc::new(TokioMutex::new(0usize));
        let questions = Arc::new(TokioMutex::new(Vec::new()));
        let queries2 = Arc::clone(&queries);
        let questions2 = Arc::clone(&questions);
        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = ln.accept().await else {
                    return;
                };
                let queries = Arc::clone(&queries2);
                let questions = Arc::clone(&questions2);
                tokio::spawn(async move {
                    handle_conn(stream, queries, questions).await;
                });
            }
        });
        Self {
            addr,
            queries,
            task,
        }
    }

    fn port(&self) -> u16 {
        self.addr.port()
    }

    async fn query_count(&self) -> usize {
        *self.queries.lock().await
    }

    async fn close(self) {
        self.task.abort();
    }
}

async fn handle_conn(
    mut stream: tokio::net::TcpStream,
    queries: Arc<TokioMutex<usize>>,
    questions: Arc<TokioMutex<Vec<String>>>,
) {
    loop {
        let mut len_buf = [0u8; 2];
        if stream.read_exact(&mut len_buf).await.is_err() {
            return;
        }
        let len = u16::from_be_bytes(len_buf) as usize;
        let mut buf = vec![0u8; len];
        if stream.read_exact(&mut buf).await.is_err() {
            return;
        }
        let Ok(msg) = decode_message(&buf) else {
            return;
        };
        let (qname, qtype) = match msg.questions.first() {
            Some(q) => (q.name.clone(), q.qtype),
            None => continue,
        };
        {
            *queries.lock().await += 1;
            questions.lock().await.push(qname.clone());
        }
        let (rcode, answers): (u16, Vec<(u16, Vec<u8>)>) =
            if qname == "gateway.test" || qname == "proxy.test" {
                if qtype == 1 {
                    (0, vec![(1, vec![127, 0, 0, 1])])
                } else {
                    (0, vec![])
                }
            } else {
                (3, vec![])
            };
        let resp = encode_response(msg.id, &qname, qtype, rcode, &answers);
        let mut framed = Vec::with_capacity(resp.len() + 2);
        framed.extend_from_slice(&(resp.len() as u16).to_be_bytes());
        framed.extend_from_slice(&resp);
        if stream.write_all(&framed).await.is_err() {
            return;
        }
    }
}

/// Encode a response: QR + RD + RA, the question echoed,
/// answers with a compression pointer to the question
/// name (offset 12).
fn encode_response(
    id: u16,
    qname: &str,
    qtype: u16,
    rcode: u16,
    answers: &[(u16, Vec<u8>)],
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&(0x8180u16 | rcode).to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&(answers.len() as u16).to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    for label in qname.split('.') {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    for (rtype, rdata) in answers {
        out.extend_from_slice(&[0xC0, 0x0C]); // pointer to the question name
        out.extend_from_slice(&rtype.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&60u32.to_be_bytes());
        out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        out.extend_from_slice(rdata);
    }
    out
}

// -- test setup (Go newTestSetup, minus the outbound
// manager: no outbound manager exists in Rust yet) --

fn tcp_dns_options(port: u16) -> DnsOptions {
    DnsOptions {
        servers: vec![DnsServer {
            tag: "dns1".to_string(),
            kind: DnsServerKind::Tcp {
                server: "127.0.0.1".to_string(),
                server_port: port,
            },
        }],
        final_tag: "dns1".to_string(),
    }
}

async fn new_client(opts: DnsOptions) -> Client {
    Client::new(
        opts,
        Arc::new(TcpTransportFactory),
        ClientOptions::default(),
    )
    .await
    .expect("client construction must succeed")
}

#[tokio::test]
async fn client_lookup_through_configured_dns() {
    let server = FakeDnsServer::start().await;
    let client = new_client(tcp_dns_options(server.port())).await;
    client.start().await.expect("client Start");
    let addrs = client
        .lookup("gateway.test")
        .await
        .expect("Lookup(gateway.test)");
    assert_eq!(addrs, vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))]);
    assert!(
        server.query_count().await > 0,
        "fake DNS server saw no queries; resolution did not go through the configured DNS"
    );
    server.close().await;
}

#[tokio::test]
async fn client_nxdomain_is_error() {
    let server = FakeDnsServer::start().await;
    let client = new_client(tcp_dns_options(server.port())).await;
    client.start().await.expect("client Start");
    assert!(
        client.lookup("missing.test").await.is_err(),
        "Lookup(missing.test) must be an NXDOMAIN error"
    );
    server.close().await;
}

#[tokio::test]
async fn client_no_system_fallback_for_localhost() {
    // The system resolver knows localhost, but the
    // configured fake DNS returns NXDOMAIN for it. A
    // successful localhost lookup would prove a
    // system-resolver fallback; it must fail instead.
    let server = FakeDnsServer::start().await;
    let client = new_client(tcp_dns_options(server.port())).await;
    client.start().await.expect("client Start");
    assert!(
        client.lookup("localhost").await.is_err(),
        "Lookup(localhost) must fail (no system fallback)"
    );
    server.close().await;
}

#[tokio::test]
async fn client_no_servers_is_error() {
    // `Client` has no `Debug` (it holds `Arc<dyn ...>`
    // trait objects), so `Result::expect_err` cannot be
    // used here; the match is the equivalent assertion.
    let err = match Client::new(
        DnsOptions::default(),
        Arc::new(TcpTransportFactory),
        ClientOptions::default(),
    )
    .await
    {
        Ok(_) => panic!("New with no servers must fail"),
        Err(e) => e,
    };
    assert_eq!(
        err.to_string(),
        "dns: no DNS servers configured: refusing to fall back to the system resolver"
    );
}

#[tokio::test]
async fn client_nil_bootstrap_is_error() {
    // `Client` has no `Debug` — see
    // `client_no_servers_is_error` above.
    let err = match Client::new(
        tcp_dns_options(53),
        Arc::new(TcpTransportFactory),
        ClientOptions::default().with_bootstrap(None),
    )
    .await
    {
        Ok(_) => panic!("explicit nil bootstrap must fail"),
        Err(e) => e,
    };
    assert_eq!(err.to_string(), "dns: bootstrap function must not be nil");
}

#[tokio::test]
async fn client_dns_failure_is_error() {
    // DNS server on a refusing port: lookup must error,
    // never fall back.
    let ln = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let closed = ln.local_addr().expect("addr").port();
    drop(ln);
    let client = new_client(DnsOptions {
        servers: vec![DnsServer {
            tag: "dead".to_string(),
            kind: DnsServerKind::Tcp {
                server: "127.0.0.1".to_string(),
                server_port: closed,
            },
        }],
        final_tag: "dead".to_string(),
    })
    .await;
    client.start().await.expect("client Start");
    assert!(
        client.lookup("gateway.test").await.is_err(),
        "Lookup through dead DNS must fail"
    );
}

#[tokio::test]
async fn client_bootstrap_for_server_hostname() {
    // The DNS server's own hostname is resolved once via
    // the injected bootstrap func; the bootstrap must
    // never be called for other hostnames. The fake
    // bootstrap maps dns.test -> 127.0.0.1 and the server
    // listens on 127.0.0.1, so the substituted address
    // reaches the fake server.
    let server = FakeDnsServer::start().await;
    let port = server.port();
    let calls = Arc::new(TokioMutex::new(0usize));
    let calls2 = Arc::clone(&calls);
    let bootstrap: BootstrapFn = Arc::new(move |host: String| {
        let calls2 = Arc::clone(&calls2);
        Box::pin(async move {
            *calls2.lock().await += 1;
            if host != "dns.test" {
                return Err(DnsError::message(&format!(
                    "bootstrap called for unexpected host {host:?}"
                )));
            }
            Ok(vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))])
        })
    });
    let opts = DnsOptions {
        servers: vec![DnsServer {
            tag: "dns1".to_string(),
            kind: DnsServerKind::Tcp {
                server: "dns.test".to_string(),
                server_port: port,
            },
        }],
        final_tag: "dns1".to_string(),
    };
    let client = Client::new(
        opts,
        Arc::new(TcpTransportFactory),
        ClientOptions::default().with_bootstrap(Some(bootstrap)),
    )
    .await
    .expect("client construction must succeed");
    assert_eq!(
        *calls.lock().await,
        1,
        "bootstrap calls must be exactly 1 (at construction)"
    );
    client.start().await.expect("client Start");
    let addrs = client
        .lookup("gateway.test")
        .await
        .expect("Lookup(gateway.test)");
    assert_eq!(addrs, vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))]);
    assert_eq!(
        *calls.lock().await,
        1,
        "bootstrap calls after lookup must still be 1 (never for other hosts)"
    );
    assert!(server.query_count().await > 0, "fake DNS saw no queries");
    server.close().await;
}

#[tokio::test]
async fn client_bootstrap_failure_is_error() {
    let bootstrap: BootstrapFn = Arc::new(|_host: String| {
        Box::pin(async move { Err(DnsError::message("bootstrap failed")) })
    });
    let opts = DnsOptions {
        servers: vec![DnsServer {
            tag: "dns1".to_string(),
            kind: DnsServerKind::Tcp {
                server: "dns.test".to_string(),
                server_port: 5353,
            },
        }],
        final_tag: "dns1".to_string(),
    };
    assert!(
        Client::new(
            opts,
            Arc::new(TcpTransportFactory),
            ClientOptions::default().with_bootstrap(Some(bootstrap)),
        )
        .await
        .is_err(),
        "New with failing bootstrap must fail"
    );
}

#[tokio::test]
async fn client_lifecycle() {
    let server = FakeDnsServer::start().await;
    let client = new_client(tcp_dns_options(server.port())).await;
    client.start().await.expect("first Start");
    assert!(client.start().await.is_err(), "second Start must fail");
    client.close().await.expect("Close");
    client.close().await.expect("second Close must succeed");
    assert!(
        client.lookup("gateway.test").await.is_err(),
        "Lookup after Close must fail"
    );
    server.close().await;
}

#[tokio::test]
async fn client_transport_access() {
    let server = FakeDnsServer::start().await;
    let client = new_client(tcp_dns_options(server.port())).await;
    assert!(
        client.transport("dns1").is_some(),
        "Transport(dns1) missing"
    );
    assert!(
        client.transport("missing").is_none(),
        "Transport(missing) found, want missing"
    );
    server.close().await;
}
