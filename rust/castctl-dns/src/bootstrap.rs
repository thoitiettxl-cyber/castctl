// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Bootstrap substitution (Go `internal/dns/bootstrap.go`
//! in full): resolve a DNS server's own hostname once
//! per server, before any transport is created. The ONLY
//! place bootstrap resolution happens: never for dial
//! targets, never for other hostnames, never as a
//! fallback after a DNS failure.

use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use crate::error::DnsError;
use crate::server::{DnsServer, DnsServerKind, is_domain};

/// Bootstrap timeout (Go `client.go:143`: 5 s).
pub const BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(5);

/// Resolves a DNS server's own hostname (Go
/// `BootstrapFunc`, `client.go:38-39`). Injected so
/// tests can substitute a fake; production passes
/// [`default_bootstrap`], the single system-resolver
/// call site.
pub type BootstrapFn = Arc<
    dyn Fn(String) -> Pin<Box<dyn Future<Output = Result<Vec<IpAddr>, DnsError>> + Send>>
        + Send
        + Sync,
>;

/// The default bootstrap: the system resolver via
/// `tokio::net::lookup_host`, with its own 5 s timeout
/// (Go `internal/outbound/bootstrap.go:61-75`,
/// `BootstrapLookupWithLogger`, which uses
/// `net.DefaultResolver.LookupHost` with a 5 s timeout
/// and logs host + address COUNT only, never addresses).
/// This port does not log (the crate has no logging
/// dependency).
pub async fn default_bootstrap(host: String) -> Result<Vec<IpAddr>, DnsError> {
    let addrs = tokio::time::timeout(
        BOOTSTRAP_TIMEOUT,
        tokio::net::lookup_host((host.as_str(), 0)),
    )
    .await
    .map_err(|_| DnsError::message("context deadline exceeded"))?
    .map_err(DnsError::Io)?;
    Ok(addrs.map(|s| s.ip()).collect())
}

/// Resolve the DNS servers' own hostnames once each,
/// before any transport is created (Go
/// `substituteBootstrap`, `bootstrap.go:26-37`).
/// Returns the servers with substituted addresses, or
/// the first bootstrap failure wrapped as
/// `dns: bootstrap for server %q: %w` (the server TAG).
pub async fn substitute_bootstrap(
    servers: &[DnsServer],
    bootstrap: &BootstrapFn,
) -> Result<Vec<DnsServer>, DnsError> {
    let mut out = Vec::with_capacity(servers.len());
    for server in servers {
        let kind = substitute_server_address(&server.kind, bootstrap)
            .await
            .map_err(|e| DnsError::Bootstrap {
                server: server.tag.clone(),
                source: Box::new(e),
            })?;
        out.push(DnsServer {
            tag: server.tag.clone(),
            kind,
        });
    }
    Ok(out)
}

async fn substitute_server_address(
    kind: &DnsServerKind,
    bootstrap: &BootstrapFn,
) -> Result<DnsServerKind, DnsError> {
    match kind {
        DnsServerKind::Tcp {
            server,
            server_port,
        } => {
            let server = substitute_address(server, None, bootstrap).await?;
            Ok(DnsServerKind::Tcp {
                server,
                server_port: *server_port,
            })
        }
        DnsServerKind::Tls {
            server,
            server_port,
            server_name,
        } => {
            let mut name = server_name.clone();
            let server = substitute_address(server, Some(&mut name), bootstrap).await?;
            Ok(DnsServerKind::Tls {
                server,
                server_port: *server_port,
                server_name: name,
            })
        }
        DnsServerKind::Https {
            server,
            server_port,
            server_name,
        } => {
            let mut name = server_name.clone();
            let server = substitute_address(server, Some(&mut name), bootstrap).await?;
            Ok(DnsServerKind::Https {
                server,
                server_port: *server_port,
                server_name: name,
            })
        }
        // Types without an address field are returned
        // unchanged (Go `bootstrap.go:39-67` default).
        DnsServerKind::Local | DnsServerKind::Hosts | DnsServerKind::FakeIp => Ok(kind.clone()),
    }
}

/// Resolve one server address (Go `substituteAddress`,
/// `bootstrap.go:76-100`): when the host is a domain,
/// resolve it via bootstrap and take the first IPv4
/// address if any, else the first address. An empty
/// bootstrap result is `bootstrap for %s returned no
/// addresses`. When `server_name` is `Some` and empty,
/// the original hostname is preserved as the TLS
/// ServerName (Go `tlsServerNameOf`, `bootstrap.go:69-74`).
async fn substitute_address(
    host: &str,
    server_name: Option<&mut String>,
    bootstrap: &BootstrapFn,
) -> Result<String, DnsError> {
    if !is_domain(host) {
        return Ok(host.to_string());
    }
    let original = host.to_string();
    let addrs = tokio::time::timeout(BOOTSTRAP_TIMEOUT, bootstrap(original.clone()))
        .await
        .map_err(|_| DnsError::message("context deadline exceeded"))??;
    if addrs.is_empty() {
        return Err(DnsError::message(&format!(
            "bootstrap for {original} returned no addresses"
        )));
    }
    let chosen = addrs
        .iter()
        .find(|a| a.is_ipv4())
        .or(addrs.first())
        .expect("non-empty, checked above");
    if let Some(name) = server_name
        && name.is_empty()
    {
        *name = original;
    }
    Ok(chosen.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn canned(addrs: Vec<IpAddr>) -> BootstrapFn {
        Arc::new(move |_host: String| {
            let addrs = addrs.clone();
            Box::pin(async move { Ok(addrs) })
        })
    }

    fn failing() -> BootstrapFn {
        Arc::new(move |_host: String| {
            Box::pin(async move { Err(DnsError::message("bootstrap failed")) })
        })
    }

    #[tokio::test]
    async fn tcp_domain_substitutes_first_ipv4() {
        let servers = vec![DnsServer {
            tag: "dns1".to_string(),
            kind: DnsServerKind::Tcp {
                server: "dns.test".to_string(),
                server_port: 53,
            },
        }];
        let out = substitute_bootstrap(
            &servers,
            &canned(vec![
                "2001:db8::1".parse().expect("ipv6"),
                "192.0.2.1".parse().expect("ipv4"),
                "192.0.2.2".parse().expect("ipv4"),
            ]),
        )
        .await
        .expect("substitution must succeed");
        assert_eq!(
            out[0].kind,
            DnsServerKind::Tcp {
                server: "192.0.2.1".to_string(),
                server_port: 53,
            }
        );
    }

    #[tokio::test]
    async fn first_address_when_no_ipv4() {
        let servers = vec![DnsServer {
            tag: "dns1".to_string(),
            kind: DnsServerKind::Tcp {
                server: "dns.test".to_string(),
                server_port: 53,
            },
        }];
        let out = substitute_bootstrap(
            &servers,
            &canned(vec!["2001:db8::1".parse().expect("ipv6")]),
        )
        .await
        .expect("substitution must succeed");
        assert_eq!(
            out[0].kind.server(),
            Some("2001:db8::1"),
            "no IPv4: the first address wins"
        );
    }

    #[tokio::test]
    async fn tcp_ip_literal_unchanged() {
        let servers = vec![DnsServer {
            tag: "dns1".to_string(),
            kind: DnsServerKind::Tcp {
                server: "127.0.0.1".to_string(),
                server_port: 53,
            },
        }];
        let calls = Arc::new(std::sync::Mutex::new(0));
        let calls2 = Arc::clone(&calls);
        let bootstrap: BootstrapFn = Arc::new(move |_host: String| {
            *calls2.lock().expect("lock") += 1;
            Box::pin(async move { Ok(vec![]) })
        });
        let out = substitute_bootstrap(&servers, &bootstrap)
            .await
            .expect("substitution must succeed");
        assert_eq!(out, servers, "IP literals are never resolved");
        assert_eq!(*calls.lock().expect("lock"), 0, "bootstrap never called");
    }

    #[tokio::test]
    async fn tls_empty_server_name_preserves_hostname() {
        let servers = vec![DnsServer {
            tag: "dns1".to_string(),
            kind: DnsServerKind::Tls {
                server: "dns.test".to_string(),
                server_port: 853,
                server_name: String::new(),
            },
        }];
        let out = substitute_bootstrap(&servers, &canned(vec!["127.0.0.1".parse().expect("ip")]))
            .await
            .expect("substitution must succeed");
        assert_eq!(
            out[0].kind,
            DnsServerKind::Tls {
                server: "127.0.0.1".to_string(),
                server_port: 853,
                server_name: "dns.test".to_string(),
            }
        );
    }

    #[tokio::test]
    async fn tls_set_server_name_kept() {
        let servers = vec![DnsServer {
            tag: "dns1".to_string(),
            kind: DnsServerKind::Tls {
                server: "dns.test".to_string(),
                server_port: 853,
                server_name: "pinned.test".to_string(),
            },
        }];
        let out = substitute_bootstrap(&servers, &canned(vec!["127.0.0.1".parse().expect("ip")]))
            .await
            .expect("substitution must succeed");
        assert_eq!(
            out[0].kind,
            DnsServerKind::Tls {
                server: "127.0.0.1".to_string(),
                server_port: 853,
                server_name: "pinned.test".to_string(),
            }
        );
    }

    #[tokio::test]
    async fn empty_bootstrap_result_is_error() {
        let servers = vec![DnsServer {
            tag: "dns1".to_string(),
            kind: DnsServerKind::Tcp {
                server: "dns.test".to_string(),
                server_port: 53,
            },
        }];
        let err = substitute_bootstrap(&servers, &canned(vec![]))
            .await
            .expect_err("empty bootstrap must fail");
        assert_eq!(
            err.to_string(),
            "dns: bootstrap for server \"dns1\": bootstrap for dns.test returned no addresses"
        );
    }

    #[tokio::test]
    async fn bootstrap_failure_wraps_with_tag() {
        let servers = vec![DnsServer {
            tag: "dns1".to_string(),
            kind: DnsServerKind::Tcp {
                server: "dns.test".to_string(),
                server_port: 53,
            },
        }];
        let err = substitute_bootstrap(&servers, &failing())
            .await
            .expect_err("failing bootstrap must fail");
        assert_eq!(
            err.to_string(),
            "dns: bootstrap for server \"dns1\": bootstrap failed"
        );
    }

    #[tokio::test]
    async fn local_hosts_fakeip_unchanged() {
        let servers = vec![
            DnsServer {
                tag: "l".to_string(),
                kind: DnsServerKind::Local,
            },
            DnsServer {
                tag: "h".to_string(),
                kind: DnsServerKind::Hosts,
            },
            DnsServer {
                tag: "f".to_string(),
                kind: DnsServerKind::FakeIp,
            },
        ];
        let out = substitute_bootstrap(&servers, &failing())
            .await
            .expect("address-less servers never call bootstrap");
        assert_eq!(out, servers);
    }
}
