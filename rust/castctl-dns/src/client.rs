// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! The DNS client (Go `internal/dns.Client`,
//! `client.go:76-244`): lifecycle + lookup over the
//! router, with the sing-box router and transport
//! manager behind the [`crate::router::DnsRouter`] and
//! [`crate::transport::DnsTransportFactory`] traits.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Mutex;

use crate::bootstrap::{BootstrapFn, default_bootstrap, substitute_bootstrap};
use crate::error::DnsError;
use crate::router::{DnsRouter, SingleServerRouter};
use crate::server::{DnsOptions, DnsServer};
use crate::transport::{DnsTransport, DnsTransportFactory};

/// Lookup timeout (Go `client.go:228`: 5 s).
pub const LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);

/// Options for [`Client::new`] (Go `ClientOption`s:
/// `WithLogFactory` has no Rust equivalent — the crate
/// has no logging dependency — and `WithBootstrap` is
/// [`ClientOptions::with_bootstrap`]).
#[derive(Default)]
pub struct ClientOptions {
    bootstrap: Option<BootstrapFn>,
    bootstrap_set: bool,
}

impl ClientOptions {
    /// Use `bootstrap` for DNS server hostnames (Go
    /// `WithBootstrap`). Passing `None` sets the
    /// bootstrap explicitly to nil, which is still an
    /// error at [`Client::new`] (Go `client.go:70-72`:
    /// callers wanting the default pass no option).
    #[must_use]
    pub fn with_bootstrap(mut self, bootstrap: Option<BootstrapFn>) -> Self {
        self.bootstrap = bootstrap;
        self.bootstrap_set = true;
        self
    }
}

struct ClientState {
    started: bool,
    closed: bool,
}

/// A started/stopped DNS client (Go `Client`). Safe
/// for concurrent `Lookup` calls after `Start`;
/// `Start`/`Close` are serialized, double `Start` is
/// an error, `Close` is idempotent, and `Lookup` after
/// `Close` is an error.
pub struct Client {
    router: Arc<dyn DnsRouter>,
    transports: HashMap<String, Arc<dyn DnsTransport>>,
    state: Mutex<ClientState>,
}

impl Client {
    /// Build a `Client` from `opts` (Go `New`,
    /// `client.go:101-177`).
    ///
    /// Checks, in order (the Go order, minus the two
    /// unrepresentable ones — see the crate docs): no
    /// servers → `dns: no DNS servers configured:
    /// refusing to fall back to the system resolver`;
    /// nil bootstrap → `dns: bootstrap function must
    /// not be nil`. Then bootstrap substitution runs
    /// (5 s timeout per server hostname), then one
    /// transport is created per server (empty tag means
    /// the index, `fmt.Sprintf("%d", i)`); a factory
    /// failure is wrapped as `dns: create transport
    /// %s[%s]: %w`.
    ///
    /// Async (Go's `New` is sync): the bootstrap may do
    /// network I/O.
    pub async fn new(
        opts: DnsOptions,
        factory: Arc<dyn DnsTransportFactory>,
        options: ClientOptions,
    ) -> Result<Self, DnsError> {
        let bootstrap = if options.bootstrap_set {
            options.bootstrap
        } else {
            let default: BootstrapFn = Arc::new(|host: String| Box::pin(default_bootstrap(host)));
            Some(default)
        };
        if opts.servers.is_empty() {
            return Err(DnsError::message(
                "dns: no DNS servers configured: refusing to fall back to the system resolver",
            ));
        }
        let Some(bootstrap) = bootstrap else {
            return Err(DnsError::message("dns: bootstrap function must not be nil"));
        };
        let servers = substitute_bootstrap(&opts.servers, &bootstrap).await?;
        let mut transports: HashMap<String, Arc<dyn DnsTransport>> = HashMap::new();
        let mut ordered: Vec<Arc<dyn DnsTransport>> = Vec::with_capacity(servers.len());
        for (i, server) in servers.iter().enumerate() {
            let tagged = DnsServer {
                tag: if server.tag.is_empty() {
                    i.to_string()
                } else {
                    server.tag.clone()
                },
                kind: server.kind.clone(),
            };
            let transport = factory
                .create(&tagged)
                .map_err(|e| DnsError::CreateTransport {
                    kind: tagged.kind.type_name().to_string(),
                    tag: tagged.tag.clone(),
                    source: Box::new(e),
                })?;
            transports.insert(tagged.tag.clone(), Arc::clone(&transport));
            ordered.push(transport);
        }
        let router = Arc::new(SingleServerRouter::new(ordered, opts.final_tag));
        Ok(Self {
            router,
            transports,
            state: Mutex::new(ClientState {
                started: false,
                closed: false,
            }),
        })
    }

    /// Start the client (Go `Start`, `client.go:179-203`).
    /// A second `Start` is `dns: Start called twice`;
    /// `Start` after `Close` is `dns: Start called after
    /// Close`. The sing-box lifecycle stages have no Rust
    /// equivalent (the TCP transport is stateless); the
    /// flag flip is the whole start step.
    pub async fn start(&self) -> Result<(), DnsError> {
        let mut state = self.state.lock().await;
        if state.started {
            return Err(DnsError::message("dns: Start called twice"));
        }
        if state.closed {
            return Err(DnsError::message("dns: Start called after Close"));
        }
        state.started = true;
        Ok(())
    }

    /// Close the client (Go `Close`, `client.go:205-218`).
    /// Idempotent; safe without `Start`.
    pub async fn close(&self) -> Result<(), DnsError> {
        let mut state = self.state.lock().await;
        state.closed = true;
        Ok(())
    }

    /// Resolve `domain` through the configured DNS (Go
    /// `Lookup`, `client.go:221-232`, 5 s timeout). DNS
    /// failure is an error; there is no system-resolver
    /// fallback. `Lookup` after `Close` is
    /// `dns: Lookup called after Close`; `Lookup` before
    /// `Start` is an error (Go: an error from the
    /// router; the text is Rust-side, see the crate docs).
    pub async fn lookup(&self, domain: &str) -> Result<Vec<IpAddr>, DnsError> {
        {
            let state = self.state.lock().await;
            if state.closed {
                return Err(DnsError::message("dns: Lookup called after Close"));
            }
            if !state.started {
                return Err(DnsError::message("dns: lookup called before Start"));
            }
        }
        let router = Arc::clone(&self.router);
        let domain = domain.to_string();
        tokio::time::timeout(LOOKUP_TIMEOUT, router.lookup(&domain))
            .await
            .map_err(|_| DnsError::Timeout)?
    }

    /// The underlying DNS router, for registration with
    /// an outbound manager (Go `Router`,
    /// `client.go:235-236`). No outbound manager exists
    /// in Rust yet; the accessor is kept for shape.
    #[must_use]
    pub fn router(&self) -> Arc<dyn DnsRouter> {
        Arc::clone(&self.router)
    }

    /// The transport with `tag`, if one was created (Go
    /// `Transport`, `client.go:241-244`).
    #[must_use]
    pub fn transport(&self, tag: &str) -> Option<Arc<dyn DnsTransport>> {
        self.transports.get(tag).map(Arc::clone)
    }
}
