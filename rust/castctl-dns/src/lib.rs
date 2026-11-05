// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! A profile DNS client, ported from Go `internal/dns`
//! (M7a, scoped).
//!
//! Fail-closed invariant (Go `client.go:1-35`): DNS failure
//! is an error. There is NO system-resolver fallback for
//! dial targets: no servers configured is an error at
//! construction, a failing transport is an error at lookup,
//! and `localhost` resolves only if the configured DNS
//! server answers for it. The system resolver is consulted
//! in exactly two cases, never for dial targets: (a) the
//! DNS server's own hostname, resolved once at
//! construction through an injected bootstrap function
//! (default: a `tokio::net::lookup_host` lookup with its
//! own 5 s timeout); (b) outbound server hostnames through
//! the synthesised `local` DNS transport — not ported
//! (see the scope note below).
//!
//! # Scope (honest, not a full router)
//!
//! Go builds on sing-box `dns.Router` +
//! `dns.TransportManager` from `option.DNSOptions`.
//! There is no Rust equivalent of either type yet, so
//! this crate ports the API surface, the bootstrap
//! substitution, and the lifecycle, behind two traits:
//!
//! - [`DnsTransport`]: one DNS exchange (a single
//!   question) against one server. The shipped
//!   implementation is [`TcpDnsTransport`] (DNS over TCP,
//!   A/AAAA only, one connection per exchange).
//! - [`DnsRouter`]: picks a transport and combines A +
//!   AAAA. The shipped implementation is
//!   [`SingleServerRouter`]: it uses the transport tagged
//!   `final_tag` (else the first server). Rule matching,
//!   `local` / `hosts` / `fakeip` servers, detours,
//!   selectors, caching, and retries all live inside
//!   sing-box and are NOT ported.
//!
//! Consequences, recorded as deviations in
//! `rust/PORTING.md` §M7a:
//!
//! - `Client::new` is `async` (Go's is sync): the
//!   bootstrap may do network I/O, and a Rust
//!   constructor that does I/O is async. The 5 s
//!   bootstrap timeout and the 5 s lookup timeout are
//!   kept verbatim.
//! - Go's `New` checks, in order: no servers, nil
//!   outbound manager, nil bootstrap, no DNS transport
//!   registry in ctx. The outbound-manager and registry
//!   checks have no Rust equivalent (there is no service
//!   context and no outbound manager yet): the transport
//!   factory is a required constructor argument, so a
//!   caller cannot construct a `Client` without one.
//!   The no-servers and nil-bootstrap checks are kept
//!   verbatim, in order.
//! - TLS / HTTPS DNS servers fail closed at construction
//!   (`DnsError::Unsupported`): the port refuses to
//!   build them rather than silently downgrading to
//!   plaintext TCP. `local` / `hosts` / `fakeip` servers
//!   fail the same way.
//! - `Lookup` before `Start` is an error (Go: an error
//!   from the router). The error text is Rust-side —
//!   Go's router error text is sing-box-internal and no
//!   ported test pins it.
//! - No log factory: the crate has no logging
//!   dependency. The default bootstrap does not log.

pub mod bootstrap;
pub mod client;
pub mod error;
pub mod router;
pub mod server;
pub mod transport;
pub mod wire;

pub use bootstrap::{BOOTSTRAP_TIMEOUT, BootstrapFn, default_bootstrap, substitute_bootstrap};
pub use client::{LOOKUP_TIMEOUT, Client, ClientOptions};
pub use error::DnsError;
pub use router::{DnsRouter, SingleServerRouter};
pub use server::{DnsOptions, DnsServer, DnsServerKind, is_domain};
pub use transport::{DnsTransport, DnsTransportFactory, TcpDnsTransport, TcpTransportFactory};
pub use wire::{DnsMessage, QTYPE_A, QTYPE_AAAA, decode_message, encode_query};
