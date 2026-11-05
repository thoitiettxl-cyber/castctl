// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! DNS server options (Go `option.DNSServerOptions` /
//! `option.DNSOptions`, `internal/dns/client.go:101-177`).
//!
//! Only the shapes the bootstrap substitution and the
//! TCP transport need are modelled. The sing-box router
//! options (rules, `final` semantics beyond the tag)
//! are not: see the crate docs.

/// One configured DNS server (Go
/// `option.DNSServerOptions`: a tag plus a type and its
/// options).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsServer {
    /// Tag (Go `DNSServerOptions.Tag`; empty at
    /// construction means the index, `fmt.Sprintf("%d",
    /// i)`, assigned by [`crate::client::Client::new`]).
    pub tag: String,
    /// Server kind and address (Go `Type` + `Options`).
    pub kind: DnsServerKind,
}

/// A DNS server kind (Go `option.DNSServerOptions.Type`
/// + the corresponding `*Options` struct).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsServerKind {
    /// Plain TCP DNS (Go type `"tcp"`,
    /// `option.RemoteDNSServerOptions`).
    Tcp {
        /// Server host: an IP literal, or a domain to be
        /// resolved once by the bootstrap at construction.
        server: String,
        /// Server port.
        server_port: u16,
    },
    /// DNS over TLS (Go type `"tls"`,
    /// `option.RemoteTLSDNSServerOptions`). The port
    /// refuses to build a transport for it (fail closed);
    /// the substitution still preserves `server_name`.
    Tls {
        server: String,
        server_port: u16,
        /// TLS ServerName (empty = the original hostname
        /// after substitution, Go `bootstrap.go:69-74`).
        server_name: String,
    },
    /// DNS over HTTPS (Go type `"https"`,
    /// `option.RemoteHTTPSDNSServerOptions`). Same
    /// fail-closed rule as [`DnsServerKind::Tls`].
    Https {
        server: String,
        server_port: u16,
        server_name: String,
    },
    /// The sing-box `local` server (system resolver).
    /// Returned unchanged by substitution; the factory
    /// refuses to build it — there is no system-resolver
    /// fallback for dial targets.
    Local,
    /// The sing-box `hosts` server (static hosts).
    /// Returned unchanged by substitution; not built.
    Hosts,
    /// The sing-box `fakeip` server. Returned unchanged
    /// by substitution; not built.
    FakeIp,
}

impl DnsServerKind {
    /// The Go type string (`"tcp"` / `"tls"` /
    /// `"https"` / `"local"` / `"hosts"` / `"fakeip"`),
    /// for the `create transport %s[%s]` error wrap.
    #[must_use]
    pub fn type_name(&self) -> &'static str {
        match self {
            Self::Tcp { .. } => "tcp",
            Self::Tls { .. } => "tls",
            Self::Https { .. } => "https",
            Self::Local => "local",
            Self::Hosts => "hosts",
            Self::FakeIp => "fakeip",
        }
    }

    /// The server address, for the kinds that carry one.
    #[must_use]
    pub fn server(&self) -> Option<&str> {
        match self {
            Self::Tcp { server, .. }
            | Self::Tls { server, .. }
            | Self::Https { server, .. } => Some(server),
            Self::Local | Self::Hosts | Self::FakeIp => None,
        }
    }
}

/// DNS options (Go `option.DNSOptions`, the fields this
/// port uses: `Servers` and `Final`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DnsOptions {
    /// Configured servers, in order.
    pub servers: Vec<DnsServer>,
    /// The final server tag (Go `DNSOptions.Final`):
    /// the router's default transport. Empty means the
    /// first server (see [`crate::router::SingleServerRouter`]).
    pub final_tag: String,
}

/// Whether a server host is a domain (Go
/// `DNSServerAddressOptions.ServerIsDomain`: the host is
/// a domain iff it does not parse as an IP literal).
#[must_use]
pub fn is_domain(host: &str) -> bool {
    host.parse::<std::net::IpAddr>().is_err()
}
