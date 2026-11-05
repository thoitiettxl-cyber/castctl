// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! DNS error type. Verbatim Go error strings are kept
//! for the construction and lifecycle errors the ported
//! tests pin (`client.go:101-232`); wire-level failures
//! use Rust-side messages (Go's are sing-box-internal
//! and no ported test pins them).

use std::fmt;

/// One DNS failure. `Display` is the message a caller
/// (or a log line) sees; no addresses are ever rendered.
#[derive(Debug)]
pub enum DnsError {
    /// A verbatim Go error string (construction and
    /// lifecycle errors).
    Message(String),
    /// `dns: bootstrap for server %q: %w` (Go
    /// `bootstrap.go:26-37`): `server` is the server
    /// TAG, `source` carries the host-level error.
    Bootstrap {
        server: String,
        source: Box<DnsError>,
    },
    /// `dns: create transport %s[%s]: %w` (Go
    /// `client.go:158-163`).
    CreateTransport {
        kind: String,
        tag: String,
        source: Box<DnsError>,
    },
    /// The server answered NXDOMAIN (RCODE 3).
    NxDomain,
    /// The server answered a non-zero RCODE other than
    /// NXDOMAIN.
    ServerRcode(u16),
    /// The 5 s lookup timeout (Go `client.go:228`). The
    /// bootstrap timeout renders Go's `context deadline
    /// exceeded` text instead (see
    /// [`crate::bootstrap::default_bootstrap`]).
    Timeout,
    /// A transport I/O failure (connect, read, write).
    Io(std::io::Error),
    /// A malformed DNS wire message.
    Protocol(String),
    /// A server kind the shipped transport cannot build
    /// (TLS / HTTPS / local / hosts / fakeip): fail
    /// closed at construction, never a silent plaintext
    /// downgrade.
    Unsupported(String),
}

impl DnsError {
    /// A verbatim Go error string.
    #[must_use]
    pub fn message(text: &str) -> Self {
        Self::Message(text.to_string())
    }
}

impl fmt::Display for DnsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Message(text) => write!(f, "{text}"),
            Self::Bootstrap { server, source } => {
                write!(f, "dns: bootstrap for server {server:?}: {source}")
            }
            Self::CreateTransport { kind, tag, source } => {
                write!(f, "dns: create transport {kind}[{tag}]: {source}")
            }
            Self::NxDomain => write!(f, "dns: NXDOMAIN"),
            Self::ServerRcode(rcode) => {
                write!(f, "dns: server returned rcode {rcode}")
            }
            Self::Timeout => write!(f, "dns: lookup timed out"),
            Self::Io(err) => write!(f, "dns: {err}"),
            Self::Protocol(msg) => write!(f, "dns: {msg}"),
            Self::Unsupported(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for DnsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Bootstrap { source, .. } | Self::CreateTransport { source, .. } => {
                Some(source.as_ref())
            }
            Self::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<std::io::Error> for DnsError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}
