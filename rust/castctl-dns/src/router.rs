// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! DNS routers: pick a transport and combine A + AAAA
//! (Go `dns.Router`, the sing-box side, behind a trait).

use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;

use crate::error::DnsError;
use crate::transport::DnsTransport;
use crate::wire::{QTYPE_A, QTYPE_AAAA};

/// A DNS router (Go `adapter.DNSRouter`): resolves a
/// domain through the configured transports.
pub trait DnsRouter: Send + Sync {
    /// Resolve `domain` (Go `Router.Lookup`): A then
    /// AAAA, combined. DNS failure is an error; there
    /// is no system-resolver fallback.
    fn lookup(
        &self,
        domain: &str,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<IpAddr>, DnsError>> + Send + '_>>;
}

/// The single-server router: the shipped
/// [`DnsRouter`]. It uses the transport tagged
/// `final_tag` (Go `DNSOptions.Final`); when the final
/// tag is empty or names no transport, it uses the
/// first transport.
///
/// NOT the sing-box router: there is no rule matching,
/// no detour, no `local` / `hosts` / `fakeip`
/// behaviour. A config whose final tag names no server
/// still resolves through the first transport (a
/// documented simplification — the rule engine that
/// would distinguish the servers is not ported).
pub struct SingleServerRouter {
    transports: Vec<Arc<dyn DnsTransport>>,
    final_tag: String,
}

impl SingleServerRouter {
    /// Build from the transports in server order.
    #[must_use]
    pub fn new(transports: Vec<Arc<dyn DnsTransport>>, final_tag: String) -> Self {
        Self {
            transports,
            final_tag,
        }
    }

    fn pick(&self) -> Option<Arc<dyn DnsTransport>> {
        if !self.final_tag.is_empty() {
            if let Some(t) = self
                .transports
                .iter()
                .find(|t| t.tag() == self.final_tag)
            {
                return Some(Arc::clone(t));
            }
        }
        self.transports.first().map(Arc::clone)
    }
}

impl DnsRouter for SingleServerRouter {
    fn lookup(
        &self,
        domain: &str,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<IpAddr>, DnsError>> + Send + '_>> {
        let Some(transport) = self.pick() else {
            // Unreachable through `Client::new` (it
            // refuses zero servers); fail closed rather
            // than answering from nothing.
            return Box::pin(async {
                Err(DnsError::message(
                    "dns: no DNS servers configured: refusing to fall back to the system resolver",
                ))
            });
        };
        let domain = domain.to_string();
        Box::pin(async move {
            let mut out = transport.exchange(&domain, QTYPE_A).await?;
            // AAAA is best effort: a v4-only answer
            // stands on its own when the AAAA exchange
            // fails (no ported test pins this; the
            // sing-box router's exact partial-failure
            // behaviour is unported).
            if let Ok(v6) = transport.exchange(&domain, QTYPE_AAAA).await {
                out.extend(v6);
            }
            Ok(out)
        })
    }
}
