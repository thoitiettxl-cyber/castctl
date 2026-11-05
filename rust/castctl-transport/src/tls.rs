// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! TLS client configuration for HTTPS over an outbound (M4b).
//!
//! Used by `HttpClient::request_tls` for the `muse.ai` HTTPS
//! side-paths (`FetchSessionInfo`, `FetchAccessToken`,
//! `FetchHatchToken`, `FetchSubscription`) and by the gateway
//! WS dial over an outbound stream (`dial_gateway_over_stream`).
//!
//! Trust basis: Mozilla roots via `webpki-roots`, the same
//! basis tokio-tungstenite's default config uses
//! (`tokio-tungstenite-0.30.0/src/tls.rs`: `root_store.extend(
//! webpki_roots::TLS_SERVER_ROOTS.iter().cloned())` then
//! `ClientConfig::builder().with_root_certificates(root_store)
//! .with_no_client_auth()`). No client auth, no native certs.
//!
//! ALPN: `["http/1.1"]`. Go pins `["http/1.1"]` for the
//! WebSocket dial (`internal/gateway/connector.go` — gorilla
//! cannot upgrade over h2); the Rust HTTPS client pins the
//! same because hyper's http1 client cannot speak h2, while
//! Go's HTTPS chain negotiates h2 via `ForceAttemptHTTP2` —
//! the same request/response over HTTP/1.1, recorded as a
//! deviation in `rust/PORTING.md` §M4b.
//!
//! The crypto provider is `ring`, declared explicitly on this
//! crate's `rustls` dependency (see `Cargo.toml`): the config
//! builder must not depend on another crate's feature
//! selection.

use std::sync::Arc;

use rustls::ClientConfig;

/// ALPN protocol pinned for HTTPS and for the WS dial over an
/// outbound stream (see the module docs).
pub const TLS_ALPN_HTTP1: &[u8] = b"http/1.1";

/// Build the shared rustls client config: Mozilla roots, no
/// client auth, ALPN `http/1.1`. Infallible: root extension
/// skips unparsable anchors instead of failing, and the
/// builder has no fallible step.
pub fn tls_client_config() -> Arc<ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![TLS_ALPN_HTTP1.to_vec()];
    Arc::new(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_config_pins_http11_alpn() {
        let cfg = tls_client_config();
        assert_eq!(
            cfg.alpn_protocols,
            vec![TLS_ALPN_HTTP1.to_vec()],
            "ALPN must be exactly [http/1.1]"
        );
    }
}
