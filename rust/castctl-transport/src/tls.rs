// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! TLS client configuration for HTTPS over an outbound (M4b).
//!
//! Used by `HttpClient::request_tls` for the `muse.ai` HTTPS
//! side-paths (`FetchSessionInfo`, `FetchAccessToken`,
//! `FetchHatchToken`, `FetchSubscription`).
//!
//! The gateway WS dial does NOT use this rustls config anymore:
//! since M4c it wraps the stream with honk's BoringSSL Chrome
//! connector (`honk_tls_wrap` below) — rustls sends a 251-byte
//! ClientHello the Meta edge answers with HTTP 502, while
//! honk/Chrome sends the Chrome fingerprint Go sends (see
//! `rust/PORTING.md` §M4c). `tls_client_config` stays for
//! `http.rs` only (the HTTPS chain passes live on rustls).
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

use honk_config::node::{AnyTlsConfig, Node, OutboundConfig, TlsOptions};
use rustls::ClientConfig;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::error::TransportError;

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

/// The gateway WS TLS failure, byte-identical to
/// `castctl-gateway::dial::tls_failed` (29 chars, Go parity —
/// see `rust/PORTING.md` §M4b.2; M4b docs said 28, the literal
/// is 29 — counted by `len()`, not by hand). Both spellings
/// must stay identical; the integration test `tests/honk_tls.rs`
/// pins this one, the gateway unit tests pin the other. Any
/// honk / BoringSSL error text is discarded here on purpose:
/// it can embed peer material, and Go's dial-stage failure is
/// a fixed class too.
fn gateway_ws_tls_failed() -> TransportError {
    TransportError::ConnectionError {
        message: "gateway: websocket TLS failed".to_string(),
    }
}

/// Build the honk (BoringSSL) TLS connector for a gateway WS
/// dial: Chrome mode, SNI = the WS host, ALPN pinned to
/// `["http/1.1"]` (Go `internal/gateway/connector.go:240`).
///
/// The node is synthetic — it is NOT an outbound node (the
/// outbound dial already happened upstream); `AnyTls` is the
/// cheapest carrier of a `TlsOptions` (`honk-config` has no
/// fingerprint/cipher/ALPS field on any node — every such
/// difference lives in honk-outbound, see PORTING §M3e.3).
/// `ech_enabled` stays default (`false`): no DNS HTTPS-RR
/// discovery at connect time, and honk still GREASEs ECH in
/// Chrome mode, matching Go/uTLS (which also only GREASEs
/// ECH for this host).
///
/// Chrome mode is process-global and `build_connector` reads
/// it at build time — and a `direct` profile NEVER runs
/// `build_tls` (`dispatch_outbound` returns before it), so a
/// gateway dial on a direct profile would otherwise build a
/// plain-BoringSSL (non-Chrome) connector. Set the mode here,
/// idempotently (same call as `apply_tls_mode`), so the wrap
/// is correct regardless of which path dialed first.
fn build_gateway_tls_connector(
    host: &str,
) -> Result<honk_outbound::tls::TlsConnector, TransportError> {
    honk_outbound::tls::set_tls_mode("utls");
    honk_outbound::tls::set_utls_imitate("chrome");
    let node = Node {
        host: host.to_string(),
        outbound: OutboundConfig::AnyTls(AnyTlsConfig {
            tls: TlsOptions {
                enabled: true,
                sni: Some(host.to_string()),
                alpn: vec!["http/1.1".to_string()],
                ..Default::default()
            },
            ..Default::default()
        }),
        ..Default::default()
    };
    honk_outbound::tls::build_connector(&node).map_err(|_| gateway_ws_tls_failed())
}

/// Type-erased TLS-wrapped stream for the gateway WS dial.
/// A trait object can only carry ONE non-auto trait
/// (`Box<dyn AsyncRead + AsyncWrite>` does not compile), so
/// the wrap returns this single trait instead of naming
/// honk's `AsyncReadWrite` — that would force a `Debug`
/// bound up through the gateway's generic dial signatures,
/// and the gateway crate stays honk-free (it only ever names
/// this transport trait).
pub trait TlsStream: AsyncRead + AsyncWrite + Send + Unpin {}

impl<T> TlsStream for T where T: AsyncRead + AsyncWrite + Send + Unpin + 'static {}

/// TLS-wrap a stream for a `wss://` gateway dial with honk's
/// BoringSSL Chrome connector (SNI = `host`, ALPN
/// `["http/1.1"]`). Any failure — connector build or
/// handshake — maps to the fixed 29-char
/// `gateway: websocket TLS failed`, never to honk/boring
/// error text.
pub async fn honk_tls_wrap<S>(stream: S, host: &str) -> Result<Box<dyn TlsStream>, TransportError>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let connector = build_gateway_tls_connector(host)?;
    let tls = connector
        .connect(host, stream)
        .await
        .map_err(|_| gateway_ws_tls_failed())?;
    Ok(Box::new(tls))
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

    #[test]
    fn gateway_tls_connector_builds_for_host() {
        // Build-only seam: the synthetic AnyTls node must pass
        // honk's validation (ALPN, node shape) without a network
        // round-trip. The handshake itself is covered by the
        // integration test + the live probe.
        assert!(
            build_gateway_tls_connector("example.com").is_ok(),
            "the gateway TLS connector must build for a plain hostname"
        );
    }
}
