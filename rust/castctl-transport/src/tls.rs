// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! TLS client configuration for HTTPS over an outbound (M4b).
//!
//! Used by `HttpClient::request_tls` for the `muse.ai` HTTPS
//! side-paths (`FetchSessionInfo`, `FetchAccessToken`,
//! `FetchHatchToken`, `FetchSubscription`).
//!
//! The gateway WS dial uses this same rustls config
//! (`rustls_tls_wrap` below, ALPN `["http/1.1"]`, SNI =
//! host) — restored in M4c step 3: the live matrix proved
//! the token, not the TLS fingerprint, decides the upgrade
//! (rustls + real token → 101, same output as honk +
//! real token; see `rust/PORTING.md` §M4c.8), so the
//! simpler rustls path stays and the honk wrap was removed.
//! `tls_client_config` serves both `http.rs` (HTTPS chain)
//! and the WS dial.
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
/// must stay identical; the gateway unit test
/// `tls_failed_is_29_chars` pins this one (the M4c
/// `tests/honk_tls.rs` integration test is gone with the honk
/// wrap). Any rustls error text is discarded here on purpose:
/// it can embed peer material, and Go's dial-stage failure is
/// a fixed class too.
fn gateway_ws_tls_failed() -> TransportError {
    TransportError::ConnectionError {
        message: "gateway: websocket TLS failed".to_string(),
    }
}

/// Type-erased TLS-wrapped stream for the gateway WS dial.
/// A trait object can only carry ONE non-auto trait
/// (`Box<dyn AsyncRead + AsyncWrite>` does not compile), so
/// the wrap returns this single trait instead of naming
/// `tokio_rustls::client::TlsStream<S>` — that would pin
/// the concrete TLS engine into the gateway's generic dial
/// signatures (the M4c honk wrap needed the same erasure
/// for the same reason).
pub trait TlsStream: AsyncRead + AsyncWrite + Send + Unpin {}

impl<T> TlsStream for T where T: AsyncRead + AsyncWrite + Send + Unpin + 'static {}

/// TLS-wrap a stream for a `wss://` gateway dial with rustls
/// (`tokio-rustls` + `tls_client_config`, ALPN
/// `["http/1.1"]`, SNI = host). Any failure — bad server
/// name or handshake — maps to the fixed 29-char
/// `gateway: websocket TLS failed`, never to rustls error
/// text.
pub async fn rustls_tls_wrap<S>(stream: S, host: &str) -> Result<Box<dyn TlsStream>, TransportError>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    // Owned form: `connect` needs a `ServerName<'static>`.
    let name = tokio_rustls::rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|_| gateway_ws_tls_failed())?;
    let tls = tokio_rustls::TlsConnector::from(tls_client_config())
        .connect(name, stream)
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
}
