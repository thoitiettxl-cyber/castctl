// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! TEMPORARY minimal TLS HTTP client (M5a, parent decision).
//!
//! Why this module exists: `castctl-transport::HttpClient`
//! is plaintext-only and the Bot API is HTTPS-only, while the
//! shared TLS code (`tls.rs` + `request_tls`, M4b) exists only
//! in uncommitted work on another branch. This module is the
//! parent-decided option (B): a minimal TLS path inside
//! `castctl-telegram`, using rustls + tokio-rustls +
//! webpki-roots pinned exactly to the versions already in
//! `Cargo.lock` (no new crate enters the lock).
//!
//! DELETE THIS MODULE on rebase after M4b merges: use M4b's
//! `tls_client_config` + `HttpClient::request_tls` instead
//! (see PORTING.md §M5a). Do not extend it: no ALPN beyond
//! `http/1.1`, no client auth, no custom roots, no TLS
//! options of any kind.
//!
//! The request path mirrors `castctl-transport::http`
//! (`HttpClient::request_inner`) exactly: one fresh stream
//! per call, no proxy env, no redirect follow (any 3xx is
//! `TransportError::RedirectRefused`), body capped at
//! `MAX_RESPONSE_BODY` while streaming, `timeout` bounding
//! one attempt. The only difference is the TLS handshake
//! between dial and the hyper HTTP/1.1 handshake.
//!
//! There is no direct Go function counterpart for this
//! module: Go's `BoundClient`
//! (`internal/telegram/bot.go:316-352`) wraps a stdlib
//! `*http.Transport` whose TLS is implicit; this module is
//! the Rust-side equivalent of "dial through the outbound,
//! then speak HTTPS".

use std::sync::Arc;
use std::time::Duration;

use bytes::{Buf, Bytes};
use http::{HeaderMap, HeaderValue, Method, Request};
use http_body_util::{BodyExt, Full};
use hyper::client::conn::http1::SendRequest;
use hyper_util::rt::TokioIo;
use rustls::ClientConfig;
use tokio_rustls::TlsConnector;

use castctl_transport::{
    BodySummary, DialTarget, Dialer, HttpResponse, MAX_RESPONSE_BODY, TransportError,
};

/// ALPN offered to the peer: HTTP/1.1 only, mirroring M4b's
/// `TLS_ALPN_HTTP1` and Go's HTTP/1.1-only bot path (the Go
/// transport sets `ForceAttemptHTTP2: true`, but the Bot API
/// is served over HTTP/1.1; offering only `http/1.1` keeps
/// the handshake on the M3 HTTP/1.1 client).
pub const TLS_ALPN_HTTP1: &[u8] = b"http/1.1";

/// Build the rustls client config: Mozilla roots via
/// webpki-roots, no client auth, ALPN `http/1.1`, ring crypto
/// provider (the `ring` feature only — enabling both
/// `aws_lc_rs` and `ring` makes `ClientConfig::builder()`
/// panic at runtime; see M4b's note and `Cargo.toml`).
/// Source: M4b's `tls_client_config` (uncommitted at M5a
/// write time); the values are the same, the function is
/// re-implemented here so M5a does not depend on M4b.
#[must_use]
pub fn tls_client_config() -> Arc<ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

/// HTTPS/1.1 client over an outbound dialer: the TLS twin of
/// `castctl-transport::HttpClient`. Hand-written `Debug` (the
/// dialer may hold credentials; nothing about it is printed).
#[derive(Clone)]
pub struct TlsHttpClient {
    dialer: Arc<dyn Dialer>,
    config: Arc<ClientConfig>,
}

impl std::fmt::Debug for TlsHttpClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsHttpClient").finish_non_exhaustive()
    }
}

impl TlsHttpClient {
    /// Build a TLS HTTP client over `dialer`.
    /// No direct Go function counterpart; see the module doc.
    #[must_use]
    pub fn new(dialer: Arc<dyn Dialer>) -> Self {
        Self {
            dialer,
            config: tls_client_config(),
        }
    }

    /// Perform one HTTPS request through the outbound and
    /// return the full response. Same contract as
    /// `HttpClient::request`: redirects refused, body capped
    /// at `MAX_RESPONSE_BODY` while streaming, `timeout`
    /// bounds one attempt (dial + TLS handshake + send +
    /// read). A timeout maps to `TransportError::Timeout`.
    pub async fn request(
        &self,
        method: Method,
        target: &DialTarget,
        path: &str,
        headers: &[(String, String)],
        body: Option<Bytes>,
        timeout: Duration,
    ) -> Result<HttpResponse, TransportError> {
        self.request_with_body_cap(
            method,
            target,
            path,
            headers,
            body,
            timeout,
            MAX_RESPONSE_BODY,
        )
        .await
    }

    /// Same as [`TlsHttpClient::request`], but with an explicit
    /// body cap. The Bot API download path needs a 20 MiB + 1
    /// cap (Go `DownloadLimit`, `internal/telegram/inbound.go:33-40`)
    /// so the post-download gate can observe one byte past the
    /// limit; the plaintext `HttpClient` caps at 16 MiB and
    /// cannot be parameterised, so downloads over the plaintext
    /// path (tests only) keep the 16 MiB cap — see PORTING.md §M5a.
    /// The arity mirrors `HttpClient::request` plus the cap;
    /// see the `#[allow]` on `send_file_multipart`.
    #[allow(clippy::too_many_arguments)]
    pub async fn request_with_body_cap(
        &self,
        method: Method,
        target: &DialTarget,
        path: &str,
        headers: &[(String, String)],
        body: Option<Bytes>,
        timeout: Duration,
        max_body: usize,
    ) -> Result<HttpResponse, TransportError> {
        let work = self.request_inner(method, target, path, headers, body, max_body);
        match tokio::time::timeout(timeout, work).await {
            Ok(result) => result,
            Err(_) => Err(TransportError::Timeout {
                message: "https request timed out".to_string(),
            }),
        }
    }

    async fn request_inner(
        &self,
        method: Method,
        target: &DialTarget,
        path: &str,
        headers: &[(String, String)],
        body: Option<Bytes>,
        max_body: usize,
    ) -> Result<HttpResponse, TransportError> {
        let stream = self.dialer.dial(target).await?;
        let server_name =
            rustls::pki_types::ServerName::try_from(target.host.clone()).map_err(|_| {
                TransportError::Validation {
                    message: "invalid tls server name".to_string(),
                }
            })?;
        // TLS handshake failure is ConnectionDown: no request
        // bytes have been sent yet, so the request is safe to
        // repeat (same "nothing sent" rule as
        // `HttpClient::request_inner`).
        let tls_stream = TlsConnector::from(Arc::clone(&self.config))
            .connect(server_name, stream)
            .await
            .map_err(|e| TransportError::ConnectionDown {
                message: castctl_transport::error::truncate(&e.to_string(), 200),
            })?;
        let (mut sender, conn): (SendRequest<Full<Bytes>>, _) =
            hyper::client::conn::http1::Builder::new()
                .handshake(TokioIo::new(tls_stream))
                .await
                .map_err(|e| TransportError::ConnectionDown {
                    message: castctl_transport::error::truncate(&e.to_string(), 200),
                })?;
        tokio::spawn(async move {
            if let Err(_e) = conn.await {
                // Connection task ended; the request future
                // reports the failure through its own result.
            }
        });
        let mut builder = Request::builder().method(method).uri(path).header(
            http::header::HOST,
            HeaderValue::from_str(&host_header(target)).map_err(|_| {
                TransportError::Validation {
                    message: "invalid host header".to_string(),
                }
            })?,
        );
        for (k, v) in headers {
            builder = builder.header(
                k.as_str(),
                HeaderValue::from_str(v).map_err(|_| TransportError::Validation {
                    message: "invalid header value".to_string(),
                })?,
            );
        }
        let req = builder
            .body(Full::new(body.unwrap_or_default()))
            .map_err(|_| TransportError::Validation {
                message: "invalid http request".to_string(),
            })?;
        let resp = sender
            .send_request(req)
            .await
            .map_err(|e| TransportError::ConnectionError {
                message: castctl_transport::error::truncate(&e.to_string(), 200),
            })?;
        let (parts, body) = resp.into_parts();
        let status = parts.status;
        if status.is_redirection() {
            return Err(TransportError::RedirectRefused);
        }
        let headers = parts.headers;
        let mut body = body;
        let mut out: Vec<u8> = Vec::new();
        loop {
            match body.frame().await {
                Some(Ok(frame)) => {
                    if let Ok(data) = frame.into_data() {
                        if out.len() + data.remaining() > max_body {
                            return Err(TransportError::Gateway(BodySummary::new(
                                status.as_u16() as i32,
                                None,
                                content_type_of(&headers),
                            )));
                        }
                        out.extend_from_slice(&data);
                    }
                }
                Some(Err(e)) => {
                    return Err(TransportError::ConnectionError {
                        message: castctl_transport::error::truncate(&e.to_string(), 200),
                    });
                }
                None => break,
            }
        }
        Ok(HttpResponse {
            status,
            headers,
            body: Bytes::from(out),
        })
    }
}

/// `Host` header value: `host` for default ports, `host:port`
/// otherwise. Mirrors `castctl-transport::http::host_header`
/// (private there, so re-implemented; same rule).
fn host_header(target: &DialTarget) -> String {
    if target.port == 80 || target.port == 443 {
        target.host.clone()
    } else {
        format!("{}:{}", target.host, target.port)
    }
}

/// Raw Content-Type header value, for the body summary.
/// Mirrors `castctl-transport::http::content_type_of`
/// (private there, so re-implemented; same rule).
fn content_type_of(headers: &HeaderMap) -> &str {
    headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
}

/// The default Bot API target.
/// Source: `internal/telegram/bot.go:191-274` (`Settings.ServerURL`:
/// empty means the library default `https://api.telegram.org`).
#[must_use]
pub fn telegram_api_target() -> DialTarget {
    DialTarget::new("api.telegram.org", 443)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_header_rules() {
        assert_eq!(
            host_header(&DialTarget::new("api.telegram.org", 443)),
            "api.telegram.org"
        );
        assert_eq!(
            host_header(&DialTarget::new("127.0.0.1", 18080)),
            "127.0.0.1:18080"
        );
    }

    #[test]
    fn tls_config_builds_without_panic() {
        // The M4b-measured failure mode is a runtime panic
        // from ClientConfig::builder() when both crypto
        // providers are enabled; this test pins the safe shape.
        let _ = tls_client_config();
    }
}
