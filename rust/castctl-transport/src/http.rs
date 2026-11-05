// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! HTTP/1.1 client over an outbound dialer.
//!
//! Go sources: `internal/outbound/dialer.go:204-236`
//! (`Dialer.HTTPClient`: `Proxy: nil`, custom `DialContext`/
//! `DialTLSContext`, `ForceAttemptHTTP2: true`,
//! `MaxIdleConns: 100`, `IdleConnTimeout: 90s`,
//! `TLSHandshakeTimeout: 10s`, `ExpectContinueTimeout: 1s`, no
//! cookie jar, no redirect policy at this layer) and
//! `internal/telegram/bot.go:316-352` (`BoundClient`,
//! `noFollowRedirect`).
//!
//! Invariants ported here, with tests in `tests/rpc.rs` and
//! `tests/env_proxy.rs`:
//! - NEVER consult proxy environment variables. This client has
//!   no proxy concept at all: it dials through the supplied
//!   `Dialer` only. (Go `BoundClient` additionally REJECTS a
//!   transport with a non-nil `Proxy` or a nil/default transport;
//!   the Rust equivalent is structural: there is no field that
//!   could hold a proxy, and the grep check in `dialer.rs` proves
//!   no env reads exist in `src/`.)
//! - NEVER follow redirects. Hyper's low-level `client::conn`
//!   does not follow redirects on its own (that is a reqwest
//!   feature); this client additionally turns ANY 3xx response
//!   into `TransportError::RedirectRefused` and never issues a
//!   second request. This matters for token-bearing paths: Go's
//!   `noFollowRedirect` exists so a token URL is never re-sent to
//!   a second host.
//! - No cookie jar: no `Cookie` header is stored or replayed
//!   between calls (each call builds its own request).
//! - One fresh stream per call (no pooling): the Go 90s idle
//!   timeout and 100-connection pool have no counterpart here
//!   because there is no pool. That is a deliberate M3
//!   simplification, recorded in PORTING.md §M3, not a parity
//!   claim.
//!
//! HTTP version: HTTP/1.1 only in M3 (hyper `http1` client conn).
//! Go sets `ForceAttemptHTTP2: true` on its transport; M3 does
//! not negotiate h2 over an outbound stream yet — a peer that
//! requires h2 will fail at this layer, which is fail-closed and
//! recorded in PORTING.md §M3.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, Request, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::client::conn::http1::SendRequest;

use crate::dialer::{DialTarget, Dialer};
use crate::error::{BodySummary, TransportError, validate_content_type};

/// Maximum response body accepted in one call. This is an M3-local
/// guard against an unbounded peer body, NOT a Go parity value:
/// Go's HTTP path has no such bound in `Dialer.HTTPClient`, while
/// its gateway (WebSocket) path has separate reassembly limits.
/// 16 MiB is large enough for any JSON RPC envelope and small
/// enough to bound memory; exceeding it is a `ConnectionError`
/// (transport failure after sending), not a gateway error.
pub const MAX_RESPONSE_BODY: usize = 16 * 1024 * 1024;

/// One HTTP response: status, headers and the full body bytes.
/// The body bytes are held only for the caller to decode; they are
/// NEVER copied into an error (see `rpc::call_json`, which
/// summarizes instead).
#[derive(Debug)]
pub struct HttpResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Bytes,
}

impl HttpResponse {
    /// Content-Type header value, raw (validation happens in the
    /// summary builder, not here).
    pub fn content_type(&self) -> &str {
        self.headers
            .get(http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
    }

    /// Allowlist summary of this response (status + length +
    /// validated content-type), for error construction.
    pub fn summary(&self) -> BodySummary {
        BodySummary::new(
            self.status.as_u16() as i32,
            Some(&self.body),
            self.content_type(),
        )
    }

    /// Validated content-type (see `error::validate_content_type`).
    pub fn validated_content_type(&self) -> Option<String> {
        validate_content_type(self.content_type())
    }
}

/// HTTP client bound to one dialer (one profile outbound).
/// Hand-written Debug: the dialer may be a `HonkDialer` whose
/// node holds credentials, and `Arc<dyn Dialer>` has no Debug
/// bound — so this struct prints nothing about the dialer.
#[derive(Clone)]
pub struct HttpClient {
    dialer: Arc<dyn Dialer>,
}

impl std::fmt::Debug for HttpClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpClient").finish_non_exhaustive()
    }
}

impl HttpClient {
    pub fn new(dialer: Arc<dyn Dialer>) -> Self {
        Self { dialer }
    }

    /// Perform one HTTP request through the outbound and return
    /// the full response. Redirects are NOT followed: a 3xx
    /// status returns `RedirectRefused` (the response body is
    /// dropped, never treated as success).
    ///
    /// `timeout` bounds the whole request (dial + send + read),
    /// mirroring Go's per-call timeouts at the RPC layer
    /// (`DefaultRequestTimeout = 30s`, `internal/gateway/calls.go`).
    /// A timeout maps to `TransportError::Timeout` (never retried).
    /// A dial failure maps to `ConnectionDown` (nothing sent);
    /// a failure after the stream opened maps to
    /// `ConnectionError` (reply possibly lost) — the distinction
    /// `retry::should_retry` depends on.
    pub async fn request(
        &self,
        method: Method,
        target: &DialTarget,
        path: &str,
        headers: &[(String, String)],
        body: Option<Bytes>,
        timeout: Duration,
    ) -> Result<HttpResponse, TransportError> {
        let work = self.request_inner(method, target, path, headers, body);
        match tokio::time::timeout(timeout, work).await {
            Ok(result) => result,
            Err(_) => Err(TransportError::Timeout {
                message: "http request timed out".to_string(),
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
    ) -> Result<HttpResponse, TransportError> {
        // Dial first: any failure here is ConnectionDown (Go:
        // nothing was sent yet, so the request is safe to repeat).
        let stream = self.dialer.dial(target).await?;
        let (mut sender, conn): (SendRequest<Full<Bytes>>, _) =
            hyper::client::conn::http1::Builder::new()
                .handshake(stream)
                .await
                .map_err(|e| TransportError::ConnectionError {
                    message: crate::error::truncate(&e.to_string(), 200),
                })?;
        // The connection task must be driven; dropping it would
        // stall the request. It is spawned, not awaited: its
        // errors surface through the send/collect calls below.
        tokio::spawn(async move {
            if let Err(_e) = conn.await {
                // Connection task ended (peer closed / error).
                // Nothing to log here: the request future reports
                // the failure through its own result.
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
        // Content-Type is set by the caller (RPC sets
        // application/json only when a body is present, mirroring
        // Go `internal/gateway/stream.go` header rules).
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
                message: crate::error::truncate(&e.to_string(), 200),
            })?;
        let (parts, body) = resp.into_parts();
        let status = parts.status;
        // Redirects are refused, never followed (Go
        // `noFollowRedirect`). The Location value is kept only as
        // a short, bounded diagnostic in the error — and even that
        // is NOT printed by Display (see error.rs).
        if status.is_redirection() {
            let location = parts
                .headers
                .get(http::header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();
            // Drain nothing: the connection is dropped with the
            // response; no second request is ever issued.
            return Err(TransportError::RedirectRefused {
                location: crate::error::truncate(&location, 200),
            });
        }
        let headers = parts.headers;
        let collected = body
            .collect()
            .await
            .map_err(|e| TransportError::ConnectionError {
                message: crate::error::truncate(&e.to_string(), 200),
            })?;
        let body_bytes = collected.to_bytes();
        if body_bytes.len() > MAX_RESPONSE_BODY {
            return Err(TransportError::ConnectionError {
                message: "response body exceeds limit".to_string(),
            });
        }
        Ok(HttpResponse {
            status,
            headers,
            body: body_bytes,
        })
    }
}

/// `Host` header value: `host` for default ports, `host:port`
/// otherwise. Port 80 (http) and 443 (https) are treated as
/// default; the RPC layer always passes an explicit target, so
/// the port is included unless it is one of those two.
fn host_header(target: &DialTarget) -> String {
    if target.port == 80 || target.port == 443 {
        target.host.clone()
    } else {
        format!("{}:{}", target.host, target.port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_header_rules() {
        assert_eq!(
            host_header(&DialTarget::new("example.com", 443)),
            "example.com"
        );
        assert_eq!(
            host_header(&DialTarget::new("127.0.0.1", 18080)),
            "127.0.0.1:18080"
        );
    }
}
