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
//! - Connections are pooled and reused, like Go's `http.Transport`
//!   (`MaxIdleConns` / `IdleConnTimeout: 90s`): up to
//!   [`MAX_IDLE_PER_TARGET`] idle sockets per target, dropped after
//!   [`IDLE_TIMEOUT`]. A pooled socket the peer already closed is
//!   retried once on a fresh connection, and only when the request
//!   was never written (`hyper::Error::is_closed`), so a POST is
//!   never replayed. M3 shipped without a pool as a deliberate
//!   simplification; the cost was measured (2026-11-07) at ~3.5x
//!   slower plain-HTTP traffic — see `rust/AGENT-CLI-SCOPE.md`.
//!
//! HTTP version: HTTP/1.1 only in M3 (hyper `http1` client conn).
//! Go sets `ForceAttemptHTTP2: true` on its transport; M3 does
//! not negotiate h2 over an outbound stream yet — a peer that
//! requires h2 will fail at this layer, which is fail-closed and
//! recorded in PORTING.md §M3.

use std::collections::HashMap;
use std::io::Read as _;
use std::sync::Arc;
use std::time::Duration;

use bytes::{Buf, Bytes};
use http::{HeaderMap, HeaderValue, Method, Request, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::client::conn::http1::SendRequest;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::dialer::{DialTarget, Dialer};
use crate::error::{BodySummary, TransportError, validate_content_type};
use crate::tls::tls_client_config;

/// Maximum response body accepted in one call. This is an M3-local
/// guard against an unbounded peer body, NOT a Go parity value:
/// Go's HTTP path has no such bound in `Dialer.HTTPClient`, while
/// its gateway (WebSocket) path has separate reassembly limits.
/// 16 MiB is large enough for any JSON RPC envelope and small
/// enough to bound memory. The cap is enforced DURING the read
/// (see `request_inner`): the body is streamed frame by frame and
/// the read aborts as soon as the running total would exceed the
/// cap — the previous `collect()`-then-check order buffered the
/// whole body first and could OOM on a hostile oversized body
/// before the check ever ran. Exceeding the cap is a `Gateway`
/// error (server-side failure, exit 3, never retried: a retry
/// would deterministically re-download the same oversized body
/// until the budget ran out), not a `ConnectionError`.
pub const MAX_RESPONSE_BODY: usize = 16 * 1024 * 1024;

/// One HTTP response: status, headers and the full body bytes.
/// The body bytes are held only for the caller to decode; they are
/// NEVER copied into an error (see `rpc::call_json`, which
/// summarizes instead).
pub struct HttpResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Bytes,
}

// Hand-written Debug (no derive): a derived Debug would print all
// response headers (including a server-sent `Set-Cookie`) and the
// full body bytes. Only status + body length are printed,
// mirroring `BodySummary`.
impl std::fmt::Debug for HttpResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpResponse")
            .field("status", &self.status)
            .field("body_length", &self.body.len())
            .finish_non_exhaustive()
    }
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

/// Raw Content-Type header value of a header map ("" when absent
/// or non-ASCII — `BodySummary::new` validates it anyway).
/// Same extraction as `HttpResponse::content_type`, for the
/// over-cap path where no `HttpResponse` exists yet.
fn content_type_of(headers: &HeaderMap) -> &str {
    headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
}

/// HTTP client bound to one dialer (one profile outbound).
/// Hand-written Debug: the dialer may be a `HonkDialer` whose
/// node holds credentials, and `Arc<dyn Dialer>` has no Debug
/// bound — so this struct prints nothing about the dialer.
#[derive(Clone)]
pub struct HttpClient {
    dialer: Arc<dyn Dialer>,
    /// Shared rustls client config (Mozilla roots, ALPN
    /// `http/1.1`), built once per client for `request_tls`.
    tls_config: Arc<rustls::ClientConfig>,
    /// Idle keep-alive connections, keyed by scheme + host + port.
    /// Shared by clones: one profile has one pool, like Go's one
    /// `http.Transport`.
    idle: Arc<std::sync::Mutex<HashMap<String, Vec<IdleConn>>>>,
}

/// One idle HTTP/1.1 connection and the instant it went idle.
type IdleConn = (std::time::Instant, SendRequest<Full<Bytes>>);

/// Idle connections kept per target. 16 is the width of the
/// subscription chunk pool, so a burst keeps its sockets instead of
/// re-handshaking mid-scan.
pub const MAX_IDLE_PER_TARGET: usize = 16;

/// How long an idle socket is kept before it is dropped without a
/// probe (Go `http.Transport.IdleConnTimeout: 90s`).
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(90);

/// Why an exchange did not produce a response.
enum ExchangeFailure {
    /// The connection was gone before the request was written (an
    /// idle socket the peer closed). Nothing was sent, so the
    /// caller may retry once on a fresh connection.
    IdleDead,
    /// Anything else: never retried here.
    Transport(TransportError),
}

impl std::fmt::Debug for HttpClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpClient").finish_non_exhaustive()
    }
}

impl HttpClient {
    pub fn new(dialer: Arc<dyn Dialer>) -> Self {
        Self {
            dialer,
            tls_config: tls_client_config(),
            idle: Arc::new(std::sync::Mutex::new(HashMap::new())),
        }
    }

    /// Pool key: one bucket per (scheme, host, port). The dialer is
    /// fixed per client, so an outbound change builds a new client.
    fn pool_key(scheme: &str, target: &DialTarget) -> String {
        format!("{scheme}|{}:{}", target.host, target.port)
    }

    /// Pop the most recently idle healthy connection for `key`.
    /// Stale entries (`>= IDLE_TIMEOUT`) are dropped on the way.
    fn take_idle(&self, key: &str) -> Option<SendRequest<Full<Bytes>>> {
        let mut guard = self.idle.lock().unwrap_or_else(|e| e.into_inner());
        let list = guard.get_mut(key)?;
        while let Some((at, sender)) = list.pop() {
            if at.elapsed() < IDLE_TIMEOUT {
                return Some(sender);
            }
        }
        None
    }

    /// Return a healthy connection to the pool. Past the cap it is
    /// dropped instead (the peer sees a normal close).
    fn put_idle(&self, key: &str, sender: SendRequest<Full<Bytes>>) {
        let mut guard = self.idle.lock().unwrap_or_else(|e| e.into_inner());
        let list = guard.entry(key.to_string()).or_default();
        if list.len() < MAX_IDLE_PER_TARGET {
            list.push((std::time::Instant::now(), sender));
        }
    }

    /// Perform one HTTPS request through the outbound: reuse an idle
    /// connection when one exists, otherwise dial + wrap the stream
    /// in TLS (SNI = the target host, ALPN `http/1.1`). A TLS
    /// handshake failure maps to `ConnectionDown` (nothing sent).
    /// The redirect, cap and error rules are the same as `request`.
    /// The `Host` header and the SNI name both come from `target`.
    pub async fn request_tls(
        &self,
        method: Method,
        target: &DialTarget,
        path: &str,
        headers: &[(String, String)],
        body: Option<Bytes>,
        timeout: Duration,
    ) -> Result<HttpResponse, TransportError> {
        let work = self.request_tls_inner(method, target, path, headers, body);
        match tokio::time::timeout(timeout, work).await {
            Ok(result) => result,
            Err(_) => Err(TransportError::Timeout {
                message: "https request timed out".to_string(),
            }),
        }
    }

    async fn request_tls_inner(
        &self,
        method: Method,
        target: &DialTarget,
        path: &str,
        headers: &[(String, String)],
        body: Option<Bytes>,
    ) -> Result<HttpResponse, TransportError> {
        let key = Self::pool_key("https", target);
        let make = || self.build_request(&method, target, path, headers, body.clone());
        if let Some(mut sender) = self.take_idle(&key) {
            match Self::exchange(&mut sender, make()?).await {
                Ok((resp, reuse)) => {
                    if reuse {
                        self.put_idle(&key, sender);
                    }
                    return Ok(resp);
                }
                Err(ExchangeFailure::IdleDead) => {}
                Err(ExchangeFailure::Transport(e)) => return Err(e),
            }
        }
        let mut sender = self.connect_tls(target).await?;
        let (resp, reuse) = match Self::exchange(&mut sender, make()?).await {
            Ok(v) => v,
            Err(ExchangeFailure::IdleDead) => {
                return Err(TransportError::ConnectionError {
                    message: "connection closed before the request was sent".to_string(),
                });
            }
            Err(ExchangeFailure::Transport(e)) => return Err(e),
        };
        if reuse {
            self.put_idle(&key, sender);
        }
        Ok(resp)
    }

    /// Perform one plain-HTTP request through the outbound, with the
    /// same pooling and error rules as [`HttpClient::request_tls`].
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
        let key = Self::pool_key("http", target);
        let make = || self.build_request(&method, target, path, headers, body.clone());
        if let Some(mut sender) = self.take_idle(&key) {
            match Self::exchange(&mut sender, make()?).await {
                Ok((resp, reuse)) => {
                    if reuse {
                        self.put_idle(&key, sender);
                    }
                    return Ok(resp);
                }
                Err(ExchangeFailure::IdleDead) => {}
                Err(ExchangeFailure::Transport(e)) => return Err(e),
            }
        }
        let stream = self.dialer.dial(target).await?;
        let mut sender = self.handshake(stream).await?;
        let (resp, reuse) = match Self::exchange(&mut sender, make()?).await {
            Ok(v) => v,
            Err(ExchangeFailure::IdleDead) => {
                return Err(TransportError::ConnectionError {
                    message: "connection closed before the request was sent".to_string(),
                });
            }
            Err(ExchangeFailure::Transport(e)) => return Err(e),
        };
        if reuse {
            self.put_idle(&key, sender);
        }
        Ok(resp)
    }

    /// Build one request. Rebuilt (never cloned into the retry) so
    /// the body bytes are handed over exactly once per attempt.
    fn build_request(
        &self,
        method: &Method,
        target: &DialTarget,
        path: &str,
        headers: &[(String, String)],
        body: Option<Bytes>,
    ) -> Result<(Request<Full<Bytes>>, bool), TransportError> {
        let mut builder = Request::builder().method(method.clone()).uri(path).header(
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
        // Go's `http.Transport` adds `Accept-Encoding: gzip` when the
        // caller did not set one and transparently decodes the reply
        // (`DisableCompression` is false). Without it the subscription
        // chunk scan pulled ~37 MB of uncompressed JS instead of
        // ~11 MB, which dominated `usage` (AGENT-CLI-SCOPE.md).
        let caller_set_encoding = headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("accept-encoding"));
        let auto_gzip = !caller_set_encoding;
        if auto_gzip {
            builder = builder.header(http::header::ACCEPT_ENCODING, "gzip");
        }
        let req = builder
            .body(Full::new(body.unwrap_or_default()))
            .map_err(|_| TransportError::Validation {
                message: "invalid http request".to_string(),
            })?;
        Ok((req, auto_gzip))
    }

    /// Dial + TLS wrap + HTTP/1.1 handshake. A failure before the
    /// request is written is `ConnectionDown` (safe to repeat).
    async fn connect_tls(
        &self,
        target: &DialTarget,
    ) -> Result<SendRequest<Full<Bytes>>, TransportError> {
        let stream = self.dialer.dial(target).await?;
        // SNI is the target host (an IP literal yields an IpAddress
        // name, for which rustls sends no SNI — correct per RFC 6066).
        let connector = tokio_rustls::TlsConnector::from(Arc::clone(&self.tls_config));
        let server_name = rustls::pki_types::ServerName::try_from(target.host.as_str())
            .map_err(|_| TransportError::Validation {
                message: "invalid TLS server name".to_string(),
            })?
            .to_owned();
        let tls_stream = connector.connect(server_name, stream).await.map_err(|e| {
            TransportError::ConnectionDown {
                message: crate::error::truncate(&e.to_string(), 200),
            }
        })?;
        self.handshake(tls_stream).await
    }

    /// HTTP/1.1 handshake over an already-connected stream.
    async fn handshake<S>(&self, stream: S) -> Result<SendRequest<Full<Bytes>>, TransportError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        // hyper's rt::Read/Write are NOT blanket-implemented for
        // tokio IO types: the canonical adapter is hyper-util's
        // TokioIo (honk's stream is tokio AsyncRead+AsyncWrite,
        // so this is a zero-copy wrapper, not a reimplementation).
        let (sender, conn): (SendRequest<Full<Bytes>>, _) =
            hyper::client::conn::http1::Builder::new()
                .handshake(TokioIo::new(stream))
                .await
                // Handshake failure is ConnectionDown, not
                // ConnectionError: the HTTP handshake happens
                // before any request bytes are sent, so the
                // request is safe to repeat for every method.
                .map_err(|e| TransportError::ConnectionDown {
                    message: crate::error::truncate(&e.to_string(), 200),
                })?;
        // The connection task must be driven; dropping it would
        // stall the request. It is spawned, not awaited: its
        // errors surface through the send/collect calls below, and
        // a pooled `SendRequest` fails once the task is gone.
        tokio::spawn(async move {
            let _ = conn.await;
        });
        Ok(sender)
    }

    /// One request/response exchange on an established connection.
    /// The bool in the `Ok` arm says whether the socket may be
    /// pooled again (no `Connection: close`, no refused redirect,
    /// body fully read).
    async fn exchange(
        sender: &mut SendRequest<Full<Bytes>>,
        req: (Request<Full<Bytes>>, bool),
    ) -> Result<(HttpResponse, bool), ExchangeFailure> {
        let (req, auto_gzip) = req;
        // An idle socket the peer closed fails here, before any
        // request byte is written.
        if sender.ready().await.is_err() {
            return Err(ExchangeFailure::IdleDead);
        }
        let resp = match sender.send_request(req).await {
            Ok(resp) => resp,
            Err(e) => {
                let message = crate::error::truncate(&e.to_string(), 200);
                return Err(if e.is_closed() {
                    ExchangeFailure::IdleDead
                } else {
                    ExchangeFailure::Transport(TransportError::ConnectionError { message })
                });
            }
        };
        let (parts, body) = resp.into_parts();
        let status = parts.status;
        // Redirects are refused, never followed (Go
        // `noFollowRedirect`). The Location value is NOT stored
        // on the error: no code in this crate reads it, and
        // storing a server-chosen URL on an error that might be
        // logged would leak redirect targets for no benefit. The
        // socket is not pooled: no second request rides it.
        if status.is_redirection() {
            return Err(ExchangeFailure::Transport(TransportError::RedirectRefused));
        }
        let mut headers = parts.headers;
        let reusable = !connection_close(&headers);
        // Capped streaming read: frames are consumed one at a
        // time and the read aborts as soon as the running total
        // would exceed MAX_RESPONSE_BODY — the body is never
        // buffered past the cap, so an endless or multi-GiB body
        // cannot OOM this process. A body over the cap is a
        // Gateway error (server-side failure, exit 3, never
        // retried); the true length is unknown, so the summary
        // carries body_length None, never a guessed number.
        let mut body = body;
        let mut out: Vec<u8> = Vec::new();
        loop {
            match body.frame().await {
                Some(Ok(frame)) => {
                    // `into_data` is Result, not Option: data
                    // frames are Ok(data), trailer frames are
                    // Err(frame) and carry no data to count.
                    if let Ok(data) = frame.into_data() {
                        if out.len() + data.remaining() > MAX_RESPONSE_BODY {
                            return Err(ExchangeFailure::Transport(TransportError::Gateway(
                                BodySummary::new(
                                    status.as_u16() as i32,
                                    None,
                                    content_type_of(&headers),
                                ),
                            )));
                        }
                        out.extend_from_slice(&data);
                    }
                }
                Some(Err(e)) => {
                    return Err(ExchangeFailure::Transport(
                        TransportError::ConnectionError {
                            message: crate::error::truncate(&e.to_string(), 200),
                        },
                    ));
                }
                None => break,
            }
        }
        let mut body_bytes = out;
        if auto_gzip
            && headers
                .get(http::header::CONTENT_ENCODING)
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| v.eq_ignore_ascii_case("gzip"))
        {
            // Go's transport deletes the header pair it decoded, so
            // callers never see an encoded body they did not ask for.
            body_bytes = match gunzip_capped(&body_bytes) {
                Some(decoded) => decoded,
                None => {
                    return Err(ExchangeFailure::Transport(TransportError::Gateway(
                        BodySummary::new(status.as_u16() as i32, None, content_type_of(&headers)),
                    )));
                }
            };
            headers.remove(http::header::CONTENT_ENCODING);
            headers.remove(http::header::CONTENT_LENGTH);
        }
        Ok((
            HttpResponse {
                status,
                headers,
                body: Bytes::from(body_bytes),
            },
            reusable,
        ))
    }
}

/// Decode one gzip body, bounded by [`MAX_RESPONSE_BODY`] AFTER
/// decompression (a gzip bomb must not OOM the process). `None`
/// means "corrupt, or bigger than the cap", both of which the
/// caller reports as a Gateway error.
fn gunzip_capped(data: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(data)
        .take(MAX_RESPONSE_BODY as u64 + 1)
        .read_to_end(&mut out)
        .ok()?;
    if out.len() > MAX_RESPONSE_BODY {
        return None;
    }
    Some(out)
}

/// True when the response asks for the connection to be closed
/// (`Connection: close`), i.e. the socket must not be pooled.
fn connection_close(headers: &HeaderMap) -> bool {
    headers
        .get(http::header::CONNECTION)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.split(',').any(|t| t.trim().eq_ignore_ascii_case("close")))
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

    #[test]
    fn http_response_debug_hides_headers_and_body() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::SET_COOKIE,
            HeaderValue::from_static("session=SECRET-COOKIE-123"),
        );
        let resp = HttpResponse {
            status: StatusCode::OK,
            headers,
            body: Bytes::from_static(b"SECRET-BODY-456"),
        };
        let dbg = format!("{resp:?}");
        assert!(
            !dbg.contains("SECRET-COOKIE-123"),
            "debug must not print headers: {dbg}"
        );
        assert!(
            !dbg.contains("SECRET-BODY-456"),
            "debug must not print body bytes: {dbg}"
        );
        assert!(dbg.contains("200"), "debug: {dbg}");
        assert!(dbg.contains("body_length"), "debug: {dbg}");
    }
}
