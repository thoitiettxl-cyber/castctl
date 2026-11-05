// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! WS dial + Noise handshake (M4a).
//!
//! Go sources: `internal/gateway/connector.go`
//! (`dialGateway`, `dialWebSocket`, `defaultWSURL`) and
//! `internal/gateway/gateway.go:144-193` (`noiseHandshake`),
//! `internal/gateway/auth.go:19-24` (`UserAgent`,
//! `GatewayHost`).
//!
//! Flow: build the WS URL → dial the WebSocket (20s upgrade
//! bound) → run the Noise XX handshake as initiator (20s per
//! step) → return a live `Gateway`. On any failure the socket
//! is closed and the error returned. The WS URL carries the
//! literal `auth_token=<redacted>` (Boss decision 2026-11-05:
//! mirror Go `defaultWSURL`, `connector.go:116` — the real
//! hatch token is never put in the URL, never stored on the
//! `Gateway`, and never logged; see `default_ws_url`).
//!
//! Gateway-dial TLS rule (M3c NB6, `internal/outbound/
//! dialer.go:161-168` `DialTLS`): whenever TLS is requested
//! at all, `Enabled` is forced to `true`. It lives HERE, at
//! the gateway-dial call site, and is NOT folded into
//! `castctl-transport::build_tls` (which serves the outbound
//! path): this crate's dial API has no `tls.enabled=false`
//! option at all — a `wss://` URL always dials with TLS, a
//! `ws://` URL always dials plain (the fake-server case).
//! There is no code path that dials `wss://` without TLS.
//!
//! ALPN (M4b fix of the M4a deviation): Go pins ALPN
//! `["http/1.1"]` for the WS dial because the uTLS Chrome
//! preset offers `h2` first and gorilla only speaks
//! HTTP/1.1. BOTH dials here pin ALPN `["http/1.1"]` now:
//! the over-stream dial via `castctl_transport::
//! tls_client_config` (M4b), and the direct dial via the
//! same config (the M4a direct dial sent NO ALPN, which
//! happened to produce the same wire outcome — the server
//! cannot negotiate `h2` without an ALPN offer — but the
//! pin is now explicit, matching Go).
//!
//! Literal token on the wire (M4b): the upgrade request is
//! written BY HAND (`ws_upgrade`), not through tungstenite's
//! request builder, because `http::Uri` rejects `<`/`>` in
//! the query and the gateway URL carries a literal
//! `auth_token=<redacted>` exactly as Go sends it. The live
//! edge returns 401 for the percent-encoded `%3Credacted%3E`
//! form (live probe on cue, 2026-11-05), so encoding it is
//! not an option; the M4a claim that "the server decodes it
//! back" was wrong — the M4a test only proved the fake
//! server tolerates the encoded form.
//! Cancellation: dropping the `dial_gateway` future aborts
//! the dial/handshake at the next await (all steps are
//! cancel-safe `tokio::time::timeout` + WS I/O); the socket
//! halves are dropped with the future, so a cancelled
//! handshake cannot hang and cannot leak a connection.

use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tokio_tungstenite::tungstenite::protocol::Role;

use crate::gateway::Gateway;
use crate::noise::{HANDSHAKE_TIMEOUT, InitiatorHandshake, NoiseTransport};
use castctl_transport::error::TransportError;
use castctl_transport::routes::{RouteTable, quote_path_param};
use castctl_transport::tls_client_config;

/// Chrome/153 Mac user agent (Go `internal/gateway/auth.go:21`
/// `UserAgent`).
pub const GATEWAY_USER_AGENT: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36";

/// Origin header for the WS dial (Go `connector.go`
/// `dialWebSocket`).
pub const GATEWAY_ORIGIN: &str = "https://muse.ai";

/// Default gateway host (Go `internal/gateway/auth.go:24`
/// `GatewayHost`).
pub const GATEWAY_HOST: &str = "hatch.metaaivm.com";

/// Bounds the WebSocket upgrade separately from the Noise
/// handshake (Go `internal/gateway/timings.go:49`
/// `WSUpgradeTimeout`).
pub const WS_UPGRADE_TIMEOUT: Duration = Duration::from_secs(20);

/// Build `ws(s)://<host>/v1/noise?vm_id=..&auth_token=<redacted>`,
/// mirroring Go `defaultWSURL` (`connector.go:116`) byte for
/// byte: the format string has 3 verbs and 4 args, so the
/// quoted hatch token is computed and silently discarded by
/// `Sprintf` — Go sends the literal, and so does this
/// function (Boss decision 2026-11-05: Go 0.9.0 production
/// relays real turns through that URL; sending the real token
/// would leak it to server/proxy logs with no evidence the
/// gateway needs it). `hatch_token` is accepted for call-site
/// compatibility and deliberately NOT sent: if later live
/// proof shows the gateway needs the real token, change this
/// one place and re-enable the token-URL test. The returned
/// string carries no secret.
pub fn default_ws_url(secure: bool, host: &str, vm_id: &str, _hatch_token: &str) -> String {
    let scheme = if secure { "wss" } else { "ws" };
    format!(
        "{scheme}://{host}/v1/noise?vm_id={}&auth_token=<redacted>",
        quote_path_param(vm_id),
    )
}

/// Render Go's `handshakeFailureError` with a status token
/// (`internal/gateway/handshake_log.go:41-46`): the validated
/// token only, never peer text. E.g. kind `status_code`,
/// token `502` renders the 45-char `gateway: websocket
/// handshake: status_code=502`. Shared by `ws_error` (the
/// tungstenite path) and `ws_upgrade` (the hand-written
/// path) — one helper, so the M4a wording error cannot
/// survive in one copy again (fix loop 1, T-B1).
fn handshake_token_error(kind: &str, token: &str) -> TransportError {
    TransportError::ConnectionError {
        message: format!("gateway: websocket handshake: {kind}={token}"),
    }
}

/// Render Go's fixed no-status handshake failure
/// (`handshake_log.go:49-51`): 35 chars, no token.
fn handshake_failed_error() -> TransportError {
    TransportError::ConnectionError {
        message: "gateway: websocket handshake failed".to_string(),
    }
}

/// Map a raw WS status-line token to Go's handshake-failure
/// rendering (`handshakeStatusToken`,
/// `handshake_log.go:103-130`): `None` means 101 — proceed
/// with the upgrade. A 3-digit code renders
/// `status_code=NNN` (its decimal form must also be 3
/// digits: `050` renders `status_code_length=2`, because Go
/// stringifies the parsed code); a token-shaped but
/// non-3-digit token renders `status_token_length=N`;
/// anything else renders the fixed 35-char message. The
/// token bytes never reach an output path.
fn handshake_failure_for_status(token: &str) -> Option<TransportError> {
    if token.len() == 3 && token.bytes().all(|b| b.is_ascii_digit()) {
        // Three ASCII digits: compute the code from the
        // bytes (no parse to fail).
        let code = token
            .bytes()
            .fold(0u16, |acc, b| acc * 10 + u16::from(b - b'0'));
        if code == 101 {
            return None;
        }
        if code >= 100 {
            return Some(handshake_token_error("status_code", &code.to_string()));
        }
        return Some(handshake_token_error(
            "status_code_length",
            &code.to_string().len().to_string(),
        ));
    }
    if !token.is_empty()
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        return Some(handshake_token_error(
            "status_token_length",
            &token.len().to_string(),
        ));
    }
    Some(handshake_failed_error())
}

/// Map a tungstenite error to the transport taxonomy without
/// embedding peer text: a WS handshake failure renders the
/// validated status only (Go `connector.go`
/// `newHandshakeFailureError`); other failures are
/// `ConnectionError` with the error class only. The raw error
/// text (which may embed a peer status line) never reaches an
/// output path. Shared with `gateway.rs`: the read loop and
/// `write_ws` route mid-connection WS errors through here too
/// (same class, no peer text).
pub(crate) fn ws_error(err: tokio_tungstenite::tungstenite::Error) -> TransportError {
    use tokio_tungstenite::tungstenite::Error as WsError;
    match &err {
        WsError::Http(resp) => {
            let status = resp.status().as_u16();
            handshake_token_error("status_code", &status.to_string())
        }
        WsError::Io(_) => TransportError::ConnectionError {
            message: "gateway: websocket dial failed".to_string(),
        },
        WsError::Tls(_) => TransportError::ConnectionError {
            message: "gateway: websocket TLS failed".to_string(),
        },
        _ => TransportError::ConnectionError {
            message: "gateway: websocket dial failed".to_string(),
        },
    }
}

/// Run the Noise XX handshake as initiator over an
/// established WS connection (Go `noiseHandshake`). Each send
/// and the msg2 reply are bounded by `HANDSHAKE_TIMEOUT`
/// (20s); a timeout is a `TimeoutError`, a close frame mid-
/// handshake is a `ConnectionError`, anything else is a
/// `ConnectionError`.
async fn noise_handshake<S, W>(
    read_half: &mut S,
    write_half: &mut W,
) -> Result<Arc<NoiseTransport>, TransportError>
where
    S: futures_core::Stream<Item = Result<WsMessage, tokio_tungstenite::tungstenite::Error>>
        + Unpin,
    W: futures_sink::Sink<WsMessage, Error = tokio_tungstenite::tungstenite::Error> + Unpin,
{
    let mut hs = InitiatorHandshake::new()?;
    let msg1 = hs.msg1()?;
    send_bounded(write_half, msg1).await?;
    let msg2 = read_bounded(read_half).await?;
    hs.read_msg2(&msg2)?;
    let msg3 = hs.msg3()?;
    send_bounded(write_half, msg3).await?;
    hs.into_transport().map(Arc::new)
}

async fn send_bounded<W>(write_half: &mut W, data: Vec<u8>) -> Result<(), TransportError>
where
    W: futures_sink::Sink<WsMessage, Error = tokio_tungstenite::tungstenite::Error> + Unpin,
{
    let fut = write_half.send(WsMessage::Binary(data.into()));
    match tokio::time::timeout(HANDSHAKE_TIMEOUT, fut).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(TransportError::ConnectionError {
            message: format!(
                "gateway handshake send failed: {}",
                ws_error(e).log_summary()
            ),
        }),
        Err(_) => Err(TransportError::Timeout {
            message: format!(
                "gateway handshake send: no progress in {}s",
                HANDSHAKE_TIMEOUT.as_secs()
            ),
        }),
    }
}

async fn read_bounded<S>(read_half: &mut S) -> Result<Vec<u8>, TransportError>
where
    S: futures_core::Stream<Item = Result<WsMessage, tokio_tungstenite::tungstenite::Error>>
        + Unpin,
{
    match tokio::time::timeout(HANDSHAKE_TIMEOUT, read_half.next()).await {
        Ok(Some(Ok(WsMessage::Binary(data)))) => Ok(data.to_vec()),
        Ok(Some(Ok(WsMessage::Close(_)))) => Err(TransportError::ConnectionError {
            message: "gateway closed the websocket during the handshake".to_string(),
        }),
        Ok(Some(Ok(_))) => Err(TransportError::ConnectionError {
            message: "gateway handshake failed: unexpected websocket message".to_string(),
        }),
        Ok(Some(Err(e))) => Err(ws_error(e)),
        Ok(None) => Err(TransportError::ConnectionError {
            message: "gateway closed the websocket during the handshake".to_string(),
        }),
        Err(_) => Err(TransportError::Timeout {
            message: format!(
                "gateway handshake: no answer in {}s",
                HANDSHAKE_TIMEOUT.as_secs()
            ),
        }),
    }
}

/// Dial one gateway: WS upgrade + Noise handshake, returning
/// a live `Gateway` (Go `dialGateway`). `url` is never stored
/// or logged (with `default_ws_url` it carries the literal
/// `auth_token=<redacted>`; see the module docs). `routes` is
/// the route table the gateway uses for `resolveRoute`.
/// `secure` selects `wss` vs `ws` only through the URL
/// scheme — a `wss://` URL always uses TLS (gateway-dial TLS
/// rule, see the module docs).
/// Wire note (M4b): the upgrade is written by hand
/// (`ws_upgrade`) so the request-target carries the literal
/// `auth_token=<redacted>` Go sends raw — `http::Uri`
/// cannot represent `<>`, and the live edge returns 401 for
/// the percent-encoded form. The direct dial pins ALPN
/// `["http/1.1"]` via `tls_client_config`, matching Go
/// (M4b fix of the M4a no-ALPN deviation).
pub async fn dial_gateway(
    url: &str,
    routes: Arc<RouteTable>,
) -> Result<Arc<Gateway>, TransportError> {
    let (host, port) = split_ws_url(url).ok_or_else(|| TransportError::Validation {
        message: "invalid websocket URL".to_string(),
    })?;
    let secure = match url.split_once("://") {
        Some(("wss", _)) => true,
        Some(("ws", _)) => false,
        _ => {
            return Err(TransportError::Validation {
                message: "invalid websocket URL".to_string(),
            });
        }
    };
    // The two branches yield different stream types
    // (`TlsStream<TcpStream>` vs `TcpStream`), so each
    // completes the dial (Noise handshake) on its own type.
    if secure {
        let ws = match tokio::time::timeout(WS_UPGRADE_TIMEOUT, dial_secure(url, &host, port)).await
        {
            Ok(Ok(ws)) => ws,
            Ok(Err(e)) => return Err(e),
            Err(_) => return Err(upgrade_timeout()),
        };
        complete_dial(ws, routes).await
    } else {
        let ws = match tokio::time::timeout(WS_UPGRADE_TIMEOUT, dial_plain(url, &host, port)).await
        {
            Ok(Ok(ws)) => ws,
            Ok(Err(e)) => return Err(e),
            Err(_) => return Err(upgrade_timeout()),
        };
        complete_dial(ws, routes).await
    }
}

/// Dial one gateway over an already-connected stream (Go
/// `dialWebSocket` + `dialGateway` via the outbound dialer):
/// WS upgrade over the given stream + Noise handshake. The
/// stream is the outbound-dialed connection (plain TCP to the
/// WS host:port); the TLS wrap happens HERE for `wss://`
/// (ALPN-pinned rustls client — matching Go's pin), while
/// `ws://` upgrades plain. The upgrade is written by hand
/// (`ws_upgrade`) so the request-target carries the literal
/// `auth_token=<redacted>` Go sends raw (M4b).
pub async fn dial_gateway_over_stream<S>(
    stream: S,
    url: &str,
    routes: Arc<RouteTable>,
) -> Result<Arc<Gateway>, TransportError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
{
    let secure = match url.split_once("://") {
        Some(("wss", _)) => true,
        Some(("ws", _)) => false,
        _ => {
            return Err(TransportError::Validation {
                message: "invalid websocket URL".to_string(),
            });
        }
    };
    // The two branches yield different stream types
    // (`TlsStream<S>` vs `S`), so each completes the dial
    // (Noise handshake) on its own type.
    if secure {
        let (host, _port) = split_ws_url(url).ok_or_else(|| TransportError::Validation {
            message: "invalid websocket URL".to_string(),
        })?;
        let ws = match tokio::time::timeout(WS_UPGRADE_TIMEOUT, async {
            let tls = tls_wrap(stream, &host).await?;
            ws_upgrade(tls, url).await
        })
        .await
        {
            Ok(Ok(ws)) => ws,
            Ok(Err(e)) => return Err(e),
            Err(_) => return Err(upgrade_timeout()),
        };
        complete_dial(ws, routes).await
    } else {
        let ws = match tokio::time::timeout(WS_UPGRADE_TIMEOUT, ws_upgrade(stream, url)).await {
            Ok(Ok(ws)) => ws,
            Ok(Err(e)) => return Err(e),
            Err(_) => return Err(upgrade_timeout()),
        };
        complete_dial(ws, routes).await
    }
}

/// Extracts the host and port from a `ws(s)` URL, applying
/// the scheme defaults (443 for wss, 80 for ws). Go
/// `splitWSURL` (`connector.go`).
pub fn split_ws_url(url: &str) -> Option<(String, u16)> {
    let (scheme, rest) = url.split_once("://")?;
    let default_port = match scheme {
        "wss" => 443,
        "ws" => 80,
        _ => return None,
    };
    let authority = rest.split('/').next()?;
    if authority.is_empty() {
        return None;
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) if !p.is_empty() => match p.parse::<u16>() {
            Ok(n) => (h, n),
            Err(_) => (authority, default_port),
        },
        _ => (authority, default_port),
    };
    Some((host.to_string(), port))
}

/// The WS-upgrade timeout error, shared by the direct and
/// over-stream dials.
fn upgrade_timeout() -> TransportError {
    TransportError::Timeout {
        message: format!(
            "gateway websocket upgrade: no answer in {}s",
            WS_UPGRADE_TIMEOUT.as_secs()
        ),
    }
}

/// The generic WS-dial failure (tungstenite's non-HTTP arm
/// in `ws_error`): the class only, never peer text.
fn dial_failed() -> TransportError {
    TransportError::ConnectionError {
        message: "gateway: websocket dial failed".to_string(),
    }
}

/// The WS TLS failure (tungstenite's TLS arm in `ws_error`).
fn tls_failed() -> TransportError {
    TransportError::ConnectionError {
        message: "gateway: websocket TLS failed".to_string(),
    }
}

/// TCP-connect to a WS host:port. Failure is a
/// `ConnectionError` (see `dial_failed`), matching Go
/// `dialWebSocket` (the dialer error is a `ConnectionError`,
/// not `ConnectionDown`).
async fn tcp_connect(host: &str, port: u16) -> Result<tokio::net::TcpStream, TransportError> {
    tokio::net::TcpStream::connect((host, port))
        .await
        .map_err(|_| dial_failed())
}

/// TLS-wrap a stream for a `wss://` dial, with the
/// ALPN-pinned rustls client (`tls_client_config`) and SNI =
/// the WS host (Go pins ALPN `["http/1.1"]` for the WS dial).
async fn tls_wrap<S>(
    stream: S,
    host: &str,
) -> Result<tokio_rustls::client::TlsStream<S>, TransportError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
{
    // Owned form: `connect` needs a `ServerName<'static>`
    // (the stream holds it for the connection lifetime);
    // `TryFrom<&str>` only borrows the caller's `host`.
    let name = tokio_rustls::rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|_| tls_failed())?;
    tokio_rustls::TlsConnector::from(tls_client_config())
        .connect(name, stream)
        .await
        .map_err(|_| tls_failed())
}

/// TCP-connect + TLS-wrap + upgrade for a direct `wss://` dial.
async fn dial_secure(
    url: &str,
    host: &str,
    port: u16,
) -> Result<WebSocketStream<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>, TransportError>
{
    let tcp = tcp_connect(host, port).await?;
    let tls = tls_wrap(tcp, host).await?;
    ws_upgrade(tls, url).await
}

/// TCP-connect + upgrade for a direct `ws://` dial.
async fn dial_plain(
    url: &str,
    host: &str,
    port: u16,
) -> Result<WebSocketStream<tokio::net::TcpStream>, TransportError> {
    let tcp = tcp_connect(host, port).await?;
    ws_upgrade(tcp, url).await
}

/// Maximum HTTP response header block accepted during the WS
/// upgrade (a 101 response is a few hundred bytes; anything
/// larger is not a WS handshake).
const MAX_UPGRADE_RESPONSE: usize = 8192;

/// Split a ws(s) URL into (authority, request-target) with
/// plain string ops — `http::Uri` rejects `<`/`>` in the
/// query, and the gateway URL carries a literal
/// `auth_token=<redacted>` exactly as Go sends it. The
/// target is returned verbatim and is never logged.
/// `None` on a malformed URL (no scheme, empty authority).
fn split_ws_request_target(url: &str) -> Option<(String, String)> {
    let (_scheme, rest) = url.split_once("://")?;
    let (authority, target) = match rest.split_once('/') {
        Some((a, t)) => (a, format!("/{t}")),
        None => (rest, "/".to_string()),
    };
    if authority.is_empty() {
        return None;
    }
    Some((authority.to_string(), target))
}

/// Perform the WS upgrade by writing the HTTP/1.1 request
/// bytes directly and reading the response headers, then
/// wrap the stream as a `WebSocketStream` (leftover bytes
/// after the header block are handed to tungstenite via
/// `from_partially_read`, so no frame bytes are lost).
/// The request-target is sent VERBATIM (see
/// `split_ws_request_target`); headers match Go
/// `dialWebSocket` (User-Agent + Origin). A non-101 status
/// is a `ConnectionError` carrying the status only (Go
/// `newHandshakeFailureError`); any other failure is a
/// `ConnectionError` with the error class only — the raw
/// response bytes never reach an output path.
async fn ws_upgrade<S>(mut stream: S, url: &str) -> Result<WebSocketStream<S>, TransportError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (authority, target) = split_ws_request_target(url).ok_or_else(dial_failed)?;
    let key_bytes: [u8; 16] = rand::random();
    let key = base64::engine::general_purpose::STANDARD.encode(key_bytes);
    let request = format!(
        "GET {target} HTTP/1.1\r\nHost: {authority}\r\nConnection: Upgrade\r\nOrigin: {GATEWAY_ORIGIN}\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\nUpgrade: websocket\r\nUser-Agent: {GATEWAY_USER_AGENT}\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|_| dial_failed())?;
    stream.flush().await.map_err(|_| dial_failed())?;
    // Read until the end of the response header block.
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 1024];
    let header_end = loop {
        let n = stream.read(&mut chunk).await.map_err(|_| dial_failed())?;
        if n == 0 {
            return Err(dial_failed());
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > MAX_UPGRADE_RESPONSE {
            return Err(dial_failed());
        }
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
    };
    let head = &buf[..header_end];
    let leftover = buf[header_end..].to_vec();
    let text = std::str::from_utf8(head).map_err(|_| dial_failed())?;
    let mut lines = text.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let status_token = status_line.split_whitespace().nth(1).unwrap_or("");
    // Go `handshakeStatusToken`: the token decides the
    // failure rendering; `None` is 101 — proceed.
    if let Some(err) = handshake_failure_for_status(status_token) {
        return Err(err);
    }
    let expected = tokio_tungstenite::tungstenite::handshake::derive_accept_key(key.as_bytes());
    let mut accept_ok = false;
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':')
            && name.trim().eq_ignore_ascii_case("sec-websocket-accept")
            && value.trim() == expected
        {
            accept_ok = true;
        }
    }
    if !accept_ok {
        return Err(dial_failed());
    }
    Ok(WebSocketStream::from_partially_read(stream, leftover, Role::Client, None).await)
}

/// Runs the Noise handshake over an established WS connection
/// and returns the live `Gateway`. Shared by the direct and
/// over-stream dials.
async fn complete_dial<S>(
    ws: tokio_tungstenite::WebSocketStream<S>,
    routes: Arc<RouteTable>,
) -> Result<Arc<Gateway>, TransportError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
{
    let (mut write_half, mut read_half) = ws.split();
    let transport = match noise_handshake(&mut read_half, &mut write_half).await {
        Ok(t) => t,
        Err(e) => {
            let _ = write_half.close().await;
            return Err(e);
        }
    };
    Ok(Gateway::from_handshaked(
        Box::pin(read_half),
        Box::pin(write_half),
        transport,
        routes,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conn_message(err: &TransportError) -> &str {
        match err {
            TransportError::ConnectionError { message } => message,
            other => panic!("want ConnectionError, got {other:?}"),
        }
    }

    /// T-B1 (fix loop 1): `ws_error` must render Go's exact
    /// `handshakeFailureError` text (`internal/gateway/
    /// handshake_log.go:41-46`): `gateway: websocket
    /// handshake: status_code=502` — 45 chars, NOT the 47-char
    /// `gateway: websocket handshake failed: status 502` this
    /// code rendered before the fix.
    #[test]
    fn ws_error_http_502_renders_go_45_chars() {
        let resp = http::Response::builder()
            .status(502)
            .body(Some(Vec::new()))
            .unwrap();
        let err = tokio_tungstenite::tungstenite::Error::Http(Box::new(resp));
        let mapped = ws_error(err);
        let message = conn_message(&mapped).to_string();
        assert_eq!(
            message, "gateway: websocket handshake: status_code=502",
            "ws_error Http arm must match Go byte-for-byte"
        );
        assert_eq!(message.len(), 45, "Go renders 45 chars for a 502");
    }

    #[test]
    fn handshake_token_error_502_is_45_chars() {
        let err = handshake_token_error("status_code", "502");
        let message = conn_message(&err).to_string();
        assert_eq!(message, "gateway: websocket handshake: status_code=502");
        assert_eq!(message.len(), 45);
    }

    #[test]
    fn handshake_failed_error_is_35_chars() {
        let err = handshake_failed_error();
        let message = conn_message(&err).to_string();
        assert_eq!(message, "gateway: websocket handshake failed");
        assert_eq!(message.len(), 35);
    }

    /// Every `handshakeStatusToken` branch
    /// (`handshake_log.go:103-130`), pinned: 101 proceeds
    /// (`None`); a 3-digit code renders `status_code`; a
    /// leading-zero code renders the length of its decimal
    /// form (`050` → `status_code_length=2`); a token-shaped
    /// non-code renders its length; anything else renders
    /// the fixed 35-char message (never the token bytes).
    #[test]
    fn handshake_failure_for_status_branches() {
        assert!(handshake_failure_for_status("101").is_none());
        assert_eq!(
            conn_message(&handshake_failure_for_status("502").unwrap()),
            "gateway: websocket handshake: status_code=502"
        );
        assert_eq!(
            conn_message(&handshake_failure_for_status("050").unwrap()),
            "gateway: websocket handshake: status_code_length=2"
        );
        assert_eq!(
            conn_message(&handshake_failure_for_status("ABC").unwrap()),
            "gateway: websocket handshake: status_token_length=3"
        );
        assert_eq!(
            conn_message(&handshake_failure_for_status("1000").unwrap()),
            "gateway: websocket handshake: status_token_length=4"
        );
        assert_eq!(
            conn_message(&handshake_failure_for_status("").unwrap()),
            "gateway: websocket handshake failed"
        );
        assert_eq!(
            conn_message(&handshake_failure_for_status("<x>").unwrap()),
            "gateway: websocket handshake failed"
        );
    }
}
