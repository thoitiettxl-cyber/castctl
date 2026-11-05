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
//! real hatch token, URL-quoted (Go `defaultWSURL`,
//! `connector.go:113-120`; see `rust/PORTING.md` §M4c.7).
//! The URL is never logged and never stored on the
//! `Gateway`; see `default_ws_url`).
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
//! ALPN (M4b fix of the M4a deviation, M4c engine swap): Go
//! pins ALPN `["http/1.1"]` for the WS dial because the uTLS
//! Chrome preset offers `h2` first and gorilla only speaks
//! HTTP/1.1. BOTH dials here pin ALPN `["http/1.1"]` now via
//! `castctl_transport::honk_tls_wrap` (M4c): honk's BoringSSL
//! Chrome connector, SNI = the WS host. The M4b rustls wrap
//! sent a 251-byte ClientHello (vs Go's Chrome fingerprint);
//! whether the fingerprint matters to the live edge was never
//! isolated — every 502 so far lacked the token too (see
//! `rust/PORTING.md` §M4c.7; the step-3 matrix decides).
//! rustls stays only for the HTTPS auth chain (`http.rs`),
//! not for this dial.
//!
//! Hand-written upgrade (M4b): the upgrade request is
//! written BY HAND (`ws_upgrade`), not through tungstenite's
//! request builder, because `http::Uri` rejects `<`/`>` in
//! the query and the request-target must go out verbatim
//! (Go writes it verbatim too). The old reason — a literal
//! `auth_token=<redacted>` in the URL — was wrong (see
//! `rust/PORTING.md` §M4c.7: Go sends the real token,
//! quoted); the M4b probe (401 for `%3Credacted%3E`, 502
//! for the literal) compared two token-less spellings, so
//! neither result constrains the quoted-token form.
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
use castctl_transport::{TlsStream, honk_tls_wrap};

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

/// Build `ws(s)://<host>/v1/noise?vm_id=..&auth_token=..`,
/// mirroring Go `defaultWSURL` (`connector.go:113-120`)
/// byte for byte: 4 verbs, 4 args — the real hatch token,
/// URL-quoted (`safe=""`, Python `quote`), goes into
/// `auth_token` (see `rust/PORTING.md` §M4c.7; the M4a
/// "3 verbs, 4 args, literal token" reading was wrong).
/// The returned string carries the token, so it must never
/// be logged — the dial error paths return fixed strings
/// only, and `redact` strips `auth_token=...` from logs.
pub fn default_ws_url(secure: bool, host: &str, vm_id: &str, hatch_token: &str) -> String {
    let scheme = if secure { "wss" } else { "ws" };
    format!(
        "{scheme}://{host}/v1/noise?vm_id={}&auth_token={}",
        quote_path_param(vm_id),
        quote_path_param(hatch_token),
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

/// Map a raw WS status-line token (bytes) to Go's
/// handshake-failure rendering. Go parses the response
/// as bytes (`net/http` `ReadResponse` + `textproto`
/// never validate UTF-8): a token that is not valid
/// UTF-8 cannot be a 3-digit code nor token-shaped, so
/// it renders the fixed 35-char message — the same
/// fallthrough the `&str` mapping gives for a
/// non-token-shaped token. A valid-UTF-8 but non-ASCII
/// token (e.g. `ééé`) takes the same fallthrough inside
/// `handshake_failure_for_status`.
fn handshake_failure_for_status_bytes(token: &[u8]) -> Option<TransportError> {
    match std::str::from_utf8(token) {
        Ok(text) => handshake_failure_for_status(text),
        Err(_) => Some(handshake_failed_error()),
    }
}

/// One header field-name byte, the way Go's `textproto`
/// validates it (`canonicalMIMEHeaderKey`,
/// `reader.go`): a tchar (`!#$%&'*+-.^_`|~` + ASCII
/// alnum) or a space (accepted uncanonicalized,
/// go.dev/issue/34540). A byte >= 0x80 fails: Go
/// rejects the whole response.
fn is_header_key_byte(byte: u8) -> bool {
    byte == b' '
        || byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

/// One header field-value byte, the way Go's `textproto`
/// validates it (`validHeaderValueByte`,
/// `reader.go:733`): HTAB / SP / VCHAR / obs-text
/// (0x80-0xFF). A control byte other than HTAB, or DEL,
/// fails: Go rejects the whole response.
fn is_header_value_byte(byte: u8) -> bool {
    byte == 0x09 || (0x20..=0x7e).contains(&byte) || byte >= 0x80
}

/// Whether a status token is exactly 3 ASCII digits —
/// the only shape Go's `ReadResponse` accepts as a code
/// (Go `isThreeDigitCode`,
/// `internal/gateway/handshake_log.go:62-67`).
fn is_three_digit_code(token: &[u8]) -> bool {
    token.len() == 3 && token.iter().all(|b| b.is_ascii_digit())
}

/// Map a MALFORMED status token (not exactly 3 ASCII
/// digits) to Go's rendering. Always returns an error:
/// `handshake_failure_for_status_bytes` returns `None`
/// only for 101, which is 3 digits, so the `None` arm
/// is unreachable — it degrades to the fixed message
/// rather than panicking, so a broken invariant can
/// never leak peer text or crash on peer input.
fn malformed_status_error(token: &[u8]) -> TransportError {
    match handshake_failure_for_status_bytes(token) {
        Some(err) => err,
        None => handshake_failed_error(),
    }
}

/// The proto field of a status line (bytes before the
/// first space), the way Go's `ReadResponse` cuts it
/// (`net/http/response.go:170`):
/// `strings.Cut(line, " ")`. No space at all → empty
/// (Go renders `malformed HTTP response` → the fixed
/// message, which is what the empty token maps to —
/// the token check runs first).
fn status_proto_from_line(line: &[u8]) -> &[u8] {
    match line.iter().position(|&b| b == b' ') {
        Some(first) => &line[..first],
        None => b"",
    }
}

/// Mirror Go's `ParseHTTPVersion`
/// (`net/http/request.go:827-847`): `HTTP/1.0`,
/// `HTTP/1.1`, or `HTTP/X.Y` with single digits
/// (exactly 8 bytes). Anything else is a malformed
/// version → Go returns nil resp → the fixed message.
fn valid_http_version(proto: &[u8]) -> bool {
    matches!(
        proto,
        [b'H', b'T', b'T', b'P', b'/', major, b'.', minor]
        if major.is_ascii_digit() && minor.is_ascii_digit()
    )
}

/// Trim SP/HTAB from both ends of a header value, the
/// way Go's `readContinuedLineSlice` trims the whole
/// header line (`net/textproto/reader.go:108-119`).
/// Applied to the VALUE after the colon, not to the
/// whole line — trimming the line would wrongly accept
/// a leading-space first header line, which Go rejects
/// outright (see `check_upgrade_head`).
fn trim_header_value(value: &[u8]) -> &[u8] {
    let mut start = 0;
    while start < value.len() && matches!(value[start], b' ' | b'\t') {
        start += 1;
    }
    let mut end = value.len();
    while end > start && matches!(value[end - 1], b' ' | b'\t') {
        end -= 1;
    }
    &value[start..end]
}

/// Extract the status token from a status line the way
/// Go's `ReadResponse` does (`response.go:170-180`):
/// cut on the first space, trim leading spaces, cut on
/// the next space. No space at all → empty (Go renders
/// `malformed HTTP response` → the fixed message, which
/// is what the empty token maps to).
fn status_token_from_line(line: &[u8]) -> &[u8] {
    let Some(first) = line.iter().position(|&b| b == b' ') else {
        return b"";
    };
    let rest = &line[first + 1..];
    let rest = {
        let mut start = 0;
        while start < rest.len() && rest[start] == b' ' {
            start += 1;
        }
        &rest[start..]
    };
    match rest.iter().position(|&b| b == b' ') {
        Some(second) => &rest[..second],
        None => rest,
    }
}

/// Check a WS upgrade response head (bytes) the way Go's
/// `http.ReadResponse` + gorilla `DialContext` do
/// (`net/http/response.go:158-206`,
/// `net/textproto/reader.go:521-596`,
/// `gorilla/client.go:372-405`): the head is bytes,
/// never UTF-8. Returns `Ok(())` when the status is 101
/// and the accept key matches, else the Go-faithful
/// handshake error. Order mirrors `ReadResponse`
/// exactly: (1) a malformed status token (not exactly
/// 3 ASCII digits) returns its mapping IMMEDIATELY —
/// Go returns the malformed-status error before parsing
/// headers; (2) a valid 3-digit code is checked for a
/// valid proto (`ParseHTTPVersion`: `HTTP/1.0`,
/// `HTTP/1.1`, or `HTTP/X.Y`, single digits) → fixed
/// on failure; (3) the header block: the FIRST line
/// must not start with SP/HTAB (Go: `malformed MIME
/// header initial line`), every line has a colon (Go:
/// `malformed MIME header: missing colon`), a
/// non-empty field-name of tchar/space bytes, and valid
/// field-value bytes — a malformed header fails even a
/// 502, but ONLY for a valid code (step 1 already
/// returned for a malformed token); (4) on a 101, the
/// FIRST `Sec-WebSocket-Accept` header only (Go:
/// `Header.Get` returns the first value), its value
/// trimmed of SP/HTAB on BOTH ends (Go:
/// `readContinuedLineSlice`'s `trim` +
/// `bytes.TrimLeft`) — mismatch → `status_code=101`;
/// otherwise the deferred status error is returned.
/// Well-formedness NOT validated (gorilla checks Rust
/// does not — see PORTING §M4b.2 deviation 25): the
/// `Upgrade` / `Connection` header values, and obs-fold
/// continuation lines (Go folds them into the previous
/// value; each physical line is checked independently
/// here). Also not handled (deviation 27): a bare-LF
/// header terminator — Go's `ReadLine` accepts bare
/// `\n`, Rust reads until `b"\r\n\r\n"`.
fn check_upgrade_head(head: &[u8], expected_accept: &str) -> Result<(), TransportError> {
    let mut lines = head
        .split(|&b| b == b'\n')
        .map(|line| line.strip_suffix(b"\r").unwrap_or(line));
    let status_line = lines.next().unwrap_or(b"");
    let token = status_token_from_line(status_line);
    // Step 1 — Go returns the malformed-status error
    // before parsing headers (`response.go:170-186`).
    if !is_three_digit_code(token) {
        return Err(malformed_status_error(token));
    }
    let status_err = handshake_failure_for_status_bytes(token);
    // Step 2 — Go validates the proto after the code
    // and before the headers (`response.go:186`).
    if !valid_http_version(status_proto_from_line(status_line)) {
        return Err(handshake_failed_error());
    }
    let mut accept_ok = false;
    let mut seen_accept = false;
    let mut first_header = true;
    for line in lines {
        if line.is_empty() {
            break;
        }
        // Step 3 — Go's `readMIMEHeader` rejects a
        // header block whose first line starts with
        // SP/HTAB before any folding
        // (`textproto/reader.go:538-545`, `Peek(1)` →
        // `malformed MIME header initial line`) → resp
        // nil → fixed message. A leading-space line
        // AFTER the first is a continuation (deviation
        // 25); a leading-space FIRST line is an error.
        if first_header && matches!(line.first(), Some(b' ') | Some(b'\t')) {
            return Err(handshake_failed_error());
        }
        first_header = false;
        let Some(colon) = line.iter().position(|&b| b == b':') else {
            // Go: `malformed MIME header: missing colon`
            // (`mustHaveFieldNameColon`) → resp nil.
            return Err(handshake_failed_error());
        };
        let (name, value) = (&line[..colon], &line[colon + 1..]);
        if name.is_empty() || !name.iter().all(|&b| is_header_key_byte(b)) {
            // Go: `canonicalMIMEHeaderKey` ok=false (empty
            // key, or a byte that is not a tchar/space) →
            // resp nil.
            return Err(handshake_failed_error());
        }
        if !value.iter().all(|&b| is_header_value_byte(b)) {
            // Go: `validHeaderValueByte` fails → resp nil.
            return Err(handshake_failed_error());
        }
        // Step 4 — only the FIRST accept header counts
        // (Go: `Header.Get` returns `vv[0]`), and its
        // value is trimmed on BOTH ends (Go:
        // `readContinuedLineSlice`'s `trim` +
        // `bytes.TrimLeft`). The trim is of the VALUE
        // after the colon, not of the whole line.
        if !seen_accept && name.eq_ignore_ascii_case(b"sec-websocket-accept") {
            seen_accept = true;
            if trim_header_value(value) == expected_accept.as_bytes() {
                accept_ok = true;
            }
        }
    }
    if let Some(err) = status_err {
        return Err(err);
    }
    if !accept_ok {
        // Gorilla returns the response non-nil on accept
        // mismatch (`client.go:394-405`) with StatusCode
        // 101, so Go renders `status_code=101`.
        return Err(handshake_token_error("status_code", "101"));
    }
    Ok(())
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
        WsError::Tls(_) => tls_failed(),
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
/// or logged (with `default_ws_url` it carries the real
/// token, quoted; see the module docs). `routes` is
/// the route table the gateway uses for `resolveRoute`.
/// `secure` selects `wss` vs `ws` only through the URL
/// scheme — a `wss://` URL always uses TLS (gateway-dial TLS
/// rule, see the module docs).
/// Wire note (M4b): the upgrade is written by hand
/// (`ws_upgrade`) so the request-target goes out verbatim —
/// `http::Uri` cannot represent `<>`, and Go writes the
/// target verbatim too. The direct dial pins ALPN
/// `["http/1.1"]` via `honk_tls_wrap`, matching Go (M4c
/// engine swap; M4b fix of the M4a no-ALPN deviation).
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
    // (boxed honk TLS stream vs `TcpStream`), so each
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
/// (honk BoringSSL Chrome — matching Go's pin and its
/// fingerprint, M4c), while `ws://` upgrades plain. The
/// upgrade is written by hand (`ws_upgrade`) so the
/// request-target goes out verbatim (M4b).
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
    // (boxed honk TLS stream vs `S`), so each completes the
    // dial (Noise handshake) on its own type.
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
/// in `ws_error`, and the local-policy arms in `ws_upgrade`):
/// the class only, never peer text. After fix loop 2 its
/// only `ws_upgrade` uses are the URL-split failure
/// (`split_ws_request_target`, a local input error — Go
/// fails earlier at `splitWSURL`, a different path) and
/// the oversized-response guard (a local DoS cap with no
/// Go equivalent — see PORTING §M4b.2 deviation 24);
/// post-connect I/O failures render Go's fixed 35-char
/// handshake message instead.
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

/// TLS-wrap a stream for a `wss://` dial with honk's
/// BoringSSL Chrome connector (`honk_tls_wrap`: SNI = the WS
/// host, ALPN pinned `["http/1.1"]`, matching Go). The
/// wrapped stream is type-erased (`TlsStream`, a transport
/// trait) so this crate stays honk-free (PORTING §M4b.2 dev
/// 23: the generic-`S` dial avoids a honk dependency in the
/// gateway crate) and the failure rendering stays here: any
/// honk failure is already the fixed 29-char `tls_failed()`
/// string.
async fn tls_wrap<S>(stream: S, host: &str) -> Result<Box<dyn TlsStream>, TransportError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
{
    honk_tls_wrap(stream, host).await
}

/// TCP-connect + TLS-wrap + upgrade for a direct `wss://` dial.
async fn dial_secure(
    url: &str,
    host: &str,
    port: u16,
) -> Result<WebSocketStream<Box<dyn TlsStream>>, TransportError> {
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
/// query, and the target must go out verbatim. The
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
/// `dialWebSocket` (User-Agent + Origin). Failures render
/// Go's `newHandshakeFailureError` (`connector.go:292-311`):
/// a non-101 status carries the status only, and a
/// post-connect I/O failure (write / read / EOF before any
/// status line) renders the fixed 35-char message — gorilla
/// returns `(nil, nil, err)` there (`client.go:372-387`),
/// so no status exists to render. The raw response bytes
/// never reach an output path.
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
        .map_err(|_| handshake_failed_error())?;
    stream.flush().await.map_err(|_| handshake_failed_error())?;
    // Read until the end of the response header block.
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 1024];
    let header_end = loop {
        let n = stream
            .read(&mut chunk)
            .await
            .map_err(|_| handshake_failed_error())?;
        if n == 0 {
            return Err(handshake_failed_error());
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
    // Go parses the head as bytes (see
    // `check_upgrade_head`); a non-UTF-8 byte anywhere
    // in it is not a parse failure by itself.
    let expected = tokio_tungstenite::tungstenite::handshake::derive_accept_key(key.as_bytes());
    check_upgrade_head(head, &expected)?;
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

    #[test]
    fn tls_failed_is_29_chars() {
        // M4c: the honk TLS failure (transport) and the
        // tungstenite TLS arm (`ws_error`, above) must render
        // the same fixed string — byte-identical to
        // `gateway_ws_tls_failed` in castctl-transport.
        // (M4b docs said 28; the literal is 29 — counted by
        // `len()` here, not by hand.)
        let err = tls_failed();
        let message = conn_message(&err).to_string();
        assert_eq!(message, "gateway: websocket TLS failed");
        assert_eq!(message.len(), 29);
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

    fn head_message(result: Result<(), TransportError>) -> Option<String> {
        result.err().map(|e| conn_message(&e).to_string())
    }

    fn accept_for(key: &[u8]) -> String {
        tokio_tungstenite::tungstenite::handshake::derive_accept_key(key)
    }

    /// Fix loop 2: `check_upgrade_head` parses the head as
    /// bytes the way Go's `ReadResponse` does — a 502 with
    /// valid headers renders `status_code=502`; a 101 with
    /// a wrong accept renders `status_code=101`; a 101 with
    /// the right accept proceeds.
    #[test]
    fn check_upgrade_head_status_and_accept_branches() {
        assert_eq!(
            head_message(check_upgrade_head(
                b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n",
                "anything"
            )),
            Some("gateway: websocket handshake: status_code=502".to_string())
        );
        assert_eq!(
            head_message(check_upgrade_head(
                b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: wrong\r\n\r\n",
                "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
            )),
            Some("gateway: websocket handshake: status_code=101".to_string())
        );
        let key = b"test-key-12345678";
        let expected = accept_for(key);
        let head = format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {expected}\r\n\r\n"
        );
        assert!(check_upgrade_head(head.as_bytes(), &expected).is_ok());
    }

    /// Fix loop 2 (non-UTF-8 arm): a non-UTF-8 status
    /// token renders the fixed message (Go: `Atoi` fails
    /// → malformed-status error → token-shape fails);
    /// non-UTF-8 in a header VALUE is valid obs-text, so
    /// a 502 still renders `status_code=502`; non-UTF-8
    /// in a header KEY fails the whole response (Go:
    /// `canonicalMIMEHeaderKey` ok=false) → fixed
    /// message; a non-UTF-8 accept value mismatches →
    /// `status_code=101`; non-UTF-8 in an unrelated
    /// header value with a correct accept proceeds.
    #[test]
    fn check_upgrade_head_non_utf8_branches() {
        assert_eq!(
            head_message(check_upgrade_head(
                b"HTTP/1.1 \xff\xff\xff Bad\r\n\r\n",
                "x"
            )),
            Some("gateway: websocket handshake failed".to_string())
        );
        assert_eq!(
            head_message(check_upgrade_head(
                b"HTTP/1.1 502 Bad Gateway\r\nX-Custom: \xff\xfe\r\n\r\n",
                "x"
            )),
            Some("gateway: websocket handshake: status_code=502".to_string())
        );
        assert_eq!(
            head_message(check_upgrade_head(
                b"HTTP/1.1 502 Bad Gateway\r\nX-\xff: v\r\n\r\n",
                "x"
            )),
            Some("gateway: websocket handshake failed".to_string())
        );
        assert_eq!(
            head_message(check_upgrade_head(
                b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: \xff\xff\r\n\r\n",
                "x"
            )),
            Some("gateway: websocket handshake: status_code=101".to_string())
        );
        let key = b"test-key-12345678";
        let expected = accept_for(key);
        let mut head = format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {expected}\r\n"
        )
        .into_bytes();
        head.extend_from_slice(b"X-Custom: \xff\r\n\r\n");
        assert!(check_upgrade_head(&head, &expected).is_ok());
    }

    /// Fix loop 2: header well-formedness is validated
    /// the way Go's `ReadResponse` does — a header line
    /// without a colon, an empty field-name, or a control
    /// byte in a value fails the whole response (resp nil
    /// → fixed message), even with a valid 502 status
    /// line. [CORRECTED in fix loop 3: this "whole head"
    /// rule holds only for a VALID status code — Go
    /// returns a malformed-status error before parsing
    /// headers, so a malformed token + a malformed header
    /// renders the token/length form, not the fixed
    /// message; see
    /// `check_upgrade_head_malformed_token_returns_immediately`.]
    /// A space before the colon is accepted (Go
    /// go.dev/issue/34540) but never matches the accept
    /// key.
    #[test]
    fn check_upgrade_head_malformed_header_is_fixed_message() {
        assert_eq!(
            head_message(check_upgrade_head(
                b"HTTP/1.1 502 Bad Gateway\r\nBadHeader\r\n\r\n",
                "x"
            )),
            Some("gateway: websocket handshake failed".to_string())
        );
        assert_eq!(
            head_message(check_upgrade_head(
                b"HTTP/1.1 502 Bad Gateway\r\n: v\r\n\r\n",
                "x"
            )),
            Some("gateway: websocket handshake failed".to_string())
        );
        assert_eq!(
            head_message(check_upgrade_head(
                b"HTTP/1.1 502 Bad Gateway\r\nX-Custom: a\x00b\r\n\r\n",
                "x"
            )),
            Some("gateway: websocket handshake failed".to_string())
        );
        // Space before the colon: accepted by Go, but the
        // name (with its trailing space) never matches.
        assert_eq!(
            head_message(check_upgrade_head(
                b"HTTP/1.1 101 Switching Protocols\r\nSec-WebSocket-Accept : s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n",
                "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
            )),
            Some("gateway: websocket handshake: status_code=101".to_string())
        );
    }

    /// Fix loop 3: Go trims the accept value on BOTH
    /// ends — every header line passes through `trim()`
    /// in `readContinuedLineSlice`
    /// (`textproto/reader.go:108-119`, leading AND
    /// trailing SP/HTAB) before `readMIMEHeader` splits
    /// on the colon, so a correct key with a trailing
    /// space or tab MATCHES in Go and the upgrade
    /// proceeds. Fix loop 2's "leading only" rule was
    /// wrong, and this test pinned the wrong behaviour
    /// — flipped to assert the Go behaviour. The trim
    /// is of the VALUE after the colon, not of the whole
    /// line (trimming the line would wrongly accept a
    /// leading-space first header line, which Go rejects
    /// outright — see the first-header test below).
    #[test]
    fn check_upgrade_head_accept_trailing_space_matches() {
        assert!(check_upgrade_head(
            b"HTTP/1.1 101 Switching Protocols\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo= \r\n\r\n",
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        )
        .is_ok());
        assert!(check_upgrade_head(
            b"HTTP/1.1 101 Switching Protocols\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\t\r\n\r\n",
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        )
        .is_ok());
    }

    /// Fix loop 3 (ordering): Go's `ReadResponse`
    /// returns a malformed-status error BEFORE parsing
    /// headers (`response.go:170-186`) — the status
    /// error is NOT deferred when the token is malformed.
    /// A malformed token + a malformed header renders the
    /// token/length form, never the fixed message.
    /// Precedence check: `FOO ABC` still renders the
    /// token length (the status error comes before the
    /// version check too).
    #[test]
    fn check_upgrade_head_malformed_token_returns_immediately() {
        assert_eq!(
            head_message(check_upgrade_head(
                b"HTTP/1.1 ABC Bad\r\nBadHeader\r\n\r\n",
                "x"
            )),
            Some("gateway: websocket handshake: status_token_length=3".to_string())
        );
        assert_eq!(
            head_message(check_upgrade_head(
                b"HTTP/1.1 1000 Bad\r\nBadHeader\r\n\r\n",
                "x"
            )),
            Some("gateway: websocket handshake: status_token_length=4".to_string())
        );
        assert_eq!(
            head_message(check_upgrade_head(
                b"HTTP/1.1 ABC Bad\r\nX-\xff: v\r\n\r\n",
                "x"
            )),
            Some("gateway: websocket handshake: status_token_length=3".to_string())
        );
        assert_eq!(
            head_message(check_upgrade_head(b"FOO ABC Bar\r\n\r\n", "x")),
            Some("gateway: websocket handshake: status_token_length=3".to_string())
        );
    }

    /// Fix loop 3 (proto): Go validates the proto with
    /// `ParseHTTPVersion` (`response.go:186`,
    /// `request.go:827-847`) after the status code and
    /// before the headers — only `HTTP/1.0`, `HTTP/1.1`,
    /// or `HTTP/X.Y` (single digits, exactly 8 bytes)
    /// pass. A bad proto renders the fixed message, even
    /// with a valid code and a bad header (version check
    /// precedes header parsing).
    #[test]
    fn check_upgrade_head_bad_proto_is_fixed_message() {
        assert_eq!(
            head_message(check_upgrade_head(b"XYZ 502 Bad\r\n\r\n", "x")),
            Some("gateway: websocket handshake failed".to_string())
        );
        assert_eq!(
            head_message(check_upgrade_head(b"HTTP/1 502 Bad\r\n\r\n", "x")),
            Some("gateway: websocket handshake failed".to_string())
        );
        assert_eq!(
            head_message(check_upgrade_head(b"HTTP/1.1.1 502 Bad\r\n\r\n", "x")),
            Some("gateway: websocket handshake failed".to_string())
        );
        assert_eq!(
            head_message(check_upgrade_head(b"FOO 502 Bad\r\nBadHeader\r\n\r\n", "x")),
            Some("gateway: websocket handshake failed".to_string())
        );
        assert_eq!(
            head_message(check_upgrade_head(b"HTTP/9.9 502 Bad\r\n\r\n", "x")),
            Some("gateway: websocket handshake: status_code=502".to_string())
        );
        assert_eq!(
            head_message(check_upgrade_head(b"HTTP/1.0 502 Bad\r\n\r\n", "x")),
            Some("gateway: websocket handshake: status_code=502".to_string())
        );
    }

    /// Fix loop 3 (duplicate accept): Go consults
    /// `resp.Header.Get("Sec-Websocket-Accept")` and
    /// `MIMEHeader.Get` returns the FIRST value
    /// (`vv[0]`) — only the first accept header counts.
    /// First-wrong/second-right mismatches
    /// (`status_code=101`); first-right/second-wrong
    /// proceeds.
    #[test]
    fn check_upgrade_head_duplicate_accept_first_only() {
        let key = b"test-key-12345678";
        let expected = accept_for(key);
        let head = format!(
            "HTTP/1.1 101 Switching Protocols\r\nSec-WebSocket-Accept: wrong\r\nSec-WebSocket-Accept: {expected}\r\n\r\n"
        );
        assert_eq!(
            head_message(check_upgrade_head(head.as_bytes(), &expected)),
            Some("gateway: websocket handshake: status_code=101".to_string())
        );
        let head = format!(
            "HTTP/1.1 101 Switching Protocols\r\nSec-WebSocket-Accept: {expected}\r\nSec-WebSocket-Accept: wrong\r\n\r\n"
        );
        assert!(check_upgrade_head(head.as_bytes(), &expected).is_ok());
    }

    /// Fix loop 3 (first header line): Go's
    /// `readMIMEHeader` rejects a header block whose
    /// first line starts with SP/HTAB before any folding
    /// (`textproto/reader.go:538-545`, `Peek(1)` →
    /// `malformed MIME header initial line`) → resp nil
    /// → fixed message. A leading-space line AFTER the
    /// first is a continuation (deviation 25, recorded);
    /// a leading-space FIRST line is an error. A
    /// spaces-only first line errors in Go too (Rust
    /// coincides there via the no-colon rule, but pin it
    /// anyway).
    #[test]
    fn check_upgrade_head_leading_space_first_header_is_fixed_message() {
        assert_eq!(
            head_message(check_upgrade_head(
                b"HTTP/1.1 502 Bad Gateway\r\n X-Custom: v\r\n\r\n",
                "x"
            )),
            Some("gateway: websocket handshake failed".to_string())
        );
        assert_eq!(
            head_message(check_upgrade_head(
                b"HTTP/1.1 502 Bad Gateway\r\n\tX-Custom: v\r\n\r\n",
                "x"
            )),
            Some("gateway: websocket handshake failed".to_string())
        );
        assert_eq!(
            head_message(check_upgrade_head(
                b"HTTP/1.1 502 Bad Gateway\r\n   \r\n\r\n",
                "x"
            )),
            Some("gateway: websocket handshake failed".to_string())
        );
    }
}
