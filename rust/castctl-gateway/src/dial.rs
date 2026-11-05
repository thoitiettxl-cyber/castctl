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
//! ALPN deviation: Go pins ALPN `["http/1.1"]` for the WS dial
//! because the uTLS Chrome preset offers `h2` first and gorilla
//! only speaks HTTP/1.1. The rustls client used here sends NO
//! ALPN by default, so the server cannot negotiate `h2` and
//! the upgrade proceeds as HTTP/1.1 — the same wire outcome
//! by a different mechanism. If a future fingerprint change
//! makes this client offer ALPN, the pin must be revisited
//! (see PORTING.md §M4a).
//!
//! Cancellation: dropping the `dial_gateway` future aborts
//! the dial/handshake at the next await (all steps are
//! cancel-safe `tokio::time::timeout` + WS I/O); the socket
//! halves are dropped with the future, so a cancelled
//! handshake cannot hang and cannot leak a connection.

use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

use crate::gateway::Gateway;
use crate::noise::{HANDSHAKE_TIMEOUT, InitiatorHandshake, NoiseTransport};
use castctl_transport::error::TransportError;
use castctl_transport::routes::{RouteTable, quote_path_param};

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
            TransportError::ConnectionError {
                message: format!("gateway: websocket handshake failed: status {status}"),
            }
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
/// `auth_token=<redacted>`, never a real token); `routes` is
/// the route table the gateway uses for `resolveRoute`.
/// `secure` selects `wss` vs `ws` only through the URL
/// scheme — a `wss://` URL always uses TLS (gateway-dial TLS
/// rule, see the module docs).
/// Wire note: `http::Uri` (used by `into_client_request`)
/// cannot represent `<`/`>` in a query, so the `<redacted>`
/// literal Go sends raw is percent-encoded here
/// (`%3Credacted%3E`) before dialing — the server decodes
/// it back to `<redacted>`, so the query VALUE is identical
/// to Go's; only the literal is ever encoded (a `vm_id` is
/// already quoted by `default_ws_url`, and no real token is
/// ever in the URL).
pub async fn dial_gateway(
    url: &str,
    routes: Arc<RouteTable>,
) -> Result<Arc<Gateway>, TransportError> {
    let encoded = url.replace("<redacted>", "%3Credacted%3E");
    let mut request = encoded.as_str().into_client_request().map_err(ws_error)?;
    request.headers_mut().insert(
        "User-Agent",
        GATEWAY_USER_AGENT
            .parse()
            .map_err(|_| TransportError::ConnectionError {
                message: "gateway: invalid user agent header".to_string(),
            })?,
    );
    request.headers_mut().insert(
        "Origin",
        GATEWAY_ORIGIN
            .parse()
            .map_err(|_| TransportError::ConnectionError {
                message: "gateway: invalid origin header".to_string(),
            })?,
    );
    let (ws, _) = match tokio::time::timeout(
        WS_UPGRADE_TIMEOUT,
        tokio_tungstenite::connect_async(request),
    )
    .await
    {
        Ok(Ok(pair)) => pair,
        Ok(Err(e)) => return Err(ws_error(e)),
        Err(_) => {
            return Err(TransportError::Timeout {
                message: format!(
                    "gateway websocket upgrade: no answer in {}s",
                    WS_UPGRADE_TIMEOUT.as_secs()
                ),
            });
        }
    };
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
