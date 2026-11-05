// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Gateway connector — port of `internal/gateway/connector.go`
//! (`NewConnector` + `dialGateway`).
//!
//! One `connect` opens one `Gateway`: it loads cookies, runs
//! the 3-step HTTPS auth chain over the outbound HTTP client
//! (session → access token → hatch token), dials the
//! WebSocket through the outbound dialer, and runs the Noise
//! handshake. Auth failures pass through as `Auth`; a missing
//! `vm_id` is a retryable `Gateway(-1)` with the
//! `vm_unavailable` marker, not an AuthError. No hatch token
//! is retained after the handshake.
//!
//! The cookies-file typing happens here, where the failure
//! enters the connection machinery (Go `connector.go`): a
//! file that cannot be read (missing, permissions) becomes
//! Auth `no cookies at <path>: <read error>` so callers treat
//! it as fatal instead of retrying it into a timeout; an
//! unparseable file is already an AuthError and passes through
//! unchanged.
//!
//! `with_auth_base` is a test seam (Go hardcodes
//! `https://muse.ai/...`); production never sets it.
//! `with_ws_url` overrides WS URL construction entirely
//! (Go `WithWSURL`, tests).

use std::sync::Arc;

use castctl_transport::{DialTarget, Dialer, HttpClient, RouteTable, TransportError};

use crate::auth::{
    MUSE_AI_BASE, fetch_access_token_base, fetch_hatch_token_base, fetch_session_info_base,
};
use crate::cookies::{CookieLoadError, load_cookies};
use crate::dial::{GATEWAY_HOST, default_ws_url, dial_gateway_over_stream, split_ws_url};
use crate::gateway::Gateway;

/// A WS-URL builder: receives (vm id, hatch token), returns
/// the full `ws(s)` URL.
type WsUrlFn = Arc<dyn Fn(&str, &str) -> String + Send + Sync>;

/// Builds one `Gateway` per `connect` call.
pub struct GatewayConnector {
    dialer: Arc<dyn Dialer>,
    http: HttpClient,
    secure: bool,
    host: String,
    ws_url: Option<WsUrlFn>,
    auth_base: String,
}

impl GatewayConnector {
    /// `secure` defaults to true (`wss`), `host` to
    /// [`GATEWAY_HOST`], the auth base to [`MUSE_AI_BASE`].
    pub fn new(dialer: Arc<dyn Dialer>) -> Self {
        let http = HttpClient::new(Arc::clone(&dialer));
        GatewayConnector {
            dialer,
            http,
            secure: true,
            host: GATEWAY_HOST.to_string(),
            ws_url: None,
            auth_base: MUSE_AI_BASE.to_string(),
        }
    }

    /// Sets whether the WebSocket dial is TLS (default true).
    /// Tests set false for a plain loopback fake gateway.
    pub fn with_secure(mut self, secure: bool) -> Self {
        self.secure = secure;
        self
    }

    /// Overrides the gateway host in the WebSocket URL
    /// (default `hatch.metaaivm.com`). It does not change
    /// dialing: the outbound dialer resolves the host it is
    /// given by the URL.
    pub fn with_host(mut self, host: &str) -> Self {
        self.host = host.to_string();
        self
    }

    /// Overrides WebSocket URL construction entirely (tests).
    /// The function receives the vm id and hatch token and
    /// must return the full `ws(s)` URL, including the
    /// `auth_token` query parameter, exactly as
    /// [`default_ws_url`] does.
    pub fn with_ws_url<F>(mut self, f: F) -> Self
    where
        F: Fn(&str, &str) -> String + Send + Sync + 'static,
    {
        self.ws_url = Some(Arc::new(f));
        self
    }

    /// Overrides the muse.ai base URL for the HTTPS auth chain
    /// (tests only; production never sets it).
    pub fn with_auth_base(mut self, base: &str) -> Self {
        self.auth_base = base.to_string();
        self
    }

    /// Opens one `Gateway`: cookies → session → access token →
    /// hatch token → WS dial over the outbound → Noise
    /// handshake.
    pub async fn connect(
        &self,
        cookies_file: &str,
        vm_id: &str,
    ) -> Result<Arc<Gateway>, TransportError> {
        let cookies = match load_cookies(cookies_file) {
            Ok(c) => c,
            Err(CookieLoadError::Read(m)) => {
                return Err(TransportError::Auth {
                    message: format!("no cookies at {cookies_file}: {m}"),
                });
            }
            Err(CookieLoadError::Parse(m)) => {
                return Err(TransportError::Auth { message: m });
            }
        };
        let mut vm_id = vm_id.to_string();
        if vm_id.is_empty() {
            let info = fetch_session_info_base(&self.http, &cookies, &self.auth_base).await?;
            vm_id = info.vm_id;
        }
        let access_token = fetch_access_token_base(&self.http, &cookies, &self.auth_base).await?;
        let hatch_token =
            fetch_hatch_token_base(&self.http, &cookies, &access_token, &vm_id, &self.auth_base)
                .await?;
        if hatch_token.is_empty() {
            return Err(TransportError::Auth {
                message: "hatch/token response missing token".to_string(),
            });
        }
        let url = match &self.ws_url {
            Some(f) => f(&vm_id, &hatch_token),
            None => default_ws_url(self.secure, &self.host, &vm_id, &hatch_token),
        };
        let routes = Arc::new(RouteTable::default_routes()?);
        let (host, port) = split_ws_url(&url).ok_or_else(|| TransportError::Validation {
            message: "invalid websocket URL".to_string(),
        })?;
        let stream = self.dialer.dial(&DialTarget::new(&host, port)).await?;
        dial_gateway_over_stream(stream, &url, routes).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_ws_url_cases() {
        assert_eq!(
            split_ws_url("wss://hatch.metaaivm.com/v1/noise?vm_id=x").unwrap(),
            ("hatch.metaaivm.com".to_string(), 443)
        );
        assert_eq!(
            split_ws_url("ws://127.0.0.1:1234/v1/noise").unwrap(),
            ("127.0.0.1".to_string(), 1234)
        );
        assert_eq!(
            split_ws_url("ws://example.com/v1/noise").unwrap(),
            ("example.com".to_string(), 80)
        );
        assert!(split_ws_url("https://example.com/x").is_none());
        assert!(split_ws_url("not a url").is_none());
    }
}
