// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Wake command (M7a): port of Go
//! `internal/deliver/wake.go`.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use castctl_gateway::{SessionInfo, fetch_access_token, fetch_session_info};
use castctl_transport::HttpClient;
use serde_json::Value;

use crate::{BoxError, DeliverError};

/// Bounds the wake POST itself (Go `WakeTimeout` = 15s).
/// It does not bound the token and session-info fetches
/// that precede it; those carry the auth helpers' own
/// timeout. The timeout applies to the `WakeVM` call only.
pub const WAKE_TIMEOUT: Duration = Duration::from_secs(15);

/// The wake helper (Go `WakeFunc`): POSTs
/// `https://muse.ai/api/hatch/vm/wake` with JSON
/// `{"vm_id", "retry_count": 0}` and returns the HTTP
/// status plus the body parsed as JSON (or the body text
/// truncated to 300 bytes when it is not JSON).
///
/// The helper exists in Go (`internal/gateway/wake.go`,
/// `gateway.WakeVM`) but has NO Rust counterpart yet, so
/// `Wake` takes it as an injected `WakeFn`; the commands
/// layer passes the Rust helper once it exists. A `None`
/// `WakeFn` means no helper was injected, and `wake`
/// returns `WakeUnavailable` before doing any network work.
pub type WakeFn = dyn Fn(
        Arc<HttpClient>,
        String,
        String,
        String,
    ) -> Pin<Box<dyn Future<Output = Result<(i64, Value), DeliverError>> + Send>>
    + Send
    + Sync;

/// Fetch an access token (Go's `WakeDeps.FetchAccessToken`
/// slot). Defaults to the gateway helper when `None`.
pub type FetchAccessTokenFn = dyn Fn(
        Arc<HttpClient>,
        String,
    ) -> Pin<Box<dyn Future<Output = Result<String, DeliverError>> + Send>>
    + Send
    + Sync;

/// Fetch session info (Go's `WakeDeps.FetchSessionInfo`
/// slot). Defaults to the gateway helper when `None`.
pub type FetchSessionInfoFn = dyn Fn(
        Arc<HttpClient>,
        String,
    ) -> Pin<Box<dyn Future<Output = Result<SessionInfo, DeliverError>> + Send>>
    + Send
    + Sync;

/// `Wake`'s explicit dependencies (Go `WakeDeps`).
/// `client` is the `HttpClient` from the dialer, passed in
/// — never a shared default client. `cookies` is the Cookie
/// header value resolved by the caller. `vm_id` is the
/// profile's `vm_id`, or empty to resolve it via
/// `FetchSessionInfo`, as Python does.
pub struct WakeDeps {
    /// The dialer's HTTP client (`None` = nil client).
    pub client: Option<Arc<HttpClient>>,
    /// The Cookie header value.
    pub cookies: String,
    /// The profile's `vm_id` (empty = resolve via session info).
    pub vm_id: String,
    /// Token fetcher (defaults to the gateway helper).
    pub fetch_access_token: Option<Box<FetchAccessTokenFn>>,
    /// Session-info fetcher (defaults to the gateway helper).
    pub fetch_session_info: Option<Box<FetchSessionInfoFn>>,
    /// The wake helper (`None` = not injected).
    pub wake_vm: Option<Box<WakeFn>>,
}

impl Default for WakeDeps {
    fn default() -> Self {
        WakeDeps {
            client: None,
            cookies: String::new(),
            vm_id: String::new(),
            fetch_access_token: None,
            fetch_session_info: None,
            wake_vm: None,
        }
    }
}

/// The `wake` output shape (Go `WakeResult`):
/// `{"status": http_status, "body": ...}`. Field order is
/// the Python dict order. Body is the server reply verbatim.
#[derive(Debug, Clone, PartialEq)]
pub struct WakeResult {
    /// HTTP status.
    pub status: i64,
    /// The server reply verbatim.
    pub body: Value,
}

/// The default token fetcher: the gateway helper (Go's
/// `gateway.FetchAccessToken` default).
pub fn default_fetch_access_token() -> Box<FetchAccessTokenFn> {
    Box::new(move |client: Arc<HttpClient>, cookies: String| {
        Box::pin(async move {
            fetch_access_token(&client, &cookies)
                .await
                .map_err(DeliverError::Transport)
        })
    })
}

/// The default session-info fetcher: the gateway helper
/// (Go's `gateway.FetchSessionInfo` default).
pub fn default_fetch_session_info() -> Box<FetchSessionInfoFn> {
    Box::new(move |client: Arc<HttpClient>, cookies: String| {
        Box::pin(async move {
            fetch_session_info(&client, &cookies)
                .await
                .map_err(DeliverError::Transport)
        })
    })
}

/// Ask muse.ai to wake the VM and return `{status, body}`
/// (Go `Wake`). Resolution order is Python's: cookies
/// (already resolved by the caller), access token via
/// `FetchAccessToken`, `vm_id` from the profile or from
/// `FetchSessionInfo` when empty, then the wake POST via
/// `WakeVM` bounded by `WakeTimeout`. Errors from the
/// fetch helpers are returned wrapped, preserving their
/// chain for `error_is` classification by the caller; a
/// nil client or a missing wake helper fails before any
/// network work.
pub async fn wake(deps: WakeDeps) -> Result<WakeResult, DeliverError> {
    let client = match deps.client {
        Some(client) => client,
        None => {
            return Err(DeliverError::msg("deliver: wake: nil http client"));
        }
    };
    let wake_vm = match deps.wake_vm {
        Some(wake_vm) => wake_vm,
        None => return Err(DeliverError::WakeUnavailable),
    };
    let fetch_access_token = deps
        .fetch_access_token
        .unwrap_or_else(default_fetch_access_token);
    let fetch_session_info = deps
        .fetch_session_info
        .unwrap_or_else(default_fetch_session_info);
    // Python's order (wake_vm): the access token is fetched
    // FIRST, then the vm_id is resolved from the profile or
    // from session info when empty. A token failure
    // therefore surfaces before any session-info error and
    // makes no session-info call at all.
    let access_token = fetch_access_token(Arc::clone(&client), deps.cookies.clone())
        .await
        .map_err(|e| {
            DeliverError::wrap("deliver: wake: fetch access token", Box::new(e) as BoxError)
        })?;
    let vm_id = if deps.vm_id.is_empty() {
        let info = fetch_session_info(Arc::clone(&client), deps.cookies.clone())
            .await
            .map_err(|e| {
                DeliverError::wrap("deliver: wake: fetch session info", Box::new(e) as BoxError)
            })?;
        info.vm_id
    } else {
        deps.vm_id
    };
    let fut = wake_vm(
        Arc::clone(&client),
        deps.cookies.clone(),
        access_token,
        vm_id,
    );
    let (status, body) = match tokio::time::timeout(WAKE_TIMEOUT, fut).await {
        Ok(result) => {
            result.map_err(|e| DeliverError::wrap("deliver: wake", Box::new(e) as BoxError))?
        }
        Err(_) => {
            return Err(DeliverError::msg(
                "deliver: wake: context deadline exceeded",
            ));
        }
    };
    Ok(WakeResult { status, body })
}
