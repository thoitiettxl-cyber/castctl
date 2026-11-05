// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! The cheap auth chain — port of `internal/keeper/tick.go`
//! (`Checker`, `GatewayChecker`) and
//! `internal/gateway/authcookies.go` (the `WithCookies`
//! variants).
//!
//! The keeper runs ONLY this chain: `GET /api/session` →
//! `POST /api/auth/check`. No hatch/token, no WebSocket, no
//! chat. The checker runs through the profile's HTTP client
//! (built by the command layer from the profile outbound),
//! with the profile identity.
//!
//! Updates are returned alongside errors whenever a
//! response header was received, so a tick that persists
//! updates (success, recovery, and gateway-down paths)
//! records a server-issued deletion even when the step
//! then reports AuthError. The stop path preserves the
//! cookies file instead. Error classes are the `conn`
//! contracts: `Auth` = expired/invalid (stop),
//! `Gateway`/transport = transient (backoff). Callers
//! distinguish with `matches!` on the variant, never
//! message text. The skipped count counts unparseable
//! Set-Cookie values.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use castctl_gateway::auth::{
    AUTH_TIMEOUT, HATCH_MAX_BODY, MUSE_AI_BASE, VM_UNAVAILABLE_LABEL, hatch_headers,
};
use castctl_gateway::summary::{summarize_body, summary_to_body_summary};
use castctl_transport::{DialTarget, HttpClient, TransportError};
use http::{Method, header::HeaderMap};

use crate::clock::Clock;
use crate::jar::{CookieUpdate, effective_set_cookie, in_filtered_domain, merge_cookie_header};
use crate::setcookie::{ParsedCookie, parse_set_cookie_header};

/// Cheap-chain endpoints for expiry detection
/// (`tick.go:26-27`).
pub const SESSION_CHECK_URL: &str = "https://muse.ai/api/session";
/// The auth/check step.
pub const AUTH_CHECK_URL: &str = "https://muse.ai/api/auth/check";

/// One `check` call's result: the ordered Set-Cookie
/// updates observed, in step order (session response
/// first, then auth/check), the count of unparseable
/// Set-Cookie values, and the step error (if any).
#[derive(Debug)]
pub struct CheckOutcome {
    pub updates: Vec<CookieUpdate>,
    pub skipped: usize,
    pub error: Option<TransportError>,
}

/// Run the cheap chain with a Cookie header
/// (`tick.go:38-41`).
#[async_trait::async_trait]
pub trait Checker: Send + Sync {
    /// Run the chain; updates are returned alongside
    /// errors whenever a response header was received.
    async fn check(&self, cookie_header: &str) -> CheckOutcome;
}

/// Adapts a function to a `Checker` (tests and the
/// command-layer wiring).
pub struct CheckerFunc<F>(pub F)
where
    F: Fn(&str) -> std::pin::Pin<Box<dyn std::future::Future<Output = CheckOutcome> + Send>>
        + Send
        + Sync;

#[async_trait::async_trait]
impl<F> Checker for CheckerFunc<F>
where
    F: Fn(&str) -> std::pin::Pin<Box<dyn std::future::Future<Output = CheckOutcome> + Send>>
        + Send
        + Sync,
{
    async fn check(&self, cookie_header: &str) -> CheckOutcome {
        (self.0)(cookie_header).await
    }
}

/// The production `Checker`: the cheap chain through the
/// profile's HTTP client, with the profile identity
/// (`tick.go:44-47`).
pub struct GatewayChecker {
    client: Arc<HttpClient>,
    clock: Arc<dyn Clock>,
    base: String,
}

impl GatewayChecker {
    /// Build a checker against the production base
    /// (`https://muse.ai`).
    pub fn new(client: Arc<HttpClient>, clock: Arc<dyn Clock>) -> Self {
        Self {
            client,
            clock,
            base: MUSE_AI_BASE.to_string(),
        }
    }

    /// Build a checker against an explicit base URL (test
    /// seam; production passes `MUSE_AI_BASE`).
    pub fn with_base(client: Arc<HttpClient>, clock: Arc<dyn Clock>, base: &str) -> Self {
        Self {
            client,
            clock,
            base: base.to_string(),
        }
    }

    /// The base URL this checker calls.
    pub fn base(&self) -> &str {
        &self.base
    }

    /// One muse.ai HTTPS request with an `AUTH_TIMEOUT`
    /// bound. Returns the status code, the body bytes
    /// truncated at `HATCH_MAX_BODY`, and the response
    /// headers. Transport errors pass through unchanged
    /// (gateway `do_hatch`).
    async fn do_hatch(
        &self,
        method: Method,
        url: &str,
        headers: &[(String, String)],
        body: Option<Bytes>,
    ) -> Result<(u16, Vec<u8>, HeaderMap), TransportError> {
        let resp = request_url(&self.client, method, url, headers, body, AUTH_TIMEOUT).await?;
        let mut data = resp.body.to_vec();
        data.truncate(HATCH_MAX_BODY);
        Ok((resp.status.as_u16(), data, resp.headers))
    }

    /// `GET /api/session` with cookies: returns the
    /// session info (only `vm_id` is read), the parsed
    /// Set-Cookie values, and the skipped-value count.
    /// Error mapping is identical to
    /// `fetch_session_info` (`authcookies.go`).
    async fn fetch_session_info_with_cookies(
        &self,
        cookies: &str,
        _now: chrono::DateTime<chrono::Utc>,
    ) -> Result<(Vec<ParsedCookie>, usize), (Vec<ParsedCookie>, usize, TransportError)> {
        let (status, data, headers) = match self
            .do_hatch(
                Method::GET,
                &format!("{}/api/session", self.base),
                &hatch_headers(cookies, ""),
                None,
            )
            .await
        {
            Ok(v) => v,
            // Transport error: no header exists, no
            // cookies are returned.
            Err(e) => return Err((vec![], 0, e)),
        };
        let (parsed, skipped) = parse_set_cookie_header(&set_cookie_values(&headers));
        if status != 200 {
            return Err((
                parsed,
                skipped,
                TransportError::Auth {
                    message: format!("api/session -> {status} (cookies expired? re-export)"),
                },
            ));
        }
        let ct = content_type_of(&headers);
        let raw = match serde_json::from_slice::<serde_json::Value>(&data) {
            Ok(v) => v,
            Err(_) => {
                let sum =
                    summarize_body("api/session returned non-JSON", Some(&data), ct, None, &[]);
                return Err((parsed, skipped, TransportError::Auth { message: sum.text }));
            }
        };
        let serde_json::Value::Object(info) = raw else {
            let sum = summarize_body(VM_UNAVAILABLE_LABEL, Some(&data), ct, None, &[]);
            return Err((parsed, skipped, vm_unavailable_gateway(-1, &sum)));
        };
        match info.get("vm_id") {
            Some(serde_json::Value::String(_)) => Ok((parsed, skipped)),
            _ => {
                let sum = summarize_body(
                    VM_UNAVAILABLE_LABEL,
                    Some(&data),
                    ct,
                    Some(&info),
                    &["status"],
                );
                Err((parsed, skipped, vm_unavailable_gateway(-1, &sum)))
            }
        }
    }

    /// `POST /api/auth/check` with cookies: returns the
    /// parsed Set-Cookie values and the skipped-value
    /// count. Error mapping is identical to
    /// `fetch_access_token` (`authcookies.go`).
    async fn fetch_access_token_with_cookies(
        &self,
        cookies: &str,
    ) -> Result<(Vec<ParsedCookie>, usize), (Vec<ParsedCookie>, usize, TransportError)> {
        let (status, data, headers) = match self
            .do_hatch(
                Method::POST,
                &format!("{}/api/auth/check", self.base),
                &hatch_headers(cookies, ""),
                Some(Bytes::new()),
            )
            .await
        {
            Ok(v) => v,
            Err(e) => return Err((vec![], 0, e)),
        };
        let (parsed, skipped) = parse_set_cookie_header(&set_cookie_values(&headers));
        if status != 200 {
            let sum = summarize_body(
                &format!("auth/check -> {status} (cookies expired? re-export)"),
                Some(&data),
                content_type_of(&headers),
                None,
                &[],
            );
            return Err((parsed, skipped, TransportError::Auth { message: sum.text }));
        }
        let decoded = match serde_json::from_slice::<serde_json::Value>(&data) {
            Ok(serde_json::Value::Object(map)) => Some(map),
            _ => None,
        };
        let Some(map) = decoded else {
            return Err((
                parsed,
                skipped,
                TransportError::Auth {
                    message: "auth/check returned non-JSON or missing access_token".to_string(),
                },
            ));
        };
        match map.get("access_token") {
            Some(serde_json::Value::String(t)) if !t.is_empty() => Ok((parsed, skipped)),
            _ => Err((
                parsed,
                skipped,
                TransportError::Auth {
                    message: "auth/check response missing access_token".to_string(),
                },
            )),
        }
    }
}

#[async_trait::async_trait]
impl Checker for GatewayChecker {
    async fn check(&self, cookie_header: &str) -> CheckOutcome {
        let now = self.clock.now();
        let mut all: Vec<CookieUpdate> = Vec::new();
        let mut skipped = 0;
        // The session step uses the original header.
        let (cookies, skip1, err) = match self
            .fetch_session_info_with_cookies(cookie_header, now)
            .await
        {
            Ok((c, s)) => (c, s, None),
            Err((c, s, e)) => (c, s, Some(e)),
        };
        skipped += skip1;
        all.extend(to_updates(&cookies, SESSION_CHECK_URL, now));
        if let Some(err) = err {
            return CheckOutcome {
                updates: all,
                skipped,
                error: Some(err),
            };
        }
        // The auth/check step uses the header merged with
        // the session step's updates.
        let header2 = merge_cookie_header(cookie_header, &all, now);
        let (cookies2, skip2, err2) = match self.fetch_access_token_with_cookies(&header2).await {
            Ok((c, s)) => (c, s, None),
            Err((c, s, e)) => (c, s, Some(e)),
        };
        skipped += skip2;
        all.extend(to_updates(&cookies2, AUTH_CHECK_URL, now));
        CheckOutcome {
            updates: all,
            skipped,
            error: err2,
        }
    }
}

/// Convert parsed Set-Cookie values to filtered updates
/// (`tick.go:toUpdates`): `EffectiveSetCookie` per value,
/// keeping only filtered-domain cookies.
fn to_updates(
    cookies: &[ParsedCookie],
    raw_url: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Vec<CookieUpdate> {
    let mut out = Vec::new();
    for c in cookies {
        let upd = effective_set_cookie(c, raw_url, now);
        if !in_filtered_domain(&upd.cookie) {
            continue;
        }
        out.push(upd);
    }
    out
}

/// Collect the `Set-Cookie` header values from a response
/// (Go `hdr.Values("Set-Cookie")`).
fn set_cookie_values(headers: &HeaderMap) -> Vec<String> {
    headers
        .get_all(http::header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok().map(|s| s.to_string()))
        .collect()
}

/// The `vm_unavailable` Gateway error (status -1, marker
/// `vm_unavailable`), mirroring gateway's
/// `vm_unavailable_gateway`.
fn vm_unavailable_gateway(status: i32, sum: &castctl_gateway::Summary) -> TransportError {
    let mut body = summary_to_body_summary(status, sum);
    body.error_code = Some("vm_unavailable".to_string());
    TransportError::Gateway(body)
}

/// The validated `Content-Type` of a response, or `""`.
fn content_type_of(headers: &HeaderMap) -> &str {
    headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
}

/// One HTTP request to an absolute URL, TLS from the
/// scheme, bounded by `timeout` (gateway `request_url`).
async fn request_url(
    client: &HttpClient,
    method: Method,
    url: &str,
    headers: &[(String, String)],
    body: Option<Bytes>,
    timeout: Duration,
) -> Result<castctl_transport::HttpResponse, TransportError> {
    let (secure, target, path) = split_url(url).ok_or_else(|| TransportError::Validation {
        message: format!("invalid URL: {url}"),
    })?;
    if secure {
        client
            .request_tls(method, &target, &path, headers, body, timeout)
            .await
    } else {
        client
            .request(method, &target, &path, headers, body, timeout)
            .await
    }
}

/// Split an absolute URL into (tls?, target, path+query).
/// Returns `None` when the URL is not absolute http(s).
fn split_url(url: &str) -> Option<(bool, DialTarget, String)> {
    let u = url::Url::parse(url).ok()?;
    let secure = match u.scheme() {
        "https" => true,
        "http" => false,
        _ => return None,
    };
    let host = u.host_str()?.to_string();
    let port = u.port_or_known_default()?;
    let path = if u.path().is_empty() {
        "/".to_string()
    } else {
        match u.query() {
            Some(q) => format!("{}?{q}", u.path()),
            None => u.path().to_string(),
        }
    };
    Some((secure, DialTarget::new(&host, port), path))
}

impl Default for CheckOutcome {
    fn default() -> Self {
        Self {
            updates: Vec::new(),
            skipped: 0,
            error: None,
        }
    }
}

/// A clock that always returns the same instant (for
/// `GatewayChecker` tests that need a fixed `now`).
pub struct FixedClock(pub chrono::DateTime<chrono::Utc>);

impl Clock for FixedClock {
    fn now(&self) -> chrono::DateTime<chrono::Utc> {
        self.0
    }

    fn sleep(
        &self,
        _d: Duration,
        _cancel: &crate::clock::CancelFlag,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + '_>> {
        Box::pin(async move { true })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::FakeClock;

    #[test]
    fn to_updates_filters_unfiltered_domains() {
        let now = chrono::Utc::now();
        let parsed = vec![
            ParsedCookie {
                name: "hatch_sess".to_string(),
                value: "v".to_string(),
                domain: Some(".muse.ai".to_string()),
                path: Some("/".to_string()),
                expires: None,
                max_age: None,
                secure: false,
                http_only: false,
            },
            ParsedCookie {
                name: "other".to_string(),
                value: "v".to_string(),
                domain: Some(".example.com".to_string()),
                path: Some("/".to_string()),
                expires: None,
                max_age: None,
                secure: false,
                http_only: false,
            },
        ];
        let out = to_updates(&parsed, SESSION_CHECK_URL, now);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].cookie.name, "hatch_sess");
    }

    #[test]
    fn split_url_shapes() {
        let (secure, target, path) = split_url("https://muse.ai/api/session").unwrap();
        assert!(secure);
        assert_eq!(target.host, "muse.ai");
        assert_eq!(target.port, 443);
        assert_eq!(path, "/api/session");
        let (secure, target, path) = split_url("http://127.0.0.1:18080/x?y=1").unwrap();
        assert!(!secure);
        assert_eq!(target.port, 18080);
        assert_eq!(path, "/x?y=1");
        assert!(split_url("ftp://example.com/").is_none());
    }

    #[test]
    fn fake_clock_now_is_fixed() {
        let now = chrono::Utc::now();
        let c = FakeClock::new(now);
        assert_eq!(c.now(), now);
    }
}
