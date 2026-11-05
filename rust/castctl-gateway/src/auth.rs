// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! HTTPS auth chain — port of `internal/gateway/auth.go` +
//! `internal/gateway/authcookies.go` (the plain variants only;
//! the `WithCookies` variants are keeper-only and NOT ported
//! in PR2).
//!
//! Chain: `GET /api/session` (discover vm_id) → `POST
//! /api/auth/check` (access token) → `POST /api/hatch/token`
//! (hatch token). Every call is bounded by `AUTH_TIMEOUT`
//! (20s) and the response body is truncated at 4 MiB before
//! decoding, exactly like Go's `LimitReader` (a truncated body
//! then fails JSON decoding; the summary's `body_length` is
//! the TRUNCATED length).
//!
//! Error mapping (Go-exact):
//! - transport failure → the `TransportError` passes through
//!   unchanged (NOT mapped to Auth — a network failure must
//!   not be marked unretryable).
//! - non-200 on `/api/session` → Auth `api/session -> N
//!   (cookies expired? re-export)` (plain, no summary).
//! - non-JSON on `/api/session` → Auth with the allowlist
//!   summary text (`api/session returned non-JSON; ...`).
//! - missing/non-string `vm_id`, or a non-object body →
//!   `TransportError::Gateway` status -1 with the
//!   `vm_unavailable` marker (Go keys the CLI's
//!   `session_unavailable` classification on the
//!   `"VM unavailable"` Payload text, which the Rust error
//!   does not keep — the marker replaces it; see
//!   `summary.rs`).
//! - non-200 on `/api/auth/check` → Auth with the summary
//!   text (`auth/check -> N (cookies expired? re-export); ...`).
//! - non-JSON / missing token on either token call → Auth
//!   with the fixed plain message.
//!
//! TLS is derived from the URL scheme (`https` →
//! `request_tls`, `http` → `request`); production URLs are
//! https, test fake-server URLs are http. The `*_base`
//! variants take the base URL as a test seam (Go hardcodes
//! `https://muse.ai/...`); the public functions default to
//! `MUSE_AI_BASE`.
//!
//! The `Raw` map keeps `serde_json::Value` numbers (not Go
//! `json.Number` literals) — nothing in PR2 re-encodes it;
//! see PORTING.md §M4b.

use std::time::Duration;

use bytes::Bytes;
use castctl_transport::{DialTarget, HttpClient, TransportError};
use http::{Method, header::HeaderMap};

use crate::cookies::escape_go_json_string;
use crate::dial::GATEWAY_USER_AGENT;
use crate::summary::{Summary, summarize_body, summary_to_body_summary};

/// Bounds each HTTPS auth call (20s in Python/Go).
pub const AUTH_TIMEOUT: Duration = Duration::from_secs(20);

/// Production base for the muse.ai HTTPS calls.
pub const MUSE_AI_BASE: &str = "https://muse.ai";

/// Response-body cap for the auth calls (4 MiB, Go
/// `doHatch`'s `LimitReader`).
pub const HATCH_MAX_BODY: usize = 4 << 20;

/// Class label for a session response that carries no usable
/// `vm_id`. A constant, never body-derived; the CLI's
/// `session_unavailable` classification keys on the `"VM
/// unavailable"` prefix (in Go, via the Payload text).
pub const VM_UNAVAILABLE_LABEL: &str =
    "VM unavailable; retry shortly or `MUSE_VM_ID=<id> castctl wake`";

/// The decoded `/api/session` response. `vm_id` is the
/// assigned personal VM id.
#[derive(Debug, Clone)]
pub struct SessionInfo {
    pub vm_id: String,
    pub raw: serde_json::Map<String, serde_json::Value>,
}

/// Builds the headers for muse.ai HTTPS calls: Chrome UA,
/// Referer/Origin, Sec-Fetch-*, Accept/Content-Type
/// application/json, Cookie, and `Authorization: Bearer ...`
/// when a token is present. The Cookie value is never copied
/// anywhere else — callers must not log this vector.
pub fn hatch_headers(cookies: &str, access_token: &str) -> Vec<(String, String)> {
    let mut h = vec![
        ("User-Agent".to_string(), GATEWAY_USER_AGENT.to_string()),
        ("Referer".to_string(), "https://muse.ai/".to_string()),
        ("Origin".to_string(), "https://muse.ai".to_string()),
        ("Sec-Fetch-Site".to_string(), "same-origin".to_string()),
        ("Sec-Fetch-Mode".to_string(), "cors".to_string()),
        ("Sec-Fetch-Dest".to_string(), "empty".to_string()),
        ("Accept".to_string(), "application/json".to_string()),
        ("Content-Type".to_string(), "application/json".to_string()),
        ("Cookie".to_string(), cookies.to_string()),
    ];
    if !access_token.is_empty() {
        h.push((
            "Authorization".to_string(),
            format!("Bearer {access_token}"),
        ));
    }
    h
}

/// One muse.ai HTTPS request with an `AUTH_TIMEOUT` bound.
/// Returns the status code, the body bytes truncated at
/// `HATCH_MAX_BODY`, and the response headers. Transport
/// errors pass through unchanged.
async fn do_hatch(
    client: &HttpClient,
    method: Method,
    url: &str,
    headers: &[(String, String)],
    body: Option<Bytes>,
) -> Result<(u16, Vec<u8>, HeaderMap), TransportError> {
    let resp = request_url(client, method, url, headers, body, AUTH_TIMEOUT).await?;
    let mut data = resp.body.to_vec();
    // Go's LimitReader truncates at 4 MiB; the summary's
    // body_length is the truncated length.
    data.truncate(HATCH_MAX_BODY);
    Ok((resp.status.as_u16(), data, resp.headers))
}

/// One HTTP request to an absolute URL, TLS from the scheme,
/// bounded by `timeout`. Returns the full response. Used by
/// the auth chain (via [`do_hatch`]) and the subscription
/// side-paths (`callAction`/`fetchText` in `subscription.rs`).
pub(crate) async fn request_url(
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

/// Discovers the assigned personal VM: `GET /api/session`.
pub async fn fetch_session_info(
    client: &HttpClient,
    cookies: &str,
) -> Result<SessionInfo, TransportError> {
    fetch_session_info_base(client, cookies, MUSE_AI_BASE).await
}

/// [`fetch_session_info`] against an explicit base URL (test
/// seam; production passes [`MUSE_AI_BASE`]).
pub async fn fetch_session_info_base(
    client: &HttpClient,
    cookies: &str,
    base: &str,
) -> Result<SessionInfo, TransportError> {
    let (status, data, headers) = do_hatch(
        client,
        Method::GET,
        &format!("{base}/api/session"),
        &hatch_headers(cookies, ""),
        None,
    )
    .await?;
    if status != 200 {
        return Err(TransportError::Auth {
            message: format!("api/session -> {status} (cookies expired? re-export)"),
        });
    }
    let ct = content_type_of(&headers);
    let raw = match serde_json::from_slice::<serde_json::Value>(&data) {
        Ok(v) => v,
        Err(_) => {
            let sum = summarize_body("api/session returned non-JSON", Some(&data), ct, None, &[]);
            return Err(TransportError::Auth { message: sum.text });
        }
    };
    let serde_json::Value::Object(info) = raw else {
        // Python: "vm_id" not in a non-dict body is also the
        // VM-unavailable case, not an auth failure.
        let sum = summarize_body(VM_UNAVAILABLE_LABEL, Some(&data), ct, None, &[]);
        return Err(vm_unavailable_gateway(-1, &sum));
    };
    match info.get("vm_id") {
        Some(serde_json::Value::String(vm_id)) => Ok(SessionInfo {
            vm_id: vm_id.clone(),
            raw: info,
        }),
        _ => {
            // JSON null (or any non-string) vm_id is the
            // missing-VM case, not a string.
            let sum = summarize_body(
                VM_UNAVAILABLE_LABEL,
                Some(&data),
                ct,
                Some(&info),
                &["status"],
            );
            Err(vm_unavailable_gateway(-1, &sum))
        }
    }
}

/// Exchanges cookies for an access token: `POST
/// /api/auth/check` with an empty body.
pub async fn fetch_access_token(
    client: &HttpClient,
    cookies: &str,
) -> Result<String, TransportError> {
    fetch_access_token_base(client, cookies, MUSE_AI_BASE).await
}

/// [`fetch_access_token`] against an explicit base URL (test
/// seam).
pub async fn fetch_access_token_base(
    client: &HttpClient,
    cookies: &str,
    base: &str,
) -> Result<String, TransportError> {
    let (status, data, headers) = do_hatch(
        client,
        Method::POST,
        &format!("{base}/api/auth/check"),
        &hatch_headers(cookies, ""),
        Some(Bytes::new()),
    )
    .await?;
    if status != 200 {
        let sum = summarize_body(
            &format!("auth/check -> {status} (cookies expired? re-export)"),
            Some(&data),
            content_type_of(&headers),
            None,
            &[],
        );
        return Err(TransportError::Auth { message: sum.text });
    }
    let d = match serde_json::from_slice::<serde_json::Value>(&data) {
        Ok(serde_json::Value::Object(m)) => m,
        _ => {
            return Err(TransportError::Auth {
                message: "auth/check returned non-JSON or missing access_token".to_string(),
            });
        }
    };
    match d.get("access_token") {
        Some(serde_json::Value::String(token)) if !token.is_empty() => Ok(token.clone()),
        _ => Err(TransportError::Auth {
            message: "auth/check response missing access_token".to_string(),
        }),
    }
}

/// Exchanges an access token for a hatch token: `POST
/// /api/hatch/token {vmAddress, vmName}`.
pub async fn fetch_hatch_token(
    client: &HttpClient,
    cookies: &str,
    access_token: &str,
    vm_id: &str,
) -> Result<String, TransportError> {
    fetch_hatch_token_base(client, cookies, access_token, vm_id, MUSE_AI_BASE).await
}

/// [`fetch_hatch_token`] against an explicit base URL (test
/// seam).
pub async fn fetch_hatch_token_base(
    client: &HttpClient,
    cookies: &str,
    access_token: &str,
    vm_id: &str,
    base: &str,
) -> Result<String, TransportError> {
    let (status, data, headers) = do_hatch(
        client,
        Method::POST,
        &format!("{base}/api/hatch/token"),
        &hatch_headers(cookies, access_token),
        Some(hatch_token_payload(vm_id)),
    )
    .await?;
    if status != 200 {
        let sum = summarize_body(
            &format!("hatch/token -> {status}"),
            Some(&data),
            content_type_of(&headers),
            None,
            &[],
        );
        return Err(TransportError::Auth { message: sum.text });
    }
    let d = match serde_json::from_slice::<serde_json::Value>(&data) {
        Ok(serde_json::Value::Object(m)) => m,
        _ => {
            return Err(TransportError::Auth {
                message: "hatch/token returned non-JSON or missing token".to_string(),
            });
        }
    };
    match d.get("token") {
        Some(serde_json::Value::String(token)) if !token.is_empty() => Ok(token.clone()),
        _ => Err(TransportError::Auth {
            message: "hatch/token response missing token".to_string(),
        }),
    }
}

/// The `hatch/token` request body: `{"vmAddress":
/// "wss://<vmID>.metaaivm.com/", "vmName": vmID}` with Go
/// `json.Marshal` key order (sorted) and string escaping.
fn hatch_token_payload(vm_id: &str) -> Bytes {
    // NOTE: the VM address host is <vmID>.metaaivm.com — NOT
    // GATEWAY_HOST (hatch.metaaivm.com), which is the WS
    // gateway dial host. Go: wss://%s.metaaivm.com/ (auth.go).
    let address = format!("wss://{vm_id}.metaaivm.com/");
    Bytes::from(format!(
        "{{\"vmAddress\":{},\"vmName\":{}}}",
        escape_go_json_string(&address),
        escape_go_json_string(vm_id),
    ))
}

/// Splits a `http(s)://host[:port]/path` URL into (secure,
/// dial target, origin-form path). `None` for anything else.
/// No IPv6-literal support (production and test URLs never
/// use one).
fn split_url(url: &str) -> Option<(bool, DialTarget, String)> {
    let (scheme, rest) = url.split_once("://")?;
    let (secure, default_port) = match scheme {
        "https" => (true, 443),
        "http" => (false, 80),
        _ => return None,
    };
    let (authority, path) = match rest.split_once('/') {
        Some((a, p)) => (a, format!("/{p}")),
        None => (rest, "/".to_string()),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) if !p.is_empty() => match p.parse::<u16>() {
            Ok(n) => (h, n),
            Err(_) => (authority, default_port),
        },
        _ => (authority, default_port),
    };
    Some((secure, DialTarget::new(host, port), path))
}

/// Raw Content-Type header value (`""` when absent or
/// non-ASCII). Validation happens in the summary builder.
fn content_type_of(headers: &HeaderMap) -> &str {
    headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
}

/// Builds the VM-unavailable Gateway error (status -1) from
/// an allowlist summary, stamping the `vm_unavailable`
/// marker the CLI classifies on (see the module docs).
fn vm_unavailable_gateway(status: i32, sum: &Summary) -> TransportError {
    let mut body = summary_to_body_summary(status, sum);
    // Go keys the CLI's session_unavailable classification on
    // the "VM unavailable" Payload text; the Payload is not
    // kept on the Rust error, so the marker replaces it.
    body.error_code = Some("vm_unavailable".to_string());
    TransportError::Gateway(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hatch_headers_shape() {
        let h = hatch_headers("hatch_sess=S", "");
        let keys: Vec<&str> = h.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(
            keys,
            [
                "User-Agent",
                "Referer",
                "Origin",
                "Sec-Fetch-Site",
                "Sec-Fetch-Mode",
                "Sec-Fetch-Dest",
                "Accept",
                "Content-Type",
                "Cookie",
            ]
        );
        assert_eq!(h[0].1, GATEWAY_USER_AGENT);
        assert_eq!(h[1].1, "https://muse.ai/");
        assert_eq!(h[8].1, "hatch_sess=S");
        // A token adds exactly one Authorization header, last.
        let h = hatch_headers("c", "tok");
        assert_eq!(h.len(), 10);
        assert_eq!(
            h[9],
            ("Authorization".to_string(), "Bearer tok".to_string())
        );
    }

    #[test]
    fn split_url_cases() {
        let (secure, target, path) = split_url("https://muse.ai/api/session").unwrap();
        assert!(secure);
        assert_eq!(target, DialTarget::new("muse.ai", 443));
        assert_eq!(path, "/api/session");
        let (secure, target, path) = split_url("http://127.0.0.1:1234/settings").unwrap();
        assert!(!secure);
        assert_eq!(target, DialTarget::new("127.0.0.1", 1234));
        assert_eq!(path, "/settings");
        let (_, _, path) = split_url("https://muse.ai").unwrap();
        assert_eq!(path, "/");
        assert!(split_url("ftp://x/y").is_none());
        assert!(split_url("not a url").is_none());
    }

    #[test]
    fn hatch_token_payload_shape() {
        let p = hatch_token_payload("vm-42");
        assert_eq!(
            p,
            Bytes::from_static(br#"{"vmAddress":"wss://vm-42.metaaivm.com/","vmName":"vm-42"}"#)
        );
        // The VM address host is <vmID>.metaaivm.com, not the
        // WS gateway host (hatch.metaaivm.com).
        assert!(std::str::from_utf8(&p).unwrap().contains("metaaivm.com"));
        assert!(
            !std::str::from_utf8(&p)
                .unwrap()
                .contains("hatch.metaaivm.com")
        );
    }
}
