// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Plain-HTTPS muse.ai invite / redeem / wake helpers.
//!
//! Go sources: `internal/gateway/invite.go` (`FetchInvite`,
//! `CreateInvite`, `RedeemInviteCode`) and
//! `internal/gateway/wake.go` (`WakeVM`). None of these go
//! through the gateway/Noise connection: they use the
//! dialer's HTTP client with the hatch headers, exactly as
//! Go does. Every function has a `_base` variant taking an
//! explicit base URL (test seam; production passes
//! [`MUSE_AI_BASE`]).
//!
//! Error mapping mirrors Go exactly: 401/403 is an
//! `Auth` error (typed exit 2, `classifyConnError`); any
//! other non-200 from Fetch/CreateInvite is a `Gateway`
//! error built from the allowlist body summary (exit 3);
//! a non-JSON or non-object body is a `Gateway` error with
//! status -1. `RedeemInviteCode` and `WakeVM` return the
//! HTTP status as data instead: every non-auth status is
//! a normal result, never an error.

use std::time::Duration;

use bytes::Bytes;
use castctl_config::gostr::go_quote;
use castctl_transport::{HttpClient, TransportError};
use http::{Method, header::HeaderMap};
use serde_json::Value as SerdeValue;

use crate::auth::{HATCH_MAX_BODY, MUSE_AI_BASE, hatch_headers, request_url};
use crate::cookies::escape_go_json_string;
use crate::summary::{gate_allowlist_value, summarize_body, summary_to_body_summary};

/// Bound for the wake POST itself (Go `deliver.WakeTimeout`
/// / `gateway.wakeTimeout`, 15s). It does not bound the
/// token and session-info fetches that precede it.
pub const WAKE_TIMEOUT: Duration = Duration::from_secs(15);

/// Effective bound for the invite/redeem calls: Go wraps
/// them in a 30s context, but `doHatch`'s own 20s bound
/// wins (`AUTH_TIMEOUT`), so the wire bound is 20s.
const HATCH_CALL_TIMEOUT: Duration = Duration::from_secs(20);

/// Go `%T` for a decoded JSON value (the same table as
/// `castctl-cli/src/network.rs` `go_type_name`): numbers
/// decode as `json.Number`, never `float64`.
fn go_type_name(v: &SerdeValue) -> &'static str {
    match v {
        SerdeValue::Null => "<nil>",
        SerdeValue::Bool(_) => "bool",
        SerdeValue::Number(_) => "json.Number",
        SerdeValue::String(_) => "string",
        SerdeValue::Array(_) => "[]interface {}",
        SerdeValue::Object(_) => "map[string]interface {}",
    }
}

fn content_type_of(headers: &HeaderMap) -> &str {
    headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
}

/// One muse.ai HTTPS request with the `doHatch` bound:
/// status, body bytes truncated at `HATCH_MAX_BODY`, and
/// response headers. Transport errors pass through.
async fn do_hatch_timeout(
    client: &HttpClient,
    method: Method,
    url: &str,
    headers: &[(String, String)],
    body: Option<Bytes>,
    timeout: Duration,
) -> Result<(u16, Vec<u8>, HeaderMap), TransportError> {
    let resp = request_url(client, method, url, headers, body, timeout).await?;
    let mut data = resp.body.to_vec();
    // Go's LimitReader truncates at 4 MiB; the summary's
    // body_length is the truncated length.
    data.truncate(HATCH_MAX_BODY);
    Ok((resp.status.as_u16(), data, resp.headers))
}

/// A `Gateway` error from an allowlist summary (Go
/// `gatewayErrorFromSummary`).
fn gateway_error(status: i32, label: &str, data: &[u8], ct: &str) -> TransportError {
    let sum = summarize_body(label, Some(data), ct, None, &[]);
    TransportError::Gateway(summary_to_body_summary(status, &sum))
}

/// Fetch the invite-friends sheet data: GET
/// `/api/hatch/invite`. 401/403 is an `Auth` error; any
/// other non-200 is a `Gateway` error; a non-JSON or
/// non-dict body is a `Gateway` error with status -1.
/// Read-only: it never POSTs.
pub async fn fetch_invite(
    client: &HttpClient,
    cookies: &str,
) -> Result<serde_json::Map<String, SerdeValue>, TransportError> {
    fetch_invite_base(client, cookies, MUSE_AI_BASE).await
}

/// [`fetch_invite`] against an explicit base URL (test
/// seam; production passes [`MUSE_AI_BASE`]).
pub async fn fetch_invite_base(
    client: &HttpClient,
    cookies: &str,
    base: &str,
) -> Result<serde_json::Map<String, SerdeValue>, TransportError> {
    let (status, data, headers) = do_hatch_timeout(
        client,
        Method::GET,
        &format!("{base}/api/hatch/invite"),
        &hatch_headers(cookies, ""),
        None,
        HATCH_CALL_TIMEOUT,
    )
    .await?;
    if status == 401 || status == 403 {
        return Err(TransportError::Auth {
            message: format!("api/hatch/invite -> {status} (cookies expired? re-export)"),
        });
    }
    let ct = content_type_of(&headers);
    if status != 200 {
        return Err(gateway_error(
            status as i32,
            &format!("api/hatch/invite -> {status}"),
            &data,
            ct,
        ));
    }
    match serde_json::from_slice::<SerdeValue>(&data) {
        Ok(SerdeValue::Object(m)) => Ok(m),
        Ok(v) => Err(gateway_error(
            -1,
            &format!("api/hatch/invite returned {}", go_type_name(&v)),
            &data,
            ct,
        )),
        Err(_) => Err(gateway_error(
            -1,
            "api/hatch/invite returned non-JSON",
            &data,
            ct,
        )),
    }
}

/// Create this account's invite code: POST
/// `/api/hatch/invite` with no body. This WRITES account
/// state — it is what opening Invite friends does. Error
/// mapping matches `fetch_invite`, with the POST status in
/// the `Auth` message. Unlike `fetch_invite`, a JSON
/// non-object body is reported with the same
/// "returned non-JSON" message (Go `CreateInvite` does
/// not distinguish the two cases).
pub async fn create_invite(
    client: &HttpClient,
    cookies: &str,
) -> Result<serde_json::Map<String, SerdeValue>, TransportError> {
    create_invite_base(client, cookies, MUSE_AI_BASE).await
}

/// [`create_invite`] against an explicit base URL (test
/// seam).
pub async fn create_invite_base(
    client: &HttpClient,
    cookies: &str,
    base: &str,
) -> Result<serde_json::Map<String, SerdeValue>, TransportError> {
    let (status, data, headers) = do_hatch_timeout(
        client,
        Method::POST,
        &format!("{base}/api/hatch/invite"),
        &hatch_headers(cookies, ""),
        Some(Bytes::new()),
        HATCH_CALL_TIMEOUT,
    )
    .await?;
    if status == 401 || status == 403 {
        return Err(TransportError::Auth {
            message: format!("api/hatch/invite POST -> {status} (cookies expired? re-export)"),
        });
    }
    let ct = content_type_of(&headers);
    if status != 200 {
        return Err(gateway_error(
            status as i32,
            &format!("api/hatch/invite POST -> {status}"),
            &data,
            ct,
        ));
    }
    match serde_json::from_slice::<SerdeValue>(&data) {
        Ok(SerdeValue::Object(m)) => Ok(m),
        _ => Err(gateway_error(
            -1,
            "api/hatch/invite POST returned non-JSON",
            &data,
            ct,
        )),
    }
}

/// ASCII whitespace, Go `trimSpaceASCII` (`invite.go`):
/// space, tab, newline, carriage return, vertical tab,
/// form feed.
fn trim_space_ascii(s: &str) -> &str {
    s.trim_matches(|c| matches!(c, ' ' | '\t' | '\n' | '\r' | '\u{b}' | '\u{c}'))
}

/// ASCII uppercasing (Go `upperASCII`): only `a`-`z` move.
fn upper_ascii(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_lowercase() {
                c.to_ascii_uppercase()
            } else {
                c
            }
        })
        .collect()
}

/// Go `inviteCodePattern`: `^[A-Z0-9]{6,16}$`.
fn is_invite_code(s: &str) -> bool {
    let n = s.chars().count();
    (6..=16).contains(&n)
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() && !b.is_ascii_lowercase())
}

/// Redeem a friend's invite code: POST
/// `/api/hatch/invite-code/redeem` with
/// `{"code", "supportsRedemptionStatus": true}`. The code
/// is stripped and uppercased; anything outside
/// `^[A-Z0-9]{6,16}$` is a `Validation` error, raised
/// BEFORE any request. 401/403 is an `Auth` error; every
/// other status is returned with its body, exactly as Go
/// returns `(http_status, body)`. A non-JSON body becomes
/// `{"success": false, "reason": "unknown", "detail":
/// <allowlist summary>}`. A JSON body on the failure path
/// (`success` is not true) is filtered to the allowlist
/// only (`success`/`reason`/`detail`, reason/detail
/// enum-gated); a success body passes through untouched.
pub async fn redeem_invite_code(
    client: &HttpClient,
    cookies: &str,
    code: &str,
) -> Result<(u16, SerdeValue), TransportError> {
    redeem_invite_code_base(client, cookies, code, MUSE_AI_BASE).await
}

/// [`redeem_invite_code`] against an explicit base URL
/// (test seam).
pub async fn redeem_invite_code_base(
    client: &HttpClient,
    cookies: &str,
    code: &str,
    base: &str,
) -> Result<(u16, SerdeValue), TransportError> {
    let code = upper_ascii(trim_space_ascii(code));
    if !is_invite_code(&code) {
        return Err(TransportError::Validation {
            message: format!("not an invite code: {}", go_quote(&code)),
        });
    }
    let payload = Bytes::from(format!(
        "{{\"code\":\"{code}\",\"supportsRedemptionStatus\":true}}"
    ));
    let (status, data, headers) = do_hatch_timeout(
        client,
        Method::POST,
        &format!("{base}/api/hatch/invite-code/redeem"),
        &hatch_headers(cookies, ""),
        Some(payload),
        HATCH_CALL_TIMEOUT,
    )
    .await?;
    if status == 401 || status == 403 {
        return Err(TransportError::Auth {
            message: format!("invite-code/redeem -> {status} (cookies expired? re-export)"),
        });
    }
    let ct = content_type_of(&headers);
    let body = match serde_json::from_slice::<SerdeValue>(&data) {
        Err(_) => {
            let sum = summarize_body("non-JSON response", Some(&data), ct, None, &[]);
            let mut m = serde_json::Map::new();
            m.insert("success".to_string(), SerdeValue::Bool(false));
            m.insert(
                "reason".to_string(),
                SerdeValue::String("unknown".to_string()),
            );
            m.insert("detail".to_string(), SerdeValue::String(sum.text));
            SerdeValue::Object(m)
        }
        Ok(SerdeValue::Object(m)) => {
            let success = m
                .get("success")
                .and_then(SerdeValue::as_bool)
                .unwrap_or(false);
            if success {
                SerdeValue::Object(m)
            } else {
                SerdeValue::Object(filter_redeem_failure_body(&m))
            }
        }
        Ok(v) => v,
    };
    Ok((status, body))
}

/// Reduce a JSON failure body to the closed allowlist:
/// `success` (false), `reason`, and `detail`, with
/// reason/detail passed through the allowlist extraction
/// (enum-gated, capped; anything else becomes
/// `"[omitted]"`). A missing `reason` becomes the
/// constant `"unknown"`; a missing `detail` stays
/// missing.
/// Source: `internal/gateway/invite.go`
/// (`filterRedeemFailureBody`).
fn filter_redeem_failure_body(
    m: &serde_json::Map<String, SerdeValue>,
) -> serde_json::Map<String, SerdeValue> {
    let mut out = serde_json::Map::new();
    out.insert("success".to_string(), SerdeValue::Bool(false));
    match m.get("reason") {
        Some(v) => {
            out.insert(
                "reason".to_string(),
                SerdeValue::String(gate_allowlist_value(Some(v))),
            );
        }
        None => {
            out.insert(
                "reason".to_string(),
                SerdeValue::String("unknown".to_string()),
            );
        }
    }
    if let Some(v) = m.get("detail") {
        out.insert(
            "detail".to_string(),
            SerdeValue::String(gate_allowlist_value(Some(v))),
        );
    }
    out
}

/// Ask muse.ai to wake the VM: POST
/// `/api/hatch/vm/wake` with
/// `{"vm_id", "retry_count": 0}` (Go `json.Marshal` on a
/// map: keys sorted, so `retry_count` comes first) and the
/// hatch headers for cookies/accessToken.
///
/// A non-2xx status is NOT an error: status and the parsed
/// body are returned and the error is nil. Only transport
/// errors (including the 15s timeout) are returned as
/// errors. The body is the parsed JSON value when the
/// response parses as JSON, null when the response body is
/// empty, and otherwise the allowlist summary string
/// (status/length/content-type) — never the raw response
/// text.
/// Source: `internal/gateway/wake.go` (`WakeVM`).
pub async fn wake_vm(
    client: &HttpClient,
    cookies: &str,
    access_token: &str,
    vm_id: &str,
) -> Result<(u16, SerdeValue), TransportError> {
    wake_vm_base(client, cookies, access_token, vm_id, MUSE_AI_BASE).await
}

/// [`wake_vm`] against an explicit base URL (test seam).
pub async fn wake_vm_base(
    client: &HttpClient,
    cookies: &str,
    access_token: &str,
    vm_id: &str,
    base: &str,
) -> Result<(u16, SerdeValue), TransportError> {
    let payload = Bytes::from(format!(
        "{{\"retry_count\":0,\"vm_id\":{}}}",
        escape_go_json_string(vm_id)
    ));
    let (status, data, headers) = do_hatch_timeout(
        client,
        Method::POST,
        &format!("{base}/api/hatch/vm/wake"),
        &hatch_headers(cookies, access_token),
        Some(payload),
        WAKE_TIMEOUT,
    )
    .await?;
    if data.is_empty() {
        // Go (Python): empty body -> None (JSON null), not "".
        return Ok((status, SerdeValue::Null));
    }
    match serde_json::from_slice::<SerdeValue>(&data) {
        Ok(v) => Ok((status, v)),
        Err(_) => {
            let sum = summarize_body(
                "non-JSON response",
                Some(&data),
                content_type_of(&headers),
                None,
                &[],
            );
            Ok((status, SerdeValue::String(sum.text)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use castctl_transport::{Dialer, DirectDialer};
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// One canned HTTP response: (status, content-type, body).
    struct Canned(pub u16, pub &'static str, pub &'static str);

    /// A minimal loopback HTTP/1.1 server for the `_base`
    /// tests: records (method, path, body) per request and
    /// answers from a canned queue. Plain HTTP only — the
    /// production base is https, the tests pass an
    /// `http://127.0.0.1:PORT` base.
    struct FakeHttp {
        addr: std::net::SocketAddr,
        seen: Arc<Mutex<Vec<(String, String, String)>>>,
    }

    impl FakeHttp {
        async fn start(canned: Vec<Canned>) -> FakeHttp {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let seen = Arc::new(Mutex::new(Vec::new()));
            let seen2 = Arc::clone(&seen);
            let canned = Arc::new(Mutex::new(canned));
            tokio::spawn(async move {
                loop {
                    let Ok((mut sock, _)) = listener.accept().await else {
                        return;
                    };
                    let seen = Arc::clone(&seen2);
                    let canned = Arc::clone(&canned);
                    tokio::spawn(async move {
                        let mut buf = vec![0u8; 8192];
                        let mut req = Vec::new();
                        // Read headers.
                        loop {
                            let Ok(n) = sock.read(&mut buf).await else {
                                return;
                            };
                            if n == 0 {
                                return;
                            }
                            req.extend_from_slice(&buf[..n]);
                            if req.windows(4).any(|w| w == b"\r\n\r\n") {
                                break;
                            }
                        }
                        let text = String::from_utf8_lossy(&req).into_owned();
                        let mut lines = text.lines();
                        let first = lines.next().unwrap_or("").to_string();
                        let mut parts = first.split_whitespace();
                        let method = parts.next().unwrap_or("").to_string();
                        let path = parts.next().unwrap_or("").to_string();
                        let mut content_len = 0usize;
                        for line in text.lines().skip(1) {
                            if line.is_empty() {
                                break;
                            }
                            if let Some(v) =
                                line.to_ascii_lowercase().strip_prefix("content-length:")
                            {
                                content_len = v.trim().parse().unwrap_or(0);
                            }
                        }
                        let header_end = req.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
                        let mut body = req[header_end..].to_vec();
                        while body.len() < content_len {
                            let Ok(n) = sock.read(&mut buf).await else {
                                return;
                            };
                            if n == 0 {
                                break;
                            }
                            body.extend_from_slice(&buf[..n]);
                        }
                        body.truncate(content_len);
                        seen.lock().unwrap().push((
                            method,
                            path,
                            String::from_utf8_lossy(&body).into_owned(),
                        ));
                        let (status, ctype, cbody) = {
                            let mut q = canned.lock().unwrap();
                            if q.is_empty() {
                                (404u16, "text/plain", "no canned response")
                            } else {
                                let c = q.remove(0);
                                (c.0, c.1, c.2)
                            }
                        };
                        let resp = format!(
                            "HTTP/1.1 {status} X\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{cbody}",
                            cbody.len()
                        );
                        let _ = sock.write_all(resp.as_bytes()).await;
                        let _ = sock.shutdown().await;
                    });
                }
            });
            FakeHttp { addr, seen }
        }

        fn base(&self) -> String {
            format!("http://{}", self.addr)
        }

        fn seen(&self) -> Vec<(String, String, String)> {
            self.seen.lock().unwrap().clone()
        }
    }

    fn http_client() -> HttpClient {
        HttpClient::new(Arc::new(DirectDialer))
    }

    #[tokio::test]
    async fn fetch_invite_ok_and_auth() {
        let srv = FakeHttp::start(vec![
            Canned(
                200,
                "application/json",
                r#"{"invite_state":"active","code":"ABCDEF"}"#,
            ),
            Canned(401, "application/json", "{}"),
            Canned(500, "application/json", r#"{"error":"boom"}"#),
            Canned(200, "text/plain", "not json"),
            Canned(200, "application/json", "[1,2]"),
        ])
        .await;
        let client = http_client();
        let base = srv.base();
        let d = fetch_invite_base(&client, "hatch_sess=FAKE", &base)
            .await
            .unwrap();
        assert_eq!(d.get("code").and_then(|v| v.as_str()), Some("ABCDEF"));
        let e = fetch_invite_base(&client, "hatch_sess=FAKE", &base)
            .await
            .unwrap_err();
        assert!(matches!(e, TransportError::Auth { .. }));
        assert!(e.to_string().contains("api/hatch/invite -> 401"));
        let e = fetch_invite_base(&client, "hatch_sess=FAKE", &base)
            .await
            .unwrap_err();
        assert!(matches!(e, TransportError::Gateway(s) if s.status == 500));
        let e = fetch_invite_base(&client, "hatch_sess=FAKE", &base)
            .await
            .unwrap_err();
        assert!(matches!(e, TransportError::Gateway(s) if s.status == -1));
        let e = fetch_invite_base(&client, "hatch_sess=FAKE", &base)
            .await
            .unwrap_err();
        assert!(matches!(e, TransportError::Gateway(s) if s.status == -1));
        let seen = srv.seen();
        assert_eq!(seen.len(), 5);
        assert_eq!(seen[0].0, "GET");
        assert_eq!(seen[0].1, "/api/hatch/invite");
        assert_eq!(seen[0].2, "");
    }

    #[tokio::test]
    async fn create_invite_posts_empty_body() {
        let srv = FakeHttp::start(vec![Canned(
            200,
            "application/json",
            r#"{"invite_state":"active","code":"NEWCODE"}"#,
        )])
        .await;
        let client = http_client();
        let d = create_invite_base(&client, "hatch_sess=FAKE", &srv.base())
            .await
            .unwrap();
        assert_eq!(d.get("code").and_then(|v| v.as_str()), Some("NEWCODE"));
        let seen = srv.seen();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].0, "POST");
        assert_eq!(seen[0].1, "/api/hatch/invite");
        assert_eq!(seen[0].2, "");
    }

    #[tokio::test]
    async fn redeem_validation_before_request() {
        let srv = FakeHttp::start(vec![]).await;
        let client = http_client();
        let e = redeem_invite_code_base(&client, "hatch_sess=FAKE", "bad!", &srv.base())
            .await
            .unwrap_err();
        assert!(
            matches!(e, TransportError::Validation { message } if message == "not an invite code: \"BAD!\"")
        );
        // No request was made.
        assert!(srv.seen().is_empty());
        // Too short, too long, lowercase input is uppercased first.
        let e = redeem_invite_code_base(&client, "hatch_sess=FAKE", "abc", &srv.base())
            .await
            .unwrap_err();
        assert!(matches!(e, TransportError::Validation { .. }));
        assert!(srv.seen().is_empty());
    }

    #[tokio::test]
    async fn redeem_success_failure_and_non_json() {
        let srv = FakeHttp::start(vec![
            Canned(
                200,
                "application/json",
                r#"{"success":true,"redemptionStatus":"ok","extra":1}"#,
            ),
            Canned(
                400,
                "application/json",
                r#"{"success":false,"reason":"already_redeemed","detail":"ok-detail","extra":"dropped"}"#,
            ),
            Canned(
                400,
                "application/json",
                r#"{"success":false,"detail":"free text here"}"#,
            ),
            Canned(200, "text/plain", "plain failure"),
        ])
        .await;
        let client = http_client();
        let base = srv.base();
        // Success passes through untouched (extra key kept).
        let (status, body) = redeem_invite_code_base(&client, "hatch_sess=FAKE", " abcdef ", &base)
            .await
            .unwrap();
        assert_eq!(status, 200);
        assert_eq!(body.get("extra").and_then(|v| v.as_i64()), Some(1));
        // Failure is filtered: extra dropped, reason/detail kept.
        let (status, body) = redeem_invite_code_base(&client, "hatch_sess=FAKE", "ABCDEF", &base)
            .await
            .unwrap();
        assert_eq!(status, 400);
        assert_eq!(body.get("success"), Some(&SerdeValue::Bool(false)));
        assert_eq!(
            body.get("reason").and_then(|v| v.as_str()),
            Some("already_redeemed")
        );
        assert_eq!(
            body.get("detail").and_then(|v| v.as_str()),
            Some("ok-detail")
        );
        assert!(body.get("extra").is_none());
        // Free-text detail is gated; missing reason becomes unknown.
        let (_status, body) = redeem_invite_code_base(&client, "hatch_sess=FAKE", "ABCDEF", &base)
            .await
            .unwrap();
        assert_eq!(body.get("reason").and_then(|v| v.as_str()), Some("unknown"));
        assert_eq!(
            body.get("detail").and_then(|v| v.as_str()),
            Some("[omitted]")
        );
        // Non-JSON body becomes the failure shape.
        let (_status, body) = redeem_invite_code_base(&client, "hatch_sess=FAKE", "ABCDEF", &base)
            .await
            .unwrap();
        assert_eq!(body.get("success"), Some(&SerdeValue::Bool(false)));
        assert_eq!(body.get("reason").and_then(|v| v.as_str()), Some("unknown"));
        assert!(
            body.get("detail")
                .and_then(|v| v.as_str())
                .map(|s| s.starts_with("non-JSON response"))
                .unwrap_or(false)
        );
        // The lowercase+spaces input was uppercased on the wire.
        let seen = srv.seen();
        assert_eq!(seen.len(), 4);
        assert!(seen[0].2.contains("\"code\":\"ABCDEF\""));
        assert!(seen[0].2.contains("\"supportsRedemptionStatus\":true"));
    }

    #[tokio::test]
    async fn wake_vm_shapes() {
        let srv = FakeHttp::start(vec![
            Canned(200, "application/json", r#"{"status":"waking"}"#),
            Canned(200, "application/json", ""),
            Canned(200, "text/plain", "not json"),
            Canned(500, "application/json", r#"{"error":"x"}"#),
        ])
        .await;
        let client = http_client();
        let base = srv.base();
        let (status, body) = wake_vm_base(&client, "c", "AT", "vm-1", &base)
            .await
            .unwrap();
        assert_eq!(status, 200);
        assert_eq!(body.get("status").and_then(|v| v.as_str()), Some("waking"));
        let (status, body) = wake_vm_base(&client, "c", "AT", "vm-1", &base)
            .await
            .unwrap();
        assert_eq!(status, 200);
        assert_eq!(body, SerdeValue::Null);
        let (status, body) = wake_vm_base(&client, "c", "AT", "vm-1", &base)
            .await
            .unwrap();
        assert_eq!(status, 200);
        assert!(
            body.as_str()
                .map(|s| s.starts_with("non-JSON response"))
                .unwrap_or(false)
        );
        // Non-2xx is data, not an error.
        let (status, body) = wake_vm_base(&client, "c", "AT", "vm-1", &base)
            .await
            .unwrap();
        assert_eq!(status, 500);
        assert_eq!(body.get("error").and_then(|v| v.as_str()), Some("x"));
        let seen = srv.seen();
        assert_eq!(seen.len(), 4);
        // Sorted keys: retry_count first (Go json.Marshal on a map).
        assert!(seen[0].2.contains(r#"{"retry_count":0,"vm_id":"vm-1"}"#));
    }
}
