// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Integration tests for the HTTPS auth chain (M4b): real
//! HTTP/1.1 against the plain-HTTP fake server in
//! `tests/http_fake` — only the handler's replies are
//! fake. Error mapping is ported from
//! `internal/gateway/auth.go` + `authcookies.go`.

mod http_fake;

use std::sync::Arc;

use castctl_gateway::auth::{
    fetch_access_token_base, fetch_hatch_token_base, fetch_session_info_base,
};
use castctl_transport::{DirectDialer, HttpClient, TransportError};
use http_fake::{HttpFakeServer, HttpHandlerFn, HttpReply};

fn client() -> HttpClient {
    HttpClient::new(Arc::new(DirectDialer::new()))
}

fn auth_message(err: &TransportError) -> Option<&str> {
    match err {
        TransportError::Auth { message } => Some(message),
        _ => None,
    }
}

fn gateway_summary(err: &TransportError) -> Option<&castctl_transport::BodySummary> {
    match err {
        TransportError::Gateway(b) => Some(b),
        _ => None,
    }
}

#[tokio::test]
async fn session_info_success() {
    let server = HttpFakeServer::start(Arc::new(|req: &http_fake::HttpRequest| {
        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/api/session");
        assert_eq!(
            req.header("User-Agent").unwrap(),
            castctl_gateway::dial::GATEWAY_USER_AGENT
        );
        assert_eq!(req.header("Cookie").unwrap(), "hatch_sess=S");
        assert!(req.header("Authorization").is_none());
        HttpReply::text(
            200,
            "application/json",
            r#"{"vm_id": "vm-123", "status": "ok"}"#,
        )
    }) as HttpHandlerFn)
    .await;
    let info = fetch_session_info_base(&client(), "hatch_sess=S", &server.base_url())
        .await
        .unwrap();
    assert_eq!(info.vm_id, "vm-123");
    assert_eq!(info.raw["status"], serde_json::json!("ok"));
    assert_eq!(server.requests.lock().unwrap().len(), 1);
    server.stop();
}

#[tokio::test]
async fn session_info_error_mapping() {
    // Non-200: plain Auth message, no summary.
    let server = HttpFakeServer::start(Arc::new(|_: &http_fake::HttpRequest| {
        HttpReply::text(401, "text/plain", "no")
    }) as HttpHandlerFn)
    .await;
    let err = fetch_session_info_base(&client(), "c", &server.base_url())
        .await
        .unwrap_err();
    assert_eq!(
        auth_message(&err),
        Some("api/session -> 401 (cookies expired? re-export)")
    );
    server.stop();

    // Non-JSON: Auth with the allowlist summary text.
    let server = HttpFakeServer::start(Arc::new(|_: &http_fake::HttpRequest| {
        HttpReply::text(200, "text/html", "not json")
    }) as HttpHandlerFn)
    .await;
    let err = fetch_session_info_base(&client(), "c", &server.base_url())
        .await
        .unwrap_err();
    let m = auth_message(&err).unwrap();
    assert!(
        m.starts_with("api/session returned non-JSON; body_length=8"),
        "{m}"
    );
    assert!(m.contains("content_type=text/html"), "{m}");
    server.stop();

    // Missing vm_id: Gateway(-1) with the vm_unavailable marker.
    let server = HttpFakeServer::start(Arc::new(|_: &http_fake::HttpRequest| {
        HttpReply::text(200, "application/json", r#"{"status": "unavailable"}"#)
    }) as HttpHandlerFn)
    .await;
    let err = fetch_session_info_base(&client(), "c", &server.base_url())
        .await
        .unwrap_err();
    let b = gateway_summary(&err).unwrap();
    assert_eq!(b.status, -1);
    assert_eq!(b.error_code.as_deref(), Some("vm_unavailable"));
    server.stop();

    // Non-object JSON: same Gateway(-1) marker case.
    let server = HttpFakeServer::start(Arc::new(|_: &http_fake::HttpRequest| {
        HttpReply::text(200, "application/json", "[1, 2]")
    }) as HttpHandlerFn)
    .await;
    let err = fetch_session_info_base(&client(), "c", &server.base_url())
        .await
        .unwrap_err();
    assert_eq!(
        gateway_summary(&err).unwrap().error_code.as_deref(),
        Some("vm_unavailable")
    );
    server.stop();

    // Null vm_id: same Gateway(-1) marker case.
    let server = HttpFakeServer::start(Arc::new(|_: &http_fake::HttpRequest| {
        HttpReply::text(200, "application/json", r#"{"vm_id": null}"#)
    }) as HttpHandlerFn)
    .await;
    let err = fetch_session_info_base(&client(), "c", &server.base_url())
        .await
        .unwrap_err();
    assert_eq!(
        gateway_summary(&err).unwrap().error_code.as_deref(),
        Some("vm_unavailable")
    );
    server.stop();

    // Over-4-MiB body: truncated, then the decode fails and
    // the summary reports the TRUNCATED length.
    let server = HttpFakeServer::start(Arc::new(|_: &http_fake::HttpRequest| HttpReply {
        status: 200,
        content_type: "text/plain".to_string(),
        body: vec![b'x'; 5 * 1024 * 1024],
    }) as HttpHandlerFn)
    .await;
    let err = fetch_session_info_base(&client(), "c", &server.base_url())
        .await
        .unwrap_err();
    let m = auth_message(&err).unwrap();
    assert!(m.contains("body_length=4194304"), "{m}");
    server.stop();
}

#[tokio::test]
async fn access_token_flow() {
    let server = HttpFakeServer::start(Arc::new(|req: &http_fake::HttpRequest| {
        assert_eq!(req.method, "POST");
        assert_eq!(req.path, "/api/auth/check");
        assert!(req.body.is_empty());
        HttpReply::text(200, "application/json", r#"{"access_token": "AT"}"#)
    }) as HttpHandlerFn)
    .await;
    let tok = fetch_access_token_base(&client(), "c", &server.base_url())
        .await
        .unwrap();
    assert_eq!(tok, "AT");
    server.stop();

    let server =
        HttpFakeServer::start(
            Arc::new(|_: &http_fake::HttpRequest| HttpReply::text(403, "", "")) as HttpHandlerFn,
        )
        .await;
    let err = fetch_access_token_base(&client(), "c", &server.base_url())
        .await
        .unwrap_err();
    let m = auth_message(&err).unwrap();
    assert!(
        m.starts_with("auth/check -> 403 (cookies expired? re-export)"),
        "{m}"
    );
    server.stop();

    let server = HttpFakeServer::start(Arc::new(|_: &http_fake::HttpRequest| {
        HttpReply::text(200, "", "junk")
    }) as HttpHandlerFn)
    .await;
    let err = fetch_access_token_base(&client(), "c", &server.base_url())
        .await
        .unwrap_err();
    assert_eq!(
        auth_message(&err),
        Some("auth/check returned non-JSON or missing access_token")
    );
    server.stop();

    let server = HttpFakeServer::start(Arc::new(|_: &http_fake::HttpRequest| {
        HttpReply::text(200, "application/json", "{}")
    }) as HttpHandlerFn)
    .await;
    let err = fetch_access_token_base(&client(), "c", &server.base_url())
        .await
        .unwrap_err();
    assert_eq!(
        auth_message(&err),
        Some("auth/check response missing access_token")
    );
    server.stop();
}

#[tokio::test]
async fn hatch_token_flow() {
    let server = HttpFakeServer::start(Arc::new(|req: &http_fake::HttpRequest| {
        assert_eq!(req.method, "POST");
        assert_eq!(req.path, "/api/hatch/token");
        assert_eq!(req.header("Authorization").unwrap(), "Bearer AT");
        assert_eq!(
            std::str::from_utf8(&req.body).unwrap(),
            r#"{"vmAddress":"wss://vm-9.metaaivm.com/","vmName":"vm-9"}"#
        );
        HttpReply::text(200, "application/json", r#"{"token": "HT"}"#)
    }) as HttpHandlerFn)
    .await;
    let tok = fetch_hatch_token_base(&client(), "c", "AT", "vm-9", &server.base_url())
        .await
        .unwrap();
    assert_eq!(tok, "HT");
    server.stop();

    let server =
        HttpFakeServer::start(
            Arc::new(|_: &http_fake::HttpRequest| HttpReply::text(500, "", "")) as HttpHandlerFn,
        )
        .await;
    let err = fetch_hatch_token_base(&client(), "c", "AT", "vm", &server.base_url())
        .await
        .unwrap_err();
    let m = auth_message(&err).unwrap();
    assert!(m.starts_with("hatch/token -> 500"), "{m}");
    server.stop();

    let server = HttpFakeServer::start(Arc::new(|_: &http_fake::HttpRequest| {
        HttpReply::text(200, "application/json", "{}")
    }) as HttpHandlerFn)
    .await;
    let err = fetch_hatch_token_base(&client(), "c", "AT", "vm", &server.base_url())
        .await
        .unwrap_err();
    assert_eq!(
        auth_message(&err),
        Some("hatch/token response missing token")
    );
    server.stop();
}
