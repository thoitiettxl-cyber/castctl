// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Integration tests for the subscription server action
//! (M4b): real HTTP/1.1 against the plain-HTTP fake server
//! in `tests/http_fake` — only the handler's replies are
//! fake. Cases port Go `TestFetchSubscription` +
//! `TestFindActionIDMaxFiles`
//! (`invite_subscription_test.go`).

mod http_fake;

use std::sync::{Arc, Mutex};

use castctl_gateway::subscription::{
    ActionIDStore, DEFAULT_SUBSCRIPTION_ACTION_ID, SUBSCRIPTION_ACTION_NAME, SubscriptionOptions,
    fetch_subscription, find_action_id,
};
use castctl_transport::{DirectDialer, HttpClient, TransportError};
use http_fake::{HttpFakeServer, HttpHandlerFn, HttpReply, HttpRequest};

fn client() -> HttpClient {
    HttpClient::new(Arc::new(DirectDialer::new()))
}

fn rsc_body(result: &str) -> String {
    format!("0:{{\"a\":\"$@1\"}}\n1:{result}\n")
}

struct MemStore {
    id: Mutex<String>,
}

impl MemStore {
    fn new() -> Self {
        MemStore {
            id: Mutex::new(String::new()),
        }
    }
}

impl ActionIDStore for MemStore {
    fn get_action_id(&self) -> String {
        self.id.lock().unwrap().clone()
    }

    fn set_action_id(&self, id: &str) -> Result<(), String> {
        *self.id.lock().unwrap() = id.to_string();
        Ok(())
    }
}

const SUB_JSON: &str =
    r#"{"success":true,"subscription":{"tier":{"name":"Pro"},"usage":{"state":"ok"}}}"#;

#[tokio::test]
async fn configured_id_wins() {
    let server = HttpFakeServer::start(Arc::new(|req: &HttpRequest| {
        assert_eq!(req.method, "POST");
        assert_eq!(req.path, "/settings");
        assert_eq!(req.header("Next-Action").unwrap(), "configuredid1234567890");
        assert_eq!(req.header("Accept").unwrap(), "text/x-component");
        assert_eq!(
            req.header("Content-Type").unwrap(),
            "text/plain;charset=UTF-8"
        );
        assert_eq!(
            std::str::from_utf8(&req.body).unwrap(),
            r#"[{"includeAgreement":false}]"#
        );
        HttpReply::text(200, "text/x-component; charset=utf-8", &rsc_body(SUB_JSON))
    }) as HttpHandlerFn)
    .await;
    let page = format!("{}/settings", server.base_url());
    let (sub, aid) = fetch_subscription(
        &client(),
        "c",
        SubscriptionOptions {
            action_id: "configuredid1234567890".to_string(),
            page,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(aid, "configuredid1234567890");
    assert_eq!(sub["tier"]["name"], serde_json::json!("Pro"));
    server.stop();
}

#[tokio::test]
async fn stale_id_falls_through_to_default_then_scan_and_caches() {
    let store = Arc::new(MemStore::new());
    let scanned = "abcdef1234567890abcdef";
    let server = HttpFakeServer::start(Arc::new(move |req: &HttpRequest| {
        if req.method == "GET" && req.path == "/settings" {
            return HttpReply::text(
                200,
                "text/html",
                r#"<script src="/_next/static/chunks/abc.js"></script>"#,
            );
        }
        if req.method == "POST" {
            if req.header("Next-Action").unwrap_or("") == scanned {
                return HttpReply::text(200, "text/x-component", &rsc_body(SUB_JSON));
            }
            // Stale: 200 without x-component.
            return HttpReply::text(200, "text/html", "<html></html>");
        }
        // Chunk fetch (any other path): the scan pattern.
        HttpReply::text(
            200,
            "application/javascript",
            "createServerReference)(\"abcdef1234567890abcdef\",{},\"fetchSubscriptionAction\")",
        )
    }) as HttpHandlerFn)
    .await;
    let page = format!("{}/settings", server.base_url());
    let store2 = Arc::clone(&store);
    let (_sub, aid) = fetch_subscription(
        &client(),
        "c",
        SubscriptionOptions {
            store: Some(store2),
            page,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(aid, scanned);
    assert_eq!(store.get_action_id(), scanned);
    // The default id was tried first (one stale POST), then
    // the scan found the fresh id.
    let posts = server
        .requests
        .lock()
        .unwrap()
        .iter()
        .filter(|r| r.method == "POST")
        .count();
    assert_eq!(posts, 2);
    server.stop();
}

#[tokio::test]
async fn subscription_error_mapping() {
    // 401 is AuthError.
    let server = HttpFakeServer::start(
        Arc::new(|_: &HttpRequest| HttpReply::text(401, "", "")) as HttpHandlerFn
    )
    .await;
    let page = format!("{}/settings", server.base_url());
    let err = fetch_subscription(
        &client(),
        "c",
        SubscriptionOptions {
            action_id: "x12345678901234567890".to_string(),
            page,
            ..Default::default()
        },
    )
    .await
    .unwrap_err();
    assert!(matches!(err, TransportError::Auth { .. }), "{err:?}");
    server.stop();

    // No id found is GatewayError(-1).
    let server = HttpFakeServer::start(Arc::new(|req: &HttpRequest| {
        if req.method == "GET" {
            return HttpReply::text(200, "text/html", "<html>no chunks</html>");
        }
        HttpReply::text(200, "text/html", "stale")
    }) as HttpHandlerFn)
    .await;
    let page = format!("{}/settings", server.base_url());
    let err = fetch_subscription(
        &client(),
        "c",
        SubscriptionOptions {
            page,
            ..Default::default()
        },
    )
    .await
    .unwrap_err();
    match &err {
        TransportError::Gateway(b) => assert_eq!(b.status, -1),
        other => panic!("want Gateway, got {other:?}"),
    }
    server.stop();

    // Failed result is GatewayError with the parsed error enum
    // (Go asserts Payload contains "error=boom"; the Rust
    // error carries it as the structured error_code).
    let server = HttpFakeServer::start(Arc::new(|_: &HttpRequest| {
        HttpReply::text(
            200,
            "text/x-component",
            &rsc_body(r#"{"success":false,"error":"boom"}"#),
        )
    }) as HttpHandlerFn)
    .await;
    let page = format!("{}/settings", server.base_url());
    let err = fetch_subscription(
        &client(),
        "c",
        SubscriptionOptions {
            action_id: "id12345678901234567890".to_string(),
            page,
            ..Default::default()
        },
    )
    .await
    .unwrap_err();
    match &err {
        TransportError::Gateway(b) => {
            assert_eq!(b.status, -1);
            assert_eq!(b.error_code.as_deref(), Some("boom"));
            assert!(
                b.render().contains("error=boom"),
                "render = {:?}",
                b.render()
            );
        }
        other => panic!("want Gateway, got {other:?}"),
    }
    server.stop();
}

#[tokio::test]
async fn find_action_id_max_files() {
    // Port of Go TestFindActionIDMaxFiles: a chunk graph that
    // keeps discovering new chunks forever — the scan must
    // stop at 3000 fetches and return "".
    let server = HttpFakeServer::start(Arc::new(|req: &HttpRequest| {
        if req.path == "/settings" {
            return HttpReply::text(200, "text/html", "/_next/static/chunks/c0.js");
        }
        let idx: usize = req
            .path
            .trim_start_matches("/_next/static/chunks/c")
            .trim_end_matches(".js")
            .parse()
            .unwrap_or(0);
        HttpReply::text(
            200,
            "application/javascript",
            &format!("/_next/static/chunks/c{}.js", idx + 1),
        )
    }) as HttpHandlerFn)
    .await;
    let page = format!("{}/settings", server.base_url());
    let id = find_action_id(&client(), "c", SUBSCRIPTION_ACTION_NAME, &page)
        .await
        .unwrap();
    assert_eq!(id, "");
    let chunks = server
        .requests
        .lock()
        .unwrap()
        .iter()
        .filter(|r| r.path.starts_with("/_next/static/chunks/"))
        .count();
    assert_eq!(chunks, 3000, "chunk fetches must stop at the cap");
    server.stop();
}

#[tokio::test]
async fn find_action_id_transport_error_carries_no_secret() {
    // Rust analogue of Go's F6 redaction test: a transport
    // failure returns a typed error whose text carries no
    // cookie bytes.
    let err = find_action_id(
        &client(),
        "hatch_sess=SECRET-COOKIE",
        SUBSCRIPTION_ACTION_NAME,
        "http://127.0.0.1:1/settings",
    )
    .await
    .unwrap_err();
    assert!(!format!("{err:?}").contains("SECRET-COOKIE"), "{err:?}");
    assert!(!matches!(err, TransportError::Auth { .. }), "{err:?}");
    // The default id is well-formed (42 hex chars).
    assert_eq!(DEFAULT_SUBSCRIPTION_ACTION_ID.len(), 42);
    assert!(
        DEFAULT_SUBSCRIPTION_ACTION_ID
            .chars()
            .all(|c| c.is_ascii_hexdigit())
    );
}
