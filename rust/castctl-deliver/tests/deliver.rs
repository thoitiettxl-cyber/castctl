// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Port of Go `internal/deliver` tests
//! (`session_test.go`, `stop_test.go`, `wake_test.go`,
//! `authlist_test.go`, `authexport_test.go` — 14 test fns).
//! Two Go tests are not portable and are recorded in
//! PORTING.md §M7a, not ported:
//! `TestWakeFuncMatchesGatewayWakeVM` (no Rust
//! `gateway.WakeVM` yet) and the Wake "context
//! cancellation reaches the wake helper" sub-test (no
//! `context.Context` in Rust).

use std::error::Error;
use std::fmt;
use std::sync::{Arc, Mutex};

use castctl_config::jsonvalue::{JsonValue, encode_ordered_json};
use castctl_deliver::{
    AuthList, DeliverError, DeliverGateway, ExportError, ProfileRow, SessionOpKind, auth_export,
    error_is, format_auth_list, list_profiles, session_op, session_start, stop_turn,
    wake::{WAKE_TIMEOUT, WakeDeps, WakeFn, wake},
};
use serde_json::{Value, json};

/// A sentinel error for the wake-failure tests (Go's
/// `errors.New("...")` + `errors.Is`).
#[derive(Debug)]
struct SentinelError(&'static str);

impl fmt::Display for SentinelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

impl Error for SentinelError {}

fn sentinel(msg: &'static str) -> DeliverError {
    // No `Other` variant exists: wrap the sentinel so
    // `error_is` finds it through the source chain and
    // the message stays in the Display text.
    DeliverError::wrap(msg, Box::new(SentinelError(msg)))
}

/// A fake gateway that records the method and body of each
/// `call_json` and returns a canned reply (Go
/// `fakeGateway`, shared by the session and stop tests).
struct FakeGateway {
    calls: Mutex<Vec<(String, JsonValue)>>,
    reply: Value,
    err: Option<DeliverError>,
    called: Mutex<usize>,
}

impl FakeGateway {
    fn new(reply: Value) -> Arc<Self> {
        Arc::new(FakeGateway {
            calls: Mutex::new(Vec::new()),
            reply,
            err: None,
            called: Mutex::new(0),
        })
    }

    fn calls(&self) -> Vec<(String, JsonValue)> {
        self.calls.lock().unwrap().clone()
    }

    fn body_json(&self, i: usize) -> String {
        let calls = self.calls();
        encode_ordered_json(&calls[i].1).unwrap()
    }
}

impl DeliverGateway for FakeGateway {
    fn call_json(
        &self,
        method: &str,
        body: JsonValue,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Value, DeliverError>> + Send + '_>>
    {
        let method = method.to_string();
        Box::pin(async move {
            self.calls.lock().unwrap().push((method, body));
            *self.called.lock().unwrap() += 1;
            if let Some(e) = &self.err {
                return Err(DeliverError::Message(e.to_string()));
            }
            Ok(self.reply.clone())
        })
    }
}

fn gw(gw: &Arc<FakeGateway>) -> Arc<dyn DeliverGateway> {
    Arc::clone(gw) as Arc<dyn DeliverGateway>
}

#[tokio::test]
async fn session_start_cases() {
    // without title
    let fake = FakeGateway::new(json!({"session_id": "s1"}));
    let got = session_start(Some(&gw(&fake)), "").await.unwrap();
    assert_eq!(fake.calls().len(), 1);
    assert_eq!(fake.calls()[0].0, "session.start");
    assert_eq!(
        fake.body_json(0),
        r#"{"method":"/api/session/start","params":{"origin":"fresh","lifecycle":"persistent"}}"#
    );
    assert_eq!(got.get("session_id").and_then(Value::as_str), Some("s1"));
    // with title
    let fake = FakeGateway::new(json!({"session_id": "s2"}));
    session_start(Some(&gw(&fake)), "My chat").await.unwrap();
    assert_eq!(
        fake.body_json(0),
        r#"{"method":"/api/session/start","params":{"origin":"fresh","lifecycle":"persistent","title":"My chat"}}"#
    );
    // nil gateway
    assert!(session_start(None, "").await.is_err());
}

#[tokio::test]
async fn session_op_cases() {
    let cases: Vec<(SessionOpKind, &str, &str, &str)> = vec![
        (
            SessionOpKind::Rename,
            "rename",
            "session.rename",
            r#"{"session_id":"s1","title":"New name"}"#,
        ),
        (
            SessionOpKind::Pin,
            "pin",
            "session.pin",
            r#"{"method":"/api/session/pin","session_id":"s1"}"#,
        ),
        (
            SessionOpKind::Unpin,
            "unpin",
            "session.unpin",
            r#"{"method":"/api/session/unpin","session_id":"s1"}"#,
        ),
        (
            SessionOpKind::Archive,
            "archive",
            "session.archive",
            r#"{"method":"/api/session/archive","session_id":"s1"}"#,
        ),
        (
            SessionOpKind::Unarchive,
            "unarchive",
            "session.unarchive",
            r#"{"method":"/api/session/unarchive","session_id":"s1"}"#,
        ),
        (
            SessionOpKind::Delete,
            "delete",
            "session.delete",
            r#"{"method":"/api/session/delete","session_id":"s1"}"#,
        ),
    ];
    for (kind, name, method, body) in cases {
        let fake = FakeGateway::new(json!({"ok": true}));
        let got = session_op(Some(&gw(&fake)), name, "s1", "New name")
            .await
            .unwrap();
        assert_eq!(fake.calls().len(), 1, "kind {name}");
        assert_eq!(fake.calls()[0].0, method, "kind {name}");
        assert_eq!(fake.body_json(0), body, "kind {name}");
        assert_eq!(got.get("ok").and_then(Value::as_bool), Some(true));
        let _ = kind;
    }
    // unknown kind
    let fake = FakeGateway::new(json!({}));
    assert!(
        session_op(Some(&gw(&fake)), "explode", "s1", "")
            .await
            .is_err()
    );
    assert_eq!(
        *fake.called.lock().unwrap(),
        0,
        "unknown kind must make 0 gateway calls"
    );
    // nil gateway
    assert!(session_op(None, "pin", "s1", "").await.is_err());
}

#[tokio::test]
async fn stop_turn_cases() {
    // main chat
    let fake = FakeGateway::new(json!({"cancelled": true}));
    let got = stop_turn(Some(&gw(&fake)), "").await.unwrap();
    assert_eq!(fake.calls().len(), 1);
    assert_eq!(fake.calls()[0].0, "chat.cancel");
    assert_eq!(fake.body_json(0), "{}");
    assert_eq!(got.get("cancelled").and_then(Value::as_bool), Some(true));
    // side chat
    let fake = FakeGateway::new(json!({"cancelled": true}));
    stop_turn(Some(&gw(&fake)), "thread-1").await.unwrap();
    assert_eq!(fake.body_json(0), r#"{"session_id":"thread-1"}"#);
    // nil gateway
    assert!(stop_turn(None, "").await.is_err());
}

#[test]
fn wake_timeout_value() {
    assert_eq!(WAKE_TIMEOUT, std::time::Duration::from_secs(15));
}

const FAKE_COOKIES: &str = "hatch_sess=FAKE; datr=FAKE";

fn token_ok() -> Box<castctl_deliver::wake::FetchAccessTokenFn> {
    Box::new(move |_client, _cookies| Box::pin(async move { Ok("fake-access-token".to_string()) }))
}

fn wake_ok(
    seen: Arc<Mutex<(Option<String>, Option<String>, Option<String>)>>,
    status: i64,
    body: Value,
) -> Box<WakeFn> {
    Box::new(move |client, cookies, token, vm_id| {
        let seen = Arc::clone(&seen);
        let body = body.clone();
        Box::pin(async move {
            let _ = client;
            *seen.lock().unwrap() = (Some(cookies), Some(token), Some(vm_id));
            Ok((status, body))
        })
    })
}

#[tokio::test]
async fn wake_cases() {
    // profile vm id, fake wake helper
    {
        let seen = Arc::new(Mutex::new((None, None, None)));
        let got = wake(WakeDeps {
            client: Some(Arc::new(castctl_transport::HttpClient::new(Arc::new(
                castctl_transport::DirectDialer::new(),
            )))),
            cookies: FAKE_COOKIES.to_string(),
            vm_id: "fake-vm-1".to_string(),
            fetch_access_token: Some(token_ok()),
            fetch_session_info: Some(Box::new(move |_client, _cookies| {
                Box::pin(
                    async move { panic!("FetchSessionInfo must not be called when VMID is set") },
                )
            })),
            wake_vm: Some(wake_ok(Arc::clone(&seen), 202, json!({"woken": true}))),
        })
        .await
        .unwrap();
        let (cookies, token, vm_id) = seen.lock().unwrap().clone();
        assert_eq!(cookies.as_deref(), Some(FAKE_COOKIES));
        assert_eq!(token.as_deref(), Some("fake-access-token"));
        assert_eq!(vm_id.as_deref(), Some("fake-vm-1"));
        assert_eq!(got.status, 202);
        assert_eq!(got.body.get("woken").and_then(Value::as_bool), Some(true));
    }
    // empty vm id resolves via session info
    {
        let seen_vm = Arc::new(Mutex::new(String::new()));
        let seen_vm2 = Arc::clone(&seen_vm);
        let err = wake(WakeDeps {
            client: Some(Arc::new(castctl_transport::HttpClient::new(Arc::new(
                castctl_transport::DirectDialer::new(),
            )))),
            cookies: FAKE_COOKIES.to_string(),
            vm_id: String::new(),
            fetch_access_token: Some(token_ok()),
            fetch_session_info: Some(Box::new(move |_client, cookies| {
                Box::pin(async move {
                    assert_eq!(cookies, FAKE_COOKIES);
                    Ok(castctl_gateway::SessionInfo {
                        vm_id: "resolved-vm-9".to_string(),
                        raw: Default::default(),
                    })
                })
            })),
            wake_vm: Some(Box::new(move |_c, _co, _t, vm_id| {
                let seen_vm2 = Arc::clone(&seen_vm2);
                Box::pin(async move {
                    *seen_vm2.lock().unwrap() = vm_id;
                    Ok((200, Value::Null))
                })
            })),
        })
        .await;
        assert!(err.is_ok(), "Wake: {err:?}");
        assert_eq!(*seen_vm.lock().unwrap(), "resolved-vm-9");
    }
    // nil client fails before network
    {
        let called = Arc::new(Mutex::new(false));
        let called2 = Arc::clone(&called);
        let err = wake(WakeDeps {
            cookies: FAKE_COOKIES.to_string(),
            wake_vm: Some(Box::new(move |_c, _co, _t, _v| {
                let called2 = Arc::clone(&called2);
                Box::pin(async move {
                    *called2.lock().unwrap() = true;
                    Ok((0, Value::Null))
                })
            })),
            ..Default::default()
        })
        .await
        .unwrap_err();
        assert!(
            !*called.lock().unwrap(),
            "wake helper was called despite a nil client"
        );
        assert!(err.to_string().contains("nil http client"), "err = {err}");
    }
    // missing wake helper fails before network
    {
        let fetch_called = Arc::new(Mutex::new(false));
        let fetch_called2 = Arc::clone(&fetch_called);
        let err = wake(WakeDeps {
            client: Some(Arc::new(castctl_transport::HttpClient::new(Arc::new(
                castctl_transport::DirectDialer::new(),
            )))),
            cookies: FAKE_COOKIES.to_string(),
            fetch_access_token: Some(Box::new(move |_c, _co| {
                let fetch_called2 = Arc::clone(&fetch_called2);
                Box::pin(async move {
                    *fetch_called2.lock().unwrap() = true;
                    Ok(String::new())
                })
            })),
            ..Default::default()
        })
        .await
        .unwrap_err();
        assert!(
            matches!(err, DeliverError::WakeUnavailable),
            "Wake(nil WakeVM): err = {err}, want WakeUnavailable"
        );
        assert!(
            !*fetch_called.lock().unwrap(),
            "token fetch ran despite a missing wake helper"
        );
    }
    // token failure surfaces before session info, empty vm id
    {
        let session_called = Arc::new(Mutex::new(false));
        let session_called2 = Arc::clone(&session_called);
        let err = wake(WakeDeps {
            client: Some(Arc::new(castctl_transport::HttpClient::new(Arc::new(
                castctl_transport::DirectDialer::new(),
            )))),
            cookies: FAKE_COOKIES.to_string(),
            vm_id: String::new(),
            fetch_access_token: Some(Box::new(move |_c, _co| {
                Box::pin(async move { Err(sentinel("fake token failure")) })
            })),
            fetch_session_info: Some(Box::new(move |_c, _co| {
                let session_called2 = Arc::clone(&session_called2);
                Box::pin(async move {
                    *session_called2.lock().unwrap() = true;
                    Err(sentinel("fake session failure"))
                })
            })),
            wake_vm: Some(wake_ok(
                Arc::new(Mutex::new((None, None, None))),
                200,
                Value::Null,
            )),
        })
        .await
        .unwrap_err();
        assert!(
            error_is::<SentinelError>(&err),
            "Wake: err = {err}, want the token error"
        );
        assert!(
            err.to_string().contains("fake token failure"),
            "err = {err}"
        );
        assert!(
            !*session_called.lock().unwrap(),
            "FetchSessionInfo was called despite the token fetch failing"
        );
    }
    // both fetches fail, token error surfaces
    {
        let err = wake(WakeDeps {
            client: Some(Arc::new(castctl_transport::HttpClient::new(Arc::new(
                castctl_transport::DirectDialer::new(),
            )))),
            cookies: FAKE_COOKIES.to_string(),
            vm_id: String::new(),
            fetch_access_token: Some(Box::new(move |_c, _co| {
                Box::pin(async move { Err(sentinel("fake token failure")) })
            })),
            fetch_session_info: Some(Box::new(move |_c, _co| {
                Box::pin(async move { Err(sentinel("fake session failure")) })
            })),
            wake_vm: Some(wake_ok(
                Arc::new(Mutex::new((None, None, None))),
                200,
                Value::Null,
            )),
        })
        .await
        .unwrap_err();
        assert!(err.to_string().contains("fake token failure"));
        assert!(
            !err.to_string().contains("fake session failure"),
            "Wake: err wraps the session error too: {err}"
        );
    }
    // token fetch error is wrapped
    {
        let err = wake(WakeDeps {
            client: Some(Arc::new(castctl_transport::HttpClient::new(Arc::new(
                castctl_transport::DirectDialer::new(),
            )))),
            cookies: FAKE_COOKIES.to_string(),
            vm_id: "fake-vm-1".to_string(),
            fetch_access_token: Some(Box::new(move |_c, _co| {
                Box::pin(async move { Err(sentinel("fake auth failure")) })
            })),
            // vm_id is set, so session info is never fetched.
            fetch_session_info: None,
            wake_vm: Some(wake_ok(
                Arc::new(Mutex::new((None, None, None))),
                200,
                Value::Null,
            )),
        })
        .await
        .unwrap_err();
        assert!(
            error_is::<SentinelError>(&err),
            "Wake: err = {err}, want it to wrap the fetch error"
        );
    }
    // wake helper error is wrapped
    {
        let err = wake(WakeDeps {
            client: Some(Arc::new(castctl_transport::HttpClient::new(Arc::new(
                castctl_transport::DirectDialer::new(),
            )))),
            cookies: FAKE_COOKIES.to_string(),
            vm_id: "fake-vm-1".to_string(),
            fetch_access_token: Some(token_ok()),
            // vm_id is set, so session info is never fetched.
            fetch_session_info: None,
            wake_vm: Some(Box::new(move |_c, _co, _t, _v| {
                Box::pin(async move { Err(sentinel("fake wake failure")) })
            })),
        })
        .await
        .unwrap_err();
        assert!(
            error_is::<SentinelError>(&err),
            "Wake: err = {err}, want it to wrap the helper error"
        );
    }
    // NOTE (not ported): Go's "context cancellation reaches
    // the wake helper" sub-test has no Rust equivalent (no
    // context.Context; cancellation is by dropping the
    // future). See PORTING.md §M7a.
}

fn write_test_file(path: &std::path::Path, content: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, content).unwrap();
}

fn temp_dir(tag: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir =
        std::env::temp_dir().join(format!("castctl-deliver-{tag}-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn list_profiles_cases() {
    let base = temp_dir("list");
    // Default profile: directory exists, non-empty cookies file,
    // single-file entry sets auto_approve always.
    write_test_file(&base.join("cookies.txt"), "hatch_sess=FAKE; datr=FAKE");
    write_test_file(
        &base.join("config.json"),
        r#"{"profiles":{"default":{"auto_approve": "always"}}}"#,
    );
    // Named profile "work": directory exists, empty cookies file.
    write_test_file(&base.join("profiles").join("work").join("cookies.txt"), "");
    // Invalid entries under profiles/ are skipped by discovery:
    // a file (not a directory) and a dot-leading directory.
    write_test_file(&base.join("profiles").join("notadir"), "x");
    std::fs::create_dir_all(base.join("profiles").join(".hidden")).unwrap();

    // Active profile "ghost" has no directory: it is appended last.
    let list = list_profiles(base.to_str().unwrap(), "ghost").unwrap();
    assert_eq!(list.active, "ghost");
    assert_eq!(list.profiles.len(), 3, "profiles = {:?}", list.profiles);
    let want = vec![
        ProfileRow {
            name: "default".to_string(),
            active: false,
            dir: base.to_str().unwrap().to_string(),
            exists: true,
            cookies: true,
            cookies_file: base.join("cookies.txt").to_str().unwrap().to_string(),
            auto_approve: "always".to_string(),
        },
        ProfileRow {
            name: "work".to_string(),
            active: false,
            dir: base
                .join("profiles")
                .join("work")
                .to_str()
                .unwrap()
                .to_string(),
            exists: true,
            cookies: false,
            cookies_file: base
                .join("profiles")
                .join("work")
                .join("cookies.txt")
                .to_str()
                .unwrap()
                .to_string(),
            auto_approve: "off".to_string(),
        },
        ProfileRow {
            name: "ghost".to_string(),
            active: true,
            dir: base
                .join("profiles")
                .join("ghost")
                .to_str()
                .unwrap()
                .to_string(),
            exists: false,
            cookies: false,
            cookies_file: base
                .join("profiles")
                .join("ghost")
                .join("cookies.txt")
                .to_str()
                .unwrap()
                .to_string(),
            auto_approve: "off".to_string(),
        },
    ];
    assert_eq!(list.profiles, want);
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn list_profiles_refuses_legacy_layout() {
    // Whole-list error: one unmigrated legacy file refuses
    // the entire auth list, naming the migration step. No
    // skip-with-warning, no partial rows.
    let base = temp_dir("legacy");
    let legacy_path = base.join("config.json");
    write_test_file(&legacy_path, r#"{"auto_approve": "always"}"#);
    let err = list_profiles(base.to_str().unwrap(), "default").unwrap_err();
    assert!(
        err.to_string().contains("castctl config migrate --write"),
        "ListProfiles error = {err}; want it to name the migration step"
    );
    assert!(
        err.to_string().contains(legacy_path.to_str().unwrap()),
        "ListProfiles error = {err}; want it to name {legacy_path:?}"
    );
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn list_profiles_json_order() {
    let base = temp_dir("json");
    let list = list_profiles(base.to_str().unwrap(), "default").unwrap();
    let raw = serde_json::to_string(&list).unwrap();
    let base_json = serde_json::to_string(&base.to_str().unwrap()).unwrap();
    let cookies_json = serde_json::to_string(&base.join("cookies.txt").to_str().unwrap()).unwrap();
    let want = format!(
        "{{\"active\":\"default\",\"profiles\":[{{\"name\":\"default\",\"active\":true,\"dir\":{base_json},\"exists\":true,\"cookies\":false,\"cookies_file\":{cookies_json},\"auto_approve\":\"off\"}}]}}"
    );
    assert_eq!(raw, want);
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn list_profiles_invalid_active() {
    assert!(list_profiles(temp_dir("bad").to_str().unwrap(), ".bad").is_err());
}

#[test]
fn format_auth_list_cases() {
    let list = AuthList {
        active: "default".to_string(),
        profiles: vec![
            ProfileRow {
                name: "default".to_string(),
                active: true,
                dir: "/cfg".to_string(),
                exists: true,
                cookies: true,
                cookies_file: String::new(),
                auto_approve: String::new(),
            },
            ProfileRow {
                name: "work".to_string(),
                active: false,
                dir: "/cfg/profiles/work".to_string(),
                exists: true,
                cookies: false,
                cookies_file: String::new(),
                auto_approve: String::new(),
            },
            ProfileRow {
                name: "ghost".to_string(),
                active: false,
                dir: "/cfg/profiles/ghost".to_string(),
                exists: false,
                cookies: false,
                cookies_file: String::new(),
                auto_approve: String::new(),
            },
        ],
    };
    // Width is the widest name ("default", 7). State is padded to 11.
    let want = "* default  cookies      /cfg\n  work     no cookies   /cfg/profiles/work\n  ghost    not created  /cfg/profiles/ghost\n";
    assert_eq!(format_auth_list(&list), want);
}

#[test]
fn format_auth_list_empty() {
    assert_eq!(
        format_auth_list(&AuthList {
            active: String::new(),
            profiles: vec![],
        }),
        ""
    );
}

#[test]
fn auth_export_cases() {
    let err = auth_export().unwrap_err();
    assert!(!err.guidance.is_empty());
    assert!(
        err.guidance.contains("https://muse.ai/"),
        "guidance does not mention https://muse.ai/"
    );
    assert!(
        err.guidance.contains("leave the tab open"),
        "guidance does not say to leave the tab open"
    );
    assert!(
        err.guidance.contains("No file was written"),
        "guidance does not state that no file was written"
    );
    assert_eq!(err.exit_code(), 1);
    assert_eq!(err.to_string(), err.guidance);
    // The error type is ExportError itself (Go's
    // errors.As(err, &*ExportError) equivalent).
    let as_export: &ExportError = &err;
    assert_eq!(as_export.exit_code(), 1);
}

#[test]
fn auth_export_writes_nothing() {
    let dir = temp_dir("export");
    let sentinel = dir.join("cookies.txt");
    std::fs::write(&sentinel, b"hatch_sess=FAKE\n").unwrap();
    let before = snapshot_dir(&dir);
    assert!(auth_export().is_err());
    let after = snapshot_dir(&dir);
    assert_eq!(before, after, "files changed by AuthExport");
    let _ = std::fs::remove_dir_all(&dir);
}

fn snapshot_dir(dir: &std::path::Path) -> std::collections::BTreeMap<String, String> {
    let mut out = std::collections::BTreeMap::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(d).unwrap() {
            let e = e.unwrap();
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else {
                let rel = p.strip_prefix(dir).unwrap().to_str().unwrap().to_string();
                out.insert(rel, std::fs::read_to_string(&p).unwrap());
            }
        }
    }
    out
}
