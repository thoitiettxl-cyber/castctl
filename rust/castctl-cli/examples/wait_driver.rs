// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Rust side of the M7a wait Tier A parity gate
//! (parity-live.md §3): run the Rust wait Runner
//! (`castctl-wait`) against a scripted gateway_server
//! (`serve-wait` mode) and print the CLI result shape +
//! exit code, so the gate can diff it byte-for-byte
//! against the Go wait_driver run with the same script
//! and argv.
//!
//! Unlike the Go driver, this one renders with the
//! PRODUCTION code under test
//! (`castctl_cli::wait::to_wait_result_json` /
//! `print_wait_text`) — no copied renderer to drift.
//! The connection mirrors the real CLI: a `SharedConn`
//! (3-attempt subscribe retry) over a fake connector
//! that dials the scripted server with the literal fake
//! token, history reads through `chat.history`.
//!
//! The canonical Tier A form is compact JSON + a
//! trailing newline on stdout (the CLI's indented form
//! is pinned separately by Tier B raw bytes + the M2
//! `write_json_text` goldens).
//!
//! Usage:
//!   cargo run -p castctl-cli --example wait_driver -- \
//!     --addr 127.0.0.1:PORT [--thread ID]
//!     [--after-seq N] [--timeout SECONDS] [--json]
//!
//! Defaults: --timeout 600 (the Runner clamps <=0 to
//! 600), text mode unless --json. --after-seq is
//! presence-tracked: absent means derive the boundary
//! from history, exactly like the CLI.
//!
//! No heartbeat is started (fixture runs are <=10 s;
//! the 25 s heartbeat never fires) and no approver is
//! configured (no case delivers approvals).

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use castctl_cli::wait::{print_wait_text, to_wait_result_json};
use castctl_config::jsonvalue::encode_ordered_json;
use castctl_gateway::dial::dial_gateway;
use castctl_gateway::gateway::{Body, Gateway, RequestOptions};
use castctl_gateway::shared::{Connector, SharedConn};
use castctl_logging::summarize_err;
use castctl_telegram::BotError;
use castctl_telegram::wait::WaitKind;
use castctl_transport::TransportError;
use castctl_transport::routes::RouteTable;
use castctl_wait::{
    Cancel, Config, HistoryReader, RunError, Runner, WaitResult, subscriber::shared_subscriber,
};
use serde_json::Value as SerdeValue;

/// Fake connector: dial the scripted server once per
/// `connect()` with the literal fake token, exactly as
/// the M4a `parity_client` example does. No real
/// credentials are ever involved.
struct FakeConnector {
    url: String,
    routes: Arc<RouteTable>,
}

impl Connector for FakeConnector {
    fn connect(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<Arc<Gateway>, TransportError>> + Send + '_>> {
        let url = self.url.clone();
        let routes = Arc::clone(&self.routes);
        Box::pin(async move { dial_gateway(&url, routes).await })
    }
}

/// `chat.history` adapter: body `{"limit"}` +
/// `session_id`, result object with `chat_events` +
/// `has_more` — the same shape as the production
/// `HistoryAdapter` in `castctl-cli/src/wait.rs`.
struct DriverHistory {
    shared: Arc<SharedConn>,
    thread: String,
}

impl HistoryReader for DriverHistory {
    fn read_history(
        &self,
        limit: usize,
        cancel: &Cancel,
    ) -> Pin<Box<dyn Future<Output = Result<(Vec<SerdeValue>, bool), TransportError>> + Send + '_>>
    {
        let shared = Arc::clone(&self.shared);
        let thread = self.thread.clone();
        let cancel = cancel.clone();
        Box::pin(async move {
            let mut body = serde_json::Map::new();
            body.insert("limit".to_string(), SerdeValue::Number(limit.into()));
            if !thread.is_empty() {
                body.insert("session_id".to_string(), SerdeValue::String(thread));
            }
            let call = shared.call_json(
                "chat.history",
                RequestOptions {
                    body: Body::Json(SerdeValue::Object(body)),
                    ..Default::default()
                },
            );
            let v = tokio::select! {
                res = call => res?,
                () = cancel.notified() => return Err(TransportError::Cancelled),
            };
            let Some(m) = v.as_object() else {
                return Err(TransportError::Validation {
                    message: format!(
                        "gateway: chat.history result is not an object: {}",
                        go_type_name(&v)
                    ),
                });
            };
            let events = m
                .get("chat_events")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            let has_more = m.get("has_more").and_then(|v| v.as_bool()).unwrap_or(false);
            Ok((events, has_more))
        })
    }
}

/// Go `%T`-style type name for the history error, mirroring
/// the production adapter (small local copy: the example
/// is a separate crate and cannot use `pub(crate)` items).
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

struct Args {
    addr: String,
    thread: String,
    after_seq: i64,
    has_after_seq: bool,
    timeout_secs: i64,
    json: bool,
}

fn parse_args() -> Result<Args, String> {
    let mut args = Args {
        addr: String::new(),
        thread: String::new(),
        after_seq: 0,
        has_after_seq: false,
        timeout_secs: 600,
        json: false,
    };
    let mut it = std::env::args().skip(1).peekable();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--addr" => {
                args.addr = it.next().ok_or("--addr needs a value")?;
            }
            "--thread" => {
                args.thread = it.next().ok_or("--thread needs a value")?;
            }
            "--after-seq" => {
                let v = it.next().ok_or("--after-seq needs a value")?;
                args.after_seq = v.parse().map_err(|_| "--after-seq must be an integer")?;
                args.has_after_seq = true;
            }
            "--timeout" => {
                let v = it.next().ok_or("--timeout needs a value")?;
                args.timeout_secs = v.parse().map_err(|_| "--timeout must be an integer")?;
            }
            "--json" => args.json = true,
            other => return Err(format!("unknown argument {other}")),
        }
    }
    if args.addr.is_empty() {
        return Err("--addr is required".to_string());
    }
    Ok(args)
}

#[tokio::main]
async fn main() {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("wait_driver: {e}");
            std::process::exit(2);
        }
    };

    let routes = match RouteTable::default_routes() {
        Ok(r) => Arc::new(r),
        Err(e) => {
            eprintln!("wait_driver: routes: {e}");
            std::process::exit(1);
        }
    };
    let url = format!(
        "ws://{}/v1/noise?vm_id=vm-test&auth_token=<redacted>",
        args.addr
    );
    let shared = Arc::new(SharedConn::new(Arc::new(FakeConnector { url, routes })));
    if let Err(e) = shared.live().await {
        eprintln!("wait_driver: connect: {e}");
        std::process::exit(1);
    }
    let subscriber = shared_subscriber(Arc::clone(&shared));
    let history = Arc::new(DriverHistory {
        shared: Arc::clone(&shared),
        thread: args.thread.clone(),
    });

    let cfg = Config {
        thread: args.thread.clone(),
        node_id: "wait-driver".to_string(),
        after_seq: args.after_seq,
        has_after_seq: args.has_after_seq,
        timeout: Duration::from_secs(args.timeout_secs.max(0) as u64),
        dial: Some(Arc::new(move |cancel| {
            let sub = Arc::clone(&subscriber);
            Box::pin(async move {
                // The connection is already live (dialled
                // above); the only cancel to honour here
                // is one that fired before the Runner's
                // first subscribe (technical F5: the
                // closure used to ignore it entirely).
                if cancel.is_set() {
                    return Err(TransportError::Cancelled);
                }
                Ok(Some(sub))
            })
        })),
        history: Some(history),
        ..Default::default()
    };
    let mut runner = match Runner::new(cfg) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("wait_driver: Runner::new: {e}");
            std::process::exit(1);
        }
    };
    let cancel = Cancel::new();
    let res = match runner.run(cancel).await {
        Ok(res) => res,
        Err(e) => {
            // Mirror `executeWait` (wait.go): auth
            // propagates as exit 2, context death as 130,
            // anything else as a synthetic timeout 124
            // with the fixed note. The fixture never
            // triggers this path; it exists so a broken
            // fixture fails loudly instead of hanging.
            // (`ApproverFatal` cannot happen here — no
            // approver is configured — but the mapping is
            // kept complete so the driver never panics on
            // a Runner error.)
            match e {
                RunError::Auth(err) => {
                    eprintln!("wait_driver: wait: {}", summarize_err(Some(&err)));
                    std::process::exit(2);
                }
                RunError::Cancelled => std::process::exit(130),
                RunError::ApproverFatal(BotError::Transport(te))
                    if matches!(te, TransportError::Auth { .. }) =>
                {
                    eprintln!("wait_driver: wait: {}", summarize_err(Some(&te)));
                    std::process::exit(2);
                }
                other => {
                    let summary = match &other {
                        RunError::ApproverFatal(fatal) => summarize_err(Some(fatal)),
                        RunError::HistoryRead(te) => summarize_err(Some(te)),
                        _ => "wait failed".to_string(),
                    };
                    eprintln!("wait_driver: wait: unexpected error ({summary}); reporting timeout");
                    // AfterSeq is the REQUESTED one (0 when
                    // absent), not the derived boundary —
                    // `executeWait` has no access to the
                    // Runner's boundary either.
                    WaitResult {
                        kind: WaitKind::Timeout,
                        outcome: "timeout".to_string(),
                        status: String::new(),
                        after_seq: args.after_seq,
                        final_text: String::new(),
                        replies: Vec::new(),
                        final_read_failed: false,
                        note: "wait failed internally; run `castctl wait` again".to_string(),
                        approvals: Vec::new(),
                        needs_input_reason: String::new(),
                        question: String::new(),
                        exit_code: 124,
                        node_id: String::new(),
                        auto_approved: Vec::new(),
                        auto_approve_errors: Vec::new(),
                    }
                }
            }
        }
    };

    if args.json {
        match encode_ordered_json(&to_wait_result_json(&res, false)) {
            Ok(compact) => println!("{compact}"),
            Err(e) => {
                eprintln!("wait_driver: encode: {e}");
                std::process::exit(1);
            }
        }
    } else {
        let (out, err) = print_wait_text(&res);
        print!("{out}");
        eprint!("{err}");
    }
    std::process::exit(res.exit_code);
}
