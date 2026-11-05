// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Screencast runners — port of
//! `internal/keeper/screencast.go` (with_chromedp) and
//! `screencast_stub.go` (`!with_chromedp`).
//!
//! Attach model: the runner attaches to the user's
//! already-running Chrome, screencasts ONE Muse page, and
//! detaches. It never closes, kills, activates, or
//! navigates a user tab, never dispatches input except the
//! user's own transport input, and sends no Runtime/JS
//! calls of its own.
//!
//! Bootstrap note (from Go, loop-2 correction): castctl's
//! own code issues no Runtime calls, but the target attach
//! does — the chromedp bootstrap enables Runtime, Log,
//! Network, Inspector, Page, DOM, and CSS on the target,
//! sets `Target.setDiscoverTargets` and
//! `Target.setAutoAttach`, enables
//! `Page.setLifecycleEventsEnabled`, and evaluates the
//! CONSTANT expression `"self"`. Any claim that the attach
//! path "never enables Runtime" is false. This port keeps
//! the same bootstrap via [`CdpSession::bootstrap`].
//!
//! CDP allowlist (§15.2 discipline, as adopted for
//! castctl's OWN calls): Page (enable, screencast, input
//! dispatch via the Input domain), Network/Storage cookie
//! reads (exporter), `Browser.getVersion`. Nothing else is
//! sent by castctl code.
//!
//! The relay side (`wsTransport` / `sessionRegistry`) is
//! M6b; this module ports the runner + the frozen
//! transport boundary only.

use std::sync::Arc;

use crate::cdp::{CdpClient, CdpEvent, TargetInfo, discover_websocket_url, list_targets};
use crate::clock::CancelFlag;
use crate::error::KeeperError;
use crate::export::{Exporter, new_cdp_exporter};
use crate::launch::{
    InboundBuilder, LaunchedChrome, browser_profile_dir, ensure_browser_profile_dir,
    resolve_browser_path, visible_launch_flags,
};
use crate::login::{BrowserVersion, LoginOutcome, RunnerResult, ScreencastRunner};
use crate::transport::{
    Frame, InputEvent, InputKind, SCREENCAST_EVERY_NTH_FRAME, SCREENCAST_JPEG_QUALITY,
    SCREENCAST_MAX_HEIGHT, SCREENCAST_MAX_WIDTH, Transport, validate_input_event,
};

/// The page hosts a login screencast may attach to: the
/// Muse app and its auth subdomain only
/// (`screencast.go:145-147`) — the same set the exporter
/// uses.
pub const SCREENCAST_HOSTS: &[&str] = &["muse.ai", "auth.muse.ai", "www.muse.ai"];

/// Derive the HTTP origin for `/json/list` from a keeper
/// `browser` URL: `http://` stays, `ws://` maps to
/// `http://` on the same host:port
/// (`screencast.go:128-141`).
pub fn http_base_from_browser_url(browser_url: &str) -> Result<String, KeeperError> {
    let raw = browser_url.trim();
    let u =
        url::Url::parse(raw).map_err(|_| KeeperError::Other("invalid browser URL".to_string()))?;
    match u.scheme() {
        "http" | "ws" => {
            let host = u
                .host_str()
                .ok_or_else(|| KeeperError::Other("invalid browser URL".to_string()))?;
            let port = u.port().map(|p| format!(":{p}")).unwrap_or_default();
            Ok(format!("http://{host}{port}"))
        }
        _ => Err(KeeperError::Other(
            "browser URL scheme must be http or ws".to_string(),
        )),
    }
}

/// Pick the ONE Muse page in the attached browser from a
/// typed `/json/list` decode (`screencast.go:158-205`).
/// Zero matches or several matches are errors: the runner
/// never guesses which tab the user means, and never
/// activates one. Titles are never logged (page titles
/// are user content).
pub async fn resolve_screencast_target(http_base: &str) -> Result<String, KeeperError> {
    let targets = list_targets(http_base).await.map_err(KeeperError::from)?;
    let mut matches: Vec<&TargetInfo> = Vec::new();
    for t in &targets {
        if t.target_type != "page" || t.id.is_empty() {
            continue;
        }
        if let Some(host) = url::Url::parse(&t.url)
            .ok()
            .and_then(|u| u.host_str().map(|h| h.to_lowercase()))
            && SCREENCAST_HOSTS.contains(&host.as_str())
        {
            matches.push(t);
        }
    }
    match matches.len() {
        0 => Err(KeeperError::Other(
            "no Muse page is open in the attached browser (open https://muse.ai/ there first)"
                .to_string(),
        )),
        1 => Ok(matches[0].id.clone()),
        n => Err(KeeperError::Other(format!(
            "several Muse pages are open in the attached browser ({n}); close all but one"
        ))),
    }
}

/// Read the browser's own identity for login provenance:
/// Product (e.g. `"Chrome/140.0.0.0"`) and UserAgent as
/// the browser reports them. Nothing is invented
/// (`screencast.go:113-126`).
pub async fn browser_version(ws_url: &str) -> Result<BrowserVersion, KeeperError> {
    let client = CdpClient::connect(ws_url)
        .await
        .map_err(KeeperError::from)?;
    let res = client.version().await.map_err(KeeperError::from)?;
    Ok(BrowserVersion {
        product: res
            .get("product")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        user_agent: res
            .get("userAgent")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
    })
}

/// The attach runner: screencasts a Muse page in the
/// user's browser.
pub struct AttachRunner {
    browser_url: String,
}

/// Build an attach runner for the browser at `browser_url`
/// (a keeper `browser` value).
pub fn new_attach_runner(browser_url: &str) -> AttachRunner {
    AttachRunner {
        browser_url: browser_url.to_string(),
    }
}

#[async_trait::async_trait]
impl ScreencastRunner for AttachRunner {
    async fn run(&self, transport: Arc<dyn Transport>, cancel: CancelFlag) -> RunnerResult {
        if !crate::cdp::CDP_AVAILABLE {
            return RunnerResult::failed(KeeperError::ReexportUnavailable);
        }
        let ws_url = match discover_websocket_url(&self.browser_url).await {
            Ok(u) => u,
            Err(e) => return RunnerResult::failed(KeeperError::from(e)),
        };
        let version = match browser_version(&ws_url).await {
            Ok(v) => v,
            Err(e) => return RunnerResult::failed(e),
        };
        let http_base = match http_base_from_browser_url(&self.browser_url) {
            Ok(b) => b,
            Err(e) => return RunnerResult::failed(e),
        };
        let target_id = match resolve_screencast_target(&http_base).await {
            Ok(t) => t,
            Err(e) => return RunnerResult::failed(e),
        };
        let client = match CdpClient::connect(&ws_url).await {
            Ok(c) => c,
            Err(e) => return RunnerResult::failed(KeeperError::from(e)),
        };
        let session = match client.attach(&target_id).await {
            Ok(s) => s,
            Err(e) => return RunnerResult::failed(KeeperError::from(e)),
        };
        if let Err(e) = session.bootstrap().await {
            return RunnerResult::failed(KeeperError::from(e));
        }
        serve_screencast(&client, &session, transport, version, cancel).await
    }

    fn exporter(&self) -> Result<Box<dyn Exporter>, KeeperError> {
        Ok(new_cdp_exporter(&self.browser_url))
    }
}

/// The launch runner: launches a castctl-owned Chrome for
/// screencast login when no attachable browser exists.
pub struct LaunchRunner {
    base_dir: String,
    profile_name: String,
    browser_path: String,
    inbound: Option<Arc<dyn InboundBuilder>>,
}

/// Build a launch runner. A nil inbound fails every `run`
/// closed before spawning (`launch.go:57-60`).
pub fn new_launch_runner(
    base_dir: &str,
    profile_name: &str,
    browser_path: &str,
    inbound: Option<Arc<dyn InboundBuilder>>,
) -> LaunchRunner {
    LaunchRunner {
        base_dir: base_dir.to_string(),
        profile_name: profile_name.to_string(),
        browser_path: browser_path.to_string(),
        inbound,
    }
}

#[async_trait::async_trait]
impl ScreencastRunner for LaunchRunner {
    async fn run(&self, transport: Arc<dyn Transport>, cancel: CancelFlag) -> RunnerResult {
        if !crate::cdp::CDP_AVAILABLE {
            return RunnerResult::failed(KeeperError::ReexportUnavailable);
        }
        // Fail closed BEFORE spawning: no inbound, no browser.
        let Some(inbound) = &self.inbound else {
            return RunnerResult::failed(KeeperError::LaunchUnavailable);
        };
        let (proxy_url, cleanup) = match inbound.build_inbound(&self.profile_name).await {
            Ok(v) => v,
            Err(e) => return RunnerResult::failed(e),
        };
        let dir = match browser_profile_dir(&self.base_dir, &self.profile_name) {
            Ok(d) => d,
            Err(e) => {
                cleanup();
                return RunnerResult::failed(e);
            }
        };
        if let Err(e) = ensure_browser_profile_dir(&dir) {
            cleanup();
            return RunnerResult::failed(e);
        }
        let flags = visible_launch_flags(&dir, &proxy_url);
        let browser_path = resolve_browser_path(&self.browser_path);
        let launched = match LaunchedChrome::spawn(
            &browser_path,
            &dir,
            &flags,
            &["https://muse.ai/".to_string()],
        )
        .await
        {
            Ok(l) => l,
            Err(e) => {
                cleanup();
                return RunnerResult::failed(e);
            }
        };
        // The launched browser owns its tab: navigating to
        // the login page is the point of the launch model
        // (never done on attach). The spawn above opens
        // https://muse.ai/ directly.
        let ws_url = match wait_for_debug_port(&dir).await {
            Ok(u) => u,
            Err(e) => {
                let _ = launched.kill().await;
                cleanup();
                return RunnerResult::failed(e);
            }
        };
        let client = match CdpClient::connect(&ws_url).await {
            Ok(c) => c,
            Err(e) => {
                let _ = launched.kill().await;
                cleanup();
                return RunnerResult::failed(KeeperError::from(e));
            }
        };
        let version = match browser_version(&ws_url).await {
            Ok(v) => v,
            Err(e) => {
                let _ = launched.kill().await;
                cleanup();
                return RunnerResult::failed(e);
            }
        };
        // Attach to the first page target (the login tab
        // the launch opened).
        let http_base = format!(
            "http://127.0.0.1:{}/",
            crate::launch::debug_port_from_file(&dir).unwrap_or(0)
        );
        let target_id = match first_page_target(&http_base).await {
            Ok(t) => t,
            Err(e) => {
                let _ = launched.kill().await;
                cleanup();
                return RunnerResult::failed(e);
            }
        };
        let session = match client.attach(&target_id).await {
            Ok(s) => s,
            Err(e) => {
                let _ = launched.kill().await;
                cleanup();
                return RunnerResult::failed(KeeperError::from(e));
            }
        };
        if let Err(e) = session.bootstrap().await {
            let _ = launched.kill().await;
            cleanup();
            return RunnerResult::failed(KeeperError::from(e));
        }
        let result = serve_screencast(&client, &session, transport, version, cancel).await;
        // The launch runner owns its browser: cancelling
        // kills the process it started (cleanup order: kill
        // everything started, leave the per-profile dir).
        let _ = launched.kill().await;
        cleanup();
        result
    }

    fn exporter(&self) -> Result<Box<dyn Exporter>, KeeperError> {
        let dir = browser_profile_dir(&self.base_dir, &self.profile_name)?;
        let port = crate::launch::debug_port_from_file(&dir)?;
        // The port-file exporter resolves the debug port
        // from the DevToolsActivePort file, then discovers
        // the WebSocket URL via /json/version like any
        // attach (Go `portFileExporter`).
        Ok(new_cdp_exporter(&format!("http://127.0.0.1:{port}/")))
    }
}

async fn wait_for_debug_port(profile_dir: &str) -> Result<String, KeeperError> {
    for _ in 0..50 {
        if let Ok(port) = crate::launch::debug_port_from_file(profile_dir) {
            let base = format!("http://127.0.0.1:{port}/");
            if let Ok(url) = discover_websocket_url(&base).await {
                return Ok(url);
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    Err(KeeperError::Other(
        "launched browser did not expose a debug port".to_string(),
    ))
}

async fn first_page_target(http_base: &str) -> Result<String, KeeperError> {
    let targets = list_targets(http_base).await.map_err(KeeperError::from)?;
    targets
        .iter()
        .find(|t| t.target_type == "page")
        .map(|t| t.id.clone())
        .ok_or_else(|| KeeperError::Other("no page target is open".to_string()))
}

/// Run the frame/input loop on an attached target until
/// the user sends Done/Cancel, the transport dies, or the
/// session ends (`screencast.go:207-307`). Every received
/// frame is acked immediately after its forward attempt
/// (ack discipline: the browser stalls past
/// `MaxFramesInFlight` without acks). No logging calls
/// exist in this path: frames and keystrokes never reach a
/// log.
pub async fn serve_screencast(
    _client: &CdpClient,
    session: &crate::cdp::CdpSession,
    transport: Arc<dyn Transport>,
    version: BrowserVersion,
    cancel: CancelFlag,
) -> RunnerResult {
    if let Err(e) = session
        .call("Page.enable", serde_json::Value::Object(Default::default()))
        .await
    {
        return RunnerResult {
            outcome: LoginOutcome::Failed,
            version,
            error: Some(KeeperError::Other(format!("page enable failed: {e}"))),
        };
    }
    if let Err(e) = session
        .call(
            "Page.startScreencast",
            serde_json::json!({
                "format": "jpeg",
                "quality": SCREENCAST_JPEG_QUALITY,
                "maxWidth": SCREENCAST_MAX_WIDTH,
                "maxHeight": SCREENCAST_MAX_HEIGHT,
                "everyNthFrame": SCREENCAST_EVERY_NTH_FRAME,
            }),
        )
        .await
    {
        return RunnerResult {
            outcome: LoginOutcome::Failed,
            version,
            error: Some(KeeperError::Other(format!("screencast start failed: {e}"))),
        };
    }
    let stop = async {
        let _ = session
            .call(
                "Page.stopScreencast",
                serde_json::Value::Object(Default::default()),
            )
            .await;
    };
    let mut events = session.events();
    let mut inputs = transport.inputs();
    let done_notify = transport.done();
    let result = loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                break RunnerResult { outcome: LoginOutcome::Cancelled, version: version.clone(), error: None };
            }
            _ = done_notify.notified() => {
                break RunnerResult {
                    outcome: LoginOutcome::Failed,
                    version: version.clone(),
                    error: Some(KeeperError::Other("screencast transport closed".to_string())),
                };
            }
            ev = events.recv() => {
                match ev {
                    Ok(CdpEvent { method, params, .. }) if method == "Page.screencastFrame" => {
                        let data_b64 = params.get("data").and_then(|v| v.as_str()).unwrap_or("");
                        let data = base64_decode(data_b64);
                        let frame_session = params.get("sessionId").and_then(|v| v.as_i64()).unwrap_or(0) as i32;
                        let (width, height) = params.get("metadata")
                            .map(|m| (
                                m.get("deviceWidth").and_then(|v| v.as_i64()).unwrap_or(0) as i32,
                                m.get("deviceHeight").and_then(|v| v.as_i64()).unwrap_or(0) as i32,
                            ))
                            .unwrap_or((0, 0));
                        // Forward attempt first (latest-only:
                        // the transport drops stale frames),
                        // ack always.
                        transport.send_frame(Frame { data, session_id: frame_session, width, height }).await;
                        let _ = session.call(
                            "Page.screencastFrameAck",
                            serde_json::json!({"sessionId": frame_session}),
                        ).await;
                    }
                    Ok(_) => {}
                    Err(_) => {
                        break RunnerResult {
                            outcome: LoginOutcome::Failed,
                            version: version.clone(),
                            error: Some(KeeperError::Other("screencast stream ended".to_string())),
                        };
                    }
                }
            }
            ev = inputs.recv() => {
                match ev {
                    Ok(ev) => {
                        match ev.kind {
                            InputKind::Done => {
                                break RunnerResult { outcome: LoginOutcome::Done, version: version.clone(), error: None };
                            }
                            InputKind::Cancel => {
                                break RunnerResult { outcome: LoginOutcome::Cancelled, version: version.clone(), error: None };
                            }
                            InputKind::Mouse => {
                                dispatch_mouse(session, &ev).await;
                            }
                            InputKind::Key => {
                                dispatch_key(session, &ev).await;
                            }
                            InputKind::Text => {
                                let _ = session.call(
                                    "Input.insertText",
                                    serde_json::json!({"text": ev.text}),
                                ).await;
                            }
                        }
                    }
                    Err(_) => {
                        break RunnerResult {
                            outcome: LoginOutcome::Failed,
                            version: version.clone(),
                            error: Some(KeeperError::Other("screencast transport closed".to_string())),
                        };
                    }
                }
            }
        }
    };
    stop.await;
    result
}

/// Dispatch a mouse event when its type is allowlisted
/// (`screencast.go:309-323`): an empty button becomes
/// `"none"`.
pub async fn dispatch_mouse(session: &crate::cdp::CdpSession, ev: &InputEvent) {
    let Some(ev) = validate_input_event(ev.clone()) else {
        return;
    };
    if ev.kind != InputKind::Mouse {
        return;
    }
    let _ = session
        .call(
            "Input.dispatchMouseEvent",
            serde_json::json!({
                "type": ev.event_type,
                "x": ev.x,
                "y": ev.y,
                "button": ev.button,
                "clickCount": ev.click_count,
                "deltaX": ev.delta_x,
                "deltaY": ev.delta_y,
                "modifiers": ev.modifiers,
            }),
        )
        .await;
}

/// Dispatch a key event when its type is allowlisted and
/// the key is non-empty (`screencast.go:324-336`). Text is
/// forwarded for `"char"` events: without it the browser
/// receives a key with no character.
pub async fn dispatch_key(session: &crate::cdp::CdpSession, ev: &InputEvent) {
    let Some(ev) = validate_input_event(ev.clone()) else {
        return;
    };
    if ev.kind != InputKind::Key {
        return;
    }
    let mut params = serde_json::json!({
        "type": ev.event_type,
        "key": ev.key,
        "code": ev.code,
        "modifiers": ev.modifiers,
    });
    if ev.event_type == "char" {
        params["text"] = serde_json::Value::String(ev.text.clone());
    }
    let _ = session.call("Input.dispatchKeyEvent", params).await;
}

/// Base64 decode (standard alphabet): screencast frames
/// arrive base64-encoded in the CDP event.
fn base64_decode(input: &str) -> Vec<u8> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(input)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_base_from_browser_url_maps_ws_to_http() {
        assert_eq!(
            http_base_from_browser_url("http://127.0.0.1:9226/").unwrap(),
            "http://127.0.0.1:9226"
        );
        assert_eq!(
            http_base_from_browser_url("ws://127.0.0.1:9226/devtools/browser/abc").unwrap(),
            "http://127.0.0.1:9226"
        );
        assert!(http_base_from_browser_url("wss://127.0.0.1:9226").is_err());
        assert!(http_base_from_browser_url("ftp://127.0.0.1:21").is_err());
    }

    #[test]
    fn base64_decode_known_vector() {
        assert_eq!(base64_decode("aGVsbG8="), b"hello");
        assert_eq!(base64_decode(""), b"");
        assert_eq!(base64_decode("/w=="), vec![0xff]);
    }
}
