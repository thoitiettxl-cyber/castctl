// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Headless re-login driver — port of
//! `internal/keeper/relogin.go` (seam) and
//! `internal/keeper/relogin_chromedp.go` (with_chromedp) /
//! `relogin_stub.go` (`!with_chromedp`).
//!
//! BOUNDARY. This driver is the ONE place in castctl that
//! evaluates JavaScript in a browser, and it does so under
//! a strict rule: the evaluated script is a FIXED string
//! that takes the contract's selectors/keywords as data and
//! returns ONLY match counts (how many elements each
//! selector matches) and fixed signal-class strings (which
//! blocker kind hit, and whether by selector or keyword).
//! No page text, HTML, attribute value, screenshot, or
//! cookie value ever crosses from the page into Rust
//! through evaluation; cookies are harvested Storage first
//! (browser-level `Storage.getCookies`, the browser's
//! authoritative store), then target-level
//! (`Network.getCookies` on the login tab, scoped with
//! `EXPORT_URLS` and then unscoped — the unscoped read is
//! harvest-only), then the browser-level Network read.
//! That Storage-first order is harvest-only: it differs
//! from the CDP exporter's target-first order. The driver
//! never exfiltrates, never screenshots, never enables the
//! screencast relay, and never touches a target it did not
//! create.
//!
//! FLOW. Attach to the already-running Chrome first (the
//! entry's browser URL); only when no attachable browser
//! exists, launch headless through the S2 profile-routed
//! inbound (the proxy URL from `InboundBuilder` is the
//! browser's ONLY egress). Match the page against the
//! recorded contract BEFORE entering anything; on any
//! mismatch or blocker signal, stop with a
//! [`ReloginBlocker`] and enter nothing. The contract
//! itself is validated before any browser is launched.
//! Fill and submit exactly the recorded steps — clearing
//! each field before typing, and re-matching the page
//! before the submit click so a blocker appearing mid-fill
//! stops before anything is submitted — then poll for the
//! harvested session cookies. Transient failures retry up
//! to `MaxAttempts` with a fresh tab each time; a blocker
//! returns immediately and is never retried. A failed
//! launch or attempt removes the browser profile dir the
//! launch created (a pre-existing dir is never removed:
//! it may belong to the screencast login path); a
//! successful harvest keeps the dir, which persists by
//! design.
//!
//! [DEVIATION] Go fills fields with chromedp's `Clear` +
//! `SendKeys` and clicks with chromedp's `Click`. This
//! port uses pure CDP domains instead: `DOM.getDocument` /
//! `DOM.querySelector` + `DOM.focus` + `Input.insertText`
//! (clear via select-all + Backspace key events), and
//! click via `DOM.getBoxModel` centre + mouse events. No
//! extra JavaScript beyond Go's fixed scripts is
//! evaluated. The equivalence of the two input paths is
//! [CHƯA KIỂM CHỨNG] on a live login page.
//!
//! K-LIVE-2 note: the harvest's Storage-first order + the
//! empty-read fall-through guard + the per-level
//! `usableSession` gate are ported as written. Whether
//! they close the original Storage-poll bug family is NOT
//! claimed here — that needs the original bug list /
//! PR #33 comparison, which is outside this port.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::cdp::{CdpClient, CdpSession, discover_websocket_url};
use crate::clock::CancelFlag;
use crate::contract::{
    LoginBlockerSignal, LoginContract, SnapshotDecisionError, SnapshotResult,
    default_login_contract, snapshot_decision, validate_contract,
};
use crate::error::{KeeperError, ReloginBlocker, ReloginError};
use crate::export::{EXPORT_URLS, parse_network_cookies};
use crate::jar::{ExportedCookie, from_exported_cookie};
use crate::launch::{
    InboundBuilder, LaunchedChrome, browser_profile_dir, ensure_browser_profile_dir,
    headless_launch_flags, resolve_browser_path,
};
use crate::notify::NoticeKind;

/// Whether this build has a headless re-login driver
/// (Go `ReloginAvailable`: the `chromedp` feature).
pub const fn relogin_available() -> bool {
    crate::cdp::CDP_AVAILABLE
}

/// The driver seam (`relogin.go`): submit `cred` to the
/// provider login form and return the harvested session
/// cookies in export form (the same shape as the CDP
/// exporter: values are SECRET MATERIAL). One `relogin`
/// call is one incident: the tick never calls it twice
/// per tick.
#[async_trait]
pub trait ReloginDriver: Send + Sync {
    /// Run one headless re-login incident.
    async fn relogin(
        &self,
        cred: castctl_config::LoginCredential,
    ) -> Result<Vec<ExportedCookie>, ReloginError>;
}

/// `ReloginDriverFunc` adapts a function to a
/// `ReloginDriver` (tests and the command-layer wiring).
pub struct ReloginDriverFunc<F>(pub F)
where
    F: Fn(
            castctl_config::LoginCredential,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<Vec<ExportedCookie>, ReloginError>> + Send>,
        > + Send
        + Sync;

#[async_trait]
impl<F> ReloginDriver for ReloginDriverFunc<F>
where
    F: Fn(
            castctl_config::LoginCredential,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<Vec<ExportedCookie>, ReloginError>> + Send>,
        > + Send
        + Sync,
{
    async fn relogin(
        &self,
        cred: castctl_config::LoginCredential,
    ) -> Result<Vec<ExportedCookie>, ReloginError> {
        (self.0)(cred).await
    }
}

/// Effective timeouts for one driver, resolved from the
/// keeper entry's `Effective*` methods by the caller (a
/// nil entry means the documented defaults).
#[derive(Debug, Clone, Copy)]
pub struct ReloginTimeouts {
    /// `EffectiveReloginMatchTimeout` (default 30s).
    pub match_timeout: Duration,
    /// `EffectiveReloginCookieTimeout` (default 30s).
    pub cookie_timeout: Duration,
    /// `EffectiveReloginPollInterval` (default 500ms).
    pub poll_interval: Duration,
    /// `EffectiveReloginAttachTimeout` (default 10s).
    pub attach_timeout: Duration,
    /// `EffectiveReloginCancelTimeout` (default 10s).
    pub cancel_timeout: Duration,
    /// `EffectiveObserveSettleTimeout` (default 15s).
    pub observe_settle_timeout: Duration,
    /// `EffectiveObserveInventoryCap` (default 200).
    pub observe_inventory_cap: usize,
}

impl Default for ReloginTimeouts {
    fn default() -> Self {
        Self {
            match_timeout: Duration::from_secs(30),
            cookie_timeout: Duration::from_secs(30),
            poll_interval: Duration::from_millis(500),
            attach_timeout: Duration::from_secs(10),
            cancel_timeout: Duration::from_secs(10),
            observe_settle_timeout: Duration::from_secs(15),
            observe_inventory_cap: 200,
        }
    }
}

/// Options wiring one headless re-login driver
/// (`relogin.go:ReloginOptions`): the attach-first browser
/// URL (`""` when the entry has none), the S2 inbound
/// builder that routes a launched browser through the
/// profile's outbound, the profile, the recorded
/// login-form contract, and the per-incident attempt cap.
pub struct ReloginOptions {
    pub browser_url: String,
    pub base_dir: String,
    pub inbound: Option<Arc<dyn InboundBuilder>>,
    pub profile_name: String,
    pub contract: LoginContract,
    pub max_attempts: i32,
    pub timeouts: ReloginTimeouts,
    pub cancel: CancelFlag,
}

/// One redacted form-control element from a read-only
/// login-page observation: tag, type, name, id, and class
/// list only. No value, placeholder, label text, href, or
/// page text is ever recorded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedElement {
    pub tag: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    #[serde(rename = "type")]
    pub element_type: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub id: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub classes: Vec<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_aria_label: bool,
}

fn is_false(b: &bool) -> bool {
    !*b
}

/// The redacted result of one automated, read-only load of
/// the login page: the final URL (after redirects, query,
/// fragment, and userinfo stripped) and the form-control
/// inventory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginPageObservation {
    pub url: String,
    pub elements: Vec<ObservedElement>,
}

/// Options wiring one read-only login-page observation
/// (`relogin.go:ObserveOptions`).
pub struct ObserveOptions {
    pub browser_url: String,
    pub base_dir: String,
    pub inbound: Option<Arc<dyn InboundBuilder>>,
    pub profile_name: String,
    pub login_url: String,
    pub timeouts: ReloginTimeouts,
    pub cancel: CancelFlag,
}

/// Strip the query string, fragment, and userinfo from an
/// observed URL, keeping scheme/host/path only
/// (`relogin.go:StripObservationURL`). An unparseable URL
/// is dropped outright rather than echoed.
pub fn strip_observation_url(raw: &str) -> String {
    let Ok(mut u) = url::Url::parse(raw) else {
        return String::new();
    };
    if u.scheme().is_empty() || u.host_str().is_none() {
        return String::new();
    }
    let _ = u.set_username("");
    let _ = u.set_password(None);
    u.set_query(None);
    u.set_fragment(None);
    u.to_string()
}

/// The FIXED evaluation script (`relogin_chromedp.go`).
/// It receives the selector list and blocker signals as
/// JSON data (never interpolated page content) and returns
/// match counts, the blocker hits, and the selectors whose
/// evaluation threw in the browser. A selector that cannot
/// be evaluated is recorded in `badSelectors` — never
/// silently counted as 0 — so the driver stops instead of
/// filling or submitting past a selector that may hide a
/// blocker.
pub fn snapshot_script(
    selectors: &[String],
    blockers: &[LoginBlockerSignal],
) -> Result<String, KeeperError> {
    let sel_json = serde_json::to_string(selectors)
        .map_err(|e| KeeperError::Other(format!("cannot encode selectors: {e}")))?;
    #[derive(Serialize)]
    struct BlockerArg {
        selector: String,
        keyword: String,
        kind: String,
    }
    let args: Vec<BlockerArg> = blockers
        .iter()
        .map(|b| BlockerArg {
            selector: b.selector.clone(),
            keyword: b.keyword.clone(),
            kind: b.kind.clone(),
        })
        .collect();
    let blk_json = serde_json::to_string(&args)
        .map_err(|e| KeeperError::Other(format!("cannot encode blockers: {e}")))?;
    Ok(format!(
        r#"(function(selectors, blockers){{
		var counts = {{}};
		var badSelectors = [];
		function noteBad(sel) {{ if (badSelectors.indexOf(sel) === -1) {{ badSelectors.push(sel); }} }}
		for (var i = 0; i < selectors.length; i++) {{
			try {{ counts[selectors[i]] = document.querySelectorAll(selectors[i]).length; }}
			catch (e) {{ counts[selectors[i]] = 0; noteBad(selectors[i]); }}
		}}
		var text = "";
		try {{ text = (document.body ? document.body.innerText : "") || ""; }} catch (e) {{}}
		var lower = text.toLowerCase();
		var hits = {{}};
		for (var j = 0; j < blockers.length; j++) {{
			var b = blockers[j];
			if (b.selector) {{ try {{ if (document.querySelector(b.selector)) {{ if (!hits[b.kind]) {{ hits[b.kind] = "selector"; }} }} }} catch (e) {{ noteBad(b.selector); }} }}
			if (b.keyword && lower.indexOf(b.keyword.toLowerCase()) !== -1) {{ if (!hits[b.kind]) {{ hits[b.kind] = "keyword"; }} }}
		}}
		return {{counts: counts, hits: hits, badSelectors: badSelectors}};
	}})({sel_json}, {blk_json})"#
    ))
}

/// The FIXED inventory script, with the entry's inventory
/// cap interpolated as a decimal: the cap is an int
/// validated at parse time, so formatting it cannot inject
/// script (`relogin_chromedp.go:inventoryScript`).
pub fn inventory_script(cap: usize) -> String {
    format!(
        r#"(function(){{
	var out = [];
	var els = document.querySelectorAll("input, button, select, textarea, form");
	for (var i = 0; i < els.length && out.length < {cap}; i++) {{
		var el = els[i];
		var cls = (el.getAttribute("class") || "").split(/\s+/).filter(function(s){{ return s !== ""; }});
		out.push({{tag: el.tagName.toLowerCase(), type: el.getAttribute("type") || "", name: el.getAttribute("name") || "", id: el.getAttribute("id") || "", classes: cls, has_aria_label: !!el.getAttribute("aria-label")}});
	}}
	return {{url: location.href, elements: out}};
}})()"#
    )
}

/// The two failure classes of a snapshot evaluation:
/// a contract decision (blocker / mismatch / not
/// established) or a transport/evaluation failure
/// (transient: the page may still be loading).
enum SnapshotMatchError {
    Decision(SnapshotDecisionError),
    Eval(String),
}

/// Evaluate the fixed count script on the target and map
/// the result onto the contract through
/// [`snapshot_decision`] (the same decision
/// `match_contract` makes).
async fn snapshot_match(
    session: &CdpSession,
    contract: &LoginContract,
) -> Result<(), SnapshotMatchError> {
    let selectors: Vec<String> = contract.steps.iter().map(|s| s.selector.clone()).collect();
    let script = snapshot_script(&selectors, &contract.blockers)
        .map_err(|e| SnapshotMatchError::Eval(e.to_string()))?;
    let out = session
        .call(
            "Runtime.evaluate",
            serde_json::json!({"expression": script, "returnByValue": true, "awaitPromise": true}),
        )
        .await
        .map_err(|e| SnapshotMatchError::Eval(e.to_string()))?;
    let result = out
        .get("result")
        .and_then(|r| r.get("value"))
        .ok_or_else(|| {
            SnapshotMatchError::Eval("Runtime.evaluate returned no value".to_string())
        })?;
    let res: SnapshotResult = serde_json::from_value(result.clone())
        .map_err(|e| SnapshotMatchError::Eval(format!("cannot decode snapshot: {e}")))?;
    snapshot_decision(contract, &res).map_err(SnapshotMatchError::Decision)
}

/// Whether one read level's cookie set passes the same
/// pre-write gate the tick applies to CDP exports
/// (`relogin_chromedp.go:usableSession`): convert with
/// `from_exported_cookie` and call `validate_exported_set`.
fn usable_session(cookies: &[ExportedCookie], now: chrono::DateTime<chrono::Utc>) -> bool {
    let stored: Vec<crate::jar::StoredCookie> = cookies.iter().map(from_exported_cookie).collect();
    crate::tick::validate_exported_set(&stored, now)
}

/// Whether the harvest holds a non-empty `hatch_sess`.
fn has_hatch_sess(cookies: &[ExportedCookie]) -> bool {
    cookies
        .iter()
        .any(|c| c.name == "hatch_sess" && !c.value.is_empty())
}

/// Build a headless re-login driver. With the `chromedp`
/// feature off, the returned driver always reports
/// [`ReloginError::Unavailable`] (Go stub).
pub fn new_relogin_driver(opts: ReloginOptions) -> Box<dyn ReloginDriver> {
    if crate::cdp::CDP_AVAILABLE {
        Box::new(RealReloginDriver { opts })
    } else {
        Box::new(StubReloginDriver)
    }
}

/// The stub driver (feature off): always unavailable.
pub struct StubReloginDriver;

#[async_trait]
impl ReloginDriver for StubReloginDriver {
    async fn relogin(
        &self,
        _cred: castctl_config::LoginCredential,
    ) -> Result<Vec<ExportedCookie>, ReloginError> {
        Err(ReloginError::Unavailable)
    }
}

/// The real headless driver (feature on).
pub struct RealReloginDriver {
    opts: ReloginOptions,
}

/// One browser context for an attempt: either an attached
/// target in the user's browser (never killed) or a
/// launched headless Chrome (killed on teardown). The
/// `remove_dir` closure removes the profile dir ONLY when
/// this launch created it AND the attempt failed.
struct BrowserContext {
    client: CdpClient,
    session: CdpSession,
    /// The fresh target this context created
    /// (`Target.createTarget`): teardown closes it
    /// (chromedp's default cancel closes the tab; only
    /// the exporter opts out with `WithDetachOnCancel`).
    target_id: String,
    launched: Option<LaunchedChrome>,
    created_dir: Option<String>,
    inbound_cleanup: Option<Box<dyn FnOnce() + Send + Sync>>,
}

impl RealReloginDriver {
    /// Acquire a browser context: attach-first when a
    /// browser URL is configured, headless launch through
    /// the S2 inbound otherwise. An attach failure falls
    /// back to launch; a launch failure is returned.
    async fn browser_context(&self) -> Result<BrowserContext, ReloginError> {
        if !self.opts.browser_url.is_empty() {
            match self
                .attach_target_context(&self.opts.browser_url, self.opts.timeouts.attach_timeout)
                .await
            {
                Ok(ctx) => return Ok(ctx),
                Err(attach_err) => {
                    if self.opts.inbound.is_none() {
                        return Err(attach_err);
                    }
                    // Attach failed: fall through to launch.
                }
            }
        }
        self.launch_headless_context().await
    }

    /// Attach to a running browser and return a fresh
    /// target in it. The attach is proven by navigating
    /// the fresh target to `about:blank`: a dead debug
    /// port must fall back to launch, not fail the attempt
    /// mid-form.
    async fn attach_target_context(
        &self,
        browser_url: &str,
        _dial_timeout: Duration,
    ) -> Result<BrowserContext, ReloginError> {
        let ws_url = discover_websocket_url(browser_url)
            .await
            .map_err(|e| ReloginError::Other(e.to_string()))?;
        let client = CdpClient::connect(&ws_url)
            .await
            .map_err(|e| ReloginError::Other(e.to_string()))?;
        let target = client
            .call(
                "Target.createTarget",
                serde_json::json!({"url": "about:blank"}),
            )
            .await
            .map_err(|e| ReloginError::Other(e.to_string()))?;
        let target_id = target
            .get("targetId")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ReloginError::Other("createTarget returned no targetId".to_string()))?
            .to_string();
        let session = client
            .attach(&target_id)
            .await
            .map_err(|e| ReloginError::Other(e.to_string()))?;
        session
            .bootstrap()
            .await
            .map_err(|e| ReloginError::Other(e.to_string()))?;
        // Prove the attach works before the caller
        // navigates.
        session
            .call("Page.navigate", serde_json::json!({"url": "about:blank"}))
            .await
            .map_err(|e| ReloginError::Other(e.to_string()))?;
        Ok(BrowserContext {
            client,
            session,
            target_id,
            launched: None,
            created_dir: None,
            inbound_cleanup: None,
        })
    }

    /// Launch a headless Chrome whose ONLY egress is the S2
    /// profile-routed inbound. The browser is killed when
    /// the context is torn down; the per-profile user-data
    /// dir persists (see `browser_context`'s remove-dir
    /// rule).
    async fn launch_headless_context(&self) -> Result<BrowserContext, ReloginError> {
        let Some(inbound) = &self.opts.inbound else {
            return Err(ReloginError::Unavailable);
        };
        if self.opts.profile_name.is_empty() {
            return Err(ReloginError::Other("re-login: no profile".to_string()));
        }
        // Fail fast on a missing Chrome binary, BEFORE
        // creating the profile dir or starting the proxy.
        let browser_path = resolve_browser_path("");
        if !browser_path.is_empty() && std::fs::metadata(&browser_path).is_err() {
            return Err(ReloginError::Other(format!(
                "re-login: chrome binary not found at {browser_path}"
            )));
        }
        let (proxy_url, cleanup) = inbound
            .build_inbound(&self.opts.profile_name)
            .await
            .map_err(|e| ReloginError::Other(e.to_string()))?;
        let mut cleanup = Some(cleanup);
        let dir = browser_profile_dir(&self.opts.base_dir, &self.opts.profile_name)
            .map_err(|e| ReloginError::Other(e.to_string()))?;
        let created = std::fs::symlink_metadata(&dir).is_err();
        if let Err(e) = ensure_browser_profile_dir(&dir) {
            if let Some(c) = cleanup.take() {
                c();
            }
            return Err(ReloginError::Other(e.to_string()));
        }
        let flags = headless_launch_flags(&dir, &proxy_url);
        let launched =
            LaunchedChrome::spawn(&browser_path, &dir, &flags, &["about:blank".to_string()])
                .await
                .map_err(|e| {
                    if let Some(c) = cleanup.take() {
                        c();
                    }
                    ReloginError::Other(e.to_string())
                })?;
        // Discover the debug port from the
        // DevToolsActivePort file (Chrome writes it once
        // the debug listener is up); poll briefly (10s
        // total, the attach timeout — R-8).
        let mut ws_url: Option<String> = None;
        for _ in 0..100 {
            if let Ok(port) = crate::launch::debug_port_from_file(&dir) {
                let base = format!("http://127.0.0.1:{port}/");
                if let Ok(url) = discover_websocket_url(&base).await {
                    ws_url = Some(url);
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let Some(ws_url) = ws_url else {
            let _ = launched.kill().await;
            if let Some(c) = cleanup.take() {
                c();
            }
            return Err(ReloginError::Other(
                "re-login: launched browser did not expose a debug port".to_string(),
            ));
        };
        let client = CdpClient::connect(&ws_url)
            .await
            .map_err(|e| ReloginError::Other(e.to_string()))?;
        let target = client
            .call(
                "Target.createTarget",
                serde_json::json!({"url": "about:blank"}),
            )
            .await
            .map_err(|e| ReloginError::Other(e.to_string()))?;
        let target_id = target
            .get("targetId")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ReloginError::Other("createTarget returned no targetId".to_string()))?
            .to_string();
        let session = client
            .attach(&target_id)
            .await
            .map_err(|e| ReloginError::Other(e.to_string()))?;
        session
            .bootstrap()
            .await
            .map_err(|e| ReloginError::Other(e.to_string()))?;
        Ok(BrowserContext {
            client,
            session,
            target_id,
            launched: Some(launched),
            created_dir: if created { Some(dir) } else { None },
            inbound_cleanup: cleanup,
        })
    }

    /// Tear a browser context down: close the target (and
    /// kill a launched browser), run the inbound cleanup,
    /// and — only when `remove_dir` is set — remove the
    /// launch-created profile dir (best effort, one settle
    /// retry).
    async fn teardown(&self, mut ctx: BrowserContext, failed: bool) {
        let _ = ctx.session.detach().await;
        // Chromedp's default cancel detaches THEN closes
        // the target (`chromedp.go:676-693`, `:269-280`);
        // only the exporter opts out with
        // `WithDetachOnCancel`. Best effort: the browser
        // may already be gone (and on the launch path the
        // kill below destroys the tab anyway). A failed
        // close is logged, not swallowed silently
        // (safety NIT-4, review round 2): a transient
        // failure here leaks a tab with no trace
        // otherwise. Only the target id and the error
        // class are printed — no cookie or page data.
        if let Err(e) = ctx.client.close_target(&ctx.target_id).await {
            eprintln!(
                "keeper: failed to close relogin target {}: {e}",
                ctx.target_id
            );
        }
        if let Some(launched) = ctx.launched.take() {
            let _ = tokio::time::timeout(self.opts.timeouts.cancel_timeout, launched.kill()).await;
        }
        if let Some(cleanup) = ctx.inbound_cleanup.take() {
            cleanup();
        }
        if failed && let Some(dir) = ctx.created_dir.take() {
            let _ = std::fs::remove_dir_all(&dir);
            if std::fs::symlink_metadata(&dir).is_ok() {
                tokio::time::sleep(self.opts.timeouts.poll_interval).await;
                let _ = std::fs::remove_dir_all(&dir);
            }
        }
    }

    /// Poll the count snapshot until the page matches the
    /// contract, a blocker signal appears, or the deadline
    /// passes (mismatch blocker). Only a named blocker
    /// signal stops immediately: a `contract_mismatch` on
    /// an early poll means "the form is not there YET" as
    /// much as "the form is not the recorded one", so it
    /// polls to the deadline like any other transient
    /// state. A snapshot evaluation failure is transient
    /// for the same reason.
    async fn wait_for_match(
        &self,
        session: &CdpSession,
        contract: &LoginContract,
        timeout: Duration,
    ) -> Result<(), ReloginError> {
        let deadline = tokio::time::Instant::now() + timeout;
        let mut last_mismatch: Option<ReloginBlocker> = None;
        let mut last_err: Option<ReloginError> = None;
        loop {
            match snapshot_match(session, contract).await {
                Ok(()) => return Ok(()),
                Err(e) => {
                    // Only a NAMED blocker signal stops
                    // immediately (Go `isBlockerSignal`,
                    // `contract.go:147-170` — the Go set
                    // `blocker_signal|blocker_selector|
                    // blocker_keyword|contract_bad_selector`);
                    // a `contract_mismatch` polls to the
                    // deadline like any transient state.
                    match e {
                        SnapshotMatchError::Decision(SnapshotDecisionError::Blocker(b)) => {
                            if crate::contract::is_blocker_signal(&b) {
                                return Err(ReloginError::Blocker(b));
                            }
                            last_mismatch = Some(b);
                        }
                        SnapshotMatchError::Decision(SnapshotDecisionError::NotEstablished) => {
                            last_err = Some(ReloginError::Other(
                                "login-form contract not established".to_string(),
                            ));
                        }
                        SnapshotMatchError::Eval(msg) => {
                            last_err = Some(ReloginError::Other(msg));
                        }
                    }
                }
            }
            if tokio::time::Instant::now() > deadline {
                if let Some(e) = last_err {
                    return Err(e);
                }
                if let Some(b) = last_mismatch {
                    return Err(ReloginError::Blocker(b));
                }
                return Err(ReloginError::Blocker(ReloginBlocker::new(
                    NoticeKind::Blocked,
                    "contract_mismatch",
                )));
            }
            if self.opts.cancel.is_cancelled() {
                return Err(ReloginError::Other("re-login cancelled".to_string()));
            }
            tokio::time::sleep(self.opts.timeouts.poll_interval).await;
        }
    }

    /// Poll the harvest until a `hatch_sess` cookie is
    /// harvested, a blocker appears, or the deadline
    /// passes (transient: the login may have failed
    /// server-side, which a retry can still recover).
    async fn wait_for_cookies(
        &self,
        ctx: &BrowserContext,
        contract: &LoginContract,
        timeout: Duration,
    ) -> Result<Vec<ExportedCookie>, ReloginError> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            // Blockers first: a captcha/2FA page after
            // submit must stop the attempt, not spin until
            // timeout. A `contract_mismatch` AFTER submit is
            // NOT a blocker: the page navigated away from
            // the form (likely a successful login).
            if let Err(SnapshotMatchError::Decision(SnapshotDecisionError::Blocker(b))) =
                snapshot_match(&ctx.session, contract).await
                && crate::contract::is_blocker_signal(&b)
            {
                return Err(ReloginError::Blocker(b));
            }
            match self.harvest(ctx).await {
                Ok(cookies) if has_hatch_sess(&cookies) => return Ok(cookies),
                Ok(_) | Err(_) => {}
            }
            if tokio::time::Instant::now() > deadline {
                return Err(ReloginError::Other(
                    "re-login: no session cookie harvested after submit".to_string(),
                ));
            }
            if self.opts.cancel.is_cancelled() {
                return Err(ReloginError::Other("re-login cancelled".to_string()));
            }
            tokio::time::sleep(self.opts.timeouts.poll_interval).await;
        }
    }

    /// Harvest the login tab's cookies, Storage first
    /// (`relogin_chromedp.go:harvest`): L1 browser-level
    /// `Storage.getCookies` → L2 target `Network.getCookies`
    /// scoped → L3 target unscoped → L4 browser
    /// `Network.getCookies` scoped. A level's set returns
    /// immediately only when it passes `usable_session`; a
    /// non-empty failing set is remembered as the first
    /// candidate; L4 error → return `first` if any else the
    /// joined error; L4 succeed-empty → `(empty, nil)` =
    /// "no session cookie yet".
    async fn harvest(&self, ctx: &BrowserContext) -> Result<Vec<ExportedCookie>, ReloginError> {
        let now = chrono::Utc::now();
        let mut first: Option<Vec<ExportedCookie>> = None;
        let mut l1_err = String::new();
        let mut l2_err = String::new();
        let mut l3_err = String::new();
        // L1: browser-level Storage.getCookies.
        match ctx
            .client
            .call("Storage.getCookies", Value::Object(Default::default()))
            .await
        {
            Ok(out) => match parse_network_cookies(&out) {
                Ok(cookies) => {
                    if usable_session(&cookies, now) {
                        return Ok(cookies);
                    }
                    if !cookies.is_empty() {
                        first = Some(cookies);
                    } else {
                        l1_err = "cdp read returned no cookies".to_string();
                    }
                }
                Err(e) => l1_err = e.to_string(),
            },
            Err(e) => l1_err = e.to_string(),
        }
        // L2: scoped target-level read.
        match ctx
            .session
            .call(
                "Network.getCookies",
                serde_json::json!({"urls": EXPORT_URLS}),
            )
            .await
        {
            Ok(out) => match parse_network_cookies(&out) {
                Ok(cookies) => {
                    if usable_session(&cookies, now) {
                        return Ok(cookies);
                    }
                    if !cookies.is_empty() && first.is_none() {
                        first = Some(cookies);
                    } else if cookies.is_empty() {
                        l2_err = "cdp read returned no cookies".to_string();
                    }
                }
                Err(e) => l2_err = e.to_string(),
            },
            Err(e) => l2_err = e.to_string(),
        }
        // L3: unscoped target-level read.
        match ctx
            .session
            .call("Network.getCookies", Value::Object(Default::default()))
            .await
        {
            Ok(out) => match parse_network_cookies(&out) {
                Ok(cookies) => {
                    if usable_session(&cookies, now) {
                        return Ok(cookies);
                    }
                    if !cookies.is_empty() && first.is_none() {
                        first = Some(cookies);
                    } else if cookies.is_empty() {
                        l3_err = "cdp read returned no cookies".to_string();
                    }
                }
                Err(e) => l3_err = e.to_string(),
            },
            Err(e) => l3_err = e.to_string(),
        }
        // L4: browser-level Network.getCookies scoped.
        match ctx
            .client
            .call(
                "Network.getCookies",
                serde_json::json!({"urls": EXPORT_URLS}),
            )
            .await
        {
            Ok(out) => match parse_network_cookies(&out) {
                Ok(cookies) => {
                    if usable_session(&cookies, now) {
                        return Ok(cookies);
                    }
                    if !cookies.is_empty() && first.is_none() {
                        first = Some(cookies.clone());
                    }
                    if let Some(f) = first {
                        return Ok(f);
                    }
                    Ok(cookies)
                }
                Err(e) => {
                    if let Some(f) = first {
                        return Ok(f);
                    }
                    Err(ReloginError::Other(format!(
                        "cookie harvest failed: l1: {l1_err}; l2: {l2_err}; l3: {l3_err}; l4: {e}"
                    )))
                }
            },
            Err(e) => {
                if let Some(f) = first {
                    return Ok(f);
                }
                Err(ReloginError::Other(format!(
                    "cookie harvest failed: l1: {l1_err}; l2: {l2_err}; l3: {l3_err}; l4: {e}"
                )))
            }
        }
    }

    /// Fill one field: focus the node, clear it
    /// (select-all + Backspace), then insert the value
    /// ([DEVIATION] pure CDP domains instead of
    /// chromedp's `Clear` + `SendKeys`).
    async fn fill_field(
        &self,
        session: &CdpSession,
        selector: &str,
        value: &str,
    ) -> Result<(), ReloginError> {
        let node_id = dom_query_selector(session, selector).await?;
        session
            .call("DOM.focus", serde_json::json!({"nodeId": node_id}))
            .await
            .map_err(|e| ReloginError::Other(e.to_string()))?;
        // Select all (Ctrl+A) then Backspace.
        for (key, code, key_type) in [
            ("a", "KeyA", "keyDown"),
            ("a", "KeyA", "keyUp"),
            ("Backspace", "Backspace", "keyDown"),
            ("Backspace", "Backspace", "keyUp"),
        ] {
            let modifiers = if key == "a" { 2 } else { 0 };
            session
                .call(
                    "Input.dispatchKeyEvent",
                    serde_json::json!({
                        "type": key_type,
                        "key": key,
                        "code": code,
                        "modifiers": modifiers,
                    }),
                )
                .await
                .map_err(|e| ReloginError::Other(e.to_string()))?;
        }
        session
            .call("Input.insertText", serde_json::json!({"text": value}))
            .await
            .map_err(|e| ReloginError::Other(e.to_string()))?;
        Ok(())
    }

    /// Click a selector's centre ([DEVIATION] `DOM.getBoxModel`
    /// + mouse events instead of chromedp's `Click`).
    async fn click_selector(
        &self,
        session: &CdpSession,
        selector: &str,
    ) -> Result<(), ReloginError> {
        let node_id = dom_query_selector(session, selector).await?;
        let model = session
            .call("DOM.getBoxModel", serde_json::json!({"nodeId": node_id}))
            .await
            .map_err(|e| ReloginError::Other(e.to_string()))?;
        let quad = model
            .get("model")
            .and_then(|m| m.get("content"))
            .and_then(|c| c.as_array())
            .ok_or_else(|| {
                ReloginError::Other("getBoxModel returned no content quad".to_string())
            })?;
        if quad.len() < 8 {
            return Err(ReloginError::Other(
                "getBoxModel content quad is incomplete".to_string(),
            ));
        }
        let xs: Vec<f64> = (0..4)
            .map(|i| quad[2 * i].as_f64().unwrap_or(0.0))
            .collect();
        let ys: Vec<f64> = (0..4)
            .map(|i| quad[2 * i + 1].as_f64().unwrap_or(0.0))
            .collect();
        let x = xs.iter().sum::<f64>() / 4.0;
        let y = ys.iter().sum::<f64>() / 4.0;
        for event_type in ["mousePressed", "mouseReleased"] {
            session
                .call(
                    "Input.dispatchMouseEvent",
                    serde_json::json!({
                        "type": event_type,
                        "x": x,
                        "y": y,
                        "button": "left",
                        "clickCount": 1,
                    }),
                )
                .await
                .map_err(|e| ReloginError::Other(e.to_string()))?;
        }
        Ok(())
    }

    /// One whole login sequence in a fresh tab: navigate,
    /// match, fill, submit, harvest. Returns either
    /// cookies, a blocker, or a transient error — never
    /// more than one of them.
    async fn attempt(
        &self,
        contract: &LoginContract,
        mut cred: castctl_config::LoginCredential,
    ) -> Result<Vec<ExportedCookie>, ReloginError> {
        let ctx = self.browser_context().await?;
        let result = self.attempt_in(&ctx, contract, &mut cred).await;
        // The attempt's credential copy is cleared on
        // return (Go `defer cred.Clear()` in `attempt`).
        cred.clear();
        let failed = result.is_err();
        self.teardown(ctx, failed).await;
        result
    }

    async fn attempt_in(
        &self,
        ctx: &BrowserContext,
        contract: &LoginContract,
        cred: &mut castctl_config::LoginCredential,
    ) -> Result<Vec<ExportedCookie>, ReloginError> {
        ctx.session
            .call(
                "Page.navigate",
                serde_json::json!({"url": contract.login_url}),
            )
            .await
            .map_err(|e| ReloginError::Other(e.to_string()))?;
        self.wait_for_match(&ctx.session, contract, self.opts.timeouts.match_timeout)
            .await?;
        for step in &contract.steps {
            if step.action == "click" {
                // Re-match before the submit click: a
                // blocker appearing mid-fill stops before
                // anything is submitted.
                if let Err(e) = snapshot_match(&ctx.session, contract).await {
                    match e {
                        SnapshotMatchError::Decision(SnapshotDecisionError::Blocker(b)) => {
                            return Err(ReloginError::Blocker(b));
                        }
                        SnapshotMatchError::Decision(SnapshotDecisionError::NotEstablished) => {
                            return Err(ReloginError::Other(
                                "login-form contract not established".to_string(),
                            ));
                        }
                        SnapshotMatchError::Eval(msg) => {
                            return Err(ReloginError::Other(msg));
                        }
                    }
                }
            }
            match step.action.as_str() {
                "fill" => {
                    let value = match step.field.as_str() {
                        "username" => cred.username.clone(),
                        "password" => cred.password.clone(),
                        _ => {
                            return Err(ReloginError::Blocker(ReloginBlocker::new(
                                NoticeKind::Blocked,
                                "contract_unknown_field",
                            )));
                        }
                    };
                    let r = self.fill_field(&ctx.session, &step.selector, &value).await;
                    // The typed value is dropped after each step.
                    drop(value);
                    r?;
                }
                "click" => {
                    self.click_selector(&ctx.session, &step.selector).await?;
                }
                _ => {
                    return Err(ReloginError::Blocker(ReloginBlocker::new(
                        NoticeKind::Blocked,
                        "contract_unknown_action",
                    )));
                }
            }
        }
        self.wait_for_cookies(ctx, contract, self.opts.timeouts.cookie_timeout)
            .await
    }
}

#[async_trait]
impl ReloginDriver for RealReloginDriver {
    async fn relogin(
        &self,
        cred: castctl_config::LoginCredential,
    ) -> Result<Vec<ExportedCookie>, ReloginError> {
        // The driver's copy is cleared on return (best
        // effort: copies already handed to CDP cannot be
        // scrubbed from here — see `LoginCredential::clear`).
        let mut cred = cred;
        let result = self.relogin_inner(&mut cred).await;
        cred.clear();
        result
    }
}

impl RealReloginDriver {
    async fn relogin_inner(
        &self,
        cred: &mut castctl_config::LoginCredential,
    ) -> Result<Vec<ExportedCookie>, ReloginError> {
        let contract = self.opts.contract.clone();
        if !contract.observed {
            return Err(ReloginError::Other(
                "login-form contract not established".to_string(),
            ));
        }
        if contract.steps.is_empty() || contract.login_url.is_empty() {
            return Err(ReloginError::Blocker(ReloginBlocker::new(
                NoticeKind::Blocked,
                "contract_empty",
            )));
        }
        // Validate the whole contract BEFORE the attempt
        // loop: no browser is launched and no credential
        // typed for a contract with an unknown version,
        // action, or field.
        if let Some(blocker) = validate_contract(&contract) {
            return Err(ReloginError::Blocker(blocker));
        }
        let mut attempts = self.opts.max_attempts;
        if attempts < 1 {
            attempts = 1;
        }
        let mut last_err: Option<ReloginError> = None;
        for _ in 0..attempts {
            if self.opts.cancel.is_cancelled() {
                return Err(ReloginError::Other("re-login cancelled".to_string()));
            }
            match self.attempt(&contract, cred.clone()).await {
                Ok(cookies) => return Ok(cookies),
                Err(ReloginError::Blocker(b)) => return Err(ReloginError::Blocker(b)),
                Err(e) => last_err = Some(e),
            }
        }
        Err(last_err.unwrap_or_else(|| {
            ReloginError::Other("re-login: attempts exhausted without cookies".to_string())
        }))
    }
}

/// Resolve a selector to a DOM node id on the target.
async fn dom_query_selector(session: &CdpSession, selector: &str) -> Result<i64, ReloginError> {
    let doc = session
        .call(
            "DOM.getDocument",
            serde_json::json!({"depth": -1, "pierce": true}),
        )
        .await
        .map_err(|e| ReloginError::Other(e.to_string()))?;
    let root = doc
        .get("root")
        .and_then(|r| r.get("nodeId"))
        .and_then(|n| n.as_i64())
        .ok_or_else(|| ReloginError::Other("getDocument returned no root nodeId".to_string()))?;
    let node = session
        .call(
            "DOM.querySelector",
            serde_json::json!({"nodeId": root, "selector": selector}),
        )
        .await
        .map_err(|e| ReloginError::Other(e.to_string()))?;
    node.get("nodeId")
        .and_then(|n| n.as_i64())
        .filter(|n| *n != 0)
        .ok_or_else(|| ReloginError::Other(format!("selector {selector} matched no element")))
}

/// Load the login page headless and return its redacted
/// form-control inventory (`relogin_chromedp.go:
/// ObserveLoginPage`). It attaches to a running browser
/// only when the caller supplies a browser URL; the `auth
/// observe-login` command never does, so observation
/// through the command always launches. No credential is
/// entered, nothing is submitted, and the tab is closed on
/// return. A failed observation removes the browser
/// profile dir the launch created; a successful one keeps
/// it.
pub async fn observe_login_page(opts: ObserveOptions) -> Result<LoginPageObservation, KeeperError> {
    if opts.login_url.is_empty() {
        return Err(KeeperError::Other("observe: no login URL".to_string()));
    }
    if opts.profile_name.is_empty() {
        return Err(KeeperError::Other("observe: no profile".to_string()));
    }
    if !crate::cdp::CDP_AVAILABLE {
        return Err(KeeperError::ReloginUnavailable);
    }
    let driver_opts = ReloginOptions {
        browser_url: opts.browser_url.clone(),
        base_dir: opts.base_dir.clone(),
        inbound: opts.inbound.clone(),
        profile_name: opts.profile_name.clone(),
        contract: default_login_contract()?,
        max_attempts: 1,
        timeouts: opts.timeouts,
        cancel: opts.cancel.clone(),
    };
    let driver = RealReloginDriver { opts: driver_opts };
    let ctx = driver
        .browser_context()
        .await
        .map_err(|e| KeeperError::Other(e.to_string()))?;
    let result = observe_in(&ctx, &opts).await;
    let failed = result.is_err();
    driver.teardown(ctx, failed).await;
    result
}

async fn observe_in(
    ctx: &BrowserContext,
    opts: &ObserveOptions,
) -> Result<LoginPageObservation, KeeperError> {
    ctx.session
        .call("Page.navigate", serde_json::json!({"url": opts.login_url}))
        .await
        .map_err(|e| KeeperError::Other(e.to_string()))?;
    let deadline = tokio::time::Instant::now() + opts.timeouts.observe_settle_timeout;
    loop {
        let script = inventory_script(opts.timeouts.observe_inventory_cap);
        match ctx
            .session
            .call(
                "Runtime.evaluate",
                serde_json::json!({"expression": script, "returnByValue": true, "awaitPromise": true}),
            )
            .await
        {
            Ok(out) => {
                if let Some(value) = out.get("result").and_then(|r| r.get("value")) {
                    let mut obs: LoginPageObservation =
                        serde_json::from_value(value.clone()).map_err(|e| {
                            KeeperError::Other(format!("cannot decode inventory: {e}"))
                        })?;
                    if !obs.elements.is_empty() || tokio::time::Instant::now() > deadline {
                        obs.url = strip_observation_url(&obs.url);
                        return Ok(obs);
                    }
                }
            }
            Err(e) => {
                if tokio::time::Instant::now() > deadline {
                    return Err(KeeperError::Other(e.to_string()));
                }
            }
        }
        if opts.cancel.is_cancelled() {
            return Err(KeeperError::Other("observation cancelled".to_string()));
        }
        tokio::time::sleep(opts.timeouts.poll_interval).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract::LoginBlockerSignal;

    #[test]
    fn snapshot_script_is_fixed_js_with_json_data() {
        let selectors = vec!["form input[aria-label]".to_string()];
        let blockers = vec![LoginBlockerSignal {
            selector: ".captcha".to_string(),
            keyword: "captcha".to_string(),
            kind: "captcha".to_string(),
        }];
        let script = snapshot_script(&selectors, &blockers).unwrap();
        assert!(script.contains("document.querySelectorAll"));
        assert!(script.contains(r#""form input[aria-label]""#));
        assert!(script.contains(r#""captcha""#));
        // No page content is interpolated: the script is a
        // fixed string plus JSON data.
        assert!(!script.contains("innerHTML"));
    }

    #[test]
    fn inventory_script_interpolates_cap_only() {
        let script = inventory_script(200);
        assert!(script.contains("out.length < 200"));
        assert!(script.contains("has_aria_label"));
        assert!(!script.contains("value"));
    }

    #[test]
    fn strip_observation_url_removes_query_fragment_userinfo() {
        assert_eq!(
            strip_observation_url("https://muse.ai/login?code=abc#token=xyz"),
            "https://muse.ai/login"
        );
        assert_eq!(
            strip_observation_url("https://user:pass@muse.ai/login"),
            "https://muse.ai/login"
        );
        assert_eq!(strip_observation_url("not a url"), "");
    }

    #[tokio::test]
    async fn stub_driver_is_unavailable() {
        let driver = StubReloginDriver;
        let cred = castctl_config::LoginCredential {
            username: "u".to_string(),
            password: "p".to_string(),
        };
        assert!(matches!(
            driver.relogin(cred).await,
            Err(ReloginError::Unavailable)
        ));
    }
}
