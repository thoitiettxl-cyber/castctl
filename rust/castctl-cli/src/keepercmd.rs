// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! `keeper run/check/status` (`internal/commands/keeper.go`).
//!
//! The command layer over `castctl-keeper`: `keeperConfig`
//! (resolve + load + keeper block), the `--tag`/`--profile`
//! selection, the per-profile runtime cache + `factory`
//! (checker, CDP exporter, gateway probe + wake, headless
//! re-login driver, Telegram notifier), and the three
//! subcommands.
//!
//! Deviations recorded here (see also the M7d report):
//! - Time fields (`next_check_at`, status times) render
//!   as RFC3339 UTC (`Z` / `+00:00`); Go echoes the
//!   stored local offset (`+07:00`). The instants are
//!   equal; only the representation differs.
//! - The Rust gateway checker bounds each request at 20s
//!   (`AUTH_TIMEOUT`), so a dead outbound fails the tick
//!   at ~20s instead of at the full 90s check timeout.
//!   Exit code and stderr text still match Go.
//! - The tick flattens transport errors into
//!   `KeeperError::Other` message strings, so the check
//!   exit-code mapping classifies by substring (timeout /
//!   gateway markers) instead of by Go's error type.
//! - The re-login driver is built with `inbound: None`:
//!   no `impl InboundBuilder` exists in the keeper crate,
//!   so the launch fallback is unavailable
//!   (`LaunchUnavailable` on that path); attaching to an
//!   already-running Chrome via the entry's browser URL
//!   still works.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use castctl_config::blocks::LoginCredential;
use castctl_config::config::{SingleConfig, load_single_config};
use castctl_config::configlocation::Getenv;
use castctl_config::gostr::go_quote;
use castctl_config::jsonvalue::{JsonValue, OrderedObject, encode_ordered_json};
use castctl_config::keeper::KeeperEntry;
use castctl_config::keeper::format_go_duration;
use castctl_config::profile::{Paths, profile_paths};
use castctl_config::profile_ops::resolve_telegram;
use castctl_gateway::auth::{fetch_access_token, fetch_session_info};
use castctl_gateway::connector::GatewayConnector;
use castctl_gateway::invite::wake_vm;
use castctl_keeper::checker::GatewayChecker;
use castctl_keeper::clock::{CancelFlag, Clock, RealClock};
use castctl_keeper::contract::default_login_contract;
use castctl_keeper::error::KeeperError;
use castctl_keeper::export::new_cdp_exporter;
use castctl_keeper::notify::{NoticeKind, Notifier, notice_text, sanitize_display};
use castctl_keeper::relogin::{ReloginOptions, ReloginTimeouts, new_relogin_driver};
use castctl_keeper::run::{
    OnTick, RunResult, SingleFlight, acquire_single_flight, read_status, run_entry,
};
use castctl_keeper::state::{
    DEFAULT_LOCK_TIMEOUT, OUTCOME_ERROR, OUTCOME_EXPORT_FAILED, OUTCOME_TRANSIENT_ERROR, load_state,
};
use castctl_keeper::tick::{GatewayProbe, TickDeps, TickResult, Wake, notify_stopped, tick};
use castctl_keeper::{Checker, Exporter, ReloginDriver};
use castctl_transport::{BodySummary, DialTarget, HttpClient, TransportError};
use http::Method;
use serde_json::Value as SerdeValue;

use crate::network::write_json_text;
use crate::run::{Ctx, FlowErr, GlobalOpts, config_err, msg, msg_empty, resolve_config};
use crate::runtime::{CookiesFailure, Runtime, build_runtime};

/// One `keeper check` tick bound (`keeper.go`:
/// `keeperCheckTimeout`, a var so tests can shorten it;
/// production default 90s).
const CHECK_TIMEOUT: Duration = Duration::from_secs(90);

/// The Telegram notice bound (`keeper.go`: 30s).
const NOTICE_TIMEOUT: Duration = Duration::from_secs(30);

/// The gateway probe bound (`conn.ConnectTimeout`, 60s).
const PROBE_TIMEOUT: Duration = Duration::from_secs(60);

/// `keeperConfig` (`keeper.go:267`): resolve the config
/// location, load the single config, resolve the keeper
/// block. A missing file or a missing block is exit 2
/// with the keeper's own wording (not the generic
/// config error).
#[derive(Debug)]
pub(crate) struct KeeperSetup {
    pub(crate) loc: castctl_config::configlocation::ConfigLocation,
    pub(crate) single: SingleConfig,
    pub(crate) entries: Vec<KeeperEntry>,
}

pub(crate) fn keeper_config(ctx: &mut Ctx<'_>, g: &GlobalOpts) -> Result<KeeperSetup, FlowErr> {
    let loc = resolve_config(ctx, g, false)?;
    let (single, _found) = load_single_config(&loc.config_dir).map_err(config_err)?;
    let Some(single) = single else {
        return Err(msg(
            2,
            "keeper: no config.json found; add a \"keeper\" block to configure the keeper",
        ));
    };
    let kcfg = single.resolve_keeper().map_err(config_err)?;
    let Some(kcfg) = kcfg else {
        return Err(msg(
            2,
            "keeper: no \"keeper\" block in config.json; the keeper is off",
        ));
    };
    let entries = kcfg.entries.clone();
    Ok(KeeperSetup {
        loc,
        single,
        entries,
    })
}

/// `keeperSelection.apply` (`keeper.go:299`): no
/// selection returns every entry; a selection with no
/// match is exit 2.
pub(crate) fn apply_selection(
    entries: Vec<KeeperEntry>,
    tag: &str,
    profile: &str,
) -> Result<Vec<KeeperEntry>, FlowErr> {
    if tag.is_empty() && profile.is_empty() {
        return Ok(entries);
    }
    let out: Vec<KeeperEntry> = entries
        .into_iter()
        .filter(|e| {
            (!tag.is_empty() && e.tag == tag) || (!profile.is_empty() && e.profile == profile)
        })
        .collect();
    if out.is_empty() {
        return Err(msg(2, "keeper: no entry matches the selection"));
    }
    Ok(out)
}

/// A `KeeperError` through the exit contract: config
/// errors are exit 2 (Go `*profile.Error`), everything
/// else is a plain error, exit 1 with the message.
fn keeper_err(e: KeeperError) -> FlowErr {
    match &e {
        KeeperError::Config(_) => msg(2, e.to_string()),
        _ => msg(1, e.to_string()),
    }
}

/// The check's surfaced-error mapping
/// (`cmdKeeperCheck`: `firstSurfacedErr` returned
/// through `classifyError`). The tick flattens the
/// transport error into a `KeeperError::Other` message
/// string, so the classification is by substring — an
/// approximation of Go's typed classification, recorded
/// in the module header and in `PORTING.md` §M7d.3.
/// The branch ORDER mirrors Go's `classifyError`
/// (`commands.go:301-314`): `GatewayError` → 3 is
/// checked BEFORE `TimeoutError` → 4, so a gateway
/// summary that names a timeout (e.g. `; error=timeout`,
/// always rendered with the `gateway error` marker by
/// `BodySummary::render`) still exits 3. The gateway
/// branch strips the tick's `check failed: ` prefix so
/// the printed text is the gateway summary itself.
fn keeper_check_error(e: &KeeperError) -> FlowErr {
    let text = e.to_string();
    let lower = text.to_ascii_lowercase();
    if lower.contains("gateway error") {
        let inner = text.strip_prefix("check failed: ").unwrap_or(&text);
        return msg(3, inner);
    }
    if lower.contains("timed out")
        || lower.contains("timeout")
        || lower.contains("deadline exceeded")
    {
        // Go `*conn.TimeoutError` renders
        // `timeout: context deadline exceeded`.
        return msg(4, "timeout: context deadline exceeded");
    }
    msg(1, text)
}

/// The gateway probe seam (`wireWake`): the full
/// connector path (auth chain + WebSocket + Noise
/// handshake), closed immediately, no chat. The probe
/// is bounded by `ConnectTimeout` (60s).
struct GatewayProbeImpl {
    rt: Arc<Runtime>,
}

#[async_trait]
impl GatewayProbe for GatewayProbeImpl {
    async fn probe(&self) -> Result<(), TransportError> {
        let connector = GatewayConnector::new(Arc::clone(&self.rt.dialer));
        let outcome = tokio::time::timeout(
            PROBE_TIMEOUT,
            connector.connect(&self.rt.profile.cookies_file, &self.rt.profile.vm_id),
        )
        .await;
        match outcome {
            Ok(Ok(gw)) => {
                gw.close().await;
                Ok(())
            }
            Ok(Err(e)) => Err(e),
            Err(_) => Err(TransportError::Timeout {
                message: "context deadline exceeded".to_string(),
            }),
        }
    }
}

/// The wake seam (`wireWake`): re-fetch the session and
/// token from the cookies file and issue one `WakeVM`
/// request. `vm_id` comes from the profile, else the
/// session info; empty is a gateway error, never auth.
struct WakeImpl {
    rt: Arc<Runtime>,
}

#[async_trait]
impl Wake for WakeImpl {
    async fn wake(&self) -> Result<(), TransportError> {
        let cookies = self.rt.cookies_raw().map_err(|f| match f {
            CookiesFailure::Missing(m) | CookiesFailure::Parse(m) => {
                TransportError::Auth { message: m }
            }
        })?;
        let info = fetch_session_info(&self.rt.http, &cookies).await?;
        let token = fetch_access_token(&self.rt.http, &cookies).await?;
        let mut vm_id = self.rt.profile.vm_id.clone();
        if vm_id.is_empty() {
            vm_id = info.vm_id.clone();
        }
        if vm_id.is_empty() {
            return Err(TransportError::Gateway(BodySummary::new(
                -1,
                Some(b"wake: no vm_id available"),
                "",
            )));
        }
        wake_vm(&self.rt.http, &cookies, &token, &vm_id).await?;
        Ok(())
    }
}

/// The Telegram notifier (`keeper.go`: `telegramNotifier`):
/// fixed-content notices via a raw `sendMessage` POST
/// through the LINKED profile's outbound. The token
/// travels in the request path only and is never logged;
/// failures carry a fixed message plus the HTTP status,
/// never a body. Delivery to the first allowlist id is
/// [NEEDS-MEASUREMENT] (Go's own targeting caveat).
struct TelegramNotifier {
    client: Arc<HttpClient>,
    token: String,
    chat_id: i64,
}

#[async_trait]
impl Notifier for TelegramNotifier {
    async fn notify(
        &self,
        kind: NoticeKind,
        profile_name: &str,
        cancel: &CancelFlag,
    ) -> Result<(), KeeperError> {
        let text = notice_text(kind, profile_name);
        let body = format!("chat_id={}&text={}", self.chat_id, form_urlencode(&text));
        let target = DialTarget::new("api.telegram.org", 443);
        let path = format!("/bot{}/sendMessage", self.token);
        let headers = [(
            "Content-Type".to_string(),
            "application/x-www-form-urlencoded".to_string(),
        )];
        let fut = self.client.request_tls(
            Method::POST,
            &target,
            &path,
            &headers,
            Some(Bytes::from(body)),
            NOTICE_TIMEOUT,
        );
        let resp = tokio::select! {
            r = fut => r,
            _ = cancel.cancelled() => {
                return Err(KeeperError::Other(
                    "telegram notice send failed".to_string(),
                ));
            }
        }
        .map_err(|_| KeeperError::Other("telegram notice send failed".to_string()))?;
        let body = &resp.body[..resp.body.len().min(64 * 1024)];
        let ok = serde_json::from_slice::<SerdeValue>(body)
            .ok()
            .and_then(|v| v.get("ok").and_then(|o| o.as_bool()))
            .unwrap_or(false);
        if !ok {
            return Err(KeeperError::Other(format!(
                "telegram notice send failed: status {}",
                resp.status.as_u16()
            )));
        }
        Ok(())
    }
}

/// A notifier that always errors (`keeper.go`:
/// `errorNotifier`): a broken notifier never fails the
/// tick, it degrades to this, leaving the warn marker
/// pending.
struct ErrorNotifier {
    message: String,
}

#[async_trait]
impl Notifier for ErrorNotifier {
    async fn notify(
        &self,
        _kind: NoticeKind,
        _profile_name: &str,
        _cancel: &CancelFlag,
    ) -> Result<(), KeeperError> {
        Err(KeeperError::Other(self.message.clone()))
    }
}

fn form_urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// The per-profile runtime cache + `factory`
/// (`keeper.go`: `keeperRuntimes`). Runtimes are built
/// lazily per profile and kept for the command's
/// lifetime; the CLI buffers output until exit, so no
/// explicit close is needed (dropping the runtime drops
/// its shared connection).
pub(crate) struct KeeperRuntimes<'a> {
    loc: castctl_config::configlocation::ConfigLocation,
    single: SingleConfig,
    getenv: Getenv<'a>,
    runtimes: HashMap<String, Arc<Runtime>>,
}

/// The two things `wire_relogin` can hand back: the relogin
/// driver (if the entry's browser can be driven) and the
/// credential provider closure.
type ReloginParts = (
    Option<Arc<dyn ReloginDriver>>,
    Option<Arc<dyn Fn() -> Option<LoginCredential> + Send + Sync>>,
);

impl<'a> KeeperRuntimes<'a> {
    pub(crate) fn new(
        loc: castctl_config::configlocation::ConfigLocation,
        single: SingleConfig,
        getenv: Getenv<'a>,
    ) -> Self {
        Self {
            loc,
            single,
            getenv,
            runtimes: HashMap::new(),
        }
    }

    /// `forProfile`: one cached runtime per profile
    /// name; a missing profile is exit 2.
    pub(crate) fn for_profile(&mut self, name: &str) -> Result<Arc<Runtime>, FlowErr> {
        if let Some(rt) = self.runtimes.get(name) {
            return Ok(Arc::clone(rt));
        }
        if !self.single.profiles.contains_key(name) {
            return Err(msg(
                2,
                format!("keeper: profile {} does not exist", go_quote(name)),
            ));
        }
        let rt = build_runtime(&self.loc, Some(&self.single), Some(name), self.getenv)?;
        let rt = Arc::new(rt);
        self.runtimes.insert(name.to_string(), Arc::clone(&rt));
        Ok(rt)
    }

    /// `notifier`: the Telegram notifier for the single
    /// telegram block, through the LINKED profile's
    /// outbound, to the first allowlist id.
    fn notifier(&mut self) -> Result<Arc<dyn Notifier>, FlowErr> {
        let tg = resolve_telegram(&self.single).map_err(config_err)?;
        let Some(tg) = tg else {
            return Err(msg(
                2,
                "keeper: entry notifies \"telegram\" but no \"telegram\" block exists",
            ));
        };
        if tg.allowed_user_ids.is_empty() {
            return Err(msg(
                2,
                "keeper: telegram block has an empty allowed_user_ids allowlist",
            ));
        }
        let profile = tg.profile.clone();
        let token = tg.token.clone();
        let chat_id = tg.allowed_user_ids[0];
        let rt = self.for_profile(&profile)?;
        Ok(Arc::new(TelegramNotifier {
            client: Arc::new(rt.http.clone()),
            token,
            chat_id,
        }))
    }

    /// `factory`: one entry's `TickDeps` — the
    /// per-profile runtime, the cheap-chain checker
    /// through it, the CDP exporter for the entry's
    /// browser URL (only when the entry configures one),
    /// the gateway probe + wake leg, the headless
    /// re-login driver when the entry references
    /// credentials, and the Telegram notifier when
    /// referenced.
    pub(crate) fn factory(
        &mut self,
        entry: &KeeperEntry,
        cancel: &CancelFlag,
    ) -> Result<TickDeps, FlowErr> {
        let rt = self.for_profile(&entry.profile)?;
        let clock: Arc<dyn Clock> = Arc::new(RealClock);
        let checker: Arc<dyn Checker> = Arc::new(GatewayChecker::new(
            Arc::new(rt.http.clone()),
            Arc::clone(&clock),
        ));
        let exporter: Option<Arc<dyn Exporter>> = if entry.browser.is_empty() {
            None
        } else {
            Some(Arc::from(new_cdp_exporter(&entry.browser)))
        };
        let (gateway_probe, wake) = if entry.effective_wake_on_gateway_failure() {
            (
                Some(Arc::new(GatewayProbeImpl {
                    rt: Arc::clone(&rt),
                }) as Arc<dyn GatewayProbe>),
                Some(Arc::new(WakeImpl {
                    rt: Arc::clone(&rt),
                }) as Arc<dyn Wake>),
            )
        } else {
            (None, None)
        };
        let (relogin, credential_provider) = self.wire_relogin(entry, cancel);
        let notifier: Option<Arc<dyn Notifier>> = if entry.notify == "telegram" {
            match self.notifier() {
                Ok(n) => Some(n),
                Err(e) => Some(Arc::new(ErrorNotifier {
                    message: match &e {
                        FlowErr::Msg { message, .. } => message.clone().unwrap_or_default(),
                        FlowErr::Verbatim { text, .. } => text.clone(),
                        _ => String::new(),
                    },
                })),
            }
        } else {
            None
        };
        Ok(TickDeps {
            clock,
            tag: entry.tag.clone(),
            interval: entry.effective_interval(),
            retry_backoff: entry.effective_retry_backoff(),
            wake_on_gateway_failure: entry.effective_wake_on_gateway_failure(),
            wake_attempts: entry.effective_wake_attempts() as usize,
            credentials_configured: !entry.credentials.is_empty(),
            base_dir: self.loc.config_dir.clone(),
            profile_name: entry.profile.clone(),
            checker,
            exporter,
            notifier,
            gateway_probe,
            wake,
            relogin,
            credential_provider,
            jitter: None,
            lock_timeout: DEFAULT_LOCK_TIMEOUT,
            before_state_save: None,
        })
    }

    /// `wireRelogin`: the headless re-login driver and
    /// the narrow credential provider when the entry
    /// references a credentials tag. The provider
    /// RE-READS `config.json` from disk on every
    /// invocation (fail-closed: no credential on any
    /// re-read failure). The driver is built with the
    /// recorded contract; `inbound` is `None` — no
    /// `impl InboundBuilder` exists in the keeper crate,
    /// so the launch fallback is unavailable
    /// (`LaunchUnavailable` on that path; attaching to
    /// an already-running Chrome via the entry's browser
    /// URL still works).
    fn wire_relogin(&self, entry: &KeeperEntry, cancel: &CancelFlag) -> ReloginParts {
        if entry.credentials.is_empty() {
            return (None, None);
        }
        let base_dir = self.loc.config_dir.clone();
        let profile_name = entry.profile.clone();
        let provider: Arc<dyn Fn() -> Option<LoginCredential> + Send + Sync> =
            Arc::new(move || {
                let Ok((fresh, _found)) = load_single_config(&base_dir) else {
                    return None;
                };
                let fresh = fresh?;
                fresh.credential_for_profile(&profile_name)
            });
        let contract = match default_login_contract() {
            Ok(c) => c,
            Err(_) => return (None, Some(provider)),
        };
        let driver = new_relogin_driver(ReloginOptions {
            browser_url: entry.browser.clone(),
            base_dir: self.loc.config_dir.clone(),
            inbound: None,
            profile_name: entry.profile.clone(),
            contract,
            max_attempts: entry.effective_relogin_attempts() as i32,
            timeouts: ReloginTimeouts {
                match_timeout: entry.effective_relogin_match_timeout(),
                cookie_timeout: entry.effective_relogin_cookie_timeout(),
                poll_interval: entry.effective_relogin_poll_interval(),
                attach_timeout: entry.effective_relogin_attach_timeout(),
                cancel_timeout: entry.effective_relogin_cancel_timeout(),
                observe_settle_timeout: entry.effective_observe_settle_timeout(),
                observe_inventory_cap: entry.effective_observe_inventory_cap() as usize,
            },
            cancel: cancel.child(),
        });
        (Some(Arc::from(driver)), Some(provider))
    }
}

/// The `next_check_at` for a check row
/// (`keeper.go`: `nextCheckAt`): read from the state
/// after the tick; a missing/corrupt state omits the
/// field instead of failing the check.
fn next_check_at(base_dir: &str, entry: &KeeperEntry) -> Option<String> {
    let paths: Paths = profile_paths(base_dir, &entry.profile).ok()?;
    let st = load_state(&paths.dir).ok()?;
    st.next_check_at.map(|t| t.to_rfc3339())
}

/// One per-tick summary line (`cmdKeeperRun`): stdout,
/// `keeper: <tag> (<profile>): <outcome>
/// cookies_seen=<n> wrote=<bool>
/// next_delay=<go duration>[ state_corrupt=true]`.
/// Tag/profile are sanitised so a newline in a name
/// can never forge a second line.
pub(crate) fn tick_summary_line(entry: &KeeperEntry, res: &TickResult) -> String {
    let corrupt = if res.state_corrupt {
        " state_corrupt=true"
    } else {
        ""
    };
    format!(
        "keeper: {} ({}): {} cookies_seen={} wrote={} next_delay={}{}\n",
        sanitize_display(&entry.tag),
        sanitize_display(&entry.profile),
        res.outcome,
        res.cookies_seen,
        res.wrote_cookies,
        format_go_duration(res.next_delay.as_nanos() as i64),
        corrupt,
    )
}

/// One synthesised `RunResult` for a factory failure
/// (`keeper.Run`: `Ticks == 0` and `Last.Err` set; the
/// entry never ticked).
fn factory_failed_result(entry: &KeeperEntry, message: String) -> RunResult {
    RunResult {
        tag: entry.tag.clone(),
        stopped: false,
        ticks: 0,
        last: Some(TickResult {
            outcome: "error".to_string(),
            stage: String::new(),
            stopped: false,
            recovered: false,
            wrote_cookies: false,
            dropped: 0,
            cdp_dropped: 0,
            exported: 0,
            cookies_seen: 0,
            skipped: 0,
            next_delay: Duration::ZERO,
            state_corrupt: false,
            error: Some(KeeperError::Other(message)),
        }),
    }
}

/// `cmdKeeperStatus` (`keeper.go:830`): read the state
/// files only, no network. JSON array (never null),
/// exit 0 even when entries are logged out or stopped.
pub(crate) fn run_status(
    ctx: &mut Ctx<'_>,
    g: &GlobalOpts,
    tag: &str,
    profile: &str,
) -> Result<(), FlowErr> {
    let setup = keeper_config(ctx, g)?;
    let entries = apply_selection(setup.entries, tag, profile)?;
    let mut statuses = Vec::new();
    for entry in &entries {
        let st =
            read_status(&setup.loc.config_dir, &entry.tag, &entry.profile).map_err(keeper_err)?;
        statuses.push(st);
    }
    // Struct field order (Go `keeper.Status`), not key
    // order: serialize the structs directly, then
    // re-indent Go-style. `write_json_serde` would sort
    // keys through `serde_json::Value`.
    let compact = serde_json::to_string(&statuses)
        .map_err(|_| msg(1, "failed to serialize keeper status"))?;
    ctx.out.stdout.push_str(&write_json_text(&compact));
    Ok(())
}

/// `cmdKeeperCheck` (`keeper.go:693`): one tick per
/// entry, 90s each, one JSON object per entry. The
/// sync wrapper builds the tokio runtime; the async
/// body below does the work.
pub(crate) fn run_check(
    ctx: &mut Ctx<'_>,
    g: &GlobalOpts,
    tag: &str,
    profile: &str,
) -> Result<(), FlowErr> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| msg(1, format!("failed to start async runtime: {e}")))?;
    rt.block_on(check_entries(ctx, g, tag, profile))
}

/// Spawn the SIGINT watcher shared by `keeper check` and
/// `keeper run`: when the `signal` future resolves, cancel
/// the ROOT flag itself — never a child of it. Go
/// `cmdKeeperRun` / `cmdKeeperCheck`
/// (`internal/commands/keeper.go:650-654`, `:714-723`)
/// return `ctx.Err()` after Run/tick, where `ctx` is the
/// process signal context; cancelling the root is what
/// makes the `root_cancel.cancelled()` arms and the
/// `msg_empty(130)` returns live. Cancelling a child
/// instead left them dead code (`CancelFlag::child`
/// documents that cancelling the child does NOT cancel
/// the parent, `castctl-keeper/src/clock.rs:61-64`), and
/// the installed tokio signal handler replaces the
/// default terminate disposition — so the pre-fix command
/// ignored Ctrl-C entirely. The signal is a parameter so
/// tests can inject a ready/pending future; production
/// passes `tokio::signal::ctrl_c()`.
fn spawn_ctrl_c_watcher(
    cancel: CancelFlag,
    signal: impl std::future::Future<Output = ()> + Send + 'static,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        signal.await;
        cancel.cancel();
    })
}

async fn check_entries(
    ctx: &mut Ctx<'_>,
    g: &GlobalOpts,
    tag: &str,
    profile: &str,
) -> Result<(), FlowErr> {
    let KeeperSetup {
        loc,
        single,
        entries,
    } = keeper_config(ctx, g)?;
    let entries = apply_selection(entries, tag, profile)?;
    let base_dir = loc.config_dir.clone();
    let mut rts = KeeperRuntimes::new(loc, single, ctx.getenv);
    let root_cancel = CancelFlag::new();
    spawn_ctrl_c_watcher(root_cancel.clone(), async {
        let _ = tokio::signal::ctrl_c().await;
    });
    let mut worst = 0i32;
    let mut first_surfaced: Option<KeeperError> = None;
    for entry in &entries {
        let cancel = root_cancel.child();
        let deps = match rts.factory(entry, &cancel) {
            Ok(d) => d,
            Err(e) => return Err(e),
        };
        let tick_cancel = cancel.child();
        let mut tick_fut = Box::pin(tick(&deps, &tick_cancel));
        let (result, timed_out) = tokio::select! {
            r = &mut tick_fut => (r, false),
            _ = tokio::time::sleep(CHECK_TIMEOUT) => {
                cancel.cancel();
                (tick_fut.await, true)
            }
            _ = root_cancel.cancelled() => {
                return Err(msg_empty(130));
            }
        };
        // An interrupted parent context ends the command:
        // never swallow it as a per-entry outcome, and
        // never continue to further entries.
        if root_cancel.is_cancelled() {
            return Err(msg_empty(130));
        }
        if result.stopped {
            notify_stopped(&deps, &root_cancel).await;
        }
        let next_at = next_check_at(&base_dir, entry);
        print_check_row(ctx, entry, &result, next_at)?;
        let mut err = result.error;
        // A tick cancelled by the check timeout surfaces
        // as Go's `TimeoutError`, not as "tick cancelled":
        // the tick was still running when the 90s bound
        // fired, so its error is the deadline, like Go's.
        if timed_out
            && let Some(e) = &err
            && e.to_string() == "tick cancelled"
        {
            err = Some(KeeperError::Other("context deadline exceeded".to_string()));
        }
        let has_err = err.is_some();
        // A hard failure (OutcomeError) is remembered even
        // when the entry also stopped: the typed error
        // must surface after the loop instead of being
        // swallowed into the stopped exit 3.
        if result.outcome == OUTCOME_ERROR && has_err && first_surfaced.is_none() {
            first_surfaced = err.take();
        }
        if timed_out {
            worst = 4;
        } else if result.stopped || result.outcome == OUTCOME_EXPORT_FAILED {
            if worst < 3 {
                worst = 3;
            }
        } else if result.outcome == OUTCOME_TRANSIENT_ERROR || result.outcome == OUTCOME_ERROR {
            if has_err && first_surfaced.is_none() {
                first_surfaced = err.take();
            } else if worst < 1 {
                worst = 1;
            }
        }
    }
    // Interrupt first (already returned above), then the
    // remembered transient/state-dir error, then the
    // worst outcome.
    if let Some(e) = first_surfaced {
        return Err(keeper_check_error(&e));
    }
    match worst {
        4 => Err(msg(4, "keeper check timed out")),
        3 => Err(msg(
            3,
            "keeper check: entry stopped (auth expired) or export failed",
        )),
        1 => Err(msg(1, "keeper check: transient error")),
        _ => Ok(()),
    }
}

/// One check row (`keeperCheckResult`): field order
/// tag, profile, outcome, stopped, cookies_seen,
/// wrote_cookies, next_check_at?, state_corrupt?.
/// `next_check_at` renders as RFC3339 UTC (see the
/// module header: Go echoes the stored offset).
fn print_check_row(
    ctx: &mut Ctx<'_>,
    entry: &KeeperEntry,
    res: &TickResult,
    next_at: Option<String>,
) -> Result<(), FlowErr> {
    let mut o = OrderedObject::new();
    o.set("tag", JsonValue::Str(entry.tag.clone()));
    o.set("profile", JsonValue::Str(entry.profile.clone()));
    o.set("outcome", JsonValue::Str(res.outcome.clone()));
    o.set("stopped", JsonValue::Bool(res.stopped));
    o.set(
        "cookies_seen",
        JsonValue::Number(res.cookies_seen.to_string()),
    );
    o.set("wrote_cookies", JsonValue::Bool(res.wrote_cookies));
    if let Some(t) = next_at {
        o.set("next_check_at", JsonValue::Str(t));
    }
    if res.state_corrupt {
        o.set("state_corrupt", JsonValue::Bool(true));
    }
    let compact = encode_ordered_json(&JsonValue::Object(o)).map_err(config_err)?;
    ctx.out.stdout.push_str(&write_json_text(&compact));
    Ok(())
}

/// `cmdKeeperRun` (`keeper.go:603`): ticks for
/// different entries run concurrently; the summary
/// lines are serialised through one shared buffer
/// (the CLI prints buffered output at exit). The sync
/// wrapper builds the tokio runtime; the async body
/// below does the work.
pub(crate) fn run_keeper(
    ctx: &mut Ctx<'_>,
    g: &GlobalOpts,
    tag: &str,
    profile: &str,
) -> Result<(), FlowErr> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| msg(1, format!("failed to start async runtime: {e}")))?;
    rt.block_on(run_entries_cmd(ctx, g, tag, profile))
}

async fn run_entries_cmd(
    ctx: &mut Ctx<'_>,
    g: &GlobalOpts,
    tag: &str,
    profile: &str,
) -> Result<(), FlowErr> {
    let KeeperSetup {
        loc,
        single,
        entries,
    } = keeper_config(ctx, g)?;
    let entries = apply_selection(entries, tag, profile)?;
    if entries.is_empty() {
        ctx.out.stdout.push_str("keeper: no entries configured\n");
        return Ok(());
    }
    // Single-flight per entry, acquired before ticking.
    // A live owner releases the already-acquired
    // flights and exits 2.
    let mut releases: Vec<SingleFlight> = Vec::new();
    for entry in &entries {
        let paths = profile_paths(&loc.config_dir, &entry.profile).map_err(config_err)?;
        match acquire_single_flight(&paths.dir, &entry.tag, Arc::new(RealClock)).await {
            Ok(f) => releases.push(f),
            Err(e) => {
                for r in releases {
                    r.release();
                }
                return Err(msg(2, e.to_string()));
            }
        }
    }
    let mut rts = KeeperRuntimes::new(loc, single, ctx.getenv);
    let root_cancel = CancelFlag::new();
    spawn_ctrl_c_watcher(root_cancel.clone(), async {
        let _ = tokio::signal::ctrl_c().await;
    });
    let out_buf: Arc<Mutex<String>> = Arc::new(Mutex::new(String::new()));
    let mut handles = Vec::new();
    let mut results: Vec<RunResult> = Vec::new();
    for entry in entries {
        let cancel = root_cancel.child();
        let deps = match rts.factory(&entry, &cancel) {
            Ok(d) => d,
            Err(e) => {
                // A factory failure is not a tick: the
                // entry never ran, and Run records it
                // with Ticks == 0 and Last.Err set.
                let message = match &e {
                    FlowErr::Msg { message, .. } => message.clone().unwrap_or_default(),
                    FlowErr::Verbatim { text, .. } => text.clone(),
                    _ => String::new(),
                };
                results.push(factory_failed_result(&entry, message));
                continue;
            }
        };
        let buf = Arc::clone(&out_buf);
        let entry_for_tick = entry.clone();
        handles.push(tokio::spawn(async move {
            let on_tick: OnTick = Arc::new(move |res: &TickResult| {
                let line = tick_summary_line(&entry_for_tick, res);
                if let Ok(mut b) = buf.lock() {
                    b.push_str(&line);
                }
            });
            run_entry(deps, cancel, Some(on_tick)).await
        }));
    }
    let mut task_failed = false;
    for h in handles {
        match h.await {
            Ok(r) => results.push(r),
            Err(_) => task_failed = true,
        }
    }
    // Release the single-flights before returning, like
    // Go's deferred releases.
    for r in releases {
        r.release();
    }
    let buffered = out_buf.lock().map(|b| b.clone()).unwrap_or_default();
    ctx.out.stdout.push_str(&buffered);
    if root_cancel.is_cancelled() {
        // Interrupted: the main contract maps this to 130.
        return Err(msg_empty(130));
    }
    if task_failed {
        return Err(msg(2, "keeper: tick task ended unexpectedly"));
    }
    // A factory failure must not exit 0 silently: name
    // the entry and exit 2.
    for res in &results {
        if res.ticks == 0
            && let Some(last) = &res.last
            && let Some(err) = &last.error
        {
            ctx.out.stdout.push_str(&format!(
                "keeper: {}: failed (factory error, entry never ticked)\n",
                sanitize_display(&res.tag)
            ));
            return Err(msg(2, err.to_string()));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::run::Outcome;
    use std::fs;

    fn ctx_for(dir: &std::path::Path) -> (Ctx<'static>, GlobalOpts) {
        (
            Ctx {
                out: Outcome::default(),
                getenv: None,
            },
            GlobalOpts {
                config_flag: dir.join("config.json").to_str().unwrap().to_string(),
                config_set: true,
                ..Default::default()
            },
        )
    }

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "castctl-cli-keepercmd-{tag}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_config(dir: &std::path::Path, text: &str) {
        fs::write(dir.join("config.json"), text).unwrap();
    }

    fn flow_code(e: &FlowErr) -> i32 {
        match e {
            FlowErr::Msg { code, .. } => *code,
            FlowErr::Verbatim { code, .. } => *code,
            FlowErr::Exit(code) => *code,
            FlowErr::HelpShown => 0,
        }
    }

    fn flow_message(e: &FlowErr) -> String {
        match e {
            FlowErr::Msg { message, .. } => message.clone().unwrap_or_default(),
            FlowErr::Verbatim { text, .. } => text.clone(),
            FlowErr::Exit(_) => String::new(),
            FlowErr::HelpShown => String::new(),
        }
    }

    /// One keeper entry, profile `alpha`, no browser,
    /// no notify: keep-alive only. The keeper block is
    /// a bare array (`parse_keeper_block`). The short
    /// retry ladder bounds the worst case if the checker
    /// ever returns a transient error instead of the
    /// expected auth failure (the auth path never sleeps
    /// on the ladder).
    const KEEP_CFG: &str = r#"{"profiles":{"alpha":{"node_id":"0123456789abcdef"}},"keeper":[{"tag":"k-alpha","profile":"alpha","retry_backoff":["1s"]}]}"#;

    fn entry(tag: &str, profile: &str) -> KeeperEntry {
        KeeperEntry {
            tag: tag.to_string(),
            profile: profile.to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn selection_shapes() {
        let entries = vec![entry("k-a", "alpha"), entry("k-b", "beta")];
        assert_eq!(apply_selection(entries.clone(), "", "").unwrap().len(), 2);
        assert_eq!(
            apply_selection(entries.clone(), "k-b", "").unwrap()[0].profile,
            "beta"
        );
        assert_eq!(
            apply_selection(entries.clone(), "", "alpha").unwrap()[0].tag,
            "k-a"
        );
        let err = apply_selection(entries, "k-z", "").unwrap_err();
        assert_eq!(flow_code(&err), 2);
        assert!(flow_message(&err).contains("no entry matches the selection"));
    }

    #[test]
    fn tick_summary_line_shape() {
        let res = TickResult {
            outcome: "auth_error".to_string(),
            stage: "session".to_string(),
            stopped: true,
            recovered: false,
            wrote_cookies: false,
            dropped: 0,
            cdp_dropped: 0,
            exported: 0,
            cookies_seen: 0,
            skipped: 0,
            next_delay: Duration::ZERO,
            state_corrupt: false,
            error: None,
        };
        assert_eq!(
            tick_summary_line(&entry("k-alpha", "alpha"), &res),
            "keeper: k-alpha (alpha): auth_error cookies_seen=0 wrote=false next_delay=0s\n"
        );
        let corrupt = TickResult {
            outcome: "ok".to_string(),
            stage: String::new(),
            stopped: false,
            recovered: false,
            wrote_cookies: true,
            dropped: 0,
            cdp_dropped: 0,
            exported: 0,
            cookies_seen: 3,
            skipped: 0,
            next_delay: Duration::from_secs(24 * 3600),
            state_corrupt: true,
            error: None,
        };
        assert_eq!(
            tick_summary_line(&entry("k-alpha", "alpha"), &corrupt),
            "keeper: k-alpha (alpha): ok cookies_seen=3 wrote=true next_delay=24h0m0s state_corrupt=true\n"
        );
    }

    #[test]
    fn check_error_mapping() {
        assert_eq!(
            flow_code(&keeper_check_error(&KeeperError::Other(
                "check failed: https request timed out".to_string()
            ))),
            4
        );
        assert_eq!(
            flow_message(&keeper_check_error(&KeeperError::Other(
                "check failed: https request timed out".to_string()
            ))),
            "timeout: context deadline exceeded"
        );
        assert_eq!(
            flow_code(&keeper_check_error(&KeeperError::Other(
                "check failed: gateway error; body_length=12".to_string()
            ))),
            3
        );
        assert_eq!(
            flow_message(&keeper_check_error(&KeeperError::Other(
                "check failed: gateway error; body_length=12".to_string()
            ))),
            "gateway error; body_length=12"
        );
        // N2 (fix loop 1): a gateway error whose summary names
        // a timeout must still exit 3. Go classifies by TYPE
        // (`classifyError`, `commands.go:301-314`: GatewayError
        // is checked BEFORE TimeoutError), so the gateway
        // branch must win over the timeout substring. The
        // `error=timeout` code is a realistic summary field
        // (`BodySummary::render` appends `; error=…`).
        assert_eq!(
            flow_code(&keeper_check_error(&KeeperError::Other(
                "check failed: gateway error; body_length=12; error=timeout".to_string()
            ))),
            3
        );
        assert_eq!(
            flow_message(&keeper_check_error(&KeeperError::Other(
                "check failed: gateway error; body_length=12; error=timeout".to_string()
            ))),
            "gateway error; body_length=12; error=timeout"
        );
        assert_eq!(
            flow_code(&keeper_check_error(&KeeperError::Other(
                "something else broke".to_string()
            ))),
            1
        );
        assert_eq!(
            flow_code(&keeper_check_error(&KeeperError::Config("bad".to_string()))),
            1
        );
    }

    /// B1 (fix loop 1): the SIGINT watcher must cancel
    /// the ROOT flag, not a child of it. Go `cmdKeeperRun`
    /// / `cmdKeeperCheck` (`keeper.go:650-654`, `:714-723`)
    /// return `ctx.Err()` after Run/tick; the `ctx` is the
    /// process signal context. The pre-fix watcher cancelled
    /// a child flag nothing waited on (`CancelFlag::child`
    /// documents that cancelling the child does NOT cancel
    /// the parent, `castctl-keeper/src/clock.rs:61-64`), so
    /// the `msg_empty(130)` arms were dead code. The signal
    /// is injected as a future so the test is deterministic:
    /// production passes `tokio::signal::ctrl_c()`, the test
    /// passes an immediately-ready future.
    #[test]
    fn ctrl_c_watcher_cancels_root() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let root = CancelFlag::new();
            let handle = spawn_ctrl_c_watcher(root.clone(), std::future::ready(()));
            tokio::time::timeout(Duration::from_secs(5), root.cancelled())
                .await
                .expect("watcher must cancel the root flag");
            assert!(root.is_cancelled());
            let _ = handle.await;
        });
    }

    /// The watcher must NOT cancel the root while the
    /// signal is still pending.
    #[test]
    fn ctrl_c_watcher_pending_signal_does_not_cancel() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let root = CancelFlag::new();
            let handle = spawn_ctrl_c_watcher(root.clone(), std::future::pending::<()>());
            tokio::time::sleep(Duration::from_millis(100)).await;
            assert!(!root.is_cancelled());
            handle.abort();
        });
    }

    #[test]
    fn form_urlencode_shapes() {
        assert_eq!(form_urlencode("a b&c=d"), "a+b%26c%3Dd");
        assert_eq!(
            form_urlencode("castctl keeper: profile alpha session logged out."),
            "castctl+keeper%3A+profile+alpha+session+logged+out."
        );
    }

    #[test]
    fn keeper_config_errors() {
        // An explicit --config path that does not exist
        // fails at RequirePresent, before the keeper
        // wording (Go `resolveConfig`, `commands.go`).
        let dir = temp_dir("cfg-missing");
        let (mut ctx, g) = ctx_for(&dir);
        let err = keeper_config(&mut ctx, &g).unwrap_err();
        assert_eq!(flow_code(&err), 2);
        assert!(flow_message(&err).contains("does not exist"));
        // A file that exists but has no "profiles"
        // marker parses as "not found": the keeper's own
        // wording names the missing config.
        let dir = temp_dir("cfg-nomarker");
        write_config(&dir, "{}");
        let (mut ctx, g) = ctx_for(&dir);
        let err = keeper_config(&mut ctx, &g).unwrap_err();
        assert_eq!(flow_code(&err), 2);
        assert!(flow_message(&err).contains("no config.json found"));
        // A config with no keeper block.
        let dir = temp_dir("cfg-noblock");
        write_config(&dir, r#"{"profiles":{"alpha":{}}}"#);
        let (mut ctx, g) = ctx_for(&dir);
        let err = keeper_config(&mut ctx, &g).unwrap_err();
        assert_eq!(flow_code(&err), 2);
        assert!(flow_message(&err).contains("no \"keeper\" block"));
    }

    #[test]
    fn status_never_ticked_row() {
        let dir = temp_dir("status-fresh");
        write_config(&dir, KEEP_CFG);
        let (mut ctx, g) = ctx_for(&dir);
        run_status(&mut ctx, &g, "", "").unwrap();
        let v: SerdeValue = serde_json::from_str(&ctx.out.stdout).unwrap();
        let rows = v.as_array().unwrap();
        assert_eq!(rows.len(), 1);
        let row = &rows[0];
        assert_eq!(row["tag"], "k-alpha");
        assert_eq!(row["profile"], "alpha");
        assert_eq!(row["logged_out"], false);
        assert_eq!(row["keeper_stopped"], false);
        // `last_tick_outcome` is always present. A
        // never-ticked state reports `"never"`, not `""`:
        // Go normalises an empty outcome on load
        // (`state.go:246`: `if st.LastTickOutcome == "" {
        // st.LastTickOutcome = OutcomeNever }`), and the R3
        // live probe shows `"last_tick_outcome": "never"`
        // for the fresh row. (The EMPTY string appears only
        // for a corrupt/unparseable state file — see the
        // test below.)
        assert_eq!(row["last_tick_outcome"], "never");
        // Go `keeper.Status.StateCorrupt` is
        // `json:"state_corrupt,omitempty"`: the key is
        // ABSENT (not `false`) for a healthy row.
        assert!(row.get("state_corrupt").is_none());
    }

    #[test]
    fn status_corrupt_state_row() {
        let dir = temp_dir("status-corrupt");
        write_config(&dir, KEEP_CFG);
        let profile_dir = dir.join("profiles/alpha");
        fs::create_dir_all(&profile_dir).unwrap();
        fs::write(profile_dir.join("session-state.json"), b"{not json").unwrap();
        let (mut ctx, g) = ctx_for(&dir);
        run_status(&mut ctx, &g, "", "").unwrap();
        let v: SerdeValue = serde_json::from_str(&ctx.out.stdout).unwrap();
        let row = &v.as_array().unwrap()[0];
        assert_eq!(row["state_corrupt"], true);
        assert_eq!(row["last_tick_outcome"], "");
    }

    /// End-to-end check against a profile with no
    /// cookies file: the tick stops with `auth_error`
    /// (R3 probe shape), the row is printed, exit 3.
    /// No network is involved: the gateway probe fails
    /// fast reading the missing cookies file.
    #[test]
    fn check_no_cookies_is_exit_3() {
        let dir = temp_dir("check-nocookies");
        write_config(&dir, KEEP_CFG);
        let (mut ctx, g) = ctx_for(&dir);
        let err = run_check(&mut ctx, &g, "", "").unwrap_err();
        assert_eq!(flow_code(&err), 3);
        assert!(flow_message(&err).contains("entry stopped"));
        let v: SerdeValue = serde_json::from_str(&ctx.out.stdout).unwrap();
        assert_eq!(v["tag"], "k-alpha");
        assert_eq!(v["outcome"], "auth_error");
        assert_eq!(v["stopped"], true);
        assert_eq!(v["cookies_seen"], 0);
        assert_eq!(v["wrote_cookies"], false);
        // No next_check_at: the stopped tick writes no
        // future check time.
        assert!(v.get("next_check_at").is_none());
    }

    /// A live single-flight owner makes `keeper run`
    /// exit 2 with the already-running text, like Go's
    /// second concurrent run (R3 probe).
    #[test]
    fn run_already_running_is_exit_2() {
        let dir = temp_dir("run-busy");
        write_config(&dir, KEEP_CFG);
        let profile_dir = dir.join("profiles/alpha");
        fs::create_dir_all(&profile_dir).unwrap();
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let flight = rt.block_on(acquire_single_flight(
            profile_dir.to_str().unwrap(),
            "k-alpha",
            Arc::new(RealClock),
        ));
        let flight = flight.unwrap();
        let (mut ctx, g) = ctx_for(&dir);
        let err = run_keeper(&mut ctx, &g, "", "").unwrap_err();
        assert_eq!(flow_code(&err), 2);
        assert!(
            flow_message(&err).contains("already running"),
            "got: {}",
            flow_message(&err)
        );
        assert!(ctx.out.stdout.is_empty());
        flight.release();
    }
}
