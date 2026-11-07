// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! `telegram run/status` (`internal/commands/telegram.go`).
//!
//! `status` is the offline JSON report of the block.
//! `run` builds the runtime for the LINKED profile,
//! persists the node id, loads the state store, starts
//! the heartbeat, constructs the bot (one `getMe`),
//! registers the command menu, prints the startup line,
//! starts the embedded keeper, and polls until Ctrl-C.
//!
//! Deviations recorded here (see also the M7d report):
//! - The CLI buffers `ctx.out` until the process exits,
//!   so the startup line and `telegram: polling stopped`
//!   appear only at exit, unlike Go which prints them
//!   live (same M2 limitation as `webui serve`).
//! - Bot construction failures exit 1 with Go's
//!   go-telegram/bot text (`telegram: bot construction
//!   failed: error call getMe, unauthorized,
//!   Unauthorized` for a fake-token 401 — measured live
//!   on cue). Poll-loop failures still exit 1 with the
//!   Rust `BotError` display text (`telegram api error
//!   401`, `transport error: ...`); Go's poll text is
//!   unprobed.
//! - The embedded keeper's ticks are logged to the
//!   stderr buffer in the port's summary-line shape,
//!   not Go's structured slog `keeper tick` line.
//! - The Rust bot core retries 5xx with the default
//!   ladder (`DEFAULT_5XX_BACKOFF`); Go's core has no
//!   5xx retry (M5 [DEVIATION], recorded in PORTING.md).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use castctl_config::config::{SingleConfig, load_profile, load_single_config};
use castctl_config::configlocation::{ConfigLocation, config_lookup_env};
use castctl_config::errors::raw_io_error;
use castctl_config::gostr::{go_quote, go_trim_space};
use castctl_config::jsonvalue::{JsonValue, OrderedObject, encode_ordered_json};
use castctl_config::profile::PROFILE_ENV;
use castctl_config::profile_ops::resolve_telegram;
use castctl_config::telegram::TelegramConfig;
use castctl_config::toggle::{generate_node_id, update_single_config};
use castctl_keeper::clock::{CancelFlag, RealClock};
use castctl_keeper::run::acquire_single_flight;
use castctl_telegram::{
    Bot, BotApi, BotApiConfig, BotError, BotSettings, CallbackRegistry, ClaimManager,
    CommandHandlerConfig, GatewayBotServices, GatewayDecider, SenderSink, SharedGatewayPort,
    TelegramStateStore, TurnRunner, state_path_for_profile_dir,
};

use crate::keepercmd::{KeeperRuntimes, tick_summary_line};
use crate::network::write_json_text;
use crate::run::{Ctx, FlowErr, GlobalOpts, config_err, msg, msg_empty, resolve_config};
use crate::runtime::build_runtime;

/// `resolveTelegramBlock` (`telegram.go:379`): resolve
/// the config, load the single config, resolve the
/// telegram block (nil when absent: exit 2), and refuse
/// an explicitly named profile that differs from the
/// block's linked profile. The bot serves the linked
/// profile, never the active one.
#[derive(Debug)]
pub(crate) struct TelegramSetup {
    pub(crate) loc: ConfigLocation,
    pub(crate) single: SingleConfig,
    pub(crate) tg: TelegramConfig,
}

pub(crate) fn resolve_telegram_block(
    ctx: &mut Ctx<'_>,
    g: &GlobalOpts,
) -> Result<TelegramSetup, FlowErr> {
    let loc = resolve_config(ctx, g, false)?;
    let (single, _found) = load_single_config(&loc.config_dir).map_err(config_err)?;
    crate::run::validate_webui_at_load(&single, &loc.config_dir)?;
    let Some(single) = single else {
        return Err(msg(
            2,
            "telegram: no config.json found; add a \"telegram\" block to configure the bot",
        ));
    };
    let tg = resolve_telegram(&single).map_err(config_err)?;
    let Some(tg) = tg else {
        return Err(msg(
            2,
            "telegram: no \"telegram\" block in config.json; the bot is off",
        ));
    };
    let tg = tg.clone();
    if g.profile_set && g.profile_flag != tg.profile {
        return Err(msg(
            2,
            format!(
                "telegram: --profile {} does not match the telegram block's profile {}",
                go_quote(&g.profile_flag),
                go_quote(&tg.profile)
            ),
        ));
    }
    if let Some(v) = config_lookup_env(ctx.getenv, PROFILE_ENV) {
        let trimmed = go_trim_space(&v);
        if !trimmed.is_empty() && trimmed != tg.profile {
            return Err(msg(
                2,
                format!(
                    "telegram: CASTCTL_PROFILE {} does not match the telegram block's profile {}",
                    go_quote(trimmed),
                    go_quote(&tg.profile)
                ),
            ));
        }
    }
    Ok(TelegramSetup { loc, single, tg })
}

/// `cmdTelegramStatus` (`telegram.go:340`): the offline
/// JSON report of the block. `allowed_user_ids` is the
/// COUNT of the config list (the owner is not merged
/// for counting); `token_valid` is always true here —
/// the block was already shape-checked.
pub(crate) fn run_status(ctx: &mut Ctx<'_>, g: &GlobalOpts) -> Result<(), FlowErr> {
    let setup = resolve_telegram_block(ctx, g)?;
    let tg = setup.tg;
    let mut o = OrderedObject::new();
    o.set("configured", JsonValue::Bool(true));
    o.set("profile", JsonValue::Str(tg.profile.clone()));
    o.set(
        "allowed_user_ids",
        JsonValue::Number(tg.allowed_user_ids.len().to_string()),
    );
    o.set("auto_approve", JsonValue::Bool(tg.auto_approve));
    o.set("auto_allow_once", JsonValue::Bool(tg.auto_allow_once));
    o.set("token_valid", JsonValue::Bool(true));
    o.set("owner_configured", JsonValue::Bool(tg.owner_id_set));
    let compact = encode_ordered_json(&JsonValue::Object(o)).map_err(config_err)?;
    ctx.out.stdout.push_str(&write_json_text(&compact));
    Ok(())
}

/// `ensureNodeID` (`wait.go:107`): the profile already
/// has one → no-op; `MUSE_NODE_ID` wins (in-memory,
/// raw value, no trim); else generate 16 hex and
/// persist via `UpdateSingleConfig` when the profile
/// has a single-file entry (adopting a concurrently
/// persisted id); in-memory only otherwise. The
/// closure's missing-profile error is a plain error,
/// exit 1, not a config error.
fn ensure_node_id(
    loc: &ConfigLocation,
    single: &SingleConfig,
    prof: &castctl_config::profile::Profile,
    getenv: castctl_config::configlocation::Getenv<'_>,
) -> Result<String, FlowErr> {
    if !prof.node_id.is_empty() {
        return Ok(prof.node_id.clone());
    }
    if let Some(v) = config_lookup_env(getenv, "MUSE_NODE_ID")
        && !v.is_empty()
    {
        return Ok(v);
    }
    // RNG failure is practically unreachable; the shared
    // generator's message carries the `profile: ` prefix
    // and the `generate node_id: ` label, where Go
    // returns the raw crypto/rand error. Exit 1 either way.
    let generated = generate_node_id().map_err(|e| msg(1, e.message))?;
    if !single.profiles.contains_key(&prof.name) {
        return Ok(generated);
    }
    let name = prof.name.clone();
    let to_write = generated.clone();
    let adopted: std::cell::Cell<Option<String>> = std::cell::Cell::new(None);
    update_single_config(&loc.config_dir, |cfg| {
        let Some(p) = cfg.profiles.get_mut(&name) else {
            // A plain error, not a config error: Go's
            // closure returns `fmt.Errorf("profile %q does
            // not exist in the single config file")`,
            // exit 1, no `profile: ` prefix.
            return Err(raw_io_error(format!(
                "profile {} does not exist in the single config file",
                go_quote(&name)
            )));
        };
        if !p.node_id.is_empty() {
            // Another writer persisted one first: adopt it.
            adopted.set(Some(p.node_id.clone()));
            return Ok(());
        }
        p.node_id = to_write;
        Ok(())
    })
    // The ConfigError carries its own exit code: 2 for a
    // lock / concurrent-change failure, 1 for the
    // closure's plain error above.
    .map_err(|e| msg(e.code, e.message))?;
    Ok(adopted.take().unwrap_or(generated))
}

/// A `BotError` from construction: Go wraps it as
/// `telegram: bot construction failed: <err>` and
/// classifies it as a plain error (exit 1). For an `Api`
/// error the `<err>` is go-telegram/bot's rendering
/// (`raw_request.go` + `bot.go:97`, measured live on cue
/// against the Go binary with a fake token: `error call
/// getMe, unauthorized, Unauthorized`), NOT the shared
/// `BotError` display — see
/// `go_telegram_construction_api_text`.
fn bot_construction_error(e: &BotError) -> FlowErr {
    if matches!(e, BotError::Cancelled) {
        return msg_empty(130);
    }
    if let BotError::Api {
        code,
        description,
        retry_after,
    } = e
    {
        return msg(
            1,
            format!(
                "telegram: bot construction failed: {}",
                go_telegram_construction_api_text(*code, description, *retry_after)
            ),
        );
    }
    msg(1, format!("telegram: bot construction failed: {e}"))
}

/// Render a Bot API failure from bot construction the
/// way go-telegram/bot does. Construction always calls
/// getMe once (`New`), so the method is fixed here.
/// Mapping (`raw_request.go`): 400 `bad request`, 401
/// `unauthorized`, 403 `forbidden`, 404 `not found`, 409
/// `conflict`, each followed by `, {description}`; 429 is
/// the `TooManyRequestsError` shape (`too many requests,
/// {description}: retry_after {n}`, `n` = 0 when the
/// server sent none); any other code is `error response
/// from telegram for method getMe, {code} {description}`.
/// The description IS server text, and Go prints it in
/// this error — this path deliberately renders it to
/// match Go byte-for-byte. The shared `BotError` Display
/// keeps its never-print rule everywhere else (notably
/// the poll-loop path, still Rust text).
fn go_telegram_construction_api_text(
    code: i32,
    description: &str,
    retry_after: Option<i64>,
) -> String {
    let inner = match code {
        400 => format!("bad request, {description}"),
        401 => format!("unauthorized, {description}"),
        403 => format!("forbidden, {description}"),
        404 => format!("not found, {description}"),
        409 => format!("conflict, {description}"),
        429 => format!(
            "too many requests, {description}: retry_after {}",
            retry_after.unwrap_or(0)
        ),
        _ => format!("error response from telegram for method getMe, {code} {description}"),
    };
    format!("error call getMe, {inner}")
}

/// A `BotError` from the poll loop: Go returns the
/// `Start` error as-is (plain error, exit 1), except
/// a cancelled context, which is 130.
fn bot_run_error(e: &BotError) -> FlowErr {
    if matches!(e, BotError::Cancelled) {
        return msg_empty(130);
    }
    msg(1, e.to_string())
}

/// The SIGINT watch shared by the poll loop and the
/// embedded keeper: the flag records the interrupt
/// (the exit code), the slot hands the bot to the
/// watcher so a Ctrl-C during `getMe` is also
/// honoured (Go's ctx is cancelled then).
struct ShutdownWatch {
    interrupted: AtomicBool,
    bot: Mutex<Option<Arc<Bot>>>,
}

/// `cmdTelegramRun` (`telegram.go:125`): the sync
/// wrapper builds the tokio runtime; the async body
/// below does the work.
pub(crate) fn run_telegram(ctx: &mut Ctx<'_>, g: &GlobalOpts) -> Result<(), FlowErr> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| msg(1, format!("failed to start async runtime: {e}")))?;
    rt.block_on(run_telegram_bot(ctx, g))
}

async fn run_telegram_bot(ctx: &mut Ctx<'_>, g: &GlobalOpts) -> Result<(), FlowErr> {
    let setup = resolve_telegram_block(ctx, g)?;
    let TelegramSetup { loc, single, tg } = setup;
    let prof = load_profile(&loc.config_dir, &tg.profile, ctx.getenv).map_err(config_err)?;
    // ensureNodeID before the runtime is built: the send
    // path transmits prof.NodeID verbatim.
    let node_id = ensure_node_id(&loc, &single, &prof, ctx.getenv)?;
    // A read failure other than "missing" fails startup;
    // a corrupt file loads fresh and is reported once
    // below; an unknown schema version fails startup.
    let state_path = state_path_for_profile_dir(std::path::Path::new(&prof.dir));
    let state = Arc::new(TelegramStateStore::load(state_path).map_err(|e| msg(1, e.to_string()))?);
    let state_corrupt = state.corrupt();
    let rt = build_runtime(&loc, Some(&single), Some(&tg.profile), ctx.getenv)?;
    let rt = Arc::new(rt);
    if state_corrupt {
        // The counts of discarded mappings/watermarks/
        // toggles are unknowable: the file did not parse.
        ctx.out.stderr.push_str(
            "telegram state file corrupt; starting with fresh state (offset reset to 0; stored chat mappings, watermarks, and runtime toggles discarded)\n",
        );
    }
    // The heartbeat lives for the bot process, not per
    // turn. `start_heartbeat` is the Rust `SharedConn`
    // seam for Go's `rt.Muse.StartHeartbeat(0)`.
    rt.shared.start_heartbeat();
    // The effective allowlist is the config list plus
    // the owner, when set. The config list itself is
    // untouched: `telegram status` counts it, and the
    // startup line below reports it.
    let mut allowed = tg.allowed_user_ids.clone();
    if tg.owner_id_set && !allowed.contains(&tg.owner_id) {
        allowed.push(tg.owner_id);
    }
    // Construction order: api → state → registry →
    // claims → port → sink → runner → services → Bot
    // (getMe once inside `Bot::new`).
    let api = Arc::new(BotApi::new(
        Arc::clone(&rt.dialer),
        BotApiConfig::production(tg.token.clone()),
    ));
    let registry = Arc::new(CallbackRegistry::new());
    let port = Arc::new(SharedGatewayPort::new(Arc::clone(&rt.shared)));
    let decider = Arc::new(GatewayDecider::new(
        Arc::clone(&port) as Arc<dyn castctl_telegram::GatewayPort>
    ));
    let claims = Arc::new(ClaimManager::new(decider, Duration::ZERO));
    let sink = Arc::new(SenderSink::new(Arc::clone(&api)));
    let runner = Arc::new(TurnRunner::new(
        Arc::clone(&port) as Arc<dyn castctl_telegram::GatewayPort>,
        Arc::clone(&sink) as Arc<dyn castctl_telegram::turn::BotSink>,
        Arc::clone(&api),
        Arc::clone(&state),
        Arc::clone(&registry),
        Arc::clone(&claims),
        tg.profile.clone(),
        node_id.clone(),
        tg.auto_approve,
        tg.auto_allow_once,
    ));
    let services = Arc::new(GatewayBotServices::new(
        Arc::clone(&port) as Arc<dyn castctl_telegram::GatewayPort>,
        Arc::clone(&api),
        Arc::clone(&state),
        Arc::clone(&registry),
        Arc::clone(&claims),
        Arc::clone(&runner),
    ));
    let handler_config = CommandHandlerConfig {
        profile_name: tg.profile.clone(),
        owner_id: tg.owner_id,
        owner_id_set: tg.owner_id_set,
        block_auto_approve: tg.auto_approve,
        block_auto_allow_once: tg.auto_allow_once,
        cookies_file: std::path::PathBuf::from(&prof.cookies_file),
        vm_id: prof.vm_id.clone(),
    };
    let settings = BotSettings {
        allowed_user_ids: allowed,
        backoff_ladder: Vec::new(),
    };
    // The SIGINT watcher is installed BEFORE `Bot::new`
    // so a Ctrl-C during getMe is honoured too.
    let watch = Arc::new(ShutdownWatch {
        interrupted: AtomicBool::new(false),
        bot: Mutex::new(None),
    });
    let watch_clone = Arc::clone(&watch);
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        watch_clone.interrupted.store(true, Ordering::SeqCst);
        if let Some(bot) = watch_clone
            .bot
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
        {
            bot.request_shutdown();
        }
    });
    let bot = Bot::new(
        api,
        Arc::clone(&state),
        registry,
        claims,
        services as Arc<dyn castctl_telegram::BotServices>,
        handler_config,
        settings,
    )
    .await
    .map_err(|e| bot_construction_error(&e))?;
    *watch.bot.lock().unwrap_or_else(|e| e.into_inner()) = Some(Arc::clone(&bot));
    if watch.interrupted.load(Ordering::SeqCst) {
        // SIGINT arrived during getMe: Go would return
        // ctx.Err() from Start.
        ctx.out.stderr.push_str("telegram: polling stopped\n");
        return Err(msg_empty(130));
    }
    // Register the "/" menu now that getMe has succeeded.
    // A failure only warns — polling must start regardless.
    if let Err(e) = bot.set_menu_commands().await {
        ctx.out.stderr.push_str(&format!(
            "telegram: setMyCommands failed: {}\n",
            e.summary()
        ));
    }
    ctx.out.stdout.push_str(&format!(
        "telegram: polling for profile {} ({} allowed users); Ctrl-C to stop\n",
        go_quote(&tg.profile),
        tg.allowed_user_ids.len()
    ));
    // Embedded keeper (G5): the keeper loop shares this
    // process and its shutdown context. Entries already
    // owned by a standalone `keeper run` are skipped,
    // never stolen; a missing keeper block starts
    // nothing. Its ticks are logged to the stderr buffer.
    let keeper_root = CancelFlag::new();
    let (keeper_handles, keeper_buf) =
        start_embedded_keeper(&loc, &single, ctx.getenv, &keeper_root, ctx).await;
    let run_result = bot.run().await;
    // The keeper stops with the bot: cancel its root
    // and wait for its loops to end, like Go's release.
    keeper_root.cancel();
    for h in keeper_handles {
        let _ = h.await;
    }
    // The keeper's tick lines happened during polling,
    // so they drain before the shutdown marker.
    if let Ok(b) = keeper_buf.lock() {
        ctx.out.stderr.push_str(&b);
    }
    // Shutdown boundary marker, always visible even on
    // error: reaching this line proves the poll loop
    // exited and in-flight turns finished teardown.
    ctx.out.stderr.push_str("telegram: polling stopped\n");
    match run_result {
        Ok(()) => {
            if watch.interrupted.load(Ordering::SeqCst) {
                Err(msg_empty(130))
            } else {
                Ok(())
            }
        }
        Err(e) => Err(bot_run_error(&e)),
    }
}

/// `startEmbeddedKeeper` (`keeper.go:193`): the keeper
/// loop shares the bot process. A missing keeper block
/// starts nothing; an entry whose single-flight is
/// already owned is skipped, never stolen. Returns the
/// spawned per-entry tasks and the buffer their tick
/// lines are appended to; the caller cancels the root
/// flag, awaits the tasks, and drains the buffer at
/// shutdown (the CLI's stderr buffer only flushes at
/// process exit, so the lines appear then, not live).
async fn start_embedded_keeper(
    loc: &ConfigLocation,
    single: &SingleConfig,
    getenv: castctl_config::configlocation::Getenv<'_>,
    root_cancel: &CancelFlag,
    ctx: &mut Ctx<'_>,
) -> (
    Vec<tokio::task::JoinHandle<()>>,
    Arc<std::sync::Mutex<String>>,
) {
    use castctl_keeper::run::run_entry;
    use std::sync::Mutex as StdMutex;
    let mut handles = Vec::new();
    let out_buf: Arc<StdMutex<String>> = Arc::new(StdMutex::new(String::new()));
    let setup = match keeper_config_for_embedded(single) {
        Ok(s) => s,
        Err(warn) => {
            ctx.out.stderr.push_str(&warn);
            return (handles, out_buf);
        }
    };
    let mut rts = KeeperRuntimes::new(loc.clone(), single.clone(), getenv);
    for entry in setup {
        let paths = match castctl_config::profile::profile_paths(&loc.config_dir, &entry.profile) {
            Ok(p) => p,
            Err(e) => {
                ctx.out.stderr.push_str(&format!(
                    "keeper: embedded keeper skipped entry \"{}\" (paths): {}\n",
                    entry.tag, e.message
                ));
                continue;
            }
        };
        let flight = match acquire_single_flight(&paths.dir, &entry.tag, Arc::new(RealClock)).await
        {
            Ok(f) => f,
            Err(e) => {
                ctx.out.stderr.push_str(&format!(
                    "keeper: embedded keeper skipped entry \"{}\" (already running): {}\n",
                    entry.tag, e
                ));
                continue;
            }
        };
        let cancel = root_cancel.child();
        let deps = match rts.factory(&entry, &cancel) {
            Ok(d) => d,
            Err(e) => {
                let message = match &e {
                    FlowErr::Msg { message, .. } => message.clone().unwrap_or_default(),
                    FlowErr::Verbatim { text, .. } => text.clone(),
                    _ => String::new(),
                };
                ctx.out.stderr.push_str(&format!(
                    "keeper: embedded keeper skipped entry \"{}\" (factory): {}\n",
                    entry.tag, message
                ));
                flight.release();
                continue;
            }
        };
        let buf = Arc::clone(&out_buf);
        let entry_for_tick = entry.clone();
        handles.push(tokio::spawn(async move {
            let on_tick = Arc::new(move |res: &castctl_keeper::tick::TickResult| {
                let line = tick_summary_line(&entry_for_tick, res);
                if let Ok(mut b) = buf.lock() {
                    b.push_str(&line);
                }
            });
            let _result = run_entry(deps, cancel, Some(on_tick)).await;
            flight.release();
        }));
    }
    (handles, out_buf)
}

/// The embedded keeper's config load: like
/// `keeperConfig` but a missing block (or a missing
/// file, or a load error) only warns and starts
/// nothing, never exits 2.
fn keeper_config_for_embedded(
    single: &SingleConfig,
) -> Result<Vec<castctl_config::keeper::KeeperEntry>, String> {
    let kcfg = match single.resolve_keeper() {
        Ok(k) => k,
        Err(e) => {
            return Err(format!(
                "keeper: embedded keeper not started (keeper block): {}\n",
                e.message
            ));
        }
    };
    let Some(kcfg) = kcfg else {
        return Ok(Vec::new());
    };
    if kcfg.entries.is_empty() {
        return Ok(Vec::new());
    }
    Ok(kcfg.entries.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::run::Outcome;
    use std::fs;

    // Fixture shapes copied from
    // `~/workspace/tmp/castctl-rust-m7d-notes/fixtures/tg-*.json`
    // (R3 live probes; fake token placeholders only).
    const TG_VALID: &str = r#"{"profiles":{"alpha":{"node_id":"ALPHA-NODE"}},"telegram":{"profile":"alpha","token":"123456:FAKE-TOKEN-PLACEHOLDER-abcdefghij","allowed_user_ids":[111,222],"owner_id":111,"auto_approve":true}}"#;
    const TG_BAD_TOKEN: &str = r#"{"profiles":{"alpha":{"node_id":"ALPHA-NODE"}},"telegram":{"profile":"alpha","token":"not-a-token","allowed_user_ids":[111]}}"#;
    const TG_EMPTY_ALLOW: &str = r#"{"profiles":{"alpha":{"node_id":"ALPHA-NODE"}},"telegram":{"profile":"alpha","token":"123456:FAKE-TOKEN-PLACEHOLDER-abcdefghij","allowed_user_ids":[]}}"#;
    const TG_NOOWNER: &str = r#"{"profiles":{"alpha":{"node_id":"ALPHA-NODE"}},"telegram":{"profile":"alpha","token":"123456:FAKE-TOKEN-PLACEHOLDER-abcdefghij","allowed_user_ids":[111],"auto_allow_once":true}}"#;
    const TG_DANGLING: &str = r#"{"profiles":{"alpha":{"node_id":"ALPHA-NODE"}},"telegram":{"profile":"ghost","token":"123456:FAKE-TOKEN-PLACEHOLDER-abcdefghij","allowed_user_ids":[111]}}"#;
    const TG_NO_BLOCK: &str = r#"{"profiles":{"alpha":{}}}"#;

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
            "castctl-cli-telegramcmd-{tag}-{}",
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

    #[test]
    fn status_valid_matches_go() {
        // R3 probe: Go `telegram status` on the valid
        // block prints exactly this JSON (MarshalIndent,
        // 2-space, trailing newline).
        let dir = temp_dir("status-valid");
        write_config(&dir, TG_VALID);
        let (mut ctx, g) = ctx_for(&dir);
        run_status(&mut ctx, &g).unwrap();
        assert_eq!(
            ctx.out.stdout,
            "{\n  \"configured\": true,\n  \"profile\": \"alpha\",\n  \"allowed_user_ids\": 2,\n  \"auto_approve\": true,\n  \"auto_allow_once\": false,\n  \"token_valid\": true,\n  \"owner_configured\": true\n}\n"
        );
        assert!(ctx.out.stderr.is_empty());
    }

    #[test]
    fn status_noowner_matches_go() {
        let dir = temp_dir("status-noowner");
        write_config(&dir, TG_NOOWNER);
        let (mut ctx, g) = ctx_for(&dir);
        run_status(&mut ctx, &g).unwrap();
        assert_eq!(
            ctx.out.stdout,
            "{\n  \"configured\": true,\n  \"profile\": \"alpha\",\n  \"allowed_user_ids\": 1,\n  \"auto_approve\": false,\n  \"auto_allow_once\": true,\n  \"token_valid\": true,\n  \"owner_configured\": false\n}\n"
        );
    }

    #[test]
    fn status_bad_token_is_exit_2() {
        let dir = temp_dir("status-badtoken");
        write_config(&dir, TG_BAD_TOKEN);
        let (mut ctx, g) = ctx_for(&dir);
        let err = run_status(&mut ctx, &g).unwrap_err();
        assert_eq!(flow_code(&err), 2);
        assert!(flow_message(&err).contains("does not look like a bot token"));
    }

    #[test]
    fn status_empty_allowlist_is_exit_2() {
        let dir = temp_dir("status-empty");
        write_config(&dir, TG_EMPTY_ALLOW);
        let (mut ctx, g) = ctx_for(&dir);
        let err = run_status(&mut ctx, &g).unwrap_err();
        assert_eq!(flow_code(&err), 2);
        assert!(flow_message(&err).contains("must not be empty"));
    }

    #[test]
    fn status_dangling_profile_is_exit_2() {
        let dir = temp_dir("status-dangling");
        write_config(&dir, TG_DANGLING);
        let (mut ctx, g) = ctx_for(&dir);
        let err = run_status(&mut ctx, &g).unwrap_err();
        assert_eq!(flow_code(&err), 2);
        assert!(flow_message(&err).contains("does not exist"));
    }

    #[test]
    fn status_no_block_is_exit_2() {
        let dir = temp_dir("status-noblock");
        write_config(&dir, TG_NO_BLOCK);
        let (mut ctx, g) = ctx_for(&dir);
        let err = run_status(&mut ctx, &g).unwrap_err();
        assert_eq!(flow_code(&err), 2);
        assert!(flow_message(&err).contains("no \"telegram\" block"));
    }

    #[test]
    fn status_profile_mismatch_is_exit_2() {
        let dir = temp_dir("status-mismatch");
        write_config(&dir, TG_VALID);
        let (mut ctx, mut g) = ctx_for(&dir);
        g.profile_flag = "beta".to_string();
        g.profile_set = true;
        let err = run_status(&mut ctx, &g).unwrap_err();
        assert_eq!(flow_code(&err), 2);
        assert!(flow_message(&err).contains("--profile \"beta\" does not match"));
    }

    #[test]
    fn status_castctl_profile_mismatch_is_exit_2() {
        let dir = temp_dir("status-envmismatch");
        write_config(&dir, TG_VALID);
        let getenv = |k: &str| {
            if k == PROFILE_ENV {
                Some("beta".to_string())
            } else {
                None
            }
        };
        let mut ctx = Ctx {
            out: Outcome::default(),
            getenv: Some(&getenv),
        };
        let g = GlobalOpts {
            config_flag: dir.join("config.json").to_str().unwrap().to_string(),
            config_set: true,
            ..Default::default()
        };
        let err = run_status(&mut ctx, &g).unwrap_err();
        assert_eq!(flow_code(&err), 2);
        assert!(flow_message(&err).contains("CASTCTL_PROFILE \"beta\" does not match"));
    }

    #[test]
    fn resolve_block_explicit_missing_config_is_exit_2() {
        // RequirePresent: an explicit --config path that
        // does not exist fails before the telegram
        // wording (Go `resolveConfig`, `commands.go`).
        let dir = temp_dir("resolve-missing");
        let (mut ctx, g) = ctx_for(&dir);
        let err = resolve_telegram_block(&mut ctx, &g).unwrap_err();
        assert_eq!(flow_code(&err), 2);
        assert!(flow_message(&err).contains("does not exist"));
    }

    #[test]
    fn run_missing_block_is_exit_2() {
        // No network: the resolve fails before any
        // runtime, state, or bot construction.
        let dir = temp_dir("run-noblock");
        write_config(&dir, TG_NO_BLOCK);
        let (mut ctx, g) = ctx_for(&dir);
        let err = run_telegram(&mut ctx, &g).unwrap_err();
        assert_eq!(flow_code(&err), 2);
        assert!(flow_message(&err).contains("no \"telegram\" block"));
        assert!(ctx.out.stdout.is_empty());
    }

    #[test]
    fn run_unknown_state_version_is_exit_1() {
        // The state store refuses an unknown schema
        // version before any network is touched.
        let dir = temp_dir("run-badstate");
        write_config(&dir, TG_VALID);
        let prof_dir = dir.join("profiles").join("alpha");
        fs::create_dir_all(&prof_dir).unwrap();
        fs::write(
            prof_dir.join("telegram-state.json"),
            r#"{"version": 99, "offset": 0}"#,
        )
        .unwrap();
        let (mut ctx, g) = ctx_for(&dir);
        let err = run_telegram(&mut ctx, &g).unwrap_err();
        assert_eq!(flow_code(&err), 1);
        assert!(ctx.out.stdout.is_empty());
    }

    #[test]
    fn ensure_node_id_persists_and_adopts() {
        let dir = temp_dir("nodeid-persist");
        write_config(&dir, r#"{"profiles":{"alpha":{}}}"#);
        let (mut ctx, g) = ctx_for(&dir);
        let loc = resolve_config(&mut ctx, &g, false).unwrap();
        let (single, _) = load_single_config(&loc.config_dir).unwrap();
        let single = single.unwrap();
        let prof = load_profile(&loc.config_dir, "alpha", ctx.getenv).unwrap();
        let id = ensure_node_id(&loc, &single, &prof, ctx.getenv).unwrap();
        assert_eq!(id.len(), 16);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
        // The file now carries it, and a second call
        // returns the same id (already set → no-op).
        let (single2, _) = load_single_config(&loc.config_dir).unwrap();
        let single2 = single2.unwrap();
        let prof2 = load_profile(&loc.config_dir, "alpha", ctx.getenv).unwrap();
        assert_eq!(prof2.node_id, id);
        assert_eq!(
            ensure_node_id(&loc, &single2, &prof2, ctx.getenv).unwrap(),
            id
        );
    }

    #[test]
    fn ensure_node_id_env_wins_in_memory() {
        let dir = temp_dir("nodeid-env");
        write_config(&dir, r#"{"profiles":{"alpha":{}}}"#);
        let (mut ctx, g) = ctx_for(&dir);
        let loc = resolve_config(&mut ctx, &g, false).unwrap();
        let (single, _) = load_single_config(&loc.config_dir).unwrap();
        let single = single.unwrap();
        let prof = load_profile(&loc.config_dir, "alpha", ctx.getenv).unwrap();
        let getenv = |k: &str| {
            if k == "MUSE_NODE_ID" {
                Some("RAW-ENV-ID".to_string())
            } else {
                None
            }
        };
        let id = ensure_node_id(&loc, &single, &prof, Some(&getenv)).unwrap();
        assert_eq!(id, "RAW-ENV-ID");
        // The file is untouched: env wins in-memory only.
        let after = fs::read_to_string(dir.join("config.json")).unwrap();
        assert!(!after.contains("node_id"));
    }

    #[test]
    fn bot_error_mapping_shapes() {
        let api_401 = BotError::Api {
            code: 401,
            description: "Unauthorized".to_string(),
            retry_after: None,
        };
        let err = bot_construction_error(&api_401);
        assert_eq!(flow_code(&err), 1);
        // Exact Go text, measured live on cue (fake
        // token): `error call getMe, unauthorized,
        // Unauthorized`.
        assert_eq!(
            flow_message(&err),
            "telegram: bot construction failed: error call getMe, unauthorized, Unauthorized"
        );
        // 429 renders the TooManyRequests shape; an
        // unmapped code renders the default shape.
        let api_429 = BotError::Api {
            code: 429,
            description: "Too Many Requests".to_string(),
            retry_after: Some(30),
        };
        assert_eq!(
            flow_message(&bot_construction_error(&api_429)),
            "telegram: bot construction failed: error call getMe, too many requests, Too Many Requests: retry_after 30"
        );
        let api_500 = BotError::Api {
            code: 500,
            description: "Internal Server Error".to_string(),
            retry_after: None,
        };
        assert_eq!(
            flow_message(&bot_construction_error(&api_500)),
            "telegram: bot construction failed: error call getMe, error response from telegram for method getMe, 500 Internal Server Error"
        );
        assert_eq!(
            flow_code(&bot_construction_error(&BotError::Cancelled)),
            130
        );
        assert_eq!(flow_code(&bot_run_error(&BotError::Cancelled)), 130);
        assert_eq!(flow_code(&bot_run_error(&api_401)), 1);
    }
}
