// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Dispatch: `scanGlobal`, `resolveConfig`, the eight
//! subcommand dispatchers, `classifyError`'s plain branch, and the
//! M2 stub (D-M2-3).
//!
//! Sources at base `dev-rust` `85a8d5e`: `internal/commands/
//! commands.go` (`runInner`, `scanGlobal`, `resolveConfig`,
//! `parseOrHelp`, `classifyError`), `fs.go` (`cmdFS`, `fsParse`),
//! `profilecmd.go` (`cmdProfile`, `profileParse`, `cmdConfig`,
//! `cmdConfigMigrate`), `deliver.go` (`cmdAuth`), `keeper.go`
//! (`cmdKeeper`, `parseKeeperSelection`), `telegram.go`
//! (`cmdTelegram`), `webui.go` (`cmdWebUI`), `plugincheck.go`
//! (`cmdPlugin`), `authimport.go` / `authlogin.go` /
//! `authstatus.go` / `authobserve.go`, `read.go` (`usageErr`),
//! `wait.go` (`parseAutoToggles`, `approveDecision`,
//! `cmdAutoApprove`), `deliver/authexport.go` (`ExportGuidance`).
//!
//! Only the offline surface is wired. Every command that would
//! need the network, the gateway, a browser, or migrate execution
//! ends in the stub (exit 1) after the checks Go performs before
//! touching those: global scan, parse, positional checks,
//! config-location resolution, and parsing the resolved config
//! file (F5). The stub sits BEFORE active-profile resolution
//! (D-M2-3).

use std::sync::{Arc, Mutex};

use castctl_config::blocks::valid_plugin_id;
use castctl_config::config::{SingleConfig, load_single_config};
use castctl_config::configlocation::{ConfigLocation, Getenv, resolve_config_location};
use castctl_config::errors::ConfigError;
use castctl_config::gostr::{go_quote, go_trim_space};
use castctl_config::log::valid_log_level;
use std::path::Path;

use crate::help_texts::*;
use crate::parser::{ArgParser, Parsed, ParserError, check_positionals};
use crate::table::{
    COMMAND_ORDER, CommandSpec, FS_SUBCOMMANDS, KEEPER_SUBCOMMANDS, PROFILE_SUBCOMMANDS,
    PositionalSpec, TELEGRAM_SUBCOMMANDS, auth_sub_defs, command_spec, fs_defs, keeper_sub_help,
    profile_sub_defs, profile_sub_help,
};

/// The Rust `--version` payload (D-M2-7): the bare version, no
/// stamp. Go's `commands.go` `Version` var defaults to `0.6.1` and
/// release builds stamp `0.9.0` via `-X`; the Rust const is the
/// stamped release version the golden binary reports.
pub const VERSION: &str = "0.9.0";

/// `ExportGuidance` (`internal/deliver/authexport.go`): the fixed
/// guidance `auth export` prints on stderr with exit 1. Verbatim.
pub const EXPORT_GUIDANCE: &str = "cookie export is not available in this build: no automatic cookie extraction is implemented yet.\n\nLog in at https://muse.ai/ in your browser, leave the tab open, and run \"castctl auth export\" again after a cookie source exists.\n\nCopy the login by hand instead:\n  1. In your browser, open https://muse.ai/ and log in.\n  2. Open the browser developer tools and read the cookies for https://muse.ai/.\n  3. Write one line to the active profile's cookies.txt file:\n       hatch_sess=VALUE; other_name=other_value\n     hatch_sess is required. Separate cookies with \"; \".\n  4. Set the file mode to 600.\n  5. Run \"castctl status\" to check the login.\n\nNo file was written or changed.";

/// Captured process output: stdout text, stderr text, exit code.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Outcome {
    /// Bytes written to stdout.
    pub stdout: String,
    /// Raw bytes written to stdout (`fs cat --binary`:
    /// arbitrary bytes cannot go through the `String`
    /// above; no command emits both text and raw bytes,
    /// so the binary writes text first, then these).
    pub stdout_bytes: Vec<u8>,
    /// Bytes written to stderr.
    pub stderr: String,
    /// Process exit code.
    pub code: i32,
}

/// Global pre-scan results (`commands.go`, `globalOpts`).
#[derive(Debug, Clone, Default)]
pub struct GlobalOpts {
    /// `--profile` value when the flag was set.
    pub profile_flag: String,
    /// Whether `--profile` was set (even to an empty value).
    pub profile_set: bool,
    /// `--config` value when the flag was set.
    pub config_flag: String,
    /// Whether `--config` was set.
    pub config_set: bool,
    /// `--log-level` value when the flag was set.
    pub log_level_flag: String,
    /// Whether `--log-level` was set.
    pub log_level_set: bool,
}

/// A handler failure. `HelpShown` is Go's `errHelpShown` sentinel
/// (exit 0, nothing more printed). `Msg` is Go's `errCode` plain
/// branch: `classifyError` appends `castctl: <message>` when the
/// message is non-empty, and prints nothing when it is empty.
/// `Exit` returns a bare exit code with no classify line (the
/// `auth export` guidance, which is itself the classify text).
/// `Verbatim` is Go's typed-auth JSON line (`classifyError`'s
/// `typedAuthError` / bare `AuthError` branch): the text is
/// printed to stderr exactly as-is (one compact JSON line, no
/// `castctl: ` prefix), plus a trailing newline (M4b).
#[derive(Debug)]
pub(crate) enum FlowErr {
    HelpShown,
    Msg { code: i32, message: Option<String> },
    Exit(i32),
    Verbatim { code: i32, text: String },
}

pub(crate) fn msg(code: i32, message: impl Into<String>) -> FlowErr {
    FlowErr::Msg {
        code,
        message: Some(message.into()),
    }
}

pub(crate) fn msg_empty(code: i32) -> FlowErr {
    FlowErr::Msg {
        code,
        message: None,
    }
}

/// `usageErr` (`read.go:1075`): a positional error becomes
/// `errCode(2, pe)` with NOTHING pre-printed, so `classifyError`
/// prints exactly one line. `pub(crate)` for the `fs` handler,
/// which validates positionals in the same way.
pub(crate) fn usage_err(pe: ParserError) -> FlowErr {
    msg(2, pe.0)
}

/// The outcome under construction, threaded through handlers the
/// way Go threads `Env` stdout/stderr writers.
pub(crate) struct Ctx<'a> {
    pub(crate) out: Outcome,
    pub(crate) getenv: Getenv<'a>,
}

impl<'a> Ctx<'a> {
    fn getenv(&self, key: &str) -> Option<String> {
        match self.getenv {
            Some(getenv) => getenv(key),
            None => std::env::var_os(key).map(|v| v.to_string_lossy().into_owned()),
        }
    }
}

/// `parseOrHelp` (`commands.go:1039`): parser errors print two
/// lines, then `classifyError` prints a third identical message
/// line.
fn parse_or_help(
    ctx: &mut Ctx<'_>,
    spec: &CommandSpec,
    args: &[String],
) -> Result<Parsed, FlowErr> {
    let ap = ArgParser {
        defs: spec.defs.clone(),
        help_text: spec.help_text,
    };
    match ap.parse(args, &mut ctx.out.stdout) {
        Ok(outcome) => {
            if outcome.help_shown {
                Err(FlowErr::HelpShown)
            } else {
                Ok(outcome.parsed)
            }
        }
        Err(pe) => {
            ctx.out.stderr.push_str(&format!("castctl: {}\n", pe.0));
            ctx.out
                .stderr
                .push_str(&format!("usage: castctl {}\n", spec.usage_line));
            Err(msg(2, pe.0))
        }
    }
}

/// The inline-parser shape (`auth list`, `keeper` selection,
/// `webui serve`, `plugin check`, `config migrate`, profile
/// subcommands): parser errors print ONE line, then
/// `classifyError` prints a second identical line.
fn inline_parse(
    ctx: &mut Ctx<'_>,
    defs: Vec<crate::parser::FlagDef>,
    help_text: &'static str,
    args: &[String],
) -> Result<Parsed, FlowErr> {
    let ap = ArgParser { defs, help_text };
    match ap.parse(args, &mut ctx.out.stdout) {
        Ok(outcome) => {
            if outcome.help_shown {
                Err(FlowErr::HelpShown)
            } else {
                Ok(outcome.parsed)
            }
        }
        Err(pe) => {
            ctx.out.stderr.push_str(&format!("castctl: {}\n", pe.0));
            Err(msg(2, pe.0))
        }
    }
}

/// `profileParse` (`profilecmd.go:84`): same one-line shape as the
/// inline parsers.
fn profile_parse(
    ctx: &mut Ctx<'_>,
    defs: Vec<crate::parser::FlagDef>,
    help_text: &'static str,
    args: &[String],
) -> Result<Parsed, FlowErr> {
    inline_parse(ctx, defs, help_text, args)
}

/// `fsParse` (`fs.go:196`): parser errors print the message plus
/// `usage: castctl fs <sub>`, then `classifyError` prints a third
/// line.
fn fs_parse(ctx: &mut Ctx<'_>, sub: &str, args: &[String]) -> Result<Parsed, FlowErr> {
    let (defs, help_text) = fs_defs(sub);
    let ap = ArgParser { defs, help_text };
    match ap.parse(args, &mut ctx.out.stdout) {
        Ok(outcome) => {
            if outcome.help_shown {
                Err(FlowErr::HelpShown)
            } else {
                Ok(outcome.parsed)
            }
        }
        Err(pe) => {
            ctx.out.stderr.push_str(&format!("castctl: {}\n", pe.0));
            ctx.out
                .stderr
                .push_str(&format!("usage: castctl fs {sub}\n"));
            Err(msg(2, pe.0))
        }
    }
}

/// `resolveConfig` (`commands.go:982`): the `--config` empty check,
/// location resolution (warnings printed first), the basename
/// rule, and `RequirePresent` unless `allow_missing_create`.
/// `pub(crate)` for the `auto-approve` handler (M7b), which
/// resolves config itself instead of going through the
/// network path.
pub(crate) fn resolve_config(
    ctx: &mut Ctx<'_>,
    g: &GlobalOpts,
    allow_missing_create: bool,
) -> Result<ConfigLocation, FlowErr> {
    if g.config_set && go_trim_space(&g.config_flag).is_empty() {
        return Err(msg(2, "--config requires a non-empty path"));
    }
    let explicit = if g.config_set {
        g.config_flag.as_str()
    } else {
        ""
    };
    let loc = match resolve_config_location(explicit, ctx.getenv) {
        Ok(loc) => loc,
        Err(e) => return Err(config_err(e)),
    };
    for w in &loc.warnings {
        ctx.out.stderr.push_str(&format!("castctl: warning: {w}\n"));
    }
    let base = loc
        .config_file
        .rsplit('/')
        .next()
        .unwrap_or(&loc.config_file);
    if base != "config.json" {
        return Err(msg(
            2,
            format!(
                "--config path {} must name a config.json file",
                go_quote(&loc.config_file)
            ),
        ));
    }
    if !allow_missing_create && let Err(e) = loc.require_present() {
        return Err(config_err(e));
    }
    Ok(loc)
}

/// A `profile.Error` / `ConfigError` through `classifyError`: exit
/// `e.code`, one `castctl: <message>` line. A profile error is
/// exit 2 and the message already carries the `profile: ` prefix
/// exactly once; a raw I/O error (`raw_io_error`, fix loop 2) is
/// exit 1 with the Go `*PathError` / `*LinkError` text verbatim.
pub(crate) fn config_err(e: ConfigError) -> FlowErr {
    msg(e.code, e.message)
}

/// `resolve_config` + config parse, returning the parsed single
/// config (M4b network path): the runtime builder needs the
/// parsed config (outbounds/endpoints for tag dispatch), so
/// unlike `resolve_and_load` this keeps it. `None` is a legacy
/// flat file (no `profiles` marker): the runtime builder's
/// profile resolution refuses it with exit 2, as Go's
/// `LoadProfile` does.
pub(crate) fn resolve_and_load_single(
    ctx: &mut Ctx<'_>,
    g: &GlobalOpts,
) -> Result<(ConfigLocation, Option<SingleConfig>), FlowErr> {
    let loc = resolve_config(ctx, g, false)?;
    let (single, _found) = load_single_config(&loc.config_dir).map_err(config_err)?;
    Ok((loc, single))
}

/// `scanGlobal` (`commands.go:865`): sequential pre-scan of flags
/// before the command name. `Done` means Run returns immediately.
enum Scan {
    Done(i32),
    Command(GlobalOpts, String, Vec<String>),
}

fn scan_global(ctx: &mut Ctx<'_>, args: &[String]) -> Scan {
    let mut g = GlobalOpts::default();
    let mut i = 0usize;
    while i < args.len() {
        let tok = args[i].clone();
        if tok == "--" {
            i += 1;
            if i < args.len() {
                return Scan::Command(g, args[i].clone(), args[i + 1..].to_vec());
            }
            return Scan::Command(g, String::new(), Vec::new());
        } else if tok == "--version" || tok == "--vers" || tok.starts_with("--version=") {
            if let Some(eq) = tok.find('=') {
                ctx.out.stderr.push_str(&format!(
                    "castctl: argument --version: ignored explicit argument {}\n",
                    go_quote(&tok[eq + 1..])
                ));
                return Scan::Done(2);
            }
            ctx.out.stdout.push_str(&format!("castctl {VERSION}\n"));
            return Scan::Done(0);
        } else if tok == "--help" || tok == "-h" || tok == "--hel" {
            ctx.out.stdout.push_str(GLOBAL_HELP_TEXT);
            return Scan::Done(0);
        } else if tok == "--profile"
            || tok == "--config"
            || tok.starts_with("--profile=")
            || tok.starts_with("--config=")
        {
            let is_profile = tok.starts_with("--profile");
            let val = match tok.find('=') {
                Some(eq) => tok[eq + 1..].to_string(),
                None => {
                    if i + 1 >= args.len() || (args[i + 1].starts_with('-') && args[i + 1] != "-") {
                        let name = if is_profile { "--profile" } else { "--config" };
                        ctx.out.stderr.push_str(&format!(
                            "castctl: argument {name}: expected one argument\n"
                        ));
                        return Scan::Done(2);
                    }
                    i += 1;
                    args[i].clone()
                }
            };
            if is_profile {
                g.profile_flag = val;
                g.profile_set = true;
            } else {
                g.config_flag = val;
                g.config_set = true;
            }
        } else if tok.starts_with("--") {
            let name_val = tok.strip_prefix("--").unwrap_or_default();
            let name = match name_val.find('=') {
                Some(eq) => &name_val[..eq],
                None => name_val,
            };
            if "log-level".starts_with(name) && !name.is_empty() {
                let val = match tok.find('=') {
                    Some(eq) => tok[eq + 1..].to_string(),
                    None => {
                        if i + 1 >= args.len()
                            || (args[i + 1].starts_with('-') && args[i + 1] != "-")
                        {
                            ctx.out
                                .stderr
                                .push_str("castctl: argument --log-level: expected one argument\n");
                            return Scan::Done(2);
                        }
                        i += 1;
                        args[i].clone()
                    }
                };
                if !valid_log_level(&val) {
                    ctx.out.stderr.push_str("castctl: argument --log-level: invalid log level (expected trace, debug, info, warn, warning, error, fatal, or panic)\n");
                    return Scan::Done(2);
                }
                g.log_level_flag = val;
                g.log_level_set = true;
            } else if "profile".starts_with(name) || "config".starts_with(name) {
                let is_profile = "profile".starts_with(name);
                let val = match tok.find('=') {
                    Some(eq) => tok[eq + 1..].to_string(),
                    None => {
                        if i + 1 >= args.len()
                            || (args[i + 1].starts_with('-') && args[i + 1] != "-")
                        {
                            ctx.out.stderr.push_str(&format!(
                                "castctl: argument --{name}: expected one argument\n"
                            ));
                            return Scan::Done(2);
                        }
                        i += 1;
                        args[i].clone()
                    }
                };
                if is_profile {
                    g.profile_flag = val;
                    g.profile_set = true;
                } else {
                    g.config_flag = val;
                    g.config_set = true;
                }
            } else if "help".starts_with(name) {
                ctx.out.stdout.push_str(GLOBAL_HELP_TEXT);
                return Scan::Done(0);
            } else if "version".starts_with(name) {
                ctx.out.stdout.push_str(&format!("castctl {VERSION}\n"));
                return Scan::Done(0);
            } else {
                ctx.out
                    .stderr
                    .push_str(&format!("castctl: unrecognized argument: {tok}\n"));
                return Scan::Done(2);
            }
        } else if tok.starts_with('-') && tok.len() > 1 && tok != "-" {
            ctx.out
                .stderr
                .push_str(&format!("castctl: unrecognized argument: {tok}\n"));
            return Scan::Done(2);
        } else {
            return Scan::Command(g, tok, args[i + 1..].to_vec());
        }
        i += 1;
    }
    Scan::Command(g, String::new(), Vec::new())
}

/// `runInner` + `classifyError`'s plain branch (`commands.go`).
/// `args` excludes argv\[0\]. Non-UTF8 argv is lossy-converted by
/// the binary (documented approximation).
pub fn run(args: &[String], getenv: Getenv<'_>) -> Outcome {
    let mut ctx = Ctx {
        out: Outcome::default(),
        getenv,
    };
    run_inner(&mut ctx, args)
}

fn run_inner(ctx: &mut Ctx<'_>, args: &[String]) -> Outcome {
    let (g, mut cmd_name, mut cmd_args) = match scan_global(ctx, args) {
        Scan::Done(code) => {
            ctx.out.code = code;
            return std::mem::take(&mut ctx.out);
        }
        Scan::Command(g, name, rest) => (g, name, rest),
    };
    if cmd_name.is_empty() {
        // Bare invocation = chat in Python; the remaining args are
        // discarded (Go replaces cmdArgs with nil).
        cmd_name = "chat".to_string();
        cmd_args = Vec::new();
    }
    let spec = match command_spec(&cmd_name) {
        Some(spec) => spec,
        None => {
            ctx.out.stderr.push_str(&format!(
                "castctl: argument cmd: invalid choice: {} (choose from {})\n",
                go_quote(&cmd_name),
                COMMAND_ORDER.join(", ")
            ));
            ctx.out.stderr.push_str(GLOBAL_HELP_TEXT);
            ctx.out.code = 2;
            return std::mem::take(&mut ctx.out);
        }
    };
    let result = match cmd_name.as_str() {
        "fs" => cmd_fs(ctx, &g, &cmd_args),
        "auth" => cmd_auth(ctx, &g, &cmd_args),
        "profile" => cmd_profile(ctx, &g, &cmd_args),
        "config" => cmd_config(ctx, &g, &cmd_args),
        "telegram" => cmd_telegram(ctx, &g, &cmd_args),
        "keeper" => cmd_keeper(ctx, &g, &cmd_args),
        "webui" => cmd_webui(ctx, &g, &cmd_args),
        "plugin" => cmd_plugin(ctx, &cmd_args),
        "update" => cmd_update(ctx, &spec, &cmd_args),
        _ => cmd_plain(ctx, &g, &spec, &cmd_args),
    };
    match result {
        Ok(()) => {
            ctx.out.code = 0;
        }
        Err(FlowErr::HelpShown) => {
            ctx.out.code = 0;
        }
        Err(FlowErr::Exit(code)) => {
            ctx.out.code = code;
        }
        Err(FlowErr::Verbatim { code, text }) => {
            if !text.is_empty() {
                ctx.out.stderr.push_str(&text);
                ctx.out.stderr.push('\n');
            }
            ctx.out.code = code;
        }
        Err(FlowErr::Msg { code, message }) => {
            if let Some(m) = message {
                ctx.out.stderr.push_str(&format!("castctl: {m}\n"));
            }
            ctx.out.code = code;
        }
    }
    std::mem::take(&mut ctx.out)
}

/// The 13 read-only commands (M4b): they run the network path.
/// `invite` is NOT here: it is wired via `M7B_COMMANDS` below (it has
/// `--create`, a POST). `history --download` is NOT here either:
/// it is checked separately below and stubbed.
const READ_COMMANDS: [&str; 13] = [
    "status",
    "usage",
    "threads",
    "history",
    "files",
    "feed",
    "feed-status",
    "feed-prompt",
    "goals",
    "goal",
    "ideas",
    "idea",
    "unread",
];

/// A `parseOrHelp` command: parse, positional/manual checks,
/// `parseAutoToggles` for wait/send, then config-location
/// resolution + config parse, then the stub — except the 13
/// read-only commands (M4b) and the 19 M7b Phase A commands,
/// which run the network path, `wait` (M7a) and `send`,
/// `watch` and `chat` (PR-2), which run their own paths,
/// and `auto-approve`, which resolves config + profile
/// itself (no network). `history --download` is NOT in
/// the network set: it is checked separately below and
/// stubbed.
fn cmd_plain(
    ctx: &mut Ctx<'_>,
    g: &GlobalOpts,
    spec: &CommandSpec,
    args: &[String],
) -> Result<(), FlowErr> {
    let p = parse_or_help(ctx, spec, args)?;
    check_spec_positionals(ctx, spec, &p)?;
    if spec.name == "wait" || spec.name == "send" {
        parse_auto_toggles(&p)?;
    }
    if spec.name == "wait" {
        return crate::wait::run_wait_command(ctx, g, &p);
    }
    if spec.name == "send" {
        return crate::send::run_send_command(ctx, g, &p);
    }
    if spec.name == "watch" {
        return crate::watch::run_watch_command(ctx, g, &p);
    }
    if spec.name == "chat" {
        return crate::chat::run_chat_command(ctx, g, &p);
    }
    if spec.name == "auto-approve" {
        return crate::autoapprove::run_auto_approve(ctx, g, &p);
    }
    if READ_COMMANDS.contains(&spec.name) {
        return crate::network::run_network_command(ctx, g, spec, &p);
    }
    if M7B_COMMANDS.contains(&spec.name) {
        return crate::network::run_network_command(ctx, g, spec, &p);
    }
    // Unreachable for every known command name: the names
    // reaching `cmd_plain` are exactly `wait` / `send` /
    // `watch` / `chat` / `auto-approve` + `READ_COMMANDS` +
    // `M7B_COMMANDS` (proven by
    // `test_cmd_plain_fallthrough_unreachable` below), and
    // unknown names exit 2 in `command_spec` before dispatch.
    // A defensive internal error, never a stub (M7b PR-3,
    // R2 §6.1; PORTING §M7b.13).
    Err(msg(
        1,
        format!("internal error: unhandled command {:?}", spec.name),
    ))
}

/// The 19 M7b Phase A network commands (PR-1) plus `raw`
/// (the 20th attempt): wired to the real gateway/HTTPS
/// through the network path. `auto-approve` is NOT here —
/// it resolves config + profile itself (no network; see
/// the branch above).
const M7B_COMMANDS: [&str; 19] = [
    "session-start",
    "session-rename",
    "session-pin",
    "session-unpin",
    "session-archive",
    "session-unarchive",
    "session-delete",
    "stop",
    "seen",
    "feed-react",
    "idea-exec",
    "approvals",
    "approve",
    "deny",
    "invite",
    "redeem",
    "wake",
    "download",
    "raw",
];

/// Positional/manual checks shared by `parseOrHelp` commands, in
/// Go handler order (positionals before toggles/decision).
fn check_spec_positionals(
    _ctx: &mut Ctx<'_>,
    spec: &CommandSpec,
    p: &Parsed,
) -> Result<(), FlowErr> {
    match spec.positionals {
        PositionalSpec::Names(names) => check_positionals(p, names).map_err(usage_err),
        PositionalSpec::AtMostOne => {
            if p.positionals.len() > 1 {
                return Err(usage_err(ParserError(format!(
                    "unrecognized arguments: {}",
                    p.positionals[1..].join(" ")
                ))));
            }
            Ok(())
        }
        PositionalSpec::FeedReact => {
            if p.positionals.is_empty() {
                return Err(usage_err(ParserError(
                    "the following arguments are required: unit".to_string(),
                )));
            }
            if p.positionals.len() > 2 {
                return Err(usage_err(ParserError(format!(
                    "unrecognized arguments: {}",
                    p.positionals[2..].join(" ")
                ))));
            }
            Ok(())
        }
        PositionalSpec::Approve => {
            if p.positionals.len() > 1 {
                return Err(usage_err(ParserError(format!(
                    "unrecognized arguments: {}",
                    p.positionals[1..].join(" ")
                ))));
            }
            approve_decision(p)?;
            let id = if p.positionals.len() == 1 {
                p.positionals[0].as_str()
            } else {
                ""
            };
            if p.bool("all") == !id.is_empty() {
                return Err(msg(2, "give an approval ID or --all (not both)"));
            }
            Ok(())
        }
        PositionalSpec::AutoApprove => {
            if p.positionals.len() > 2 {
                return Err(usage_err(ParserError(format!(
                    "unrecognized arguments: {}",
                    p.positionals[2..].join(" ")
                ))));
            }
            let state = if p.positionals.is_empty() {
                "status"
            } else {
                p.positionals[0].as_str()
            };
            let once_state = if p.positionals.len() == 2 {
                p.positionals[1].as_str()
            } else {
                ""
            };
            match state {
                "on" | "always" | "off" | "status" | "once" => {}
                _ => {
                    return Err(msg(
                        2,
                        format!(
                            "argument state: invalid choice: {} (choose from on, always, off, status, once)",
                            go_quote(state)
                        ),
                    ));
                }
            }
            match once_state {
                "" | "on" | "off" | "status" => {}
                _ => {
                    return Err(msg(
                        2,
                        format!(
                            "argument once_state: invalid choice: {} (choose from on, off, status)",
                            go_quote(once_state)
                        ),
                    ));
                }
            }
            if !once_state.is_empty() && state != "once" {
                return Err(msg(
                    2,
                    format!(
                        "unexpected {}: use `auto-approve once on|off|status`",
                        go_quote(once_state)
                    ),
                ));
            }
            Ok(())
        }
        PositionalSpec::None => Ok(()),
    }
}

/// `approveDecision` (`wait.go:1277`): at most one of
/// once/session/today/always; the second reports the first as the
/// conflicting argument.
fn approve_decision(p: &Parsed) -> Result<(), FlowErr> {
    let mut seen: Option<&str> = None;
    for k in ["once", "session", "today", "always"] {
        if p.bool(k) {
            if let Some(first) = seen {
                return Err(msg(
                    2,
                    format!("argument --{k}: not allowed with argument --{first}"),
                ));
            }
            seen = Some(k);
        }
    }
    Ok(())
}

/// `parseAutoToggles` (`wait.go:70`): both halves of a pair is a
/// usage error; the approve pair is checked first.
fn parse_auto_toggles(p: &Parsed) -> Result<(), FlowErr> {
    if p.bool("auto-approve") && p.bool("no-auto-approve") {
        return Err(msg(
            2,
            "argument --no-auto-approve: not allowed with argument --auto-approve",
        ));
    }
    if p.bool("auto-allow-once") && p.bool("no-auto-allow-once") {
        return Err(msg(
            2,
            "argument --no-auto-allow-once: not allowed with argument --auto-allow-once",
        ));
    }
    Ok(())
}

/// `cmdUpdate` (`update.go:72`): parse + positionals, then NO
/// config load (release downloads are public URLs). Wired in
/// M7b PR-3 (`crate::update`); Go has no `--check` flag —
/// `--dry-run` is the check mode (D-M7b-PR3-7).
fn cmd_update(ctx: &mut Ctx<'_>, spec: &CommandSpec, args: &[String]) -> Result<(), FlowErr> {
    let p = parse_or_help(ctx, spec, args)?;
    check_positionals(&p, &[]).map_err(usage_err)?;
    crate::update::run_update(
        ctx,
        p.bool("dry-run"),
        &p.str("version"),
        p.bool("allow-downgrade"),
        p.bool("allow-prerelease"),
    )
}

/// `cmdFS` (`fs.go:141`) + per-subcommand `fsParse` /
/// `validate_fs` (positionals, `rm` --yes, traversal
/// reject, `norm`), then `run_fs_command` (config +
/// runtime + `exec_fs`).
fn cmd_fs(ctx: &mut Ctx<'_>, g: &GlobalOpts, args: &[String]) -> Result<(), FlowErr> {
    if args.is_empty() {
        ctx.out
            .stderr
            .push_str("castctl: the following arguments are required: subcommand\n");
        ctx.out.stderr.push_str(FS_HELP_TEXT);
        return Err(msg_empty(2));
    }
    if args[0] == "--help" || args[0] == "-h" {
        ctx.out.stdout.push_str(FS_HELP_TEXT);
        return Err(FlowErr::HelpShown);
    }
    let sub = args[0].as_str();
    let rest = &args[1..];
    if !FS_SUBCOMMANDS.contains(&sub) {
        ctx.out.stderr.push_str(&format!(
            "castctl: argument subcommand: invalid choice: {} (choose from {})\n",
            go_quote(sub),
            FS_SUBCOMMANDS.join(", ")
        ));
        return Err(msg_empty(2));
    }
    let p = fs_parse(ctx, sub, rest)?;
    crate::fs::validate_fs(sub, &p)?;
    // `fs write` reads stdin BEFORE connecting (Go
    // `fs.go:584-596`: stdin is read before `runFS`).
    let stdin_data = if sub == "write" {
        let mut data = Vec::new();
        std::io::Read::read_to_end(&mut std::io::stdin(), &mut data)
            .map_err(|e| msg(1, e.to_string()))?;
        Some(data)
    } else {
        None
    };
    crate::fs::run_fs_command(ctx, g, sub, &p, stdin_data)
}

/// `cmdAuth` (`deliver.go:71`) + subcommand parsers.
fn cmd_auth(ctx: &mut Ctx<'_>, g: &GlobalOpts, args: &[String]) -> Result<(), FlowErr> {
    if args.is_empty() {
        ctx.out
            .stderr
            .push_str("castctl: the following arguments are required: subcommand\n");
        ctx.out.stderr.push_str(AUTH_HELP_TEXT);
        return Err(msg_empty(2));
    }
    if args[0] == "--help" || args[0] == "-h" {
        ctx.out.stdout.push_str(AUTH_HELP_TEXT);
        return Err(FlowErr::HelpShown);
    }
    let sub = args[0].as_str();
    let rest = &args[1..];
    match sub {
        "list" => {
            let p = inline_parse(ctx, auth_sub_defs("list"), AUTH_LIST_HELP_TEXT, rest)?;
            check_positionals(&p, &[]).map_err(usage_err)?;
            let loc = resolve_config(ctx, g, false)?;
            crate::auth::run_auth_list(ctx, &loc, g, p.bool("json"))
        }
        "export" => {
            // No checkPositionals: extra positionals are silently
            // ignored (Go quirk). No config resolution. The
            // guidance prints on stderr with exit 1.
            let _ = inline_parse(ctx, vec![], AUTH_EXPORT_HELP_TEXT, rest)?;
            ctx.out.stderr.push_str(EXPORT_GUIDANCE);
            ctx.out.stderr.push('\n');
            Err(FlowErr::Exit(1))
        }
        "import" => {
            let p = inline_parse(ctx, vec![], AUTH_IMPORT_HELP_TEXT, rest)?;
            check_positionals(&p, &[]).map_err(usage_err)?;
            // Go reads stdin BEFORE config resolution
            // (`authimport.go:67-81`); `fs write` reads stdin
            // the same way (`run.rs`, `fs.go:584-596`).
            let mut stdin_data = Vec::new();
            std::io::Read::read_to_end(&mut std::io::stdin(), &mut stdin_data)
                .map_err(|e| msg(2, format!("read stdin: {e}")))?;
            crate::auth::run_auth_import(ctx, g, &stdin_data)
        }
        "login" => {
            let p = inline_parse(ctx, auth_sub_defs("login"), AUTH_LOGIN_HELP_TEXT, rest)?;
            check_positionals(&p, &[]).map_err(usage_err)?;
            let experimental = p.bool("experimental-login")
                || ctx.getenv("CASTCTL_EXPERIMENTAL_LOGIN").as_deref() == Some("1");
            if !experimental {
                return Err(msg(
                    2,
                    "auth login is experimental: pass --experimental-login (or set CASTCTL_EXPERIMENTAL_LOGIN=1), or use \"castctl auth import\" instead",
                ));
            }
            // Tag-off build (no with_chromedp): CDP export is
            // unavailable; the release builds carry no such tag.
            Err(msg(
                2,
                "auth login is not available in this build: rebuild with -tags with_chromedp",
            ))
        }
        "status" => {
            let p = inline_parse(ctx, auth_sub_defs("status"), AUTH_STATUS_HELP_TEXT, rest)?;
            check_positionals(&p, &[]).map_err(usage_err)?;
            let profile_name = if p.str_is_set("profile") {
                p.str("profile")
            } else {
                String::new()
            };
            if p.bool("all") && !profile_name.is_empty() {
                return Err(msg(
                    2,
                    "auth status: --profile and --all are mutually exclusive",
                ));
            }
            let (loc, single) = resolve_and_load_single(ctx, g)?;
            crate::auth::run_auth_status(
                ctx,
                &loc,
                single.as_ref(),
                g,
                &profile_name,
                p.bool("all"),
            )
        }
        "observe-login" => {
            let p = inline_parse(
                ctx,
                auth_sub_defs("observe-login"),
                AUTH_OBSERVE_LOGIN_HELP_TEXT,
                rest,
            )?;
            check_positionals(&p, &[]).map_err(usage_err)?;
            // Tag-off build (no with_chromedp): Go checks
            // `keeper.ReloginAvailable()` FIRST, before config
            // (`authobserve.go`), and the shipped Go binary is
            // built without the tag — the check fails there too,
            // so this fixed exit-2 error IS the faithful port
            // of the shipped build, not a stub (D-M7b-PR3-9).
            // The Rust build has no chromedp tag at all, and
            // the S2 loopback proxy has no Rust equivalent, so
            // no feature could enable this path (PORTING
            // §M7b.13).
            Err(msg(
                2,
                "auth observe-login is not available in this build: rebuild with -tags with_chromedp",
            ))
        }
        _ => {
            ctx.out.stderr.push_str(&format!(
                "castctl: argument subcommand: invalid choice: {} (choose from list, export, import, login, status, observe-login)\n",
                go_quote(sub)
            ));
            Err(msg_empty(2))
        }
    }
}

/// `cmdProfile` (`profilecmd.go:52`) + `profileParse` subcommands.
fn cmd_profile(ctx: &mut Ctx<'_>, g: &GlobalOpts, args: &[String]) -> Result<(), FlowErr> {
    if args.is_empty() {
        ctx.out
            .stderr
            .push_str("castctl: the following arguments are required: subcommand\n");
        ctx.out.stderr.push_str(PROFILE_HELP_TEXT);
        return Err(msg_empty(2));
    }
    if args[0] == "--help" || args[0] == "-h" {
        ctx.out.stdout.push_str(PROFILE_HELP_TEXT);
        return Err(FlowErr::HelpShown);
    }
    let sub = args[0].as_str();
    let rest = &args[1..];
    if !PROFILE_SUBCOMMANDS.contains(&sub) {
        ctx.out.stderr.push_str(&format!(
            "castctl: argument subcommand: invalid choice: {} (choose from {})\n",
            go_quote(sub),
            PROFILE_SUBCOMMANDS.join(", ")
        ));
        return Err(msg_empty(2));
    }
    let p = profile_parse(ctx, profile_sub_defs(sub), profile_sub_help(sub), rest)?;
    match sub {
        "list" => {
            check_positionals(&p, &[]).map_err(usage_err)?;
        }
        "show" | "test" => {
            if p.positionals.len() > 1 {
                return Err(usage_err(ParserError(format!(
                    "unrecognized arguments: {}",
                    p.positionals[1..].join(" ")
                ))));
            }
        }
        "add" | "rm" => {
            check_positionals(&p, &["name"]).map_err(usage_err)?;
        }
        "set-outbound" => {
            // Go's positionals are ["name","file"]
            // (`profilecmd.go:579`); the M2 stub named the
            // second one "value" by mistake (R1 finding).
            check_positionals(&p, &["name", "file"]).map_err(usage_err)?;
        }
        "set-fingerprint" | "set-tls-engine" => {
            check_positionals(&p, &["name", "value"]).map_err(usage_err)?;
        }
        _ => {}
    }
    // `profile rm` refuses without --yes BEFORE config resolution
    // (`profilecmd.go:540`).
    if sub == "rm" && !p.bool("yes") {
        return Err(msg(
            2,
            format!(
                "refusing to remove profile {} without --yes",
                go_quote(&p.positionals[0])
            ),
        ));
    }
    // `profile add` rejects --outbound together with
    // --outbound-from-env BEFORE config resolution
    // (`profilecmd.go:408-412`).
    if sub == "add" && p.str_is_set("outbound") && p.bool("outbound-from-env") {
        return Err(msg(
            2,
            "--outbound and --outbound-from-env are mutually exclusive",
        ));
    }
    match sub {
        "list" => crate::profilecmd::run_list(ctx, g),
        "show" => crate::profilecmd::run_show(ctx, g, &p),
        "add" => crate::profilecmd::run_add(ctx, g, &p),
        "rm" => crate::profilecmd::run_rm(ctx, g, &p),
        "set-outbound" => crate::profilecmd::run_set_outbound(ctx, g, &p),
        "set-fingerprint" => crate::profilecmd::run_set_fingerprint(ctx, g, &p),
        "set-tls-engine" => crate::profilecmd::run_set_tls_engine(ctx, g, &p),
        "test" => crate::profiletest::run_test(ctx, g, &p),
        _ => unreachable!("subcommand validated against PROFILE_SUBCOMMANDS above"),
    }
}

/// `cmdConfig` / `cmdConfigMigrate` (`profilecmd.go:1093`).
fn cmd_config(ctx: &mut Ctx<'_>, g: &GlobalOpts, args: &[String]) -> Result<(), FlowErr> {
    if args.is_empty() {
        ctx.out
            .stderr
            .push_str("castctl: the following arguments are required: subcommand\n");
        ctx.out.stderr.push_str(CONFIG_HELP_TEXT);
        return Err(msg_empty(2));
    }
    if args[0] == "--help" || args[0] == "-h" {
        ctx.out.stdout.push_str(CONFIG_HELP_TEXT);
        return Err(FlowErr::HelpShown);
    }
    if args[0] != "migrate" {
        ctx.out.stderr.push_str(&format!(
            "castctl: argument subcommand: invalid choice: {} (choose from migrate)\n",
            go_quote(&args[0])
        ));
        return Err(msg_empty(2));
    }
    let rest = &args[1..];
    let p = inline_parse(
        ctx,
        vec![
            crate::parser::bool_flag("write"),
            crate::parser::str_flag("from"),
        ],
        CONFIG_MIGRATE_HELP_TEXT,
        rest,
    )?;
    check_positionals(&p, &[]).map_err(usage_err)?;
    let mut source_dir = String::new();
    if p.str_is_set("from") {
        source_dir = go_trim_space(&p.str("from")).to_string();
        if source_dir.is_empty() {
            return Err(usage_err(ParserError(
                "--from requires a non-empty directory".to_string(),
            )));
        }
    }
    // The handler resolves the config itself
    // (`write || source_dir != ""` is its
    // `allowMissingCreate`); the dispatcher only
    // absolutises `--from`, like Go's `filepath.Abs`.
    let source = if source_dir.is_empty() {
        String::new()
    } else {
        crate::profilecmd::absolutise_from(&source_dir)
    };
    crate::profilecmd::run_config_migrate(ctx, g, &source, p.bool("write"))
}

/// `cmdTelegram` (`telegram.go:95`) + run/status takes-no-args.
fn cmd_telegram(ctx: &mut Ctx<'_>, g: &GlobalOpts, args: &[String]) -> Result<(), FlowErr> {
    if args.is_empty() {
        ctx.out
            .stderr
            .push_str("castctl: the following arguments are required: subcommand\n");
        ctx.out.stderr.push_str(TELEGRAM_HELP_TEXT);
        return Err(msg_empty(2));
    }
    if args[0] == "--help" || args[0] == "-h" {
        ctx.out.stdout.push_str(TELEGRAM_HELP_TEXT);
        return Err(FlowErr::HelpShown);
    }
    let sub = args[0].as_str();
    let rest = &args[1..];
    if !TELEGRAM_SUBCOMMANDS.contains(&sub) {
        ctx.out.stderr.push_str(&format!(
            "castctl: argument subcommand: invalid choice: {} (choose from {})\n",
            go_quote(sub),
            TELEGRAM_SUBCOMMANDS.join(", ")
        ));
        return Err(msg_empty(2));
    }
    let help_text = if sub == "run" {
        TELEGRAM_RUN_HELP_TEXT
    } else {
        TELEGRAM_STATUS_HELP_TEXT
    };
    if !rest.is_empty() && (rest[0] == "--help" || rest[0] == "-h") {
        ctx.out.stdout.push_str(help_text);
        return Err(FlowErr::HelpShown);
    }
    if !rest.is_empty() {
        ctx.out.stderr.push_str(&format!(
            "castctl: telegram {sub} takes no arguments (got {})\n",
            go_quote(&rest[0])
        ));
        return Err(msg_empty(2));
    }
    match sub {
        "run" => crate::telegramcmd::run_telegram(ctx, g),
        "status" => crate::telegramcmd::run_status(ctx, g),
        _ => unreachable!("subcommand validated against TELEGRAM_SUBCOMMANDS above"),
    }
}

/// `cmdKeeper` (`keeper.go:116`) + `parseKeeperSelection`.
fn cmd_keeper(ctx: &mut Ctx<'_>, g: &GlobalOpts, args: &[String]) -> Result<(), FlowErr> {
    if args.is_empty() {
        ctx.out
            .stderr
            .push_str("castctl: the following arguments are required: subcommand\n");
        ctx.out.stderr.push_str(KEEPER_HELP_TEXT);
        return Err(msg_empty(2));
    }
    if args[0] == "--help" || args[0] == "-h" {
        ctx.out.stdout.push_str(KEEPER_HELP_TEXT);
        return Err(FlowErr::HelpShown);
    }
    let sub = args[0].as_str();
    let rest = &args[1..];
    if !KEEPER_SUBCOMMANDS.contains(&sub) {
        ctx.out.stderr.push_str(&format!(
            "castctl: argument subcommand: invalid choice: {} (choose from {})\n",
            go_quote(sub),
            KEEPER_SUBCOMMANDS.join(", ")
        ));
        return Err(msg_empty(2));
    }
    let p = inline_parse(
        ctx,
        vec![
            crate::parser::str_flag("tag"),
            crate::parser::str_flag("profile"),
        ],
        keeper_sub_help(sub),
        rest,
    )?;
    check_positionals(&p, &[]).map_err(usage_err)?;
    let tag = if p.str_is_set("tag") {
        p.str("tag")
    } else {
        String::new()
    };
    let profile = if p.str_is_set("profile") {
        p.str("profile")
    } else {
        String::new()
    };
    if !tag.is_empty() && !profile.is_empty() {
        return Err(msg(2, "keeper: --tag and --profile are mutually exclusive"));
    }
    match sub {
        "run" => crate::keepercmd::run_keeper(ctx, g, &tag, &profile),
        "check" => crate::keepercmd::run_check(ctx, g, &tag, &profile),
        "status" => crate::keepercmd::run_status(ctx, g, &tag, &profile),
        _ => unreachable!("subcommand validated against KEEPER_SUBCOMMANDS above"),
    }
}

/// `cmdWebUI` (`webui.go:83`) + `cmdWebUIServe`.
fn cmd_webui(ctx: &mut Ctx<'_>, g: &GlobalOpts, args: &[String]) -> Result<(), FlowErr> {
    if args.is_empty() {
        ctx.out
            .stderr
            .push_str("castctl: the following arguments are required: subcommand\n");
        ctx.out.stderr.push_str(WEBUI_HELP_TEXT);
        return Err(msg_empty(2));
    }
    if args[0] == "--help" || args[0] == "-h" {
        ctx.out.stdout.push_str(WEBUI_HELP_TEXT);
        return Err(FlowErr::HelpShown);
    }
    if args[0] != "serve" {
        ctx.out.stderr.push_str(&format!(
            "castctl: argument subcommand: invalid choice: {} (choose from serve)\n",
            go_quote(&args[0])
        ));
        ctx.out.stderr.push_str(WEBUI_HELP_TEXT);
        return Err(msg_empty(2));
    }
    let p = inline_parse(ctx, vec![], WEBUI_SERVE_HELP_TEXT, &args[1..])?;
    check_positionals(&p, &[]).map_err(usage_err)?;
    let loc = resolve_config(ctx, g, false)?;
    serve_webui(ctx, &loc)
}

/// `cmdWebUIServe` (`internal/commands/webui.go`): the
/// pre-serve sequence — load → block check → ui_dir
/// first → hash-on-start → bind → serve. Exit 2 config,
/// 1 runtime, 130 interrupt.
///
/// Seams not yet wired ("chưa nối"): cookie import /
/// restore are `None` (the handlers report 501) and the
/// screencast starter is `None` (status/start report
/// unavailable, never fake success). Live chats ARE wired
/// — as a failing seam that reports 502 (see the `chats`
/// wiring below); `None` would report 501, which no
/// production Go server ever emits. The screencast
/// availability seam is wired over the config file (keeper
/// entry with a browser URL), matching the server's
/// in-crate check.
///
/// NOTE: the startup line is pushed to `ctx.out.stderr`,
/// which the CLI buffers until the process exits (M2
/// architecture) — it does not appear live while the
/// server runs.
/// A chat seam with no Muse Runtime behind it: every call
/// fails with [`ChatSeamError`], which the handlers map to
/// the fixed 502 `upstream_error`. This is the M6b stand-in
/// for Go's live gateway seam failing (no live session):
/// list/history/start/op all 502, and send creates its job
/// (202) whose worker then fails the same way. No chat text
/// is ever served — there is none to serve.
fn failing_chat_deps() -> castctl_webui::chats::ChatDeps {
    use castctl_webui::chats::{ChatDeps, ChatSeamError};
    fn fail<T>() -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<T, ChatSeamError>> + Send + 'static>,
    > {
        Box::pin(async move { Err(ChatSeamError) })
    }
    ChatDeps {
        list_sessions: std::sync::Arc::new(|_, _| fail()),
        get_history: std::sync::Arc::new(|_, _, _| fail()),
        start_session: std::sync::Arc::new(|_, _| fail()),
        session_op: std::sync::Arc::new(|_, _, _, _| fail()),
        send_chat: std::sync::Arc::new(|_, _, _| fail()),
    }
}

fn serve_webui(ctx: &mut Ctx<'_>, loc: &ConfigLocation) -> Result<(), FlowErr> {
    use castctl_config::jsonvalue::JsonValue;
    use castctl_webui::auth::{hash_token, looks_like_bcrypt_hash};
    use castctl_webui::config::{effective_listen, resolve_webui};
    use castctl_webui::error::err_validation;
    use castctl_webui::guarded::sha256_hex;
    use castctl_webui::server::{Deps, NewServerError, Server};
    use castctl_webui::store::{load_config, save_guarded};

    let dir = Path::new(&loc.config_dir);
    // Go's LoadSingleConfig: a bad config exits 2 here
    // (config_err, `profile: ` prefix); a legacy flat file
    // parses as "not found" → the no-config-file message.
    let (single, found) = load_single_config(&loc.config_dir).map_err(config_err)?;
    if !found {
        return Err(msg(
            2,
            "webui serve: no config file: run \"castctl config migrate\" or create a config with a \"webui\" block first",
        ));
    }
    let Some(single) = single else {
        return Err(msg(
            2,
            "webui serve: no config file: run \"castctl config migrate\" or create a config with a \"webui\" block first",
        ));
    };
    let block = resolve_webui(single.webui_raw.as_ref()).map_err(|e| msg(2, e))?;
    let Some(block) = block else {
        return Err(msg(
            2,
            "webui serve: no \"webui\" block in config.json: add one (see docs/config.md) or use the CLI",
        ));
    };
    let listen = effective_listen(&block);
    let token = block.token.clone();
    if token.is_empty() {
        return Err(msg(
            2,
            "webui serve: no token configured: add a \"token\" to the \"webui\" block",
        ));
    }
    let mut cookies_files: Vec<String> = Vec::new();
    for p in single.profiles.values() {
        if !p.cookies_file.is_empty() {
            cookies_files.push(p.cookies_file.clone());
        }
    }
    // ui_dir FIRST: a present-but-broken value fails closed
    // (exit 2) before any token write-back; only an absent
    // key falls back to the embedded frontend.
    let mut ui_dir: Option<String> = None;
    let mut bundle_hash = castctl_webui::static_shell::bundle_sha256();
    if !block.ui_dir.trim().is_empty() {
        let root = castctl_webui::uidir::check_ui_dir(dir, block.ui_dir.trim(), &cookies_files)
            .map_err(|e| msg(2, webui_uidir_msg(&e.to_string())))?;
        let index = std::fs::read(root.join("index.html"))
            .map_err(|_| msg(2, "webui serve: ui_dir has no readable index.html"))?;
        bundle_hash = sha256_hex(&index);
        ui_dir = Some(root.to_string_lossy().into_owned());
    }
    // Hash-on-start (fail closed): a plaintext block token
    // is hashed and written back before serving; an
    // already-hashed token is used as-is and the file is
    // not touched (Go's early return in
    // hashWebUITokenOnStart). Any write-back failure maps
    // to the one fixed exit-2 message.
    let token_hash = if looks_like_bcrypt_hash(&token) {
        token.clone()
    } else {
        let load = load_config(dir).map_err(|_| {
            msg(
                2,
                "webui serve: failed to hash and store the \"webui\" token",
            )
        })?;
        let plaintext = token.clone();
        let outcome = save_guarded(&load, dir, "", false, move |doc| {
            let JsonValue::Object(doc_obj) = doc else {
                return Err(err_validation("config document must be a JSON object"));
            };
            // No `get_mut` on OrderedObject: clone the block,
            // mutate it, put it back (key order preserved).
            let Some(JsonValue::Object(mut webui)) = doc_obj.get("webui").cloned() else {
                return Err(err_validation("webui: no \"webui\" block"));
            };
            let current = match webui.get("token") {
                Some(JsonValue::Str(t)) => t.clone(),
                _ => String::new(),
            };
            if looks_like_bcrypt_hash(&current) {
                // A concurrent writer hashed first: use the
                // stored hash. The funnel still re-encodes
                // and writes the file, values unchanged (as
                // Go's UpdateSingleConfig does).
                return Ok(());
            }
            if current != plaintext {
                return Err(err_validation("webui: token changed during startup"));
            }
            let hash = hash_token(&plaintext).map_err(err_validation)?;
            webui.set("token", JsonValue::Str(hash));
            doc_obj.set("webui", JsonValue::Object(webui));
            Ok(())
        })
        .map_err(|_| {
            msg(
                2,
                "webui serve: failed to hash and store the \"webui\" token",
            )
        })?;
        match outcome.webui_token {
            Some(hash) => hash,
            None => {
                return Err(msg(
                    2,
                    "webui serve: failed to hash and store the \"webui\" token",
                ));
            }
        }
    };
    // The plaintext token is dead after the hash is
    // computed: drop it now (Go clears
    // `single.WebUI.Token = ""`) so it does not linger in
    // scope for the server's whole lifetime.
    drop(token);
    // Server construction: UIDirError → exit 2 (Go's
    // errCodef(2, "webui serve: %v", uidErr) — the doubled
    // "webui serve: webui: ..." prefix is Go's own text),
    // any other construction failure → exit 1.
    let avail_dir = dir.to_path_buf();
    let screencast_available = Arc::new(move |profile: &str| {
        let load = match load_config(&avail_dir) {
            Ok(l) => l,
            Err(e) => return (false, e.msg),
        };
        castctl_webui::screencast::screencast_availability(&avail_dir, &load, profile)
            .unwrap_or_else(|e| (false, e.msg))
    });
    let server = Server::new(Deps {
        config_dir: dir.to_path_buf(),
        version: VERSION.to_string(),
        listen_addr: listen.clone(),
        token_hash,
        has_token: true,
        bundle_sha256: bundle_hash,
        ui_dir,
        cookies_files,
        // Cookie import/restore stay None (501)
        // deliberately, unlike chats: no faithful failing
        // stand-in exists — a failing cookie seam would
        // fabricate a 400 where the live Go server succeeds
        // with 200 `saved: true` (the import path needs the
        // real profile store, which lands with the keeper
        // port). See PORTING §M6b.7.
        import_cookies: None,
        restore_cookies: None,
        screencast_available: Some(screencast_available),
        screencast_starter: None,
        // Chats: no Muse Runtime exists in this build, but the
        // production Go binary always wires a (live) chat seam,
        // so the seam is present and every call fails closed
        // with `upstream_error` (502) — exactly what the live
        // Go server returns for a profile with no live session.
        // Wiring None instead would report 501 `unavailable`
        // (Go's nil-seam branch, reachable only in Go's unit
        // tests), which no production Go server ever emits.
        chats: Some(std::sync::Arc::new(failing_chat_deps())),
    })
    .map_err(|e| match e {
        NewServerError::UIDir(m) => msg(2, format!("webui serve: {m}")),
        NewServerError::Config(m) => msg(1, format!("webui serve: {m}")),
    })?;
    let tokio_rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| msg(1, format!("failed to start async runtime: {e}")))?;
    let (code, err_text) = tokio_rt.block_on(async {
        let listener = match Server::bind(&listen).await {
            Ok(l) => l,
            Err(e) => {
                return (1, Some(format!("webui serve: listen {listen}: {e}")));
            }
        };
        ctx.out.stderr.push_str(&format!(
            "castctl: web UI listening on {listen} (loopback only, token auth)\n"
        ));
        let serve_fut = server.serve_on(listener);
        tokio::pin!(serve_fut);
        tokio::select! {
            res = &mut serve_fut => match res {
                Ok(()) => (0, None),
                Err(e) => (1, Some(format!("webui serve: {e}"))),
            },
            _ = tokio::signal::ctrl_c() => {
                server.request_shutdown();
                match serve_fut.await {
                    Ok(()) => (130, None),
                    Err(e) => (1, Some(format!("webui serve: {e}"))),
                }
            }
        }
    });
    match (code, err_text) {
        (0, _) => Ok(()),
        (130, _) => Err(msg_empty(130)),
        (c, Some(text)) => Err(msg(c, text)),
        (c, None) => Err(msg_empty(c)),
    }
}

/// Go's `resolveWebUIUIDir` reports a broken ui_dir as
/// "webui serve: <rule>"; the shared check reports the
/// rule as "webui: <rule>". Drop the shared prefix so the
/// startup failure reads exactly as Go's.
fn webui_uidir_msg(m: &str) -> String {
    format!("webui serve: {}", m.strip_prefix("webui: ").unwrap_or(m))
}

/// `cmdPlugin` / `cmdPluginCheck` (`plugincheck.go:43`).
fn cmd_plugin(ctx: &mut Ctx<'_>, args: &[String]) -> Result<(), FlowErr> {
    if args.is_empty() {
        // Unlike the other dispatchers: help text only, no
        // required line, on stderr.
        ctx.out.stderr.push_str(PLUGIN_CHECK_HELP_TEXT);
        return Err(msg_empty(2));
    }
    if args[0] == "--help" || args[0] == "-h" {
        ctx.out.stdout.push_str(PLUGIN_CHECK_HELP_TEXT);
        return Err(FlowErr::HelpShown);
    }
    if args[0] != "check" {
        ctx.out.stderr.push_str(&format!(
            "castctl: argument subcommand: invalid choice: {} (choose from check)\n",
            go_quote(&args[0])
        ));
        return Err(msg_empty(2));
    }
    let p = inline_parse(
        ctx,
        vec![
            crate::parser::str_flag("tag"),
            crate::parser::str_flag("type"),
        ],
        PLUGIN_CHECK_HELP_TEXT,
        &args[1..],
    )?;
    check_positionals(&p, &["path"]).map_err(usage_err)?;
    let mut tag = p.str("tag");
    if tag.is_empty() {
        tag = "check".to_string();
    }
    if !valid_plugin_id(&tag) {
        return Err(msg(2, format!("plugin: invalid --tag {}", go_quote(&tag))));
    }
    let mut typ = p.str("type");
    if typ.is_empty() {
        typ = "check".to_string();
    }
    // No config resolution (probed Go exception): the
    // loader runs next, through the real Rust loader.
    let path = p.positionals[0].clone();
    plugin_check(ctx, &tag, &typ, &path)
}

/// `cmdPluginCheck` (`plugincheck.go:61-147`): load one
/// plugin through the real loader and run a single
/// provider call against it. Prints one line per stage
/// (dlopen, init, register, provider.call, shutdown),
/// plus any host.log lines the plugin emits (printed as
/// plugin log lines). It loads no config, starts no
/// services, writes no config or cookies, and logs no
/// secrets. Exit 0 when every stage passes, exit 2
/// otherwise.
fn plugin_check(ctx: &mut Ctx<'_>, tag: &str, typ: &str, path: &str) -> Result<(), FlowErr> {
    use castctl_pluginhost::host::{Desired, Host, Options};
    use castctl_pluginhost::pluginabi::METHOD_PROVIDER_CALL;
    use castctl_pluginhost::text::truncate_runes;

    // host.log lines are collected in arrival order and
    // flushed before the next stage line, so they stay
    // interleaved the way Go prints them. The sink is
    // bounded (fix loop 1, B6): a plugin flooding
    // `host.log` mid-call must not grow this String
    // without bound — past the cap, lines are dropped
    // and a single truncation marker is recorded.
    let logs: Arc<Mutex<String>> = Arc::new(Mutex::new(String::new()));
    let logs_clone = Arc::clone(&logs);
    let log_truncated: Arc<Mutex<bool>> = Arc::new(Mutex::new(false));
    let log_truncated_clone = Arc::clone(&log_truncated);
    let host = Host::new(Options {
        loader: None,
        log: Some(Arc::new(move |level: &str, message: &str| {
            let mut line = format!("plugin log [{level}]: {message}");
            if line.len() > 4096 {
                line = format!("{}…", truncate_runes(&line, 4096));
            }
            push_plugin_log_line(&logs_clone, &log_truncated_clone, &line);
        })),
    });
    let mut desired = Desired::new(tag, typ, path);
    desired.fragment = b"{}".to_vec();
    let report = host.apply_config(vec![desired]);
    // Flush any host.log lines from the load before the
    // stage lines.
    let drained = {
        let mut sink = logs.lock().unwrap_or_else(|e| e.into_inner());
        std::mem::take(&mut *sink)
    };
    ctx.out.stdout.push_str(&drained);
    if let Some(skipped) = report.skipped.first() {
        ctx.out.stderr.push_str(&format!(
            "plugin check: FAIL {}: {}\n",
            tag,
            check_text_full(&skipped.reason)
        ));
        host.close();
        return Err(msg_empty(2));
    }
    let Some(loaded) = host.loaded(tag) else {
        ctx.out.stderr.push_str(&format!(
            "plugin check: FAIL {tag}: loaded but not reported\n"
        ));
        host.close();
        return Err(msg_empty(2));
    };
    ctx.out.stdout.push_str("dlopen: ok\n");
    ctx.out.stdout.push_str("init: ok\n");
    let mut caps: Vec<&str> = Vec::new();
    if loaded.capabilities.provider {
        caps.push("provider");
    }
    if loaded.capabilities.command_provider {
        caps.push("command-provider");
    }
    ctx.out.stdout.push_str(&format!(
        "register: ok schema={} name={} version={} capabilities={}\n",
        loaded.schema_version,
        check_text(&loaded.metadata.name, 200),
        check_text(&loaded.metadata.version, 200),
        caps.join(",")
    ));
    if !loaded.capabilities.provider {
        // Command-only plugin: provider.call has no
        // dispatch path and must not FAIL the check.
        ctx.out
            .stdout
            .push_str("provider.call: skipped (command-only plugin)\n");
        host.close();
        return finish_shutdown(ctx, tag, &host);
    }
    let result = host.call(tag, METHOD_PROVIDER_CALL, b"{\"input\":\"ping\"}", None);
    // Flush host.log lines from the provider call before
    // its stage line.
    let drained = {
        let mut sink = logs.lock().unwrap_or_else(|e| e.into_inner());
        std::mem::take(&mut *sink)
    };
    ctx.out.stdout.push_str(&drained);
    host.close();
    match result {
        Ok(bytes) => {
            ctx.out
                .stdout
                .push_str(&format!("provider.call: ok {}\n", compact_json(&bytes)));
            finish_shutdown(ctx, tag, &host)
        }
        Err(e) => {
            ctx.out.stderr.push_str(&format!(
                "plugin check: FAIL {tag}: provider.call: {}\n",
                check_text(&e.to_string(), 200)
            ));
            Err(msg_empty(2))
        }
    }
}

/// The `shutdown` stage line, after `Host::close`.
/// A worker crash inside plugin `shutdown` (fix loop 1,
/// B4) fails the check with a distinct line instead of
/// printing `shutdown: ok` for a dead worker.
fn finish_shutdown(
    ctx: &mut Ctx<'_>,
    tag: &str,
    host: &castctl_pluginhost::host::Host,
) -> Result<(), FlowErr> {
    use castctl_pluginhost::error::PluginHostError;
    if let Some((_, e)) = host.shutdown_errors().into_iter().next() {
        let line = match &e {
            PluginHostError::PluginCrashed {
                signal: Some(sig), ..
            } => format!("shutdown: crashed (signal {sig})"),
            _ => "shutdown: crashed".to_string(),
        };
        ctx.out.stdout.push_str(&format!("{line}\n"));
        ctx.out.stderr.push_str(&format!(
            "plugin check: FAIL {tag}: shutdown: {}\n",
            check_text_full(&e.to_string())
        ));
        return Err(msg_empty(2));
    }
    ctx.out.stdout.push_str("shutdown: ok\n");
    Ok(())
}

/// Total `plugin check` log bytes kept between stage
/// flushes (fix loop 1, B6). A flooding plugin's lines
/// past this cap are dropped, never accumulated.
const PLUGIN_CHECK_LOG_CAP: usize = 65536;

/// Append one (already per-line capped) plugin log
/// line to the sink, bounded by
/// `PLUGIN_CHECK_LOG_CAP`. Past the cap the line is
/// dropped and a single truncation marker is recorded.
fn push_plugin_log_line(sink: &Arc<Mutex<String>>, truncated: &Arc<Mutex<bool>>, line: &str) {
    let mut s = sink.lock().unwrap_or_else(|e| e.into_inner());
    if s.len() + line.len() + 1 > PLUGIN_CHECK_LOG_CAP {
        let mut t = truncated.lock().unwrap_or_else(|e| e.into_inner());
        if !*t {
            *t = true;
            s.push_str("plugin log: … (truncated, log cap reached)\n");
        }
        return;
    }
    s.push_str(line);
    s.push('\n');
}

/// `checkField` / `shortPluginCheckError`
/// (`plugincheck.go`): strip control characters,
/// redact secrets, cap at `max` bytes at a rune
/// boundary with an explicit marker.
fn check_text(s: &str, max: usize) -> String {
    use castctl_pluginhost::text::{safe_plugin_text, strip_control_chars, truncate_runes};
    let cleaned = safe_plugin_text(&strip_control_chars(s));
    if cleaned.len() > max {
        format!("{}…", truncate_runes(&cleaned, max))
    } else {
        cleaned
    }
}

/// Like `check_text` with no length cap (fix loop 1,
/// tech N3): the `plugin check: FAIL` reason is
/// printed whole, like Go (`plugincheck.go` prints the
/// skip reason uncapped). Only the `register:` line
/// cap and the provider.call error cap are Go-exact.
fn check_text_full(s: &str) -> String {
    use castctl_pluginhost::text::{safe_plugin_text, strip_control_chars};
    safe_plugin_text(&strip_control_chars(s))
}

/// `compactJSON` (`plugincheck.go`): re-marshal the
/// result compactly (sorted keys, like Go's
/// `json.Marshal`); unparsable input passes through
/// trimmed and capped.
fn compact_json(raw: &[u8]) -> String {
    match serde_json::from_slice::<serde_json::Value>(raw) {
        Ok(value) => match serde_json::to_string(&value) {
            Ok(compact) => check_text(&compact, 4096),
            Err(_) => check_text(&String::from_utf8_lossy(raw), 4096),
        },
        Err(_) => check_text(String::from_utf8_lossy(raw).trim(), 4096),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn run_args(args: &[&str]) -> Outcome {
        let argv: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        run(&argv, None)
    }

    fn run_env(args: &[&str], map: HashMap<String, String>) -> Outcome {
        let argv: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        let g = move |k: &str| map.get(k).cloned();
        run(&argv, Some(&g))
    }

    /// Parse a `config migrate` stdout result object.
    fn migrate_result(out: &Outcome) -> castctl_config::jsonvalue::OrderedObject {
        let v = castctl_config::jsonvalue::decode_ordered_json(out.stdout.as_bytes())
            .unwrap_or_else(|e| panic!("migrate stdout is not JSON ({e}): {}", out.stdout));
        match v {
            castctl_config::jsonvalue::JsonValue::Object(o) => o,
            _ => panic!("want migrate result object, got: {}", out.stdout),
        }
    }

    /// An empty layout migrates to one synthesised `default`
    /// legacy profile (Go `MigrateFrom`, verified live on
    /// cue against the Go binary: same shape, `migrated:
    /// true`, one `default`/`legacy` row).
    fn assert_migrated_empty_layout(out: &Outcome) {
        let obj = migrate_result(out);
        assert_eq!(
            obj.get("migrated"),
            Some(&castctl_config::jsonvalue::JsonValue::Bool(true))
        );
        let profiles = match obj.get("profiles") {
            Some(castctl_config::jsonvalue::JsonValue::Array(p)) => p,
            _ => panic!("want profiles array, got: {}", out.stdout),
        };
        assert_eq!(profiles.len(), 1, "profiles: {profiles:?}");
        let row = match &profiles[0] {
            castctl_config::jsonvalue::JsonValue::Object(o) => o,
            _ => panic!("want profile object"),
        };
        assert_eq!(
            row.get("name"),
            Some(&castctl_config::jsonvalue::JsonValue::Str("default".into()))
        );
        assert_eq!(
            row.get("source"),
            Some(&castctl_config::jsonvalue::JsonValue::Str("legacy".into()))
        );
    }

    fn temp_home(tag: &str) -> std::path::PathBuf {
        // Unique per CALL, not per process: tests run in
        // parallel threads of one binary (same pid), and
        // wired commands (e.g. `config migrate --write`)
        // CREATE files in the home — a pid-shared dir lets
        // one test delete/migrate under another (the M7d
        // parallel-run failure: exit 1 from a concurrent
        // migrate on the same isolated home).
        use std::sync::atomic::{AtomicUsize, Ordering};
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir =
            std::env::temp_dir().join(format!("castctl-cli-{tag}-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Env with an isolated HOME and an empty config dir (no
    /// config.json): config resolution fails at RequirePresent.
    fn isolated_env() -> (std::path::PathBuf, HashMap<String, String>) {
        let home = temp_home("home");
        let mut map = HashMap::new();
        map.insert("HOME".to_string(), home.to_str().unwrap().to_string());
        map.insert(
            "XDG_CONFIG_HOME".to_string(),
            home.join(".config").to_str().unwrap().to_string(),
        );
        (home, map)
    }

    #[test]
    fn test_version_and_global_help() {
        let out = run_args(&["--version"]);
        assert_eq!(
            out,
            Outcome {
                stdout: "castctl 0.9.0\n".to_string(),
                stdout_bytes: Vec::new(),
                stderr: String::new(),
                code: 0
            }
        );
        let out = run_args(&["--vers"]);
        assert_eq!(out.stdout, "castctl 0.9.0\n");
        assert_eq!(out.code, 0);
        let out = run_args(&["--v"]);
        assert_eq!(out.stdout, "castctl 0.9.0\n");
        let out = run_args(&["--help"]);
        assert_eq!(out.stdout, GLOBAL_HELP_TEXT);
        assert_eq!(out.code, 0);
        assert!(out.stderr.is_empty());
        let out = run_args(&["--he"]);
        assert_eq!(out.stdout, GLOBAL_HELP_TEXT);
        let out = run_args(&["--h"]);
        assert_eq!(out.stdout, GLOBAL_HELP_TEXT);
    }

    #[test]
    fn test_version_with_value_rejected() {
        let out = run_args(&["--vers=x"]);
        assert_eq!(out.stdout, "castctl 0.9.0\n");
        let out = run_args(&["--version=x"]);
        assert_eq!(out.code, 2);
        assert_eq!(
            out.stderr,
            "castctl: argument --version: ignored explicit argument \"x\"\n"
        );
        assert!(out.stdout.is_empty());
    }

    #[test]
    fn test_scan_order_and_unknown_flags() {
        let out = run_args(&["--bogus", "--help"]);
        assert_eq!(out.code, 2);
        assert_eq!(out.stderr, "castctl: unrecognized argument: --bogus\n");
        let out = run_args(&["--help", "--bogus"]);
        assert_eq!(out.stdout, GLOBAL_HELP_TEXT);
        assert_eq!(out.code, 0);
        let out = run_args(&["-x"]);
        assert_eq!(out.stderr, "castctl: unrecognized argument: -x\n");
        assert_eq!(out.code, 2);
        // scanGlobal does NOT bundle short flags: only the exact
        // "-h" prints help; "-hx" is unrecognized.
        let out = run_args(&["-hx"]);
        assert_eq!(out.stderr, "castctl: unrecognized argument: -hx\n");
        assert_eq!(out.code, 2);
        assert_eq!(out.code, 2);
    }

    #[test]
    fn test_unknown_command_lists_46_and_help() {
        let out = run_args(&["bogus"]);
        assert_eq!(out.code, 2);
        assert!(out.stdout.is_empty());
        let expected = format!(
            "castctl: argument cmd: invalid choice: \"bogus\" (choose from {})\n{GLOBAL_HELP_TEXT}",
            COMMAND_ORDER.join(", ")
        );
        assert_eq!(out.stderr, expected);
    }

    #[test]
    fn test_log_level_validation_never_echoes() {
        let out = run_args(&["--log-level", "xyz"]);
        assert_eq!(out.code, 2);
        assert_eq!(
            out.stderr,
            "castctl: argument --log-level: invalid log level (expected trace, debug, info, warn, warning, error, fatal, or panic)\n"
        );
        let out = run_args(&["--log-level"]);
        assert_eq!(
            out.stderr,
            "castctl: argument --log-level: expected one argument\n"
        );
        // Valid level, then a command: scan continues. With an
        // isolated HOME and no config file, `config migrate
        // --write` is WIRED (M7d): it writes a single file
        // with the synthesised default profile and reports
        // `migrated: true`, exit 0 — Go's `MigrateFrom`
        // returns a result with no error for an empty layout.
        let (_home, map) = isolated_env();
        let out = run_env(
            &["--log-level", "warn", "config", "migrate", "--write"],
            map,
        );
        assert_eq!(out.code, 0);
        assert!(out.stderr.is_empty(), "stderr: {}", out.stderr);
        assert_migrated_empty_layout(&out);
    }

    #[test]
    fn test_config_basename_error_before_presence() {
        let out = run_args(&["--config", "/nonexistent"]);
        assert_eq!(out.code, 2);
        assert_eq!(
            out.stderr,
            "castctl: --config path \"/nonexistent\" must name a config.json file\n"
        );
        assert!(out.stdout.is_empty());
    }

    #[test]
    fn test_bare_config_flag_empty() {
        let out = run_args(&["--config", "   ", "status"]);
        assert_eq!(out.code, 2);
        assert_eq!(out.stderr, "castctl: --config requires a non-empty path\n");
    }

    #[test]
    fn test_command_help_all_46() {
        for name in COMMAND_ORDER {
            let out = run_args(&[name, "--help"]);
            assert_eq!(out.code, 0, "{name}");
            assert!(out.stderr.is_empty(), "{name}");
            assert_eq!(out.stdout, command_spec(name).unwrap().help_text, "{name}");
        }
    }

    #[test]
    fn test_parser_error_is_three_lines() {
        let out = run_args(&["history", "--bogus"]);
        assert_eq!(out.code, 2);
        assert_eq!(
            out.stderr,
            "castctl: unrecognized argument: --bogus\nusage: castctl history [--thread ID] [--limit N] [--raw] [--download DIR]\ncastctl: unrecognized argument: --bogus\n"
        );
        assert!(out.stdout.is_empty());
    }

    #[test]
    fn test_profile_parse_error_is_two_lines() {
        let out = run_args(&["profile", "add", "--bogus"]);
        assert_eq!(out.code, 2);
        assert_eq!(
            out.stderr,
            "castctl: unrecognized argument: --bogus\ncastctl: unrecognized argument: --bogus\n"
        );
    }

    #[test]
    fn test_fs_parse_error_is_three_lines_with_fs_usage() {
        let out = run_args(&["fs", "ls", "--bogus"]);
        assert_eq!(out.code, 2);
        assert_eq!(
            out.stderr,
            "castctl: unrecognized argument: --bogus\nusage: castctl fs ls\ncastctl: unrecognized argument: --bogus\n"
        );
    }

    #[test]
    fn test_positional_error_is_one_line() {
        let out = run_args(&["redeem"]);
        assert_eq!(out.code, 2);
        assert_eq!(
            out.stderr,
            "castctl: the following arguments are required: code\n"
        );
        let out = run_args(&["goal", "a", "b"]);
        assert_eq!(out.stderr, "castctl: unrecognized arguments: b\n");
        let out = run_args(&["send"]);
        assert_eq!(
            out.stderr,
            "castctl: the following arguments are required: text\n"
        );
    }

    #[test]
    fn test_dispatcher_shapes() {
        // No-arg: required line + help on stderr, exit 2.
        let out = run_args(&["fs"]);
        assert_eq!(out.code, 2);
        assert_eq!(
            out.stderr,
            format!("castctl: the following arguments are required: subcommand\n{FS_HELP_TEXT}")
        );
        // Unknown subcommand: one line, no help (except webui).
        let out = run_args(&["fs", "bogus"]);
        assert_eq!(
            out.stderr,
            "castctl: argument subcommand: invalid choice: \"bogus\" (choose from ls, tree, stat, cat, get, find, put, write, edit, mkdir, mv, rm)\n"
        );
        assert_eq!(out.code, 2);
        let out = run_args(&["webui", "bogus"]);
        assert_eq!(
            out.stderr,
            format!(
                "castctl: argument subcommand: invalid choice: \"bogus\" (choose from serve)\n{WEBUI_HELP_TEXT}"
            )
        );
        // Dispatcher help: only exact --help/-h at args[0].
        let out = run_args(&["fs", "--help"]);
        assert_eq!(out.stdout, FS_HELP_TEXT);
        assert_eq!(out.code, 0);
        let out = run_args(&["fs", "--hel"]);
        assert_eq!(out.code, 2);
        assert!(out.stderr.contains("invalid choice"));
        // Plugin no-arg: help only, no required line.
        let out = run_args(&["plugin"]);
        assert_eq!(out.stderr, PLUGIN_CHECK_HELP_TEXT);
        assert_eq!(out.code, 2);
        assert!(out.stdout.is_empty());
    }

    #[test]
    fn test_migrate_after_config_resolution() {
        // Non-explicit location, no config file: RequirePresent
        // passes (Go: non-explicit always passes) — and
        // `config migrate --write` is WIRED (M7d): it writes
        // a single file with the synthesised default profile,
        // exit 0 with a result JSON.
        let (_home, map) = isolated_env();
        let out = run_env(&["config", "migrate", "--write"], map);
        assert_eq!(out.code, 0);
        assert!(out.stderr.is_empty(), "stderr: {}", out.stderr);
        assert_migrated_empty_layout(&out);
        // Explicit location with a correct basename but a missing
        // file: RequirePresent fails BEFORE the command runs (exit 2).
        let home = temp_home("explicit-missing");
        let missing = home.join("config.json");
        let out = run_args(&["--config", missing.to_str().unwrap(), "status"]);
        assert_eq!(out.code, 2);
        assert!(out.stderr.contains("does not exist"));
        assert!(!out.stderr.contains("not ported yet"));
    }

    #[test]
    fn test_migrate_writes_nothing_when_already_migrated() {
        let home = temp_home("stub");
        let cfg_dir = home.join(".config/castctl");
        std::fs::create_dir_all(&cfg_dir).unwrap();
        std::fs::write(cfg_dir.join("config.json"), "{\"profiles\":{}}").unwrap();
        let mut map = HashMap::new();
        map.insert("HOME".to_string(), home.to_str().unwrap().to_string());
        map.insert(
            "XDG_CONFIG_HOME".to_string(),
            home.join(".config").to_str().unwrap().to_string(),
        );
        let out = run_env(&["config", "migrate", "--write"], map);
        assert_eq!(out.code, 0);
        assert!(out.stderr.is_empty(), "stderr: {}", out.stderr);
        let obj = migrate_result(&out);
        assert_eq!(
            obj.get("reason"),
            Some(&castctl_config::jsonvalue::JsonValue::Str(
                "already-migrated".into()
            ))
        );
        assert_eq!(
            obj.get("migrated"),
            Some(&castctl_config::jsonvalue::JsonValue::Bool(false))
        );
    }

    #[test]
    fn test_update_invalid_version_no_network() {
        // `update` loads no config (release downloads are public
        // URLs): an invalid --version fails at version parse,
        // before any fetch, with exit 2 — no network, no config.
        let (_home, map) = isolated_env();
        let out = run_env(&["update", "--version", "bogus"], map.clone());
        assert_eq!(out.code, 2);
        assert!(
            out.stderr.contains("invalid --version value"),
            "{}",
            out.stderr
        );
        assert!(out.stdout.is_empty());
        // `plugin check` is real now (M6c-b): a missing
        // file fails at the shadow gate with exit 2, not
        // the stub — no worker is spawned for it. The
        // reason carries the absolute path (cwd-joined),
        // so only the invariant head and tail are pinned.
        let out = run_env(&["plugin", "check", "x.so"], map);
        assert_eq!(out.code, 2);
        assert!(out.stdout.is_empty());
        assert!(
            out.stderr
                .starts_with("plugin check: FAIL check: plugin path "),
            "unexpected stderr: {}",
            out.stderr
        );
        assert!(
            out.stderr
                .ends_with("x.so: No such file or directory (os error 2)\n"),
            "unexpected stderr: {}",
            out.stderr
        );
    }

    #[test]
    fn plugin_log_sink_is_bounded() {
        // Fix loop 1, B6: the `plugin check` log sink
        // never grows past the cap, however many lines
        // a flooding plugin emits.
        let sink: Arc<Mutex<String>> = Arc::new(Mutex::new(String::new()));
        let truncated: Arc<Mutex<bool>> = Arc::new(Mutex::new(false));
        let line = "x".repeat(4096);
        for _ in 0..100 {
            push_plugin_log_line(&sink, &truncated, &line);
        }
        let s = sink.lock().unwrap_or_else(|e| e.into_inner());
        assert!(
            s.len() <= PLUGIN_CHECK_LOG_CAP + 64,
            "sink grew past the cap: {} bytes",
            s.len()
        );
        assert!(
            s.contains("truncated, log cap reached"),
            "no truncation marker: {s:?}"
        );
        assert!(
            *truncated.lock().unwrap_or_else(|e| e.into_inner()),
            "truncated flag must be set"
        );
        // Short lines still land when there is room.
        let sink2: Arc<Mutex<String>> = Arc::new(Mutex::new(String::new()));
        let truncated2: Arc<Mutex<bool>> = Arc::new(Mutex::new(false));
        push_plugin_log_line(&sink2, &truncated2, "hello");
        assert_eq!(
            sink2.lock().unwrap_or_else(|e| e.into_inner()).as_str(),
            "hello\n"
        );
    }

    #[test]
    fn test_auth_export_guidance_exit_1() {
        let out = run_args(&["auth", "export"]);
        assert_eq!(out.code, 1);
        assert_eq!(out.stderr, format!("{EXPORT_GUIDANCE}\n"));
        assert!(out.stdout.is_empty());
        // Extra positionals silently ignored (Go quirk).
        let out = run_args(&["auth", "export", "extra", "args"]);
        assert_eq!(out.code, 1);
    }

    #[test]
    fn test_approve_and_auto_approve_checks() {
        let out = run_args(&["approve", "--once", "--today"]);
        assert_eq!(
            out.stderr,
            "castctl: argument --today: not allowed with argument --once\n"
        );
        assert_eq!(out.code, 2);
        let out = run_args(&["approve"]);
        assert_eq!(
            out.stderr,
            "castctl: give an approval ID or --all (not both)\n"
        );
        let out = run_args(&["approve", "id1", "--all"]);
        assert_eq!(
            out.stderr,
            "castctl: give an approval ID or --all (not both)\n"
        );
        let out = run_args(&["auto-approve", "bogus"]);
        assert_eq!(
            out.stderr,
            "castctl: argument state: invalid choice: \"bogus\" (choose from on, always, off, status, once)\n"
        );
        let out = run_args(&["auto-approve", "on", "extra", "third"]);
        assert_eq!(out.stderr, "castctl: unrecognized arguments: third\n");
        let out = run_args(&["auto-approve", "on", "off"]);
        assert_eq!(
            out.stderr,
            "castctl: unexpected \"off\": use `auto-approve once on|off|status`\n"
        );
        let out = run_args(&["wait", "--auto-approve", "--no-auto-approve"]);
        assert_eq!(
            out.stderr,
            "castctl: argument --no-auto-approve: not allowed with argument --auto-approve\n"
        );
    }

    #[test]
    fn test_keeper_mutual_exclusion_and_migrate_from() {
        let out = run_args(&["keeper", "run", "--tag", "t", "--profile", "p"]);
        assert_eq!(
            out.stderr,
            "castctl: keeper: --tag and --profile are mutually exclusive\n"
        );
        let out = run_args(&["config", "migrate", "--from", "   "]);
        assert_eq!(
            out.stderr,
            "castctl: --from requires a non-empty directory\n"
        );
        let out = run_args(&["profile", "rm", "work"]);
        assert_eq!(
            out.stderr,
            "castctl: refusing to remove profile \"work\" without --yes\n"
        );
        let out = run_args(&["auth", "status", "--all", "--profile", "x"]);
        assert_eq!(
            out.stderr,
            "castctl: auth status: --profile and --all are mutually exclusive\n"
        );
    }

    #[test]
    fn test_auth_login_gates() {
        let out = run_args(&["auth", "login"]);
        assert_eq!(
            out.stderr,
            "castctl: auth login is experimental: pass --experimental-login (or set CASTCTL_EXPERIMENTAL_LOGIN=1), or use \"castctl auth import\" instead\n"
        );
        assert_eq!(out.code, 2);
        let out = run_args(&["auth", "login", "--experimental-login"]);
        assert_eq!(
            out.stderr,
            "castctl: auth login is not available in this build: rebuild with -tags with_chromedp\n"
        );
        let out = run_args(&["auth", "observe-login"]);
        assert_eq!(
            out.stderr,
            "castctl: auth observe-login is not available in this build: rebuild with -tags with_chromedp\n"
        );
    }

    #[test]
    fn test_plugin_tag_validation_before_check() {
        let out = run_args(&["plugin", "check", "x.so", "--tag", "bad tag!"]);
        assert_eq!(out.code, 2);
        assert_eq!(out.stderr, "castctl: plugin: invalid --tag \"bad tag!\"\n");
        let out = run_args(&["plugin", "check"]);
        assert_eq!(
            out.stderr,
            "castctl: the following arguments are required: path\n"
        );
    }

    #[test]
    fn test_telegram_takes_no_args() {
        let out = run_args(&["telegram", "run", "extra"]);
        assert_eq!(out.code, 2);
        assert_eq!(
            out.stderr,
            "castctl: telegram run takes no arguments (got \"extra\")\n"
        );
        assert!(out.stdout.is_empty());
        let out = run_args(&["telegram", "status", "--help"]);
        assert_eq!(out.stdout, TELEGRAM_STATUS_HELP_TEXT);
        assert_eq!(out.code, 0);
    }

    #[test]
    fn test_dashdash_and_empty_token() {
        let out = run_args(&["--", "bogus"]);
        assert_eq!(out.code, 2);
        assert!(out.stderr.contains("invalid choice"));
        // Lone "--" -> chat -> config resolution passes for a
        // non-explicit location -> chat runs (wired in PR-2)
        // and its eager connect fails: no cookies in the
        // isolated HOME, so an auth failure, exit 2. The
        // guidance goes to the real stdout (chat owns the
        // terminal), not the captured ctx streams.
        let (_home, map) = isolated_env();
        let out = run_env(&["--"], map);
        assert_eq!(out.code, 2);
        assert!(out.stderr.contains("auth_failed"));
        assert!(out.stdout.is_empty());
    }

    #[test]
    fn test_config_migrate_help_and_wired() {
        let out = run_args(&["config", "migrate", "--help"]);
        assert_eq!(out.stdout, CONFIG_MIGRATE_HELP_TEXT);
        assert_eq!(out.code, 0);
        let out = run_args(&["config", "--help"]);
        assert_eq!(out.stdout, CONFIG_HELP_TEXT);
        assert_eq!(out.code, 0);
        // Parse-successful migrate is WIRED (M7d): with no
        // config file anywhere, --write creates a single file
        // with the synthesised default profile and reports
        // `migrated: true`, exit 0.
        let (_home, map) = isolated_env();
        let out = run_env(&["config", "migrate", "--write"], map);
        assert_eq!(out.code, 0);
        assert!(out.stderr.is_empty(), "stderr: {}", out.stderr);
        assert_migrated_empty_layout(&out);
    }

    #[test]
    fn test_cmd_plain_fallthrough_unreachable() {
        // The `cmd_plain` fallthrough (internal error) can only
        // fire for a name in none of the handled sets. Every
        // name that reaches `cmd_plain` — `COMMAND_ORDER`
        // minus the 9 dedicated dispatch arms — must be
        // covered exactly by the handled sets (R2 §6.1).
        let dedicated = [
            "fs", "auth", "profile", "config", "telegram", "keeper", "webui", "plugin", "update",
        ];
        let mut reaching: Vec<&str> = COMMAND_ORDER
            .iter()
            .copied()
            .filter(|n| !dedicated.contains(n))
            .collect();
        let mut covered: Vec<&str> = vec!["wait", "send", "watch", "chat", "auto-approve"];
        covered.extend(READ_COMMANDS.iter().copied());
        covered.extend(M7B_COMMANDS.iter().copied());
        reaching.sort_unstable();
        covered.sort_unstable();
        assert_eq!(reaching, covered);
    }

    #[test]
    fn test_update_has_no_check_flag() {
        // D-M7b-PR3-7: Go has no `--check` flag; `--dry-run`
        // is the check mode. The parser must reject `--check`.
        let out = run_args(&["update", "--check"]);
        assert_eq!(out.code, 2);
        assert!(out.stderr.contains("--check"), "{}", out.stderr);
        assert!(out.stdout.is_empty());
    }

    #[test]
    fn test_auth_list_no_config() {
        // No config anywhere: the active profile synthesises
        // as "default" (F1) and the list has one row, "not
        // created" — exit 0, no stub.
        let (home, map) = isolated_env();
        let out = run_env(&["auth", "list"], map.clone());
        assert_eq!(out.code, 0);
        let dir = home.join(".config/castctl");
        assert_eq!(
            out.stdout,
            format!("* default  not created  {}\n", dir.to_str().unwrap())
        );
        assert!(out.stderr.is_empty());
        let out = run_env(&["auth", "list", "--json"], map);
        assert_eq!(out.code, 0);
        let expected = format!(
            "{{\n  \"active\": \"default\",\n  \"profiles\": [\n    {{\n      \"name\": \"default\",\n      \"active\": true,\n      \"dir\": \"{}\",\n      \"exists\": false,\n      \"cookies\": false,\n      \"cookies_file\": \"{}/cookies.txt\",\n      \"auto_approve\": \"off\"\n    }}\n  ]\n}}\n",
            dir.to_str().unwrap(),
            dir.to_str().unwrap()
        );
        assert_eq!(out.stdout, expected);
    }

    #[test]
    fn test_auth_status_no_config() {
        let (_home, map) = isolated_env();
        let out = run_env(&["auth", "status"], map);
        assert_eq!(out.code, 2);
        assert_eq!(out.stderr, "castctl: auth status: no config.json found\n");
        assert!(out.stdout.is_empty());
    }

    #[test]
    fn test_auth_status_one_profile_ok() {
        // Fixture: one profile with a jar cookies file whose
        // hatch_sess expires in 2030 — status ok, headless
        // unavailable for lack of a keeper entry.
        let home = temp_home("auth-status");
        let cfg_dir = home.join(".config/castctl");
        let prof_dir = cfg_dir.join("profiles/no1");
        std::fs::create_dir_all(&prof_dir).unwrap();
        std::fs::write(cfg_dir.join("config.json"), "{\"profiles\":{\"no1\":{}}}").unwrap();
        std::fs::write(
            prof_dir.join("cookies.txt"),
            ".muse.ai\tTRUE\t/\tTRUE\t1893456000\thatch_sess\tFAKE-SESSION\n",
        )
        .unwrap();
        let mut map = HashMap::new();
        map.insert("HOME".to_string(), home.to_str().unwrap().to_string());
        map.insert(
            "XDG_CONFIG_HOME".to_string(),
            home.join(".config").to_str().unwrap().to_string(),
        );
        let out = run_env(&["auth", "status", "--profile", "no1"], map.clone());
        assert_eq!(out.code, 0);
        assert!(
            out.stdout.contains("\"profile\": \"no1\""),
            "{}",
            out.stdout
        );
        assert!(out.stdout.contains("\"status\": \"ok\""), "{}", out.stdout);
        assert!(
            out.stdout.contains("\"driving_cookie\": \"hatch_sess\""),
            "{}",
            out.stdout
        );
        assert!(
            out.stdout
                .contains("\"headless_reason\": \"no_keeper_entry\""),
            "{}",
            out.stdout
        );
        assert!(out.stdout.contains("\"cookies_seen\": 1"), "{}", out.stdout);
        assert!(out.stdout.contains("2030-01-01"), "{}", out.stdout);
        // --all with a single configured profile prints the
        // same single object, not an array (Go `len(out)==1`
        // rule).
        let out = run_env(&["auth", "status", "--all"], map);
        assert_eq!(out.code, 0);
        assert!(out.stdout.trim_start().starts_with('{'), "{}", out.stdout);
        assert!(out.stdout.contains("\"status\": \"ok\""), "{}", out.stdout);
    }

    #[test]
    fn test_fs_positional_checks() {
        let out = run_args(&["fs", "ls", "a", "b"]);
        assert_eq!(out.stderr, "castctl: unrecognized arguments: b\n");
        let out = run_args(&["fs", "stat"]);
        assert_eq!(
            out.stderr,
            "castctl: the following arguments are required: path\n"
        );
        let out = run_args(&["fs", "put", "only-one"]);
        assert_eq!(
            out.stderr,
            "castctl: the following arguments are required: remote\n"
        );
        let out = run_args(&["fs", "edit", "a", "b"]);
        assert_eq!(out.stderr, "castctl: unrecognized arguments: b\n");
    }

    /// The M6b chat seam wired by `webui serve`: every call
    /// fails closed, so the handlers report the fixed 502
    /// `upstream_error` (the live Go binary's behaviour when
    /// its gateway seam has no live session).
    #[test]
    fn test_failing_chat_deps_all_err() {
        let deps = failing_chat_deps();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            assert!(
                (deps.list_sessions)("muse01".to_string(), false)
                    .await
                    .is_err()
            );
            assert!(
                (deps.get_history)("muse01".to_string(), "s1".to_string(), 50)
                    .await
                    .is_err()
            );
            assert!(
                (deps.start_session)("muse01".to_string(), "t".to_string())
                    .await
                    .is_err()
            );
            assert!(
                (deps.session_op)(
                    "muse01".to_string(),
                    "s1".to_string(),
                    "pin".to_string(),
                    String::new(),
                )
                .await
                .is_err()
            );
            assert!(
                (deps.send_chat)("muse01".to_string(), "s1".to_string(), "hi".to_string())
                    .await
                    .is_err()
            );
        });
    }
}
