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

use castctl_config::blocks::valid_plugin_id;
use castctl_config::config::load_single_config;
use castctl_config::configlocation::{ConfigLocation, Getenv, resolve_config_location};
use castctl_config::errors::ConfigError;
use castctl_config::gostr::{go_quote, go_trim_space};
use castctl_config::log::valid_log_level;

use crate::help_texts::*;
use crate::parser::{ArgParser, Parsed, ParserError, check_positionals};
use crate::table::{
    COMMAND_ORDER, CommandSpec, FS_SUBCOMMANDS, KEEPER_SUBCOMMANDS, PROFILE_SUBCOMMANDS,
    PositionalSpec, TELEGRAM_SUBCOMMANDS, auth_sub_defs, command_spec, fs_defs,
    fs_positional_names, keeper_sub_help, profile_sub_defs, profile_sub_help,
};

/// The Rust `--version` payload (D-M2-7): the bare version, no
/// stamp. Go's `commands.go` `Version` var defaults to `0.6.1` and
/// release builds stamp `0.9.0` via `-X`; the Rust const is the
/// stamped release version the golden binary reports.
pub const VERSION: &str = "0.9.0";

/// The fixed stub line (D-M2-3): exit 1, exactly one stderr line
/// containing `not ported yet`, empty stdout, no argv echo.
pub const STUB_LINE: &str = "castctl: not ported yet in the Rust port\n";

/// `ExportGuidance` (`internal/deliver/authexport.go`): the fixed
/// guidance `auth export` prints on stderr with exit 1. Verbatim.
pub const EXPORT_GUIDANCE: &str = "cookie export is not available in this build: no automatic cookie extraction is implemented yet.\n\nLog in at https://muse.ai/ in your browser, leave the tab open, and run \"castctl auth export\" again after a cookie source exists.\n\nCopy the login by hand instead:\n  1. In your browser, open https://muse.ai/ and log in.\n  2. Open the browser developer tools and read the cookies for https://muse.ai/.\n  3. Write one line to the active profile's cookies.txt file:\n       hatch_sess=VALUE; other_name=other_value\n     hatch_sess is required. Separate cookies with \"; \".\n  4. Set the file mode to 600.\n  5. Run \"castctl status\" to check the login.\n\nNo file was written or changed.";

/// Captured process output: stdout text, stderr text, exit code.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Outcome {
    /// Bytes written to stdout.
    pub stdout: String,
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
enum FlowErr {
    HelpShown,
    Msg { code: i32, message: Option<String> },
    Exit(i32),
}

fn msg(code: i32, message: impl Into<String>) -> FlowErr {
    FlowErr::Msg {
        code,
        message: Some(message.into()),
    }
}

fn msg_empty(code: i32) -> FlowErr {
    FlowErr::Msg {
        code,
        message: None,
    }
}

/// `usageErr` (`read.go:1075`): a positional error becomes
/// `errCode(2, pe)` with NOTHING pre-printed, so `classifyError`
/// prints exactly one line.
fn usage_err(pe: ParserError) -> FlowErr {
    msg(2, pe.0)
}

/// The outcome under construction, threaded through handlers the
/// way Go threads `Env` stdout/stderr writers.
struct Ctx<'a> {
    out: Outcome,
    getenv: Getenv<'a>,
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
fn resolve_config(
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
    if !allow_missing_create {
        if let Err(e) = loc.require_present() {
            return Err(config_err(e));
        }
    }
    Ok(loc)
}

/// A `profile.Error` / `ConfigError` through `classifyError`: exit
/// 2, one `castctl: <message>` line (the message already carries
/// the `profile: ` prefix exactly once).
fn config_err(e: ConfigError) -> FlowErr {
    msg(e.code, e.message)
}

/// Parse the resolved single config (F5; Go `resolveActive` /
/// `runWithProfile` → `LoadProfile` → `LoadSingleConfig`):
/// every stub path that resolves config in Go also parses the
/// file before resolving the active profile, so a bad config
/// exits 2 here, before the stub. Profile resolution itself
/// stays unimplemented in M2 — the `--profile nosuch`
/// divergence stands. Callers that never resolve config in Go
/// (`update`, `plugin check`, `auth export`, `config migrate`)
/// must NOT call this. A legacy flat file (no `profiles`
/// marker) parses as "not found" here, so it still stubs: Go's
/// legacy-layout refusal is a remaining divergence (see
/// PORTING.md §M2.8).
fn load_resolved_config(loc: &ConfigLocation) -> Result<(), FlowErr> {
    load_single_config(&loc.config_dir).map_err(config_err)?;
    Ok(())
}

/// `resolve_config` + `load_resolved_config`: the full
/// pre-profile gate for stub paths.
fn resolve_and_load(
    ctx: &mut Ctx<'_>,
    g: &GlobalOpts,
    allow_missing_create: bool,
) -> Result<(), FlowErr> {
    let loc = resolve_config(ctx, g, allow_missing_create)?;
    load_resolved_config(&loc)
}

/// The M2 stub (D-M2-3): exactly one fixed stderr line, empty
/// stdout, exit 1.
fn stub(ctx: &mut Ctx<'_>) -> FlowErr {
    ctx.out.stderr.push_str(STUB_LINE);
    msg_empty(1)
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
        Err(FlowErr::Msg { code, message }) => {
            if let Some(m) = message {
                ctx.out.stderr.push_str(&format!("castctl: {m}\n"));
            }
            ctx.out.code = code;
        }
    }
    std::mem::take(&mut ctx.out)
}

/// A `parseOrHelp` command: parse, positional/manual checks,
/// `parseAutoToggles` for wait/send, then config-location
/// resolution + config parse, then the stub.
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
    resolve_and_load(ctx, g, false)?;
    Err(stub(ctx))
}

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
/// config load (release downloads are public URLs). Stub.
fn cmd_update(ctx: &mut Ctx<'_>, spec: &CommandSpec, args: &[String]) -> Result<(), FlowErr> {
    let p = parse_or_help(ctx, spec, args)?;
    check_positionals(&p, &[]).map_err(usage_err)?;
    Err(stub(ctx))
}

/// `cmdFS` (`fs.go:141`) + per-subcommand `fsParse` /
/// `fsPositionals`, then config-location resolution, then stub.
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
    match fs_positional_names(sub) {
        Some(names) => {
            check_positionals(&p, names).map_err(usage_err)?;
        }
        None => {
            if p.positionals.len() > 1 {
                return Err(usage_err(ParserError(format!(
                    "unrecognized arguments: {}",
                    p.positionals[1..].join(" ")
                ))));
            }
        }
    }
    // `fs rm` refuses without --yes BEFORE config resolution
    // (`fs.go:738`); note the message differs from `profile rm`.
    if sub == "rm" && !p.bool("yes") {
        return Err(msg(2, "refusing to delete without --yes"));
    }
    resolve_and_load(ctx, g, false)?;
    Err(stub(ctx))
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
            resolve_and_load(ctx, g, false)?;
            Err(stub(ctx))
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
            resolve_and_load(ctx, g, false)?;
            Err(stub(ctx))
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
            resolve_and_load(ctx, g, false)?;
            Err(stub(ctx))
        }
        "observe-login" => {
            let p = inline_parse(
                ctx,
                auth_sub_defs("observe-login"),
                AUTH_OBSERVE_LOGIN_HELP_TEXT,
                rest,
            )?;
            check_positionals(&p, &[]).map_err(usage_err)?;
            // Tag-off build (no with_chromedp).
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
        "set-outbound" | "set-fingerprint" | "set-tls-engine" => {
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
    resolve_and_load(ctx, g, false)?;
    Err(stub(ctx))
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
    let allow_missing = p.bool("write") || !source_dir.is_empty();
    resolve_config(ctx, g, allow_missing)?;
    Err(stub(ctx))
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
    resolve_and_load(ctx, g, false)?;
    Err(stub(ctx))
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
    resolve_and_load(ctx, g, false)?;
    Err(stub(ctx))
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
    resolve_and_load(ctx, g, false)?;
    Err(stub(ctx))
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
    // No config resolution (probed Go exception): the loader
    // would run next; the stub replaces it.
    Err(stub(ctx))
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

    fn temp_home(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("castctl-cli-{tag}-{}", std::process::id()));
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
        // isolated HOME and no config file, RequirePresent does
        // NOT fail (non-explicit locations always pass) — the
        // stub fires.
        let (_home, map) = isolated_env();
        let out = run_env(&["--log-level", "warn", "status"], map);
        assert_eq!(out.code, 1);
        assert_eq!(out.stderr, STUB_LINE);
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
    fn test_stub_after_config_resolution() {
        // Non-explicit location, no config file: RequirePresent
        // passes (Go: non-explicit always passes) — the stub
        // fires with exit 1.
        let (_home, map) = isolated_env();
        let out = run_env(&["status"], map);
        assert_eq!(out.code, 1);
        assert_eq!(out.stderr, STUB_LINE);
        // Explicit location with a correct basename but a missing
        // file: RequirePresent fails BEFORE the stub (exit 2).
        let home = temp_home("explicit-missing");
        let missing = home.join("config.json");
        let out = run_args(&["--config", missing.to_str().unwrap(), "status"]);
        assert_eq!(out.code, 2);
        assert!(out.stderr.contains("does not exist"));
        assert!(!out.stderr.contains("not ported yet"));
    }

    #[test]
    fn test_stub_fires_with_existing_config() {
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
        let out = run_env(&["status"], map);
        assert_eq!(out.code, 1);
        assert_eq!(out.stdout, "");
        assert_eq!(out.stderr, STUB_LINE);
    }

    #[test]
    fn test_update_and_plugin_check_skip_config() {
        // No config anywhere: update still stubs (no resolution).
        let (_home, map) = isolated_env();
        let out = run_env(&["update", "--dry-run"], map.clone());
        assert_eq!(out.code, 1);
        assert_eq!(out.stderr, STUB_LINE);
        let out = run_env(&["plugin", "check", "x.so"], map);
        assert_eq!(out.code, 1);
        assert_eq!(out.stderr, STUB_LINE);
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
    fn test_plugin_tag_validation_before_stub() {
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
        // non-explicit location -> stub.
        let (_home, map) = isolated_env();
        let out = run_env(&["--"], map);
        assert_eq!(out.code, 1);
        assert_eq!(out.stderr, STUB_LINE);
    }

    #[test]
    fn test_config_migrate_help_and_stub() {
        let out = run_args(&["config", "migrate", "--help"]);
        assert_eq!(out.stdout, CONFIG_MIGRATE_HELP_TEXT);
        assert_eq!(out.code, 0);
        let out = run_args(&["config", "--help"]);
        assert_eq!(out.stdout, CONFIG_HELP_TEXT);
        assert_eq!(out.code, 0);
        // Parse-successful migrate stubs (D-M2-5), even with a
        // missing config file when --write is given.
        let (_home, map) = isolated_env();
        let out = run_env(&["config", "migrate", "--write"], map);
        assert_eq!(out.code, 1);
        assert_eq!(out.stderr, STUB_LINE);
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
}
