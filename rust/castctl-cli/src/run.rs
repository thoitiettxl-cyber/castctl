// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Dispatch: `scanGlobal`, `resolveConfig`, the eight
//! subcommand dispatchers, `classifyError`'s plain branch,
//! and the wired command paths (M7b PR-3 + M7d; the M2 stub
//! D-M2-3 was retired when the stub count reached 0, see
//! PORTING §M7d).
//!
//! Sources at base `dev-rust` `85a8d5e`: `internal/commands/
//! commands.go` (`runInner`, `scanGlobal`, `resolveConfig`,
//! `parseOrHelp`, `classifyError`), `fs.go` (`cmdFS`, `fsParse`),
//! `profilecmd.go` (`cmdProfile`, `profileParse`, `cmdConfig`,
//! `cmdConfigMigrate`), `deliver.go` (`cmdAuth`), `keeper.go`
//! (`cmdKeeper`, `parseKeeperSelection`),
//! `authimport.go` / `authlogin.go` /
//! `authstatus.go` / `authobserve.go`, `read.go` (`usageErr`),
//! `wait.go` (`parseAutoToggles`, `approveDecision`,
//! `cmdAutoApprove`), `deliver/authexport.go` (`ExportGuidance`).
//!
//! All commands in the dispatch table are wired (M7b PR-3 +
//! M7d). The checks Go performs before touching the network
//! still run first: global scan, parse, positional checks,
//! config-location resolution, and parsing the resolved config
//! file (F5). The M2 stub (D-M2-3) this paragraph used to
//! describe was retired when the stub count reached 0.

use castctl_config::config::{SingleConfig, load_single_config};
use castctl_config::configlocation::{ConfigLocation, Getenv, resolve_config_location};
use castctl_config::errors::ConfigError;
use castctl_config::gostr::{go_quote, go_trim_space};
use castctl_config::log::valid_log_level;
use castctl_log_redact::safe_string;

use crate::help_texts::*;
use crate::parser::{ArgParser, Parsed, ParserError, check_positionals};
use crate::table::{
    COMMAND_ORDER, CommandSpec, FS_SUBCOMMANDS, KEEPER_SUBCOMMANDS, PROFILE_SUBCOMMANDS,
    PositionalSpec, auth_sub_defs, command_spec, fs_defs, keeper_sub_help, profile_sub_defs,
    profile_sub_help,
};

/// The version number. Go keeps `Version`/`Commit`/`BuildDate` as
/// vars stamped with `-X` at release time and renders
/// `Version (Commit BuildDate)` whenever a stamp is set
/// (`internal/commands/commands.go:71-76`). The Rust port derives the
/// same stamps from git in `build.rs` (`CASTCTL_BUILD_COMMIT` /
/// `CASTCTL_BUILD_DATE`), so a git checkout renders the same shape as
/// a stamped Go release; without git metadata the bare version is
/// printed, exactly like an unstamped Go build.
pub const VERSION: &str = "0.9.0";

/// Length of the short commit Go stamps into `Commit`
/// (`-X ...Commit=<short hash>`; the release binary reports 7 chars).
const SHORT_COMMIT_LEN: usize = 7;

/// `versionString` (`internal/commands/commands.go:71-76`): the bare
/// version when both stamps are empty, else `VERSION (Commit Date)`
/// with the joined pieces trimmed. Go renders the build date as
/// RFC3339 UTC (`...Z`) while `git log --format=%cI` renders a UTC
/// commit as `+00:00`, so that suffix is normalised to `Z` to keep the
/// rendered shape identical.
fn version_string(commit: &str, date: &str) -> String {
    let commit = commit.trim();
    // `get` keeps a non-ASCII byte boundary from panicking; the stamp
    // is a hex hash, so the fallback is unreachable in practice.
    let commit = commit.get(..SHORT_COMMIT_LEN).unwrap_or(commit);
    let date = date.trim();
    let date = match date.strip_suffix("+00:00") {
        Some(head) => format!("{head}Z"),
        None => date.to_string(),
    };
    if commit.is_empty() && date.is_empty() {
        return VERSION.to_string();
    }
    format!("{VERSION} ({})", format!("{commit} {date}").trim())
}

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
/// `config migrate`, profile
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
/// Set once any command has written through [`write_live`].
static LIVE_WRITTEN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Whether this process already wrote command output straight to the
/// real streams, so the binary must skip replaying the buffered copy
/// that exists only for tests.
pub fn live_output_written() -> bool {
    LIVE_WRITTEN.load(std::sync::atomic::Ordering::SeqCst)
}

/// Write to the real process stream right now, like Go's
/// `fmt.Fprintf(os.Stdout, ...)` inside the keeper tick loop. A
/// long-running command must show its
/// lines while it runs: the buffered `Outcome` only reaches the
/// terminal when the process exits, which is invisible to
/// `journalctl -f` and to anything waiting for the startup line.
/// Write errors are ignored, as Go ignores them on these paths.
pub(crate) fn write_live(to_stderr: bool, text: &str) {
    use std::io::Write;
    // Record that this process streamed: the binary must not replay
    // the buffered copy at exit, or every line prints twice.
    LIVE_WRITTEN.store(true, std::sync::atomic::Ordering::SeqCst);
    if to_stderr {
        let mut e = std::io::stderr();
        let _ = e.write_all(text.as_bytes());
        let _ = e.flush();
    } else {
        let mut o = std::io::stdout();
        let _ = o.write_all(text.as_bytes());
        let _ = o.flush();
    }
}

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
            ctx.out.stdout.push_str(&format!(
                "castctl {}\n",
                version_string(env!("CASTCTL_BUILD_COMMIT"), env!("CASTCTL_BUILD_DATE"))
            ));
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
                ctx.out.stdout.push_str(&format!(
                    "castctl {}\n",
                    version_string(env!("CASTCTL_BUILD_COMMIT"), env!("CASTCTL_BUILD_DATE"))
                ));
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
        "keeper" => cmd_keeper(ctx, &g, &cmd_args),
        "update" => cmd_update(ctx, &spec, &cmd_args),
        _ => cmd_plain(ctx, &g, &spec, &cmd_args),
    };
    match result {
        Ok(()) => {
            ctx.out.code = 0;
        }
        // The single CLI error-render boundary: every handler error
        // is rendered through `render_flow_err`, which applies Go's
        // `SafeString` to the error text — mirroring Go
        // `classifyError` (`commands.go:268-336`), where the plain
        // `cmdError` branch renders `"castctl: " + SummarizeErr`
        // and the `ExportError` branch renders `SafeString`
        // verbatim. Pre-printed parser/usage lines above are NOT
        // redacted: Go's `parseOrHelp` prints those without
        // `SafeString` too.
        Err(e) => {
            let (code, text) = crate::network::render_flow_err(&e);
            ctx.out.code = code;
            ctx.out.stderr.push_str(&text);
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
/// resolution + config parse, then the command's own path —
/// the 13 read-only commands (M4b) and the 19 M7b Phase A
/// commands run the network path, `wait` (M7a) and `send`,
/// `watch` and `chat` (PR-2) run their own paths, and
/// `auto-approve` resolves config + profile itself (no
/// network). `history --download` is NOT in the network
/// set: it is checked separately below and runs its own
/// download path (PR-3). (The M2 stub this doc used to
/// describe was retired at stub count 0; see PORTING
/// §M7d.)
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
            // guidance prints on stderr with exit 1 — through
            // `SafeString`, like Go's `ExportError` branch of
            // `classifyError` (M7f fix loop 1, B1: Go renders
            // `hatch_sess=[redacted]`, probed on cue 2026-11-07).
            let _ = inline_parse(ctx, vec![], AUTH_EXPORT_HELP_TEXT, rest)?;
            ctx.out.stderr.push_str(&safe_string(EXPORT_GUIDANCE));
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

    /// The `--version` line the binary must print, built from the same
    /// stamps the binary uses (Go renders a stamped build the same way,
    /// `internal/commands/commands.go:71-76`).
    fn version_line() -> String {
        format!(
            "castctl {}\n",
            version_string(env!("CASTCTL_BUILD_COMMIT"), env!("CASTCTL_BUILD_DATE"))
        )
    }

    #[test]
    fn version_string_matches_go_rendering() {
        // Go: bare version when neither stamp is set.
        assert_eq!(version_string("", ""), "0.9.0");
        // Go: short commit only.
        assert_eq!(version_string("1396697", ""), "0.9.0 (1396697)");
        // Go: date only, RFC3339 UTC.
        assert_eq!(
            version_string("", "2026-11-04T21:38:36Z"),
            "0.9.0 (2026-11-04T21:38:36Z)"
        );
        // Go release shape: short hash + UTC date.
        assert_eq!(
            version_string("1396697abc", "2026-11-04T21:38:36Z"),
            "0.9.0 (1396697 2026-11-04T21:38:36Z)"
        );
        // `git log --format=%cI` renders UTC as +00:00; Go writes Z.
        assert_eq!(
            version_string("1396697abc", "2026-11-04T21:38:36+00:00"),
            "0.9.0 (1396697 2026-11-04T21:38:36Z)"
        );
        // Non-UTC offsets are preserved verbatim.
        assert_eq!(
            version_string("1396697", "2026-11-04T21:38:36+07:00"),
            "0.9.0 (1396697 2026-11-04T21:38:36+07:00)"
        );
        // Whitespace is trimmed like Go's strings.TrimSpace.
        assert_eq!(
            version_string("  1396697  ", "  2026-11-04T21:38:36Z  "),
            "0.9.0 (1396697 2026-11-04T21:38:36Z)"
        );
    }

    #[test]
    fn test_version_and_global_help() {
        let out = run_args(&["--version"]);
        assert_eq!(
            out,
            Outcome {
                stdout: version_line(),
                stdout_bytes: Vec::new(),
                stderr: String::new(),
                code: 0
            }
        );
        let out = run_args(&["--vers"]);
        assert_eq!(out.stdout, version_line());
        assert_eq!(out.code, 0);
        let out = run_args(&["--v"]);
        assert_eq!(out.stdout, version_line());
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
        assert_eq!(out.stdout, version_line());
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
        // Unknown subcommand: one line, no help.
        let out = run_args(&["fs", "bogus"]);
        assert_eq!(
            out.stderr,
            "castctl: argument subcommand: invalid choice: \"bogus\" (choose from ls, tree, stat, cat, get, find, put, write, edit, mkdir, mv, rm)\n"
        );
        assert_eq!(out.code, 2);
        // Dispatcher help: only exact --help/-h at args[0].
        let out = run_args(&["fs", "--help"]);
        assert_eq!(out.stdout, FS_HELP_TEXT);
        assert_eq!(out.code, 0);
        let out = run_args(&["fs", "--hel"]);
        assert_eq!(out.code, 2);
        assert!(out.stderr.contains("invalid choice"));
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
    }

    #[test]
    fn test_auth_export_guidance_exit_1() {
        // M7f fix loop 1 (B1): Go renders the guidance through
        // `SafeString` (`ExportError` branch of `classifyError`),
        // so `hatch_sess=VALUE` becomes `hatch_sess=[redacted]`
        // (probed on cue 2026-11-07, exit 1, stdout empty).
        // `other_name=other_value` is untouched (not in the vocab).
        // The old test asserted the raw guidance — that
        // contradicted Go.
        let out = run_args(&["auth", "export"]);
        assert_eq!(out.code, 1);
        assert_eq!(
            out.stderr,
            "cookie export is not available in this build: no automatic cookie extraction is implemented yet.\n\nLog in at https://muse.ai/ in your browser, leave the tab open, and run \"castctl auth export\" again after a cookie source exists.\n\nCopy the login by hand instead:\n  1. In your browser, open https://muse.ai/ and log in.\n  2. Open the browser developer tools and read the cookies for https://muse.ai/.\n  3. Write one line to the active profile's cookies.txt file:\n       hatch_sess=[redacted]; other_name=other_value\n     hatch_sess is required. Separate cookies with \"; \".\n  4. Set the file mode to 600.\n  5. Run \"castctl status\" to check the login.\n\nNo file was written or changed.\n"
        );
        assert!(out.stdout.is_empty());
        // Extra positionals silently ignored (Go quirk).
        let out = run_args(&["auth", "export", "extra", "args"]);
        assert_eq!(out.code, 1);
    }

    /// M7f fix loop 1 (B1): run `profile list` against a single-config
    /// fixture (sweep-style base profile + one bad block) with a fake
    /// cookie file; the parse fails before any cookie read, so the
    /// cookie content is irrelevant and the test is hermetic.
    fn run_profile_list_with_cfg(tag: &str, cfg: &str) -> Outcome {
        let dir = temp_home(tag);
        std::fs::create_dir_all(dir.join("profiles/p1")).unwrap();
        std::fs::write(dir.join("profiles/p1/cookies.txt"), "hatch_sess=FAKE\n").unwrap();
        std::fs::write(dir.join("config.json"), cfg).unwrap();
        let (_home, map) = isolated_env();
        run_env(
            &[
                "--config",
                dir.join("config.json").to_str().unwrap(),
                "profile",
                "list",
            ],
            map,
        )
    }

    /// Sweep-style base profile shared by the B1 fixtures (same shape
    /// as the Go probes on cue).
    const B1_BASE: &str = r#"{"default_profile":"p1","profiles":{"p1":{"cookies_file":"profiles/p1/cookies.txt","node_id":"a4d787ca4a5a87d9","auto_approve":"always"}}}"#;

    fn b1_cfg(extra: &str) -> String {
        // Strip exactly ONE trailing `}` (the root close) so `extra`
        // lands at the top level; `trim_end_matches` would eat all
        // three trailing braces.
        let mut base = B1_BASE[..B1_BASE.len() - 1].to_string();
        base.push(',');
        base.push_str(extra);
        base.push('}');
        base
    }

    #[test]
    fn m7f_fix1_b1_private_key_redacted() {
        // Go (probed on cue 2026-11-07, `profile list`, exit 2):
        // `castctl: profile: parse outbound: private_key: [redacted]
        // unknown field "private_key"` — Go renders every plain CLI
        // error through `SafeString` (`classifyError` →
        // `SummarizeErr`); Rust printed the raw `private_key: json:`.
        let out = run_profile_list_with_cfg(
            "m7f-red-privkey",
            &b1_cfg(r#""outbounds":[{"type":"direct","tag":"d","private_key":5}]"#),
        );
        assert_eq!(out.code, 2);
        assert!(out.stdout.is_empty());
        assert_eq!(
            out.stderr,
            "castctl: profile: parse outbound: private_key: [redacted] unknown field \"private_key\"\n"
        );
    }

    #[test]
    fn m7f_fix1_b1_password_redacted() {
        let out = run_profile_list_with_cfg(
            "m7f-red-password",
            &b1_cfg(
                r#""outbounds":[{"type":"hysteria2","tag":"h","server":"example.com","server_port":443,"password":5}]"#,
            ),
        );
        assert_eq!(out.code, 2);
        assert!(out.stdout.is_empty());
        assert_eq!(
            out.stderr,
            "castctl: profile: parse outbound: password: [redacted] cannot unmarshal number into Go struct field Hysteria2OutboundOptions.password of type string\n"
        );
    }

    #[test]
    fn m7f_fix1_b1_token_redacted() {
        let out = run_profile_list_with_cfg(
            "m7f-red-token",
            &b1_cfg(r#""outbounds":[{"type":"direct","tag":"d","token":5}]"#),
        );
        assert_eq!(out.code, 2);
        assert!(out.stdout.is_empty());
        assert_eq!(
            out.stderr,
            "castctl: profile: parse outbound: token: [redacted] unknown field \"token\"\n"
        );
    }

    #[test]
    fn m7f_fix1_b1_dns_fragment_redacted() {
        // The redacted token is not a secret at all (a docs anchor
        // Go's backstop over-redacts), so only applying SafeString
        // itself reproduces it — a validator-local "redact secret
        // values" fix would not.
        let out = run_profile_list_with_cfg(
            "m7f-red-dns",
            &b1_cfg(r#""dns":{"servers":[{"tag":"s","address":"1.1.1.1"}]}"#),
        );
        assert_eq!(out.code, 2);
        assert!(out.stdout.is_empty());
        assert_eq!(
            out.stderr,
            "castctl: profile: parse dns: servers[0]: legacy DNS server formats are deprecated in sing-box 1.12.0 and removed in sing-box 1.14.0, checkout migration: https://sing-box.sagernet.org/migration/#%5Bredacted%5D\n"
        );
    }

    #[test]
    fn m7f_fix1_b1_bearer_token_unredacted() {
        // Negative control (probed on cue 2026-11-07): Go prints
        // `bearer_token: json:` unredacted — the vocab has no
        // `bearer_token` entry and it does not end in `_key`.
        let out = run_profile_list_with_cfg(
            "m7f-red-bearer",
            &b1_cfg(r#""outbounds":[{"type":"direct","tag":"d","bearer_token":5}]"#),
        );
        assert_eq!(out.code, 2);
        assert!(out.stdout.is_empty());
        assert_eq!(
            out.stderr,
            "castctl: profile: parse outbound: bearer_token: json: unknown field \"bearer_token\"\n"
        );
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
        // minus the 6 dedicated dispatch arms — must be
        // covered exactly by the handled sets (R2 §6.1).
        let dedicated = ["fs", "auth", "profile", "config", "keeper", "update"];
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

    /// Go's `LoadSingleConfig` runs the deep `webui` block parse with
    /// the config directory (`internal/profile/webui.go:274-287`), so a
    /// block that breaks a rule fails EVERY command with exit 2 and the
    /// `profile: ` prefix. Verified live against the Go binary on cue:
    /// `castctl --config <dir>/config.json status` →
    /// `castctl: profile: "webui.ui_dir" must not overlap the config
    /// directory`, exit 2 (and the same for the unknown-key, listen,
    /// token, duration and rate-limit rules).
    #[test]
    fn bad_webui_block_fails_every_command_at_load() {
        let cases: [(&str, &str); 4] = [
            (
                r#"{"listen":"127.0.0.1:8317","token":"t","bogus":1}"#,
                "castctl: profile: unknown webui config key \"bogus\"\n",
            ),
            (
                r#"{"listen":"0.0.0.0:8317","token":"t"}"#,
                "castctl: profile: \"webui.listen\" host must be loopback\n",
            ),
            (
                r#"{"listen":"127.0.0.1:8317","token":"   "}"#,
                "castctl: profile: \"webui.token\" must not be empty\n",
            ),
            (
                r#"{"listen":"127.0.0.1:8317","token":"t","session_idle_timeout":"1s"}"#,
                "castctl: profile: \"webui.session_idle_timeout\" must be a duration string from 1m0s to 720h0m0s\n",
            ),
        ];
        for (block, want) in cases {
            let home = temp_home("webui-load");
            let cfg_dir = home.join(".config/castctl");
            std::fs::create_dir_all(&cfg_dir).unwrap();
            let cfg = format!(
                "{{\"default_profile\":\"x\",\"profiles\":{{\"x\":{{}}}},\"webui\":{block}}}"
            );
            std::fs::write(cfg_dir.join("config.json"), cfg).unwrap();
            let mut map = HashMap::new();
            map.insert("HOME".to_string(), home.to_str().unwrap().to_string());
            map.insert(
                "XDG_CONFIG_HOME".to_string(),
                cfg_dir.parent().unwrap().to_str().unwrap().to_string(),
            );
            for cmd in [&["status"][..], &["profile", "list"][..]] {
                let out = run_env(cmd, map.clone());
                assert_eq!(out.code, 2, "{cmd:?} must refuse: {block}");
                assert_eq!(out.stderr, want, "{cmd:?} message: {block}");
                assert!(out.stdout.is_empty(), "{cmd:?} stdout: {block}");
            }
        }
    }

    /// The overlap rule is checked with the config directory, so a
    /// `ui_dir` that resolves inside it is refused at load exactly like
    /// Go (`DirOverlaps`, `internal/profile/webui.go:350`).
    #[test]
    fn overlapping_ui_dir_is_refused_at_load() {
        let home = temp_home("webui-overlap");
        let cfg_dir = home.join(".config/castctl");
        std::fs::create_dir_all(cfg_dir.join("ui")).unwrap();
        let cfg = r#"{"default_profile":"x","profiles":{"x":{}},"webui":{"listen":"127.0.0.1:8317","token":"t","ui_dir":"ui"}}"#;
        std::fs::write(cfg_dir.join("config.json"), cfg).unwrap();
        let mut map = HashMap::new();
        map.insert("HOME".to_string(), home.to_str().unwrap().to_string());
        map.insert(
            "XDG_CONFIG_HOME".to_string(),
            cfg_dir.parent().unwrap().to_str().unwrap().to_string(),
        );
        let out = run_env(&["status"], map);
        assert_eq!(out.code, 2);
        assert_eq!(
            out.stderr,
            "castctl: profile: \"webui.ui_dir\" must not overlap the config directory\n"
        );
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
}
