// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! `fs` — System Files over the gateway (Go
//! `internal/commands/fs.go` + `internal/fsclient`).
//!
//! The CLI `fs` handler: per-subcommand parse (in
//! `run.rs`, `fs_parse`) → `validate_fs` (positional
//! checks, `rm` --yes refusal, pre-collapse `..`
//! reject, `norm` validation — all before any config
//! resolution or gateway call) → config/profile
//! resolution (`run_fs_command`, mirroring
//! `run_network_command`) → the `Fs` client over the
//! leased gateway (`exec_fs`).
//!
//! The pre-collapse `..` reject is the CLI analogue of
//! Go's Telegram-layer `fsHasTraversal`
//! (`internal/commands/telegram_fs.go:60-93`): Go's CLI
//! has no equivalent — `normOr2` only clamps — so the
//! Rust CLI ADDS the layer (M7a dev 30, Boss mandatory).
//! It lives here, not in `castctl-fsclient::norm`
//! (which must keep clamping for Go parity).

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use castctl_fsclient::editor::{apply_replace, edit_in_editor, fmt_size};
use castctl_fsclient::{Entry, Fs, FsError, FsGateway, go_json_string, norm};
use castctl_gateway::gateway::{Body, RequestOptions};
use castctl_gateway::shared::SharedConn;
use serde_json::{Value, json};

use crate::network::{CmdOut, classify_conn_error, write_json_serde, write_json_text};
use crate::parser::{Parsed, ParserError, check_positionals};
use crate::run::{FlowErr, GlobalOpts, msg, resolve_and_load_single, usage_err};
use crate::runtime::{Runtime, build_runtime};
use crate::table::fs_positional_names;

/// Pre-collapse `..` check (Go `fsHasTraversal`,
/// `internal/commands/telegram_fs.go:60-70`): trim,
/// backslashes → slashes, strip ONE leading
/// `sandbox://`, then any `/`-separated component
/// exactly `..` rejects. `..hidden`, `...`, `..etc`
/// are NOT components and pass; `a/../b` rejects.
pub(crate) fn has_traversal(raw: &str) -> bool {
    let s = raw.trim();
    let s = s.replace('\\', "/");
    let s = s.strip_prefix("sandbox://").unwrap_or(&s);
    s.split('/').any(|part| part == "..")
}

/// The CLI reject (D-M7b-PR2-6): fixed sentence, never
/// echoing the input path, exit 2 (a validation failure,
/// like `normOr2`'s mapping).
pub(crate) fn reject_traversal() -> FlowErr {
    msg(2, "path traversal not allowed")
}

/// The `FsGateway` over the CLI's leased `SharedConn`
/// (Go `fsclient.Gateway` over `conn.Gateway`): one
/// unary JSON call with the `Fs` layer's timeout.
struct SharedFsGateway {
    shared: Arc<SharedConn>,
}

impl FsGateway for SharedFsGateway {
    fn call_json(
        &self,
        method: &str,
        body: Value,
        timeout: Duration,
    ) -> Pin<Box<dyn Future<Output = Result<Value, FsError>> + Send + '_>> {
        let shared = Arc::clone(&self.shared);
        let method = method.to_string();
        Box::pin(async move {
            let v = shared
                .call_json(
                    &method,
                    RequestOptions {
                        body: Body::Json(body),
                        timeout,
                        ..Default::default()
                    },
                )
                .await
                .map_err(FsError::from)?;
            Ok(v)
        })
    }
}

/// Map an `FsError` to the CLI exit taxonomy (Go
/// `runFS` → `runNetwork` → `classifyConnError`):
/// transport errors classify as gateway/auth/timeout;
/// local-filesystem and protocol errors are plain
/// errors, exit 1. NOTE (M7a dev 21 class): a local
/// `io::Error` renders in Rust form (`No such file or
/// directory (os error 2)`), not Go's `*PathError`
/// form — the `Fs` layer carries no op/path context
/// to render Go-style, so this is a known text gap,
/// not a code path the harness pins.
fn fs_err(e: FsError) -> FlowErr {
    match e {
        FsError::Transport(t) => classify_conn_error(&t),
        FsError::Io(io) => msg(1, io.to_string()),
        FsError::Other(other) => msg(1, other.to_string()),
    }
}

/// Which positionals of `sub` are remote paths (the
/// reject + `norm` apply to these, in order). `find`
/// takes a name fragment — never checked. `put` checks
/// the REMOTE only — the local path is never normed
/// (Go `fs.go:560-566`).
fn fs_path_args<'a>(sub: &str, p: &'a Parsed) -> Vec<&'a str> {
    match sub {
        "ls" | "tree" | "stat" | "cat" | "get" | "mkdir" | "rm" | "write" | "edit" => {
            match p.positionals.first() {
                Some(path) => vec![path.as_str()],
                None => vec![],
            }
        }
        "put" => match p.positionals.get(1) {
            Some(remote) => vec![remote.as_str()],
            None => vec![],
        },
        "mv" => p.positionals.iter().map(String::as_str).collect(),
        _ => vec![],
    }
}

/// Positional checks + `fs rm` --yes refusal +
/// traversal reject + `norm` validation, in Go order
/// (`fs.go`: `fsPositionals` → `rm` refusal → `normOr2`,
/// with the reject inserted before `norm`, since `norm`
/// would clamp the `..` away). Runs BEFORE any config
/// resolution or gateway call: a rejected path makes
/// ZERO gateway calls (fail-before).
pub(crate) fn validate_fs(sub: &str, p: &Parsed) -> Result<(), FlowErr> {
    match fs_positional_names(sub) {
        Some(names) => {
            check_positionals(p, names).map_err(usage_err)?;
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
    // `fs rm` refuses without --yes BEFORE the traversal
    // check (`fs.go:738`): the refusal wins over the
    // traversal error for `fs rm ../x` without --yes.
    if sub == "rm" && !p.bool("yes") {
        return Err(msg(2, "refusing to delete without --yes"));
    }
    let paths = fs_path_args(sub, p);
    for path in &paths {
        if has_traversal(path) {
            return Err(reject_traversal());
        }
    }
    // `normOr2` (`fs.go:254`): a `Norm` error is a
    // validation failure, exit 2. Unreachable for rooted
    // input (the clamp never yields `..`), but mapped
    // exactly like Go's.
    for path in &paths {
        norm(path).map_err(|e| msg(2, e.to_string()))?;
    }
    Ok(())
}

/// `pad19` (`fs.go:341`): truncate to 19 runes, then
/// pad with spaces to 19 runes.
fn pad19(s: &str) -> String {
    let mut r: Vec<char> = s.chars().take(19).collect();
    while r.len() < 19 {
        r.push(' ');
    }
    r.into_iter().collect()
}

/// Go `path.Ext` (`fs.go:640` passes it as the editor
/// suffix): the suffix from the final dot in the final
/// path element, or `""`. Unlike Rust's
/// `Path::extension`, a dotfile (`.md`) yields `.md`.
fn go_path_ext(remote: &str) -> &str {
    let base = remote.rsplit('/').next().unwrap_or(remote);
    match base.rfind('.') {
        Some(i) => &base[i..],
        None => "",
    }
}

/// `writeTreeJSON` (`fs.go:421`): `[{"path": rel,
/// **entry}]` with path first, 2-space indent.
fn write_tree_json(rows: &[castctl_fsclient::WalkEntry]) -> String {
    let mut b = String::new();
    b.push_str("[\n");
    for (i, r) in rows.iter().enumerate() {
        let entry_json = r.entry.to_json();
        if i > 0 {
            b.push_str(",\n");
        }
        b.push_str("  {\"path\":");
        b.push_str(&go_json_string(&r.rel));
        // Splice the entry object after its opening brace
        // (Go's exact branch, including its len guard).
        if entry_json.len() > 1 {
            b.push(',');
            b.push_str(&entry_json[1..]);
        } else {
            b.push('}');
        }
    }
    if !rows.is_empty() {
        b.push('\n');
    }
    b.push_str("]\n");
    b
}

/// `writeEditResult` (`fs.go:670`): `{**write_result,
/// "changed": true}` with the write result's fields
/// first (path, bytes_written, changed).
fn write_edit_result(path: &str, bytes_written: i64) -> String {
    format!(
        "{{\n  \"path\": {},\n  \"bytes_written\": {},\n  \"changed\": true\n}}\n",
        go_json_string(path),
        bytes_written
    )
}

/// Render a list of entries as Go `writeJSON` does
/// (2-space indent + trailing newline) from the
/// entries' compact `to_json` forms.
fn entries_json(entries: &[Entry]) -> String {
    let compact = format!(
        "[{}]",
        entries
            .iter()
            .map(Entry::to_json)
            .collect::<Vec<_>>()
            .join(",")
    );
    write_json_text(&compact)
}

/// Run one `fs` subcommand against an already-built
/// runtime. `stdin_data` is the `fs write` stdin bytes,
/// read BEFORE connecting (Go `fs.go:584-596` reads
/// stdin before `runFS`); `None` for every other
/// subcommand.
pub(crate) async fn exec_fs(
    rt: &Runtime,
    sub: &str,
    p: &Parsed,
    stdin_data: Option<Vec<u8>>,
) -> Result<CmdOut, FlowErr> {
    let fs = Fs::new(Some(Arc::new(SharedFsGateway {
        shared: Arc::clone(&rt.shared),
    })));
    match sub {
        "ls" => {
            let path = p.positionals.first().cloned().unwrap_or_default();
            let mut ents = fs.list_dir(&path).await.map_err(fs_err)?;
            if !p.bool("all") {
                ents.retain(|e| !e.name.starts_with('.'));
            }
            if p.bool("json") {
                return Ok(CmdOut::out(entries_json(&ents)));
            }
            let mut s = String::new();
            for e in &ents {
                let mut name = e.name.clone();
                if e.entry_type == "directory" {
                    name.push('/');
                }
                if p.bool("long") {
                    let type_char = e.entry_type.chars().next().unwrap_or('?');
                    s.push_str(&format!(
                        "{type_char} {:>7} {} {name}\n",
                        fmt_size(e.size),
                        pad19(&e.modified_at)
                    ));
                } else {
                    s.push_str(&name);
                    s.push('\n');
                }
            }
            Ok(CmdOut::out(s))
        }
        "tree" => {
            let path = p.positionals.first().cloned().unwrap_or_default();
            let mut depth = p.int_val("depth");
            if depth < 0 {
                // A negative depth must never reach `Walk`,
                // whose negative is the internal unlimited
                // sentinel used by `fs get` (`fs.go:352-368`).
                depth = 0;
            }
            let mut rows = fs.walk(&path, depth).await.map_err(fs_err)?;
            if !p.bool("all") {
                rows.retain(|r| !r.rel.split('/').any(|comp| comp.starts_with('.')));
            }
            if p.bool("json") {
                return Ok(CmdOut::out(write_tree_json(&rows)));
            }
            let mut s = String::new();
            let header = if path.is_empty() {
                "/".to_string()
            } else {
                path
            };
            s.push_str(&header);
            s.push('\n');
            for r in &rows {
                let mut name = r.entry.name.clone();
                if r.entry.entry_type == "directory" {
                    name.push('/');
                }
                s.push_str(&"  ".repeat((r.level + 1) as usize));
                s.push_str(&name);
                s.push('\n');
            }
            Ok(CmdOut::out(s))
        }
        "stat" => {
            let path = p.positionals.first().cloned().unwrap_or_default();
            let st = fs.stat(&path).await.map_err(fs_err)?;
            Ok(CmdOut::out(write_json_serde(&st)?))
        }
        "cat" => {
            let path = p.positionals.first().cloned().unwrap_or_default();
            let max_bytes = if p.int_is_set("max-bytes") {
                Some(p.int_val("max-bytes"))
            } else {
                None
            };
            let data = fs.read_file(&path, max_bytes).await.map_err(fs_err)?;
            let head_len = data.len().min(8192);
            if data[..head_len].contains(&0) && !p.bool("binary") {
                return Err(msg(
                    1,
                    format!(
                        "{path}: binary file ({} bytes); use `fs get` or --binary",
                        data.len()
                    ),
                ));
            }
            Ok(CmdOut::bytes(data))
        }
        "get" => {
            let path = p.positionals.first().cloned().unwrap_or_default();
            let output = if p.str_is_set("output") {
                p.str("output")
            } else {
                ".".to_string()
            };
            // `os.MkdirAll(output)` FIRST, before the
            // gateway call (`fs.go:509-534`); Go-style
            // error text via the shared `oserr` helper.
            castctl_config::oserr::mkdir_all(&output).map_err(|text| msg(1, text))?;
            let saved = fs
                .get(&path, std::path::Path::new(&output), p.bool("recursive"))
                .await
                .map_err(fs_err)?;
            let saved: Vec<String> = saved
                .iter()
                .map(|pb| pb.to_string_lossy().into_owned())
                .collect();
            Ok(CmdOut::out(write_json_serde(&json!({"saved": saved}))?))
        }
        "find" => {
            let name = p.positionals.first().cloned().unwrap_or_default();
            let ents = fs.search(&name, p.int_val("limit")).await.map_err(fs_err)?;
            Ok(CmdOut::out(entries_json(&ents)))
        }
        "put" => {
            let local = p.positionals.first().cloned().unwrap_or_default();
            let remote = p.positionals.get(1).cloned().unwrap_or_default();
            let results = fs
                .put(
                    std::path::Path::new(&local),
                    &remote,
                    p.bool("recursive"),
                    !p.bool("no-clobber"),
                )
                .await
                .map_err(fs_err)?;
            let compact = format!(
                "[{}]",
                results
                    .iter()
                    .map(|r| r.to_json())
                    .collect::<Vec<_>>()
                    .join(",")
            );
            Ok(CmdOut::out(write_json_text(&compact)))
        }
        "write" => {
            let remote = p.positionals.first().cloned().unwrap_or_default();
            // Stdin was read before connecting (in
            // `cmd_fs`); the driver passes its own read.
            let data = stdin_data.unwrap_or_default();
            if p.bool("append") {
                let old = fs.read_file(&remote, None).await.map_err(fs_err)?;
                let mut combined = old;
                combined.extend_from_slice(&data);
                let r = fs
                    .write_file(&remote, &combined, true, true)
                    .await
                    .map_err(fs_err)?;
                Ok(CmdOut::out(write_json_text(&r.to_json())))
            } else {
                let r = fs
                    .write_file(&remote, &data, !p.bool("no-clobber"), true)
                    .await
                    .map_err(fs_err)?;
                Ok(CmdOut::out(write_json_text(&r.to_json())))
            }
        }
        "edit" => {
            let remote = p.positionals.first().cloned().unwrap_or_default();
            let before = fs.read_file(&remote, None).await.map_err(fs_err)?;
            let pairs = p.pairs("replace");
            let after: Vec<u8> = if !pairs.is_empty() {
                // NOTE: Go applies replacements to the raw
                // bytes as a string; Rust needs `&str`, so
                // non-UTF8 content round-trips lossily here
                // (U+FFFD substitution). Recorded in PORTING.
                let mut text = String::from_utf8_lossy(&before).into_owned();
                for (old, new) in &pairs {
                    text = apply_replace(&text, old, new, -1).map_err(|e| msg(2, e.to_string()))?;
                }
                text.into_bytes()
            } else {
                edit_in_editor(&before, go_path_ext(&remote)).map_err(fs_err)?
            };
            if after == before {
                return Ok(CmdOut::out(write_json_serde(
                    &json!({"path": remote, "changed": false}),
                )?));
            }
            let r = fs
                .write_file(&remote, &after, true, true)
                .await
                .map_err(fs_err)?;
            Ok(CmdOut::out(write_edit_result(&r.path, r.bytes_written)))
        }
        "mkdir" => {
            let path = p.positionals.first().cloned().unwrap_or_default();
            let r = fs.mkdir(&path, true).await.map_err(fs_err)?;
            Ok(CmdOut::out(write_json_serde(&r)?))
        }
        "mv" => {
            let src = p.positionals.first().cloned().unwrap_or_default();
            let dst = p.positionals.get(1).cloned().unwrap_or_default();
            let r = fs
                .move_path(&src, &dst, p.bool("force"), true)
                .await
                .map_err(fs_err)?;
            Ok(CmdOut::out(write_json_serde(&r)?))
        }
        "rm" => {
            let path = p.positionals.first().cloned().unwrap_or_default();
            let r = fs
                .delete(&path, p.bool("recursive"))
                .await
                .map_err(fs_err)?;
            Ok(CmdOut::out(write_json_serde(&r)?))
        }
        _ => Err(msg(1, format!("command fs {sub} is not a network command"))),
    }
}

/// Run one `fs` subcommand from the CLI: resolve the
/// config and profile (kept for the runtime builder),
/// build the tokio runtime and the per-profile runtime,
/// dispatch, and append the stdout/stderr text to the
/// outcome. This is the `fs` mirror of
/// `run_network_command`.
///
/// `stdin_data` is the `fs write` stdin bytes (read
/// before connecting by the caller).
pub(crate) fn run_fs_command(
    ctx: &mut crate::run::Ctx<'_>,
    g: &GlobalOpts,
    sub: &str,
    p: &Parsed,
    stdin_data: Option<Vec<u8>>,
) -> Result<(), FlowErr> {
    let (loc, single) = resolve_and_load_single(ctx, g)?;
    let profile_flag = if g.profile_set {
        Some(g.profile_flag.as_str())
    } else {
        None
    };
    let getenv = ctx.getenv;
    let tokio_rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| msg(1, format!("failed to start async runtime: {e}")))?;
    let sub = sub.to_string();
    let p = p.clone();
    let out = tokio_rt.block_on(async move {
        let runtime = build_runtime(&loc, single.as_ref(), profile_flag, getenv)?;
        exec_fs(&runtime, &sub, &p, stdin_data).await
    })?;
    ctx.out.stdout.push_str(&out.stdout);
    ctx.out.stdout_bytes.extend_from_slice(&out.stdout_bytes);
    ctx.out.stderr.push_str(&out.stderr);
    if out.code != 0 {
        return Err(FlowErr::Exit(out.code));
    }
    Ok(())
}

/// Run one `fs` subcommand against an already-built
/// runtime (a fake gateway in tests) and return
/// (stdout bytes, stderr, exit code), rendering
/// `FlowErr` exactly like `run_driver_command` does.
/// Test-only: production never calls this.
pub async fn run_driver_fs(
    rt: &Runtime,
    sub: &str,
    p: &Parsed,
    stdin_data: Option<Vec<u8>>,
) -> (Vec<u8>, String, i32) {
    if let Err(e) = validate_fs(sub, p) {
        return render_driver_fs(Err(e));
    }
    render_driver_fs(exec_fs(rt, sub, p, stdin_data).await)
}

fn render_driver_fs(result: Result<CmdOut, FlowErr>) -> (Vec<u8>, String, i32) {
    match result {
        Ok(out) => (out.stdout_combined(), out.stderr, out.code),
        Err(FlowErr::HelpShown) => (Vec::new(), String::new(), 0),
        Err(FlowErr::Exit(code)) => (Vec::new(), String::new(), code),
        Err(FlowErr::Verbatim { code, text }) => (
            Vec::new(),
            if text.is_empty() {
                String::new()
            } else {
                format!("{text}\n")
            },
            code,
        ),
        Err(FlowErr::Msg { code, message }) => (
            Vec::new(),
            message
                .map(|m| format!("castctl: {m}\n"))
                .unwrap_or_default(),
            code,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::render_flow_err;
    use crate::parser::ArgParser;
    use crate::table::fs_defs;

    /// Parse `args` with the production `fs` subcommand
    /// defs (the same parser `cmd_fs` uses).
    fn parse_fs(sub: &str, args: &[&str]) -> Parsed {
        let (defs, help_text) = fs_defs(sub);
        let ap = ArgParser { defs, help_text };
        let argv: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        let mut stdout = String::new();
        ap.parse(&argv, &mut stdout).unwrap().parsed
    }

    #[test]
    fn has_traversal_rejects_dotdot_components() {
        // (D-M7b-PR2-7 + Go TestTelegramFSTraversalBlocked
        // shapes, adapted to raw CLI paths.)
        for raw in [
            "..",
            "../",
            "../etc",
            "a/../b",
            "a/../../b",
            "../a",
            "a/..",
            "../..",
            "sandbox://../x",
            "sandbox://../etc",
            "..\\x",
            "..\\etc",
        ] {
            assert!(has_traversal(raw), "must reject {raw:?}");
        }
    }

    #[test]
    fn has_traversal_allows_dot_names() {
        for raw in [
            "",
            "x",
            "a/b",
            "..hidden",
            "..hidden/x",
            "...",
            "..etc",
            "a/./b",
            "a//b",
            ".hidden/x",
            "sandbox://a/b",
        ] {
            assert!(!has_traversal(raw), "must allow {raw:?}");
        }
    }

    #[test]
    fn reject_traversal_message_is_fixed() {
        let (code, text) = render_flow_err(&reject_traversal());
        assert_eq!(code, 2);
        assert_eq!(text, "castctl: path traversal not allowed\n");
    }

    #[test]
    fn validate_fs_cat_traversal_rejects_before_network() {
        let p = parse_fs("cat", &["../x"]);
        let (code, text) = render_flow_err(&validate_fs("cat", &p).unwrap_err());
        assert_eq!(code, 2);
        assert_eq!(text, "castctl: path traversal not allowed\n");
    }

    #[test]
    fn validate_fs_rm_without_yes_refuses_first() {
        // `fs rm ../x` without --yes reports the refusal,
        // not the traversal (`fs.go:738` order).
        let p = parse_fs("rm", &["../x"]);
        let (code, text) = render_flow_err(&validate_fs("rm", &p).unwrap_err());
        assert_eq!(code, 2);
        assert_eq!(text, "castctl: refusing to delete without --yes\n");
        // With --yes, the traversal reject fires.
        let p = parse_fs("rm", &["--yes", "../x"]);
        let (code, text) = render_flow_err(&validate_fs("rm", &p).unwrap_err());
        assert_eq!(code, 2);
        assert_eq!(text, "castctl: path traversal not allowed\n");
    }

    #[test]
    fn validate_fs_mv_checks_both_paths() {
        let p = parse_fs("mv", &["../a", "b"]);
        assert!(validate_fs("mv", &p).is_err());
        let p = parse_fs("mv", &["a", "../b"]);
        assert!(validate_fs("mv", &p).is_err());
        let p = parse_fs("mv", &["a", "b"]);
        assert!(validate_fs("mv", &p).is_ok());
    }

    #[test]
    fn validate_fs_find_is_exempt() {
        // `find` takes a name fragment: never checked.
        let p = parse_fs("find", &[".."]);
        assert!(validate_fs("find", &p).is_ok());
        let p = parse_fs("find", &["../x"]);
        assert!(validate_fs("find", &p).is_ok());
    }

    #[test]
    fn validate_fs_put_checks_remote_only() {
        // A traversal in the LOCAL path is not the CLI's
        // business (it is never normed); the remote is.
        let p = parse_fs("put", &["../local.txt", "remote.txt"]);
        assert!(validate_fs("put", &p).is_ok());
        let p = parse_fs("put", &["local.txt", "../remote.txt"]);
        assert!(validate_fs("put", &p).is_err());
    }

    #[test]
    fn symlink_named_component_passes_through_unresolved() {
        // D-M7b-PR2-7 boundary pin: the client cannot see
        // a remote symlink's target (`Norm` is purely
        // lexical; `fs.list` returns name/type only), so a
        // bare symlink-named component is NOT resolved
        // client-side — it passes through, and only a
        // literal `..` component rejects.
        assert!(!has_traversal("link"));
        assert_eq!(norm("link").unwrap(), "link");
        assert!(!has_traversal("link/x"));
        assert!(has_traversal("link/../x"));
        let p = parse_fs("cat", &["link"]);
        assert!(validate_fs("cat", &p).is_ok());
    }

    #[test]
    fn pad19_truncates_and_pads_by_runes() {
        assert_eq!(pad19(""), "                   ");
        assert_eq!(pad19("abc"), "abc                ");
        assert_eq!(pad19("1234567890123456789"), "1234567890123456789");
        assert_eq!(pad19("12345678901234567890"), "1234567890123456789");
    }

    #[test]
    fn go_path_ext_matches_go() {
        assert_eq!(go_path_ext("a.md"), ".md");
        assert_eq!(go_path_ext("a"), "");
        assert_eq!(go_path_ext(".md"), ".md");
        assert_eq!(go_path_ext("a.tar.gz"), ".gz");
        assert_eq!(go_path_ext("dir/a.md"), ".md");
        assert_eq!(go_path_ext("dir/"), "");
    }
}
