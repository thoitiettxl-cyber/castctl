// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! `profile` subcommands (list/show/add/rm/set-outbound/
//! set-fingerprint/set-tls-engine) and `config migrate`.
//!
//! Go sources: `internal/commands/profilecmd.go`
//! (`cmdProfileList`, `cmdProfileShow`, `cmdProfileAdd`,
//! `cmdProfileRm`, `cmdProfileSetOutbound`,
//! `cmdProfileSetStored`, `cmdConfigMigrate`,
//! `profileWarnings`, `writeRedactedProfile`,
//! `prevalidateAddOutbound`, `explicitProfileSelected`)
//! and `internal/profile/profilecmd.go` (AddProfile,
//! RemoveProfile, SetOutbound, SetFingerprint,
//! SetTlsEngine) + `internal/profile/migrate.go`
//! (MigrateFrom).
//!
//! JSON rendering: every `writeJSON` output is built with
//! the ordered encoder (`SetEscapeHTML(false)`, matching
//! Go's `encodeOrderedJSON` + `json.Indent`), EXCEPT the
//! `profile show` `paths`/`warnings` splice parts, which
//! Go renders with `json.Marshal` (HTML escaping ON) —
//! those go through `serde_json::to_string` on a struct,
//! which escapes the same way. `profile show` itself is a
//! hand-built splice, exactly like Go's `strings.Builder`
//! version.
//!
//! Stdin (`--outbound -`, `set-outbound -`) is read
//! directly from `std::io::stdin`, like `chat.rs` does
//! for interactive input: there is no stdin seam in
//! `Ctx`, and the `-` path is covered by the live
//! parity checks on cue (piped stdin to the built
//! binary), not by unit tests.
//!
//! No `unsafe`, no `unwrap()`/`expect()` on external input.

use std::io::Read;
use std::os::unix::fs::PermissionsExt;

use castctl_config::config::{
    SingleConfig, load_profile, load_single_config, profile_exists, resolve_active_profile,
};
use castctl_config::configlocation::{ConfigLocation, config_lookup_env};
use castctl_config::errors::ConfigError;
use castctl_config::gopath::{go_clean, go_is_abs, go_join};
use castctl_config::gostr::{go_quote, go_trim_space};
use castctl_config::jsonvalue::{
    JsonValue, OrderedObject, encode_ordered_json, encode_ordered_json_indent,
};
use castctl_config::migrate::{migrate_from, render_migrate_result};
use castctl_config::oserr;
use castctl_config::profile::{PROFILE_ENV, Profile, discover_profile_names};
use castctl_config::profile_ops::{
    AddProfileOptions, add_profile, outbound_from_env, remove_profile, set_fingerprint,
    set_outbound, set_tls_engine,
};
use castctl_config::redact::redact_profile;

use crate::network::write_json_text;
use crate::parser::Parsed;
use crate::run::{Ctx, FlowErr, GlobalOpts, config_err, msg, resolve_config};

/// `resolveActive` (`commands.go:1012`): the `--profile`
/// flag, else the active profile for this config.
pub(crate) fn resolve_active(
    ctx: &Ctx<'_>,
    g: &GlobalOpts,
    loc: &ConfigLocation,
) -> Result<Profile, FlowErr> {
    let flag = if g.profile_set {
        Some(g.profile_flag.as_str())
    } else {
        None
    };
    resolve_active_profile(&loc.config_dir, flag, ctx.getenv).map_err(config_err)
}

/// `explicitProfileSelected` (`profilecmd.go:308`): a
/// positional, the `--profile` flag, or a non-empty
/// `CASTCTL_PROFILE`. Implicitly resolved names
/// (`default_profile`, then `"default"`) are not
/// explicit: with no config file yet they may synthesise
/// a default profile instead of failing.
pub(crate) fn explicit_profile_selected(ctx: &Ctx<'_>, g: &GlobalOpts, positional: bool) -> bool {
    if positional || g.profile_set {
        return true;
    }
    match config_lookup_env(ctx.getenv, PROFILE_ENV) {
        Some(v) => !go_trim_space(&v).is_empty(),
        None => false,
    }
}

/// The redacted profile rendering (`RedactProfile`,
/// `redact.go:74`): 2-space indented, HTML unescaped,
/// trimmed — the `Fprintln(TrimSpace(redacted))` form
/// `writeRedactedProfile` and `profile show` print.
fn redacted_text(prof: &Profile) -> Result<String, FlowErr> {
    let obj = redact_profile(prof).map_err(config_err)?;
    let text = encode_ordered_json_indent(&JsonValue::Object(obj), 2).map_err(config_err)?;
    Ok(text.trim().to_string())
}

/// `writeRedactedProfile` (`profilecmd.go`): the redacted
/// profile plus one trailing newline on stdout.
fn write_redacted_profile(ctx: &mut Ctx<'_>, prof: &Profile) -> Result<(), FlowErr> {
    let text = redacted_text(prof)?;
    ctx.out.stdout.push_str(&text);
    ctx.out.stdout.push('\n');
    Ok(())
}

/// `profileWarnings` (`profilecmd.go`): missing cookies,
/// non-0600 cookies/config files, and dangling outbound
/// tag references. A stat error other than "not exist"
/// on the cookies file is silent, exactly like Go.
fn profile_warnings(single: Option<&SingleConfig>, prof: &Profile) -> Vec<String> {
    let mut warnings = Vec::new();
    match std::fs::metadata(&prof.cookies_file) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            warnings.push(format!("cookies file {} does not exist", prof.cookies_file));
        }
        Ok(meta) => {
            let perm = meta.permissions().mode() & 0o777;
            if perm != 0o600 {
                warnings.push(format!(
                    "cookies file {} has mode {:04o}, expected 0600",
                    prof.cookies_file, perm
                ));
            }
        }
        Err(_) => {}
    }
    if !prof.config_file.is_empty()
        && let Ok(meta) = std::fs::metadata(&prof.config_file)
    {
        let perm = meta.permissions().mode() & 0o777;
        if perm != 0o600 {
            warnings.push(format!(
                "config file {} has mode {:04o}, expected 0600",
                prof.config_file, perm
            ));
        }
    }
    if prof.outbound.kind == castctl_config::profile::OutboundKind::Tag
        && !prof.outbound.tag.is_empty()
        && prof.outbound.tag != "direct"
        && let Some(single) = single
        && !tag_defined(single, &prof.outbound.tag)
    {
        warnings.push(format!(
            "outbound tag {} is not defined in the config",
            go_quote(&prof.outbound.tag)
        ));
    }
    warnings
}

/// `tagDefined` (`profilecmd.go`): the tag names an entry
/// in `outbounds` or `endpoints`. (Unreachable after the
/// parse — the tag graph already rejects dangling tags —
/// but kept for fidelity: Go carries the same check.)
fn tag_defined(single: &SingleConfig, tag: &str) -> bool {
    let has = |entries: &[JsonValue]| {
        entries.iter().any(|e| {
            matches!(e, JsonValue::Object(obj)
                if obj.get("tag").is_some_and(|t| matches!(t, JsonValue::Str(s) if s == tag)))
        })
    };
    has(&single.outbounds_raw) || has(&single.endpoints_raw)
}

fn json_str(s: &str) -> JsonValue {
    JsonValue::Str(s.to_string())
}

fn json_bool(b: bool) -> JsonValue {
    JsonValue::Bool(b)
}

/// `cmdProfileList` (`profilecmd.go:116`): rows ordered
/// discovered (default first) + single-only sorted +
/// active if missing; the aggregate `source` is
/// `"single"` when a single file exists, else `"none"`.
pub(crate) fn run_list(ctx: &mut Ctx<'_>, g: &GlobalOpts) -> Result<(), FlowErr> {
    let loc = resolve_config(ctx, g, false)?;
    let active = resolve_active(ctx, g, &loc)?;
    let (single, _found) = load_single_config(&loc.config_dir).map_err(config_err)?;
    let names = discover_profile_names(&loc.config_dir).map_err(config_err)?;
    let mut ordered: Vec<String> = Vec::new();
    let mut seen: Vec<String> = Vec::new();
    for n in names {
        if !seen.contains(&n) {
            seen.push(n.clone());
            ordered.push(n);
        }
    }
    if let Some(single) = &single {
        let mut extra: Vec<String> = single
            .profiles
            .keys()
            .filter(|k| !seen.contains(*k))
            .cloned()
            .collect();
        extra.sort();
        for n in extra {
            seen.push(n.clone());
            ordered.push(n);
        }
    }
    if !seen.contains(&active.name) {
        ordered.push(active.name.clone());
    }
    let mut rows: Vec<JsonValue> = Vec::new();
    for name in &ordered {
        // The validated single entry when present (its
        // outbound type/from are resolved); otherwise a
        // fresh load (SourceNone defaults, or the legacy
        // refusal — same as Go's per-row `LoadProfile`).
        let mut prof = match single.as_ref().and_then(|s| s.profiles.get(name)) {
            Some(p) => p.clone(),
            None => load_profile(&loc.config_dir, name, ctx.getenv).map_err(config_err)?,
        };
        // Go's `LoadProfile` sets `Exists` from the dir stat
        // on EVERY path (config.go:1219) — the single file
        // carries no `exists` of its own, so a single-file
        // entry must be re-statted here too, or a profile
        // whose directory exists reports `exists: false`.
        prof.exists = std::fs::metadata(&prof.dir)
            .map(|m| m.is_dir())
            .unwrap_or(false);
        let cookies = match std::fs::metadata(&prof.cookies_file) {
            Ok(meta) => meta.len() > 0,
            Err(_) => false,
        };
        let mut outbound = OrderedObject::new();
        outbound.set("kind", json_str(prof.outbound.kind.as_str()));
        outbound.set("type", json_str(&prof.outbound.typ));
        outbound.set("tag", json_str(&prof.outbound.tag));
        let mut row = OrderedObject::new();
        row.set("name", json_str(&prof.name));
        row.set("dir", json_str(&prof.dir));
        row.set("exists", json_bool(prof.exists));
        row.set("cookies", json_bool(cookies));
        row.set("cookies_file", json_str(&prof.cookies_file));
        row.set("outbound", JsonValue::Object(outbound));
        row.set("auto_approve", json_str(&prof.auto_approve));
        row.set("source", json_str(prof.source.as_str()));
        rows.push(JsonValue::Object(row));
    }
    let source = if single.is_some() { "single" } else { "none" };
    let default_profile = match &single {
        Some(s) if !s.default_profile.is_empty() => s.default_profile.clone(),
        _ => "default".to_string(),
    };
    let mut top = OrderedObject::new();
    top.set("active", json_str(&active.name));
    top.set("default_profile", json_str(&default_profile));
    top.set("source", json_str(source));
    top.set("profiles", JsonValue::Array(rows));
    let compact = encode_ordered_json(&JsonValue::Object(top)).map_err(config_err)?;
    ctx.out.stdout.push_str(&write_json_text(&compact));
    Ok(())
}

/// The `profile show` `paths` block, rendered with
/// `json.Marshal` (HTML escaping ON, compact) — a struct
/// through `serde_json`, whose field order and escaping
/// match Go's.
#[derive(serde::Serialize)]
struct ShowPaths {
    dir: String,
    config_file: String,
    cookies_file: String,
    chat_file: String,
    telegram_config: String,
    telegram_state: String,
}

/// `cmdProfileShow` (`profilecmd.go:222`): the explicit
/// existence gate, then the redacted profile spliced
/// verbatim into the `{"profile", "paths", "warnings"}`
/// wrapper, exactly like Go's `strings.Builder` version.
pub(crate) fn run_show(ctx: &mut Ctx<'_>, g: &GlobalOpts, p: &Parsed) -> Result<(), FlowErr> {
    let loc = resolve_config(ctx, g, false)?;
    let active = resolve_active(ctx, g, &loc)?;
    let (name, explicit) = match p.positionals.first() {
        Some(n) => (n.clone(), true),
        None => (active.name.clone(), false),
    };
    let (single, _found) = load_single_config(&loc.config_dir).map_err(config_err)?;
    if explicit_profile_selected(ctx, g, explicit)
        && !profile_exists(&loc.config_dir, &name, single.as_ref())
    {
        return Err(msg(
            2,
            format!("profile {} does not exist", go_quote(&name)),
        ));
    }
    let prof = load_profile(&loc.config_dir, &name, ctx.getenv).map_err(config_err)?;
    let redacted = redacted_text(&prof)?;
    let warnings = profile_warnings(single.as_ref(), &prof);
    let paths = ShowPaths {
        dir: prof.dir.clone(),
        config_file: prof.config_file.clone(),
        cookies_file: prof.cookies_file.clone(),
        chat_file: prof.chat_file.clone(),
        telegram_config: go_join(&[&prof.dir, "telegram.json"]),
        telegram_state: go_join(&[&prof.dir, "telegram-state.json"]),
    };
    let paths_json =
        serde_json::to_string(&paths).map_err(|_| msg(1, "failed to serialize profile paths"))?;
    let warnings_json = serde_json::to_string(&warnings)
        .map_err(|_| msg(1, "failed to serialize profile warnings"))?;
    ctx.out.stdout.push_str(&format!(
        "{{\n  \"profile\": {redacted},\n  \"paths\": {paths_json},\n  \"warnings\": {warnings_json}\n}}\n"
    ));
    Ok(())
}

/// Whether `path` exists and is not a directory
/// (`isExistingFile`, `profilecmd.go`): stat only, never
/// opened.
fn is_existing_file(path: &str) -> bool {
    match std::fs::metadata(path) {
        Ok(meta) => !meta.is_dir(),
        Err(_) => false,
    }
}

/// One scratch directory, removed on drop
/// (`os.RemoveAll` deferred in `prevalidateAddOutbound`).
struct ScratchDir {
    path: std::path::PathBuf,
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// `prevalidateAddOutbound` (`profilecmd.go`): run
/// AddProfile followed by SetOutbound against a scratch
/// copy of the single config file (or an empty scratch
/// directory when no single file exists yet), so outbound
/// validation failures surface before the real config is
/// written. The scratch copy carries the same single-file
/// bytes, so parse, tag-graph, and shared-WireGuard-key
/// validation decide identically; the scratch directory
/// has no legacy layout, but a real AddProfile refusal for
/// an unmigrated layout writes nothing itself, so the
/// scratch result never masks a real write. The scratch
/// profile is discarded; only validation errors are
/// returned.
fn prevalidate_add_outbound(
    base_dir: &str,
    name: &str,
    opts: &AddProfileOptions,
    outbound_data: &[u8],
) -> Result<(), FlowErr> {
    let scratch_path = std::env::temp_dir().join(format!(
        "castctl-profile-add-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&scratch_path)
        .map_err(|e| msg(1, format!("mkdir {scratch_path:?}: {e}")))?;
    let scratch = ScratchDir { path: scratch_path };
    let config_path = go_join(&[base_dir, "config.json"]);
    match std::fs::read(&config_path) {
        Ok(data) => {
            let dest = scratch.path.join("config.json");
            {
                use std::os::unix::fs::OpenOptionsExt;
                let mut f = std::fs::OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .mode(0o600)
                    .open(&dest)
                    .map_err(|e| msg(1, oserr::open_error_text(dest.to_str().unwrap_or(""), &e)))?;
                use std::io::Write;
                f.write_all(&data).map_err(|e| {
                    msg(1, oserr::write_error_text(dest.to_str().unwrap_or(""), &e))
                })?;
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(msg(1, oserr::open_error_text(&config_path, &e)));
        }
    }
    let Some(scratch_str) = scratch.path.to_str() else {
        return Err(msg(1, "scratch path is not valid UTF-8"));
    };
    add_profile(scratch_str, name, opts.clone()).map_err(config_err)?;
    set_outbound(scratch_str, name, outbound_data).map_err(config_err)?;
    Ok(())
}

/// `cmdProfileAdd` (`profilecmd.go:393`): resolve config
/// + active, then the outbound (env/file/stdin/tag),
///   prevalidate on a scratch copy, AddProfile (write 1),
///   SetOutbound (write 2), then the redacted profile.
///   A failed SetOutbound after a successful AddProfile
///   leaves the profile behind with a direct outbound —
///   the two-write window is inherent to the library API
///   (see `prevalidateAddOutbound`).
pub(crate) fn run_add(ctx: &mut Ctx<'_>, g: &GlobalOpts, p: &Parsed) -> Result<(), FlowErr> {
    let name = p.positionals[0].clone();
    let loc = resolve_config(ctx, g, false)?;
    let _active = resolve_active(ctx, g, &loc)?;
    let mut outbound_data: Option<Vec<u8>> = None;
    let mut outbound_tag = String::new();
    if p.bool("outbound-from-env") {
        match outbound_from_env(ctx.getenv).map_err(config_err)? {
            None => {
                return Err(msg(
                    2,
                    "no proxy environment variables set: --outbound-from-env needs HTTPS_PROXY, HTTP_PROXY or ALL_PROXY",
                ));
            }
            Some(obj) => {
                let data = encode_ordered_json(&obj).map_err(config_err)?;
                outbound_data = Some(data.into_bytes());
            }
        }
    } else if p.str_is_set("outbound") {
        let value = p.str("outbound");
        if value == "-" {
            let mut data = Vec::new();
            std::io::stdin()
                .lock()
                .read_to_end(&mut data)
                .map_err(|e| msg(1, e.to_string()))?;
            outbound_data = Some(data);
        } else if is_existing_file(&value) {
            let data =
                std::fs::read(&value).map_err(|e| msg(2, oserr::open_error_text(&value, &e)))?;
            outbound_data = Some(data);
        } else {
            outbound_tag = value;
        }
    }
    let opts = AddProfileOptions {
        cookies_file: p.str("cookies-file"),
        outbound_tag,
        set_default: p.bool("set-default"),
        fingerprint: p.str("fingerprint"),
        tls_engine: p.str("tls-engine"),
    };
    if let Some(data) = &outbound_data {
        prevalidate_add_outbound(&loc.config_dir, &name, &opts, data)?;
    }
    let created = add_profile(&loc.config_dir, &name, opts).map_err(config_err)?;
    let updated = match &outbound_data {
        Some(data) => set_outbound(&loc.config_dir, &name, data).map_err(config_err)?,
        None => created,
    };
    write_redacted_profile(ctx, &updated)
}

/// `cmdProfileRm` (`profilecmd.go:540`): the `--yes`
/// refusal happens in the dispatcher, before config
/// resolution. The result JSON carries `default_profile`
/// as `null` when the removal cleared it.
pub(crate) fn run_rm(ctx: &mut Ctx<'_>, g: &GlobalOpts, p: &Parsed) -> Result<(), FlowErr> {
    let name = p.positionals[0].clone();
    let loc = resolve_config(ctx, g, false)?;
    let _active = resolve_active(ctx, g, &loc)?;
    let result = remove_profile(&loc.config_dir, &name).map_err(config_err)?;
    let mut out = OrderedObject::new();
    out.set("removed", json_str(&result.name));
    if result.default_profile.is_empty() {
        out.set("default_profile", JsonValue::Null);
    } else {
        out.set("default_profile", json_str(&result.default_profile));
    }
    if !result.warning.is_empty() {
        out.set("warning", json_str(&result.warning));
    }
    let compact = encode_ordered_json(&JsonValue::Object(out)).map_err(config_err)?;
    ctx.out.stdout.push_str(&write_json_text(&compact));
    Ok(())
}

/// Read the `set-outbound` source (`profilecmd.go:579`):
/// `-` is stdin, anything else is a file. This runs
/// BEFORE config resolution (Go order); a file read
/// error is exit 2 with the raw `open ...` text, a stdin
/// read error is a plain error (exit 1).
fn read_outbound_source(source: &str) -> Result<Vec<u8>, FlowErr> {
    if source == "-" {
        let mut data = Vec::new();
        std::io::stdin()
            .lock()
            .read_to_end(&mut data)
            .map_err(|e| msg(1, e.to_string()))?;
        Ok(data)
    } else {
        std::fs::read(source).map_err(|e| msg(2, oserr::open_error_text(source, &e)))
    }
}

/// `cmdProfileSetOutbound` (`profilecmd.go:579`).
pub(crate) fn run_set_outbound(
    ctx: &mut Ctx<'_>,
    g: &GlobalOpts,
    p: &Parsed,
) -> Result<(), FlowErr> {
    let name = p.positionals[0].clone();
    let source = p.positionals[1].clone();
    let data = read_outbound_source(&source)?;
    let loc = resolve_config(ctx, g, false)?;
    let _active = resolve_active(ctx, g, &loc)?;
    let updated = set_outbound(&loc.config_dir, &name, &data).map_err(config_err)?;
    write_redacted_profile(ctx, &updated)
}

/// `cmdProfileSetStored` (`profilecmd.go:614`): shared by
/// `set-fingerprint` and `set-tls-engine`.
fn run_set_stored(
    ctx: &mut Ctx<'_>,
    g: &GlobalOpts,
    p: &Parsed,
    set: fn(&str, &str, &str) -> Result<Profile, ConfigError>,
) -> Result<(), FlowErr> {
    let name = p.positionals[0].clone();
    let value = p.positionals[1].clone();
    let loc = resolve_config(ctx, g, false)?;
    let _active = resolve_active(ctx, g, &loc)?;
    let updated = set(&loc.config_dir, &name, &value).map_err(config_err)?;
    write_redacted_profile(ctx, &updated)
}

/// `cmdProfileSetFingerprint` (`profilecmd.go:614`).
pub(crate) fn run_set_fingerprint(
    ctx: &mut Ctx<'_>,
    g: &GlobalOpts,
    p: &Parsed,
) -> Result<(), FlowErr> {
    run_set_stored(ctx, g, p, set_fingerprint)
}

/// `cmdProfileSetTLSEngine` (`profilecmd.go:614`).
pub(crate) fn run_set_tls_engine(
    ctx: &mut Ctx<'_>,
    g: &GlobalOpts,
    p: &Parsed,
) -> Result<(), FlowErr> {
    run_set_stored(ctx, g, p, set_tls_engine)
}

/// `cmdConfigMigrate` (`profilecmd.go:1093`): the result
/// JSON is printed on stdout EVEN on error, then the
/// error is returned (stdout JSON + stderr + exit 2).
/// `source_dir` is already absolutised by the dispatcher
/// (`filepath.Abs`, when it succeeds); empty means the
/// config directory itself.
pub(crate) fn run_config_migrate(
    ctx: &mut Ctx<'_>,
    g: &GlobalOpts,
    source_dir: &str,
    write: bool,
) -> Result<(), FlowErr> {
    let loc = resolve_config(ctx, g, write || !source_dir.is_empty())?;
    let source = if source_dir.is_empty() {
        loc.config_dir.clone()
    } else {
        source_dir.to_string()
    };
    let (result, err) = migrate_from(&source, &loc.config_dir, write);
    let text = render_migrate_result(&result).map_err(config_err)?;
    ctx.out.stdout.push_str(&text);
    ctx.out.stdout.push('\n');
    match err {
        Some(e) => Err(config_err(e)),
        None => Ok(()),
    }
}

/// `filepath.Abs` for a `--from` value (`profilecmd.go`):
/// a relative value is working-directory relative; on
/// failure the value stays relative, like Go's
/// `if abs, aerr := filepath.Abs(sourceDir); aerr == nil`.
pub(crate) fn absolutise_from(source_dir: &str) -> String {
    if go_is_abs(source_dir) {
        return source_dir.to_string();
    }
    if let Ok(cwd) = std::env::current_dir()
        && let Some(cwd_s) = cwd.to_str()
    {
        return go_clean(&go_join(&[cwd_s, source_dir]));
    }
    source_dir.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::run::Outcome;
    use castctl_config::jsonvalue::decode_ordered_json;

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "castctl-cli-profilecmd-{tag}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_config(dir: &std::path::Path, text: &str) {
        std::fs::write(dir.join("config.json"), text).unwrap();
    }

    /// A `Ctx` + `GlobalOpts` pair pointing `--config` at
    /// `dir/config.json`, with the real process environment
    /// for `getenv` (no `CASTCTL_PROFILE` is set by the
    /// test harness).
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

    fn parsed(positionals: &[&str]) -> Parsed {
        Parsed {
            positionals: positionals.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }

    /// The R3 `cfgA` shape (verbatim, paths substituted):
    /// `default_profile` alpha, alpha + beta, one socks
    /// outbound `proxy-sg` (FAKE credentials).
    const CFG_A: &str = r#"{"default_profile":"alpha","profiles":{"alpha":{"node_id":"ALPHA-NODE"},"beta":{"node_id":"BETA-NODE","auto_approve":"off"}},"outbounds":[{"type":"socks","tag":"proxy-sg","server":"127.0.0.1","server_port":1080,"version":"5","username":"FAKE-USER","password":"FAKE-PW"}]}"#;

    #[test]
    fn list_cfg_a_matches_go_probe() {
        let dir = temp_dir("list-a");
        write_config(&dir, CFG_A);
        // Alpha has a (fake) cookies file, like the R3 probe
        // dir; beta has none.
        let cookies = dir.join("profiles/alpha/cookies.txt");
        std::fs::create_dir_all(cookies.parent().unwrap()).unwrap();
        std::fs::write(&cookies, "FAKE-COOKIE").unwrap();
        let (mut ctx, g) = ctx_for(&dir);
        run_list(&mut ctx, &g).unwrap();
        let out = ctx.out.stdout.clone();
        // Ground truth: R3 transcript probe [3] verbatim.
        let v = decode_ordered_json(out.as_bytes()).unwrap();
        let obj = match &v {
            JsonValue::Object(o) => o,
            _ => panic!("want object"),
        };
        assert_eq!(obj.get("active"), Some(&JsonValue::Str("alpha".into())));
        assert_eq!(
            obj.get("default_profile"),
            Some(&JsonValue::Str("alpha".into()))
        );
        assert_eq!(obj.get("source"), Some(&JsonValue::Str("single".into())));
        let rows = match obj.get("profiles") {
            Some(JsonValue::Array(rows)) => rows,
            _ => panic!("want profiles array"),
        };
        assert_eq!(rows.len(), 3);
        // Synthesised default row first.
        let def = match &rows[0] {
            JsonValue::Object(o) => o,
            _ => panic!("want row object"),
        };
        assert_eq!(def.get("name"), Some(&JsonValue::Str("default".into())));
        assert_eq!(
            def.get("dir"),
            Some(&JsonValue::Str(dir.to_str().unwrap().into()))
        );
        assert_eq!(def.get("exists"), Some(&JsonValue::Bool(true)));
        assert_eq!(def.get("cookies"), Some(&JsonValue::Bool(false)));
        assert_eq!(def.get("source"), Some(&JsonValue::Str("none".into())));
        let ob = match def.get("outbound") {
            Some(JsonValue::Object(o)) => o,
            _ => panic!("want outbound object"),
        };
        assert_eq!(ob.get("kind"), Some(&JsonValue::Str("direct".into())));
        assert_eq!(ob.get("type"), Some(&JsonValue::Str("direct".into())));
        assert_eq!(ob.get("tag"), Some(&JsonValue::Str(String::new())));
        // Alpha: cookies present.
        let alpha = match &rows[1] {
            JsonValue::Object(o) => o,
            _ => panic!("want row object"),
        };
        assert_eq!(alpha.get("name"), Some(&JsonValue::Str("alpha".into())));
        assert_eq!(alpha.get("cookies"), Some(&JsonValue::Bool(true)));
        assert_eq!(alpha.get("exists"), Some(&JsonValue::Bool(true)));
        // Beta: no dir, no cookies.
        let beta = match &rows[2] {
            JsonValue::Object(o) => o,
            _ => panic!("want row object"),
        };
        assert_eq!(beta.get("name"), Some(&JsonValue::Str("beta".into())));
        assert_eq!(beta.get("exists"), Some(&JsonValue::Bool(false)));
        assert_eq!(beta.get("cookies"), Some(&JsonValue::Bool(false)));
    }

    #[test]
    fn list_legacy_flat_file_is_exit_2() {
        // A `{}` base file is NOT "no single config" for
        // `profile list`: Go's `LoadProfile` (config.go:1150)
        // refuses ANY legacy file in the layout, and the flat
        // base file counts whenever no single file was found
        // (`scanLegacyConfigFile` with `includeBase=true`) —
        // so list fails whole-command with the legacy error,
        // exit 2 (Go `cmdProfileList`: "A legacy layout never
        // reaches the aggregation: LoadProfile refuses it
        // above"). Synthesis only happens in a layout with no
        // legacy file at all, which an explicit `--config`
        // pointing at an existing file can never be.
        let dir = temp_dir("list-empty");
        write_config(&dir, "{}");
        let (mut ctx, g) = ctx_for(&dir);
        let err = run_list(&mut ctx, &g).unwrap_err();
        assert_eq!(flow_code(&err), 2);
        assert!(
            flow_message(&err).contains("legacy layout found"),
            "got: {}",
            flow_message(&err)
        );
    }

    #[test]
    fn list_explicit_missing_config_is_exit_2() {
        // Go `RequirePresent` (`configlocation.go:184`):
        // an explicit path that does not exist is
        // `config file %q does not exist`, exit 2.
        let dir = temp_dir("list-missing");
        let (mut ctx, g) = ctx_for(&dir);
        let err = run_list(&mut ctx, &g).unwrap_err();
        assert_eq!(flow_code(&err), 2);
        assert!(
            flow_message(&err).contains("does not exist"),
            "got: {err:?}"
        );
        assert!(ctx.out.stdout.is_empty());
    }

    #[test]
    fn list_tag_outbound_type_resolved() {
        let dir = temp_dir("list-tag");
        write_config(
            &dir,
            r#"{"profiles":{"p1":{"outbound":"proxy-sg"}},"outbounds":[{"type":"socks","tag":"proxy-sg","server":"127.0.0.1","server_port":1080,"version":"5"}]}"#,
        );
        let (mut ctx, g) = ctx_for(&dir);
        run_list(&mut ctx, &g).unwrap();
        let v = decode_ordered_json(ctx.out.stdout.as_bytes()).unwrap();
        let rows = match &v {
            JsonValue::Object(o) => match o.get("profiles") {
                Some(JsonValue::Array(rows)) => rows.clone(),
                _ => panic!("want profiles array"),
            },
            _ => panic!("want object"),
        };
        // default row + p1.
        let p1 = match &rows[1] {
            JsonValue::Object(o) => o,
            _ => panic!("want row object"),
        };
        let ob = match p1.get("outbound") {
            Some(JsonValue::Object(o)) => o,
            _ => panic!("want outbound object"),
        };
        assert_eq!(ob.get("kind"), Some(&JsonValue::Str("tag".into())));
        assert_eq!(ob.get("type"), Some(&JsonValue::Str("socks".into())));
        assert_eq!(ob.get("tag"), Some(&JsonValue::Str("proxy-sg".into())));
    }

    #[test]
    fn list_dangling_tag_is_exit_2() {
        let dir = temp_dir("list-dangling");
        write_config(&dir, r#"{"profiles":{"p1":{"outbound":"nosuch"}}}"#);
        let (mut ctx, g) = ctx_for(&dir);
        let err = run_list(&mut ctx, &g).unwrap_err();
        assert_eq!(flow_code(&err), 2);
        assert!(
            flow_message(&err).contains("outbound tag \"nosuch\" does not exist"),
            "got: {}",
            flow_message(&err)
        );
    }

    #[test]
    fn show_explicit_missing_is_exit_2() {
        let dir = temp_dir("show-missing");
        write_config(&dir, CFG_A);
        let (mut ctx, g) = ctx_for(&dir);
        let err = run_show(&mut ctx, &g, &parsed(&["nope"])).unwrap_err();
        assert_eq!(flow_code(&err), 2);
        assert_eq!(flow_message(&err), "profile \"nope\" does not exist");
    }

    #[test]
    fn show_synthesised_default_shape() {
        // `{"profiles":{}}` HAS the marker (found, zero
        // entries), so `LoadProfile` synthesises the default
        // with SourceNone — unlike a missing explicit file
        // (exit 2, see the test above) or a `{}` flat file
        // (legacy refusal).
        let dir = temp_dir("show-default");
        write_config(&dir, "{\"profiles\":{}}");
        let (mut ctx, g) = ctx_for(&dir);
        run_show(&mut ctx, &g, &parsed(&[])).unwrap();
        let out = ctx.out.stdout.clone();
        // Splice shape: {"profile": {...}, "paths": {...},
        // "warnings": [...]} with the profile indented.
        assert!(out.starts_with("{\n  \"profile\": {\n"), "got: {out}");
        assert!(out.contains("\"name\": \"default\""), "got: {out}");
        let v = decode_ordered_json(out.as_bytes()).unwrap();
        let obj = match &v {
            JsonValue::Object(o) => o,
            _ => panic!("want object"),
        };
        let warnings = match obj.get("warnings") {
            Some(JsonValue::Array(w)) => w,
            _ => panic!("want warnings array"),
        };
        // TWO warnings: the cookies file does not exist,
        // and the config file itself is 0644 (written by
        // the test helper), not 0600 — Go's
        // `profileWarnings` warns on both
        // (`profilecmd.go:348`).
        assert_eq!(warnings.len(), 2);
        assert!(
            matches!(&warnings[0], JsonValue::Str(s) if s.contains("cookies file") && s.contains("does not exist")),
            "got: {warnings:?}"
        );
        assert!(
            matches!(&warnings[1], JsonValue::Str(s) if s.contains("config file") && s.contains("0644") && s.contains("expected 0600")),
            "got: {warnings:?}"
        );
        let paths = match obj.get("paths") {
            Some(JsonValue::Object(o)) => o,
            _ => panic!("want paths object"),
        };
        assert_eq!(
            paths.get("telegram_state"),
            Some(&JsonValue::Str(
                dir.join("telegram-state.json").to_str().unwrap().into()
            ))
        );
    }

    #[test]
    fn add_round_trip_writes_600_no_cookies_no_bak() {
        let dir = temp_dir("add-rt");
        write_config(&dir, CFG_A);
        let before = std::fs::read(dir.join("config.json")).unwrap();
        let (mut ctx, g) = ctx_for(&dir);
        let p = Parsed {
            positionals: vec!["gamma".to_string()],
            ..Default::default()
        };
        run_add(&mut ctx, &g, &p).unwrap();
        let out = ctx.out.stdout.clone();
        assert!(out.contains("\"name\": \"gamma\""), "got: {out}");
        // node_id is a secret key: the redacted print
        // shows the marker, not the value.
        let v = decode_ordered_json(out.as_bytes()).unwrap();
        let node = match &v {
            JsonValue::Object(o) => match o.get("node_id") {
                Some(JsonValue::Str(s)) => s.clone(),
                _ => panic!("want node_id string, got: {v:?}"),
            },
            _ => panic!("want object"),
        };
        assert_eq!(node, "<redacted>");
        // The FILE holds the real id: 16 lowercase hex.
        let stored =
            decode_ordered_json(std::fs::read(dir.join("config.json")).unwrap().as_slice())
                .unwrap();
        let stored_node = match &stored {
            JsonValue::Object(o) => match o.get("profiles") {
                Some(JsonValue::Object(profiles)) => match profiles.get("gamma") {
                    Some(JsonValue::Object(gamma)) => match gamma.get("node_id") {
                        Some(JsonValue::Str(s)) => s.clone(),
                        _ => panic!("want stored node_id string, got: {stored:?}"),
                    },
                    _ => panic!("want gamma entry, got: {stored:?}"),
                },
                _ => panic!("want profiles object, got: {stored:?}"),
            },
            _ => panic!("want object"),
        };
        assert_eq!(stored_node.len(), 16);
        assert!(stored_node.chars().all(|c| c.is_ascii_hexdigit()));
        // No cookies file/dir created, no .bak.
        assert!(!dir.join("profiles/gamma").exists());
        assert!(!dir.join("config.json.bak").exists());
        // File mode 0600, and the old bytes are replaced
        // (alpha/beta kept).
        use std::os::unix::fs::PermissionsExt;
        let perm = std::fs::metadata(dir.join("config.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(perm, 0o600);
        let after = std::fs::read_to_string(dir.join("config.json")).unwrap();
        assert_ne!(after.as_bytes(), before.as_slice());
        assert!(after.contains("\"gamma\""));
        assert!(after.contains("\"alpha\""));
    }

    #[test]
    fn add_duplicate_is_exit_2_file_unchanged() {
        let dir = temp_dir("add-dup");
        write_config(&dir, CFG_A);
        let before = std::fs::read(dir.join("config.json")).unwrap();
        let (mut ctx, g) = ctx_for(&dir);
        let err = run_add(&mut ctx, &g, &parsed(&["alpha"])).unwrap_err();
        assert_eq!(flow_code(&err), 2);
        // Go `newConfigErrorf`: the message carries the
        // `profile: ` prefix (R3 transcript:
        // `castctl: profile: profile "gamma" already exists`).
        assert_eq!(
            flow_message(&err),
            "profile: profile \"alpha\" already exists"
        );
        assert_eq!(std::fs::read(dir.join("config.json")).unwrap(), before);
    }

    #[test]
    fn add_bad_fingerprint_is_exit_2_file_unchanged() {
        let dir = temp_dir("add-badfp");
        write_config(&dir, CFG_A);
        let before = std::fs::read(dir.join("config.json")).unwrap();
        let (mut ctx, g) = ctx_for(&dir);
        let p = Parsed {
            positionals: vec!["delta".to_string()],
            strs: vec![("fingerprint".to_string(), "bogus".to_string())],
            str_set: vec!["fingerprint".to_string()],
            ..Default::default()
        };
        let err = run_add(&mut ctx, &g, &p).unwrap_err();
        assert_eq!(flow_code(&err), 2);
        assert!(
            flow_message(&err).contains("fingerprint must be one of"),
            "got: {}",
            flow_message(&err)
        );
        assert_eq!(std::fs::read(dir.join("config.json")).unwrap(), before);
    }

    #[test]
    fn add_outbound_file_then_show_renders_tag() {
        let dir = temp_dir("add-ob");
        write_config(&dir, CFG_A);
        let ob = dir.join("ob-socks.json");
        std::fs::write(
            &ob,
            r#"{"type":"socks","tag":"proxy-sg","server":"127.0.0.1","server_port":1080,"version":"5"}"#,
        )
        .unwrap();
        let (mut ctx, g) = ctx_for(&dir);
        let p = Parsed {
            positionals: vec!["eps".to_string()],
            strs: vec![("outbound".to_string(), ob.to_str().unwrap().to_string())],
            str_set: vec!["outbound".to_string()],
            ..Default::default()
        };
        run_add(&mut ctx, &g, &p).unwrap();
        assert!(ctx.out.stdout.contains("\"outbound\": \"proxy-sg\""));
        let (mut ctx, g) = ctx_for(&dir);
        run_show(&mut ctx, &g, &parsed(&["eps"])).unwrap();
        assert!(ctx.out.stdout.contains("\"outbound\": \"proxy-sg\""));
    }

    #[test]
    fn add_outbound_dangling_tag_is_exit_2_file_unchanged() {
        let dir = temp_dir("add-dangling");
        write_config(&dir, CFG_A);
        let before = std::fs::read(dir.join("config.json")).unwrap();
        let (mut ctx, g) = ctx_for(&dir);
        let p = Parsed {
            positionals: vec!["delta".to_string()],
            strs: vec![("outbound".to_string(), "nosuchtag".to_string())],
            str_set: vec!["outbound".to_string()],
            ..Default::default()
        };
        let err = run_add(&mut ctx, &g, &p).unwrap_err();
        assert_eq!(flow_code(&err), 2);
        assert!(
            flow_message(&err).contains("outbound tag \"nosuchtag\" does not exist"),
            "got: {}",
            flow_message(&err)
        );
        assert_eq!(std::fs::read(dir.join("config.json")).unwrap(), before);
    }

    #[test]
    fn rm_clears_default_with_warning_null() {
        let dir = temp_dir("rm-clear");
        write_config(
            &dir,
            r#"{"default_profile":"gamma","profiles":{"gamma":{"node_id":"G-NODE"}}}"#,
        );
        let (mut ctx, g) = ctx_for(&dir);
        run_rm(&mut ctx, &g, &parsed(&["gamma"])).unwrap();
        let v = decode_ordered_json(ctx.out.stdout.as_bytes()).unwrap();
        let obj = match &v {
            JsonValue::Object(o) => o,
            _ => panic!("want object"),
        };
        assert_eq!(obj.get("removed"), Some(&JsonValue::Str("gamma".into())));
        assert_eq!(obj.get("default_profile"), Some(&JsonValue::Null));
        assert_eq!(
            obj.get("warning"),
            Some(&JsonValue::Str(
                "default_profile cleared: no \"default\" profile remains".into()
            ))
        );
        let after = std::fs::read_to_string(dir.join("config.json")).unwrap();
        assert!(!after.contains("default_profile"));
        assert!(!after.contains("gamma"));
    }

    #[test]
    fn rm_unknown_is_exit_2() {
        let dir = temp_dir("rm-unknown");
        write_config(&dir, CFG_A);
        let (mut ctx, g) = ctx_for(&dir);
        let err = run_rm(&mut ctx, &g, &parsed(&["nope"])).unwrap_err();
        assert_eq!(flow_code(&err), 2);
        // Go `newConfigErrorf` (`profilecmd.go:250`): the
        // message carries the `profile: ` prefix.
        assert_eq!(
            flow_message(&err),
            "profile: profile \"nope\" does not exist in the single config file"
        );
    }

    #[test]
    fn set_fingerprint_empty_resets_key() {
        let dir = temp_dir("set-fp-reset");
        write_config(
            &dir,
            r#"{"profiles":{"alpha":{"fingerprint":"firefox","node_id":"A"}}}"#,
        );
        let (mut ctx, g) = ctx_for(&dir);
        run_set_fingerprint(&mut ctx, &g, &parsed(&["alpha", ""])).unwrap();
        assert!(ctx.out.stdout.contains("\"fingerprint\": \"chrome\""));
        let after = std::fs::read_to_string(dir.join("config.json")).unwrap();
        assert!(!after.contains("fingerprint"), "got: {after}");
    }

    #[test]
    fn set_tls_engine_bad_value_is_exit_2_file_unchanged() {
        let dir = temp_dir("set-tls-bad");
        write_config(&dir, CFG_A);
        let before = std::fs::read(dir.join("config.json")).unwrap();
        let (mut ctx, g) = ctx_for(&dir);
        let err = run_set_tls_engine(&mut ctx, &g, &parsed(&["alpha", "bogus"])).unwrap_err();
        assert_eq!(flow_code(&err), 2);
        assert!(
            flow_message(&err).contains("tls_engine must be one of"),
            "got: {}",
            flow_message(&err)
        );
        assert_eq!(std::fs::read(dir.join("config.json")).unwrap(), before);
    }

    #[test]
    fn set_outbound_missing_file_is_exit_2_raw_open_text() {
        let dir = temp_dir("set-ob-missing");
        write_config(&dir, CFG_A);
        let (mut ctx, g) = ctx_for(&dir);
        let err = run_set_outbound(
            &mut ctx,
            &g,
            &parsed(&["alpha", "/tmp/does-not-exist-m7d.json"]),
        )
        .unwrap_err();
        assert_eq!(flow_code(&err), 2);
        assert_eq!(
            flow_message(&err),
            "open /tmp/does-not-exist-m7d.json: no such file or directory"
        );
    }

    #[test]
    fn migrate_handler_dry_run_prints_json_exit_0() {
        let dir = temp_dir("mig-handler");
        let src = dir.join("legacy-src");
        std::fs::create_dir_all(src.join("profiles/muse01")).unwrap();
        std::fs::write(
            src.join("config.json"),
            r#"{"auto_approve":"always","node_id":"MAIN-NODE","vm_id":"FAKE-VM"}"#,
        )
        .unwrap();
        std::fs::write(src.join("cookies.txt"), "FAKE").unwrap();
        std::fs::write(
            src.join("profiles/muse01/config.json"),
            r#"{"auto_approve":"off","node_id":"MUSE01-NODE"}"#,
        )
        .unwrap();
        std::fs::write(src.join("profiles/muse01/cookies.txt"), "FAKE").unwrap();
        let dest = dir.join("dest");
        std::fs::create_dir_all(&dest).unwrap();
        let (mut ctx, g) = ctx_for(&dest);
        run_config_migrate(&mut ctx, &g, src.to_str().unwrap(), false).unwrap();
        let v = decode_ordered_json(ctx.out.stdout.as_bytes()).unwrap();
        let obj = match &v {
            JsonValue::Object(o) => o,
            _ => panic!("want object"),
        };
        assert_eq!(
            obj.get("would_write"),
            Some(&JsonValue::Bool(true)),
            "got: {}",
            ctx.out.stdout
        );
        assert_eq!(obj.get("migrated"), Some(&JsonValue::Bool(false)));
        // Dry run writes nothing.
        assert!(!dest.join("config.json").exists());
    }

    #[test]
    fn migrate_handler_refuse_overwrite_prints_json_then_exit_2() {
        let dir = temp_dir("mig-refuse");
        let src = dir.join("legacy-src");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("config.json"), r#"{"node_id":"LEGACY-NODE"}"#).unwrap();
        std::fs::write(src.join("cookies.txt"), "FAKE").unwrap();
        let dest = dir.join("dest");
        std::fs::create_dir_all(&dest).unwrap();
        write_config(&dest, r#"{"profiles":{"other":{"node_id":"OTHER-NODE"}}}"#);
        let before = std::fs::read(dest.join("config.json")).unwrap();
        let (mut ctx, g) = ctx_for(&dest);
        let err = run_config_migrate(&mut ctx, &g, src.to_str().unwrap(), false).unwrap_err();
        assert_eq!(flow_code(&err), 2);
        // The result JSON was still printed on stdout.
        let v = decode_ordered_json(ctx.out.stdout.as_bytes()).unwrap();
        let obj = match &v {
            JsonValue::Object(o) => o,
            _ => panic!("want object, got: {}", ctx.out.stdout),
        };
        assert_eq!(
            obj.get("reason"),
            Some(&JsonValue::Str("refuse-overwrite".into()))
        );
        assert_eq!(obj.get("migrated"), Some(&JsonValue::Bool(false)));
        assert_eq!(std::fs::read(dest.join("config.json")).unwrap(), before);
    }
}
