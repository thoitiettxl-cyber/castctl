// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! `auth list` / `auth status` / `auth import` wiring (M7b
//! PR-3): `internal/commands/deliver.go:99` (`cmdAuthList`),
//! `internal/commands/authstatus.go:75` (`cmdAuthStatus`),
//! `internal/commands/authimport.go:51` (`cmdAuthImport`).
//!
//! `auth observe-login` is NOT wired here: it stays the fixed
//! tag-off exit-2 error in `run.rs` (Go checks
//! `keeper.ReloginAvailable()` FIRST, before config, and the
//! shipped Go binary is built WITHOUT `with_chromedp` — the
//! error is the faithful port of that build; see
//! `rust/PORTING.md` §M7b.13 for the CDP feature story and
//! why the keeper's `CDP_AVAILABLE` is never consulted).
//!
//! No cookie VALUE is ever printed, logged, or echoed: only
//! names, paths, and expiry dates leave this module (repo
//! `AGENTS.md` rule 1).

use std::sync::Arc;

use castctl_config::config::{SingleConfig, resolve_active_profile};
use castctl_config::configlocation::ConfigLocation;
use castctl_config::gostr::go_quote;
use castctl_config::jsonvalue::{JsonValue, OrderedObject, encode_ordered_json};
use castctl_config::keeper::DEFAULT_EXPIRING_WITHIN;
use castctl_config::profile::profile_paths;
use castctl_deliver::{DeliverError, format_auth_list, list_profiles};
use castctl_keeper::{
    AuthStatus, AuthStatusValue, DEFAULT_LOCK_TIMEOUT, KeeperError, RealClock, SessionState,
    cookie_expiry_metadata, default_login_contract, derive_auth_status, load_state,
    lock_cookies_file, parse_cookies_lenient, reset_after_login, write_cookies_file,
};
use chrono::Utc;

use crate::network::write_json_text;
use crate::run::{Ctx, FlowErr, GlobalOpts, config_err, msg, resolve_config};

// ---------------------------------------------------------------------------
// auth list
// ---------------------------------------------------------------------------

/// `cmdAuthList` (`deliver.go:99`): resolve config (done by
/// the caller) + active profile (honouring the global
/// `--profile` flag, Go `resolveActive`) + `ListProfiles`,
/// then `--json` or the text table. A `ListProfiles` config
/// failure keeps its exit code; anything else is exit 2.
pub(crate) fn run_auth_list(
    ctx: &mut Ctx<'_>,
    loc: &ConfigLocation,
    g: &GlobalOpts,
    json: bool,
) -> Result<(), FlowErr> {
    let flag = if g.profile_set {
        Some(g.profile_flag.as_str())
    } else {
        None
    };
    let active = resolve_active_profile(&loc.config_dir, flag, ctx.getenv).map_err(config_err)?;
    let list = list_profiles(&loc.config_dir, &active.name).map_err(|e| match e {
        DeliverError::Config(ce) => config_err(ce),
        other => msg(2, other.to_string()),
    })?;
    if json {
        // `serde_json::to_string` on the struct keeps field
        // order, leaves `<>&` literal, and `write_json_text`
        // adds Go's 2-space indent + trailing newline (the
        // same rendering `write_json_serde` does for a
        // `serde_json::Value`).
        let compact = serde_json::to_string(&list)
            .map_err(|e| msg(1, format!("failed to serialize auth list result: {e}")))?;
        ctx.out.stdout.push_str(&write_json_text(&compact));
    } else {
        ctx.out.stdout.push_str(&format_auth_list(&list));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// auth status
// ---------------------------------------------------------------------------

/// The driver is NEVER available in this build: the shipped
/// Go binary is built WITHOUT `with_chromedp` (verified from
/// the binary itself), and the Rust build has no chromedp tag
/// at all (M6b precedent, `castctl-webui/src/screencast.rs`).
/// The keeper crate's `CDP_AVAILABLE` is `cfg!(feature =
/// "chromedp")`, which is TRUE in workspace builds (keeper's
/// default features) — consulting it would report headless
/// available where Go reports `no_chromedp` (the M6b M-1
/// bug). So the shipped-binary model is a constant `false`,
/// and the S2 loopback proxy has no Rust equivalent anyway:
/// even a chromedp-enabled build would fail closed at the
/// inbound step. See PORTING §M7b.13.
const DRIVER_AVAILABLE: bool = false;

/// The pure gate order behind `authHeadlessCapability`
/// (`authstatus.go:252-266`), unit-testable for every
/// branch. Gates, in order: a keeper entry must exist
/// (re-login only runs from a tick), this build must have
/// the driver, the versioned login-form contract must be
/// established and usable (observed, with steps and a login
/// URL), the keeper entry must reference credentials, and
/// stored credentials must exist for the profile. The
/// contract gate precedes the credentials gates.
pub(crate) fn headless_capability(
    has_entry: bool,
    driver_available: bool,
    has_credentials: bool,
    contract_usable: bool,
    has_credentials_ref: bool,
) -> (bool, &'static str) {
    if !has_entry {
        return (false, "no_keeper_entry");
    }
    if !driver_available {
        return (false, "no_chromedp");
    }
    if !contract_usable {
        return (false, "no_contract");
    }
    if !has_credentials_ref {
        return (false, "no_credentials_ref");
    }
    if !has_credentials {
        return (false, "no_credentials");
    }
    (true, "")
}

/// Whether the versioned login-form contract is established
/// and usable (`authstatus.go:247-250`): loadable, observed,
/// with steps and a login URL.
fn contract_usable() -> bool {
    match default_login_contract() {
        Ok(c) => c.observed && !c.steps.is_empty() && !c.login_url.is_empty(),
        Err(_) => false,
    }
}

/// One profile's state-only report
/// (`authStatusForProfile`, `authstatus.go:171-230`). A
/// corrupt state file is treated as no state (the cookies
/// file still decides); any other state read error fails
/// the command. An unreadable cookies file is a config
/// error naming the profile only, never file bytes.
#[allow(clippy::too_many_arguments)]
fn auth_status_for_profile(
    base_dir: &str,
    name: &str,
    single: &SingleConfig,
    now: chrono::DateTime<Utc>,
) -> Result<AuthStatus, FlowErr> {
    let entry = single.keeper_entry_for_profile(name);
    let paths = profile_paths(base_dir, name).map_err(config_err)?;
    let st = match load_state(&paths.dir) {
        Ok(st) => st,
        Err(e) => {
            if matches!(e, KeeperError::StateCorrupt(_)) {
                SessionState::new()
            } else {
                return Err(msg(1, e.to_string()));
            }
        }
    };
    // Go: `prof.CookiesFile`, falling back to the default
    // path when empty (`authstatus.go:190-193`). A profile
    // synthesised by `resolve_active_profile` (the F1
    // "default") has no entry in `single.profiles`, so the
    // same fallback covers a missing entry too.
    let cookies_path = single
        .profiles
        .get(name)
        .map(|p| p.cookies_file.clone())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| paths.cookies.clone());
    let (driving_name, driving_expiry, seen, file_missing) =
        cookie_expiry_metadata(&cookies_path, now).map_err(|_| {
            msg(
                2,
                format!(
                    "auth status: profile {} cookies file is unreadable",
                    go_quote(name)
                ),
            )
        })?;
    let expiring_within = entry.map_or(DEFAULT_EXPIRING_WITHIN, |e| e.effective_expiring_within());
    let has_credentials = single.has_credential_for_profile(name);
    let has_ref = entry.is_some_and(|e| !e.credentials.is_empty());
    let (headless_available, headless_reason) = headless_capability(
        entry.is_some(),
        DRIVER_AVAILABLE,
        has_credentials,
        contract_usable(),
        has_ref,
    );
    Ok(derive_auth_status(
        name,
        &driving_name,
        driving_expiry,
        seen,
        file_missing,
        Some(&st),
        expiring_within,
        headless_available,
        headless_reason,
        now,
    ))
}

/// Render one status as Go's `authStatusJSON` struct
/// (`authstatus.go:60-74`): field-declaration order,
/// `omitempty` skips, `liveness_checked` always false (this
/// command performs no live check). Times render as Go's
/// `RFC3339Nano` (trailing zeros trimmed, `Z` for UTC) via
/// the shared `castctl_shared::timefmt::format_go_rfc3339_nano`
/// helper (fix loop 1, B1: the old `AutoSi` render printed
/// `.500` where Go prints `.5`).
fn auth_status_json(st: &AuthStatus) -> JsonValue {
    let mut o = OrderedObject::new();
    o.set("profile", JsonValue::Str(st.profile.clone()));
    o.set("status", JsonValue::Str(st.status.as_str().to_string()));
    o.set("liveness_checked", JsonValue::Bool(false));
    if !st.driving_cookie.is_empty() {
        o.set("driving_cookie", JsonValue::Str(st.driving_cookie.clone()));
    }
    if let Some(exp) = st.driving_expiry {
        o.set(
            "driving_expiry",
            JsonValue::Str(castctl_shared::timefmt::format_go_rfc3339_nano(&exp)),
        );
    }
    if let Some(t) = st.last_checked_at {
        o.set(
            "last_checked_at",
            JsonValue::Str(castctl_shared::timefmt::format_go_rfc3339_nano(&t)),
        );
    }
    o.set("keeper_stopped", JsonValue::Bool(st.keeper_stopped));
    if !st.keeper_stopped_reason.is_empty() {
        o.set(
            "keeper_stopped_reason",
            JsonValue::Str(st.keeper_stopped_reason.clone()),
        );
    }
    o.set("headless_available", JsonValue::Bool(st.headless_available));
    if !st.headless_reason.is_empty() {
        o.set(
            "headless_reason",
            JsonValue::Str(st.headless_reason.clone()),
        );
    }
    o.set("needs_action", JsonValue::Bool(st.needs_action));
    o.set(
        "cookies_seen",
        JsonValue::Number(st.cookies_seen.to_string()),
    );
    JsonValue::Object(o)
}

/// `cmdAuthStatus` (`authstatus.go:75`): resolve config
/// (done by the caller) + `LoadSingleConfig` — no config
/// file is exit 2 — + keeper/credentials resolution, then
/// one report per name: `--all` iterates
/// `single.ProfileNames()` (empty is exit 2), `--profile`
/// must name a configured profile, otherwise the active
/// profile (global `--profile` flag honoured). One object
/// for a single profile, an array otherwise; the worst
/// status wins the exit code: 3 expired (`castctl: auth
/// status: session expired`), 1 expiring (`castctl: auth
/// status: session expiring`), else 0.
pub(crate) fn run_auth_status(
    ctx: &mut Ctx<'_>,
    loc: &ConfigLocation,
    single: Option<&SingleConfig>,
    g: &GlobalOpts,
    profile_name: &str,
    all: bool,
) -> Result<(), FlowErr> {
    let Some(single) = single else {
        return Err(msg(2, "auth status: no config.json found"));
    };
    // Go resolves keeper + credentials before the names
    // switch; parse already validated the credentials block
    // (`blocks.rs`, Go `validateCredentials`), so only the
    // keeper resolution can still fail here.
    let _kcfg = single.resolve_keeper().map_err(config_err)?;
    let names: Vec<String> = if all {
        let names = single.profile_names();
        if names.is_empty() {
            return Err(msg(2, "auth status: no profiles configured"));
        }
        names
    } else if !profile_name.is_empty() {
        if !single.profiles.contains_key(profile_name) {
            return Err(msg(
                2,
                format!(
                    "auth status: profile {} does not exist",
                    go_quote(profile_name)
                ),
            ));
        }
        vec![profile_name.to_string()]
    } else {
        let flag = if g.profile_set {
            Some(g.profile_flag.as_str())
        } else {
            None
        };
        let active =
            resolve_active_profile(&loc.config_dir, flag, ctx.getenv).map_err(config_err)?;
        vec![active.name]
    };
    let now = Utc::now();
    let mut worst = 0;
    let mut out: Vec<JsonValue> = Vec::with_capacity(names.len());
    for name in &names {
        let st = auth_status_for_profile(&loc.config_dir, name, single, now)?;
        match st.status {
            AuthStatusValue::Expired => worst = 3,
            AuthStatusValue::Expiring => {
                if worst < 1 {
                    worst = 1;
                }
            }
            AuthStatusValue::Ok => {}
        }
        out.push(auth_status_json(&st));
    }
    let rendered = if out.len() == 1 {
        encode_ordered_json(&out[0])
    } else {
        encode_ordered_json(&JsonValue::Array(out))
    }
    .map_err(|e| msg(1, format!("failed to serialize auth status result: {e}")))?;
    ctx.out.stdout.push_str(&write_json_text(&rendered));
    match worst {
        3 => Err(msg(3, "auth status: session expired")),
        1 => Err(msg(1, "auth status: session expiring")),
        _ => Ok(()),
    }
}

// ---------------------------------------------------------------------------
// auth import
// ---------------------------------------------------------------------------

/// `normaliseImportInput` (`authimport.go:123-134`): stdin
/// must be valid UTF-8, CRLF and CR-only line endings become
/// `\n`, leading/trailing whitespace is stripped. A BOM is
/// NOT stripped: BOM behaviour is exactly `ParseCookies`
/// behaviour. The result is stored verbatim apart from this
/// normalisation plus the single trailing newline added by
/// the caller.
fn normalise_import_input(raw: &[u8]) -> Result<String, String> {
    let s = std::str::from_utf8(raw).map_err(|_| "stdin is not valid UTF-8".to_string())?;
    let s = s.replace("\r\n", "\n").replace('\r', "\n");
    Ok(s.trim().to_string())
}

/// `validateImportInput` (`authimport.go:143-158`): the
/// normalised input must be non-empty, must parse under
/// `ParseCookies` semantics (unmodified), and must carry a
/// `hatch_sess` pair with a non-empty value. Every message
/// is fixed and never echoes input bytes.
fn validate_import_input(normalised: &str) -> Result<(), FlowErr> {
    if normalised.is_empty() {
        return Err(msg(2, "no cookies on stdin"));
    }
    if parse_cookies_lenient(normalised).is_err() {
        return Err(msg(2, "could not parse cookies input"));
    }
    if !import_has_hatch_sess(normalised) {
        return Err(msg(2, "no hatch_sess cookie in input"));
    }
    Ok(())
}

/// `importHasHatchSess` (`authimport.go:171-227`): mirrors
/// the `ParseCookies` dispatch order — JSON object first
/// (only when the JSON decode succeeds and yields an
/// object), then the one-line form (only when the
/// `hatch_sess=`/`datr=` trigger is present), then the
/// Netscape jar. Comment lines are excluded entirely.
fn import_has_hatch_sess(raw: &str) -> bool {
    if raw.starts_with('{') {
        let (decided, ok) = import_json_has_hatch_sess(raw);
        if decided {
            return ok;
        }
    }
    if raw.contains("hatch_sess=") || raw.contains("datr=") {
        for line in raw.split('\n') {
            let line = line.trim();
            if !line.is_empty()
                && !is_import_comment_line(line)
                && !is_jar_row_line(line)
                && line.contains('=')
                && line.contains(';')
            {
                // The FIRST qualifying line decides: a later
                // line is never consulted.
                return line_has_hatch_pair(line);
            }
        }
        // No qualifying line: strict pairs from the flattened
        // non-comment, non-jar lines only.
        let mut kept: Vec<&str> = Vec::new();
        for line in raw.split('\n') {
            let line = line.trim();
            if !line.is_empty() && !is_import_comment_line(line) && !is_jar_row_line(line) {
                kept.push(line);
            }
        }
        return fallback_has_hatch_pair(&kept.join(" "));
    }
    for line in raw.split('\n') {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let cols: Vec<&str> = line.split('\t').collect();
        if cols.len() >= 7 && cols[5] == "hatch_sess" && !cols[6].trim().is_empty() {
            return true;
        }
    }
    false
}

/// `importJSONHasHatchSess` (`authimport.go:229-251`):
/// decided=false when the input is not a JSON object, so
/// the caller falls through to the line forms exactly as
/// `ParseCookies` does (invalid JSON and trailing data both
/// fall through). A `"cookies"` value that is an object
/// scopes the check to that object; otherwise all
/// top-level entries are checked.
///
/// Strictness note: Go decodes ONE value and requires the
/// second decode to be `io.EOF` — `{"hatch_sess":"x"}}`
/// (extra brace) is UNDECIDED there, while the shared
/// `decode_ordered_json` (Go `More()` semantics) accepts
/// it. `serde_json::from_str` is the strict oracle here: it
/// requires the whole input to be exactly one value.
fn import_json_has_hatch_sess(raw: &str) -> (bool, bool) {
    let v: serde_json::Value = match serde_json::from_str(raw) {
        Ok(v) => v,
        Err(_) => return (false, false),
    };
    let serde_json::Value::Object(obj) = v else {
        return (false, false);
    };
    if let Some(serde_json::Value::Object(inner)) = obj.get("cookies") {
        return (true, json_value_has_hatch_pair(inner));
    }
    (true, json_value_has_hatch_pair(&obj))
}

/// `jsonHasHatchPair` (`authimport.go:253-264`): only a
/// non-blank STRING counts. Numbers, booleans, arrays,
/// objects, and null do NOT count, even though
/// `ParseCookies` would render them as non-empty literals.
fn json_value_has_hatch_pair(obj: &serde_json::Map<String, serde_json::Value>) -> bool {
    matches!(obj.get("hatch_sess"), Some(serde_json::Value::String(s)) if !s.trim().is_empty())
}

/// `isImportCommentLine` (`authimport.go:266-272`): a `#`
/// first after surrounding whitespace (and an optional BOM
/// at the start of the input, which `TrimSpace` does not
/// strip).
fn is_import_comment_line(line: &str) -> bool {
    let line = line.trim();
    let line = line.strip_prefix('\u{feff}').unwrap_or(line);
    line.starts_with('#')
}

/// `isJarRowLine` (`authimport.go:274-280`): at least seven
/// tab-separated columns, the same threshold the jar branch
/// uses.
fn is_jar_row_line(line: &str) -> bool {
    line.split('\t').count() >= 7
}

/// `fallbackHasHatchPair` (`authimport.go:282-303`): the
/// flattened text is split into whitespace-separated fields;
/// some field must be exactly `hatch_sess=` plus a
/// non-empty remainder containing no `;`.
fn fallback_has_hatch_pair(s: &str) -> bool {
    let s = s.strip_prefix('\u{feff}').unwrap_or(s);
    const PREFIX: &str = "hatch_sess=";
    for field in s.split_whitespace() {
        if !field.starts_with(PREFIX) {
            continue;
        }
        let remainder = &field[PREFIX.len()..];
        if !remainder.is_empty() && !remainder.contains(';') {
            return true;
        }
    }
    false
}

/// `lineHasHatchPair` (`authimport.go:305-322`): segments
/// split on `;` and whitespace, each pair splits on its
/// first `=`, the name must be exactly `hatch_sess` with a
/// non-blank value. A leading BOM is stripped for the check
/// only.
fn line_has_hatch_pair(s: &str) -> bool {
    let s = s.strip_prefix('\u{feff}').unwrap_or(s);
    for seg in s.split([';', ' ', '\t', '\n']) {
        if seg.is_empty() {
            continue;
        }
        let Some((name, value)) = seg.split_once('=') else {
            continue;
        };
        if name == "hatch_sess" && !value.trim().is_empty() {
            return true;
        }
    }
    false
}

/// `cmdAuthImport` (`authimport.go:51`): stdin is read by
/// the caller in `run.rs` BEFORE config resolution (Go
/// `authimport.go:67-81`: read stdin, normalise, validate,
/// then resolve config + active profile). The stored bytes
/// are the normalised input verbatim plus one trailing
/// newline. The write goes through the same per-cookies-file
/// lock the keeper uses (5s, `DEFAULT_LOCK_TIMEOUT`), atomic
/// temp + rename, mode 0600, `.bak` backup of the previous
/// file; then `ResetAfterLogin` clears the keeper's sticky
/// stopped/logged_out markers. Write errors are exit 2
/// (`write cookies file: ...`); a reset failure is exit 2
/// with the file already written (`cookies written but
/// keeper state reset failed: ...`). The result JSON is
/// `{"ok": true, "profile", "cookies_file", "backup"}`.
pub(crate) fn run_auth_import(
    ctx: &mut Ctx<'_>,
    g: &GlobalOpts,
    stdin_data: &[u8],
) -> Result<(), FlowErr> {
    let stored = normalise_import_input(stdin_data).map_err(|m| msg(2, m))?;
    validate_import_input(&stored)?;
    // Config resolution happens AFTER validation, in Go's
    // order (`authimport.go:78-85`).
    let loc = resolve_config(ctx, g, false)?;
    let flag = if g.profile_set {
        Some(g.profile_flag.as_str())
    } else {
        None
    };
    let active = resolve_active_profile(&loc.config_dir, flag, ctx.getenv).map_err(config_err)?;
    let stored_bytes = format!("{stored}\n");
    let backup = {
        let _guard = lock_cookies_file(
            &loc.config_dir,
            &active.name,
            &active.cookies_file,
            DEFAULT_LOCK_TIMEOUT,
        )
        .map_err(|e| msg(2, format!("write cookies file: {e}")))?;
        write_cookies_file(
            &loc.config_dir,
            &active.name,
            &active.cookies_file,
            stored_bytes.as_bytes(),
        )
        .map_err(|e| msg(2, format!("write cookies file: {e}")))?
        // The guard drops here: the lock is released before
        // the keeper-state reset, exactly like Go's
        // `WriteCookiesFileLocked` returning first.
    };
    if let Err(e) = reset_keeper_after_login(&loc.config_dir, &active.name) {
        return Err(msg(
            2,
            format!("cookies written but keeper state reset failed: {e}"),
        ));
    }
    let mut o = OrderedObject::new();
    o.set("ok", JsonValue::Bool(true));
    o.set("profile", JsonValue::Str(active.name));
    o.set("cookies_file", JsonValue::Str(active.cookies_file));
    o.set("backup", JsonValue::Bool(backup));
    let rendered = encode_ordered_json(&JsonValue::Object(o))
        .map_err(|e| msg(1, format!("failed to serialize auth import result: {e}")))?;
    ctx.out.stdout.push_str(&write_json_text(&rendered));
    Ok(())
}

/// `keeper.ResetAfterLogin` is async; the CLI is sync, so
/// block on it with a fresh multi-threaded runtime (the same
/// shape `chat.rs` uses). The reset does no network: it
/// clears sticky state markers under the state lock.
fn reset_keeper_after_login(base_dir: &str, profile_name: &str) -> Result<(), KeeperError> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| KeeperError::Other(e.to_string()))?;
    let clock: Arc<dyn castctl_keeper::Clock> = Arc::new(RealClock);
    rt.block_on(reset_after_login(base_dir, profile_name, clock))
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- headless_capability: every gate branch (Go
    // `headlessCapability`, `authstatus.go:252-266`). ---

    #[test]
    fn headless_gates_in_order() {
        assert_eq!(
            headless_capability(false, true, true, true, true),
            (false, "no_keeper_entry")
        );
        assert_eq!(
            headless_capability(true, false, true, true, true),
            (false, "no_chromedp")
        );
        assert_eq!(
            headless_capability(true, true, true, false, true),
            (false, "no_contract")
        );
        assert_eq!(
            headless_capability(true, true, true, true, false),
            (false, "no_credentials_ref")
        );
        assert_eq!(
            headless_capability(true, true, false, true, true),
            (false, "no_credentials")
        );
        assert_eq!(
            headless_capability(true, true, true, true, true),
            (true, "")
        );
        // The contract gate precedes the credentials gates:
        // unusable contract + missing credentials still says
        // no_contract.
        assert_eq!(
            headless_capability(true, true, false, false, false),
            (false, "no_contract")
        );
    }

    // --- normalise_import_input ---

    #[test]
    fn normalise_rejects_invalid_utf8() {
        assert_eq!(
            normalise_import_input(&[0xff, 0xfe]),
            Err("stdin is not valid UTF-8".to_string())
        );
    }

    #[test]
    fn normalise_folds_crlf_and_trims() {
        assert_eq!(
            normalise_import_input(b"  hatch_sess=FAKE\r\nfoo=bar\r  ").unwrap(),
            "hatch_sess=FAKE\nfoo=bar"
        );
    }

    // --- import_has_hatch_sess: dispatch fidelity ---

    #[test]
    fn hatch_json_string_counts() {
        assert!(import_has_hatch_sess(r#"{"hatch_sess": "FAKE"}"#));
        assert!(import_has_hatch_sess(
            r#"{"cookies": {"hatch_sess": "FAKE"}}"#
        ));
        // Scoped: a top-level hatch_sess does NOT count when
        // "cookies" holds an object without it.
        assert!(!import_has_hatch_sess(
            r#"{"hatch_sess": "FAKE", "cookies": {"other": "x"}}"#
        ));
    }

    #[test]
    fn hatch_json_non_string_does_not_count() {
        // Numbers, booleans, null, arrays, objects: decided
        // false, no fallthrough to line forms.
        assert!(!import_has_hatch_sess(r#"{"hatch_sess": 123}"#));
        assert!(!import_has_hatch_sess(r#"{"hatch_sess": true}"#));
        assert!(!import_has_hatch_sess(r#"{"hatch_sess": null}"#));
        assert!(!import_has_hatch_sess(r#"{"hatch_sess": ""}"#));
        assert!(!import_has_hatch_sess(r#"{"hatch_sess": "   "}"#));
    }

    #[test]
    fn hatch_json_trailing_data_falls_through() {
        // `{"hatch_sess":"x"}}` (extra brace): Go's second
        // Decode fails, so the JSON branch is undecided and
        // the line forms find nothing.
        assert!(!import_has_hatch_sess(r#"{"hatch_sess": "FAKE"}}"#));
        // Invalid JSON falls through to line forms: a
        // one-line pair still counts.
        assert!(import_has_hatch_sess(
            r#"{"hatch_sess": "FAKE", hatch_sess=LINE"#
        ));
    }

    #[test]
    fn hatch_one_line_first_qualifying_line_decides() {
        assert!(import_has_hatch_sess("datr=X; hatch_sess=FAKE; foo=bar"));
        assert!(import_has_hatch_sess("hatch_sess=FAKE"));
        // First qualifying line has no hatch pair: later
        // lines are never consulted.
        assert!(!import_has_hatch_sess("foo=1; bar=2\nhatch_sess=FAKE"));
        // No qualifying line: the flattened fallback still
        // finds a bare pair.
        assert!(import_has_hatch_sess("hatch_sess=FAKE datr=X"));
        // A hatch_sess mention inside another cookie's value
        // does not count.
        assert!(!import_has_hatch_sess("foo=hatch_sess=FAKE; bar=1"));
    }

    #[test]
    fn hatch_comments_and_jar_rows_excluded() {
        // `#` mentions never count, in any branch.
        assert!(!import_has_hatch_sess("# hatch_sess=FAKE"));
        assert!(!import_has_hatch_sess("# hatch_sess=FAKE\nhatch_sess="));
        // A jar row counts only via the jar branch (col 6).
        assert!(import_has_hatch_sess(
            ".muse.ai\tTRUE\t/\tTRUE\t0\thatch_sess\tFAKE"
        ));
        assert!(!import_has_hatch_sess(
            ".muse.ai\tTRUE\t/\tTRUE\t0\thatch_sess\t"
        ));
        assert!(!import_has_hatch_sess(
            ".muse.ai\tTRUE\t/\tTRUE\t0\tother\tFAKE"
        ));
        // A jar row's value column must not be pair-scanned
        // as one-line input even when it contains ";".
        assert!(!import_has_hatch_sess(
            ".muse.ai\tTRUE\t/\tTRUE\t0\tother\thatch_sess=FAKE; x=1"
        ));
    }

    #[test]
    fn hatch_duplicate_json_keys_last_wins() {
        assert!(import_has_hatch_sess(
            r#"{"hatch_sess": "", "hatch_sess": "FAKE"}"#
        ));
        assert!(!import_has_hatch_sess(
            r#"{"hatch_sess": "FAKE", "hatch_sess": ""}"#
        ));
    }

    // --- validate_import_input ---

    #[test]
    fn validate_rejects_empty_unparseable_no_hatch() {
        assert!(matches!(
            validate_import_input(""),
            Err(FlowErr::Msg { code: 2, message: Some(m) }) if m == "no cookies on stdin"
        ));
        assert!(matches!(
            validate_import_input("just some words"),
            Err(FlowErr::Msg { code: 2, message: Some(m) }) if m == "could not parse cookies input"
        ));
        assert!(matches!(
            validate_import_input("datr=FAKE; foo=bar"),
            Err(FlowErr::Msg { code: 2, message: Some(m) }) if m == "no hatch_sess cookie in input"
        ));
        assert!(validate_import_input("hatch_sess=FAKE; datr=X").is_ok());
    }

    // --- run_auth_import: fixture config home ---
    //
    // The import writes through the keeper lock to a TEST
    // profile only (never the live `no.0` cookies); the
    // values below are obvious fakes.

    fn fixture_home(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("castctl-auth-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join(".config/castctl")).unwrap();
        dir
    }

    fn fixture_env(home: &std::path::Path) -> std::collections::HashMap<String, String> {
        let mut map = std::collections::HashMap::new();
        map.insert("HOME".to_string(), home.to_str().unwrap().to_string());
        map.insert(
            "XDG_CONFIG_HOME".to_string(),
            home.join(".config").to_str().unwrap().to_string(),
        );
        map
    }

    #[test]
    fn import_jar_writes_0600_with_backup() {
        use std::os::unix::fs::PermissionsExt;
        let home = fixture_home("import");
        std::fs::write(
            home.join(".config/castctl/config.json"),
            "{\"default_profile\":\"no1\",\"profiles\":{\"no1\":{}}}",
        )
        .unwrap();
        let map = fixture_env(&home);
        let getenv = |k: &str| map.get(k).cloned();
        let mut ctx = Ctx {
            out: crate::run::Outcome::default(),
            getenv: Some(&getenv),
        };
        let g = GlobalOpts::default();
        let cookies = home.join(".config/castctl/profiles/no1/cookies.txt");
        let bak = home.join(".config/castctl/profiles/no1/cookies.txt.bak");

        // First import: no previous file, backup false.
        run_auth_import(&mut ctx, &g, b"hatch_sess=FAKE-ONE; datr=FAKE-DATR").unwrap();
        let expected = format!(
            "{{\n  \"ok\": true,\n  \"profile\": \"no1\",\n  \"cookies_file\": \"{}\",\n  \"backup\": false\n}}\n",
            cookies.to_str().unwrap()
        );
        assert_eq!(ctx.out.stdout, expected);
        assert_eq!(
            std::fs::read_to_string(&cookies).unwrap(),
            "hatch_sess=FAKE-ONE; datr=FAKE-DATR\n"
        );
        assert_eq!(
            std::fs::metadata(&cookies).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(!bak.exists());

        // Second import: backup true, `.bak` holds the first.
        ctx.out.stdout.clear();
        run_auth_import(&mut ctx, &g, b"hatch_sess=FAKE-TWO").unwrap();
        assert!(
            ctx.out.stdout.contains("\"backup\": true"),
            "{}",
            ctx.out.stdout
        );
        assert_eq!(
            std::fs::read_to_string(&cookies).unwrap(),
            "hatch_sess=FAKE-TWO\n"
        );
        assert_eq!(
            std::fs::read_to_string(&bak).unwrap(),
            "hatch_sess=FAKE-ONE; datr=FAKE-DATR\n"
        );
        assert_eq!(
            std::fs::metadata(&bak).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn import_json_and_crlf_forms() {
        let home = fixture_home("import-json");
        std::fs::write(
            home.join(".config/castctl/config.json"),
            "{\"default_profile\":\"no1\",\"profiles\":{\"no1\":{}}}",
        )
        .unwrap();
        let map = fixture_env(&home);
        let getenv = |k: &str| map.get(k).cloned();
        let mut ctx = Ctx {
            out: crate::run::Outcome::default(),
            getenv: Some(&getenv),
        };
        let g = GlobalOpts::default();
        let cookies = home.join(".config/castctl/profiles/no1/cookies.txt");
        run_auth_import(&mut ctx, &g, b"{\"hatch_sess\": \"FAKE-JSON\"}").unwrap();
        assert_eq!(
            std::fs::read_to_string(&cookies).unwrap(),
            "{\"hatch_sess\": \"FAKE-JSON\"}\n"
        );
        // CRLF folds to LF before storing.
        run_auth_import(&mut ctx, &g, b"hatch_sess=FAKE-CRLF\r\ndatr=X\r\n").unwrap();
        assert_eq!(
            std::fs::read_to_string(&cookies).unwrap(),
            "hatch_sess=FAKE-CRLF\ndatr=X\n"
        );
    }

    #[test]
    fn import_errors_are_exit_2_without_writing() {
        let home = fixture_home("import-err");
        std::fs::write(
            home.join(".config/castctl/config.json"),
            "{\"default_profile\":\"no1\",\"profiles\":{\"no1\":{}}}",
        )
        .unwrap();
        let map = fixture_env(&home);
        let getenv = |k: &str| map.get(k).cloned();
        let mut ctx = Ctx {
            out: crate::run::Outcome::default(),
            getenv: Some(&getenv),
        };
        let g = GlobalOpts::default();
        let cookies = home.join(".config/castctl/profiles/no1/cookies.txt");
        for (input, want) in [
            (&b"\xff\xfe"[..], "stdin is not valid UTF-8"),
            (b"" as &[u8], "no cookies on stdin"),
            (b"datr=FAKE; foo=bar", "no hatch_sess cookie in input"),
        ] {
            let err = run_auth_import(&mut ctx, &g, input).unwrap_err();
            assert!(
                matches!(err, FlowErr::Msg { code: 2, message: Some(ref m) } if m == want),
                "{err:?} (want {want})"
            );
        }
        assert!(!cookies.exists());
    }

    #[test]
    fn auth_status_json_trims_trailing_zeros_like_go() {
        // Fix loop 1, B1 (`auth status` render site): Go
        // RFC3339Nano renders `.5` / `.12`, not `.500` /
        // `.120` — for both the UTC driving expiry and the
        // LOCAL last-checked time.
        use chrono::{FixedOffset, TimeZone, Timelike};
        let st = AuthStatus {
            profile: "no.0".to_string(),
            status: AuthStatusValue::Ok,
            driving_cookie: "hatch_sess".to_string(),
            driving_expiry: Some(
                FixedOffset::east_opt(0)
                    .unwrap()
                    .with_ymd_and_hms(2026, 12, 5, 0, 0, 0)
                    .unwrap()
                    .with_nanosecond(500_000_000)
                    .unwrap(),
            ),
            last_checked_at: Some(
                FixedOffset::east_opt(7 * 3600)
                    .unwrap()
                    .with_ymd_and_hms(2026, 11, 7, 18, 33, 11)
                    .unwrap()
                    .with_nanosecond(120_000_000)
                    .unwrap(),
            ),
            keeper_stopped: false,
            keeper_stopped_reason: String::new(),
            headless_available: true,
            headless_reason: String::new(),
            needs_action: false,
            cookies_seen: 10,
        };
        let JsonValue::Object(o) = auth_status_json(&st) else {
            panic!("object")
        };
        assert_eq!(
            o.get("driving_expiry"),
            Some(&JsonValue::Str("2026-12-05T00:00:00.5Z".to_string()))
        );
        assert_eq!(
            o.get("last_checked_at"),
            Some(&JsonValue::Str("2026-11-07T18:33:11.12+07:00".to_string()))
        );
    }
}
