// SPDX-License-Identifier: GPL-3.0-only
// Section editors for the `keeper` and `webui` blocks:
// GET/PUT pairs mirroring the DNS and Telegram section
// saves. Port of Go internal/webui/sections.go.
//
// Every mutation funnels through saveGuarded
// (full-document parse, sentinel assertion, hash-on-save,
// flock + atomic 0600 write, 409 on a stale
// base_sha256): there is no second save path.
//
// The keeper editor edits configuration only: it never
// ticks the keeper, writes cookies, or contacts a
// browser.
//
// The `webui` editor's token field is write-only, like
// Telegram's: empty means unchanged, a placeholder is
// rejected, and a new plaintext token is hashed on save
// by saveGuarded. Editing `listen` takes effect on
// restart (the running server keeps its bound address);
// editing the idle timeout or rate limit takes effect
// immediately, because the server re-reads the stored
// block per request.

use crate::auth::REDACTED_MARKER;
use crate::config::{
    DEFAULT_LOGIN_RATE_LIMIT_ATTEMPTS, DEFAULT_LOGIN_RATE_LIMIT_WINDOW_NS,
    DEFAULT_SESSION_IDLE_TIMEOUT_NS, MAX_LOGIN_RATE_LIMIT_ATTEMPTS, MAX_LOGIN_RATE_LIMIT_WINDOW_NS,
    MAX_SESSION_IDLE_TIMEOUT_NS, MIN_LOGIN_RATE_LIMIT_WINDOW_NS, MIN_SESSION_IDLE_TIMEOUT_NS,
    effective_listen, effective_login_rate_limit, effective_session_idle_timeout_ns, resolve_webui,
};
use crate::duration::{format_duration, parse_duration};
use crate::error::{ApiError, err_validation};
use crate::server::{Resp, envelope_resp};
use crate::store::{ConfigLoad, SaveOutcome, parse_loaded, save_merged};
use castctl_config::jsonvalue::{JsonValue, OrderedObject};
use std::path::Path;

// --- keeper settings ------------------------------------------

/// One `keeper` entry as the settings editor shows it:
/// the config fields plus the interval in seconds (the
/// keeper status view's unit).
fn keeper_settings_entry_json(e: &crate::validate::KeeperEntry) -> JsonValue {
    let mut obj = OrderedObject::new();
    obj.set("tag", JsonValue::Str(e.tag.clone()));
    obj.set("profile", JsonValue::Str(e.profile.clone()));
    obj.set("browser", JsonValue::Str(e.browser.clone()));
    let interval = if e.interval_set && e.interval_ns > 0 {
        format_duration(e.interval_ns)
    } else {
        String::new()
    };
    obj.set("interval", JsonValue::Str(interval));
    obj.set(
        "interval_seconds",
        JsonValue::Number((e.effective_interval_ns() / 1_000_000_000).to_string()),
    );
    obj.set("notify", JsonValue::Str(e.notify.clone()));
    JsonValue::Object(obj)
}

/// GET /settings/keeper. Response map (sorted keys):
/// `{entries, sha256}`.
pub fn handle_get_keeper_settings(config_dir: &Path, load: &ConfigLoad) -> Result<Resp, ApiError> {
    let (_, entries) = parse_loaded(load, config_dir)?;
    let entries: Vec<JsonValue> = entries.iter().map(keeper_settings_entry_json).collect();
    let mut map = OrderedObject::new();
    map.set("entries", JsonValue::Array(entries));
    map.set("sha256", JsonValue::Str(load.hash.clone()));
    Ok(envelope_resp(200, JsonValue::Object(map)))
}

struct PutKeeperEntry {
    tag: String,
    profile: String,
    browser: String,
    interval: Option<String>,
    notify: Option<String>,
}

/// PUT /settings/keeper (1 MiB cap). `entries` is
/// required (missing → 400); `null` deletes the block;
/// an array replaces it (entries built in canonical key
/// order tag, profile, browser, interval, notify).
/// Response `{sha256}`. The [`SaveOutcome`] rides along
/// so the caller can refresh the live Bearer comparator
/// from the saved document (Go's `refreshTokenHash` in
/// `saveGuarded`); the keeper editor never changes the
/// token, but the funnel reports it uniformly.
pub fn handle_put_keeper_settings(
    config_dir: &Path,
    load: &ConfigLoad,
    body: &[u8],
) -> Result<(Resp, SaveOutcome), ApiError> {
    let (entries_raw, base_sha) = crate::server::decode_body_typed(
        body,
        crate::server::BODY_CAP_1M,
        &["entries", "base_sha256"],
        |obj| {
            let base_sha = match obj.get("base_sha256") {
                None | Some(JsonValue::Null) => String::new(),
                Some(JsonValue::Str(s)) => s.clone(),
                Some(_) => {
                    return Err(err_validation("invalid JSON in request body"));
                }
            };
            let entries_raw = obj.get("entries").cloned();
            Ok((entries_raw, base_sha))
        },
    )?;
    let Some(entries_raw) = entries_raw else {
        return Err(err_validation("entries is required"));
    };
    if base_sha.trim().is_empty() {
        return Err(err_validation("base_sha256 is required"));
    }
    let delete_block = matches!(entries_raw, JsonValue::Null);
    let mut submitted: Vec<JsonValue> = Vec::new();
    if !delete_block {
        let JsonValue::Array(arr) = &entries_raw else {
            return Err(err_validation("entries must be an array of keeper entries"));
        };
        for elem in arr {
            submitted.push(parse_put_keeper_entry(elem)?);
        }
    }
    let outcome = save_merged(load, config_dir, &base_sha, move |doc| {
        let JsonValue::Object(doc_obj) = doc else {
            return Err(err_validation("config document must be a JSON object"));
        };
        if delete_block {
            doc_obj.remove("keeper");
        } else {
            doc_obj.set("keeper", JsonValue::Array(submitted));
        }
        Ok(())
    })?;
    let mut map = OrderedObject::new();
    map.set("sha256", JsonValue::Str(outcome.sha256.clone()));
    Ok((envelope_resp(200, JsonValue::Object(map)), outcome))
}

fn parse_put_keeper_entry(elem: &JsonValue) -> Result<JsonValue, ApiError> {
    let err = || err_validation("entries must be an array of keeper entries");
    let JsonValue::Object(obj) = elem else {
        return Err(err());
    };
    for key in obj.keys() {
        if !matches!(
            key.as_str(),
            "tag" | "profile" | "browser" | "interval" | "notify"
        ) {
            return Err(err());
        }
    }
    let get_str = |key: &str| -> Result<String, ApiError> {
        match obj.get(key) {
            None | Some(JsonValue::Null) => Ok(String::new()),
            Some(JsonValue::Str(s)) => Ok(s.clone()),
            Some(_) => Err(err()),
        }
    };
    let get_opt_str = |key: &str| -> Result<Option<String>, ApiError> {
        match obj.get(key) {
            None | Some(JsonValue::Null) => Ok(None),
            Some(JsonValue::Str(s)) => Ok(Some(s.clone())),
            Some(_) => Err(err()),
        }
    };
    let entry = PutKeeperEntry {
        tag: get_str("tag")?,
        profile: get_str("profile")?,
        browser: get_str("browser")?,
        interval: get_opt_str("interval")?,
        notify: get_opt_str("notify")?,
    };
    // Canonical key order tag, profile, browser, interval,
    // notify, rendered via OrderedObject: a plain map
    // would re-encode with sorted keys for entries the
    // stored document does not already carry.
    let mut out = OrderedObject::new();
    out.set("tag", JsonValue::Str(entry.tag));
    out.set("profile", JsonValue::Str(entry.profile));
    out.set("browser", JsonValue::Str(entry.browser));
    if let Some(interval) = entry.interval
        && !interval.trim().is_empty()
    {
        // Stored VERBATIM (not trimmed), as Go does.
        out.set("interval", JsonValue::Str(interval));
    }
    if let Some(notify) = entry.notify
        && !notify.is_empty()
    {
        out.set("notify", JsonValue::Str(notify));
    }
    Ok(JsonValue::Object(out))
}

// --- webui settings -------------------------------------------

/// GET /settings/webui. The view fields are FLAT in
/// `data` alongside sha256 (struct order, NOT sorted):
/// listen, ui_dir, token_set, masked,
/// session_idle_timeout, session_idle_timeout_seconds,
/// login_rate_limit{attempts, window, window_seconds},
/// sha256. Duration and limit values are the EFFECTIVE
/// values (defaults applied). Note `listen` is "" when
/// no block exists (the effective default applies only
/// when a block is present).
pub fn handle_get_webui_settings(config_dir: &Path, load: &ConfigLoad) -> Result<Resp, ApiError> {
    let (cfg, _) = parse_loaded(load, config_dir)?;
    let mut listen = String::new();
    let mut ui_dir = String::new();
    let mut token_set = false;
    let mut masked = String::new();
    let mut idle_ns = DEFAULT_SESSION_IDLE_TIMEOUT_NS;
    let mut attempts = DEFAULT_LOGIN_RATE_LIMIT_ATTEMPTS;
    let mut window_ns = DEFAULT_LOGIN_RATE_LIMIT_WINDOW_NS;
    if let Some(raw) = &cfg.webui_raw
        && let Ok(Some(block)) = resolve_webui(Some(raw))
    {
        listen = effective_listen(&block);
        ui_dir = block.ui_dir.clone();
        token_set = !block.token.is_empty();
        if token_set {
            masked = "***".to_string();
        }
        idle_ns = effective_session_idle_timeout_ns(&block);
        let (a, w) = effective_login_rate_limit(&block);
        attempts = a;
        window_ns = w;
    }
    let mut limit = OrderedObject::new();
    limit.set("attempts", JsonValue::Number(attempts.to_string()));
    limit.set("window", JsonValue::Str(format_duration(window_ns)));
    limit.set(
        "window_seconds",
        JsonValue::Number((window_ns / 1_000_000_000).to_string()),
    );
    let mut map = OrderedObject::new();
    map.set("listen", JsonValue::Str(listen));
    map.set("ui_dir", JsonValue::Str(ui_dir));
    map.set("token_set", JsonValue::Bool(token_set));
    map.set("masked", JsonValue::Str(masked));
    map.set(
        "session_idle_timeout",
        JsonValue::Str(format_duration(idle_ns)),
    );
    map.set(
        "session_idle_timeout_seconds",
        JsonValue::Number((idle_ns / 1_000_000_000).to_string()),
    );
    map.set("login_rate_limit", JsonValue::Object(limit));
    map.set("sha256", JsonValue::Str(load.hash.clone()));
    Ok(envelope_resp(200, JsonValue::Object(map)))
}

struct PutWebUISettings {
    listen: Option<String>,
    token: Option<String>,
    ui_dir: Option<String>,
    session_idle_timeout: Option<String>,
    /// None = absent (unchanged); Some(None) = null (delete);
    /// Some(Some((attempts, window))) = object merge.
    login_rate_limit: Option<Option<(Option<i64>, Option<String>)>>,
    base_sha256: String,
}

/// PUT /settings/webui (64 KiB cap). Response `{sha256}`.
/// Returns the [`SaveOutcome`] alongside the response so
/// the caller can refresh the live Bearer comparator
/// from the saved document (Go's `refreshTokenHash` in
/// `saveGuarded`) — including token-clear semantics.
pub fn handle_put_webui_settings(
    config_dir: &Path,
    load: &ConfigLoad,
    body: &[u8],
) -> Result<(Resp, SaveOutcome), ApiError> {
    let put = crate::server::decode_body_typed(
        body,
        crate::server::BODY_CAP_64K,
        &[
            "listen",
            "token",
            "ui_dir",
            "session_idle_timeout",
            "login_rate_limit",
            "base_sha256",
        ],
        |obj| {
            let get_opt = |key: &str| -> Result<Option<String>, ApiError> {
                match obj.get(key) {
                    None | Some(JsonValue::Null) => Ok(None),
                    Some(JsonValue::Str(s)) => Ok(Some(s.clone())),
                    Some(_) => Err(err_validation("invalid JSON in request body")),
                }
            };
            let base_sha = match obj.get("base_sha256") {
                None | Some(JsonValue::Null) => String::new(),
                Some(JsonValue::Str(s)) => s.clone(),
                Some(_) => {
                    return Err(err_validation("invalid JSON in request body"));
                }
            };
            // login_rate_limit: absent → unchanged; null →
            // delete; object → per-field merge. Unknown
            // nested keys are rejected.
            let login_rate_limit = match obj.get("login_rate_limit") {
                None => None,
                Some(JsonValue::Null) => Some(None),
                Some(JsonValue::Object(nested)) => {
                    for key in nested.keys() {
                        if !matches!(key.as_str(), "attempts" | "window") {
                            return Err(err_validation("login_rate_limit must be an object"));
                        }
                    }
                    let attempts = match nested.get("attempts") {
                        None | Some(JsonValue::Null) => None,
                        Some(JsonValue::Number(n)) => {
                            let v: i64 = n
                                .parse()
                                .map_err(|_| err_validation("invalid JSON in request body"))?;
                            Some(v)
                        }
                        Some(_) => {
                            return Err(err_validation("invalid JSON in request body"));
                        }
                    };
                    let window = match nested.get("window") {
                        None | Some(JsonValue::Null) => None,
                        Some(JsonValue::Str(s)) => Some(s.clone()),
                        Some(_) => {
                            return Err(err_validation("invalid JSON in request body"));
                        }
                    };
                    Some(Some((attempts, window)))
                }
                Some(_) => {
                    return Err(err_validation("login_rate_limit must be an object"));
                }
            };
            Ok(PutWebUISettings {
                listen: get_opt("listen")?,
                token: get_opt("token")?,
                ui_dir: get_opt("ui_dir")?,
                session_idle_timeout: get_opt("session_idle_timeout")?,
                login_rate_limit,
                base_sha256: base_sha,
            })
        },
    )?;
    if put.base_sha256.trim().is_empty() {
        return Err(err_validation("base_sha256 is required"));
    }
    let outcome = save_merged(load, config_dir, &put.base_sha256, move |doc| {
        let JsonValue::Object(doc_obj) = doc else {
            return Err(err_validation("config document must be a JSON object"));
        };
        let mut section = match doc_obj.get("webui") {
            Some(JsonValue::Object(o)) => o.clone(),
            _ => OrderedObject::new(),
        };
        if let Some(listen) = &put.listen {
            // Empty restores the default by deleting the
            // key: a present-but-empty listen is a parse
            // error.
            if listen.trim().is_empty() {
                section.remove("listen");
            } else {
                section.set("listen", JsonValue::Str(listen.trim().to_string()));
            }
        }
        if let Some(token) = &put.token {
            // Empty token = unchanged (write-only field).
            // A non-empty token replaces the stored one; a
            // placeholder is never a token. Whitespace
            // anywhere is rejected, matching parse.
            if !token.trim().is_empty() {
                if token == "***" || token == REDACTED_MARKER {
                    return Err(err_validation(
                        "webui.token must be a real token, not a placeholder",
                    ));
                }
                if token.contains([' ', '\t', '\r', '\n']) {
                    return Err(err_validation("webui.token must not contain whitespace"));
                }
                section.set("token", JsonValue::Str(token.clone()));
            }
        }
        if let Some(ui_dir) = &put.ui_dir {
            if ui_dir.trim().is_empty() {
                section.remove("ui_dir");
            } else {
                section.set("ui_dir", JsonValue::Str(ui_dir.trim().to_string()));
            }
        }
        if let Some(idle) = &put.session_idle_timeout {
            if idle.trim().is_empty() {
                section.remove("session_idle_timeout");
            } else {
                // Enforced here, not only by the
                // full-document parse in saveMerged:
                // sub-floor values are rejected with a
                // fixed message, never silently clamped.
                // Stored VERBATIM (untrimmed): a value
                // with surrounding whitespace fails the
                // full re-parse, as in Go.
                let d = parse_duration(idle.trim()).map_err(|_| {
                    err_validation("session_idle_timeout must be a duration string from 1m to 720h")
                })?;
                if !(MIN_SESSION_IDLE_TIMEOUT_NS..=MAX_SESSION_IDLE_TIMEOUT_NS).contains(&d) {
                    return Err(err_validation(
                        "session_idle_timeout must be a duration string from 1m to 720h",
                    ));
                }
                section.set("session_idle_timeout", JsonValue::Str(idle.clone()));
            }
        }
        match &put.login_rate_limit {
            Some(None) => {
                section.remove("login_rate_limit");
            }
            Some(Some((attempts, window))) => {
                let mut nested = match section.get("login_rate_limit") {
                    Some(JsonValue::Object(o)) => o.clone(),
                    _ => OrderedObject::new(),
                };
                if let Some(a) = attempts {
                    if *a < 1 || *a > MAX_LOGIN_RATE_LIMIT_ATTEMPTS {
                        return Err(err_validation(format!(
                            "login_rate_limit.attempts must be an integer from 1 to {}",
                            MAX_LOGIN_RATE_LIMIT_ATTEMPTS
                        )));
                    }
                    nested.set("attempts", JsonValue::Number(a.to_string()));
                }
                if let Some(w) = window {
                    if w.trim().is_empty() {
                        return Err(err_validation("login_rate_limit.window must not be empty"));
                    }
                    let d = parse_duration(w.trim()).map_err(|_| {
                        err_validation(
                            "login_rate_limit.window must be a duration string from 1s to 24h",
                        )
                    })?;
                    if !(MIN_LOGIN_RATE_LIMIT_WINDOW_NS..=MAX_LOGIN_RATE_LIMIT_WINDOW_NS)
                        .contains(&d)
                    {
                        return Err(err_validation(
                            "login_rate_limit.window must be a duration string from 1s to 24h",
                        ));
                    }
                    nested.set("window", JsonValue::Str(w.clone()));
                }
                section.set("login_rate_limit", JsonValue::Object(nested));
            }
            None => {}
        }
        doc_obj.set("webui", JsonValue::Object(section));
        Ok(())
    })?;
    let mut map = OrderedObject::new();
    map.set("sha256", JsonValue::Str(outcome.sha256.clone()));
    Ok((envelope_resp(200, JsonValue::Object(map)), outcome))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guarded::ConfigState;
    use std::fs;

    fn test_load(dir: &Path, raw: &[u8]) -> ConfigLoad {
        ConfigLoad {
            raw: raw.to_vec(),
            hash: crate::guarded::sha256_hex(raw),
            state: ConfigState {
                found: true,
                exists: true,
                sha256: crate::guarded::sha256_hex(raw),
                raw: raw.to_vec(),
                base_dir: dir.to_path_buf(),
            },
        }
    }

    fn write_config(dir: &Path, raw: &[u8]) {
        fs::create_dir_all(dir).unwrap();
        fs::write(dir.join("config.json"), raw).unwrap();
    }

    #[test]
    fn get_webui_settings_defaults() {
        let dir = std::env::temp_dir().join(format!("m6b-sec-webui-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        write_config(&dir, b"{\"profiles\":{}}");
        let load = test_load(&dir, b"{\"profiles\":{}}");
        let resp = handle_get_webui_settings(&dir, &load).unwrap();
        let body = String::from_utf8(resp.body).unwrap();
        // No block: listen "" (not the effective default),
        // idle 12h, limit 5/5m.
        assert!(body.contains("\"listen\":\"\""));
        assert!(body.contains("\"session_idle_timeout\":\"12h0m0s\""));
        assert!(body.contains("\"session_idle_timeout_seconds\":43200"));
        assert!(body.contains("\"attempts\":5"));
        assert!(body.contains("\"window\":\"5m0s\""));
        assert!(body.contains("\"token_set\":false"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn put_webui_settings_idle_timeout() {
        let dir = std::env::temp_dir().join(format!("m6b-sec-put-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let raw = b"{\"profiles\":{},\"webui\": {\"token\": \"t0\"}}";
        write_config(&dir, raw);
        let load = test_load(&dir, raw);
        let hash = crate::guarded::sha256_hex(raw);
        let body = format!(
            "{{\"session_idle_timeout\": \"13h\", \"base_sha256\": \"{}\"}}",
            hash
        );
        let (resp, _) = handle_put_webui_settings(&dir, &load, body.as_bytes()).unwrap();
        assert_eq!(resp.status, 200);
        let saved = fs::read_to_string(dir.join("config.json")).unwrap();
        assert!(saved.contains("\"session_idle_timeout\": \"13h\""));
        // Hash-on-save: the plaintext token is replaced by a
        // bcrypt hash, never persisted verbatim.
        assert!(!saved.contains("\"token\": \"t0\""));
        assert!(saved.contains("$2b$10$"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn put_keeper_settings_null_deletes_block() {
        let dir = std::env::temp_dir().join(format!("m6b-sec-keeper-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let raw = b"{\"profiles\":{\"muse01\":{}},\"keeper\": [{\"tag\": \"k1\", \"profile\": \"muse01\", \"browser\": \"http://127.0.0.1:9222\"}]}";
        write_config(&dir, raw);
        let load = test_load(&dir, raw);
        let hash = crate::guarded::sha256_hex(raw);
        let body = format!("{{\"entries\": null, \"base_sha256\": \"{}\"}}", hash);
        let (resp, _) = handle_put_keeper_settings(&dir, &load, body.as_bytes()).unwrap();
        assert_eq!(resp.status, 200);
        let saved = fs::read_to_string(dir.join("config.json")).unwrap();
        assert!(!saved.contains("\"keeper\""), "{saved}");
        let _ = fs::remove_dir_all(&dir);
    }
}
