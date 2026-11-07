// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! The top-level `webui` config block (`internal/profile/webui.go`:
//! `parseWebUIBlock`, `validateWebUIListen`,
//! `parseLoginRateLimitBlock`, `DirOverlaps`).
//!
//! This is the parse-time authority for the block: `parse_single_config`
//! runs it, so a block that breaks a rule (unknown key, listen not
//! loopback, token empty, duration or limit floor, `ui_dir` overlap)
//! fails EVERY command with exit 2 — not only `webui serve`. The
//! `castctl-webui` crate delegates its `parse_webui_block` /
//! `validate_listen` / `parse_login_rate_limit_block` here, converting
//! the result into its own `WebUIConfig` type field by field.
//!
//! Exactly five keys: `listen`, `token`, `ui_dir`,
//! `session_idle_timeout`, `login_rate_limit`. Unknown keys are
//! rejected. Durations are nanosecond counts (`i64`); error texts
//! name the rule only, never the supplied value (the value sits next
//! to a secret in the same block).
//!
//! One deliberate fix over the old `castctl-webui` copy:
//! `validate_listen` uses `ip.to_canonical().is_loopback()` — Go's
//! `net.ParseIP(...).IsLoopback()` converts an IPv4-mapped IPv6
//! address (`::ffff:127.0.0.1`) to 127.0.0.1 first, while Rust's
//! `IpAddr::is_loopback()` is false for the mapped form.

use crate::errors::{ConfigError, config_error};
use crate::gopath::{go_clean, go_is_abs, go_join, go_rel};
use crate::gostr::go_quote;
use crate::jsonvalue::JsonValue;
use crate::keeper::{format_go_duration, parse_go_duration};

/// Default listen when a `webui` block is present without a
/// `listen` key: loopback only, port 8317.
pub const DEFAULT_LISTEN: &str = "127.0.0.1:8317";

/// Default frontend idle-expiry cadence: 12h.
pub const DEFAULT_SESSION_IDLE_TIMEOUT_NS: i64 = 12 * 3_600_000_000_000;
/// Floor for a configured idle timeout: 1m.
pub const MIN_SESSION_IDLE_TIMEOUT_NS: i64 = 60_000_000_000;
/// Cap for a configured idle timeout: 30d = 720h.
pub const MAX_SESSION_IDLE_TIMEOUT_NS: i64 = 720 * 3_600_000_000_000;

/// Default failed-verification allowance: 5 attempts.
pub const DEFAULT_LOGIN_RATE_LIMIT_ATTEMPTS: i64 = 5;
/// Default rate-limit window: 5m.
pub const DEFAULT_LOGIN_RATE_LIMIT_WINDOW_NS: i64 = 5 * 60_000_000_000;
/// Cap for configured attempts: 100.
pub const MAX_LOGIN_RATE_LIMIT_ATTEMPTS: i64 = 100;
/// Floor for a configured window: 1s.
pub const MIN_LOGIN_RATE_LIMIT_WINDOW_NS: i64 = 1_000_000_000;
/// Cap for a configured window: 24h.
pub const MAX_LOGIN_RATE_LIMIT_WINDOW_NS: i64 = 24 * 3_600_000_000_000;

/// Typed `login_rate_limit` block. Both fields optional;
/// `*_set` records presence (Go's `AttemptsSet` / `WindowSet`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LoginRateLimitConfig {
    pub attempts: i64,
    pub attempts_set: bool,
    pub window_ns: i64,
    pub window_set: bool,
}

/// Typed `webui` block (`internal/profile/webui.go`
/// `WebUIConfig`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WebUIConfig {
    /// `listen` value, trimmed ("" when absent).
    pub listen: String,
    /// Stored `token` verbatim: plaintext or a bcrypt hash.
    /// Never logged or echoed.
    pub token: String,
    /// `ui_dir` value, trimmed ("" when absent).
    pub ui_dir: String,
    /// `session_idle_timeout` in nanoseconds.
    pub session_idle_timeout_ns: i64,
    pub session_idle_timeout_set: bool,
    /// `login_rate_limit` block, when present.
    pub login_rate_limit: Option<LoginRateLimitConfig>,
}

/// `validateWebUIListen`: the loopback-only listen rule.
/// The value must be a bare host:port — not a URL, carrying
/// no userinfo, query, or fragment — with a loopback host
/// and an explicit port 1–65535. Returns the rule violated
/// (never the supplied value).
pub fn validate_listen(raw: &str) -> Result<(), String> {
    let s = raw.trim();
    if s.contains("://") {
        return Err("must be a host:port, not a URL".to_string());
    }
    let (host, port_str) = split_host_port(s)
        .ok_or_else(|| "must be a host:port with an explicit port".to_string())?;
    if host.contains(['@', '/', '?', '#']) {
        return Err("must not carry userinfo, a path, a query, or a fragment".to_string());
    }
    // Go `strconv.Atoi`: any non-decimal (empty, `+5`, ` 5`,
    // `0x10`) or out-of-range value is the same error.
    let port: i64 = match port_str.parse() {
        Ok(p) => p,
        Err(_) => return Err("port out of range".to_string()),
    };
    if !(1..=65535).contains(&port) {
        return Err("port out of range".to_string());
    }
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        // Go `ip.IsLoopback()` converts an IPv4-mapped IPv6
        // address to its IPv4 form first (`::ffff:127.0.0.1`
        // is loopback); `to_canonical` does the same.
        if !ip.to_canonical().is_loopback() {
            return Err("host must be loopback".to_string());
        }
        return Ok(());
    }
    if !host.eq_ignore_ascii_case("localhost") {
        return Err("host must be loopback".to_string());
    }
    Ok(())
}

/// Go `net.SplitHostPort` (host, port) or `None` on error:
/// missing port, too many colons, unbalanced brackets.
fn split_host_port(s: &str) -> Option<(&str, &str)> {
    if let Some(bracketed) = s.strip_prefix('[') {
        let close = bracketed.find(']')?;
        let host = &bracketed[..close];
        let rest = &bracketed[close + 1..];
        let port = rest.strip_prefix(':')?;
        if port.contains(':') {
            return None;
        }
        return Some((host, port));
    }
    let (host, port) = s.split_once(':')?;
    if port.contains(':') {
        return None;
    }
    Some((host, port))
}

/// `DirOverlaps` (`webui.go:350`): whether candidate is equal
/// to, inside, or an ancestor of dir. Both paths are absolutized
/// against the working directory first; an unresolvable Rel or
/// absolutization fails closed (overlap).
pub fn dir_overlaps(dir: &str, candidate: &str) -> bool {
    let Some(dir_abs) = go_abs(dir) else {
        return true;
    };
    let Some(candidate_abs) = go_abs(candidate) else {
        return true;
    };
    let Some(rel) = go_rel(&dir_abs, &candidate_abs) else {
        return true;
    };
    if rel == "." {
        return true;
    }
    let parts: Vec<&str> = rel.split('/').collect();
    if parts[0] != ".." {
        return true;
    }
    parts.iter().all(|p| *p == "..")
}

/// Go `filepath.Abs`: the path made absolute against the
/// working directory, then cleaned. `None` when the working
/// directory cannot be read (Go's error → fail closed).
fn go_abs(path: &str) -> Option<String> {
    if go_is_abs(path) {
        return Some(go_clean(path));
    }
    let cwd = std::env::current_dir().ok()?;
    let cwd = cwd.to_str()?;
    Some(go_clean(&go_join(&[cwd, path])))
}

/// Parse one `login_rate_limit` object
/// (`parseLoginRateLimitBlock`). Unknown nested keys are
/// rejected; wrong types and out-of-bound values are config
/// errors (never echoing the supplied value).
pub fn parse_login_rate_limit_block(
    value: &JsonValue,
) -> Result<LoginRateLimitConfig, ConfigError> {
    let JsonValue::Object(obj) = value else {
        return Err(config_error("\"webui.login_rate_limit\" must be an object"));
    };
    let mut rl = LoginRateLimitConfig::default();
    for (k, val) in obj.iter() {
        match k.as_str() {
            "attempts" => {
                // Go `json.Number.Int64()`: a float or exponent
                // literal fails → the range message.
                let JsonValue::Number(lit) = val else {
                    return Err(config_error(
                        "\"webui.login_rate_limit.attempts\" must be an integer",
                    ));
                };
                let attempts: i64 = lit.parse().map_err(|_| {
                    config_error(format!(
                        "\"webui.login_rate_limit.attempts\" must be an integer from 1 to {MAX_LOGIN_RATE_LIMIT_ATTEMPTS}"
                    ))
                })?;
                if !(1..=MAX_LOGIN_RATE_LIMIT_ATTEMPTS).contains(&attempts) {
                    return Err(config_error(format!(
                        "\"webui.login_rate_limit.attempts\" must be an integer from 1 to {MAX_LOGIN_RATE_LIMIT_ATTEMPTS}"
                    )));
                }
                rl.attempts = attempts;
                rl.attempts_set = true;
            }
            "window" => {
                let JsonValue::Str(s) = val else {
                    return Err(config_error(
                        "\"webui.login_rate_limit.window\" must be a duration string",
                    ));
                };
                if s.trim().is_empty() {
                    return Err(config_error(
                        "\"webui.login_rate_limit.window\" must not be empty",
                    ));
                }
                let d = parse_go_duration(s).map_err(|_| {
                    config_error(format!(
                        "\"webui.login_rate_limit.window\" must be a duration string from {} to {}",
                        format_go_duration(MIN_LOGIN_RATE_LIMIT_WINDOW_NS),
                        format_go_duration(MAX_LOGIN_RATE_LIMIT_WINDOW_NS)
                    ))
                })?;
                if !(MIN_LOGIN_RATE_LIMIT_WINDOW_NS..=MAX_LOGIN_RATE_LIMIT_WINDOW_NS).contains(&d) {
                    return Err(config_error(format!(
                        "\"webui.login_rate_limit.window\" must be a duration string from {} to {}",
                        format_go_duration(MIN_LOGIN_RATE_LIMIT_WINDOW_NS),
                        format_go_duration(MAX_LOGIN_RATE_LIMIT_WINDOW_NS)
                    )));
                }
                rl.window_ns = d;
                rl.window_set = true;
            }
            _ => {
                return Err(config_error(format!(
                    "unknown webui.login_rate_limit config key {}",
                    go_quote(k)
                )));
            }
        }
    }
    Ok(rl)
}

/// Parse a `webui` block value (`parseWebUIBlock`).
/// `base_dir` is the config directory, for the lexical
/// `ui_dir` overlap check (skipped when empty, mirroring
/// Go's `baseDir != ""` guard).
pub fn parse_webui_block(value: &JsonValue, base_dir: &str) -> Result<WebUIConfig, ConfigError> {
    let JsonValue::Object(obj) = value else {
        return Err(config_error("\"webui\" must be an object"));
    };
    let mut cfg = WebUIConfig::default();
    for (k, val) in obj.iter() {
        match k.as_str() {
            "listen" => {
                let JsonValue::Str(s) = val else {
                    return Err(config_error("\"webui.listen\" must be a string"));
                };
                if s.trim().is_empty() {
                    return Err(config_error("\"webui.listen\" must not be empty"));
                }
                validate_listen(s)
                    .map_err(|rule| config_error(format!("\"webui.listen\" {rule}")))?;
                cfg.listen = s.trim().to_string();
            }
            "token" => {
                let JsonValue::Str(s) = val else {
                    return Err(config_error("\"webui.token\" must be a string"));
                };
                if s.trim().is_empty() {
                    return Err(config_error("\"webui.token\" must not be empty"));
                }
                if s.contains([' ', '\t', '\r', '\n']) {
                    return Err(config_error("\"webui.token\" must not contain whitespace"));
                }
                cfg.token = s.clone();
            }
            "ui_dir" => {
                let JsonValue::Str(s) = val else {
                    return Err(config_error("\"webui.ui_dir\" must be a string"));
                };
                if s.trim().is_empty() {
                    return Err(config_error("\"webui.ui_dir\" must not be empty"));
                }
                cfg.ui_dir = s.trim().to_string();
            }
            "session_idle_timeout" => {
                let JsonValue::Str(s) = val else {
                    return Err(config_error(
                        "\"webui.session_idle_timeout\" must be a duration string",
                    ));
                };
                if s.trim().is_empty() {
                    return Err(config_error(
                        "\"webui.session_idle_timeout\" must not be empty",
                    ));
                }
                let d = parse_go_duration(s).map_err(|_| {
                    config_error(format!(
                        "\"webui.session_idle_timeout\" must be a duration string from {} to {}",
                        format_go_duration(MIN_SESSION_IDLE_TIMEOUT_NS),
                        format_go_duration(MAX_SESSION_IDLE_TIMEOUT_NS)
                    ))
                })?;
                if !(MIN_SESSION_IDLE_TIMEOUT_NS..=MAX_SESSION_IDLE_TIMEOUT_NS).contains(&d) {
                    return Err(config_error(format!(
                        "\"webui.session_idle_timeout\" must be a duration string from {} to {}",
                        format_go_duration(MIN_SESSION_IDLE_TIMEOUT_NS),
                        format_go_duration(MAX_SESSION_IDLE_TIMEOUT_NS)
                    )));
                }
                cfg.session_idle_timeout_ns = d;
                cfg.session_idle_timeout_set = true;
            }
            "login_rate_limit" => {
                cfg.login_rate_limit = Some(parse_login_rate_limit_block(val)?);
            }
            _ => {
                return Err(config_error(format!(
                    "unknown webui config key {}",
                    go_quote(k)
                )));
            }
        }
    }
    if !cfg.ui_dir.is_empty() && !base_dir.is_empty() {
        let resolved = if go_is_abs(&cfg.ui_dir) {
            cfg.ui_dir.clone()
        } else {
            go_join(&[base_dir, &cfg.ui_dir])
        };
        if dir_overlaps(base_dir, &resolved) {
            return Err(config_error(
                "\"webui.ui_dir\" must not overlap the config directory",
            ));
        }
    }
    Ok(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jsonvalue::decode_ordered_json;

    fn block(json: &str) -> JsonValue {
        decode_ordered_json(json.as_bytes()).unwrap()
    }

    fn err(json: &str, base_dir: &str) -> String {
        parse_webui_block(&block(json), base_dir)
            .unwrap_err()
            .message
    }

    #[test]
    fn listen_loopback_rules() {
        // Go `net.ParseIP(...).IsLoopback()`: an IPv4-mapped
        // IPv6 loopback IS loopback; Rust's bare
        // `is_loopback()` says otherwise — `to_canonical`
        // closes the gap.
        assert!(validate_listen("[::ffff:127.0.0.1]:8317").is_ok());
        assert!(validate_listen("[::1]:8317").is_ok());
        assert!(validate_listen("127.0.0.1:8317").is_ok());
        assert!(validate_listen("localhost:8317").is_ok());
        assert_eq!(
            validate_listen("0.0.0.0:8317").unwrap_err(),
            "host must be loopback"
        );
        assert_eq!(
            validate_listen("[::ffff:8.8.8.8]:8317").unwrap_err(),
            "host must be loopback"
        );
        assert_eq!(
            validate_listen("example.com:8317").unwrap_err(),
            "host must be loopback"
        );
        assert_eq!(
            validate_listen("http://127.0.0.1:8317").unwrap_err(),
            "must be a host:port, not a URL"
        );
        assert_eq!(
            validate_listen("127.0.0.1").unwrap_err(),
            "must be a host:port with an explicit port"
        );
        assert_eq!(
            validate_listen("127.0.0.1:0").unwrap_err(),
            "port out of range"
        );
        assert_eq!(
            validate_listen("127.0.0.1:70000").unwrap_err(),
            "port out of range"
        );
    }

    #[test]
    fn block_rules() {
        assert_eq!(
            err(r#"{"listen":"0.0.0.0:8317"}"#, "/tmp"),
            "profile: \"webui.listen\" host must be loopback"
        );
        assert_eq!(
            err(r#"{"token":""}"#, "/tmp"),
            "profile: \"webui.token\" must not be empty"
        );
        assert_eq!(
            err(r#"{"token":"a b"}"#, "/tmp"),
            "profile: \"webui.token\" must not contain whitespace"
        );
        assert_eq!(
            err(r#"{"bogus":1}"#, "/tmp"),
            "profile: unknown webui config key \"bogus\""
        );
        assert_eq!(
            err(r#"{"session_idle_timeout":"30s"}"#, "/tmp"),
            "profile: \"webui.session_idle_timeout\" must be a duration string from 1m0s to 720h0m0s"
        );
        assert_eq!(
            err(r#"{"login_rate_limit":{"attempts":0}}"#, "/tmp"),
            "profile: \"webui.login_rate_limit.attempts\" must be an integer from 1 to 100"
        );
        assert_eq!(
            err(r#"{"login_rate_limit":{"attempts":1.5}}"#, "/tmp"),
            "profile: \"webui.login_rate_limit.attempts\" must be an integer from 1 to 100"
        );
        assert_eq!(
            err(r#"{"login_rate_limit":{"window":"500ms"}}"#, "/tmp"),
            "profile: \"webui.login_rate_limit.window\" must be a duration string from 1s to 24h0m0s"
        );
        assert_eq!(
            err(r#"{"login_rate_limit":{"bogus":1}}"#, "/tmp"),
            "profile: unknown webui.login_rate_limit config key \"bogus\""
        );
        assert_eq!(
            err(r#"{"ui_dir":"/tmp"}"#, "/tmp"),
            "profile: \"webui.ui_dir\" must not overlap the config directory"
        );
        // A sibling subtree does not overlap.
        assert!(parse_webui_block(&block(r#"{"ui_dir":"/other"}"#), "/tmp").is_ok());
        // A relative ui_dir resolves against the config dir.
        assert_eq!(
            err(r#"{"ui_dir":"sub"}"#, "/tmp"),
            "profile: \"webui.ui_dir\" must not overlap the config directory"
        );
        assert!(parse_webui_block(&block(r#"{"ui_dir":"../other"}"#), "/tmp/cfg").is_ok());
    }
}
