// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Typed `webui` block (`internal/profile/webui.go`:
//! `parseWebUIBlock`, `validateWebUIListen`,
//! `parseLoginRateLimitBlock`, `ResolveWebUI`,
//! `EffectiveListen`, `EffectiveSessionIdleTimeout`,
//! `EffectiveLoginRateLimit`, `encodeWebUIBlock`).
//!
//! The parse is authoritative in `castctl-config`
//! (`castctl_config::webui`): `parse_single_config` runs it
//! at load time, so this crate delegates to it and converts
//! the result into its own `WebUIConfig` type field by
//! field. All error messages carry Go's `profile: ` prefix
//! (`internal/profile/errors.go` `newConfigError`), because
//! they surface verbatim in `stored config is invalid: ...`
//! responses and in CLI exit-2 messages. Error texts name
//! the rule only, never the supplied value (the value sits
//! next to a secret in the same block).
//!
//! Exactly five keys: `listen`, `token`, `ui_dir`,
//! `session_idle_timeout`, `login_rate_limit`. Unknown keys
//! are rejected. Durations are nanosecond counts (`i64`);
//! see [`crate::duration`].

use crate::duration::{HOUR_NS, MINUTE_NS, SECOND_NS, format_duration};
use castctl_config::jsonvalue::JsonValue;
use std::path::Path;

/// Default listen when a `webui` block is present without a
/// `listen` key: loopback only, port 8317.
pub const DEFAULT_LISTEN: &str = "127.0.0.1:8317";

/// Default frontend idle-expiry cadence: 12h.
pub const DEFAULT_SESSION_IDLE_TIMEOUT_NS: i64 = 12 * HOUR_NS;
/// Floor for a configured idle timeout: 1m.
pub const MIN_SESSION_IDLE_TIMEOUT_NS: i64 = MINUTE_NS;
/// Cap for a configured idle timeout: 30d = 720h.
pub const MAX_SESSION_IDLE_TIMEOUT_NS: i64 = 720 * HOUR_NS;

/// Default failed-verification allowance: 5 attempts.
pub const DEFAULT_LOGIN_RATE_LIMIT_ATTEMPTS: i64 = 5;
/// Default rate-limit window: 5m.
pub const DEFAULT_LOGIN_RATE_LIMIT_WINDOW_NS: i64 = 5 * MINUTE_NS;
/// Cap for configured attempts: 100.
pub const MAX_LOGIN_RATE_LIMIT_ATTEMPTS: i64 = 100;
/// Floor for a configured window: 1s.
pub const MIN_LOGIN_RATE_LIMIT_WINDOW_NS: i64 = SECOND_NS;
/// Cap for a configured window: 24h.
pub const MAX_LOGIN_RATE_LIMIT_WINDOW_NS: i64 = 24 * HOUR_NS;

/// Typed `login_rate_limit` block. Both fields optional;
/// `*_set` records presence (Go's `AttemptsSet` /
/// `WindowSet`).
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
/// Delegates to the config crate (the parse-time authority);
/// the rule text is returned unchanged.
pub fn validate_listen(raw: &str) -> Result<(), String> {
    castctl_config::webui::validate_listen(raw)
}

/// Parse one `login_rate_limit` object
/// (`parseLoginRateLimitBlock`). Delegates to the config
/// crate and converts the result field by field.
pub fn parse_login_rate_limit_block(value: &JsonValue) -> Result<LoginRateLimitConfig, String> {
    castctl_config::webui::parse_login_rate_limit_block(value)
        .map(|rl| LoginRateLimitConfig {
            attempts: rl.attempts,
            attempts_set: rl.attempts_set,
            window_ns: rl.window_ns,
            window_set: rl.window_set,
        })
        .map_err(|e| e.message)
}

/// Parse a `webui` block value (`parseWebUIBlock`).
/// `base_dir` is the config directory, for the lexical
/// `ui_dir` overlap check (skipped when empty, mirroring
/// Go's `baseDir != ""` guard). Delegates to the config
/// crate and converts the result field by field.
pub fn parse_webui_block(value: &JsonValue, base_dir: &Path) -> Result<WebUIConfig, String> {
    castctl_config::webui::parse_webui_block(value, &base_dir.to_string_lossy())
        .map(|cfg| WebUIConfig {
            listen: cfg.listen,
            token: cfg.token,
            ui_dir: cfg.ui_dir,
            session_idle_timeout_ns: cfg.session_idle_timeout_ns,
            session_idle_timeout_set: cfg.session_idle_timeout_set,
            login_rate_limit: cfg.login_rate_limit.map(|rl| LoginRateLimitConfig {
                attempts: rl.attempts,
                attempts_set: rl.attempts_set,
                window_ns: rl.window_ns,
                window_set: rl.window_set,
            }),
        })
        .map_err(|e| e.message)
}

/// `ResolveWebUI`: re-check a parsed block (or a
/// hand-built one) without the config directory: listen,
/// token, duration and limit rules, but NOT the `ui_dir`
/// overlap rule (the command layer enforces it
/// canonically). Returns `None` when the block is absent.
pub fn resolve_webui(value: Option<&JsonValue>) -> Result<Option<WebUIConfig>, String> {
    let Some(value) = value else {
        return Ok(None);
    };
    let cfg = parse_webui_block(value, Path::new(""))?;
    Ok(Some(cfg))
}

/// `EffectiveListen`: the block's `listen` when set,
/// otherwise `127.0.0.1:8317`.
pub fn effective_listen(cfg: &WebUIConfig) -> String {
    if cfg.listen.trim().is_empty() {
        DEFAULT_LISTEN.to_string()
    } else {
        cfg.listen.trim().to_string()
    }
}

/// `EffectiveSessionIdleTimeout` in nanoseconds (12h default).
pub fn effective_session_idle_timeout_ns(cfg: &WebUIConfig) -> i64 {
    if cfg.session_idle_timeout_set && cfg.session_idle_timeout_ns > 0 {
        cfg.session_idle_timeout_ns
    } else {
        DEFAULT_SESSION_IDLE_TIMEOUT_NS
    }
}

/// `EffectiveLoginRateLimit`: per-field defaults (5 / 5m).
pub fn effective_login_rate_limit(cfg: &WebUIConfig) -> (i64, i64) {
    let mut attempts = DEFAULT_LOGIN_RATE_LIMIT_ATTEMPTS;
    let mut window = DEFAULT_LOGIN_RATE_LIMIT_WINDOW_NS;
    if let Some(rl) = &cfg.login_rate_limit {
        if rl.attempts_set && rl.attempts > 0 {
            attempts = rl.attempts;
        }
        if rl.window_set && rl.window_ns > 0 {
            window = rl.window_ns;
        }
    }
    (attempts, window)
}

/// `encodeWebUIBlock`: canonical key order (listen, token,
/// ui_dir, session_idle_timeout, login_rate_limit), only the
/// keys that were set; durations as Go duration strings.
pub fn encode_webui_block(cfg: &WebUIConfig) -> JsonValue {
    let mut out = castctl_config::jsonvalue::OrderedObject::new();
    if !cfg.listen.trim().is_empty() {
        out.set(
            "listen".to_string(),
            JsonValue::Str(cfg.listen.trim().to_string()),
        );
    }
    if !cfg.token.is_empty() {
        out.set("token".to_string(), JsonValue::Str(cfg.token.clone()));
    }
    if !cfg.ui_dir.trim().is_empty() {
        out.set(
            "ui_dir".to_string(),
            JsonValue::Str(cfg.ui_dir.trim().to_string()),
        );
    }
    if cfg.session_idle_timeout_set && cfg.session_idle_timeout_ns > 0 {
        out.set(
            "session_idle_timeout".to_string(),
            JsonValue::Str(format_duration(cfg.session_idle_timeout_ns)),
        );
    }
    if let Some(rl) = &cfg.login_rate_limit {
        let mut nested = castctl_config::jsonvalue::OrderedObject::new();
        if rl.attempts_set && rl.attempts > 0 {
            nested.set(
                "attempts".to_string(),
                JsonValue::Number(rl.attempts.to_string()),
            );
        }
        if rl.window_set && rl.window_ns > 0 {
            nested.set(
                "window".to_string(),
                JsonValue::Str(format_duration(rl.window_ns)),
            );
        }
        out.set("login_rate_limit".to_string(), JsonValue::Object(nested));
    }
    JsonValue::Object(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use castctl_config::jsonvalue::decode_ordered_json;

    fn block(json: &str) -> JsonValue {
        decode_ordered_json(json.as_bytes()).unwrap()
    }

    #[test]
    fn parse_full_block() {
        let cfg = parse_webui_block(
            &block(r#"{"listen":"127.0.0.1:8317","token":"abc","ui_dir":"/ui","session_idle_timeout":"13h","login_rate_limit":{"attempts":100,"window":"5m"}}"#),
            Path::new("/cfg"),
        )
        .unwrap();
        assert_eq!(cfg.listen, "127.0.0.1:8317");
        assert_eq!(cfg.token, "abc");
        assert_eq!(cfg.ui_dir, "/ui");
        assert_eq!(cfg.session_idle_timeout_ns, 13 * HOUR_NS);
        assert_eq!(effective_session_idle_timeout_ns(&cfg), 13 * HOUR_NS);
        let (a, w) = effective_login_rate_limit(&cfg);
        assert_eq!((a, w), (100, 5 * MINUTE_NS));
        assert_eq!(effective_listen(&cfg), "127.0.0.1:8317");
    }

    #[test]
    fn defaults_apply_per_field() {
        let cfg = parse_webui_block(&block(r#"{"token":"abc"}"#), Path::new("/cfg")).unwrap();
        assert_eq!(effective_listen(&cfg), DEFAULT_LISTEN);
        assert_eq!(effective_session_idle_timeout_ns(&cfg), 12 * HOUR_NS);
        let (a, w) = effective_login_rate_limit(&cfg);
        assert_eq!((a, w), (5, 5 * MINUTE_NS));
    }

    #[test]
    fn listen_rules() {
        assert!(validate_listen("127.0.0.1:8317").is_ok());
        assert!(validate_listen("localhost:8317").is_ok());
        assert!(validate_listen("[::1]:8317").is_ok());
        assert!(validate_listen("127.0.0.2:1").is_ok());
        assert_eq!(
            validate_listen("0.0.0.0:8317").unwrap_err(),
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
            validate_listen("127.0.0.1:65536").unwrap_err(),
            "port out of range"
        );
        assert_eq!(
            validate_listen("example.com:8317").unwrap_err(),
            "host must be loopback"
        );
        assert_eq!(
            validate_listen("user@127.0.0.1:8317").unwrap_err(),
            "must not carry userinfo, a path, a query, or a fragment"
        );
    }

    #[test]
    fn ui_dir_overlap_rejected_at_parse() {
        let err = parse_webui_block(&block(r#"{"token":"abc","ui_dir":"."}"#), Path::new("/cfg"))
            .unwrap_err();
        assert!(err.contains("must not overlap"), "{err}");
        let err2 = parse_webui_block(
            &block(r#"{"token":"abc","ui_dir":"../cfg"}"#),
            Path::new("/cfg"),
        )
        .unwrap_err();
        assert!(err2.contains("must not overlap"), "{err2}");
    }

    #[test]
    fn duration_bounds() {
        let err = parse_webui_block(
            &block(r#"{"token":"abc","session_idle_timeout":"30s"}"#),
            Path::new("/cfg"),
        )
        .unwrap_err();
        assert!(err.contains("from 1m0s to 720h0m0s"), "{err}");
        let err2 = parse_webui_block(
            &block(r#"{"token":"abc","login_rate_limit":{"window":"12h"}}"#),
            Path::new("/cfg"),
        );
        // 12h is within 1s..24h: parses fine.
        assert!(err2.is_ok());
        let err3 = parse_webui_block(
            &block(r#"{"token":"abc","login_rate_limit":{"window":"25h"}}"#),
            Path::new("/cfg"),
        )
        .unwrap_err();
        assert!(err3.contains("from 1s to 24h0m0s"), "{err3}");
    }

    #[test]
    fn unknown_keys_rejected() {
        let err = parse_webui_block(&block(r#"{"token":"abc","bogus":1}"#), Path::new("/cfg"))
            .unwrap_err();
        assert!(err.contains("unknown webui config key"), "{err}");
        let err2 = parse_webui_block(
            &block(r#"{"token":"abc","login_rate_limit":{"bogus":1}}"#),
            Path::new("/cfg"),
        )
        .unwrap_err();
        assert!(
            err2.contains("unknown webui.login_rate_limit config key"),
            "{err2}"
        );
    }

    #[test]
    fn encode_round_trips_canonical_order() {
        let cfg = parse_webui_block(
            &block(r#"{"token":"abc","listen":"127.0.0.1:8317","session_idle_timeout":"13h"}"#),
            Path::new("/cfg"),
        )
        .unwrap();
        let encoded = encode_webui_block(&cfg);
        let text = castctl_config::jsonvalue::encode_ordered_json(&encoded).unwrap();
        assert_eq!(
            text,
            r#"{"listen":"127.0.0.1:8317","token":"abc","session_idle_timeout":"13h0m0s"}"#
        );
    }

    #[test]
    fn fail_before_listen_loopback() {
        // If the loopback rule were dropped, 0.0.0.0 would
        // parse and the server would bind publicly: pinned.
        assert!(validate_listen("0.0.0.0:8317").is_err());
        assert!(validate_listen(":: :8317").is_err());
    }
}
