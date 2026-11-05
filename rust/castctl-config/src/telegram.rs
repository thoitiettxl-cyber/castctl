//! The top-level `telegram` config block: exactly six keys, strict.
//!
//! Source: `internal/profile/telegram.go` at base `dev-rust`
//! `85a8d5e` (`parseTelegramBlock`, `validateTelegram`,
//! `ResolveTelegram`, `validTelegramTokenShape`). The token is never
//! echoed in an error; fixture tokens in tests are invented
//! shape-only values, never real credentials.

use crate::errors::{ConfigError, config_error};
use crate::gostr::{go_parse_int64, go_quote, go_trim_space};
use crate::jsonvalue::JsonValue;

/// One parsed `telegram` block. `None` on `SingleConfig` means the
/// block was absent (bot off).
///
/// Source: `internal/profile/telegram.go` (`TelegramConfig`).
///
/// `Debug` is hand-written (M1 F5 precedent): the token renders as
/// `[redacted]` and is never printed by `{:?}`.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct TelegramConfig {
    /// Linked profile name (required).
    pub profile: String,
    /// Bot token, stored stripped (required). Never echoed.
    pub token: String,
    /// Allowlist (required, non-empty).
    pub allowed_user_ids: Vec<i64>,
    /// `auto_approve` (default false).
    pub auto_approve: bool,
    /// `auto_allow_once` (default false).
    pub auto_allow_once: bool,
    /// Owner-only gate id.
    pub owner_id: i64,
    /// Whether `owner_id` was present (0 is not a valid owner).
    pub owner_id_set: bool,
}

impl std::fmt::Debug for TelegramConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TelegramConfig")
            .field("profile", &self.profile)
            .field("token", &"[redacted]")
            .field("allowed_user_ids", &self.allowed_user_ids)
            .field("auto_approve", &self.auto_approve)
            .field("auto_allow_once", &self.auto_allow_once)
            .field("owner_id", &self.owner_id)
            .field("owner_id_set", &self.owner_id_set)
            .finish()
    }
}

/// `validTelegramTokenShape` (`telegram.go:116`): Python's shape,
/// `^[0-9]+:[A-Za-z0-9_-]{20,}$` fullmatch on the stripped value,
/// ASCII digits only.
pub fn valid_telegram_token_shape(token: &str) -> bool {
    let Some((digits, rest)) = token.split_once(':') else {
        return false;
    };
    !digits.is_empty()
        && digits.bytes().all(|b| b.is_ascii_digit())
        && rest.len() >= 20
        && rest
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// `parseTelegramBlock` (`telegram.go:127`): keys are scanned in
/// file order, the first error wins; missing-key checks run after
/// the loop in `profile` → `token` → `allowed_user_ids` order.
pub fn parse_telegram_block(value: &JsonValue) -> Result<TelegramConfig, ConfigError> {
    let obj = match value {
        JsonValue::Object(obj) => obj,
        _ => return Err(config_error("\"telegram\" must be an object")),
    };
    let mut cfg = TelegramConfig::default();
    let mut profile_set = false;
    let mut token_set = false;
    let mut allowlist_set = false;
    for (k, val) in obj.iter() {
        match k.as_str() {
            "profile" => match val {
                JsonValue::Str(s) => {
                    if go_trim_space(s).is_empty() {
                        return Err(config_error("\"telegram.profile\" must not be empty"));
                    }
                    cfg.profile = s.clone();
                    profile_set = true;
                }
                _ => return Err(config_error("\"telegram.profile\" must be a string")),
            },
            "token" => match val {
                JsonValue::Str(s) => {
                    let stripped = go_trim_space(s);
                    if !valid_telegram_token_shape(stripped) {
                        return Err(config_error(
                            "\"telegram.token\" does not look like a bot token (expected digits, a colon, then 20 or more token characters)",
                        ));
                    }
                    cfg.token = stripped.to_string();
                    token_set = true;
                }
                _ => return Err(config_error("\"telegram.token\" must be a string")),
            },
            "allowed_user_ids" => match val {
                JsonValue::Array(arr) => {
                    if arr.is_empty() {
                        return Err(config_error(
                            "\"telegram.allowed_user_ids\" must not be empty: the bot refuses to start without an allowlist",
                        ));
                    }
                    let mut ids = Vec::with_capacity(arr.len());
                    for elem in arr {
                        let n = match elem {
                            JsonValue::Number(n) => n,
                            _ => {
                                return Err(config_error(
                                    "\"telegram.allowed_user_ids\" must contain integers only",
                                ));
                            }
                        };
                        let id = match go_parse_int64(n) {
                            Ok(id) => id,
                            Err(_) => {
                                return Err(config_error(
                                    "\"telegram.allowed_user_ids\" must contain integers only",
                                ));
                            }
                        };
                        if id <= 0 {
                            return Err(config_error(
                                "\"telegram.allowed_user_ids\" must contain positive user ids only",
                            ));
                        }
                        ids.push(id);
                    }
                    cfg.allowed_user_ids = ids;
                    allowlist_set = true;
                }
                _ => {
                    return Err(config_error(
                        "\"telegram.allowed_user_ids\" must be an array of user ids",
                    ));
                }
            },
            "auto_approve" => match val {
                JsonValue::Bool(b) => cfg.auto_approve = *b,
                _ => return Err(config_error("\"telegram.auto_approve\" must be a boolean")),
            },
            "auto_allow_once" => match val {
                JsonValue::Bool(b) => cfg.auto_allow_once = *b,
                _ => {
                    return Err(config_error(
                        "\"telegram.auto_allow_once\" must be a boolean",
                    ));
                }
            },
            "owner_id" => match val {
                JsonValue::Number(n) => {
                    let id = match go_parse_int64(n) {
                        Ok(id) => id,
                        Err(_) => {
                            return Err(config_error("\"telegram.owner_id\" must be an integer"));
                        }
                    };
                    if id <= 0 {
                        return Err(config_error(
                            "\"telegram.owner_id\" must be a positive user id",
                        ));
                    }
                    cfg.owner_id = id;
                    cfg.owner_id_set = true;
                }
                _ => {
                    return Err(config_error("\"telegram.owner_id\" must be an integer"));
                }
            },
            _ => {
                return Err(config_error(format!(
                    "unknown telegram config key {}",
                    go_quote(k)
                )));
            }
        }
    }
    if !profile_set {
        return Err(config_error(
            "\"telegram\" requires a \"profile\" key naming a profile in \"profiles\"",
        ));
    }
    if !token_set {
        return Err(config_error("\"telegram\" requires a \"token\" key"));
    }
    if !allowlist_set {
        return Err(config_error(
            "\"telegram\" requires a non-empty \"allowed_user_ids\" key",
        ));
    }
    Ok(cfg)
}

/// `validateTelegram` (`telegram.go:232`): the linked profile must
/// exist, and the shape invariants are re-checked defensively.
pub fn validate_telegram(
    cfg: &TelegramConfig,
    profile_exists: impl Fn(&str) -> bool,
) -> Result<(), ConfigError> {
    if !profile_exists(&cfg.profile) {
        return Err(crate::config_errorf!(
            "telegram: profile {} does not exist",
            go_quote(&cfg.profile)
        ));
    }
    if !valid_telegram_token_shape(&cfg.token) {
        return Err(config_error(
            "\"telegram.token\" does not look like a bot token (expected digits, a colon, then 20 or more token characters)",
        ));
    }
    if cfg.allowed_user_ids.is_empty() {
        return Err(config_error(
            "\"telegram.allowed_user_ids\" must not be empty: the bot refuses to start without an allowlist",
        ));
    }
    for id in &cfg.allowed_user_ids {
        if *id <= 0 {
            return Err(config_error(
                "\"telegram.allowed_user_ids\" must contain positive user ids only",
            ));
        }
    }
    if cfg.owner_id_set && cfg.owner_id <= 0 {
        return Err(config_error(
            "\"telegram.owner_id\" must be a positive user id",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jsonvalue::decode_ordered_json;

    /// Invented shape-only token for fixtures (never a real
    /// credential): digits, colon, 20+ token characters.
    const FAKE_TOKEN: &str = "123456789:ABCDEFGHIJKLMNOPQRST";

    fn parse(input: &str) -> Result<TelegramConfig, ConfigError> {
        parse_telegram_block(&decode_ordered_json(input.as_bytes()).unwrap())
    }

    fn valid_json() -> String {
        format!(
            "{{\"profile\":\"default\",\"token\":\"{FAKE_TOKEN}\",\"allowed_user_ids\":[111,222]}}"
        )
    }

    #[test]
    fn test_parse_telegram_valid() {
        let cfg = parse(&valid_json()).unwrap();
        assert_eq!(cfg.profile, "default");
        assert_eq!(cfg.token, FAKE_TOKEN);
        assert_eq!(cfg.allowed_user_ids, vec![111, 222]);
        assert!(!cfg.owner_id_set);
    }

    #[test]
    fn test_parse_telegram_token_stripped() {
        let cfg = parse(&format!(
            "{{\"profile\":\"default\",\"token\":\"  {FAKE_TOKEN}  \",\"allowed_user_ids\":[1]}}"
        ))
        .unwrap();
        assert_eq!(cfg.token, FAKE_TOKEN);
    }

    #[test]
    fn test_parse_telegram_owner_id() {
        let cfg = parse(&format!(
            "{{\"profile\":\"default\",\"token\":\"{FAKE_TOKEN}\",\"allowed_user_ids\":[1],\"owner_id\":999}}"
        ))
        .unwrap();
        assert!(cfg.owner_id_set);
        assert_eq!(cfg.owner_id, 999);
    }

    #[test]
    fn test_parse_telegram_errors() {
        assert_eq!(
            parse("[]").unwrap_err().message,
            "profile: \"telegram\" must be an object"
        );
        assert_eq!(
            parse(&format!(
                "{{\"token\":\"{FAKE_TOKEN}\",\"allowed_user_ids\":[1]}}"
            ))
            .unwrap_err()
            .message,
            "profile: \"telegram\" requires a \"profile\" key naming a profile in \"profiles\""
        );
        assert_eq!(
            parse("{\"profile\":\"default\",\"allowed_user_ids\":[1]}")
                .unwrap_err()
                .message,
            "profile: \"telegram\" requires a \"token\" key"
        );
        assert_eq!(
            parse(&format!(
                "{{\"profile\":\"default\",\"token\":\"{FAKE_TOKEN}\"}}"
            ))
            .unwrap_err()
            .message,
            "profile: \"telegram\" requires a non-empty \"allowed_user_ids\" key"
        );
        assert_eq!(
            parse("{\"profile\":\"default\",\"token\":\"short\",\"allowed_user_ids\":[1]}")
                .unwrap_err()
                .message,
            "profile: \"telegram.token\" does not look like a bot token (expected digits, a colon, then 20 or more token characters)"
        );
        assert_eq!(
            parse(&format!(
                "{{\"profile\":\"default\",\"token\":\"{FAKE_TOKEN}\",\"allowed_user_ids\":[]}}"
            ))
            .unwrap_err()
            .message,
            "profile: \"telegram.allowed_user_ids\" must not be empty: the bot refuses to start without an allowlist"
        );
        assert_eq!(
            parse(&format!(
                "{{\"profile\":\"default\",\"token\":\"{FAKE_TOKEN}\",\"allowed_user_ids\":[1.5]}}"
            ))
            .unwrap_err()
            .message,
            "profile: \"telegram.allowed_user_ids\" must contain integers only"
        );
        assert_eq!(
            parse(&format!(
                "{{\"profile\":\"default\",\"token\":\"{FAKE_TOKEN}\",\"allowed_user_ids\":[0]}}"
            ))
            .unwrap_err()
            .message,
            "profile: \"telegram.allowed_user_ids\" must contain positive user ids only"
        );
        assert_eq!(
            parse(&format!(
                "{{\"profile\":\"default\",\"token\":\"{FAKE_TOKEN}\",\"allowed_user_ids\":[1],\"owner_id\":0}}"
            ))
            .unwrap_err()
            .message,
            "profile: \"telegram.owner_id\" must be a positive user id"
        );
        assert_eq!(
            parse(&format!(
                "{{\"profile\":\"default\",\"token\":\"{FAKE_TOKEN}\",\"allowed_user_ids\":[1],\"bogus\":1}}"
            ))
            .unwrap_err()
            .message,
            "profile: unknown telegram config key \"bogus\""
        );
        // File order wins: the unknown key before the missing-key check.
        assert_eq!(
            parse("{\"bogus\":1}").unwrap_err().message,
            "profile: unknown telegram config key \"bogus\""
        );
    }

    #[test]
    fn test_token_shape_ascii_only() {
        assert!(!valid_telegram_token_shape("١٢٣:ABCDEFGHIJKLMNOPQRST"));
        assert!(valid_telegram_token_shape(FAKE_TOKEN));
        assert!(!valid_telegram_token_shape("123:short"));
        assert!(!valid_telegram_token_shape(
            "123456789:ABCDEFGHIJKLMNOPQRS "
        ));
    }

    #[test]
    fn test_validate_telegram_dangling_profile() {
        let cfg = parse(&valid_json()).unwrap();
        let err = validate_telegram(&cfg, |_| false).unwrap_err();
        assert_eq!(
            err.message,
            "profile: telegram: profile \"default\" does not exist"
        );
        assert!(validate_telegram(&cfg, |_| true).is_ok());
    }

    #[test]
    fn test_debug_never_prints_token() {
        let cfg = parse(&valid_json()).unwrap();
        let rendered = format!("{cfg:?}");
        assert!(!rendered.contains(FAKE_TOKEN));
        assert!(rendered.contains("[redacted]"));
    }
}
