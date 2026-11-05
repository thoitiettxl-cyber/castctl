//! The top-level `log` config block: exactly four keys, strict.
//!
//! Source: `internal/profile/log.go` at base `dev-rust` `85a8d5e`
//! (`parseLogBlock`, `ValidLogLevel`, `validLogLevel`). Resolution
//! (`ResolveLogSettings`) is runtime behaviour, deferred; only the
//! parse-time shape and the level vocabulary are ported here.

use crate::errors::{ConfigError, config_error};
use crate::gostr::go_quote;
use crate::jsonvalue::{JsonValue, OrderedObject};

/// Accepted level spellings, including sing-box's `warning` alias.
/// Case-sensitive; `""` is not accepted in a config block.
///
/// Source: `internal/profile/log.go` (`logLevels`, `validLogLevel`).
pub const LOG_LEVELS: [&str; 8] = [
    "trace", "debug", "info", "warn", "warning", "error", "fatal", "panic",
];

/// `ValidLogLevel` (`log.go`): whether `s` is an accepted
/// `--log-level` / config log level spelling.
pub fn valid_log_level(s: &str) -> bool {
    LOG_LEVELS.contains(&s)
}

/// One parsed `log` block. A missing block is `None` on
/// `SingleConfig`; presence (including `{}`) is preserved.
///
/// Source: `internal/profile/log.go` (`LogConfig`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LogConfig {
    /// `disabled` (default false).
    pub disabled: bool,
    /// `level` (default `""` = sing-box trace default at runtime).
    pub level: String,
    /// `output` (default `""` = stderr at runtime).
    pub output: String,
    /// `timestamp` (default false).
    pub timestamp: bool,
}

/// `parseLogBlock` (`log.go:101`): wrong shapes, wrong types,
/// unknown keys, and unknown/empty levels are config errors. The
/// supplied level value is never echoed.
pub fn parse_log_block(value: &JsonValue) -> Result<LogConfig, ConfigError> {
    let obj = match value {
        JsonValue::Object(obj) => obj,
        _ => return Err(config_error("\"log\" must be an object")),
    };
    let mut cfg = LogConfig::default();
    for (k, val) in obj.iter() {
        match k.as_str() {
            "disabled" => match val {
                JsonValue::Bool(b) => cfg.disabled = *b,
                _ => return Err(config_error("\"log.disabled\" must be a boolean")),
            },
            "level" => match val {
                JsonValue::Str(s) => {
                    if s.is_empty() || !valid_log_level(s) {
                        return Err(config_error(
                            "unknown log level (expected trace, debug, info, warn, warning, error, fatal, or panic)",
                        ));
                    }
                    cfg.level = s.clone();
                }
                _ => return Err(config_error("\"log.level\" must be a string")),
            },
            "output" => match val {
                JsonValue::Str(s) => cfg.output = s.clone(),
                _ => return Err(config_error("\"log.output\" must be a string")),
            },
            "timestamp" => match val {
                JsonValue::Bool(b) => cfg.timestamp = *b,
                _ => return Err(config_error("\"log.timestamp\" must be a boolean")),
            },
            _ => {
                return Err(config_error(format!(
                    "unknown log config key {}",
                    go_quote(k)
                )));
            }
        }
    }
    Ok(cfg)
}

/// Render a parsed `log` block in canonical within-block order
/// (`disabled`, `level`, `output`, `timestamp`), the synthesized
/// branch of `buildSingleFileOrdered` (`config.go`).
pub fn render_log_block(cfg: &LogConfig) -> OrderedObject {
    let mut entry = OrderedObject::new();
    entry.set("disabled".to_string(), JsonValue::Bool(cfg.disabled));
    entry.set("level".to_string(), JsonValue::Str(cfg.level.clone()));
    entry.set("output".to_string(), JsonValue::Str(cfg.output.clone()));
    entry.set("timestamp".to_string(), JsonValue::Bool(cfg.timestamp));
    entry
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jsonvalue::decode_ordered_json;

    fn parse(input: &str) -> Result<LogConfig, ConfigError> {
        parse_log_block(&decode_ordered_json(input.as_bytes()).unwrap())
    }

    #[test]
    fn test_parse_log_block_valid() {
        let cfg = parse(
            "{\"disabled\":true,\"level\":\"warn\",\"output\":\"stdout\",\"timestamp\":true}",
        )
        .unwrap();
        assert_eq!(
            cfg,
            LogConfig {
                disabled: true,
                level: "warn".to_string(),
                output: "stdout".to_string(),
                timestamp: true,
            }
        );
        // Empty block is valid (presence matters, defaults are runtime-only).
        assert_eq!(parse("{}").unwrap(), LogConfig::default());
    }

    #[test]
    fn test_parse_log_block_errors() {
        assert_eq!(
            parse("[]").unwrap_err().message,
            "profile: \"log\" must be an object"
        );
        assert_eq!(
            parse("{\"level\":\"\"}").unwrap_err().message,
            "profile: unknown log level (expected trace, debug, info, warn, warning, error, fatal, or panic)"
        );
        assert_eq!(
            parse("{\"level\":\"WARN\"}").unwrap_err().message,
            "profile: unknown log level (expected trace, debug, info, warn, warning, error, fatal, or panic)"
        );
        assert_eq!(
            parse("{\"level\":\"secret-value\"}").unwrap_err().message,
            "profile: unknown log level (expected trace, debug, info, warn, warning, error, fatal, or panic)"
        );
        assert_eq!(
            parse("{\"bogus\":1}").unwrap_err().message,
            "profile: unknown log config key \"bogus\""
        );
        assert_eq!(
            parse("{\"disabled\":1}").unwrap_err().message,
            "profile: \"log.disabled\" must be a boolean"
        );
    }

    #[test]
    fn test_valid_log_level_set() {
        for level in LOG_LEVELS {
            assert!(valid_log_level(level));
        }
        assert!(!valid_log_level(""));
        assert!(!valid_log_level("Warn"));
    }
}
