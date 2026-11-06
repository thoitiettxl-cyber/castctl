// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! `ResolveLogSettings`: the effective log settings for one
//! invocation. Port of Go `internal/profile/log.go:150-195`
//! (`ResolveLogSettings`, `validLogLevel`).
//!
//! The castctl gate (Boss decision 2026-10-30): when the
//! config has NO log block AND no `--log-level` flag was
//! given, logging is OFF (`disabled: true`) — stderr carries
//! only the typed JSON error. A present block — INCLUDING an
//! empty `{}` block — follows sing-box defaults exactly, and
//! `--log-level` with no block turns logging ON at that level
//! (output stderr). Presence is the `Option` (`None` vs
//! `Some`); parse preserves it (`castctl-config::LogConfig`).
//! Precedence is CLI > config block > sing-box default. No
//! resolved value is ever echoed in an error.

use castctl_config::errors::{config_error, ConfigError};
use castctl_config::log::{valid_log_level, LogConfig};

/// Re-export under the Go name for callers that think in
/// `profile` terms.
pub fn valid_log_level(s: &str) -> bool {
    valid_log_level(s)
}

/// `ResolveLogSettings` (`log.go:167`): `single_log` is the
/// parsed top-level `log` block (`None` = absent);
/// `cli_level` is honoured only when `cli_set` is true. A
/// set-but-empty CLI level is an error (an empty level must
/// never mean "no filtering"). A CLI flag turns logging ON
/// when no block exists, but never clears a present block's
/// `disabled: true`. A `"warning"` level (CLI or config)
/// normalises to `"warn"`. Errors are `ConfigError` with exit
/// code 2, exactly like Go's `newConfigError`.
pub fn resolve_log_settings(
    single_log: Option<&LogConfig>,
    cli_level: &str,
    cli_set: bool,
) -> Result<LogConfig, ConfigError> {
    let block_present = single_log.is_some();
    let mut out = if let Some(block) = single_log {
        let mut c = block.clone();
        if c.level.is_empty() {
            c.level = "trace".to_string();
        }
        c
    } else {
        LogConfig {
            disabled: true,
            level: "trace".to_string(),
            ..Default::default()
        }
    };
    if cli_set {
        if cli_level.is_empty() || !valid_log_level(cli_level) {
            return Err(config_error("invalid --log-level value"));
        }
        out.level = cli_level.to_string();
        if !block_present {
            out.disabled = false;
        }
    }
    if out.level == "warning" {
        out.level = "warn".to_string();
    }
    if !valid_log_level(&out.level) {
        return Err(config_error(
            "unknown log level (expected trace, debug, info, warn, warning, error, fatal, or panic)",
        ));
    }
    if out.output.trim().is_empty() {
        out.output = String::new();
    }
    Ok(out)
}
