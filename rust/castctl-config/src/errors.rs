// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Typed config errors carrying an exit code, mirroring Go's
//! `profile.Error`.
//!
//! Source: `internal/profile/errors.go` at base `dev-rust` `85a8d5e`.
//! This package only produces code 2 (plus 0 for no error, via
//! `exit_code`); the CLI layer maps other codes for other error
//! families. The `Debug` impl prints only the message: messages
//! never carry secret values by construction (see PORTING.md §M2),
//! and no `Debug` output of a config value is ever produced.

/// Error kinds, mirroring the Go sentinel `Kind` strings
/// (`internal/profile/errors.go:126-143`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    /// `invalid_profile` (`ErrInvalidProfile`).
    InvalidProfile,
    /// `config_parse` (`ErrConfigParse`).
    ConfigParse,
    /// `auth` (`ErrAuth`).
    Auth,
    /// `refuse_overwrite` (`ErrRefuseOverwrite`, migrate-only; unused in M2).
    RefuseOverwrite,
    /// `concurrent_change` (`ErrConcurrentChange`, guard-only; unused in M2).
    ConcurrentChange,
    /// `legacy_layout` (`ErrLegacyLayout`).
    LegacyLayout,
}

impl ErrorKind {
    /// The Go `Kind` string.
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorKind::InvalidProfile => "invalid_profile",
            ErrorKind::ConfigParse => "config_parse",
            ErrorKind::Auth => "auth",
            ErrorKind::RefuseOverwrite => "refuse_overwrite",
            ErrorKind::ConcurrentChange => "concurrent_change",
            ErrorKind::LegacyLayout => "legacy_layout",
        }
    }
}

/// A typed config error: exit code, kind, and message.
///
/// Source: `internal/profile/errors.go:108` (`Error` struct). `Error()`
/// returns the message; `ExitCode()` returns the code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError {
    /// Process exit code (always 2 for this type).
    pub code: i32,
    /// Error kind (Go sentinel kind).
    pub kind: ErrorKind,
    /// The message (`Error()` in Go).
    pub message: String,
}

impl ConfigError {
    /// The process exit code for this error (Go `ExitCode`, `errors.go:122`).
    pub fn exit_code(&self) -> i32 {
        self.code
    }
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ConfigError {}

/// `newConfigError` (`internal/profile/errors.go:156`): prefix the
/// message with `profile: ` once, kind `config_parse`, code 2.
pub fn config_error(msg: impl Into<String>) -> ConfigError {
    ConfigError {
        code: 2,
        kind: ErrorKind::ConfigParse,
        message: format!("profile: {}", msg.into()),
    }
}

/// `newConfigErrorf` (`internal/profile/errors.go:160`): formatted
/// `newConfigError`.
#[macro_export]
macro_rules! config_errorf {
    ($fmt:literal $(, $arg:expr)*) => {
        $crate::errors::config_error(format!($fmt $(, $arg)*))
    };
}

/// `newInvalidProfileError` (`internal/profile/errors.go:163`):
/// truncate names longer than 64 runes to 64 runes + `…`, kind
/// `invalid_profile`, code 2.
pub fn invalid_profile_error(name: &str) -> ConfigError {
    let shown: String = if name.chars().count() > 64 {
        let mut s: String = name.chars().take(64).collect();
        s.push('…');
        s
    } else {
        name.to_string()
    };
    ConfigError {
        code: 2,
        kind: ErrorKind::InvalidProfile,
        message: format!(
            "profile: invalid profile name {}: use 1-64 letters, digits, '.', '-' or '_' (not starting or ending with '.')",
            crate::gostr::go_quote(&shown)
        ),
    }
}

/// `newLegacyLayoutError` (`internal/profile/errors.go:185`): names
/// the legacy file path only, never contents.
pub fn legacy_layout_error(legacy_path: &str) -> ConfigError {
    ConfigError {
        code: 2,
        kind: ErrorKind::LegacyLayout,
        message: format!(
            "profile: legacy layout found at {}; run `castctl config migrate --write` first",
            crate::gostr::go_quote(legacy_path)
        ),
    }
}

/// `newRefuseError` (`internal/profile/errors.go:176`, migrate-only).
/// Kept for API completeness; M2 never produces it.
pub fn refuse_error(msg: impl Into<String>) -> ConfigError {
    ConfigError {
        code: 2,
        kind: ErrorKind::RefuseOverwrite,
        message: format!("profile: {}", msg.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_error_prefix_once() {
        let e = config_error("x");
        assert_eq!(e.message, "profile: x");
        assert_eq!(e.exit_code(), 2);
        assert_eq!(e.kind, ErrorKind::ConfigParse);
    }

    #[test]
    fn test_invalid_profile_truncation() {
        let long = "a".repeat(70);
        let e = invalid_profile_error(&long);
        assert!(e.message.contains(&"a".repeat(64)));
        assert!(e.message.contains('…'));
        assert_eq!(e.kind, ErrorKind::InvalidProfile);
    }

    #[test]
    fn test_legacy_layout_error_names_path_only() {
        let e = legacy_layout_error("/cfg/profiles/x/config.json");
        assert_eq!(
            e.message,
            "profile: legacy layout found at \"/cfg/profiles/x/config.json\"; run `castctl config migrate --write` first"
        );
    }
}
