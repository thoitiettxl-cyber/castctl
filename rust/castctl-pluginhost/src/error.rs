// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! One error type for the plugin host: messages are fixed
//! constants (or verbatim Go validation strings), never
//! shadow paths, secrets, or plugin-chosen server bodies.
//! Follows the `castctl-telegram/src/error.rs:28-60`
//! `BotError` pattern.

use std::fmt;

/// The plugin host's single error type.
/// No direct Go type counterpart: Go returns plain `error`
/// values; Rust groups the call sites so the loader
/// limitation is typed, not a string match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PluginHostError {
    /// Validation refusal: registration, discovery, or
    /// checksum rules. The message is the verbatim Go
    /// validation string (it may quote a plugin-declared
    /// hostname, never a path or secret).
    Invalid(String),
    /// The dlopen loader is unavailable (STOPPED scope —
    /// see `loader.rs`). The message names the limit and
    /// the Option A delegation, never a path.
    LoaderUnavailable,
    /// Any other operational failure. The message is a
    /// fixed constant, never a path, secret, or server body.
    Failed(String),
}

impl PluginHostError {
    /// Build a validation error from a fixed message.
    #[must_use]
    pub fn invalid(msg: impl Into<String>) -> Self {
        PluginHostError::Invalid(msg.into())
    }

    /// Build an operational error from a fixed message.
    #[must_use]
    pub fn failed(msg: impl Into<String>) -> Self {
        PluginHostError::Failed(msg.into())
    }
}

impl fmt::Display for PluginHostError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PluginHostError::Invalid(m) | PluginHostError::Failed(m) => {
                write!(f, "{m}")
            }
            PluginHostError::LoaderUnavailable => write!(
                f,
                "plugin loading requires the Go binary (Option A: keep the Go binary as plugin host, Rust delegates plugin check)"
            ),
        }
    }
}

impl std::error::Error for PluginHostError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_never_leaks_paths() {
        assert_eq!(
            PluginHostError::LoaderUnavailable.to_string(),
            "plugin loading requires the Go binary (Option A: keep the Go binary as plugin host, Rust delegates plugin check)"
        );
        assert_eq!(
            PluginHostError::invalid("plugin metadata name is required").to_string(),
            "plugin metadata name is required"
        );
    }
}
