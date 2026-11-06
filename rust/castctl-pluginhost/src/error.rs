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
    /// The plugin worker process died while a load or a
    /// call was outstanding. `signal` is the terminating
    /// signal when the worker died by signal (11 =
    /// SIGSEGV, 7 = SIGBUS, 6 = SIGABRT), `None` when it
    /// exited without a signal. `detail` is the worker's
    /// stderr tail (capped, control chars stripped) for
    /// diagnosis, never a secret: the worker's stderr
    /// carries the crashing runtime's own output.
    /// The plugin is fused by the client holding this
    /// error: a second call returns the same error, never
    /// a silent reload. Source: M6c-b worker isolation
    /// (see `loader.rs`); Go has no counterpart — a Go
    /// host dies on a plugin segfault instead.
    PluginCrashed {
        /// Terminating signal, when the worker died by
        /// signal.
        signal: Option<i32>,
        /// Worker stderr tail (capped, sanitised).
        detail: String,
    },
    /// Any other operational failure. The message is a
    /// fixed constant, never a path, secret, or server body.
    Failed(String),
    /// The plugin worker process is DEAD (killed on a
    /// transact timeout, a host-callback flood, or a
    /// protocol violation — `worker.rs`
    /// `kill_timeout`/`kill_protocol`). The client can
    /// never succeed again: the worker is gone and the
    /// socket is closed. Typed (not a `Failed` with a
    /// message to re-parse) so the `Host` can fuse on
    /// client-deadness, not on the error variant (fix
    /// loop 2, NB1): a timeout/flood/protocol kill
    /// leaves the Host exactly as dead as a crash, and
    /// fusing only on `PluginCrashed` let the next
    /// `apply_config` burn a doomed reconfigure +
    /// rollback and fuse with the wrong reason.
    /// Displayed exactly like a `Failed` (the message
    /// itself), so callers that only print the error
    /// see no change.
    ClientDead(String),
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

    /// Build a worker-crash error. `detail` is the
    /// worker's stderr tail, already capped and
    /// sanitised by the caller.
    #[must_use]
    pub fn plugin_crashed(signal: Option<i32>, detail: impl Into<String>) -> Self {
        PluginHostError::PluginCrashed {
            signal,
            detail: detail.into(),
        }
    }

    /// Whether this error is a worker crash (fix loop
    /// 1, B3). A crash fuses the plugin at the `Host`
    /// level; so does a kill (`ClientDead`, fix loop
    /// 2, NB1) — see `is_fatal_client_death`.
    /// Oversize, decode, and other `Failed` transport
    /// errors (worker alive) still do not fuse.
    #[must_use]
    pub fn is_crash(&self) -> bool {
        matches!(self, PluginHostError::PluginCrashed { .. })
    }

    /// Whether this error means the client is dead
    /// and can never succeed again (fix loop 2, NB1):
    /// a worker crash OR a worker killed by
    /// `kill_timeout`/`kill_protocol` (transact
    /// timeout, host-callback flood, protocol
    /// violation). The `Host` fuses on this, not on
    /// `is_crash()` alone: a killed worker is exactly
    /// as dead as a crashed one, and the next
    /// `apply_config` must skip as fused instead of
    /// burning a doomed reconfigure + rollback.
    /// Genuinely-alive cases stay unfused: an oversize
    /// host request (`Failed`, pre-check, worker
    /// untouched), an oversize worker reply, and
    /// decode errors are all `Failed`, never
    /// `ClientDead`.
    #[must_use]
    pub fn is_fatal_client_death(&self) -> bool {
        matches!(
            self,
            PluginHostError::PluginCrashed { .. } | PluginHostError::ClientDead(_)
        )
    }
}

impl fmt::Display for PluginHostError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PluginHostError::Invalid(m)
            | PluginHostError::Failed(m)
            | PluginHostError::ClientDead(m) => {
                write!(f, "{m}")
            }
            PluginHostError::LoaderUnavailable => write!(
                f,
                "plugin loading is not supported on this platform (no worker loader)"
            ),
            PluginHostError::PluginCrashed { signal, detail } => {
                match signal {
                    Some(sig) => write!(f, "plugin crashed with signal {sig}")?,
                    None => write!(f, "plugin crashed")?,
                }
                if !detail.is_empty() {
                    write!(f, ": {detail}")?;
                }
                Ok(())
            }
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
            "plugin loading is not supported on this platform (no worker loader)"
        );
        assert_eq!(
            PluginHostError::invalid("plugin metadata name is required").to_string(),
            "plugin metadata name is required"
        );
    }

    /// Fix loop 2, NB1: the fuse predicate is
    /// client-deadness, not the crash variant alone.
    /// A killed worker (`ClientDead`) fuses; a
    /// genuinely-alive failure (`Failed`: oversize,
    /// decode) does not.
    #[test]
    fn fatal_client_death_covers_kills_not_alive_failures() {
        let crashed = PluginHostError::plugin_crashed(Some(11), "");
        assert!(crashed.is_crash());
        assert!(crashed.is_fatal_client_death());
        let killed = PluginHostError::ClientDead("plugin call timed out".to_string());
        assert!(!killed.is_crash());
        assert!(killed.is_fatal_client_death());
        assert_eq!(killed.to_string(), "plugin call timed out");
        let alive = PluginHostError::failed("plugin worker frame too large");
        assert!(!alive.is_crash());
        assert!(!alive.is_fatal_client_death());
    }
}
