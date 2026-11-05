// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Log factory, levels, the slog bridge and error summarising.
//!
//! Port of Go `internal/logging` (the remainder: `factory.go`,
//! `level.go`, `slog.go`, `safe.go` `WrapErr`) plus
//! `internal/profile` `ResolveLogSettings` (`log.go:150-195`).
//! The `SafeString` core lives in `castctl-log-redact` (already
//! ported, 21 Go test fns); this crate extends it, never forks it.
//!
//! Format is sing-box's (`github.com/sagernet/sing-box/log`
//! v1.14.4 `format.go`, `level.go`), byte-exact:
//! levels are inverted (`Panic = 0` … `Trace = 6`, emit iff
//! `level <= configured`); the prefix is `LEVEL ` when the
//! timestamp is disabled (file + `timestamp:false`), `<ts> LEVEL `
//! with layout `-0700 2006-01-02 15:04:05` for a full timestamp,
//! else `LEVEL[SSSS] ` (elapsed whole seconds since construction,
//! zero-padded to 4 digits); console colours are
//! Debug/Trace 37, Info 36, Warn 33, Error/Fatal/Panic 31
//! (`\x1b[<n>m<label>\x1b[0m`); files are plain. Go has NO log
//! rotation — none is added here.

mod factory;
mod resolve;
mod slog;
mod summarize;

pub use factory::{
    EmitFn, Handle, Level, LogError, Logger, Settings, emit, new_factory, open_log_file,
    parse_level,
};
pub use resolve::{resolve_log_settings, valid_log_level};
pub use slog::{SlogLevel, SlogLogger, SlogValue};
pub use summarize::{RedactedError, safe_err_for_level, summarize_err, wrap_err, wrap_error};
