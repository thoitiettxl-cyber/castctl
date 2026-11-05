// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Log scrubbing and error classification, ported from Go
//! `internal/logging/safe.go`, `internal/redact/*`, and the
//! `internal/telegram/bot.go` summarize region.
//!
//! Security invariants (load-bearing, do not weaken):
//! - `summarize`/`summarize_error` output contains ONLY fixed
//!   vocabulary plus a rune count — never raw server text.
//! - [`safe_string()`] is a backstop only: bare secrets with no
//!   label are NOT stripped; callers exclude them by
//!   construction.
//! - [`scrub_chain`] holds no reference to pre-scrub text.
//! - Decode phrases are matched ONLY by the anchored chain
//!   check; the string fallback never selects a decode class.

pub mod chain;
pub mod redact_str;
pub mod safe_string;
pub mod summarize;
mod url;

pub use chain::{
    ChainLevel, ErrnoKind, ErrorChain, LevelKind, SentinelKind, classify_error, scrub_chain,
    summarize_error,
};
pub use redact_str::{MARKER, REDACTED, is_secret_key, redact_string, redact_url_userinfo};
pub use safe_string::{safe_err_text, safe_host, safe_string};
pub use summarize::{
    ErrorClass, SUMMARIZE_PREFIX_RUNES, anchored_decode_class, fallback_class, first_runes,
    format_summary, http_class_from_prefix, is_tls_failure_text, scrub_text, summarize,
    summarize_class,
};
