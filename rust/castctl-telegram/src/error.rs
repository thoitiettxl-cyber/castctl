// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Bot error taxonomy.
//!
//! Go sources: `internal/telegram/bot.go:740-1200`
//! (`summarizeError`, `classifyError`, `scrubErr`) and
//! `internal/commands/commands.go:241-360` (`classifyError`
//! exit codes). The allowlist-summary rendering itself is
//! reused from `castctl-log-redact` (`summarize_error`,
//! `summarize`, `format_summary`); this module only maps
//! `BotError` onto that vocabulary.
//!
//! Security invariant: `Display` for `BotError` NEVER emits
//! server body text, the token, or a URL. `Api` descriptions
//! are held for internal parse-error detection only
//! (`is_parse_error`, `is_not_modified`); they are never
//! printed by `Display`/`Debug` and never logged. Use
//! [`BotError::summary`] for any log line.

use castctl_log_redact::{ErrorClass, format_summary};
use castctl_transport::TransportError;

/// Errors a bot operation can return.
///
/// Source: the Go bot core has no single error type; errors
/// surface as scrubbed `error` values whose class is derived
/// by `classifyError` (`internal/telegram/bot.go:817`). This
/// enum is the Rust-side equivalent: one variant per failure
/// family, with the class mapping in [`BotError::error_class`].
/// There is no direct Go type counterpart for this enum; the
/// variants model the Go failure families.
#[derive(Clone)]
pub enum BotError {
    /// Transport failure under the Bot API call.
    /// Source: `internal/telegram/bot.go:956-998` (`transportClass`).
    Transport(TransportError),
    /// Bot API answered `{"ok":false}`. `description` is server
    /// text: never logged, never displayed; see the module doc.
    /// Source: the go-telegram/bot error shape surfaced through
    /// `retryCall` (`internal/telegram/bot.go:1527-1546`).
    Api {
        /// HTTP status / Bot API `error_code`.
        code: i32,
        /// Server `description` (held, never printed).
        description: String,
        /// Bot API `parameters.retry_after`, when present.
        retry_after: Option<i64>,
    },
    /// Local validation failure (bad command name, bad
    /// `setMyCommands` entry, bad state, bad argument shape).
    /// Source: `internal/telegram/bot.go:1786-1816`
    /// (`SetCommands` validation) and
    /// `internal/commands/telegram_commands.go:154-167`.
    Validation(String),
    /// State-file failure (load/save). The message carries
    /// counts and paths only, never file contents.
    /// Source: `internal/telegram/state.go:188-310`.
    State(String),
    /// A seam command whose M5b/M4b wiring does not exist yet.
    /// Returned by `BotServices` default behaviour, never by
    /// the bot core itself. There is no direct Go function
    /// counterpart: Go has the wiring; the Rust port marks the
    /// gap explicitly instead of claiming the command works.
    NotWired(&'static str),
    /// The operation was cancelled (shutdown).
    /// Source: `internal/telegram/bot.go:507-523` (`Start`
    /// returns `ctx.Err()`).
    Cancelled,
}

impl BotError {
    /// The Bot API error code, when this is an `Api` error.
    /// No direct Go function counterpart; exposes the code
    /// the Go code reads via `errors.As` to
    /// `*bot.TooManyRequestsError` / sentinel checks
    /// (`internal/telegram/bot.go:817-871`).
    #[must_use]
    pub fn api_code(&self) -> Option<i32> {
        match self {
            BotError::Api { code, .. } => Some(*code),
            _ => None,
        }
    }

    /// The Bot API `retry_after` value, when present.
    /// Source: `internal/telegram/bot.go:1527-1546` (`retryCall`
    /// reads `tmr.RetryAfter`).
    #[must_use]
    pub fn retry_after(&self) -> Option<i64> {
        match self {
            BotError::Api { retry_after, .. } => *retry_after,
            _ => None,
        }
    }

    /// Whether this error is a Bot API parse failure: HTTP 400
    /// whose description names a parse problem.
    /// Source: `internal/telegram/bot.go:1547-1555` (`isParseError`).
    #[must_use]
    pub fn is_parse_error(&self) -> bool {
        match self {
            BotError::Api {
                code, description, ..
            } => {
                *code == 400 && {
                    let lower = description.to_lowercase();
                    lower.contains("can't parse")
                        || lower.contains("parse entities")
                        || lower.contains("unsupported start tag")
                }
            }
            _ => false,
        }
    }

    /// Whether this error is the "message is not modified"
    /// no-op. Source: `internal/telegram/bot.go:1557-1560`
    /// (`isNotModified`).
    #[must_use]
    pub fn is_not_modified(&self) -> bool {
        match self {
            BotError::Api { description, .. } => description
                .to_lowercase()
                .contains("message is not modified"),
            _ => false,
        }
    }

    /// The fixed-vocabulary class for this error, mirroring
    /// Go `classifyError` precedence as far as the Rust error
    /// shape allows (`internal/telegram/bot.go:817-871`).
    /// 429/400/401/403/404/409 map to the matching sentinel
    /// classes; other HTTP statuses map to `http 4xx`/`http 5xx`.
    /// Transport errors map by variant; `ConnectionDown` /
    /// `ConnectionError` collapse to `Unclassified` because
    /// `TransportError` does not preserve the DNS/TLS/errno
    /// distinction Go's `transportClass` reads from the live
    /// error type — a known limitation, recorded in
    /// PORTING.md §M5a (the class is fixed-vocabulary either
    /// way; only the label granularity is lost).
    #[must_use]
    pub fn error_class(&self) -> ErrorClass {
        match self {
            BotError::Transport(e) => match e {
                TransportError::Auth { .. } => ErrorClass::Unauthorized,
                TransportError::Gateway(summary) => match summary.status {
                    429 => ErrorClass::TooManyRequests,
                    400 => ErrorClass::BadRequest,
                    401 => ErrorClass::Unauthorized,
                    403 => ErrorClass::Forbidden,
                    404 => ErrorClass::NotFound,
                    409 => ErrorClass::Conflict,
                    s if (500..=599).contains(&s) => ErrorClass::Http5xx,
                    s if (400..=499).contains(&s) => ErrorClass::Http4xx,
                    _ => ErrorClass::Unclassified,
                },
                TransportError::Timeout { .. } => ErrorClass::Timeout,
                TransportError::Cancelled => ErrorClass::ContextCanceled,
                _ => ErrorClass::Unclassified,
            },
            BotError::Api { code, .. } => match *code {
                429 => ErrorClass::TooManyRequests,
                400 => ErrorClass::BadRequest,
                401 => ErrorClass::Unauthorized,
                403 => ErrorClass::Forbidden,
                404 => ErrorClass::NotFound,
                409 => ErrorClass::Conflict,
                s if (500..=599).contains(&s) => ErrorClass::Http5xx,
                s if (400..=499).contains(&s) => ErrorClass::Http4xx,
                _ => ErrorClass::Unclassified,
            },
            BotError::Validation(_) | BotError::State(_) | BotError::NotWired(_) => {
                ErrorClass::Unclassified
            }
            BotError::Cancelled => ErrorClass::ContextCanceled,
        }
    }

    /// Allowlist summary for a log line: fixed-vocabulary label
    /// plus a rune count, never raw text.
    /// Source: `internal/telegram/bot.go:764-770`
    /// (`summarizeError` = `formatSummary(classifyError(err),
    /// runeCount(err))`). The rune count here is the length of
    /// the safe `Display` text, not of any server body.
    #[must_use]
    pub fn summary(&self, _token: &str) -> String {
        let text = self.to_string();
        let count = text.chars().count();
        // The rune count is over the safe `Display` text only;
        // nothing verbatim from any server body is emitted.
        format_summary(self.error_class(), count)
    }
}

impl std::fmt::Debug for BotError {
    /// Hand-written: the derived `Debug` would print the
    /// `Api` description (server text). The description
    /// renders as `[redacted]` here, exactly as in
    /// `Display`; only `is_parse_error` /
    /// `is_not_modified` may read it.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BotError::Transport(e) => f.debug_tuple("Transport").field(e).finish(),
            BotError::Api {
                code, retry_after, ..
            } => f
                .debug_struct("Api")
                .field("code", code)
                .field("description", &"[redacted]")
                .field("retry_after", retry_after)
                .finish(),
            BotError::Validation(m) => f.debug_tuple("Validation").field(m).finish(),
            BotError::State(m) => f.debug_tuple("State").field(m).finish(),
            BotError::NotWired(s) => f.debug_tuple("NotWired").field(s).finish(),
            BotError::Cancelled => write!(f, "Cancelled"),
        }
    }
}

impl std::fmt::Display for BotError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BotError::Transport(e) => write!(f, "transport error: {}", e.log_summary()),
            // Never print the Api description: it is server text.
            BotError::Api { code, .. } => write!(f, "telegram api error {code}"),
            BotError::Validation(msg) => write!(f, "validation error: {msg}"),
            BotError::State(msg) => write!(f, "state error: {msg}"),
            BotError::NotWired(name) => write!(f, "command {name} is not wired yet"),
            BotError::Cancelled => write!(f, "cancelled"),
        }
    }
}

impl std::error::Error for BotError {}

impl From<TransportError> for BotError {
    fn from(e: TransportError) -> Self {
        BotError::Transport(e)
    }
}

impl From<serde_json::Error> for BotError {
    fn from(_e: serde_json::Error) -> Self {
        // Never carry the serde message: it can quote the
        // offending input bytes.
        BotError::Validation("response decode failure".to_string())
    }
}

/// Rune count of a string (Go `runeCount`).
/// Source: `internal/telegram/bot.go:750-762` (`formatSummary`
/// counts runes, not bytes).
#[must_use]
pub fn rune_count(s: &str) -> usize {
    s.chars().count()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_display_never_prints_description() {
        let err = BotError::Api {
            code: 400,
            description: "Bad Request: can't parse entities: secret-body-text".to_string(),
            retry_after: None,
        };
        assert!(!format!("{err}").contains("secret-body-text"));
        assert!(!format!("{err:?}").contains("secret-body-text"));
        assert!(err.is_parse_error());
        assert_eq!(err.error_class(), ErrorClass::BadRequest);
    }

    #[test]
    fn summary_is_fixed_vocabulary_only() {
        let err = BotError::Api {
            code: 429,
            description: "Too Many Requests: retry after 5".to_string(),
            retry_after: Some(5),
        };
        let s = err.summary("123456:fake-token-value");
        assert_eq!(s, "telegram error: too many requests message_length=22");
        assert!(!s.contains("123456"));
        assert!(!s.contains("fake-token"));
    }

    #[test]
    fn cancelled_maps_to_context_canceled() {
        assert_eq!(
            BotError::Cancelled.error_class(),
            ErrorClass::ContextCanceled
        );
    }
}
