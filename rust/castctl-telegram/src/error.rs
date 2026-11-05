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

use castctl_log_redact::{ErrorClass, fallback_class, format_summary};
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
    /// A Bot API response body/result could not be
    /// decoded. Fixed vocabulary by construction (no
    /// server text is stored). Maps to
    /// `ResponseDecodeFailure` (`telegram poll error:`
    /// prefix in the summary).
    /// Source: `internal/telegram/bot.go:900-915`
    /// (`anchoredDecodeClass`: `error decode response
    /// body` / `error decode response result` /
    /// `error read response body`).
    ResponseDecode,
    /// One `getUpdates` item could not be decoded.
    /// Fixed vocabulary by construction. Maps to
    /// `UpdateDecodeFailure` (`telegram poll error:`
    /// prefix in the summary).
    /// Source: `internal/telegram/bot.go:900-915`
    /// (`anchoredDecodeClass`: `error decode update`).
    UpdateDecode,
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
    /// Decode failures are typed at construction
    /// (`ResponseDecode` / `UpdateDecode`), which is the
    /// structural equivalent of Go's anchored-decode rule —
    /// the rule itself (`anchored_decode_class`) is not
    /// called, because this crate never builds the
    /// `ErrorChain` values `classify_error` operates on
    /// (see PORTING §M5a.4). Transport `ConnectionDown` /
    /// `ConnectionError` are classified from their message
    /// with `fallback_class`, mirroring Go's
    /// `transportClass` + string fallback
    /// (`bot.go:956-998`, `:1015-1056`): DNS/TLS/errno
    /// phrases in the message decide the class, and a
    /// message with no such phrase stays `Unclassified`.
    /// The one class this crate can never emit is
    /// `ContextDeadlineExceeded`: no deadline-exceeded
    /// error surfaces distinctly here (deadlines arrive
    /// as `Timeout`). Every other label of the 20-label
    /// vocabulary is reachable.
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
                TransportError::ConnectionDown { message }
                | TransportError::ConnectionError { message } => fallback_class(message),
                TransportError::Validation { .. }
                | TransportError::RedirectRefused
                | TransportError::Unsupported { .. } => ErrorClass::Unclassified,
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
            BotError::ResponseDecode => ErrorClass::ResponseDecodeFailure,
            BotError::UpdateDecode => ErrorClass::UpdateDecodeFailure,
            BotError::Validation(_) | BotError::State(_) | BotError::NotWired(_) => {
                ErrorClass::Unclassified
            }
            BotError::Cancelled => ErrorClass::ContextCanceled,
        }
    }

    /// Rune count of the error's underlying text, for
    /// [`BotError::summary`]. The rule is: count the text
    /// the variant stores (the Api description, the
    /// transport message, the local message); variants
    /// that store no text count 0. Only the COUNT is ever
    /// emitted — the text itself never is — so a token or
    /// a 30KB body can influence the count but never leak
    /// through it. This mirrors Go `summarizeError`
    /// (`bot.go:764-770`), which counts the runes of the
    /// raw error text; the lengths are comparable in
    /// signal (a long body yields a large count) but not
    /// byte-identical to Go's, because Go's `err.Error()`
    /// includes library framing (method/status) this port
    /// does not reproduce.
    fn raw_text_len(&self) -> usize {
        match self {
            BotError::Api { description, .. } => description.chars().count(),
            BotError::Transport(e) => match e {
                TransportError::Auth { message }
                | TransportError::ConnectionDown { message }
                | TransportError::ConnectionError { message }
                | TransportError::Timeout { message }
                | TransportError::Validation { message }
                | TransportError::Unsupported { message } => message.chars().count(),
                TransportError::Gateway(_)
                | TransportError::RedirectRefused
                | TransportError::Cancelled => 0,
            },
            BotError::Validation(m) | BotError::State(m) => m.chars().count(),
            BotError::NotWired(name) => name.chars().count(),
            BotError::ResponseDecode | BotError::UpdateDecode | BotError::Cancelled => 0,
        }
    }

    /// Allowlist summary for a log line: fixed-vocabulary label
    /// plus a rune count, never raw text.
    /// Source: `internal/telegram/bot.go:764-770`
    /// (`summarizeError` = `formatSummary(classifyError(err),
    /// runeCount(err))`). The count is over the raw error
    /// text (see [`BotError::raw_text_len`]), never over a
    /// scrubbed rendering. There is deliberately NO token
    /// parameter: a count cannot leak a token, and the old
    /// ignored `_token` parameter wrongly suggested the
    /// summary scrubbed one (fix loop 1, safety N3).
    #[must_use]
    pub fn summary(&self) -> String {
        format_summary(self.error_class(), self.raw_text_len())
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
            BotError::ResponseDecode => write!(f, "ResponseDecode"),
            BotError::UpdateDecode => write!(f, "UpdateDecode"),
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
            BotError::ResponseDecode => write!(f, "response decode failure"),
            BotError::UpdateDecode => write!(f, "update decode failure"),
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
        // offending input bytes. A generic JSON decode
        // failure is a response decode failure; update
        // decode sites map explicitly to `UpdateDecode`
        // instead of using this conversion.
        BotError::ResponseDecode
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

    /// `summary()` counts the runes of the raw error
    /// text, not of the safe `Display` text (fix loop 1,
    /// tech B8): the 429 description below is 32 runes, so
    /// `message_length=32` — the old test pinned 22, the
    /// length of the `Display` string, which carried no
    /// diagnostic signal at all.
    #[test]
    fn summary_is_fixed_vocabulary_only() {
        let err = BotError::Api {
            code: 429,
            description: "Too Many Requests: retry after 5".to_string(),
            retry_after: Some(5),
        };
        let s = err.summary();
        assert_eq!(s, "telegram error: too many requests message_length=32");
        assert!(!s.contains("123456"));
        assert!(!s.contains("fake-token"));
    }

    /// The count stays sensitive to body size: a long
    /// server description yields a large `message_length`
    /// (the diagnostic signal the old `Display`-length
    /// count lost), while the text itself never appears.
    #[test]
    fn summary_count_tracks_raw_text_length() {
        let long = "x".repeat(5000);
        let err = BotError::Api {
            code: 400,
            description: long,
            retry_after: None,
        };
        let s = err.summary();
        assert_eq!(s, "telegram error: bad request message_length=5000");
        assert!(!s.contains('x'));
    }

    /// Decode failures map to the decode classes with the
    /// `telegram poll error:` prefix (fix loop 1, tech B8).
    #[test]
    fn decode_failures_map_to_decode_classes() {
        assert_eq!(
            BotError::ResponseDecode.error_class(),
            ErrorClass::ResponseDecodeFailure
        );
        assert_eq!(
            BotError::UpdateDecode.error_class(),
            ErrorClass::UpdateDecodeFailure
        );
        assert_eq!(
            BotError::ResponseDecode.summary(),
            "telegram poll error: response decode failure message_length=0"
        );
        assert_eq!(
            BotError::UpdateDecode.summary(),
            "telegram poll error: update decode failure message_length=0"
        );
    }

    /// Transport connection failures classify from their
    /// message phrases, mirroring Go's `transportClass` +
    /// fallback (fix loop 1, tech B8).
    #[test]
    fn transport_connection_failures_classify_from_message() {
        let refused = BotError::Transport(TransportError::ConnectionDown {
            message: "dial tcp: connection refused".to_string(),
        });
        assert_eq!(refused.error_class(), ErrorClass::ConnectionRefused);
        let dns = BotError::Transport(TransportError::ConnectionError {
            message: "dial tcp: lookup api.telegram.org: no such host".to_string(),
        });
        assert_eq!(dns.error_class(), ErrorClass::Dns);
        let tls = BotError::Transport(TransportError::ConnectionDown {
            message: "tls: handshake failure".to_string(),
        });
        assert_eq!(tls.error_class(), ErrorClass::Tls);
        let unknown = BotError::Transport(TransportError::ConnectionDown {
            message: "something unrecognised happened".to_string(),
        });
        assert_eq!(unknown.error_class(), ErrorClass::Unclassified);
    }

    #[test]
    fn cancelled_maps_to_context_canceled() {
        assert_eq!(
            BotError::Cancelled.error_class(),
            ErrorClass::ContextCanceled
        );
    }
}
