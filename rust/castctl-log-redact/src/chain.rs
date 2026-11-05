// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Typed error-chain classification, ported from Go
//! `internal/telegram/bot.go` (`classifyError`,
//! `chainPrefixClass`, `transportClass`, `scrubErr`).
//!
//! The chain is a TREE, not a flat list: Go errors unwrap
//! through `Unwrap() error` and `Unwrap() []error`, so one
//! level may have several children. Construction rule: level
//! 0's text IS the whole error's text; deeper levels' texts
//! are their own `Error()` strings.
//!
//! Security invariant: `scrub_chain` builds a NEW chain whose
//! root text is scrubbed and whose preserved children carry
//! only scrubbed messages plus non-text fields; it holds no
//! reference to pre-scrub text.

use std::fmt;

use crate::summarize::{
    ErrorClass, SUMMARIZE_PREFIX_RUNES, anchored_decode_class, fallback_class, first_runes,
    format_summary, http_class_from_prefix, is_tls_failure_text, scrub_text,
};

/// The six library sentinel classes, in Go's step-1 check
/// order (too many requests first, then the five in
/// `classifyError`'s table order).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SentinelKind {
    /// `bot.ErrorTooManyRequests`.
    TooManyRequests,
    /// `bot.ErrorBadRequest`.
    BadRequest,
    /// `bot.ErrorForbidden`.
    Forbidden,
    /// `bot.ErrorUnauthorized`.
    Unauthorized,
    /// `bot.ErrorNotFound`.
    NotFound,
    /// `bot.ErrorConflict`.
    Conflict,
}

/// `syscall` errnos that select transport classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrnoKind {
    /// `ECONNREFUSED`.
    ConnRefused,
    /// `ECONNRESET`.
    ConnReset,
    /// `EHOSTUNREACH`.
    HostUnreach,
    /// `ENETUNREACH`.
    NetUnreach,
    /// `EHOSTDOWN`.
    HostDown,
    /// `ENETDOWN`.
    NetDown,
}

/// What one chain level is, for classification. `Plain`
/// levels (wraps, `*url.Error` inners that are not themselves
/// typed, `fmt.Errorf` leaves) classify only through their
/// text in the anchored/fallback passes.
///
/// `Debug` is hand-written (see below): it never emits raw
/// message text, which may carry tokens.
#[derive(Clone, PartialEq, Eq)]
pub enum LevelKind {
    /// No typed meaning; text only.
    Plain,
    /// `*bot.TooManyRequestsError`; `RetryAfter` survives
    /// scrubbing, `Message` is scrubbed.
    TooManyRequests {
        /// Server message (scrubbed by `scrub_chain`).
        message: String,
        /// Retry delay in seconds.
        retry_after: i64,
    },
    /// `*bot.MigrateError`; the chat id survives scrubbing.
    Migrate {
        /// Server message (scrubbed by `scrub_chain`).
        message: String,
        /// Target chat id.
        migrate_to_chat_id: i64,
    },
    /// A library sentinel, matched by identity.
    Sentinel(SentinelKind),
    /// `context.Canceled`.
    ContextCanceled,
    /// `context.DeadlineExceeded` (including an expired
    /// context's `Err()`).
    ContextDeadlineExceeded,
    /// `*net.DNSError`.
    DnsError,
    /// A `net.Error` timeout, or `os.ErrDeadlineExceeded`.
    NetTimeout,
    /// `tls.RecordHeaderError`.
    TlsRecordHeader,
    /// `*url.Error`; the TLS check reads the inner level's
    /// text (`children[0]` when present).
    UrlError,
    /// A `syscall.Errno` leaf.
    Errno(ErrnoKind),
    /// `io.EOF` or `io.ErrUnexpectedEOF`.
    Eof,
}

impl fmt::Debug for LevelKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Defence in depth: message fields may carry tokens,
        // so only their rune lengths are printed, never the
        // text itself.
        match self {
            LevelKind::Plain => f.write_str("Plain"),
            LevelKind::TooManyRequests {
                message,
                retry_after,
            } => f
                .debug_struct("TooManyRequests")
                .field("message_len", &message.chars().count())
                .field("retry_after", retry_after)
                .finish(),
            LevelKind::Migrate {
                message,
                migrate_to_chat_id,
            } => f
                .debug_struct("Migrate")
                .field("message_len", &message.chars().count())
                .field("migrate_to_chat_id", migrate_to_chat_id)
                .finish(),
            LevelKind::Sentinel(kind) => f.debug_tuple("Sentinel").field(kind).finish(),
            LevelKind::ContextCanceled => f.write_str("ContextCanceled"),
            LevelKind::ContextDeadlineExceeded => f.write_str("ContextDeadlineExceeded"),
            LevelKind::DnsError => f.write_str("DnsError"),
            LevelKind::NetTimeout => f.write_str("NetTimeout"),
            LevelKind::TlsRecordHeader => f.write_str("TlsRecordHeader"),
            LevelKind::UrlError => f.write_str("UrlError"),
            LevelKind::Errno(kind) => f.debug_tuple("Errno").field(kind).finish(),
            LevelKind::Eof => f.write_str("Eof"),
        }
    }
}

/// One level of an error chain: its own `Error()` text, its
/// kind, and the levels reachable through `Unwrap`.
///
/// `Debug` is hand-written (see below): it reports only the
/// rune length of the text, never the text itself.
#[derive(Clone, PartialEq, Eq)]
pub struct ChainLevel {
    /// This level's own error text.
    pub text: String,
    /// This level's classification kind.
    pub kind: LevelKind,
    /// Unwrapped children, in Go's `Unwrap` order.
    pub children: Vec<ChainLevel>,
}

impl fmt::Debug for ChainLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Defence in depth: the text may carry tokens, so
        // only its rune length is printed, never the text.
        // Children use this same impl, so a whole chain's
        // `Debug` output is token-free even unscrubbed.
        f.debug_struct("ChainLevel")
            .field("text_len", &self.text.chars().count())
            .field("kind", &self.kind)
            .field("children", &self.children)
            .finish()
    }
}

impl ChainLevel {
    /// A plain level with the given text and children.
    ///
    /// Source: `internal/telegram/bot.go:864-872` (the
    /// `chainPrefixClass` chain model: each level is an error
    /// reachable through `Unwrap`). There is no direct Go
    /// function counterpart for this constructor: it is a
    /// Rust-side constructor for building a [`ChainLevel`].
    #[must_use]
    pub fn plain(text: &str, children: Vec<ChainLevel>) -> Self {
        ChainLevel {
            text: text.to_string(),
            kind: LevelKind::Plain,
            children,
        }
    }

    /// A leaf level (no children) of the given kind.
    ///
    /// Source: `internal/telegram/bot.go:864-872` (the
    /// `chainPrefixClass` chain model: a level with no
    /// `Unwrap` children). There is no direct Go function
    /// counterpart for this constructor: it is a Rust-side
    /// constructor for building a [`ChainLevel`].
    #[must_use]
    pub fn leaf(text: &str, kind: LevelKind) -> Self {
        ChainLevel {
            text: text.to_string(),
            kind,
            children: Vec::new(),
        }
    }
}

/// An error chain: its root level. `None` (Go nil error)
/// classifies as unclassified with length 0.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorChain {
    /// The root level; its text is the whole error's text.
    pub root: ChainLevel,
}

impl ErrorChain {
    /// A chain with a single plain level.
    ///
    /// Source: `internal/telegram/bot.go:864-872` (the
    /// `chainPrefixClass` chain model: a chain is its root
    /// level plus the levels reachable through `Unwrap`).
    /// There is no direct Go function counterpart for this
    /// constructor: it is a Rust-side constructor for
    /// building an [`ErrorChain`].
    #[must_use]
    pub fn plain(text: &str) -> Self {
        ErrorChain {
            root: ChainLevel::plain(text, Vec::new()),
        }
    }
}

/// Walks the chain depth-first (explicit stack, children
/// pushed in order and popped last-first, exactly like Go's
/// `chainPrefixClass`), applying `check` to each level's
/// scrubbed bounded prefix. Levels at depth 0..=32 are
/// inspected; depth 32 is not expanded. Returns the first
/// non-`None` label, or `None`.
/// Source: `internal/telegram/bot.go:872`, `chainPrefixClass`.
fn chain_prefix_class(
    chain: &ErrorChain,
    token: &str,
    check: impl Fn(&str) -> Option<ErrorClass>,
) -> Option<ErrorClass> {
    // Stack items borrow the chain; depths mirror Go's item
    // depth (root = 0).
    let mut stack: Vec<(&ChainLevel, usize)> = vec![(&chain.root, 0)];
    while let Some((level, depth)) = stack.pop() {
        if depth > 32 {
            continue;
        }
        let prefix = scrub_text(first_runes(&level.text, SUMMARIZE_PREFIX_RUNES), token);
        if let Some(class) = check(&prefix) {
            return Some(class);
        }
        if depth == 32 {
            continue;
        }
        for child in &level.children {
            stack.push((child, depth + 1));
        }
    }
    None
}

/// Step-1 search with the correct per-class order, split out
/// so the order is auditable against `classifyError`.
/// Part of `internal/telegram/bot.go:817`, `classifyError`.
fn step1_search(chain: &ErrorChain) -> Option<ErrorClass> {
    fn contains(chain: &ErrorChain, want: &dyn Fn(&LevelKind) -> bool) -> bool {
        let mut stack: Vec<&ChainLevel> = vec![&chain.root];
        while let Some(level) = stack.pop() {
            if want(&level.kind) {
                return true;
            }
            for child in &level.children {
                stack.push(child);
            }
        }
        false
    }
    if contains(chain, &|k| matches!(k, LevelKind::TooManyRequests { .. })) {
        return Some(ErrorClass::TooManyRequests);
    }
    if contains(chain, &|k| {
        matches!(k, LevelKind::Sentinel(SentinelKind::TooManyRequests))
    }) {
        return Some(ErrorClass::TooManyRequests);
    }
    if contains(chain, &|k| matches!(k, LevelKind::Migrate { .. })) {
        return Some(ErrorClass::BadRequest);
    }
    for (kind, class) in [
        (SentinelKind::BadRequest, ErrorClass::BadRequest),
        (SentinelKind::Forbidden, ErrorClass::Forbidden),
        (SentinelKind::Unauthorized, ErrorClass::Unauthorized),
        (SentinelKind::NotFound, ErrorClass::NotFound),
        (SentinelKind::Conflict, ErrorClass::Conflict),
    ] {
        if contains(
            chain,
            &|k| matches!(k, LevelKind::Sentinel(s) if *s == kind),
        ) {
            return Some(class);
        }
    }
    None
}

/// Step-3 search: context classes, canceled before deadline,
/// over the whole tree.
/// Part of `internal/telegram/bot.go:817`, `classifyError`.
fn step3_class(chain: &ErrorChain) -> Option<ErrorClass> {
    fn contains(chain: &ErrorChain, want: &dyn Fn(&LevelKind) -> bool) -> bool {
        let mut stack: Vec<&ChainLevel> = vec![&chain.root];
        while let Some(level) = stack.pop() {
            if want(&level.kind) {
                return true;
            }
            for child in &level.children {
                stack.push(child);
            }
        }
        false
    }
    if contains(chain, &|k| matches!(k, LevelKind::ContextCanceled)) {
        return Some(ErrorClass::ContextCanceled);
    }
    if contains(chain, &|k| matches!(k, LevelKind::ContextDeadlineExceeded)) {
        return Some(ErrorClass::ContextDeadlineExceeded);
    }
    None
}

/// The first `UrlError` level in pre-order DFS (children in
/// unwrap order), matching Go `errors.As` for the first
/// `*url.Error`. Used only by the URL-inner TLS step of
/// `transport_class` (`bot.go:956`).
fn first_url_error_level(chain: &ErrorChain) -> Option<&ChainLevel> {
    let mut stack: Vec<&ChainLevel> = vec![&chain.root];
    while let Some(level) = stack.pop() {
        if matches!(level.kind, LevelKind::UrlError) {
            return Some(level);
        }
        for child in level.children.iter().rev() {
            stack.push(child);
        }
    }
    None
}

/// Step-4 transport classification, in Go `transportClass`
/// order: DNS, timeout, TLS record header, URL-inner TLS,
/// errnos (refused, reset, unreachable group), EOF.
/// Source: `internal/telegram/bot.go:956`, `transportClass`.
fn transport_class(chain: &ErrorChain) -> Option<ErrorClass> {
    fn contains(chain: &ErrorChain, want: &dyn Fn(&LevelKind) -> bool) -> bool {
        let mut stack: Vec<&ChainLevel> = vec![&chain.root];
        while let Some(level) = stack.pop() {
            if want(&level.kind) {
                return true;
            }
            for child in &level.children {
                stack.push(child);
            }
        }
        false
    }
    if contains(chain, &|k| matches!(k, LevelKind::DnsError)) {
        return Some(ErrorClass::Dns);
    }
    if contains(chain, &|k| matches!(k, LevelKind::NetTimeout)) {
        return Some(ErrorClass::Timeout);
    }
    if contains(chain, &|k| matches!(k, LevelKind::TlsRecordHeader)) {
        return Some(ErrorClass::Tls);
    }
    // URL-inner TLS: Go `transportClass` finds the FIRST
    // `*url.Error` via `errors.As` (pre-order DFS, unwrap
    // order) and checks ONLY that error's inner text (its
    // first child here). Deeper UrlError levels are never
    // consulted, even when the first one's inner text hides
    // TLS text behind a wrapper.
    if let Some(url_level) = first_url_error_level(chain) {
        if let Some(inner) = url_level.children.first() {
            if is_tls_failure_text(&inner.text) {
                return Some(ErrorClass::Tls);
            }
        }
    }
    if contains(chain, &|k| {
        matches!(k, LevelKind::Errno(ErrnoKind::ConnRefused))
    }) {
        return Some(ErrorClass::ConnectionRefused);
    }
    if contains(chain, &|k| {
        matches!(k, LevelKind::Errno(ErrnoKind::ConnReset))
    }) {
        return Some(ErrorClass::ConnectionReset);
    }
    if contains(chain, &|k| {
        matches!(
            k,
            LevelKind::Errno(ErrnoKind::HostUnreach)
                | LevelKind::Errno(ErrnoKind::NetUnreach)
                | LevelKind::Errno(ErrnoKind::HostDown)
                | LevelKind::Errno(ErrnoKind::NetDown)
        )
    }) {
        return Some(ErrorClass::Unreachable);
    }
    if contains(chain, &|k| matches!(k, LevelKind::Eof)) {
        return Some(ErrorClass::Eof);
    }
    None
}

/// Classifies a chain with Go's 7-step precedence, first
/// match wins. `token` is the scrub token (empty when the
/// caller has none).
/// Source: `internal/telegram/bot.go:817`, `classifyError`.
pub fn classify_error(chain: Option<&ErrorChain>, token: &str) -> ErrorClass {
    let Some(chain) = chain else {
        return ErrorClass::Unclassified;
    };
    if let Some(class) = step1_search(chain) {
        return class;
    }
    if let Some(class) = chain_prefix_class(chain, token, anchored_decode_class) {
        return class;
    }
    if let Some(class) = step3_class(chain) {
        return class;
    }
    if let Some(class) = transport_class(chain) {
        return class;
    }
    if let Some(class) = chain_prefix_class(chain, token, http_class_from_prefix) {
        return class;
    }
    fallback_class(&scrub_text(
        first_runes(&chain.root.text, SUMMARIZE_PREFIX_RUNES),
        token,
    ))
}

/// Renders a chain as a class/length summary. `None`
/// classifies as unclassified with length 0; otherwise the
/// length is the rune count of the root (whole-error) text.
/// Source: `internal/telegram/bot.go:764`, `summarizeError`.
pub fn summarize_error(chain: Option<&ErrorChain>, token: &str) -> String {
    match chain {
        None => format_summary(ErrorClass::Unclassified, 0),
        Some(chain) => format_summary(
            classify_error(Some(chain), token),
            chain.root.text.chars().count(),
        ),
    }
}

/// The first level (pre-order DFS, children in unwrap
/// order) whose kind satisfies `want`, or `None`. Matches Go
/// `errors.As` visit order for the `scrubErr` preservation
/// scans (`bot.go:1156`). Existence-only scans (steps 1/3/4)
/// do not use this: their result is order-insensitive.
fn first_match<'a>(
    chain: &'a ErrorChain,
    want: &dyn Fn(&LevelKind) -> bool,
) -> Option<&'a ChainLevel> {
    let mut stack: Vec<&'a ChainLevel> = vec![&chain.root];
    while let Some(level) = stack.pop() {
        if want(&level.kind) {
            return Some(level);
        }
        for child in level.children.iter().rev() {
            stack.push(child);
        }
    }
    None
}

/// Returns a copy of `chain` with the token scrubbed out of
/// the error text AND out of every preserved typed field.
/// Transport/context kinds are deliberately dropped; only
/// the step-1 chain is preserved (TMR with scrubbed message
/// and original `RetryAfter`, Migrate with scrubbed message
/// and original id, sentinels in Go's listed order), as
/// children of a new plain root carrying the scrubbed whole
/// text. A `None` chain stays `None`.
/// Source: `internal/telegram/bot.go:1156`, `scrubErr`.
pub fn scrub_chain(chain: Option<&ErrorChain>, token: &str) -> Option<ErrorChain> {
    let chain = chain?;
    let root_text = scrub_text(&chain.root.text, token);
    let mut unwraps: Vec<ChainLevel> = Vec::new();
    // TMR first, in pre-order DFS (children in unwrap order),
    // matching Go `errors.As` in `scrubErr`: the FIRST match
    // wins, never the last.
    if let Some(level) = first_match(chain, &|k| matches!(k, LevelKind::TooManyRequests { .. })) {
        if let LevelKind::TooManyRequests {
            message,
            retry_after,
        } = &level.kind
        {
            unwraps.push(ChainLevel::leaf(
                "",
                LevelKind::TooManyRequests {
                    message: scrub_text(message, token),
                    retry_after: *retry_after,
                },
            ));
        }
    }
    // Migrate second, same pre-order discipline.
    if let Some(level) = first_match(chain, &|k| matches!(k, LevelKind::Migrate { .. })) {
        if let LevelKind::Migrate {
            message,
            migrate_to_chat_id,
        } = &level.kind
        {
            unwraps.push(ChainLevel::leaf(
                "",
                LevelKind::Migrate {
                    message: scrub_text(message, token),
                    migrate_to_chat_id: *migrate_to_chat_id,
                },
            ));
        }
    }
    // Sentinels in Go's listed order.
    for kind in [
        SentinelKind::BadRequest,
        SentinelKind::Forbidden,
        SentinelKind::Unauthorized,
        SentinelKind::NotFound,
        SentinelKind::Conflict,
        SentinelKind::TooManyRequests,
    ] {
        let mut stack: Vec<&ChainLevel> = vec![&chain.root];
        let mut found = false;
        while let Some(level) = stack.pop() {
            if matches!(&level.kind, LevelKind::Sentinel(s) if *s == kind) {
                found = true;
                break;
            }
            for child in &level.children {
                stack.push(child);
            }
        }
        if found {
            unwraps.push(ChainLevel::leaf("", LevelKind::Sentinel(kind)));
        }
    }
    Some(ErrorChain {
        root: ChainLevel {
            text: root_text,
            kind: LevelKind::Plain,
            children: unwraps,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::summarize::ErrorClass;

    /// Invented 32-char placeholder token for the Rust chain
    /// tests (same length as the Go fixture token, so
    /// G1-measured rune counts reproduce; a DIFFERENT value
    /// — never the Go fixture).
    const TOKEN: &str = "RUSTFIX-TOKEN-PLACEHOLDER-012345";

    fn plain(text: &str) -> ChainLevel {
        ChainLevel::plain(text, Vec::new())
    }

    fn wrap(text: &str, child: ChainLevel) -> ChainLevel {
        ChainLevel::plain(text, vec![child])
    }

    fn sentinel(text: &str, kind: SentinelKind) -> ChainLevel {
        ChainLevel::leaf(text, LevelKind::Sentinel(kind))
    }

    fn chain(root: ChainLevel) -> ErrorChain {
        ErrorChain { root }
    }

    fn check(chain: Option<&ErrorChain>, token: &str, want: &str) {
        let got = summarize_error(chain, token);
        assert_eq!(got, want, "summarize_error");
        assert!(
            !got.contains("method="),
            "summarize_error emitted a method= field in {got:?}"
        );
        assert!(
            !got.contains(TOKEN),
            "summarize_error kept the fixture token in {got:?}"
        );
        assert!(
            got.len() <= 400,
            "summarize_error output is {} bytes",
            got.len()
        );
    }

    // Ported from Go `TestSummarizeErrorClasses` (44 cases).
    // Root texts are the G1-measured Go `Error()` renderings
    // (probe-out.txt, 2026-11-04), with the 32-char Rust
    // placeholder substituted for the Go fixture token at
    // the same length; expected summaries are the measured
    // G1 summaries verbatim. Scrubbed cases build the
    // pre-scrub chain and run `scrub_chain` first, as Go's
    // `b.scrubErr` does.
    #[test]
    fn test_summarize_error_classes() {
        let decode_leaf = || plain("unexpected end of JSON input");
        let url_timeout = || ChainLevel {
            text: format!(
                "Post \"https://api.telegram.org/bot{TOKEN}/getUpdates\": read tcp: i/o timeout"
            ),
            kind: LevelKind::UrlError,
            children: vec![ChainLevel::leaf(
                "read tcp: i/o timeout",
                LevelKind::NetTimeout,
            )],
        };
        let url_dns = || ChainLevel {
            text: "Post \"https://api.telegram.org/\": lookup api.telegram.org: no such host"
                .to_string(),
            kind: LevelKind::UrlError,
            children: vec![ChainLevel::leaf(
                "lookup api.telegram.org: no such host",
                LevelKind::DnsError,
            )],
        };
        let url_refused = || ChainLevel {
            text: "dial \"\": dial tcp 127.0.0.1:443: connect: connection refused".to_string(),
            kind: LevelKind::UrlError,
            children: vec![wrap(
                "dial tcp 127.0.0.1:443: connect: connection refused",
                ChainLevel::leaf(
                    "connection refused",
                    LevelKind::Errno(ErrnoKind::ConnRefused),
                ),
            )],
        };

        // (name, chain, scrub-first?, expected summary)
        let tmr_typed = chain(ChainLevel {
            text: "too many requests, retry after 5: retry_after 5".to_string(),
            kind: LevelKind::TooManyRequests {
                message: "too many requests, retry after 5".to_string(),
                retry_after: 5,
            },
            children: vec![],
        });
        let tmr_wrap = chain(wrap(
            "too many requests, retry after 5",
            sentinel("too many requests", SentinelKind::TooManyRequests),
        ));
        let tmr_scrubbed_pre = chain(ChainLevel {
            text: format!("too many requests, {TOKEN}: retry_after 5"),
            kind: LevelKind::TooManyRequests {
                message: format!("too many requests, {TOKEN}"),
                retry_after: 5,
            },
            children: vec![],
        });
        let badreq_wrap = chain(wrap(
            "bad request, can't parse entities",
            sentinel("bad request", SentinelKind::BadRequest),
        ));
        let badreq_scrubbed_pre = chain(wrap(
            &format!("bad request, Bad Request: {TOKEN}"),
            sentinel("bad request", SentinelKind::BadRequest),
        ));
        let migrate = chain(ChainLevel {
            text: "bad request: group migrated: migrate_to_chat_id -100123".to_string(),
            kind: LevelKind::Migrate {
                message: "bad request: group migrated".to_string(),
                migrate_to_chat_id: -100123,
            },
            children: vec![],
        });
        let forbidden = chain(wrap(
            "forbidden, bot was blocked by the user",
            sentinel("forbidden", SentinelKind::Forbidden),
        ));
        let unauthorized = chain(wrap(
            "unauthorized, Unauthorized",
            sentinel("unauthorized", SentinelKind::Unauthorized),
        ));
        let notfound = chain(wrap(
            "not found, chat not found",
            sentinel("not found", SentinelKind::NotFound),
        ));
        let conflict = chain(wrap(
            "conflict, terminated by other getUpdates request",
            sentinel("conflict", SentinelKind::Conflict),
        ));
        let resp_decode = chain(wrap(
            "error decode response body for method getUpdates, {\"ok\":true,\"result\":[]}, unexpected end of JSON input",
            decode_leaf(),
        ));
        let resp_decode_wrapped = chain(wrap(
            "error get updates, error decode response body for method getUpdates, {\"ok\":true,\"result\":[]}, unexpected end of JSON input",
            wrap(
                "error decode response body for method getUpdates, {\"ok\":true,\"result\":[]}, unexpected end of JSON input",
                decode_leaf(),
            ),
        ));
        let resp_result = chain(wrap(
            "error decode response result for method sendMessage, unexpected end of JSON input",
            decode_leaf(),
        ));
        let read_body_eof = chain(wrap(
            "error read response body for method getUpdates, unexpected EOF",
            ChainLevel::leaf("unexpected EOF", LevelKind::Eof),
        ));
        let update_decode = chain(wrap(
            "error decode update, {\"update_id\":42}, unexpected end of JSON input",
            decode_leaf(),
        ));
        let update_decode_skipped = chain(wrap(
            "error decode update 42, skipped, {\"update_id\":42}, unexpected end of JSON input",
            decode_leaf(),
        ));
        let timeout_op = chain(url_timeout());
        let timeout_wrapped = chain(wrap(
            &format!(
                "error do request for method getUpdates, Post \"https://api.telegram.org/bot{TOKEN}/getUpdates\": read tcp: i/o timeout"
            ),
            url_timeout(),
        ));
        let timeout_scrubbed_pre = chain(wrap(
            &format!(
                "error do request for method sendMessage, Post \"https://api.telegram.org/bot{TOKEN}/getUpdates\": read tcp: i/o timeout"
            ),
            url_timeout(),
        ));
        let dns = chain(url_dns());
        let dns_wrapped = chain(wrap(
            "error do request for method getMe, Post \"https://api.telegram.org/\": lookup api.telegram.org: no such host",
            url_dns(),
        ));
        let tls_record = chain(ChainLevel {
            text: "Post \"https://api.telegram.org/\": tls: first record does not look like a TLS handshake".to_string(),
            kind: LevelKind::UrlError,
            children: vec![ChainLevel::leaf(
                "tls: first record does not look like a TLS handshake",
                LevelKind::TlsRecordHeader,
            )],
        });
        let tls_cert = chain(ChainLevel {
            text: "Post \"https://api.telegram.org/\": tls: bad certificate".to_string(),
            kind: LevelKind::UrlError,
            children: vec![plain("tls: bad certificate")],
        });
        let refused_errno = chain(wrap(
            "dial tcp: connection refused",
            ChainLevel::leaf(
                "connection refused",
                LevelKind::Errno(ErrnoKind::ConnRefused),
            ),
        ));
        let refused_url = chain(url_refused());
        let refused_scrubbed_pre = chain(wrap(
            "error do request for method sendMessage, dial \"\": dial tcp 127.0.0.1:443: connect: connection refused",
            url_refused(),
        ));
        let reset_errno = chain(wrap(
            "read tcp: connection reset by peer",
            ChainLevel::leaf(
                "connection reset by peer",
                LevelKind::Errno(ErrnoKind::ConnReset),
            ),
        ));
        let unreach_host = chain(wrap(
            "dial: no route to host",
            ChainLevel::leaf("no route to host", LevelKind::Errno(ErrnoKind::HostUnreach)),
        ));
        let unreach_net = chain(wrap(
            "dial: network is unreachable",
            ChainLevel::leaf(
                "network is unreachable",
                LevelKind::Errno(ErrnoKind::NetUnreach),
            ),
        ));
        let eof = chain(wrap(
            "reading response: EOF",
            ChainLevel::leaf("EOF", LevelKind::Eof),
        ));
        let unexpected_eof = chain(ChainLevel::leaf("unexpected EOF", LevelKind::Eof));
        let ctx_canceled = chain(ChainLevel::leaf(
            "context canceled",
            LevelKind::ContextCanceled,
        ));
        let ctx_canceled_wrapped = chain(wrap(
            "poll: context canceled",
            ChainLevel::leaf("context canceled", LevelKind::ContextCanceled),
        ));
        let ctx_canceled_url = chain(ChainLevel {
            text: "Post \"https://api.telegram.org/\": context canceled".to_string(),
            kind: LevelKind::UrlError,
            children: vec![ChainLevel::leaf(
                "context canceled",
                LevelKind::ContextCanceled,
            )],
        });
        let ctx_deadline = chain(ChainLevel::leaf(
            "context deadline exceeded",
            LevelKind::ContextDeadlineExceeded,
        ));
        let http_5xx = chain(plain(
            "error response from telegram for method getUpdates, 500 Internal Server Error",
        ));
        let http_5xx_wrapped = chain(wrap(
            "error get updates, error response from telegram for method getUpdates, 503 Service Unavailable",
            plain("error response from telegram for method getUpdates, 503 Service Unavailable"),
        ));
        let http_4xx = chain(plain(
            "error response from telegram for method sendMessage, 422 Unprocessable Entity",
        ));
        let unclassified = chain(plain("something completely unexpected"));

        // Direct (unscrubbed) cases.
        let direct: [(&str, &ErrorChain, &str); 36] = [
            (
                "too many requests typed",
                &tmr_typed,
                "telegram error: too many requests message_length=47",
            ),
            (
                "too many requests sentinel wrap",
                &tmr_wrap,
                "telegram error: too many requests message_length=32",
            ),
            (
                "bad request sentinel",
                &badreq_wrap,
                "telegram error: bad request message_length=33",
            ),
            (
                "bad request migrate error",
                &migrate,
                "telegram error: bad request message_length=55",
            ),
            (
                "forbidden sentinel",
                &forbidden,
                "telegram error: forbidden message_length=38",
            ),
            (
                "unauthorized sentinel",
                &unauthorized,
                "telegram error: unauthorized message_length=26",
            ),
            (
                "not found sentinel",
                &notfound,
                "telegram error: not found message_length=25",
            ),
            (
                "conflict sentinel",
                &conflict,
                "telegram error: conflict message_length=48",
            ),
            (
                "response decode body",
                &resp_decode,
                "telegram poll error: response decode failure message_length=103",
            ),
            (
                "response decode body wrapped by poll loop",
                &resp_decode_wrapped,
                "telegram poll error: response decode failure message_length=122",
            ),
            (
                "response decode result",
                &resp_result,
                "telegram poll error: response decode failure message_length=81",
            ),
            (
                "response read body beats eof",
                &read_body_eof,
                "telegram poll error: response decode failure message_length=62",
            ),
            (
                "update decode",
                &update_decode,
                "telegram poll error: update decode failure message_length=67",
            ),
            (
                "update decode skipped",
                &update_decode_skipped,
                "telegram poll error: update decode failure message_length=79",
            ),
            (
                "timeout op error",
                &timeout_op,
                "telegram error: timeout message_length=101",
            ),
            (
                "timeout wrapped do request",
                &timeout_wrapped,
                "telegram error: timeout message_length=141",
            ),
            ("dns error", &dns, "telegram error: dns message_length=71"),
            (
                "dns wrapped do request",
                &dns_wrapped,
                "telegram error: dns message_length=106",
            ),
            (
                "tls record header",
                &tls_record,
                "telegram error: tls message_length=86",
            ),
            (
                "tls bad certificate text",
                &tls_cert,
                "telegram error: tls message_length=54",
            ),
            (
                "connection refused errno",
                &refused_errno,
                "telegram error: connection refused message_length=28",
            ),
            (
                "connection refused url wrapped",
                &refused_url,
                "telegram error: connection refused message_length=60",
            ),
            (
                "connection reset errno",
                &reset_errno,
                "telegram error: connection reset message_length=34",
            ),
            (
                "unreachable host",
                &unreach_host,
                "telegram error: unreachable message_length=22",
            ),
            (
                "unreachable network",
                &unreach_net,
                "telegram error: unreachable message_length=28",
            ),
            ("eof", &eof, "telegram error: eof message_length=21"),
            (
                "unexpected eof",
                &unexpected_eof,
                "telegram error: eof message_length=14",
            ),
            (
                "context canceled",
                &ctx_canceled,
                "telegram error: context canceled message_length=16",
            ),
            (
                "context canceled wrapped",
                &ctx_canceled_wrapped,
                "telegram error: context canceled message_length=22",
            ),
            (
                "context canceled in url error",
                &ctx_canceled_url,
                "telegram error: context canceled message_length=50",
            ),
            (
                "context deadline exceeded",
                &ctx_deadline,
                "telegram error: context deadline exceeded message_length=25",
            ),
            (
                "context deadline exceeded from expired ctx",
                &ctx_deadline,
                "telegram error: context deadline exceeded message_length=25",
            ),
            (
                "http 5xx",
                &http_5xx,
                "telegram error: http 5xx message_length=77",
            ),
            (
                "http 5xx wrapped by poll loop",
                &http_5xx_wrapped,
                "telegram error: http 5xx message_length=94",
            ),
            (
                "http 4xx",
                &http_4xx,
                "telegram error: http 4xx message_length=77",
            ),
            (
                "unclassified plain",
                &unclassified,
                "telegram error: unclassified message_length=31",
            ),
        ];
        for (name, c, want) in direct {
            check(Some(c), TOKEN, want);
            let _ = name;
        }
        // Nil case.
        check(None, TOKEN, "telegram error: unclassified message_length=0");

        // Scrubbed cases: scrub first, then classify the
        // scrubbed chain, as Go's `b.scrubErr` + `summarizeError`
        // does. The scrubbed root texts are pinned to the
        // G1-measured scrubbed renderings.
        let scrubbed: [(&str, ErrorChain, &str, &str); 7] = [
            (
                "too many requests scrubbed",
                tmr_scrubbed_pre,
                "too many requests, ***: retry_after 5",
                "telegram error: too many requests message_length=37",
            ),
            (
                "bad request scrubbed",
                badreq_scrubbed_pre,
                "bad request, Bad Request: ***",
                "telegram error: bad request message_length=29",
            ),
            (
                "response decode body scrubbed",
                resp_decode.clone(),
                "error decode response body for method getUpdates, {\"ok\":true,\"result\":[]}, unexpected end of JSON input",
                "telegram poll error: response decode failure message_length=103",
            ),
            (
                "timeout scrubbed fallback",
                timeout_scrubbed_pre,
                "error do request for method sendMessage, Post \"https://api.telegram.org/bot***/getUpdates\": read tcp: i/o timeout",
                "telegram error: timeout message_length=113",
            ),
            (
                "dns scrubbed fallback",
                dns_wrapped.clone(),
                "error do request for method getMe, Post \"https://api.telegram.org/\": lookup api.telegram.org: no such host",
                "telegram error: dns message_length=106",
            ),
            (
                "connection refused scrubbed fallback",
                refused_scrubbed_pre,
                "error do request for method sendMessage, dial \"\": dial tcp 127.0.0.1:443: connect: connection refused",
                "telegram error: connection refused message_length=101",
            ),
            (
                "unclassified scrubbed unknown",
                chain(plain("weird failure")),
                "weird failure",
                "telegram error: unclassified message_length=13",
            ),
        ];
        for (name, pre, scrubbed_text, want) in scrubbed {
            let scrubbed_chain = scrub_chain(Some(&pre), TOKEN).expect("scrub_chain of Some");
            assert_eq!(
                scrubbed_chain.root.text, scrubbed_text,
                "scrubbed root text ({name})"
            );
            assert!(
                !format!("{scrubbed_chain:?}").contains(TOKEN),
                "scrubbed chain Debug contains the token ({name})"
            );
            check(Some(&scrubbed_chain), TOKEN, want);
        }
    }

    // Ported from Go
    // `TestSummarizeErrorHostileDescriptionNotDecode` (H1/H2).
    // H1: sentinel wins over a decode phrase buried in a
    // 400-rune description. H2: an unanchored decode phrase
    // with no chain at all stays unclassified.
    #[test]
    fn test_summarize_error_hostile_description_not_decode() {
        let phrase = "decode response body";
        let desc = format!(
            "{} {} {} {}",
            "D".repeat(100),
            phrase,
            TOKEN,
            "E".repeat(400 - 100 - 1 - phrase.len() - 1 - TOKEN.len() - 1)
        );
        assert_eq!(desc.chars().count(), 400);
        let err = chain(wrap(
            &format!("bad request, {desc}"),
            sentinel("bad request", SentinelKind::BadRequest),
        ));
        let got = summarize_error(Some(&err), TOKEN);
        assert_eq!(got, "telegram error: bad request message_length=413");
        assert!(!got.contains(phrase) && !got.contains(TOKEN));

        let plain_input = format!(
            "{} decode response body for method getUpdates, {{\"ok\":true}}{}",
            "z".repeat(100),
            "z".repeat(200)
        );
        assert_eq!(plain_input.chars().count(), 356);
        let plain_err = chain(plain(&plain_input));
        let got_plain = summarize_error(Some(&plain_err), TOKEN);
        assert_eq!(got_plain, "telegram error: unclassified message_length=356");
        assert!(!got_plain.contains(phrase));
    }

    // Ported from Go `TestSummarizeErrorHugeInputBounded`
    // (2 inputs, typed path).
    #[test]
    fn test_summarize_error_huge_input_bounded() {
        let inputs: [(&str, ErrorChain, &str, &str); 2] = [
            (
                "plain 5MB",
                chain(plain(&"R6D-CPU-MARKER-".repeat(350_000))),
                "telegram error: unclassified message_length=5250000",
                "R6D-CPU-MARKER-",
            ),
            (
                "late decode phrase",
                chain(plain(&format!(
                    "{} decode response body {}",
                    "q".repeat(100_000),
                    "q".repeat(5_000_000 - 100_000 - 22)
                ))),
                "telegram error: unclassified message_length=5000000",
                "decode response body",
            ),
        ];
        for (name, err, want, absent) in inputs {
            let start = std::time::Instant::now();
            let got = summarize_error(Some(&err), TOKEN);
            assert!(
                start.elapsed() < std::time::Duration::from_secs(10),
                "summarizeError({name}) took {:?}",
                start.elapsed()
            );
            assert_eq!(got, want, "summarizeError({name})");
            assert!(
                !got.contains(absent),
                "summarizeError({name}) kept an input fragment in {got:?}"
            );
            assert!(
                got.len() <= 400,
                "summarizeError({name}) output is {} bytes",
                got.len()
            );
        }
    }

    // Ported from Go `TestBotScrubbedErrorTokenFreeAtObjectLevel`,
    // first 3 subcases (TMR / sentinel-wrap / Migrate). The
    // 4th subcase needs the fake Telegram HTTP server and
    // `Send`, and the `isParseError` assertion needs the
    // retry layer — both excluded as Go-only; see PORTING.md.
    #[test]
    fn test_scrubbed_error_token_free_at_object_level() {
        // 429 path: typed copy carries the scrubbed message
        // and RetryAfter; the kind must still be found.
        let tmr = chain(ChainLevel {
            text: format!("too many requests, {TOKEN}: retry_after 5"),
            kind: LevelKind::TooManyRequests {
                message: format!("too many requests, {TOKEN}"),
                retry_after: 5,
            },
            children: vec![],
        });
        let scrubbed = scrub_chain(Some(&tmr), TOKEN).expect("scrubbed TMR");
        assert!(
            !format!("{scrubbed:?}").contains(TOKEN),
            "scrubbed TMR Debug contains the token"
        );
        assert!(!scrubbed.root.text.contains(TOKEN));
        assert_eq!(scrubbed.root.children.len(), 1);
        match &scrubbed.root.children[0].kind {
            LevelKind::TooManyRequests {
                message,
                retry_after,
            } => {
                assert_eq!(*retry_after, 5);
                assert!(!message.contains(TOKEN));
            }
            other => panic!("scrubbed TMR child kind = {other:?}, want TooManyRequests"),
        }
        assert_eq!(
            classify_error(Some(&scrubbed), TOKEN),
            ErrorClass::TooManyRequests
        );

        // 400 path: the BadRequest sentinel survives scrubbing.
        let bad = chain(wrap(
            &format!("bad request, Bad Request: can't parse entities: {TOKEN}"),
            sentinel("bad request", SentinelKind::BadRequest),
        ));
        let scrubbed_bad = scrub_chain(Some(&bad), TOKEN).expect("scrubbed 400");
        assert!(
            !format!("{scrubbed_bad:?}").contains(TOKEN),
            "scrubbed 400 Debug contains the token"
        );
        assert!(
            scrubbed_bad
                .root
                .children
                .iter()
                .any(|c| matches!(c.kind, LevelKind::Sentinel(SentinelKind::BadRequest)))
        );
        assert_eq!(
            classify_error(Some(&scrubbed_bad), TOKEN),
            ErrorClass::BadRequest
        );

        // Migrate path: typed fields scrubbed, id preserved.
        let mig = chain(ChainLevel {
            text: format!("migrate: {TOKEN}: migrate_to_chat_id 42"),
            kind: LevelKind::Migrate {
                message: format!("migrate: {TOKEN}"),
                migrate_to_chat_id: 42,
            },
            children: vec![],
        });
        let scrubbed_mig = scrub_chain(Some(&mig), TOKEN).expect("scrubbed Migrate");
        assert!(
            !format!("{scrubbed_mig:?}").contains(TOKEN),
            "scrubbed Migrate Debug contains the token"
        );
        assert_eq!(scrubbed_mig.root.children.len(), 1);
        match &scrubbed_mig.root.children[0].kind {
            LevelKind::Migrate {
                migrate_to_chat_id, ..
            } => assert_eq!(*migrate_to_chat_id, 42),
            other => panic!("scrubbed Migrate child kind = {other:?}, want Migrate"),
        }
    }

    // PROBE tests (not ported cases): unpinned edges of the
    // chain model, labelled as probes per D-scope-note.

    /// A chain of `depths` plain levels; the deepest level
    /// carries `leaf_kind`/`leaf_text`. Root depth = 0.
    fn deep_chain(depths: usize, leaf_kind: LevelKind, leaf_text: &str) -> ErrorChain {
        let mut level = ChainLevel::leaf(leaf_text, leaf_kind);
        for d in (0..depths).rev() {
            level = ChainLevel::plain(&format!("wrap {d}"), vec![level]);
        }
        ErrorChain { root: level }
    }

    // PROBE: the 32-level cap applies to the anchored
    // decode/HTTP passes only. A decode marker at depth 32
    // is inspected; at depth 33 it is not. Step-1 kinds are
    // NOT depth-capped (Go errors.As walks the whole chain).
    #[test]
    fn probe_chain_depth_cap() {
        let marker =
            "error decode response body for method getUpdates, unexpected end of JSON input";
        assert_eq!(
            classify_error(Some(&deep_chain(32, LevelKind::Plain, marker)), TOKEN),
            ErrorClass::ResponseDecodeFailure,
            "decode marker at depth 32"
        );
        assert_eq!(
            classify_error(Some(&deep_chain(33, LevelKind::Plain, marker)), TOKEN),
            ErrorClass::Unclassified,
            "decode marker at depth 33"
        );
        assert_eq!(
            classify_error(
                Some(&deep_chain(
                    40,
                    LevelKind::Sentinel(SentinelKind::Forbidden),
                    "forbidden"
                )),
                TOKEN
            ),
            ErrorClass::Forbidden,
            "sentinel at depth 40 (step 1 is uncapped)"
        );
    }

    // PROBE: step precedence on synthetic chains — a
    // shallower step always beats a deeper earlier-step
    // class, even when the deeper class is textually first.
    #[test]
    fn probe_chain_step_order_synthetics() {
        // Step 1 beats step 2: decode marker at the root,
        // sentinel deeper.
        let c = chain(wrap(
            "error decode response body for method getUpdates, x",
            sentinel("bad request", SentinelKind::BadRequest),
        ));
        assert_eq!(classify_error(Some(&c), TOKEN), ErrorClass::BadRequest);
        // Step 4 beats step 5: HTTP marker at the root,
        // DNS deeper.
        let c = chain(wrap(
            "error response from telegram for method getUpdates, 500 Internal Server Error",
            ChainLevel::leaf("lookup api.telegram.org: no such host", LevelKind::DnsError),
        ));
        assert_eq!(classify_error(Some(&c), TOKEN), ErrorClass::Dns);
        // Step 3 beats step 4: context deeper than DNS.
        let c = chain(wrap(
            "dial: no route to host",
            ChainLevel::leaf("context canceled", LevelKind::ContextCanceled),
        ));
        // NOTE: the root carries no kind here, so step 3
        // finds the context child before step 4's errno
        // group — the errno here is only root TEXT, not a
        // typed level, so DNS/transport finds nothing.
        assert_eq!(classify_error(Some(&c), TOKEN), ErrorClass::ContextCanceled);
        // Step-1 order: TMR sentinel beats Migrate.
        let c = chain(ChainLevel::plain(
            "x",
            vec![
                ChainLevel {
                    text: "m: migrate_to_chat_id 1".to_string(),
                    kind: LevelKind::Migrate {
                        message: "m".to_string(),
                        migrate_to_chat_id: 1,
                    },
                    children: vec![],
                },
                sentinel("too many requests", SentinelKind::TooManyRequests),
            ],
        ));
        assert_eq!(classify_error(Some(&c), TOKEN), ErrorClass::TooManyRequests);
    }

    // PROBE: DFS order inside the anchored pass — the root
    // level's marker wins over a deeper level's marker.
    #[test]
    fn probe_chain_anchored_dfs_order() {
        let c = chain(wrap(
            "error decode update, x",
            plain("error decode response body for method getUpdates, x"),
        ));
        assert_eq!(
            classify_error(Some(&c), TOKEN),
            ErrorClass::UpdateDecodeFailure
        );
    }

    // PROBE: unpinned-but-implemented transport kinds and
    // HTTP branches.
    #[test]
    fn probe_chain_unpinned_branches() {
        let host_down = chain(wrap(
            "dial: host is down",
            ChainLevel::leaf("host is down", LevelKind::Errno(ErrnoKind::HostDown)),
        ));
        assert_eq!(
            classify_error(Some(&host_down), TOKEN),
            ErrorClass::Unreachable
        );
        let net_down = chain(wrap(
            "dial: network is down",
            ChainLevel::leaf("network is down", LevelKind::Errno(ErrnoKind::NetDown)),
        ));
        assert_eq!(
            classify_error(Some(&net_down), TOKEN),
            ErrorClass::Unreachable
        );
        // Non-4/5 first digit: no HTTP class, falls through
        // to the fallback (unclassified for this text).
        let redirect = chain(plain(
            "error response from telegram for method getUpdates, 302 Found",
        ));
        assert_eq!(
            classify_error(Some(&redirect), TOKEN),
            ErrorClass::Unclassified
        );
        // Short rest after ", ": the code slice is
        // unavailable, so no HTTP class.
        let short = chain(plain(
            "error response from telegram for method getUpdates, 5",
        ));
        assert_eq!(
            classify_error(Some(&short), TOKEN),
            ErrorClass::Unclassified
        );
    }

    // FIX-LOOP REGRESSION (Round 1 finding F1, typed path;
    // not a ported case): a multibyte char in the HTTP
    // code window must classify as unclassified through
    // `classify_error`, never panic.
    #[test]
    fn regression_f1_multibyte_http_via_classify() {
        let c = chain(plain("error response from telegram for method ab, éé"));
        assert_eq!(classify_error(Some(&c), TOKEN), ErrorClass::Unclassified);
    }

    // FIX-LOOP REGRESSION (Round 1 finding F3a; not a
    // ported case): Go `transportClass` checks only the
    // FIRST `*url.Error`'s inner text. A hiding-wrapper
    // outer UrlError over a TLS inner must stay
    // unclassified; deeper UrlError levels are never
    // consulted.
    #[test]
    fn regression_f3a_first_url_error_only() {
        let inner_url = ChainLevel {
            text: "hiding wrapper".to_string(),
            kind: LevelKind::UrlError,
            children: vec![plain("tls: bad certificate")],
        };
        let root = ChainLevel {
            text: "outer".to_string(),
            kind: LevelKind::UrlError,
            children: vec![inner_url],
        };
        let c = chain(root);
        assert_eq!(classify_error(Some(&c), TOKEN), ErrorClass::Unclassified);
    }

    // FIX-LOOP REGRESSION (Round 1 finding F3b; not a
    // ported case): Go `scrubErr` via `errors.As` keeps the
    // FIRST match in pre-order DFS. With two TMR children
    // (and, separately, two Migrate children), the scrubbed
    // chain must preserve the first, not the last.
    #[test]
    fn regression_f3b_scrub_keeps_first_match() {
        let tmr_a = ChainLevel {
            text: "msg A".to_string(),
            kind: LevelKind::TooManyRequests {
                message: "msg A".to_string(),
                retry_after: 1,
            },
            children: vec![],
        };
        let tmr_b = ChainLevel {
            text: "msg B".to_string(),
            kind: LevelKind::TooManyRequests {
                message: "msg B".to_string(),
                retry_after: 2,
            },
            children: vec![],
        };
        let c = chain(ChainLevel::plain("x", vec![tmr_a, tmr_b]));
        let scrubbed = scrub_chain(Some(&c), TOKEN).expect("scrub_chain of Some");
        assert_eq!(scrubbed.root.children.len(), 1);
        match &scrubbed.root.children[0].kind {
            LevelKind::TooManyRequests {
                message,
                retry_after,
            } => {
                assert_eq!(message, "msg A");
                assert_eq!(*retry_after, 1);
            }
            other => panic!("scrubbed child kind = {other:?}, want TooManyRequests A/1"),
        }

        let mig_a = ChainLevel {
            text: "mig A".to_string(),
            kind: LevelKind::Migrate {
                message: "mig A".to_string(),
                migrate_to_chat_id: 10,
            },
            children: vec![],
        };
        let mig_b = ChainLevel {
            text: "mig B".to_string(),
            kind: LevelKind::Migrate {
                message: "mig B".to_string(),
                migrate_to_chat_id: 20,
            },
            children: vec![],
        };
        let c = chain(ChainLevel::plain("x", vec![mig_a, mig_b]));
        let scrubbed = scrub_chain(Some(&c), TOKEN).expect("scrub_chain of Some");
        assert_eq!(scrubbed.root.children.len(), 1);
        match &scrubbed.root.children[0].kind {
            LevelKind::Migrate {
                message,
                migrate_to_chat_id,
            } => {
                assert_eq!(message, "mig A");
                assert_eq!(*migrate_to_chat_id, 10);
            }
            other => panic!("scrubbed child kind = {other:?}, want Migrate A/10"),
        }
    }

    // FIX-LOOP REGRESSION (Round 1 finding F5, hardening;
    // not a ported case): `Debug` of an UNSCRUBBED chain must
    // never emit raw message text (e.g. a token). Only
    // lengths/kinds may appear.
    #[test]
    fn regression_f5_debug_never_prints_raw_text() {
        let c = chain(ChainLevel {
            text: format!("error carrying {TOKEN}"),
            kind: LevelKind::TooManyRequests {
                message: format!("server said {TOKEN}"),
                retry_after: 5,
            },
            children: vec![plain(&format!("child {TOKEN}"))],
        });
        let debug = format!("{c:?}");
        assert!(
            !debug.contains(TOKEN),
            "unscrubbed chain Debug leaked the token: {debug}"
        );
        let level_debug = format!("{:?}", c.root);
        assert!(
            !level_debug.contains(TOKEN),
            "unscrubbed level Debug leaked the token: {level_debug}"
        );
    }
}
