//! String-only error summarisation, ported from Go
//! `internal/telegram/bot.go` (`summarize`, `summarizeClass`,
//! `formatSummary`, `fallbackClass`, `anchoredDecodeClass`,
//! `httpClassFromPrefix`, `isTLSFailure`).
//!
//! Security invariant: output contains ONLY fixed-vocabulary
//! labels plus a rune count. Raw server/peer body text must
//! NEVER reach output — no preview/snippet variant exists.
//! `fallback_class` deliberately never matches decode
//! phrases; only the anchored chain check selects a decode
//! class (see `chain.rs`).

use crate::safe_string::go_lower;

/// How much of an error text classification ever inspects.
/// Source: `internal/telegram/bot.go`, `summarizePrefixRunes`.
pub const SUMMARIZE_PREFIX_RUNES: usize = 256;

/// The 20 summary classes, with Go's exact label spellings.
/// Source: `internal/telegram/bot.go`, `classifyError` /
/// `fallbackClass` / `summarizeClass` labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorClass {
    /// Too many requests (429).
    TooManyRequests,
    /// Bad request (400).
    BadRequest,
    /// Forbidden (403).
    Forbidden,
    /// Unauthorized (401).
    Unauthorized,
    /// Not found (404).
    NotFound,
    /// Conflict (409).
    Conflict,
    /// Response body/result decode failure.
    ResponseDecodeFailure,
    /// Update decode failure.
    UpdateDecodeFailure,
    /// Timeout.
    Timeout,
    /// DNS failure.
    Dns,
    /// TLS failure.
    Tls,
    /// Connection refused.
    ConnectionRefused,
    /// Connection reset.
    ConnectionReset,
    /// Unreachable host/network.
    Unreachable,
    /// EOF / unexpected EOF.
    Eof,
    /// Context canceled.
    ContextCanceled,
    /// Context deadline exceeded.
    ContextDeadlineExceeded,
    /// HTTP 5xx status format.
    Http5xx,
    /// HTTP 4xx status format.
    Http4xx,
    /// No class matched.
    Unclassified,
}

impl ErrorClass {
    /// Go's fixed-vocabulary label for this class.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            ErrorClass::TooManyRequests => "too many requests",
            ErrorClass::BadRequest => "bad request",
            ErrorClass::Forbidden => "forbidden",
            ErrorClass::Unauthorized => "unauthorized",
            ErrorClass::NotFound => "not found",
            ErrorClass::Conflict => "conflict",
            ErrorClass::ResponseDecodeFailure => "response decode failure",
            ErrorClass::UpdateDecodeFailure => "update decode failure",
            ErrorClass::Timeout => "timeout",
            ErrorClass::Dns => "dns",
            ErrorClass::Tls => "tls",
            ErrorClass::ConnectionRefused => "connection refused",
            ErrorClass::ConnectionReset => "connection reset",
            ErrorClass::Unreachable => "unreachable",
            ErrorClass::Eof => "eof",
            ErrorClass::ContextCanceled => "context canceled",
            ErrorClass::ContextDeadlineExceeded => "context deadline exceeded",
            ErrorClass::Http5xx => "http 5xx",
            ErrorClass::Http4xx => "http 4xx",
            ErrorClass::Unclassified => "unclassified",
        }
    }
}

impl std::fmt::Display for ErrorClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

/// First `n` runes of `s` without scanning the rest.
/// Source: `internal/telegram/bot.go`, `firstRunes`.
pub fn first_runes(s: &str, n: usize) -> &str {
    match s.char_indices().nth(n) {
        Some((i, _)) => &s[..i],
        None => s,
    }
}

/// Removes every occurrence of `token` from `s`. An empty
/// token leaves `s` unchanged (Go `strings.ReplaceAll` with
/// an empty old string would be a no-op here because the Bot
/// token is never empty in practice; the guard also avoids
/// Rust `str::replace` inserting at every boundary).
/// Source: `internal/telegram/bot.go`, `Bot::scrub`.
pub fn scrub_text(s: &str, token: &str) -> String {
    if token.is_empty() {
        return s.to_string();
    }
    s.replace(token, "***")
}

/// Renders one class/length summary. The decode classes keep
/// the historical `"telegram poll error:"` prefix; every other
/// class uses `"telegram error:"`.
/// Source: `internal/telegram/bot.go`, `formatSummary`.
pub fn format_summary(class: ErrorClass, length: usize) -> String {
    match class {
        ErrorClass::ResponseDecodeFailure | ErrorClass::UpdateDecodeFailure => {
            format!(
                "telegram poll error: {} message_length={}",
                class.label(),
                length
            )
        }
        _ => format!(
            "telegram error: {} message_length={}",
            class.label(),
            length
        ),
    }
}

/// Whether the prefix is one of the library's body-carrying
/// errors (substring match, case-sensitive).
/// Source: `internal/telegram/bot.go`, `isResponseBodyError`.
fn is_response_body_error(prefix: &str) -> bool {
    prefix.contains("decode response body")
        || prefix.contains("read response body")
        || prefix.contains("decode response result")
}

/// String-only classification: substring search in the
/// prefix, case-sensitive. Kept only for callers with no
/// error value (panic values); the typed path in `chain.rs`
/// refuses bare-substring decode matches.
/// Source: `internal/telegram/bot.go`, `summarizeClass`.
pub fn summarize_class(prefix: &str) -> ErrorClass {
    if is_response_body_error(prefix) {
        return ErrorClass::ResponseDecodeFailure;
    }
    if prefix.contains("decode update") {
        return ErrorClass::UpdateDecodeFailure;
    }
    for (phrase, class) in [
        ("too many requests", ErrorClass::TooManyRequests),
        ("bad request", ErrorClass::BadRequest),
        ("forbidden", ErrorClass::Forbidden),
        ("unauthorized", ErrorClass::Unauthorized),
        ("not found", ErrorClass::NotFound),
        ("conflict", ErrorClass::Conflict),
    ] {
        if prefix.contains(phrase) {
            return class;
        }
    }
    ErrorClass::Unclassified
}

/// Renders a bare message string as a class/length summary:
/// scrub the first 256 runes, classify the scrubbed prefix
/// with the string-only rules, count the runes of the whole
/// message. Scrubbing happens AFTER truncation.
/// Source: `internal/telegram/bot.go`, `Bot::summarize`.
pub fn summarize(msg: &str, token: &str) -> String {
    let class = summarize_class(&scrub_text(first_runes(msg, SUMMARIZE_PREFIX_RUNES), token));
    format_summary(class, msg.chars().count())
}

/// The string fallback for errors with no usable chain.
/// Decode phrases are deliberately never matched here.
/// Order is most specific first; `context deadline exceeded`
/// precedes generic `deadline exceeded`, and the bare `dns`
/// catch-all comes after the specific DNS phrases.
/// Source: `internal/telegram/bot.go`, `fallbackClass`.
pub fn fallback_class(prefix: &str) -> ErrorClass {
    let lower = go_lower(prefix);
    for (phrase, class) in [
        ("too many requests", ErrorClass::TooManyRequests),
        ("bad request", ErrorClass::BadRequest),
        ("forbidden", ErrorClass::Forbidden),
        ("unauthorized", ErrorClass::Unauthorized),
        ("not found", ErrorClass::NotFound),
        ("conflict", ErrorClass::Conflict),
        (
            "context deadline exceeded",
            ErrorClass::ContextDeadlineExceeded,
        ),
        ("context canceled", ErrorClass::ContextCanceled),
        ("connection refused", ErrorClass::ConnectionRefused),
        ("connection reset", ErrorClass::ConnectionReset),
        ("no route to host", ErrorClass::Unreachable),
        ("host unreachable", ErrorClass::Unreachable),
        ("network unreachable", ErrorClass::Unreachable),
        ("network is unreachable", ErrorClass::Unreachable),
        ("no such host", ErrorClass::Dns),
        ("name resolution", ErrorClass::Dns),
        ("server misbehaving", ErrorClass::Dns),
        ("dns", ErrorClass::Dns),
        ("connection timed out", ErrorClass::Timeout),
        ("timed out", ErrorClass::Timeout),
        ("deadline exceeded", ErrorClass::Timeout),
        ("timeout", ErrorClass::Timeout),
        ("tls:", ErrorClass::Tls),
        ("certificate", ErrorClass::Tls),
        ("handshake", ErrorClass::Tls),
        ("unexpected eof", ErrorClass::Eof),
        (" eof", ErrorClass::Eof),
    ] {
        if lower.contains(phrase) {
            return class;
        }
    }
    if lower == "eof" {
        return ErrorClass::Eof;
    }
    ErrorClass::Unclassified
}

/// The decode class for one chain level's bounded prefix, or
/// `None`. The marker must START the level's text.
/// Source: `internal/telegram/bot.go`, `anchoredDecodeClass`.
pub fn anchored_decode_class(prefix: &str) -> Option<ErrorClass> {
    if prefix.starts_with("error decode response body")
        || prefix.starts_with("error decode response result")
        || prefix.starts_with("error read response body")
    {
        Some(ErrorClass::ResponseDecodeFailure)
    } else if prefix.starts_with("error decode update") {
        Some(ErrorClass::UpdateDecodeFailure)
    } else {
        None
    }
}

/// The HTTP class for one chain level's bounded prefix, or
/// `None`. Only the library's default-branch format, with the
/// status code parsed from its anchored position.
/// Source: `internal/telegram/bot.go`, `httpClassFromPrefix`.
pub fn http_class_from_prefix(prefix: &str) -> Option<ErrorClass> {
    const MARKER: &str = "error response from telegram for method ";
    let rest = prefix.strip_prefix(MARKER)?;
    let i = rest.find(", ")?;
    if rest.len() < i + 5 {
        return None;
    }
    let code = &rest[i + 2..i + 5];
    if !code.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    match code.as_bytes()[0] {
        b'4' => Some(ErrorClass::Http4xx),
        b'5' => Some(ErrorClass::Http5xx),
        _ => None,
    }
}

/// Whether the inner error text of a `*url.Error` marks a TLS
/// failure: the lowercased first 256 runes contain `tls:` or
/// `certificate`.
/// Source: `internal/telegram/bot.go`, `isTLSFailure`.
pub fn is_tls_failure_text(inner_text: &str) -> bool {
    let prefix = go_lower(first_runes(inner_text, SUMMARIZE_PREFIX_RUNES));
    prefix.contains("tls:") || prefix.contains("certificate")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Invented 32-char placeholder token for the Rust tests
    /// (same length as the Go fixture token, so measured rune
    /// counts reproduce; a DIFFERENT value — never the Go
    /// fixture). Used only inside test inputs.
    const TOKEN: &str = "RUSTFIX-TOKEN-PLACEHOLDER-012345";

    #[test]
    fn placeholder_token_length() {
        // PROBE (not a ported case): the placeholder must be
        // 32 chars so G1-measured rune counts reproduce.
        assert_eq!(TOKEN.chars().count(), 32);
    }

    // Ported from Go `TestSummarizeNeverEmitsServerText`
    // (5 inputs; the fake-server `newTestBot` setup is not
    // needed — `summarize` is the string API under test).
    #[test]
    fn test_summarize_never_emits_server_text() {
        let cases: [(&str, String, &str); 5] = [
            ("short description", format!("bad request, R6D-SHORT-MARKER {TOKEN}"), "R6D-SHORT-MARKER"),
            ("short decode update", r#"error decode update 42, skipped, {"update_id":42,"message":"R6D-DECODE-MARKER"}: cannot unmarshal"#.to_string(), "R6D-DECODE-MARKER"),
            ("long description", format!("bad request, {}", "R6D-LONG-MARKER-".repeat(1500)), "R6D-LONG-MARKER-"),
            ("long decode update", format!("error decode update 42, skipped, {}", "R6D-LONG-UPDATE-".repeat(1500)), "R6D-LONG-UPDATE-"),
            ("long arbitrary", "R6D-GENERIC-".repeat(5000), "R6D-GENERIC-"),
        ];
        for (name, input, absent) in cases {
            let got = summarize(&input, TOKEN);
            assert!(
                !got.contains(absent),
                "{name}: summarize kept a server fragment in {got:?}"
            );
            assert!(
                !got.contains(TOKEN),
                "{name}: summarize kept the fixture token"
            );
            assert!(
                got.len() <= 400,
                "{name}: summarize output is {} bytes; want length-bounded",
                got.len()
            );
            assert!(
                got.contains("message_length="),
                "{name}: summarize output {got:?} lacks message_length="
            );
        }
    }

    // Ported from Go `TestSummarizeHostileBodyBoundedWork`
    // (one 5MB input; the <10s bound is a probe-grade
    // assertion kept as written in Go).
    #[test]
    fn test_summarize_hostile_body_bounded_work() {
        let input = "R6D-CPU-MARKER-".repeat(350_000);
        let start = std::time::Instant::now();
        let got = summarize(&input, TOKEN);
        assert!(
            start.elapsed() < std::time::Duration::from_secs(10),
            "summarize(5MB) took {:?}",
            start.elapsed()
        );
        assert!(
            !got.contains("R6D-CPU-MARKER-"),
            "summarize kept a server fragment from a 5MB input"
        );
        assert!(
            got.len() <= 400,
            "summarize(5MB) output is {} bytes",
            got.len()
        );
        assert!(
            got.contains("message_length="),
            "summarize(5MB) output lacks message_length="
        );
    }

    // Ported from Go `TestSummarizeUnclassifiedFallback`
    // (2 exact strings).
    #[test]
    fn test_summarize_unclassified_fallback() {
        for input in ["totally unknown shape", ""] {
            let got = summarize(input, TOKEN);
            let want = format!(
                "telegram error: unclassified message_length={}",
                input.chars().count()
            );
            assert_eq!(got, want, "summarize({input:?})");
            assert!(
                !got.contains("telegram error: message_length="),
                "summarize({input:?}) emitted the old labelless shape {got:?}"
            );
        }
    }

    // Ported from Go `TestSummarizeLoop4NoMethodField`
    // (4 inputs). Pins the string/typed split: the string
    // path keeps the legacy substring behaviour, so a
    // decode-body phrase anywhere in the prefix selects the
    // decode class — no method= field is ever emitted.
    #[test]
    fn test_summarize_loop4_no_method_field() {
        let cases: [(&str, String, &str); 4] = [
            (
                "identifier",
                "failed to decode response body for method L4D1IDENT, retry".to_string(),
                "L4D1IDENT",
            ),
            (
                "capped",
                format!(
                    "failed to decode response body for method L4D1CAP{}, retry",
                    "X".repeat(44)
                ),
                "L4D1CAP",
            ),
            (
                "token digits",
                "failed to decode response body for method 123456, retry".to_string(),
                "123456",
            ),
            (
                "misclassifying phrase",
                "bad request, decode response body for method L4D1MISCLASS, bad".to_string(),
                "L4D1MISCLASS",
            ),
        ];
        for (name, input, absent) in cases {
            let got = summarize(&input, TOKEN);
            assert!(
                !got.contains("method="),
                "{name}: summarize emitted a method= field in {got:?}"
            );
            assert!(
                !got.contains(absent),
                "{name}: summarize kept the injected fragment in {got:?}"
            );
            assert!(
                !got.contains(TOKEN),
                "{name}: summarize kept the fixture token"
            );
            assert!(
                got.starts_with("telegram poll error: response decode failure message_length="),
                "{name}: summarize = {got:?}"
            );
            assert!(
                got.len() <= 400,
                "{name}: summarize output is {} bytes",
                got.len()
            );
        }
    }

    // PROBE (not a ported case): the empty-token scrub guard.
    // Rust `str::replace` with an empty pattern inserts at
    // every boundary; `scrub_text` must return the input
    // unchanged instead, as Go does.
    #[test]
    fn probe_scrub_empty_token_guard() {
        assert_eq!(scrub_text("abc", ""), "abc");
        assert_eq!(scrub_text("", ""), "");
        assert_eq!(scrub_text("aXbXc", "X"), "a***b***c");
    }
}
