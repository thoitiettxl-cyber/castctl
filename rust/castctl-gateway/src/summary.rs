// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Allowlist summary of a server/peer response body — port of
//! `internal/gateway/summary.go`.
//!
//! A response body is NEVER emitted anywhere (no error string,
//! no log line, no stderr typed JSON). Producers replace every
//! body emission with the CLOSED allowlist summary built here:
//! the class label (a producer constant), the wire body length
//! (when known), the structured content-type (part before `;`,
//! validated), and specific known-safe fields parsed BY KEY
//! from known Muse response schemas, each length-capped AND
//! enum-gated. The parsed-by-key list is CLOSED: `error`,
//! `status`, `reason` — no other key is ever extracted, in
//! particular `detail`, `message`, and `code` are never
//! extracted here.
//!
//! Two renderings come out of one summary: the TEXT (for an
//! AuthError message, where Go's `GatewayError.Error()` text
//! is the Payload) and the STRUCTURED fields (for a
//! `TransportError::Gateway` — the transport `BodySummary`,
//! whose `render()` reproduces Go's `GatewayError.Error()`
//! shape). The text content-type is Go-exact (case preserved,
//! `|`/`~` allowed); the structured content-type goes through
//! the transport validator (lowercased, `|`/`~` dropped) — see
//! PORTING.md §M4b. The `Payload` text itself is NOT kept on
//! the structured error (Go's `Error()` never prints it either
//! — only the summary text is printed, via the structured
//! fields); the VM-unavailable case is carried by the
//! `error_code: Some("vm_unavailable")` marker instead, which
//! the CLI maps to typed `session_unavailable`.

use castctl_transport::BodySummary;
use castctl_transport::error::{validate_content_type, validate_error_code};

/// Cap for every extracted allowlist value, in runes.
/// 64 runes holds any short error enum or media type with
/// headroom; anything longer is not an enum.
pub const ALLOWLIST_VALUE_CAP: usize = 64;

/// Replaces an extracted value that cannot be emitted safely
/// (wrong shape, wrong type, over cap). Carries no body bytes.
pub const ALLOWLIST_OMITTED: &str = "[omitted]";

/// One allowlist summary: the text for a Payload/Message
/// field, the wire body length, whether that length is known,
/// and the structured fields for GatewayError rendering.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Summary {
    /// Summary text, e.g. `api error; body_length=27;
    /// content_type=application/json; error=denied`.
    pub text: String,
    /// Wire body length (bytes), when known.
    pub length: usize,
    /// Whether `length` is known at all. Renderers omit the
    /// `body_length` field entirely when it is unknown, never
    /// falling back to the summary-text length.
    pub length_known: bool,
    /// Validated content-type (`""` when absent or omitted).
    pub content_type: String,
    /// Extracted `error` enum (`""` when absent or omitted).
    pub error_code: String,
}

/// The field name used in the summary text for each closed key.
fn field_name(key: &str) -> Option<&'static str> {
    match key {
        "error" => Some("error"),
        "status" => Some("body_status"),
        "reason" => Some("reason"),
        _ => None,
    }
}

/// Reports whether `s` is an emittable short enum: non-empty,
/// at most [`ALLOWLIST_VALUE_CAP`] runes, letters, digits,
/// underscore, dot, or hyphen only. Anything else (spaces,
/// quotes, slashes, unicode prose) is free text and must not
/// be emitted.
pub fn is_enum_value(s: &str) -> bool {
    let mut n = 0;
    for r in s.chars() {
        n += 1;
        if n > ALLOWLIST_VALUE_CAP {
            return false;
        }
        if !(r.is_ascii_alphanumeric() || r == '_' || r == '.' || r == '-') {
            return false;
        }
    }
    n > 0
}

/// Renders one allowlisted value: an emittable short enum
/// passes through; anything else (free text, numeric,
/// composite, over cap) becomes the placeholder, never
/// emitted truncated.
pub fn gate_allowlist_value(v: Option<&serde_json::Value>) -> String {
    match v {
        Some(serde_json::Value::String(s)) if is_enum_value(s) => s.clone(),
        _ => ALLOWLIST_OMITTED.to_string(),
    }
}

/// Extracts one allowlisted field from a decoded response
/// map. `None` means the key is not in the closed list or is
/// absent from the map: nothing is emitted for it. `Some`
/// with the placeholder means the key was present but its
/// value is not an emittable enum.
pub fn extract_allowlist_field(
    decoded: Option<&serde_json::Map<String, serde_json::Value>>,
    key: &str,
) -> Option<String> {
    field_name(key)?;
    let decoded = decoded?;
    let v = decoded.get(key)?;
    Some(gate_allowlist_value(Some(v)))
}

/// Reduces a raw Content-Type header value to its structured
/// media type: the part before the first `;` (parameters
/// dropped), trimmed. `""` means no header was present
/// (nothing emitted). A present-but-invalid value (over cap,
/// whitespace/control characters, no slash, empty side)
/// becomes the placeholder.
pub fn summarize_content_type(raw: &str) -> String {
    if raw.is_empty() {
        return String::new();
    }
    let ct = raw.split(';').next().unwrap_or("").trim();
    if ct.is_empty() || ct.chars().count() > ALLOWLIST_VALUE_CAP {
        return ALLOWLIST_OMITTED.to_string();
    }
    // Byte indices, like Go's strings.IndexByte / len.
    match ct.find('/') {
        Some(i) if i > 0 && i < ct.len() - 1 && ct.matches('/').count() == 1 => {}
        _ => return ALLOWLIST_OMITTED.to_string(),
    }
    for r in ct.chars() {
        if !(r.is_ascii_alphanumeric()
            || matches!(
                r,
                '!' | '#' | '$' | '&' | '^' | '_' | '.' | '+' | '-' | '|' | '~' | '/'
            ))
        {
            return ALLOWLIST_OMITTED.to_string();
        }
    }
    ct.to_string()
}

/// Builds the allowlist summary for one response body.
/// `label` is the producer's constant class label (never
/// body-derived). `data` is the wire body (`None` when the
/// producer has no body bytes — then no `body_length` field
/// is emitted; `Some(&[])` is a known 0-byte body).
/// `raw_content_type` is the response's Content-Type header
/// value, `""` when unknown. `decoded` is the decoded JSON
/// body when the producer parsed one, `None` otherwise;
/// `keys` names the allowlisted keys to extract from it
/// (unknown keys are ignored).
pub fn summarize_body(
    label: &str,
    data: Option<&[u8]>,
    raw_content_type: &str,
    decoded: Option<&serde_json::Map<String, serde_json::Value>>,
    keys: &[&str],
) -> Summary {
    let (length, known) = match data {
        Some(b) => (b.len(), true),
        None => (0, false),
    };
    summarize_fields(label, length, known, raw_content_type, decoded, keys)
}

/// Builds the allowlist summary for a parsed result whose
/// wire body length is known but whose bytes are not retained
/// (the RSC case in FetchSubscription): `body_length` is
/// always the wire length threaded through callAction, never
/// the summary-text length. A known 0-byte body renders
/// `body_length=0`, an unknown length renders no
/// `body_length` field.
pub fn summarize_parsed_body(
    label: &str,
    body_len: usize,
    body_len_known: bool,
    decoded: Option<&serde_json::Map<String, serde_json::Value>>,
    keys: &[&str],
) -> Summary {
    summarize_fields(label, body_len, body_len_known, "", decoded, keys)
}

/// Builds the allowlist summary for a stream reset frame:
/// the reset code (a number) and the byte length of the
/// peer-controlled reason — never the reason bytes.
pub fn reset_summary(code: i32, reason: &str) -> Summary {
    Summary {
        text: format!("stream reset; code={code}; reason_length={}", reason.len()),
        length: reason.len(),
        length_known: true,
        content_type: String::new(),
        error_code: String::new(),
    }
}

/// Builds a transport [`BodySummary`] from an allowlist
/// summary: the wire length the summary measured (only when
/// known), the validated content-type / error-enum fields for
/// rendering. The Payload text itself is not kept (see the
/// module docs).
pub fn summary_to_body_summary(status: i32, sum: &Summary) -> BodySummary {
    BodySummary {
        status,
        body_length: if sum.length_known {
            Some(sum.length)
        } else {
            None
        },
        content_type: if sum.content_type.is_empty() {
            None
        } else {
            validate_content_type(&sum.content_type)
        },
        error_code: if sum.error_code.is_empty() {
            None
        } else {
            validate_error_code(&sum.error_code)
        },
    }
}

/// Shared allowlist-summary builder: the class label, the
/// wire body length (when known — `emit_length` IS the known
/// flag), the validated content-type, and the parsed-by-key
/// fields.
fn summarize_fields(
    label: &str,
    length: usize,
    emit_length: bool,
    raw_content_type: &str,
    decoded: Option<&serde_json::Map<String, serde_json::Value>>,
    keys: &[&str],
) -> Summary {
    let mut text = String::from(label);
    if emit_length {
        text.push_str(&format!("; body_length={length}"));
    }
    let mut content_type = String::new();
    if !raw_content_type.is_empty() {
        let ct = summarize_content_type(raw_content_type);
        if ct != ALLOWLIST_OMITTED {
            content_type = ct.clone();
        }
        text.push_str(&format!("; content_type={ct}"));
    }
    let mut error_code = String::new();
    for key in keys {
        let Some(value) = extract_allowlist_field(decoded, key) else {
            continue;
        };
        // `field_name` is Some whenever the field was found:
        // extraction already checked the closed list.
        let field = field_name(key).unwrap_or(key);
        text.push_str(&format!("; {field}={value}"));
        if *key == "error" && value != ALLOWLIST_OMITTED {
            error_code = value;
        }
    }
    Summary {
        text,
        length,
        length_known: emit_length,
        content_type,
        error_code,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn map(v: serde_json::Value) -> serde_json::Map<String, serde_json::Value> {
        match v {
            serde_json::Value::Object(m) => m,
            _ => panic!("not an object"),
        }
    }

    #[test]
    fn extract_allowlist_field_cases() {
        // Port of Go TestExtractAllowlistField (summary_test.go).
        let cap64 = "a".repeat(64);
        let cases: Vec<(&str, Option<serde_json::Value>, &str, Option<&str>)> = vec![
            (
                "error enum",
                Some(json!({"error": "denied"})),
                "error",
                Some("denied"),
            ),
            (
                "error free text",
                Some(json!({"error": "rate limited"})),
                "error",
                Some("[omitted]"),
            ),
            (
                "error over cap",
                Some(json!({"error": "a".repeat(65)})),
                "error",
                Some("[omitted]"),
            ),
            (
                "error at cap",
                Some(json!({"error": "a".repeat(64)})),
                "error",
                Some(cap64.as_str()),
            ),
            (
                "error numeric",
                Some(json!({"error": 123})),
                "error",
                Some("[omitted]"),
            ),
            (
                "error object",
                Some(json!({"error": {"x": 1}})),
                "error",
                Some("[omitted]"),
            ),
            (
                "status enum",
                Some(json!({"status": "unavailable"})),
                "status",
                Some("unavailable"),
            ),
            (
                "status free text",
                Some(json!({"status": "vm is down"})),
                "status",
                Some("[omitted]"),
            ),
            (
                "reason enum",
                Some(json!({"reason": "unknown"})),
                "reason",
                Some("unknown"),
            ),
            (
                "unknown key detail",
                Some(json!({"detail": "denied"})),
                "detail",
                None,
            ),
            (
                "unknown key message",
                Some(json!({"message": "denied"})),
                "message",
                None,
            ),
            (
                "unknown key code",
                Some(json!({"code": "denied"})),
                "code",
                None,
            ),
            ("absent key", Some(json!({})), "error", None),
            ("nil map", None, "error", None),
        ];
        for (name, decoded, key, want) in cases {
            let decoded = decoded.as_ref().map(|v| map(v.clone()));
            let got = extract_allowlist_field(decoded.as_ref(), key);
            assert_eq!(got.as_deref(), want, "{name}");
        }
    }

    #[test]
    fn summarize_content_type_cases() {
        // Port of Go TestSummarizeContentType (summary_test.go).
        let cases: Vec<(&str, &str)> = vec![
            ("plain", "application/json"),
            ("parameters stripped", "text/plain; charset=utf-8"),
            ("empty means absent", ""),
            ("whitespace trimmed", "  application/json  "),
            (
                "over cap",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/json",
            ),
            ("crlf injection", "text/plain\r\nX-Injected: evil"),
            ("space in type", "not a type"),
            ("no slash", "textplain"),
            ("empty subtype", "text/"),
        ];
        let wants = [
            "application/json",
            "text/plain",
            "",
            "application/json",
            "[omitted]",
            "[omitted]",
            "[omitted]",
            "[omitted]",
            "[omitted]",
        ];
        for ((name, raw), want) in cases.into_iter().zip(wants) {
            assert_eq!(summarize_content_type(raw), want, "{name}");
        }
    }

    #[test]
    fn summarize_body_cases() {
        // Port of Go TestSummarizeBody (summary_test.go).
        let data = br#"{"ok":false,"error":"denied"}"#;
        let decoded = map(json!({"ok": false, "error": "denied"}));
        let s = summarize_body(
            "api error",
            Some(data),
            "application/json; charset=utf-8",
            Some(&decoded),
            &["error"],
        );
        assert_eq!(s.length, data.len());
        assert_eq!(s.content_type, "application/json");
        assert_eq!(s.error_code, "denied");
        for want in [
            "api error",
            &format!("body_length={}", data.len()),
            "content_type=application/json",
            "error=denied",
        ] {
            assert!(
                s.text.contains(want),
                "text = {:?}, want {:?}",
                s.text,
                want
            );
        }
        // Over-cap extracted value: placeholder, never a
        // truncated prefix of the value.
        let long = "b".repeat(100);
        let decoded2 = map(json!({"error": long}));
        let s2 = summarize_body(
            "api error",
            Some(long.as_bytes()),
            "",
            Some(&decoded2),
            &["error"],
        );
        assert!(
            !s2.text.contains(&long[..64]) && !s2.text.contains(&long),
            "text = {:?}",
            s2.text
        );
        assert!(s2.text.contains("error=[omitted]"), "text = {:?}", s2.text);
        // No decoded map, no content-type: status + length only.
        let s3 = summarize_body("gateway error", Some(b"plain body"), "", None, &[]);
        assert_eq!(
            s3.text,
            format!("gateway error; body_length={}", b"plain body".len())
        );
        assert_eq!(s3.content_type, "");
        assert_eq!(s3.error_code, "");
        // Nil body: no body_length field, length unknown.
        let s4 = summarize_body("gateway error", None, "", None, &[]);
        assert_eq!(s4.text, "gateway error");
        assert!(!s4.length_known);
    }

    #[test]
    fn summarize_parsed_body_and_reset() {
        let decoded = map(json!({"success": false, "error": "boom"}));
        let s = summarize_parsed_body(
            "fetchSubscriptionAction failed",
            42,
            true,
            Some(&decoded),
            &["error"],
        );
        assert!(
            s.text.contains("fetchSubscriptionAction failed"),
            "text = {:?}",
            s.text
        );
        assert!(s.text.contains("body_length=42"), "text = {:?}", s.text);
        assert!(s.text.contains("error=boom"), "text = {:?}", s.text);
        assert_eq!(s.error_code, "boom");
        let s_unknown = summarize_parsed_body(
            "fetchSubscriptionAction failed",
            0,
            false,
            Some(&decoded),
            &["error"],
        );
        assert!(
            !s_unknown.text.contains("body_length"),
            "text = {:?}",
            s_unknown.text
        );
        let r = reset_summary(7, "gone");
        assert_eq!(r.text, "stream reset; code=7; reason_length=4");
        assert_eq!(r.length, 4);
        assert!(r.length_known);
    }

    #[test]
    fn summary_to_body_summary_roundtrip() {
        let decoded = map(json!({"error": "denied"}));
        let s = summarize_body(
            "api error",
            Some(b"x"),
            "application/json",
            Some(&decoded),
            &["error"],
        );
        let b = summary_to_body_summary(-1, &s);
        assert_eq!(b.status, -1);
        assert_eq!(b.body_length, Some(1));
        assert_eq!(b.content_type.as_deref(), Some("application/json"));
        assert_eq!(b.error_code.as_deref(), Some("denied"));
        let s2 = summarize_body("gateway error", None, "", None, &[]);
        let b2 = summary_to_body_summary(-1, &s2);
        assert_eq!(b2.body_length, None);
        assert_eq!(b2.content_type, None);
        assert_eq!(b2.error_code, None);
    }
}
