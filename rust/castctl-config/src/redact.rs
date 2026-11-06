// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Ordered-JSON redaction: `redact.Value` over ordered
//! `JsonValue`, plus `RedactProfile`.
//!
//! Go sources: `internal/redact/value.go` (`Value`,
//! `IsSecretKey`, `redactChild`, `redactHeaders`,
//! `isHeaderMapKey`) and `internal/profile/redact.go`
//! (`RedactProfile`).
//!
//! The secret-key set itself lives in `castctl-log-redact`
//! (`is_secret_key`, the exact Go 43-key set) and is NOT
//! duplicated here. This module adds only the ordered walk
//! over `JsonValue`: `castctl-pluginhost::redact_value`
//! cannot be reused — it works on `serde_json::Value`,
//! whose `Map` is a `BTreeMap` and loses key order.
//!
//! Rules (`redact.Value`):
//! - A map entry whose key is secret is replaced wholesale
//!   with `"<redacted>"`, whatever the value's type.
//! - A map entry whose key names an HTTP header map
//!   (`"headers"` or `"extra_headers"`, exact after
//!   lowercasing) has EVERY value replaced with the marker;
//!   header names are preserved. A nil header map stays
//!   nil; a non-map header value is replaced wholesale.
//! - Every other string value has embedded URL userinfo
//!   redacted, whatever its key and at any depth.
//! - Slices and maps are rebuilt element by element; null,
//!   bools, and numbers (whose literal form is preserved)
//!   are returned unchanged. The input is never mutated.

use castctl_log_redact::{MARKER, is_secret_key, redact_url_userinfo};

use crate::config::build_profile_entry;
use crate::errors::ConfigError;
use crate::fingerprint::{DEFAULT_FINGERPRINT, DEFAULT_TLS_ENGINE};
use crate::jsonvalue::{JsonValue, OrderedObject};
use crate::profile::Profile;

/// The replacement for every redacted structured value:
/// exactly `"<redacted>"` (Go `redact.Marker`).
pub use castctl_log_redact::MARKER as REDACT_MARKER;

/// Whether `key` names an HTTP header map in the sing-box
/// 1.14.4 option schema: `"headers"` or `"extra_headers"`.
/// Exact after lowercasing, like `is_secret_key`:
/// `"custom_headers"` and `"early_data_header_name"` are
/// not header maps.
fn is_header_map_key(key: &str) -> bool {
    let lower: String = key.chars().flat_map(|c| c.to_lowercase()).collect();
    lower == "headers" || lower == "extra_headers"
}

/// `redact.Value` over ordered `JsonValue`: recursively
/// redact a JSON-shaped value and return the redacted
/// copy; the input is never mutated.
#[must_use]
pub fn redact_value(v: &JsonValue) -> JsonValue {
    match v {
        JsonValue::Null | JsonValue::Bool(_) | JsonValue::Number(_) => v.clone(),
        JsonValue::Str(s) => JsonValue::Str(redact_url_userinfo(s)),
        JsonValue::Array(items) => JsonValue::Array(items.iter().map(redact_value).collect()),
        JsonValue::Object(obj) => {
            let mut out = OrderedObject::new();
            for (k, child) in obj.iter() {
                out.set(k.clone(), redact_child(k, child));
            }
            JsonValue::Object(out)
        }
    }
}

/// Apply the key rule to one map entry: a secret key is
/// replaced wholesale, a header-map key has every value
/// replaced, any other key recurses into `redact_value`.
/// The secret rule wins over the header rule.
fn redact_child(key: &str, child: &JsonValue) -> JsonValue {
    if is_secret_key(key) {
        return JsonValue::Str(MARKER.to_string());
    }
    if is_header_map_key(key) {
        return redact_headers(child);
    }
    redact_value(child)
}

/// Replace every value in a header map with the marker,
/// preserving the header names (and key order). A null
/// header map stays null; any non-map value is replaced
/// wholesale with the marker.
fn redact_headers(v: &JsonValue) -> JsonValue {
    match v {
        JsonValue::Null => JsonValue::Null,
        JsonValue::Object(obj) => {
            let mut out = OrderedObject::new();
            for (k, _) in obj.iter() {
                out.set(k.clone(), JsonValue::Str(MARKER.to_string()));
            }
            JsonValue::Object(out)
        }
        _ => JsonValue::Str(MARKER.to_string()),
    }
}

/// `RedactProfile` (`internal/profile/redact.go`): the
/// display rendering of one profile — `name` first, then
/// the `buildProfileEntry` keys, then the effective
/// fingerprint/tls_engine appended when absent from the
/// entry (display always shows the recorded identity
/// settings with their effective values, even when the
/// key is absent from the file); the whole object is then
/// redacted, so `vm_id` / `node_id` /
/// `subscription_action_id` render as `"<redacted>"`, a
/// tag outbound stays a bare tag string, and a direct
/// profile omits the `outbound` key. Identity fields and
/// paths are kept, the inline outbound is redacted.
pub fn redact_profile(p: &Profile) -> Result<OrderedObject, ConfigError> {
    let entry = build_profile_entry(p)?;
    let mut out = OrderedObject::new();
    if !p.name.is_empty() {
        out.set("name".to_string(), JsonValue::Str(p.name.clone()));
    }
    for (k, v) in entry.iter() {
        out.set(k.clone(), v.clone());
    }
    // Display always shows the effective values, even when
    // the key is absent from the file (buildProfileEntry
    // omits absent keys so a save never writes a default
    // back). Neither value is a secret.
    if !out.has("fingerprint") {
        let fp = if p.fingerprint.is_empty() {
            DEFAULT_FINGERPRINT
        } else {
            p.fingerprint.as_str()
        };
        out.set("fingerprint".to_string(), JsonValue::Str(fp.to_string()));
    }
    if !out.has("tls_engine") {
        let te = if p.tls_engine.is_empty() {
            DEFAULT_TLS_ENGINE
        } else {
            p.tls_engine.as_str()
        };
        out.set("tls_engine".to_string(), JsonValue::Str(te.to_string()));
    }
    match redact_value(&JsonValue::Object(out)) {
        JsonValue::Object(obj) => Ok(obj),
        _ => unreachable!("redact_value of an object is an object"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jsonvalue::{decode_ordered_json, encode_ordered_json_indent};
    use crate::profile::{OutboundKind, OutboundRef};

    fn redact_compact(json: &str) -> String {
        let v = decode_ordered_json(json.as_bytes()).unwrap();
        encode_ordered_json_indent(&redact_value(&v), 2).unwrap()
    }

    #[test]
    fn secret_keys_replaced_wholesale_whatever_the_type() {
        assert_eq!(
            redact_compact(r#"{"password":"s3cret","token":{"x":1},"vm_id":42,"key":null}"#),
            "{\n  \"password\": \"<redacted>\",\n  \"token\": \"<redacted>\",\n  \"vm_id\": \"<redacted>\",\n  \"key\": \"<redacted>\"\n}"
        );
        // Case-insensitive, exact after lowercasing.
        assert_eq!(
            redact_compact(r#"{"Password":"x","my_token":"y","vmid":"z"}"#),
            "{\n  \"Password\": \"<redacted>\",\n  \"my_token\": \"y\",\n  \"vmid\": \"z\"\n}"
        );
    }

    #[test]
    fn header_maps_redact_every_value_names_preserved() {
        assert_eq!(
            redact_compact(
                r#"{"headers":{"X-Custom":"v","Authorization":"Bearer t"},"extra_headers":{"A":"b"}}"#
            ),
            "{\n  \"headers\": {\n    \"X-Custom\": \"<redacted>\",\n    \"Authorization\": \"<redacted>\"\n  },\n  \"extra_headers\": {\n    \"A\": \"<redacted>\"\n  }\n}"
        );
        // Non-map headers value: wholesale marker. Null stays null.
        assert_eq!(
            redact_compact(r#"{"headers":"oops","extra_headers":null}"#),
            "{\n  \"headers\": \"<redacted>\",\n  \"extra_headers\": null\n}"
        );
        // Not a header map: custom_headers survives.
        assert_eq!(
            redact_compact(r#"{"custom_headers":{"A":"b"}}"#),
            "{\n  \"custom_headers\": {\n    \"A\": \"b\"\n  }\n}"
        );
    }

    #[test]
    fn strings_get_url_userinfo_only_key_order_preserved() {
        assert_eq!(
            redact_compact(
                r#"{"server":"socks5://user:s3cret@proxy.invalid:1080","tag":"x","n":1,"b":true,"a":[1,"https://bob@host/x"]}"#
            ),
            "{\n  \"server\": \"socks5://<redacted>@proxy.invalid:1080\",\n  \"tag\": \"x\",\n  \"n\": 1,\n  \"b\": true,\n  \"a\": [\n    1,\n    \"https://<redacted>@host/x\"\n  ]\n}"
        );
    }

    fn test_profile() -> Profile {
        Profile {
            name: "alpha".to_string(),
            cookies_file: "/tmp/cfg/alpha/cookies.txt".to_string(),
            vm_id: "vm-123".to_string(),
            node_id: "0123456789abcdef".to_string(),
            vm_id_present: true,
            node_id_present: true,
            auto_approve: "off".to_string(),
            fingerprint: "chrome".to_string(),
            tls_engine: "utls".to_string(),
            outbound: OutboundRef {
                kind: OutboundKind::Inline,
                tag: "profile:alpha".to_string(),
                typ: "socks".to_string(),
                from: String::new(),
                raw: Some(
                    decode_ordered_json(
                        br#"{"type":"socks","tag":"profile:alpha","server":"127.0.0.1","server_port":1080,"username":"u","password":"p"}"#,
                    )
                    .unwrap(),
                ),
            },
            ..Default::default()
        }
    }

    #[test]
    fn redact_profile_shape() {
        let out = redact_profile(&test_profile()).unwrap();
        let text = encode_ordered_json_indent(&JsonValue::Object(out), 2).unwrap();
        // name first, then entry order; secrets redacted.
        assert!(text.starts_with("{\n  \"name\": \"alpha\""), "got:\n{text}");
        assert!(text.contains("\"vm_id\": \"<redacted>\""), "got:\n{text}");
        assert!(text.contains("\"node_id\": \"<redacted>\""), "got:\n{text}");
        assert!(
            text.contains("\"username\": \"<redacted>\""),
            "got:\n{text}"
        );
        assert!(
            text.contains("\"password\": \"<redacted>\""),
            "got:\n{text}"
        );
        // Non-secret inline fields survive; server host survives.
        assert!(text.contains("\"server\": \"127.0.0.1\""), "got:\n{text}");
        // Effective fingerprint/tls_engine appended (absent from
        // the entry: defaults, not present in the file).
        assert!(text.contains("\"fingerprint\": \"chrome\""), "got:\n{text}");
        assert!(text.contains("\"tls_engine\": \"utls\""), "got:\n{text}");
        // Fingerprint/tls_engine come AFTER outbound (appended).
        assert!(
            text.find("\"outbound\"").unwrap() < text.find("\"fingerprint\"").unwrap(),
            "got:\n{text}"
        );
    }

    #[test]
    fn redact_profile_tag_outbound_and_direct() {
        let mut p = test_profile();
        p.outbound = OutboundRef {
            kind: OutboundKind::Tag,
            tag: "proxy-sg".to_string(),
            typ: "socks".to_string(),
            from: String::new(),
            raw: None,
        };
        let out = redact_profile(&p).unwrap();
        let text = encode_ordered_json_indent(&JsonValue::Object(out), 2).unwrap();
        assert!(text.contains("\"outbound\": \"proxy-sg\""), "got:\n{text}");
        p.outbound = OutboundRef {
            kind: OutboundKind::Direct,
            tag: String::new(),
            typ: String::new(),
            from: String::new(),
            raw: None,
        };
        let out = redact_profile(&p).unwrap();
        let text = encode_ordered_json_indent(&JsonValue::Object(out), 2).unwrap();
        assert!(!text.contains("outbound"), "got:\n{text}");
    }
}
