// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Structured redaction (`internal/redact/value.go`
//! `Value` + `internal/webui/redact.go` `RedactRawConfig`).
//!
//! - A map entry whose key is secret (`is_secret_key`, the
//!   42-key set from `castctl-log-redact`) is replaced
//!   wholesale with `<redacted>`, whatever the value type.
//! - A map entry whose key names an HTTP header map
//!   (`headers` / `extra_headers`, exact after lowercasing)
//!   has EVERY value replaced with `<redacted>`; header
//!   names (keys) are preserved; a nil header map stays nil
//!   and a non-map header value is replaced wholesale.
//! - Every other string value has embedded URL userinfo
//!   redacted (`redact_url_userinfo`), at any depth.
//! - Arrays are rebuilt element by element; nil, bools and
//!   numbers (literals preserved) are unchanged. The input
//!   is never mutated.

use castctl_config::jsonvalue::JsonValue;
use castctl_log_redact::{MARKER, is_secret_key, redact_url_userinfo};

/// `redact.Value` over a [`JsonValue`]: returns a redacted
/// copy, never mutating the input.
pub fn redact_value(value: &JsonValue) -> JsonValue {
    match value {
        JsonValue::Null | JsonValue::Bool(_) | JsonValue::Number(_) => value.clone(),
        JsonValue::Str(s) => JsonValue::Str(redact_url_userinfo(s)),
        JsonValue::Array(items) => {
            JsonValue::Array(items.iter().map(redact_value).collect())
        }
        JsonValue::Object(obj) => {
            let mut out = castctl_config::jsonvalue::OrderedObject::new();
            for (k, child) in obj.iter() {
                out.set(k.clone(), redact_child(k, child));
            }
            JsonValue::Object(out)
        }
    }
}

fn redact_child(key: &str, child: &JsonValue) -> JsonValue {
    if is_secret_key(key) {
        return JsonValue::Str(MARKER.to_string());
    }
    if is_header_map_key(key) {
        return redact_headers(child);
    }
    redact_value(child)
}

/// `redactPluginsBlock` (`internal/profile/redact.go`):
/// a `plugins` block shows tag/type only, everything else
/// as one `<redacted>` marker under the `fragment` key. A
/// non-array block is the marker wholesale; a non-object
/// element is the marker wholesale. Never mutates input.
pub fn redact_plugins_block(root: &mut castctl_config::jsonvalue::OrderedObject) {
    let Some(plugins) = root.get("plugins").cloned() else {
        return;
    };
    let JsonValue::Array(arr) = &plugins else {
        root.set("plugins".to_string(), JsonValue::Str(MARKER.to_string()));
        return;
    };
    let mut out: Vec<JsonValue> = Vec::with_capacity(arr.len());
    for elem in arr {
        let JsonValue::Object(entry) = elem else {
            out.push(JsonValue::Str(MARKER.to_string()));
            continue;
        };
        let mut shown = castctl_config::jsonvalue::OrderedObject::new();
        if let Some(tag) = entry.get("tag") {
            match tag {
                JsonValue::Str(s) => {
                    shown.set("tag".to_string(), JsonValue::Str(s.clone()));
                }
                _ => {
                    shown.set("tag".to_string(), JsonValue::Str(MARKER.to_string()));
                }
            }
        }
        if let Some(typ) = entry.get("type") {
            match typ {
                JsonValue::Str(s) => {
                    shown.set("type".to_string(), JsonValue::Str(s.clone()));
                }
                _ => {
                    shown.set("type".to_string(), JsonValue::Str(MARKER.to_string()));
                }
            }
        }
        let has_fragment = entry
            .keys()
            .iter()
            .any(|k| k != "tag" && k != "type");
        if has_fragment {
            shown.set("fragment".to_string(), JsonValue::Str(MARKER.to_string()));
        }
        out.push(JsonValue::Object(shown));
    }
    root.set("plugins".to_string(), JsonValue::Array(out));
}

/// `RedactRawConfig` (`internal/profile/redact.go`):
/// decode the stored document, redact the `plugins` block
/// wholesale, then redact generically and render with
/// 2-space indent (Go `json.MarshalIndent`, HTML escaping
/// on, no trailing newline). The plugins round-trip edge
/// is documented in Go, not hidden: a real top-level
/// `fragment` key collapses on a PUT round-trip.
pub fn redact_raw_config(data: &[u8]) -> Result<String, String> {
    let text = String::from_utf8_lossy(data).into_owned();
    let mut value = castctl_config::jsonvalue::decode_ordered_json(&text)
        .map_err(|e| e.message().to_string())?;
    if let JsonValue::Object(root) = &mut value {
        redact_plugins_block(root);
    }
    let redacted = redact_value(&value);
    Ok(crate::go_json::encode_go_json_indent(&redacted))
}

fn is_header_map_key(key: &str) -> bool {
    matches!(key.to_lowercase().as_str(), "headers" | "extra_headers")
}

fn redact_headers(child: &JsonValue) -> JsonValue {
    match child {
        JsonValue::Null => JsonValue::Null,
        JsonValue::Object(obj) => {
            let mut out = castctl_config::jsonvalue::OrderedObject::new();
            for (k, _) in obj.iter() {
                out.set(k.clone(), JsonValue::Str(MARKER.to_string()));
            }
            JsonValue::Object(out)
        }
        _ => JsonValue::Str(MARKER.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use castctl_config::jsonvalue::OrderedObject;

    fn obj(pairs: &[(&str, JsonValue)]) -> JsonValue {
        let mut o = OrderedObject::new();
        for (k, v) in pairs {
            o.set((*k).to_string(), v.clone());
        }
        JsonValue::Object(o)
    }

    #[test]
    fn secret_keys_replaced_wholesale() {
        let v = obj(&[
            ("password", JsonValue::Str("hunter2".to_string())),
            ("Password", JsonValue::Number("42".to_string())),
            ("token", JsonValue::Object(OrderedObject::new())),
            ("plain", JsonValue::Str("keep me".to_string())),
        ]);
        let r = redact_value(&v);
        let JsonValue::Object(o) = r else { panic!("object") };
        assert_eq!(o.get("password"), Some(&JsonValue::Str("<redacted>".to_string())));
        assert_eq!(o.get("Password"), Some(&JsonValue::Str("<redacted>".to_string())));
        assert_eq!(o.get("token"), Some(&JsonValue::Str("<redacted>".to_string())));
        assert_eq!(o.get("plain"), Some(&JsonValue::Str("keep me".to_string())));
        // Non-matching keys are not secrets.
        let v2 = obj(&[("my_token", JsonValue::Str("x".to_string()))]);
        let r2 = redact_value(&v2);
        assert_eq!(r2, v2);
    }

    #[test]
    fn header_maps_replaced_but_names_kept() {
        let inner = obj(&[("X-Custom", JsonValue::Str("benign".to_string()))]);
        let v = obj(&[("headers", inner)]);
        let r = redact_value(&v);
        let JsonValue::Object(o) = r else { panic!("object") };
        let JsonValue::Object(h) = o.get("headers").unwrap() else { panic!("headers") };
        assert_eq!(h.get("X-Custom"), Some(&JsonValue::Str("<redacted>".to_string())));
        // custom_headers is NOT a header map.
        let v2 = obj(&[("custom_headers", obj(&[("X-A", JsonValue::Str("v".to_string()))]))]);
        assert_eq!(redact_value(&v2), v2);
    }

    #[test]
    fn url_userinfo_scrubbed_in_plain_strings() {
        let v = JsonValue::Str("socks5://user:pass@host:1080".to_string());
        assert_eq!(
            redact_value(&v),
            JsonValue::Str("socks5://<redacted>@host:1080".to_string())
        );
        // An @ in the path is not userinfo.
        let v2 = JsonValue::Str("https://example.com/@user".to_string());
        assert_eq!(redact_value(&v2), v2);
    }

    #[test]
    fn fail_before_secret_replacement() {
        // If secret-key replacement were dropped, a password
        // would survive redaction: this pins the rule.
        let v = obj(&[("private_key", JsonValue::Str("SECRET".to_string()))]);
        let r = redact_value(&v);
        let text = castctl_config::jsonvalue::encode_ordered_json(&r);
        assert!(!text.contains("SECRET"), "leaked: {text}");
    }
}
