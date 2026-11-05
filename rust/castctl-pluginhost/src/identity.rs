// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Plugin-facing identity: the outbound tag plus the
//! secret-stripped hash of the outbound object.
//!
//! Go source: `internal/pluginhost/identity.go` (all of
//! it) and `internal/redact/value.go` (the JSON-value
//! redactor, NEW in this crate — `redact.Value`
//! reflection was explicitly excluded from
//! `castctl-log-redact`, so this is new work here).
//!
//! Two outbound objects differing ONLY in secret values
//! hash identically: the plugin-facing identity is blind
//! to secret rotation and carries no secret value. This
//! deliberately differs from
//! `profile.OutboundIdentityForConfig`, which hashes the
//! RAW outbound JSON.
//!
//! Canonical form: Go `encoding/json` map encoding
//! (keys sorted, HTML-escaped, numbers as float64).
//! The renderer below reproduces it exactly, including
//! Go's float formatting and HTML escaping, so a hash
//! computed here equals the hash Go computes for the
//! same redacted object.

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::error::PluginHostError;
use crate::pluginabi::Identity;

/// The replacement for every redacted structured value.
/// Source: `redact.Marker` (`value.go:12-15`).
pub const MARKER: &str = "<redacted>";

/// Whether `key` names secret material. Exact after
/// lowercasing: `"Password"` matches, `"my_token"` and
/// `"vmid"` do not.
/// Source: `redact.IsSecretKey` (`value.go:63-66`),
/// reusing `castctl_log_redact::is_secret_key`
/// (`redact_str.rs:192`).
#[must_use]
pub fn is_secret_key(key: &str) -> bool {
    castctl_log_redact::is_secret_key(key)
}

/// Whether `key` names an HTTP header map (`"headers"`
/// or `"extra_headers"`, exact after lowercasing).
/// Source: `isHeaderMapKey` (`value.go:200-209`).
#[must_use]
pub fn is_header_map_key(key: &str) -> bool {
    matches!(
        key.to_ascii_lowercase().as_str(),
        "headers" | "extra_headers"
    )
}

/// Recursively redact a JSON-shaped value and return
/// the redacted copy; the input is never mutated.
///
///   - A map entry whose key is secret is replaced
///     wholesale with `MARKER`, whatever the value's
///     type.
///   - A map entry whose key names an HTTP header map
///     has EVERY value replaced with `MARKER`, whatever
///     the header name. Header names are preserved; only
///     values are replaced. A nil header map stays nil,
///     and a non-map header value is replaced wholesale.
///   - Every other string value has embedded URL
///     userinfo redacted, whatever its key and at any
///     depth.
///   - Arrays and objects are rebuilt element by
///     element, so no field is dropped and no unrelated
///     key is touched.
///   - Null, bools, and numbers are returned unchanged.
///   - The secret rule wins over the header rule.
/// Source: `redact.Value` / `redactChild` /
/// `redactHeaders` (`value.go:147-226`).
#[must_use]
pub fn redact_value(v: &Value) -> Value {
    match v {
        Value::Null | Value::Bool(_) | Value::Number(_) => v.clone(),
        Value::String(s) => Value::String(castctl_log_redact::redact_url_userinfo(s)),
        Value::Array(items) => Value::Array(items.iter().map(redact_value).collect()),
        Value::Object(map) => {
            let mut out = serde_json::Map::new();
            for (k, child) in map {
                out.insert(k.clone(), redact_child(k, child));
            }
            Value::Object(out)
        }
    }
}

fn redact_child(key: &str, child: &Value) -> Value {
    if is_secret_key(key) {
        return Value::String(MARKER.to_string());
    }
    if is_header_map_key(key) {
        return redact_headers(child);
    }
    redact_value(child)
}

fn redact_headers(v: &Value) -> Value {
    match v {
        Value::Null => Value::Null,
        Value::Object(map) => {
            let mut out = serde_json::Map::new();
            for k in map.keys() {
                out.insert(k.clone(), Value::String(MARKER.to_string()));
            }
            Value::Object(out)
        }
        _ => Value::String(MARKER.to_string()),
    }
}

/// Render `v` as Go `encoding/json` would marshal the
/// redacted map: keys sorted, HTML-escaped
/// (`<`/`>`/`&` as `\u003c`/`\u003e`/`\u0026`),
/// U+2028/U+2029 escaped, numbers as float64 (Go
/// unmarshals JSON numbers into `float64`).
fn canonical_json(v: &Value) -> String {
    match v {
        Value::Null => "null".to_string(),
        Value::Bool(true) => "true".to_string(),
        Value::Bool(false) => "false".to_string(),
        Value::Number(n) => canonical_number(n),
        Value::String(s) => escape_go_string(s),
        Value::Array(items) => {
            let parts: Vec<String> = items.iter().map(canonical_json).collect();
            format!("[{}]", parts.join(","))
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let parts: Vec<String> = keys
                .iter()
                .map(|k| format!("{}:{}", escape_go_string(k), canonical_json(&map[*k])))
                .collect();
            format!("{{{}}}", parts.join(","))
        }
    }
}

/// Go `encoding/json` float64 rendering: shortest
/// digits, `e` format when `abs < 1e-6` or `abs >= 1e21`
/// (and non-zero), `f` format otherwise; `1` renders
/// as `"1"`, never `"1.0"`.
fn canonical_number(n: &serde_json::Number) -> String {
    // Go unmarshals every JSON number into float64, so
    // the literal spelling is lost: render the float64
    // value. `arbitrary_precision` keeps the literal in
    // `Number`; `as_f64` recovers the float64 Go sees.
    let Some(f) = n.as_f64() else {
        return n.to_string();
    };
    if f == 0.0 {
        return if f.is_sign_negative() {
            "-0".to_string()
        } else {
            "0".to_string()
        };
    }
    let abs = f.abs();
    if abs < 1e-6 || abs >= 1e21 {
        // Rust `{f:e}` gives e.g. "1e21" / "1.5e-7";
        // Go gives "1e+21" / "1.5e-7".
        let sci = format!("{f:e}");
        if let Some((mantissa, exp)) = sci.split_once('e') {
            let exp_val: i32 = exp.parse().unwrap_or(0);
            if exp_val >= 0 {
                return format!("{mantissa}e+{exp_val}");
            }
            return format!("{mantissa}e{exp_val}");
        }
        return sci;
    }
    format!("{f}")
}

/// Go `encoding/json` string escaping with HTML
/// escaping on (the `Marshal` default).
fn escape_go_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '<' => out.push_str("\\u003c"),
            '>' => out.push_str("\\u003e"),
            '&' => out.push_str("\\u0026"),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// The sha256 hex of the canonical JSON of the outbound
/// object with every secret field replaced wholesale.
/// The JSON must parse and be a top-level object.
/// Source: `StrippedOutboundHash` (`identity.go:44-58`).
pub fn stripped_outbound_hash(raw: &[u8]) -> Result<String, PluginHostError> {
    let v: Value = serde_json::from_slice(raw).map_err(|e| {
        PluginHostError::failed(format!("stripped outbound hash: invalid json: {e}"))
    })?;
    let obj = match &v {
        Value::Object(_) => v,
        _ => {
            return Err(PluginHostError::failed(
                "stripped outbound hash: outbound json must be an object",
            ));
        }
    };
    let canonical = canonical_json(&redact_value(&obj));
    Ok(hex::encode(Sha256::digest(canonical.as_bytes())))
}

/// Build the ONLY identity a plugin may receive: the
/// outbound tag plus the secret-stripped hash.
/// Source: `NewPluginIdentity` (`identity.go:34-43`).
pub fn new_plugin_identity(
    outbound_tag: &str,
    outbound_raw_json: &[u8],
) -> Result<Identity, PluginHostError> {
    if outbound_tag.is_empty() {
        return Err(PluginHostError::failed(
            "plugin identity requires an outbound tag",
        ));
    }
    let hash = stripped_outbound_hash(outbound_raw_json)?;
    Ok(Identity {
        outbound_tag: outbound_tag.to_string(),
        outbound_hash: hash,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Port of `TestPluginIdentitySecretBlind`
    /// (`identity_test.go:9-35`).
    #[test]
    fn plugin_identity_secret_blind() {
        let a = new_plugin_identity(
            "wg1",
            br#"{"type":"wireguard","server":"10.0.0.1","private_key":"SECRET-A","password":"hunter2"}"#,
        )
        .unwrap();
        let b = new_plugin_identity(
            "wg1",
            br#"{"type":"wireguard","server":"10.0.0.1","private_key":"SECRET-B","password":"different"}"#,
        )
        .unwrap();
        assert_eq!(a.outbound_hash, b.outbound_hash);
        assert_eq!(a.outbound_tag, "wg1");
        // A non-secret change DOES change the hash.
        let c = new_plugin_identity(
            "wg1",
            br#"{"type":"wireguard","server":"10.0.0.2","private_key":"SECRET-A","password":"hunter2"}"#,
        )
        .unwrap();
        assert_ne!(a.outbound_hash, c.outbound_hash);
        // Empty tag refuses; non-object refuses; bad
        // JSON refuses.
        assert!(new_plugin_identity("", b"{}").is_err());
        assert!(new_plugin_identity("wg1", b"[1,2]").is_err());
        assert!(new_plugin_identity("wg1", b"{bad").is_err());
    }

    #[test]
    fn redact_value_rules() {
        // Secret key replaced wholesale, whatever type.
        let v: Value = serde_json::json!({"api_key": {"nested": true}, "token": [1, 2]});
        let r = redact_value(&v);
        assert_eq!(r["api_key"], Value::String(MARKER.into()));
        assert_eq!(r["token"], Value::String(MARKER.into()));
        // Header map: every value replaced, names kept.
        let v: Value =
            serde_json::json!({"headers": {"X-Custom": "v", "Authorization": "Bearer x"}});
        let r = redact_value(&v);
        assert_eq!(r["headers"]["X-Custom"], Value::String(MARKER.into()));
        assert_eq!(r["headers"]["Authorization"], Value::String(MARKER.into()));
        // Non-map headers value replaced wholesale.
        let v: Value = serde_json::json!({"headers": "not-a-map"});
        assert_eq!(redact_value(&v)["headers"], Value::String(MARKER.into()));
        // Nil header map stays nil.
        let v: Value = serde_json::json!({"headers": null});
        assert_eq!(redact_value(&v)["headers"], Value::Null);
        // Other strings get URL-userinfo redaction only.
        let v: Value = serde_json::json!({"server": "https://user:s3cret@proxy.invalid:1080"});
        let r = redact_value(&v);
        assert_eq!(
            r["server"],
            Value::String("https://<redacted>@proxy.invalid:1080".into())
        );
        // Key order in the input does not affect the hash.
        let h1 = stripped_outbound_hash(br#"{"b":1,"a":"x"}"#).unwrap();
        let h2 = stripped_outbound_hash(br#"{"a":"x","b":1}"#).unwrap();
        assert_eq!(h1, h2);
        // Go float64 canonical form: 1e3 -> "1000".
        assert_eq!(canonical_json(&serde_json::json!(1000.0)), "1000");
        assert_eq!(canonical_json(&serde_json::json!(1.5)), "1.5");
        // HTML escaping matches Go's Marshal default.
        assert_eq!(
            canonical_json(&Value::String("a<b>&".to_string())),
            "\"a\\u003cb\\u003e\\u0026\""
        );
    }
}
