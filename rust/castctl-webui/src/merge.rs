// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Sentinel merge (`internal/webui/merge.go`: `mergeConfig`,
//! `adoptNew`, `spliceUserinfo`, `checkElementIdentity`,
//! `findSentinelAtSecretPosition`, `checkWhitespaceKeys`),
//! implementing webui/SECRETS-CONTRACT.md rules R1–R9.
//! The Go implementation is the authority.
//!
//! Rules, in brief: an exact sentinel string at a present
//! secret position keeps the stored value verbatim (R1); a
//! sentinel at a path absent from stored rejects the whole
//! save (R2, including renames); a sentinel at a present
//! non-secret position is an ordinary literal (R-A). Arrays
//! merge positionally with an identity guard (R4). A
//! single-span URL userinfo edit splices the stored userinfo
//! into the edited string (R6); multi-URL strings fail
//! closed. Deletion, empty, and null are distinct from keep
//! (R9). Error paths name the JSON path only, never a value.

use castctl_config::jsonvalue::JsonValue;
use castctl_log_redact::{MARKER, is_secret_key, redact_url_userinfo};
use regex::Regex;
use std::sync::OnceLock;

/// The Go userinfo pattern from `redact.RedactURLUserinfo`,
/// reused to locate userinfo spans for the R6 splice. Greedy:
/// the userinfo run extends to the LAST `@` before the first
/// `/`, `?`, or `#` after `://`. Go `\s` is ASCII-only, hence
/// the explicit class.
fn re_userinfo_span() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)([a-z][a-z0-9+.-]*://)[^/\t\n\f\r ?#]+@").expect("reURLUserinfoSpan")
    })
}

#[derive(Debug, Clone, Copy)]
struct UserinfoSpan {
    /// Index of the first userinfo character (just after `://`).
    start: usize,
    /// Index of the `@` delimiting userinfo from host.
    at: usize,
    /// Byte range of the userinfo text within the string.
    range: std::ops::Range<usize>,
}

fn userinfo_spans(s: &str) -> Vec<UserinfoSpan> {
    let re = re_userinfo_span();
    let mut spans = Vec::new();
    for caps in re.captures_iter(s) {
        let whole = caps.get(0).expect("whole match");
        let scheme = caps.get(1).expect("scheme group");
        let start = scheme.end();
        let at = whole.end() - 1;
        spans.push(UserinfoSpan { start, at, range: start..at });
    }
    spans
}

/// R6 splice: the submitted string carries exactly one
/// userinfo segment whose value is the sentinel, and the
/// stored string carries exactly one userinfo segment.
/// Splice the stored userinfo into the submitted string.
fn splice_userinfo(stored: &str, submitted: &str) -> Option<String> {
    let stored_spans = userinfo_spans(stored);
    if stored_spans.len() != 1 {
        return None;
    }
    let submitted_spans = userinfo_spans(submitted);
    if submitted_spans.len() != 1 {
        return None;
    }
    let sub = submitted_spans[0];
    if &submitted[sub.range.clone()] != MARKER {
        return None;
    }
    let stored_info = &stored[stored_spans[0].range.clone()];
    let mut out = String::with_capacity(submitted.len() + stored_info.len());
    out.push_str(&submitted[..sub.start]);
    out.push_str(stored_info);
    out.push_str(&submitted[sub.at..]);
    Some(out)
}

/// Rejection naming the JSON path of an offending sentinel.
/// Handlers render it as `redacted value at <path>` — path
/// only, never a value. The error string itself is the fixed
/// `submitted value rejected`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SentinelRejection {
    /// JSON path of the offending sentinel ("" at the root).
    pub path: String,
}

impl std::fmt::Display for SentinelRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("submitted value rejected")
    }
}

impl std::error::Error for SentinelRejection {}

pub fn join_path(path: &str, key: &str) -> String {
    if path.is_empty() { key.to_string() } else { format!("{path}.{key}") }
}

pub fn join_index_path(path: &str, index: usize) -> String {
    format!("{path}[{index}]")
}

/// `adoptNew`: adopt a brand-new subtree (no stored
/// counterpart). An exact sentinel anywhere in it rejects;
/// a userinfo span merely containing the marker rejects too.
fn adopt_new(submitted: &JsonValue, path: &str) -> Result<JsonValue, SentinelRejection> {
    if let JsonValue::Str(s) = submitted {
        if s == MARKER {
            return Err(SentinelRejection { path: path.to_string() });
        }
        for sp in userinfo_spans(s) {
            let info = &s[sp.range.clone()];
            if info != MARKER && info.contains(MARKER) {
                return Err(SentinelRejection { path: path.to_string() });
            }
        }
    }
    match submitted {
        JsonValue::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for (i, elem) in items.iter().enumerate() {
                out.push(adopt_new(elem, &join_index_path(path, i))?);
            }
            Ok(JsonValue::Array(out))
        }
        JsonValue::Object(obj) => {
            let mut out = castctl_config::jsonvalue::OrderedObject::new();
            for (k, child) in obj.iter() {
                out.set(k.clone(), adopt_new(child, &join_path(path, k))?);
            }
            Ok(JsonValue::Object(out))
        }
        _ => Ok(submitted.clone()),
    }
}

fn json_kind(v: &JsonValue) -> &'static str {
    match v {
        JsonValue::Null => "null",
        JsonValue::Array(_) => "array",
        JsonValue::Object(_) => "object",
        JsonValue::Str(_) => "string",
        JsonValue::Bool(_) => "boolean",
        JsonValue::Number(_) => "number",
    }
}

fn json_deep_equal(a: &JsonValue, b: &JsonValue) -> bool {
    match (a, b) {
        (JsonValue::Object(ao), JsonValue::Object(bo)) => {
            if ao.len() != bo.len() {
                return false;
            }
            ao.iter().all(|(k, av)| match bo.get(k) {
                Some(bv) => json_deep_equal(av, bv),
                None => false,
            })
        }
        (JsonValue::Array(aa), JsonValue::Array(ab)) => {
            aa.len() == ab.len()
                && aa.iter().zip(ab.iter()).all(|(x, y)| json_deep_equal(x, y))
        }
        (JsonValue::Number(an), JsonValue::Number(bn)) => an == bn,
        (JsonValue::Str(x), JsonValue::Str(y)) => x == y,
        (JsonValue::Bool(x), JsonValue::Bool(y)) => x == y,
        (JsonValue::Null, JsonValue::Null) => true,
        _ => false,
    }
}

/// R4 identity guard: an array element whose merge restored
/// a secret must still be the same element. Every identity
/// key present in the stored element (tag, type, username,
/// name, address, port) must be present and unchanged in
/// the MERGED element. An `address` value carrying a URL
/// userinfo span is governed by R6, not by identity.
fn check_element_identity(
    stored_element: &JsonValue,
    merged_element: &JsonValue,
    path: &str,
) -> Result<(), SentinelRejection> {
    let (JsonValue::Object(stored_obj), JsonValue::Object(merged_obj)) =
        (stored_element, merged_element)
    else {
        return Ok(());
    };
    for key in ["tag", "type", "username", "name", "address", "port"] {
        let Some(stored_value) = stored_obj.get(key) else { continue };
        let Some(merged_value) = merged_obj.get(key) else {
            return Err(SentinelRejection { path: path.to_string() });
        };
        if key == "address" {
            if let (JsonValue::Str(sv), JsonValue::Str(uv)) = (stored_value, merged_value) {
                if !userinfo_spans(sv).is_empty() || !userinfo_spans(uv).is_empty() {
                    continue;
                }
            }
        }
        if !json_deep_equal(stored_value, merged_value) {
            return Err(SentinelRejection { path: path.to_string() });
        }
    }
    Ok(())
}

/// `mergeNode`: merge one submitted value against its stored
/// counterpart. Returns the merged value and whether any
/// keep (R1 restoration) happened inside this subtree.
/// Neither input is mutated.
#[allow(clippy::too_many_lines)]
fn merge_node(
    stored: Option<&JsonValue>,
    submitted: &JsonValue,
    path: &str,
    secret_position: bool,
) -> Result<(JsonValue, bool), SentinelRejection> {
    // Exact sentinel string (whole-value match after parse
    // only). R2 / R1 / R-A in order.
    if let JsonValue::Str(s) = submitted {
        if s == MARKER {
            match stored {
                None => return Err(SentinelRejection { path: path.to_string() }),
                Some(stored_v) => {
                    if secret_position {
                        return Ok((stored_v.clone(), true));
                    }
                    return Ok((JsonValue::Str(MARKER.to_string()), false));
                }
            }
        }
    }
    let Some(stored_v) = stored else {
        return Ok((adopt_new(submitted, path)?, false));
    };

    if let (JsonValue::Object(stored_obj), JsonValue::Object(submitted_obj)) =
        (stored_v, submitted)
    {
        let mut out = castctl_config::jsonvalue::OrderedObject::new();
        let mut restored = false;
        for (key, child) in submitted_obj.iter() {
            let child_secret = secret_position
                || is_secret_key(key)
                || matches!(key.to_lowercase().as_str(), "headers" | "extra_headers");
            let child_stored = stored_obj.get(key);
            let (result, child_restored) =
                merge_node(child_stored, child, &join_path(path, key), child_secret)?;
            restored = restored || child_restored;
            out.set(key.clone(), result);
        }
        return Ok((JsonValue::Object(out), restored));
    }

    if let (JsonValue::Array(stored_arr), JsonValue::Array(submitted_arr)) =
        (stored_v, submitted)
    {
        let mut out: Vec<JsonValue> = Vec::with_capacity(submitted_arr.len());
        let mut restored = false;
        for (i, elem) in submitted_arr.iter().enumerate() {
            let elem_path = join_index_path(path, i);
            if i < stored_arr.len() {
                let (result, elem_restored) =
                    merge_node(Some(&stored_arr[i]), elem, &elem_path, secret_position)?;
                if elem_restored {
                    check_element_identity(&stored_arr[i], &result, &elem_path)?;
                }
                restored = restored || elem_restored;
                out.push(result);
            } else {
                out.push(adopt_new(elem, &elem_path)?);
            }
        }
        return Ok((JsonValue::Array(out), restored));
    }

    if let (JsonValue::Str(stored_str), JsonValue::Str(submitted_str)) = (stored_v, submitted) {
        if submitted_str == stored_str {
            return Ok((stored_v.clone(), false));
        }
        // Untouched userinfo-redacted string: keep stored
        // verbatim (R6). This IS a restore, so it marks
        // restored for the array identity guard.
        if submitted_str == &redact_url_userinfo(stored_str) {
            return Ok((stored_v.clone(), true));
        }
        let stored_spans = userinfo_spans(stored_str);
        let submitted_spans = userinfo_spans(submitted_str);
        let has_sentinel_span = submitted_spans
            .iter()
            .any(|sp| &submitted_str[sp.range.clone()] == MARKER);
        if has_sentinel_span && (stored_spans.len() != 1 || submitted_spans.len() != 1) {
            return Err(SentinelRejection { path: path.to_string() });
        }
        for sp in &submitted_spans {
            let info = &submitted_str[sp.range.clone()];
            if info != MARKER && info.contains(MARKER) {
                return Err(SentinelRejection { path: path.to_string() });
            }
        }
        if let Some(spliced) = splice_userinfo(stored_str, submitted_str) {
            return Ok((JsonValue::Str(spliced), true));
        }
        return Ok((submitted.clone(), false));
    }

    // Type change or scalar edit: adopt as new (any exact
    // sentinel nested inside rejects). Same-kind scalar
    // edits are taken verbatim.
    if json_kind(stored_v) != json_kind(submitted) {
        return Ok((adopt_new(submitted, path)?, false));
    }
    Ok((submitted.clone(), false))
}

/// `mergeConfig`: merge a submitted (redacted, edited)
/// document against the stored document, per R1–R9. It
/// never mutates either input.
pub fn merge_config(stored: &JsonValue, submitted: &JsonValue) -> Result<JsonValue, SentinelRejection> {
    let (merged, _) = merge_node(Some(stored), submitted, "", false)?;
    Ok(merged)
}

/// `mergeNode` at one base path, for a single section
/// (outbound/endpoint/dns): `stored` is `None` for a brand-new
/// element (Go's `mergeNode(nil, false, ...)` — any sentinel
/// inside rejects), `Some` for a patch against the stored
/// element (Go's `mergeNode(obj, true, ..., "outbounds[i]",
/// false)`). The rejection path carries the base prefix, so
/// handlers render `redacted value at outbounds[0].password
/// ...` exactly as Go does.
pub fn merge_node_at(
    stored: Option<&JsonValue>,
    submitted: &JsonValue,
    base_path: &str,
) -> Result<JsonValue, SentinelRejection> {
    let (merged, _) = merge_node(stored, submitted, base_path, false)?;
    Ok(merged)
}

/// R8 assertion: the first path where the exact sentinel
/// sits at a secret position — under a secret key, at any
/// depth inside a secret-key subtree, or anywhere inside a
/// header map. `None` when no such position holds the
/// sentinel. A sentinel at a present non-secret position is
/// an ordinary literal and is NOT reported.
pub fn find_sentinel_at_secret_position(
    value: &JsonValue,
    secret_position: bool,
    path: &str,
) -> Option<String> {
    if let JsonValue::Str(s) = value {
        if s == MARKER && secret_position {
            return Some(path.to_string());
        }
        return None;
    }
    match value {
        JsonValue::Array(items) => {
            for (i, elem) in items.iter().enumerate() {
                if let Some(found) =
                    find_sentinel_at_secret_position(elem, secret_position, &join_index_path(path, i))
                {
                    return Some(found);
                }
            }
            None
        }
        JsonValue::Object(obj) => {
            for (k, child) in obj.iter() {
                let child_secret = secret_position
                    || is_secret_key(k)
                    || matches!(k.to_lowercase().as_str(), "headers" | "extra_headers");
                if let Some(found) =
                    find_sentinel_at_secret_position(child, child_secret, &join_path(path, k))
                {
                    return Some(found);
                }
            }
            None
        }
        _ => None,
    }
}

/// `checkWhitespaceKeys`: reject any object key with leading
/// or trailing whitespace in the submitted document, naming
/// the path only. Go's `TrimSpace` is Unicode whitespace;
/// Rust `char::is_whitespace` covers the same set for the
/// keys that can appear in JSON.
pub fn check_whitespace_keys(value: &JsonValue, path: &str) -> Result<(), SentinelRejection> {
    match value {
        JsonValue::Object(obj) => {
            for (k, child) in obj.iter() {
                if k.trim() != k {
                    return Err(SentinelRejection { path: join_path(path, k) });
                }
                check_whitespace_keys(child, &join_path(path, k))?;
            }
            Ok(())
        }
        JsonValue::Array(items) => {
            for (i, elem) in items.iter().enumerate() {
                check_whitespace_keys(elem, &join_index_path(path, i))?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use castctl_config::jsonvalue::{OrderedObject, decode_ordered_json};

    fn doc(json: &str) -> JsonValue {
        decode_ordered_json(json).unwrap()
    }

    #[test]
    fn r1_sentinel_at_secret_keeps_stored() {
        let stored = doc(r#"{"outbounds":[{"tag":"eu","type":"trojan","password":"SECRET"}]}"#);
        let submitted = doc(r#"{"outbounds":[{"tag":"eu","type":"trojan","password":"<redacted>"}]}"#);
        let merged = merge_config(&stored, &submitted).unwrap();
        assert_eq!(merged, stored);
    }

    #[test]
    fn r2_sentinel_at_absent_path_rejects() {
        let stored = doc(r#"{"a": 1}"#);
        let submitted = doc(r#"{"new_secret": "<redacted>"}"#);
        // "new_secret" is not a secret key, so R-A applies
        // here; use a real secret key at an absent path.
        let submitted2 = doc(r#"{"token": "<redacted>"}"#);
        let _ = submitted;
        let err = merge_config(&stored, &submitted2).unwrap_err();
        assert_eq!(err.path, "token");
    }

    #[test]
    fn ra_sentinel_at_non_secret_is_literal() {
        let stored = doc(r#"{"note": "hi"}"#);
        let submitted = doc(r#"{"note": "<redacted>"}"#);
        let merged = merge_config(&stored, &submitted).unwrap();
        assert_eq!(merged, submitted);
    }

    #[test]
    fn r6_splice_restores_stored_userinfo() {
        let stored = doc(r#"{"url": "https://user:pass@host/x"}"#);
        let submitted = doc(r#"{"url": "https://<redacted>@host/x"}"#);
        let merged = merge_config(&stored, &submitted).unwrap();
        assert_eq!(merged, stored);
        // Edited host with a sentinel userinfo splices too.
        let submitted2 = doc(r#"{"url": "https://<redacted>@other/x"}"#);
        let merged2 = merge_config(&stored, &submitted2).unwrap();
        assert_eq!(
            merged2,
            doc(r#"{"url": "https://user:pass@other/x"}"#)
        );
    }

    #[test]
    fn r9_deletion_is_not_keep() {
        let stored = doc(r#"{"a": 1, "b": 2}"#);
        let submitted = doc(r#"{"a": 1}"#);
        let merged = merge_config(&stored, &submitted).unwrap();
        assert_eq!(merged, submitted);
    }

    #[test]
    fn r8_finds_sentinel_at_secret_position() {
        let v = doc(r#"{"outbounds": [{"password": "<redacted>", "tag": "x"}]}"#);
        let found = find_sentinel_at_secret_position(&v, false, "");
        assert_eq!(found, Some("outbounds[0].password".to_string()));
        let v2 = doc(r#"{"note": "<redacted>"}"#);
        assert_eq!(find_sentinel_at_secret_position(&v2, false, ""), None);
    }

    #[test]
    fn whitespace_keys_rejected() {
        let v = doc(r#"{"a ": 1}"#);
        let err = check_whitespace_keys(&v, "").unwrap_err();
        assert_eq!(err.path, "a ");
    }

    #[test]
    fn fail_before_r1_keep() {
        // If R1 keep were dropped, the sentinel would be
        // stored verbatim at a secret position; R8 must
        // catch it, and the merge must restore the secret.
        let stored = doc(r#"{"token": "REAL"}"#);
        let submitted = doc(r#"{"token": "<redacted>"}"#);
        let merged = merge_config(&stored, &submitted).unwrap();
        assert_eq!(
            merged,
            stored,
            "merge must restore the stored token, not keep the sentinel"
        );
        assert_eq!(find_sentinel_at_secret_position(&merged, false, ""), None);
    }

    #[test]
    fn identity_guard_rejects_renamed_element() {
        // Stored outbound eu restored (password sentinel)
        // but its tag changed: R4 rejects.
        let stored = doc(r#"{"outbounds":[{"tag":"eu","type":"trojan","password":"SECRET"}]}"#);
        let submitted = doc(r#"{"outbounds":[{"tag":"us","type":"trojan","password":"<redacted>"}]}"#);
        let err = merge_config(&stored, &submitted).unwrap_err();
        assert_eq!(err.path, "outbounds[0]");
    }

    #[test]
    fn object_order_preserved_by_merge() {
        // Merge output keeps submitted key order (Go maps
        // render sorted downstream; the store re-encodes
        // via marshalOrdered against stored bytes).
        let stored = doc(r#"{"b": 1, "a": 2}"#);
        let submitted = doc(r#"{"a": 20, "b": 10}"#);
        let merged = merge_config(&stored, &submitted).unwrap();
        let JsonValue::Object(o) = merged else { panic!("object") };
        let keys: Vec<&str> = o.keys().iter().map(|k| k.as_str()).collect();
        assert_eq!(keys, ["a", "b"]);
        let _ = OrderedObject::new();
    }
}
