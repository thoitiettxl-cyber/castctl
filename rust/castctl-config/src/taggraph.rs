// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Go-faithful `validateTagGraph` (`internal/profile/config.go:678`).
//!
//! Enforces one tag namespace across outbounds, endpoints, and
//! inline profile outbounds; resolves tag references and
//! detour/selector references; rejects dangling references. It
//! also enforces the synthesised-direct reservation: any config
//! tag carrying the `castctl-direct:` prefix is rejected here.
//!
//! Do NOT reuse `castctl-webui::validate_tag_graph` for this:
//! it collapses detour/member refs to `"outbound" %q`, skips
//! endpoint detours and DNS checks, and does not resolve
//! Type/From.
//!
//! The validator reads the tag/type/detour/member fields out of
//! the raw JSON (`outbounds_raw` / `endpoints_raw` / profile
//! `outbound.raw` / `dns_raw`). It does NOT reproduce sing-box's
//! option parsing (D-M2-1): an outbound object with an unknown
//! `type`, or a socks object without a server, is accepted here
//! the way the Rust parser accepts it at load; only the tag
//! graph is checked. An element that is not an object, or has
//! no string `tag`, cannot be referenced by tag and is skipped
//! for the duplicate/reserve checks (Go would have failed the
//! parse first — the same D-M2-1 gap, recorded in PORTING.md).
//!
//! Order note: Go iterates Go maps for the profile loops, so
//! when several errors exist at once its first error is
//! arbitrary; Rust iterates the sorted `BTreeMap`, so the
//! first error is deterministic. The checks and their texts
//! are identical; only the choice among multiple simultaneous
//! errors can differ.

use crate::config::SingleConfig;
use crate::config_errorf;
use crate::errors::ConfigError;
use crate::gostr::go_quote;
use crate::jsonvalue::JsonValue;
use crate::profile::{OutboundKind, is_reserved_synthesized_tag};

/// One outbound/endpoint entry's tag-graph fields, read from
/// raw JSON.
struct Entry {
    tag: String,
    typ: String,
}

pub(crate) fn obj_str<'a>(v: &'a JsonValue, key: &str) -> Option<&'a str> {
    match v {
        JsonValue::Object(obj) => match obj.get(key) {
            Some(JsonValue::Str(s)) => Some(s.as_str()),
            _ => None,
        },
        _ => None,
    }
}

fn entry_of(v: &JsonValue) -> Option<Entry> {
    let tag = obj_str(v, "tag")?;
    let typ = obj_str(v, "type").unwrap_or("");
    Some(Entry {
        tag: tag.to_string(),
        typ: typ.to_string(),
    })
}

/// `detourOf` (`internal/profile/outbound.go:141`): the
/// `detour` field of an options object (`""` when absent).
/// Only `hosts` and `fakeip` DNS server types lack a detour
/// field; every other type (including `local`, whose options
/// embed `DialerOptions`) carries one.
pub(crate) fn detour_of(v: &JsonValue) -> &str {
    obj_str(v, "detour").unwrap_or("")
}

/// Whether a DNS server object carries a detour field:
/// every type except `hosts` and `fakeip` (sing-box v1.14.4
/// `option/dns.go`: only those two server option types lack
/// `DialerOptions`).
fn dns_server_carries_detour(v: &JsonValue) -> bool {
    !matches!(obj_str(v, "type"), Some("hosts") | Some("fakeip"))
}

/// `groupMembers` (`internal/profile/outbound.go:151`):
/// selector member lists plus the selector default; urltest
/// member lists only. Other option types reference no
/// members.
pub(crate) fn group_members(v: &JsonValue) -> Vec<String> {
    let mut out = Vec::new();
    match obj_str(v, "type") {
        Some("selector") => {
            if let JsonValue::Object(obj) = v
                && let Some(JsonValue::Array(members)) = obj.get("outbounds")
            {
                for m in members {
                    if let JsonValue::Str(s) = m {
                        out.push(s.clone());
                    }
                }
            }
            if let Some(d) = obj_str(v, "default")
                && !d.is_empty()
            {
                out.push(d.to_string());
            }
        }
        Some("urltest") => {
            if let JsonValue::Object(obj) = v
                && let Some(JsonValue::Array(members)) = obj.get("outbounds")
            {
                for m in members {
                    if let JsonValue::Str(s) = m {
                        out.push(s.clone());
                    }
                }
            }
        }
        _ => {}
    }
    out
}

/// `validateTagGraph` (`internal/profile/config.go:678`).
/// Takes `&mut SingleConfig` because it resolves each
/// tag-referencing profile's `Outbound.From` (`"outbound"` /
/// `"endpoint"` / `"inline"`) and `Outbound.Type` from the
/// referenced object, exactly as Go's parse does.
pub fn validate_tag_graph(cfg: &mut SingleConfig) -> Result<(), ConfigError> {
    let reserve = |tag: &str, kind: &str| -> Result<(), ConfigError> {
        if is_reserved_synthesized_tag(tag) {
            return Err(config_errorf!(
                "tag {} ({}) is reserved for castctl's synthesised direct outbounds (castctl-direct:<profile>); rename the tag",
                go_quote(tag),
                kind
            ));
        }
        Ok(())
    };
    for raw in &cfg.outbounds_raw {
        if let Some(e) = entry_of(raw) {
            reserve(&e.tag, "outbound")?;
        }
    }
    for raw in &cfg.endpoints_raw {
        if let Some(e) = entry_of(raw) {
            reserve(&e.tag, "endpoint")?;
        }
    }
    for (name, p) in &cfg.profiles {
        if p.outbound.kind == OutboundKind::Inline {
            reserve(
                &p.outbound.tag,
                &format!("inline outbound for profile {name}"),
            )?;
        }
    }

    // tag -> "outbound" | "endpoint" | "inline"
    let mut tags: std::collections::BTreeMap<String, &str> = std::collections::BTreeMap::new();
    for raw in &cfg.outbounds_raw {
        let Some(e) = entry_of(raw) else { continue };
        if let Some(prev) = tags.get(&e.tag) {
            return Err(config_errorf!(
                "duplicate outbound tag {} (already {})",
                go_quote(&e.tag),
                prev
            ));
        }
        tags.insert(e.tag, "outbound");
    }
    for raw in &cfg.endpoints_raw {
        let Some(e) = entry_of(raw) else { continue };
        if let Some(prev) = tags.get(&e.tag) {
            return Err(config_errorf!(
                "duplicate tag {} (already {})",
                go_quote(&e.tag),
                prev
            ));
        }
        tags.insert(e.tag, "endpoint");
    }
    for (name, p) in &cfg.profiles {
        if p.outbound.kind == OutboundKind::Inline {
            if let Some(prev) = tags.get(&p.outbound.tag) {
                return Err(config_errorf!(
                    "duplicate tag {} for profile {} (already {})",
                    go_quote(&p.outbound.tag),
                    go_quote(name),
                    prev
                ));
            }
            tags.insert(p.outbound.tag.clone(), "inline");
        }
    }

    let require = |tag: &str, what: &str| -> Result<(), ConfigError> {
        if !tags.contains_key(tag) {
            return Err(config_errorf!(
                "dangling reference: {} {} does not exist",
                what,
                go_quote(tag)
            ));
        }
        Ok(())
    };

    // Resolve profile tag references (From + Type).
    let mut resolutions: Vec<(String, String, String)> = Vec::new();
    for (name, p) in &cfg.profiles {
        if p.outbound.kind == OutboundKind::Tag {
            let Some(from) = tags.get(&p.outbound.tag) else {
                return Err(config_errorf!(
                    "profile {}: outbound tag {} does not exist",
                    go_quote(name),
                    go_quote(&p.outbound.tag)
                ));
            };
            let mut typ = String::new();
            for raw in &cfg.outbounds_raw {
                if let Some(e) = entry_of(raw)
                    && e.tag == p.outbound.tag
                {
                    typ = e.typ;
                }
            }
            for raw in &cfg.endpoints_raw {
                if let Some(e) = entry_of(raw)
                    && e.tag == p.outbound.tag
                {
                    typ = e.typ;
                }
            }
            resolutions.push((name.clone(), from.to_string(), typ));
        }
    }
    for (name, from, typ) in resolutions {
        if let Some(p) = cfg.profiles.get_mut(&name) {
            p.outbound.from = from;
            p.outbound.typ = typ;
        }
    }

    for raw in &cfg.outbounds_raw {
        let Some(e) = entry_of(raw) else { continue };
        if !detour_of(raw).is_empty() {
            // Go wraps the inner *profile.Error with %v, and
            // Error() carries the `profile: ` prefix, so the
            // rendered text has the prefix TWICE (recorded
            // behaviour, not a bug in this port).
            require(detour_of(raw), "detour")
                .map_err(|err| config_errorf!("outbound {}: {}", go_quote(&e.tag), err.message))?;
        }
        for r in group_members(raw) {
            require(&r, "outbound")
                .map_err(|err| config_errorf!("outbound {}: {}", go_quote(&e.tag), err.message))?;
        }
    }
    for raw in &cfg.endpoints_raw {
        let Some(e) = entry_of(raw) else { continue };
        if !detour_of(raw).is_empty() {
            require(detour_of(raw), "detour")
                .map_err(|err| config_errorf!("endpoint {}: {}", go_quote(&e.tag), err.message))?;
        }
    }
    if let Some(JsonValue::Object(dns)) = &cfg.dns_raw {
        let mut server_tags: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        if let Some(JsonValue::Array(servers)) = dns.get("servers") {
            for srv in servers {
                let Some(tag) = obj_str(srv, "tag") else {
                    continue;
                };
                server_tags.insert(tag.to_string());
                if dns_server_carries_detour(srv) && !detour_of(srv).is_empty() {
                    require(detour_of(srv), "detour").map_err(|err| {
                        config_errorf!("dns server {}: {}", go_quote(tag), err.message)
                    })?;
                }
            }
        }
        if let Some(JsonValue::Str(fin)) = dns.get("final")
            && !fin.is_empty()
            && !server_tags.contains(fin)
        {
            return Err(config_errorf!(
                "dns final {} does not match any dns server tag",
                go_quote(fin)
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jsonvalue::decode_ordered_json;
    use crate::profile::{OutboundKind, OutboundRef};

    fn cfg_from(json: &str) -> SingleConfig {
        let data = json.as_bytes();
        crate::config::parse_single_config(data, "/tmp").unwrap()
    }

    fn raw(json: &str) -> JsonValue {
        decode_ordered_json(json.as_bytes()).unwrap()
    }

    #[test]
    fn reserved_prefix_rejected_everywhere() {
        let mut cfg = cfg_from(
            r#"{"profiles":{"a":{}},"outbounds":[{"type":"direct","tag":"castctl-direct:a"}]}"#,
        );
        let e = validate_tag_graph(&mut cfg).unwrap_err();
        assert_eq!(
            e.message,
            "profile: tag \"castctl-direct:a\" (outbound) is reserved for castctl's synthesised direct outbounds (castctl-direct:<profile>); rename the tag"
        );
        let mut cfg = cfg_from(
            r#"{"profiles":{"a":{"outbound":{"type":"socks","tag":"castctl-direct:a","server":"127.0.0.1","server_port":1080}}}}"#,
        );
        let e = validate_tag_graph(&mut cfg).unwrap_err();
        assert!(
            e.message.contains("inline outbound for profile a"),
            "message: {}",
            e.message
        );
    }

    #[test]
    fn duplicates_and_dangling() {
        let mut cfg = cfg_from(
            r#"{"profiles":{"a":{}},"outbounds":[{"type":"direct","tag":"x"},{"type":"socks","tag":"x"}]}"#,
        );
        let e = validate_tag_graph(&mut cfg).unwrap_err();
        assert_eq!(
            e.message,
            "profile: duplicate outbound tag \"x\" (already outbound)"
        );
        let mut cfg = cfg_from(r#"{"profiles":{"a":{"outbound":"ghost"}}}"#);
        let e = validate_tag_graph(&mut cfg).unwrap_err();
        assert_eq!(
            e.message,
            "profile: profile \"a\": outbound tag \"ghost\" does not exist"
        );
        // Detour dangles.
        let mut cfg = cfg_from(
            r#"{"profiles":{"a":{"outbound":"o1"}},"outbounds":[{"type":"socks","tag":"o1","server":"127.0.0.1","server_port":1080,"detour":"ghost"}]}"#,
        );
        let e = validate_tag_graph(&mut cfg).unwrap_err();
        assert_eq!(
            e.message,
            "profile: outbound \"o1\": profile: dangling reference: detour \"ghost\" does not exist"
        );
        // Selector member dangles.
        let mut cfg = cfg_from(
            r#"{"profiles":{"a":{"outbound":"sel"}},"outbounds":[{"type":"selector","tag":"sel","outbounds":["ghost"]}]}"#,
        );
        let e = validate_tag_graph(&mut cfg).unwrap_err();
        assert_eq!(
            e.message,
            "profile: outbound \"sel\": profile: dangling reference: outbound \"ghost\" does not exist"
        );
        // Endpoint detour dangles.
        let mut cfg = cfg_from(
            r#"{"profiles":{"a":{"outbound":"wg1"}},"endpoints":[{"type":"wireguard","tag":"wg1","detour":"ghost"}]}"#,
        );
        let e = validate_tag_graph(&mut cfg).unwrap_err();
        assert_eq!(
            e.message,
            "profile: endpoint \"wg1\": profile: dangling reference: detour \"ghost\" does not exist"
        );
        // DNS final dangles.
        let mut cfg = cfg_from(
            r#"{"profiles":{"a":{}},"dns":{"servers":[{"tag":"s1","type":"https","server":"1.1.1.1","server_port":443}],"final":"s2"}}"#,
        );
        let e = validate_tag_graph(&mut cfg).unwrap_err();
        assert_eq!(
            e.message,
            "profile: dns final \"s2\" does not match any dns server tag"
        );
    }

    #[test]
    fn resolves_from_and_type() {
        let mut cfg = cfg_from(
            r#"{"profiles":{"a":{"outbound":"o1"},"b":{"outbound":"wg1"}},"outbounds":[{"type":"socks","tag":"o1"}],"endpoints":[{"type":"wireguard","tag":"wg1"}]}"#,
        );
        validate_tag_graph(&mut cfg).unwrap();
        assert_eq!(cfg.profiles["a"].outbound.from, "outbound");
        assert_eq!(cfg.profiles["a"].outbound.typ, "socks");
        assert_eq!(cfg.profiles["b"].outbound.from, "endpoint");
        assert_eq!(cfg.profiles["b"].outbound.typ, "wireguard");
    }

    #[test]
    fn hosts_and_fakeip_servers_carry_no_detour() {
        // A hosts server with no detour is fine; an https
        // server naming a missing detour fails.
        let mut cfg = cfg_from(
            r#"{"profiles":{"a":{}},"dns":{"servers":[{"tag":"h","type":"hosts"},{"tag":"f","type":"fakeip"}],"final":"h"}}"#,
        );
        validate_tag_graph(&mut cfg).unwrap();
        let mut cfg = cfg_from(
            r#"{"profiles":{"a":{}},"dns":{"servers":[{"tag":"s1","type":"https","server":"1.1.1.1","server_port":443,"detour":"ghost"}],"final":"s1"}}"#,
        );
        let e = validate_tag_graph(&mut cfg).unwrap_err();
        assert_eq!(
            e.message,
            "profile: dns server \"s1\": profile: dangling reference: detour \"ghost\" does not exist"
        );
    }

    #[test]
    fn group_members_selector_default() {
        // Selector default is a referenced tag too.
        let v = raw(r#"{"type":"selector","tag":"sel","outbounds":["o1"],"default":"ghost"}"#);
        assert_eq!(
            group_members(&v),
            vec!["o1".to_string(), "ghost".to_string()]
        );
        let v = raw(r#"{"type":"urltest","tag":"u","outbounds":["o1","o2"]}"#);
        assert_eq!(group_members(&v), vec!["o1".to_string(), "o2".to_string()]);
        let v = raw(r#"{"type":"socks","tag":"s","detour":"d"}"#);
        assert!(group_members(&v).is_empty());
        assert_eq!(detour_of(&v), "d");
    }

    #[test]
    fn direct_outbound_string_is_not_a_tag_ref() {
        // parseProfileEntry treats the string "direct" as
        // Direct kind always (config.go:591): no tag lookup.
        let mut cfg = cfg_from(r#"{"profiles":{"a":{"outbound":"direct"}}}"#);
        validate_tag_graph(&mut cfg).unwrap();
        assert_eq!(cfg.profiles["a"].outbound.kind, OutboundKind::Direct);
    }

    #[test]
    fn inline_tag_resolution_uses_raw() {
        let mut cfg = cfg_from(
            r#"{"profiles":{"a":{"outbound":{"type":"socks","tag":"profile:a","server":"127.0.0.1","server_port":1080}}}}"#,
        );
        validate_tag_graph(&mut cfg).unwrap();
        // Inline keeps its parsed type; From stays "" (only
        // tag refs resolve From/Type).
        assert_eq!(cfg.profiles["a"].outbound.kind, OutboundKind::Inline);
        assert_eq!(cfg.profiles["a"].outbound.typ, "socks");
        let _ = OutboundRef::default();
    }
}
