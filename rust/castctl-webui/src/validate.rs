// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! The Go `ParseSingleConfig` tail that `castctl-config`
//! does not (yet) cover: typed `keeper` block parsing
//! (`internal/profile/keeper.go` `parseKeeperBlock`),
//! `validateTagGraph` (`internal/profile/config.go:678`),
//! `validateKeeper` (`keeper.go:824`) and
//! `validateCredentialRefs` (`credentials.go:311`), plus the
//! typed `webui` block (`internal/profile/webui.go`,
//! see [`crate::config`]).
//!
//! Go's parse order: block parses in fixed order (log,
//! telegram, keeper, webui, plugins, credentials), then the
//! tail validations (tag graph, keeper, credential refs).
//! The first error wins, so [`parse_and_validate_config`]
//! runs the same order. All messages carry Go's `profile: `
//! prefix. Only names/tags/paths are named, never values.
//!
//! The web UI needs only `tag` / `profile` / `browser` /
//! `interval` / `notify` / `credentials` from a keeper
//! entry (views + screencast availability); every other key
//! is validated for shape and bounds but not retained —
//! the raw block (`keeper_raw`) is what gets re-encoded on
//! save.

use crate::config::{parse_webui_block, resolve_webui};
use crate::duration::{HOUR_NS, MINUTE_NS, format_duration, parse_duration};
use castctl_config::jsonvalue::JsonValue;
use castctl_config::{SingleConfig, is_reserved_synthesized_tag, validate_profile_name};
use std::collections::HashMap;

/// Default keeper tick cadence: 24h.
pub const DEFAULT_KEEPER_INTERVAL_NS: i64 = 24 * HOUR_NS;
/// Cap for a configured keeper `interval`: 1 year.
pub const MAX_KEEPER_INTERVAL_NS: i64 = 365 * 24 * HOUR_NS;
/// Cap for `retry_backoff` steps: 8.
pub const MAX_RETRY_BACKOFF_STEPS: usize = 8;
/// Cap for `wake_attempts` / `relogin_attempts`: 10.
pub const MAX_KEEPER_ATTEMPTS: i64 = 10;
/// Cap for `proxy_max_header_bytes`: 1 MiB.
pub const MAX_PROXY_HEADER_BYTES: i64 = 1 << 20;
/// Cap for `proxy_max_body_bytes`: 1 GiB.
pub const MAX_PROXY_BODY_BYTES: i64 = 1 << 30;
/// Cap for `observe_inventory_cap`: 10000.
pub const MAX_OBSERVE_INVENTORY_CAP: i64 = 10000;
/// Cap for `proxy_dial_timeout` / `relogin_attach_timeout` /
/// `relogin_cancel_timeout`: 1m.
pub const MAX_PROXY_DIAL_TIMEOUT_NS: i64 = MINUTE_NS;
/// Cap for `relogin_match_timeout`, `relogin_cookie_timeout`,
/// `observe_settle_timeout`, `observe_timeout`: 10m.
pub const MAX_RELOGIN_WAIT_TIMEOUT_NS: i64 = 10 * MINUTE_NS;
/// Cap for `relogin_poll_interval`: 1m.
pub const MAX_RELOGIN_POLL_INTERVAL_NS: i64 = MINUTE_NS;

/// One parsed keeper entry: the fields the web UI reads.
/// All other keys are validated and dropped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeeperEntry {
    pub tag: String,
    pub profile: String,
    pub browser: String,
    pub interval_ns: i64,
    pub interval_set: bool,
    pub notify: String,
    pub credentials: String,
}

impl KeeperEntry {
    /// `EffectiveInterval`: the parsed `interval` when set,
    /// otherwise the 24h default.
    pub fn effective_interval_ns(&self) -> i64 {
        if self.interval_set && self.interval_ns > 0 {
            self.interval_ns
        } else {
            DEFAULT_KEEPER_INTERVAL_NS
        }
    }
}

fn config_error(msg: impl Into<String>) -> String {
    format!("profile: {}", msg.into())
}

/// `ValidateKeeperTag`: non-empty, no surrounding
/// whitespace, not `.` / `..`, no `/`, `\` or control
/// character. The error names the tag (it is an identifier,
/// not a secret).
fn validate_keeper_tag(tag: &str) -> Result<(), String> {
    if tag.is_empty() {
        return Err("keeper tag must not be empty".to_string());
    }
    if tag != tag.trim() {
        return Err(format!("keeper tag {tag:?} has surrounding whitespace"));
    }
    if tag == "." || tag == ".." {
        return Err(format!("keeper tag {tag:?} is a path component"));
    }
    if tag.chars().any(|r| r == '/' || r == '\\' || r.is_control()) {
        return Err(format!("keeper tag {tag:?} contains a forbidden character"));
    }
    Ok(())
}

/// `validateKeeperBrowserURL`: loopback-only CDP URL, http
/// or ws scheme, explicit port 1–65535, no userinfo, query
/// or fragment. Rule-only errors, never the URL.
fn validate_keeper_browser_url(raw: &str) -> Result<(), String> {
    let s = raw.trim();
    // Minimal URL parse: scheme://authority (path ignored
    // for validation except query/fragment rejection).
    let scheme_end = s.find("://").ok_or("unparseable URL")?;
    let scheme = &s[..scheme_end];
    if scheme != "http" && scheme != "ws" {
        return Err("scheme must be http or ws".to_string());
    }
    let rest = &s[scheme_end + 3..];
    let auth_end = rest.find(|c| c == '/' || c == '?' || c == '#').unwrap_or(rest.len());
    let authority = &rest[..auth_end];
    let tail = &rest[auth_end..];
    if tail.contains('?') || tail.contains('#') {
        return Err("must not carry a query or fragment".to_string());
    }
    if authority.contains('@') {
        return Err("must not carry userinfo".to_string());
    }
    let (host, port_str) = split_host_port(authority).ok_or("unparseable URL")?;
    if host.is_empty() {
        return Err("missing host".to_string());
    }
    if port_str.is_empty() {
        return Err("missing port".to_string());
    }
    let port: i64 = port_str.parse().map_err(|_| "port out of range")?;
    if !(1..=65535).contains(&port) {
        return Err("port out of range".to_string());
    }
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        if !ip.is_loopback() {
            return Err("host must be loopback".to_string());
        }
        return Ok(());
    }
    if !host.eq_ignore_ascii_case("localhost") {
        return Err("host must be loopback".to_string());
    }
    Ok(())
}

fn split_host_port(s: &str) -> Option<(&str, &str)> {
    if let Some(bracketed) = s.strip_prefix('[') {
        let close = bracketed.find(']')?;
        let host = &bracketed[..close];
        let rest = &bracketed[close + 1..];
        let port = rest.strip_prefix(':')?;
        if port.contains(':') {
            return None;
        }
        return Some((host, port));
    }
    let mut parts = s.splitn(2, ':');
    let host = parts.next()?;
    let port = parts.next()?;
    if port.contains(':') {
        return None;
    }
    Some((host, port))
}

/// `canonicalBrowserURL` (dedup key): lowercased host
/// (IPs normalized), numeric port, path without a trailing
/// slash. The scheme is NOT part of the key. Falls back to
/// the raw string when the URL does not parse
/// (`canonicalBrowser`).
fn canonical_browser(raw: &str) -> String {
    let s = raw.trim();
    let Some(scheme_end) = s.find("://") else {
        return raw.to_string();
    };
    let scheme = &s[..scheme_end];
    if scheme != "http" && scheme != "ws" {
        return raw.to_string();
    }
    let rest = &s[scheme_end + 3..];
    let auth_end = rest.find(|c| c == '/' || c == '?' || c == '#').unwrap_or(rest.len());
    let authority = &rest[..auth_end];
    let path = rest[auth_end..]
        .split(|c| c == '?' || c == '#')
        .next()
        .unwrap_or("");
    let (host, port_str) = match split_host_port(authority) {
        Some((h, p)) => (h, p),
        None => return raw.to_string(),
    };
    let mut host = host.to_lowercase();
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        host = ip.to_string();
    }
    let port: i64 = match port_str.parse() {
        Ok(p) => p,
        Err(_) => return raw.to_string(),
    };
    let path = path.strip_suffix('/').unwrap_or(path);
    format!("{host}:{port}{path}")
}

/// `normalizeAllowedHost`: lowercase, trailing dots
/// stripped, no `/ : @ ? # [ ] *`, space or control.
fn normalize_allowed_host(raw: &str) -> Result<String, String> {
    if raw.is_empty() {
        return Err("host must not be empty".to_string());
    }
    if raw != raw.trim() {
        return Err("host entry has surrounding whitespace".to_string());
    }
    let s = raw.to_lowercase();
    let s = s.trim_end_matches('.');
    if s.is_empty() {
        return Err("host must not be empty".to_string());
    }
    if s.chars().any(|r| {
        matches!(r, '/' | ':' | '@' | '?' | '#' | '[' | ']' | '*')
            || r.is_whitespace()
            || r.is_control()
    }) {
        return Err("host entry contains a forbidden character".to_string());
    }
    Ok(s.to_string())
}

fn parse_keeper_duration(
    i: usize,
    key: &str,
    s: &str,
    max_ns: i64,
) -> Result<i64, String> {
    if s.trim().is_empty() {
        return Err(config_error(format!(
            "\"keeper\" entry {i}: {key:?} must be a duration string"
        )));
    }
    let d = parse_duration(s).map_err(|_| {
        config_error(format!(
            "\"keeper\" entry {i}: {key:?} must be a positive duration string of at most {}",
            format_duration(max_ns)
        ))
    })?;
    if d <= 0 || d > max_ns {
        return Err(config_error(format!(
            "\"keeper\" entry {i}: {key:?} must be a positive duration string of at most {}",
            format_duration(max_ns)
        )));
    }
    Ok(d)
}

fn parse_keeper_int(i: usize, key: &str, val: &JsonValue, max: i64) -> Result<i64, String> {
    let JsonValue::Number(lit) = val else {
        return Err(config_error(format!(
            "\"keeper\" entry {i}: {key:?} must be a positive integer"
        )));
    };
    let iv: i64 = lit.parse().map_err(|_| {
        config_error(format!(
            "\"keeper\" entry {i}: {key:?} must be a positive integer of at most {max}"
        ))
    })?;
    if iv <= 0 || iv > max {
        return Err(config_error(format!(
            "\"keeper\" entry {i}: {key:?} must be a positive integer of at most {max}"
        )));
    }
    Ok(iv)
}

/// `parseKeeperBlock`: parse one decoded `keeper` value
/// (an array of entry objects). Wrong shapes, wrong types,
/// unknown keys, missing required keys, duplicate tags and
/// invalid browser URLs are all config errors.
pub fn parse_keeper_block(value: &JsonValue) -> Result<Vec<KeeperEntry>, String> {
    let JsonValue::Array(arr) = value else {
        return Err(config_error("\"keeper\" must be an array of entries"));
    };
    let mut entries: Vec<KeeperEntry> = Vec::new();
    let mut seen_tags: Vec<String> = Vec::new();
    for (i, elem) in arr.iter().enumerate() {
        let JsonValue::Object(obj) = elem else {
            return Err(config_error(format!(
                "\"keeper\" entry {i} must be an object"
            )));
        };
        let mut entry = KeeperEntry {
            tag: String::new(),
            profile: String::new(),
            browser: String::new(),
            interval_ns: 0,
            interval_set: false,
            notify: String::new(),
            credentials: String::new(),
        };
        for (k, val) in obj.iter() {
            match k.as_str() {
                "tag" => {
                    let JsonValue::Str(s) = val else {
                        return Err(config_error(format!(
                            "\"keeper\" entry {i}: \"tag\" must be a non-empty string"
                        )));
                    };
                    validate_keeper_tag(s).map_err(|e| {
                        config_error(format!("\"keeper\" entry {i}: invalid \"tag\": {e}"))
                    })?;
                    entry.tag = s.clone();
                }
                "profile" => {
                    let JsonValue::Str(s) = val else {
                        return Err(config_error(format!(
                            "\"keeper\" entry {i}: \"profile\" must be a non-empty string"
                        )));
                    };
                    if s.trim().is_empty() {
                        return Err(config_error(format!(
                            "\"keeper\" entry {i}: \"profile\" must be a non-empty string"
                        )));
                    }
                    validate_profile_name(s).map_err(|_| {
                        config_error(format!(
                            "\"keeper\" entry {i}: invalid profile name {s:?}"
                        ))
                    })?;
                    entry.profile = s.clone();
                }
                "browser" => {
                    let JsonValue::Str(s) = val else {
                        return Err(config_error(format!(
                            "\"keeper\" entry {i}: \"browser\" must be a non-empty CDP URL"
                        )));
                    };
                    if s.trim().is_empty() {
                        return Err(config_error(format!(
                            "\"keeper\" entry {i}: \"browser\" must be a non-empty CDP URL"
                        )));
                    }
                    validate_keeper_browser_url(s).map_err(|e| {
                        config_error(format!("\"keeper\" entry {i}: invalid \"browser\" URL: {e}"))
                    })?;
                    entry.browser = s.trim().to_string();
                }
                "interval" => {
                    let JsonValue::Str(s) = val else {
                        return Err(config_error(format!(
                            "\"keeper\" entry {i}: \"interval\" must be a duration string"
                        )));
                    };
                    if !s.trim().is_empty() {
                        entry.interval_ns =
                            parse_keeper_duration(i, "interval", s, MAX_KEEPER_INTERVAL_NS)?;
                        entry.interval_set = true;
                    }
                }
                "notify" => {
                    let JsonValue::Str(s) = val else {
                        return Err(config_error(format!(
                            "\"keeper\" entry {i}: \"notify\" must be a string"
                        )));
                    };
                    entry.notify = s.clone();
                }
                "credentials" => {
                    let JsonValue::Str(s) = val else {
                        return Err(config_error(format!(
                            "\"keeper\" entry {i}: \"credentials\" must be a non-empty tag string"
                        )));
                    };
                    if s.trim().is_empty() {
                        return Err(config_error(format!(
                            "\"keeper\" entry {i}: \"credentials\" must be a non-empty tag string"
                        )));
                    }
                    validate_keeper_tag(s).map_err(|e| {
                        config_error(format!(
                            "\"keeper\" entry {i}: invalid \"credentials\" tag: {e}"
                        ))
                    })?;
                    entry.credentials = s.clone();
                }
                "wake_on_gateway_failure" => {
                    if !matches!(val, JsonValue::Bool(_)) {
                        return Err(config_error(format!(
                            "\"keeper\" entry {i}: \"wake_on_gateway_failure\" must be a boolean"
                        )));
                    }
                }
                "retry_backoff" => {
                    let JsonValue::Array(items) = val else {
                        return Err(config_error(format!(
                            "\"keeper\" entry {i}: \"retry_backoff\" must be a non-empty array of duration strings"
                        )));
                    };
                    if items.is_empty() {
                        return Err(config_error(format!(
                            "\"keeper\" entry {i}: \"retry_backoff\" must be a non-empty array of duration strings"
                        )));
                    }
                    if items.len() > MAX_RETRY_BACKOFF_STEPS {
                        return Err(config_error(format!(
                            "\"keeper\" entry {i}: \"retry_backoff\" must have at most {MAX_RETRY_BACKOFF_STEPS} steps"
                        )));
                    }
                    for (j, elem) in items.iter().enumerate() {
                        let JsonValue::Str(s) = elem else {
                            return Err(config_error(format!(
                                "\"keeper\" entry {i}: \"retry_backoff\" element {j} must be a duration string"
                            )));
                        };
                        if s.trim().is_empty() {
                            return Err(config_error(format!(
                                "\"keeper\" entry {i}: \"retry_backoff\" element {j} must be a duration string"
                            )));
                        }
                        parse_keeper_duration(i, "retry_backoff", s, MAX_KEEPER_INTERVAL_NS)
                            .map_err(|_| {
                                config_error(format!(
                                    "\"keeper\" entry {i}: \"retry_backoff\" element {j} must be a positive duration string of at most {}",
                                    format_duration(MAX_KEEPER_INTERVAL_NS)
                                ))
                            })?;
                    }
                }
                "expiring_within" => {
                    let JsonValue::Str(s) = val else {
                        return Err(config_error(format!(
                            "\"keeper\" entry {i}: \"expiring_within\" must be a duration string"
                        )));
                    };
                    if !s.trim().is_empty() {
                        parse_keeper_duration(i, "expiring_within", s, MAX_KEEPER_INTERVAL_NS)?;
                    }
                }
                "wake_attempts" | "relogin_attempts" => {
                    parse_keeper_int(i, k, val, MAX_KEEPER_ATTEMPTS)?;
                }
                "proxy_dial_timeout" | "relogin_attach_timeout" | "relogin_cancel_timeout" => {
                    let JsonValue::Str(s) = val else {
                        return Err(config_error(format!(
                            "\"keeper\" entry {i}: {k:?} must be a duration string"
                        )));
                    };
                    parse_keeper_duration(i, k, s, MAX_PROXY_DIAL_TIMEOUT_NS)?;
                }
                "relogin_match_timeout" | "relogin_cookie_timeout" | "observe_settle_timeout"
                | "observe_timeout" => {
                    let JsonValue::Str(s) = val else {
                        return Err(config_error(format!(
                            "\"keeper\" entry {i}: {k:?} must be a duration string"
                        )));
                    };
                    parse_keeper_duration(i, k, s, MAX_RELOGIN_WAIT_TIMEOUT_NS)?;
                }
                "relogin_poll_interval" => {
                    let JsonValue::Str(s) = val else {
                        return Err(config_error(format!(
                            "\"keeper\" entry {i}: {k:?} must be a duration string"
                        )));
                    };
                    parse_keeper_duration(i, k, s, MAX_RELOGIN_POLL_INTERVAL_NS)?;
                }
                "proxy_max_header_bytes" => {
                    parse_keeper_int(i, k, val, MAX_PROXY_HEADER_BYTES)?;
                }
                "proxy_max_body_bytes" => {
                    parse_keeper_int(i, k, val, MAX_PROXY_BODY_BYTES)?;
                }
                "observe_inventory_cap" => {
                    parse_keeper_int(i, k, val, MAX_OBSERVE_INVENTORY_CAP)?;
                }
                "proxy_allowed_hosts" => {
                    let JsonValue::Array(items) = val else {
                        return Err(config_error(format!(
                            "\"keeper\" entry {i}: \"proxy_allowed_hosts\" must be a non-empty array of host strings"
                        )));
                    };
                    if items.is_empty() {
                        return Err(config_error(format!(
                            "\"keeper\" entry {i}: \"proxy_allowed_hosts\" must be a non-empty array of host strings"
                        )));
                    }
                    for (j, elem) in items.iter().enumerate() {
                        let JsonValue::Str(s) = elem else {
                            return Err(config_error(format!(
                                "\"keeper\" entry {i}: \"proxy_allowed_hosts\" element {j} must be a string"
                            )));
                        };
                        normalize_allowed_host(s).map_err(|e| {
                            config_error(format!(
                                "\"keeper\" entry {i}: \"proxy_allowed_hosts\" element {j}: {e}"
                            ))
                        })?;
                    }
                }
                _ => {
                    return Err(config_error(format!("unknown keeper config key {k:?}")));
                }
            }
        }
        if entry.tag.is_empty() {
            return Err(config_error(format!(
                "\"keeper\" entry {i} requires a \"tag\" key"
            )));
        }
        if entry.profile.is_empty() {
            return Err(config_error(format!(
                "\"keeper\" entry {i} requires a \"profile\" key"
            )));
        }
        if seen_tags.contains(&entry.tag) {
            return Err(config_error(format!(
                "\"keeper\" has duplicate tag {:?}",
                entry.tag
            )));
        }
        seen_tags.push(entry.tag.clone());
        entries.push(entry);
    }
    Ok(entries)
}

/// The tags an outbound object references: its `detour`
/// (when present) plus, for selector/urltest types, the
/// `outbounds` member list and the selector `default`.
/// Mirrors Go's `detourOf` + `referencedTags`
/// (`groupMembers`) on the parsed options, read off the raw
/// JSON instead (the `detour` key and the member lists sit
/// at the outbound object's top level in the file).
fn outbound_referenced_tags(obj: &castctl_config::jsonvalue::OrderedObject) -> Vec<String> {
    let mut refs: Vec<String> = Vec::new();
    if let Some(JsonValue::Str(d)) = obj.get("detour") {
        if !d.is_empty() {
            refs.push(d.clone());
        }
    }
    let is_group = matches!(obj.get("type"), Some(JsonValue::Str(t)) if t == "selector" || t == "urltest");
    if is_group {
        if let Some(JsonValue::Array(members)) = obj.get("outbounds") {
            for m in members {
                if let JsonValue::Str(tag) = m {
                    refs.push(tag.clone());
                }
            }
        }
        if let Some(JsonValue::Str(d)) = obj.get("default") {
            if !d.is_empty() {
                refs.push(d.clone());
            }
        }
    }
    refs
}

/// `validateTagGraph`: one tag namespace across outbounds,
/// endpoints and inline profile outbounds; reserved
/// synthesized tags; dangling profile/outbound references.
pub fn validate_tag_graph(cfg: &SingleConfig) -> Result<(), String> {
    let mut tags: HashMap<String, &str> = HashMap::new();
    // Reserved synthesized tags first, in Go's order:
    // outbounds, endpoints, inline profile outbounds.
    if let Some(JsonValue::Array(obs)) = &cfg.outbounds_raw {
        for ob in obs {
            if let JsonValue::Object(o) = ob {
                if let Some(JsonValue::Str(tag)) = o.get("tag") {
                    if is_reserved_synthesized_tag(tag) {
                        return Err(config_error(format!(
                            "tag {tag:?} (outbound) is reserved for castctl's synthesised direct outbounds (castctl-direct:<profile>); rename the tag"
                        )));
                    }
                }
            }
        }
    }
    if let Some(JsonValue::Array(eps)) = &cfg.endpoints_raw {
        for ep in eps {
            if let JsonValue::Object(o) = ep {
                if let Some(JsonValue::Str(tag)) = o.get("tag") {
                    if is_reserved_synthesized_tag(tag) {
                        return Err(config_error(format!(
                            "tag {tag:?} (endpoint) is reserved for castctl's synthesised direct outbounds (castctl-direct:<profile>); rename the tag"
                        )));
                    }
                }
            }
        }
    }
    for (name, p) in cfg.profiles.iter() {
        if let castctl_config::profile::OutboundKind::Inline = p.outbound.kind {
            if is_reserved_synthesized_tag(&p.outbound.tag) {
                return Err(config_error(format!(
                    "tag {:?} (inline outbound for profile {}) is reserved for castctl's synthesised direct outbounds (castctl-direct:<profile>); rename the tag",
                    p.outbound.tag, name
                )));
            }
        }
    }
    // Duplicate tags, in Go's order: outbounds, endpoints,
    // inline profile outbounds.
    if let Some(JsonValue::Array(obs)) = &cfg.outbounds_raw {
        for ob in obs {
            if let JsonValue::Object(o) = ob {
                if let Some(JsonValue::Str(tag)) = o.get("tag") {
                    if let Some(prev) = tags.get(tag) {
                        return Err(config_error(format!(
                            "duplicate outbound tag {tag:?} (already {prev})"
                        )));
                    }
                    tags.insert(tag.clone(), "outbound");
                }
            }
        }
    }
    if let Some(JsonValue::Array(eps)) = &cfg.endpoints_raw {
        for ep in eps {
            if let JsonValue::Object(o) = ep {
                if let Some(JsonValue::Str(tag)) = o.get("tag") {
                    if let Some(prev) = tags.get(tag) {
                        return Err(config_error(format!(
                            "duplicate tag {tag:?} (already {prev})"
                        )));
                    }
                    tags.insert(tag.clone(), "endpoint");
                }
            }
        }
    }
    for (name, p) in cfg.profiles.iter() {
        if let castctl_config::profile::OutboundKind::Inline = p.outbound.kind {
            let tag = &p.outbound.tag;
            if let Some(prev) = tags.get(tag) {
                return Err(config_error(format!(
                    "duplicate tag {tag:?} for profile {name:?} (already {prev})"
                )));
            }
            tags.insert(tag.clone(), "inline");
        }
    }
    // Dangling profile outbound references.
    for (name, p) in cfg.profiles.iter() {
        if let castctl_config::profile::OutboundKind::Tag = p.outbound.kind {
            if !tags.contains_key(&p.outbound.tag) {
                return Err(config_error(format!(
                    "profile {name:?}: outbound tag {:?} does not exist",
                    p.outbound.tag
                )));
            }
        }
    }
    // Dangling outbound references (detour / group members).
    if let Some(JsonValue::Array(obs)) = &cfg.outbounds_raw {
        for ob in obs {
            if let JsonValue::Object(o) = ob {
                let tag = match o.get("tag") {
                    Some(JsonValue::Str(t)) => t.clone(),
                    _ => String::new(),
                };
                for r in outbound_referenced_tags(o) {
                    if !tags.contains_key(&r) {
                        return Err(config_error(format!(
                            "outbound {tag:?}: dangling reference: \"outbound\" {r:?} does not exist"
                        )));
                    }
                }
            }
        }
    }
    Ok(())
}

/// `validateKeeper`: every entry's profile must exist, no
/// two entries may name the same profile or share a browser
/// URL (canonicalised), and `notify: "telegram"` requires
/// the `telegram` block.
pub fn validate_keeper(cfg: &SingleConfig, entries: &[KeeperEntry]) -> Result<(), String> {
    let mut seen_profiles: HashMap<&str, &str> = HashMap::new();
    let mut seen_browsers: HashMap<String, &str> = HashMap::new();
    for e in entries {
        if !cfg.profiles.contains_key(&e.profile) {
            return Err(config_error(format!(
                "keeper: entry {:?} names profile {:?}, which does not exist",
                e.tag, e.profile
            )));
        }
        if let Some(prev) = seen_profiles.get(e.profile.as_str()) {
            return Err(config_error(format!(
                "keeper: entries {prev:?} and {:?} both name profile {:?}",
                e.tag, e.profile
            )));
        }
        seen_profiles.insert(e.profile.as_str(), e.tag.as_str());
        if !e.browser.is_empty() {
            let canon = canonical_browser(&e.browser);
            if let Some(prev) = seen_browsers.get(&canon) {
                return Err(config_error(format!(
                    "keeper: entries {prev:?} and {:?} share one browser URL",
                    e.tag
                )));
            }
            seen_browsers.insert(canon, e.tag.as_str());
        }
        match e.notify.as_str() {
            "" | "telegram" => {}
            _ => {
                return Err(config_error(format!(
                    "keeper: entry {:?} has unknown notify {:?} (only \"telegram\" is supported)",
                    e.tag, e.notify
                )));
            }
        }
        if e.notify == "telegram" && cfg.telegram.is_none() {
            return Err(config_error(format!(
                "keeper: entry {:?} notifies \"telegram\" but no \"telegram\" block exists",
                e.tag
            )));
        }
    }
    Ok(())
}

/// `validateCredentialRefs`: a keeper entry's `credentials`
/// tag must name an entry in the `credentials` block, for
/// the same profile.
pub fn validate_credential_refs(cfg: &SingleConfig, entries: &[KeeperEntry]) -> Result<(), String> {
    for e in entries {
        if e.credentials.is_empty() {
            continue;
        }
        let Some(creds) = &cfg.credentials else {
            return Err(config_error(format!(
                "keeper: entry {:?} references credentials {:?}, but no \"credentials\" block exists",
                e.tag, e.credentials
            )));
        };
        let Some(cred) = creds.entries.iter().find(|c| c.tag == e.credentials) else {
            return Err(config_error(format!(
                "keeper: entry {:?} references credentials {:?}, which does not exist",
                e.tag, e.credentials
            )));
        };
        if cred.profile != e.profile {
            return Err(config_error(format!(
                "keeper: entry {:?} references credentials {:?} for profile {:?}, not {:?}",
                e.tag, e.credentials, cred.profile, e.profile
            )));
        }
    }
    Ok(())
}

/// Go's `ParseSingleConfig` tail, in Go's order: the typed
/// `keeper` block, then the typed `webui` block, then the
/// tag graph, keeper cross-references and credential refs.
/// Returns the parsed config plus the keeper entries.
pub fn parse_and_validate_config(
    data: &[u8],
    base_dir: &std::path::Path,
) -> Result<(SingleConfig, Vec<KeeperEntry>), String> {
    let cfg = castctl_config::parse_single_config(data, base_dir)
        .map_err(|e| e.message().to_string())?;
    let mut entries: Vec<KeeperEntry> = Vec::new();
    if let Some(raw) = &cfg.keeper_raw {
        entries = parse_keeper_block(raw)?;
    }
    if let Some(raw) = &cfg.webui_raw {
        parse_webui_block(raw, base_dir)?;
    }
    validate_tag_graph(&cfg)?;
    validate_keeper(&cfg, &entries)?;
    validate_credential_refs(&cfg, &entries)?;
    Ok((cfg, entries))
}

/// `ResolveWebUI` on a parsed config (re-check without the
/// config directory; see [`resolve_webui`]).
pub fn resolve_webui_from_config(cfg: &SingleConfig) -> Result<Option<crate::config::WebUIConfig>, String> {
    resolve_webui(cfg.webui_raw.as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;
    use castctl_config::jsonvalue::decode_ordered_json;
    use std::path::Path;

    fn cfg(json: &str) -> (SingleConfig, Vec<KeeperEntry>) {
        parse_and_validate_config(json.as_bytes(), Path::new("/cfg")).unwrap()
    }

    #[test]
    fn valid_fixture_parses() {
        let (c, k) = cfg(
            r#"{"default_profile":"muse01","profiles":{"muse01":{"cookies_file":"profiles/muse01/cookies.txt","outbound":"proxy-eu"}},"outbounds":[{"type":"trojan","tag":"proxy-eu","server":"203.0.113.10","server_port":443,"password":"x"}],"webui":{"listen":"127.0.0.1:8317","token":"abc"}}"#,
        );
        assert_eq!(c.default_profile, Some("muse01".to_string()));
        assert!(k.is_empty());
    }

    #[test]
    fn duplicate_outbound_tag_rejected() {
        let err = parse_and_validate_config(
            br#"{"profiles":{},"outbounds":[{"type":"trojan","tag":"x"},{"type":"trojan","tag":"x"}]}"#,
            Path::new("/cfg"),
        )
        .unwrap_err();
        assert!(err.contains("duplicate outbound tag \"x\" (already outbound)"), "{err}");
    }

    #[test]
    fn dangling_profile_outbound_rejected() {
        let err = parse_and_validate_config(
            br#"{"profiles":{"p":{"outbound":"nope"}}}"#,
            Path::new("/cfg"),
        )
        .unwrap_err();
        assert!(err.contains("profile \"p\": outbound tag \"nope\" does not exist"), "{err}");
    }

    #[test]
    fn keeper_entry_needs_existing_profile() {
        let err = parse_and_validate_config(
            br#"{"profiles":{},"keeper":[{"tag":"k1","profile":"ghost","browser":"http://127.0.0.1:9222"}]}"#,
            Path::new("/cfg"),
        )
        .unwrap_err();
        assert!(err.contains("names profile \"ghost\", which does not exist"), "{err}");
    }

    #[test]
    fn keeper_entry_parses_and_effective_interval() {
        let (_, k) = cfg(
            r#"{"profiles":{"p":{}},"keeper":[{"tag":"k1","profile":"p","browser":"http://127.0.0.1:9222","interval":"30m","notify":"telegram"}],"telegram":{"profile":"p","token":"x","allowed_user_ids":[1]}}"#,
        );
        assert_eq!(k.len(), 1);
        assert_eq!(k[0].effective_interval_ns(), 30 * 60 * 1_000_000_000);
        let (_, k2) = cfg(
            r#"{"profiles":{"p":{}},"keeper":[{"tag":"k1","profile":"p","browser":"http://127.0.0.1:9222"}]}"#,
        );
        assert_eq!(k2[0].effective_interval_ns(), 24 * HOUR_NS);
    }

    #[test]
    fn keeper_unknown_key_rejected() {
        let err = parse_and_validate_config(
            br#"{"profiles":{"p":{}},"keeper":[{"tag":"k1","profile":"p","browser":"http://127.0.0.1:9222","bogus":1}]}"#,
            Path::new("/cfg"),
        )
        .unwrap_err();
        assert!(err.contains("unknown keeper config key"), "{err}");
    }

    #[test]
    fn fail_before_tag_graph() {
        // If the tag-graph check were dropped, a config
        // with a dangling outbound reference would parse
        // and serve: this pins the refusal.
        assert!(parse_and_validate_config(
            br#"{"profiles":{"p":{"outbound":"ghost"}}}"#,
            Path::new("/cfg"),
        )
        .is_err());
        let _ = decode_ordered_json("{}");
    }
}
