// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Per-profile DNS resolution and the DNS / WireGuard
//! validators: `ResolveProfileDNS`, `validateProfileDNS`,
//! `validateWireGuardDNS`, `validateWireGuardPrivateKeys`,
//! `detourChain`, `OutboundIdentityForConfig`, and the
//! load-time tail chain (`validate_single_config`).
//!
//! Go sources: `internal/profile/dns.go`
//! (`ResolveProfileDNS`, `ensureLocalBootstrapServer`,
//! `ruleRoutesToServer`, `defaultDetourForProfile`,
//! `buildDefaultDNSOptions`, `buildWireGuardDNSOptions`,
//! `wireGuardDNSForProfile`, `reachableTagsForProfile`,
//! `validateProfileDNS`, `validateWireGuardDNS`,
//! `profileDNSWireGuardEndpoints`),
//! `internal/profile/wireguard.go`
//! (`validateWireGuardPrivateKeys`,
//! `canonicalWireGuardKey`, `wireGuardEndpointsForProfile`,
//! `dnsWireGuardEndpoints`, `walkWireGuardEndpoints`,
//! `outboundNextTags`, `nextTags`, `wireGuardPrivateKey`),
//! `internal/profile/outbound.go` (`detourOf`,
//! `groupMembers`), `internal/commands/runtime.go`
//! (`detourChain`), `internal/profile/identity.go`
//! (`OutboundIdentityForConfig`).
//!
//! The validators read tag/type/detour/member/private-key
//! fields out of the raw JSON, like `taggraph.rs`: sing-box
//! option parsing is deferred (D-M2-1), so an unknown DNS
//! server type or a malformed server object is not rejected
//! here the way Go's `parseDNS` rejects it at load. A
//! non-object server is skipped for the detour/final checks
//! (Go would have failed the parse first).
//!
//! Order note: Go iterates Go maps for the
//! `wireguard_dns` map and the profile loops, so when
//! several errors exist at once its first error is
//! arbitrary; Rust iterates file/sorted order, so the first
//! error is deterministic. The checks and their texts are
//! identical; only the choice among multiple simultaneous
//! errors can differ.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use sha2::{Digest, Sha256};

use crate::config::SingleConfig;
use crate::config_errorf;
use crate::errors::{ConfigError, raw_io_error};
use crate::gostr::go_quote;
use crate::jsonvalue::{JsonValue, encode_ordered_json};
use crate::profile::{OutboundKind, Profile, synthesized_direct_tag};
use crate::taggraph::{detour_of, group_members, obj_str};

/// The tag of the single server in the synthesised default
/// and WireGuard resolvers (`dns.go`, `defaultDNSServerTag`).
pub const DEFAULT_DNS_SERVER_TAG: &str = "castctl-doh";

/// The tag of the `local` DNS server
/// (`domain_resolver.go`, `LocalBootstrapServerTag`).
pub const LOCAL_BOOTSTRAP_SERVER_TAG: &str = "local";

/// Which precedence branch produced a resolution
/// (`dns.go`, `DNSSource`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsSource {
    Profile,
    WireGuard,
    Default,
    GlobalCompat,
    None,
}

impl DnsSource {
    /// The Go `DNSSource` string.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            DnsSource::Profile => "profile",
            DnsSource::WireGuard => "wireguard",
            DnsSource::Default => "default",
            DnsSource::GlobalCompat => "global-compat",
            DnsSource::None => "none",
        }
    }
}

/// One DNS server, as the profile-test query path needs it:
/// tag, type, address, port, DoH path, detour.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsServer {
    pub tag: String,
    pub typ: String,
    pub server: String,
    pub server_port: u16,
    pub path: String,
    pub detour: String,
}

/// One profile's effective resolver
/// (`dns.go`, `ResolvedDNS`).
#[derive(Debug, Clone)]
pub struct ResolvedDns {
    pub source: DnsSource,
    pub servers: Vec<DnsServer>,
    pub final_tag: String,
    /// Set for the global-compat branch and for the
    /// WireGuard branch when it shadows a present
    /// top-level dns section; the caller prints it once
    /// on stderr. (`profile test` ignores it.)
    pub warning: String,
    /// The runtime-only direct outbound tag the detour
    /// names, or `""` when the resolution detours to an
    /// existing config tag.
    pub synthesized_direct_tag: String,
    /// The tag of the `local` DNS server, or `""` when
    /// there is no resolver at all (`DNSSourceNone`).
    /// Always `"local"` when set.
    pub local_server_tag: String,
}

impl ResolvedDns {
    /// The server a query goes to: the `final` server when
    /// set and present, else the first server. (Go's
    /// `profile test` reports `Servers[0].Tag` for display
    /// but the sing-box client routes through `final`.)
    #[must_use]
    pub fn query_server(&self) -> Option<&DnsServer> {
        if !self.final_tag.is_empty()
            && let Some(s) = self.servers.iter().find(|s| s.tag == self.final_tag)
        {
            return Some(s);
        }
        self.servers.first()
    }

    /// The display server tag: the first server's tag
    /// (`profile test` reports `Servers[0].Tag`).
    #[must_use]
    pub fn display_server_tag(&self) -> Option<&str> {
        self.servers.first().map(|s| s.tag.as_str())
    }
}

/// Outbounds by tag, from the raw list (first entry wins;
/// duplicates are rejected by `validate_tag_graph`).
fn outbounds_by_tag(cfg: &SingleConfig) -> BTreeMap<String, &JsonValue> {
    let mut m = BTreeMap::new();
    for raw in &cfg.outbounds_raw {
        if let Some(tag) = obj_str(raw, "tag") {
            m.entry(tag.to_string()).or_insert(raw);
        }
    }
    m
}

/// Endpoints by tag, from the raw list.
fn endpoints_by_tag(cfg: &SingleConfig) -> BTreeMap<String, &JsonValue> {
    let mut m = BTreeMap::new();
    for raw in &cfg.endpoints_raw {
        if let Some(tag) = obj_str(raw, "tag") {
            m.entry(tag.to_string()).or_insert(raw);
        }
    }
    m
}

/// `outboundNextTags` (`wireguard.go:253`): an outbound's
/// member tags plus its detour.
fn outbound_next_tags(v: &JsonValue) -> Vec<String> {
    let mut next = group_members(v);
    if !detour_of(v).is_empty() {
        next.push(detour_of(v).to_string());
    }
    next
}

/// `nextTags` (`wireguard.go:262`): an endpoint's detour
/// tag, if any.
fn endpoint_next_tags(v: &JsonValue) -> Vec<String> {
    if detour_of(v).is_empty() {
        Vec::new()
    } else {
        vec![detour_of(v).to_string()]
    }
}

/// `wireGuardPrivateKey` (`wireguard.go:273`): the private
/// key of a parsed WireGuard endpoint. `None` when the
/// object is not a WireGuard endpoint; `Some("")` when it
/// is one with no key (an absent key is sing-box's own
/// runtime concern, not a sharing violation).
fn wireguard_private_key(ep_raw: &JsonValue) -> Option<String> {
    if obj_str(ep_raw, "type") != Some("wireguard") {
        return None;
    }
    Some(obj_str(ep_raw, "private_key").unwrap_or("").to_string())
}

/// `canonicalWireGuardKey` (`wireguard.go:153`): keys that
/// base64-decode (StdEncoding, as sing-box does) compare
/// by decoded bytes; keys that do not decode compare by
/// exact string. The `b:`/`s:` prefix keeps the two
/// families apart. (Go keeps the decoded bytes in a
/// `string`; Rust uses a byte vector for the same reason.)
/// Go's `StdEncoding.DecodeString` IGNORES non-zero
/// padding bits in the last data character, while the
/// Rust `base64` crate rejects them (`InvalidLastSymbol`)
/// — so `"...A="` and `"...B="` must both decode to 32
/// zero bytes here, as Go documents. The masked retry
/// below reproduces Go's leniency exactly.
fn canonical_wireguard_key(key: &str) -> Vec<u8> {
    if let Some(decoded) = decode_wireguard_key_go(key) {
        let mut out = vec![b'b'];
        out.extend_from_slice(&decoded);
        return out;
    }
    let mut out = vec![b's'];
    out.extend_from_slice(key.as_bytes());
    out
}

/// Decode a WireGuard private key the way Go does: strict
/// first, then — only when the strict decode fails — mask
/// the unused low bits of the last data character (2 bits
/// for one `=` pad, 4 for two) and retry. Any other
/// invalidity still fails and falls back to exact-string
/// comparison.
fn decode_wireguard_key_go(key: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(key) {
        return Some(decoded);
    }
    let pad = key.bytes().rev().take_while(|b| *b == b'=').count();
    if (pad != 1 && pad != 2) || !key.len().is_multiple_of(4) {
        return None;
    }
    let data = &key[..key.len() - pad];
    let last = data.as_bytes().last()?;
    let value = match last {
        b'A'..=b'Z' => last - b'A',
        b'a'..=b'z' => last - b'a' + 26,
        b'0'..=b'9' => last - b'0' + 52,
        b'+' => 62,
        b'/' => 63,
        _ => return None,
    };
    let mask: u8 = if pad == 1 { 0b1111_1100 } else { 0b1111_0000 };
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut fixed = data.as_bytes().to_vec();
    fixed[data.len() - 1] = ALPHABET[(value & mask) as usize];
    let fixed_str = std::str::from_utf8(&fixed).ok()?;
    let mut padded = fixed_str.to_string();
    for _ in 0..pad {
        padded.push('=');
    }
    base64::engine::general_purpose::STANDARD
        .decode(padded)
        .ok()
}

/// `walkWireGuardEndpoints` (`wireguard.go:213`): the
/// sorted tags of the WireGuard endpoints reachable from
/// seeds, following detour chains and selector/urltest
/// member lists. Cycles terminate via the visited set.
/// Tags that do not exist in either section are ignored
/// here: `validate_tag_graph` already rejects dangling
/// references before this runs.
fn walk_wireguard_endpoints(
    seeds: &[String],
    endpoints: &BTreeMap<String, &JsonValue>,
    outbounds: &BTreeMap<String, &JsonValue>,
) -> Vec<String> {
    let mut visited: BTreeSet<String> = BTreeSet::new();
    let mut found: BTreeSet<String> = BTreeSet::new();
    let mut queue: VecDeque<String> = seeds.iter().cloned().collect();
    while let Some(tag) = queue.pop_front() {
        if !visited.insert(tag.clone()) {
            continue;
        }
        if let Some(ep) = endpoints.get(&tag) {
            if obj_str(ep, "type") == Some("wireguard") {
                found.insert(tag.clone());
            }
            queue.extend(endpoint_next_tags(ep));
            continue;
        }
        if let Some(ob) = outbounds.get(&tag) {
            queue.extend(outbound_next_tags(ob));
        }
    }
    found.into_iter().collect()
}

/// `wireGuardEndpointsForProfile` (`wireguard.go:176`):
/// the sorted tags of the WireGuard endpoints reachable
/// from a profile's outbound selection.
fn wireguard_endpoints_for_profile(
    p: &Profile,
    endpoints: &BTreeMap<String, &JsonValue>,
    outbounds: &BTreeMap<String, &JsonValue>,
) -> Vec<String> {
    let mut seeds: Vec<String> = Vec::new();
    match p.outbound.kind {
        OutboundKind::Tag => seeds.push(p.outbound.tag.clone()),
        OutboundKind::Inline => {
            if let Some(raw) = &p.outbound.raw {
                // An inline outbound can never itself be
                // wireguard (parseOutbound rejects type
                // "wireguard"), but its detour or member
                // list may resolve to one.
                seeds.extend(outbound_next_tags(raw));
            }
        }
        OutboundKind::Direct => {}
    }
    walk_wireguard_endpoints(&seeds, endpoints, outbounds)
}

/// `dnsWireGuardEndpoints` (`wireguard.go:195`): the
/// sorted tags of the WireGuard endpoints reachable from
/// the global dns section's detour chains.
fn dns_wireguard_endpoints(
    cfg: &SingleConfig,
    endpoints: &BTreeMap<String, &JsonValue>,
    outbounds: &BTreeMap<String, &JsonValue>,
) -> Vec<String> {
    let Some(JsonValue::Object(dns)) = &cfg.dns_raw else {
        return Vec::new();
    };
    let Some(JsonValue::Array(servers)) = dns.get("servers") else {
        return Vec::new();
    };
    let mut seeds: Vec<String> = Vec::new();
    for srv in servers {
        if !detour_of(srv).is_empty() {
            seeds.push(detour_of(srv).to_string());
        }
    }
    walk_wireguard_endpoints(&seeds, endpoints, outbounds)
}

/// `profileDNSWireGuardEndpoints` (`dns.go:652`): the
/// WireGuard endpoint tags reachable from one profile's
/// own dns detour chains.
fn profile_dns_wireguard_endpoints(
    p: &Profile,
    endpoints: &BTreeMap<String, &JsonValue>,
    outbounds: &BTreeMap<String, &JsonValue>,
) -> Vec<String> {
    let Some(dns) = &p.dns else {
        return Vec::new();
    };
    let mut seeds: Vec<String> = Vec::new();
    if let JsonValue::Object(obj) = dns
        && let Some(JsonValue::Array(servers)) = obj.get("servers")
    {
        for srv in servers {
            if !detour_of(srv).is_empty() {
                seeds.push(detour_of(srv).to_string());
            }
        }
    }
    walk_wireguard_endpoints(&seeds, endpoints, outbounds)
}

/// `validateWireGuardPrivateKeys` (`wireguard.go:68`):
/// two profiles may NOT share a WireGuard endpoint config
/// with the same private key (compared by value, never by
/// tag). The error names both profiles and both endpoint
/// tags and NEVER contains the key value. Endpoints not
/// referenced by any profile are out of scope; two
/// same-key endpoints resolved by ONE profile are out of
/// scope; an endpoint with an empty private key is
/// skipped.
pub fn validate_wireguard_private_keys(cfg: &SingleConfig) -> Result<(), ConfigError> {
    let endpoints = endpoints_by_tag(cfg);
    let outbounds = outbounds_by_tag(cfg);

    // WireGuard endpoints reachable from the global dns
    // servers' detour chains, keyed by canonical key: the
    // first dns tag seen per key.
    let mut dns_tag_by_key: BTreeMap<Vec<u8>, String> = BTreeMap::new();
    for tag in dns_wireguard_endpoints(cfg, &endpoints, &outbounds) {
        let Some(ep) = endpoints.get(&tag) else {
            continue;
        };
        let Some(key) = wireguard_private_key(ep) else {
            continue;
        };
        if key.is_empty() {
            continue;
        }
        let canonical = canonical_wireguard_key(&key);
        dns_tag_by_key.entry(canonical).or_insert(tag);
    }

    struct SeenKey {
        profile: String,
        tag: String,
    }
    let mut seen: BTreeMap<Vec<u8>, SeenKey> = BTreeMap::new();
    for name in cfg.profile_names() {
        let Some(p) = cfg.profiles.get(&name) else {
            continue;
        };
        let own_tags = wireguard_endpoints_for_profile(p, &endpoints, &outbounds);
        let dns_tags = profile_dns_wireguard_endpoints(p, &endpoints, &outbounds);
        // Own dns detour vs own outbound: same key through
        // two different tags is the sharing violation; the
        // same tag is one config and is not an error.
        let mut own_by_key: BTreeMap<Vec<u8>, String> = BTreeMap::new();
        for tag in &own_tags {
            let Some(ep) = endpoints.get(tag) else {
                continue;
            };
            let Some(key) = wireguard_private_key(ep) else {
                continue;
            };
            if key.is_empty() {
                continue;
            }
            own_by_key.insert(canonical_wireguard_key(&key), tag.clone());
        }
        for tag in &dns_tags {
            let Some(ep) = endpoints.get(tag) else {
                continue;
            };
            let Some(key) = wireguard_private_key(ep) else {
                continue;
            };
            if key.is_empty() {
                continue;
            }
            let canonical = canonical_wireguard_key(&key);
            if let Some(own_tag) = own_by_key.get(&canonical)
                && own_tag != tag
            {
                return Err(config_errorf!(
                    "wireguard private key shared by profile {} and the dns detour (endpoints {} and {}); each profile must use a distinct wireguard private key",
                    go_quote(&name),
                    go_quote(own_tag),
                    go_quote(tag)
                ));
            }
        }
        // Cross-profile check over the union of the
        // profile's outbound and own-dns endpoints.
        for tag in own_tags.iter().chain(dns_tags.iter()) {
            let Some(ep) = endpoints.get(tag) else {
                continue;
            };
            let Some(key) = wireguard_private_key(ep) else {
                continue;
            };
            if key.is_empty() {
                continue;
            }
            let canonical = canonical_wireguard_key(&key);
            if let Some(dns_tag) = dns_tag_by_key.get(&canonical)
                && dns_tag != tag
            {
                return Err(config_errorf!(
                    "wireguard private key shared by profile {} and the dns detour (endpoints {} and {}); each profile must use a distinct wireguard private key",
                    go_quote(&name),
                    go_quote(tag),
                    go_quote(dns_tag)
                ));
            }
            if let Some(prev) = seen.get(&canonical) {
                if prev.profile == name {
                    continue;
                }
                return Err(config_errorf!(
                    "wireguard private key shared by profiles {} and {} (endpoints {} and {}); each profile must use a distinct wireguard private key",
                    go_quote(&prev.profile),
                    go_quote(&name),
                    go_quote(&prev.tag),
                    go_quote(tag)
                ));
            }
            seen.insert(
                canonical,
                SeenKey {
                    profile: name.clone(),
                    tag: tag.clone(),
                },
            );
        }
    }
    Ok(())
}

/// `reachableTagsForProfile` (`dns.go:478`): the tag set
/// a profile's own dns detours may name — the profile's
/// outbound tag (or inline tag), every tag reachable from
/// it through detour chains and selector/urltest member
/// lists that names a global outbound or endpoint node,
/// plus, for direct profiles only, the profile's
/// synthesised direct tag. A tag that resolves to no
/// global node — a dangling tag, or another profile's
/// inline outbound tag — is NOT reachable.
pub(crate) fn reachable_tags_for_profile(cfg: &SingleConfig, p: &Profile) -> BTreeSet<String> {
    let outbounds = outbounds_by_tag(cfg);
    let endpoints = endpoints_by_tag(cfg);
    let own_inline = if p.outbound.kind == OutboundKind::Inline {
        p.outbound.tag.clone()
    } else {
        String::new()
    };
    let synth = if p.outbound.kind == OutboundKind::Direct {
        synthesized_direct_tag(&p.name)
    } else {
        String::new()
    };
    let is_node = |tag: &str| -> bool {
        tag == own_inline
            || tag == synth
            || outbounds.contains_key(tag)
            || endpoints.contains_key(tag)
    };
    let mut reachable: BTreeSet<String> = BTreeSet::new();
    let mut queue: VecDeque<String> = VecDeque::new();
    match p.outbound.kind {
        OutboundKind::Tag => queue.push_back(p.outbound.tag.clone()),
        OutboundKind::Inline => {
            queue.push_back(p.outbound.tag.clone());
            if let Some(raw) = &p.outbound.raw {
                queue.extend(outbound_next_tags(raw));
            }
        }
        OutboundKind::Direct => {
            reachable.insert(synthesized_direct_tag(&p.name));
        }
    }
    while let Some(tag) = queue.pop_front() {
        if reachable.contains(&tag) {
            continue;
        }
        if !is_node(&tag) {
            continue;
        }
        reachable.insert(tag.clone());
        if let Some(ob) = outbounds.get(&tag) {
            queue.extend(outbound_next_tags(ob));
            continue;
        }
        if let Some(ep) = endpoints.get(&tag) {
            queue.extend(endpoint_next_tags(ep));
        }
    }
    reachable
}

/// `validateProfileDNS` (`dns.go:545`): every profile's
/// own dns block — each server's detour must be non-empty
/// (G2) and in the owning profile's reachable set, server
/// tags are unique within the block, and final (when set)
/// matches a server tag in the same block.
pub fn validate_profile_dns(cfg: &SingleConfig) -> Result<(), ConfigError> {
    for name in cfg.profile_names() {
        let Some(p) = cfg.profiles.get(&name) else {
            continue;
        };
        if !p.dns_present || p.dns.is_none() {
            continue;
        }
        let reachable = reachable_tags_for_profile(cfg, p);
        let Some(JsonValue::Object(obj)) = &p.dns else {
            continue;
        };
        let mut server_tags: BTreeSet<String> = BTreeSet::new();
        if let Some(JsonValue::Array(servers)) = obj.get("servers") {
            for srv in servers {
                let Some(tag) = obj_str(srv, "tag") else {
                    continue;
                };
                if server_tags.contains(tag) {
                    return Err(config_errorf!(
                        "profile {}: duplicate dns server tag {}",
                        go_quote(&name),
                        go_quote(tag)
                    ));
                }
                server_tags.insert(tag.to_string());
                let d = detour_of(srv);
                if d.is_empty() {
                    return Err(config_errorf!(
                        "profile {}: dns server {} has no detour: DNS must travel through the profile's outbound",
                        go_quote(&name),
                        go_quote(tag)
                    ));
                }
                if !reachable.contains(d) {
                    return Err(config_errorf!(
                        "profile {}: dns server {}: dangling reference: detour {} is not reachable from this profile's outbound",
                        go_quote(&name),
                        go_quote(tag),
                        go_quote(d)
                    ));
                }
            }
        }
        if let Some(JsonValue::Str(fin)) = obj.get("final")
            && !fin.is_empty()
            && !server_tags.contains(fin)
        {
            return Err(config_errorf!(
                "profile {}: dns final {} does not match any dns server tag in this profile's dns block",
                go_quote(&name),
                go_quote(fin)
            ));
        }
    }
    Ok(())
}

/// `validateWireGuardDNS` (`dns.go:584`): each
/// `wireguard_dns` key must name a WireGuard endpoint in
/// the same file, and each value must be a non-empty
/// server address (IP literal or hostname).
pub fn validate_wireguard_dns(cfg: &SingleConfig) -> Result<(), ConfigError> {
    if cfg.wireguard_dns.is_empty() {
        return Ok(());
    }
    let endpoints = endpoints_by_tag(cfg);
    for (tag, servers) in &cfg.wireguard_dns {
        let Some(ep) = endpoints.get(tag) else {
            return Err(config_errorf!(
                "wireguard_dns: endpoint tag {} does not exist",
                go_quote(tag)
            ));
        };
        if obj_str(ep, "type") != Some("wireguard") {
            return Err(config_errorf!(
                "wireguard_dns: endpoint {} is type {}, not wireguard",
                go_quote(tag),
                go_quote(obj_str(ep, "type").unwrap_or(""))
            ));
        }
        if servers.is_empty() {
            return Err(config_errorf!(
                "wireguard_dns: endpoint {} has no dns servers",
                go_quote(tag)
            ));
        }
        for srv in servers {
            if srv.trim().is_empty() {
                return Err(config_errorf!(
                    "wireguard_dns: endpoint {} has an empty dns server",
                    go_quote(tag)
                ));
            }
        }
    }
    Ok(())
}

/// The load-time tail chain for M7d read/write paths
/// (`ParseSingleConfig` tail, `config.go:420`): the Rust
/// parser already runs G1, telegram, keeper,
/// credentials, credential refs, and plugins validation
/// (`config.rs` tail); this runs the remaining four, in
/// Go order — tag graph, profile DNS, WireGuard DNS,
/// WireGuard private keys. It also resolves each
/// tag-referencing profile's `Outbound.From`/`Type`
/// (needed by `profile list`).
pub fn validate_single_config(cfg: &mut SingleConfig) -> Result<(), ConfigError> {
    crate::taggraph::validate_tag_graph(cfg)?;
    validate_profile_dns(cfg)?;
    validate_wireguard_dns(cfg)?;
    validate_wireguard_private_keys(cfg)?;
    Ok(())
}

// ---------------------------------------------------------------------
// DNS resolution
// ---------------------------------------------------------------------

/// Parse one dns block (raw JSON) into servers, the final
/// tag, and the rules (kept raw for the local-bootstrap
/// guard). Non-object servers are skipped (D-M2-1: Go's
/// `parseDNS` would fail the parse first). A missing
/// `server_port` defaults by type: 443 for `https`, 53
/// otherwise (sing-box defaults).
pub(crate) fn parse_dns_block(raw: &JsonValue) -> (Vec<DnsServer>, String, Vec<JsonValue>) {
    let mut servers = Vec::new();
    let mut final_tag = String::new();
    let mut rules = Vec::new();
    let JsonValue::Object(obj) = raw else {
        return (servers, final_tag, rules);
    };
    if let Some(JsonValue::Array(list)) = obj.get("servers") {
        for srv in list {
            let JsonValue::Object(o) = srv else { continue };
            let tag = obj_str(srv, "tag").unwrap_or("").to_string();
            let typ = obj_str(srv, "type").unwrap_or("").to_string();
            let server = obj_str(srv, "server").unwrap_or("").to_string();
            let port = match o.get("server_port") {
                Some(JsonValue::Number(lit)) => lit.parse::<u16>().unwrap_or(0),
                _ => 0,
            };
            let port = if port != 0 {
                port
            } else if typ == "https" {
                443
            } else {
                53
            };
            servers.push(DnsServer {
                tag,
                typ,
                server,
                server_port: port,
                path: obj_str(srv, "path").unwrap_or("").to_string(),
                detour: detour_of(srv).to_string(),
            });
        }
    }
    if let Some(JsonValue::Str(f)) = obj.get("final") {
        final_tag = f.clone();
    }
    if let Some(JsonValue::Array(list)) = obj.get("rules") {
        rules = list.clone();
    }
    (servers, final_tag, rules)
}

/// `ruleRoutesToServer` (`dns.go:392`): whether any DNS
/// rule routes lookups to the given server tag, recursing
/// through logical rules. In raw JSON a route/evaluate
/// action names its server with a flat `"server"` key, so
/// the walk checks every rule object's `"server"` field
/// and recurses into nested `"rules"` arrays — the same
/// references Go checks, conservatively (a `"server"` key
/// in a rule object always names a route target in any
/// config Go's parser accepts).
fn rule_routes_to_server(rules: &[JsonValue], tag: &str) -> bool {
    for r in rules {
        if let JsonValue::Object(obj) = r {
            if let Some(JsonValue::Str(s)) = obj.get("server")
                && s == tag
            {
                return true;
            }
            if let Some(JsonValue::Array(nested)) = obj.get("rules")
                && rule_routes_to_server(nested, tag)
            {
                return true;
            }
        }
    }
    false
}

/// `ensureLocalBootstrapServer` (`dns.go:255`): guarantee
/// the effective DNS options carry a `local` server usable
/// as the default domain_resolver target, reconciling a
/// user-defined server with that tag. A server tagged
/// `local` that is not type `local`, or carries any
/// detour, fails closed; a block with no servers, a
/// `final` naming `local`, or a rule routing to `local`
/// fails closed when no clean user-defined `local` server
/// exists. Otherwise the synthesised server
/// (`{"tag":"local","type":"local"}`) is appended last
/// (final untouched, no rules added).
fn ensure_local_bootstrap_server(
    profile_name: &str,
    servers: Vec<DnsServer>,
    final_tag: &str,
    rules: &[JsonValue],
) -> Result<Vec<DnsServer>, ConfigError> {
    for srv in &servers {
        if srv.tag != LOCAL_BOOTSTRAP_SERVER_TAG {
            continue;
        }
        if srv.typ != "local" {
            return Err(config_errorf!(
                "profile {}: dns server tag {} is type {}, not \"local\": the tag is reserved for the local bootstrap server; rename the server",
                go_quote(profile_name),
                go_quote(LOCAL_BOOTSTRAP_SERVER_TAG),
                go_quote(&srv.typ)
            ));
        }
        if !srv.detour.is_empty() {
            return Err(config_errorf!(
                "profile {}: dns server tag {} is a local server with detour {}: the bootstrap server must have no detour; rename the server or remove the detour",
                go_quote(profile_name),
                go_quote(LOCAL_BOOTSTRAP_SERVER_TAG),
                go_quote(&srv.detour)
            ));
        }
        return Ok(servers);
    }
    if servers.is_empty() {
        return Err(config_errorf!(
            "profile {}: dns block has no servers: refusing to synthesise the local bootstrap server as the only server",
            go_quote(profile_name)
        ));
    }
    if final_tag == LOCAL_BOOTSTRAP_SERVER_TAG {
        return Err(config_errorf!(
            "profile {}: dns final {} names the reserved local bootstrap server tag with no user-defined local server: define a clean local server to route targets there, or name another server",
            go_quote(profile_name),
            go_quote(LOCAL_BOOTSTRAP_SERVER_TAG)
        ));
    }
    if rule_routes_to_server(rules, LOCAL_BOOTSTRAP_SERVER_TAG) {
        return Err(config_errorf!(
            "profile {}: dns rule routes to the reserved local bootstrap server tag {} with no user-defined local server: define a clean local server to route targets there, or name another server",
            go_quote(profile_name),
            go_quote(LOCAL_BOOTSTRAP_SERVER_TAG)
        ));
    }
    let mut out = servers;
    out.push(DnsServer {
        tag: LOCAL_BOOTSTRAP_SERVER_TAG.to_string(),
        typ: "local".to_string(),
        server: String::new(),
        server_port: 0,
        path: String::new(),
        detour: String::new(),
    });
    Ok(out)
}

/// `defaultDetourForProfile` (`dns.go:408`): the detour
/// tag the synthesised default DoH uses, plus the
/// synthesised direct tag to create (`""` unless the
/// profile is direct).
pub(crate) fn default_detour_for_profile(p: &Profile) -> (String, String) {
    match p.outbound.kind {
        OutboundKind::Tag | OutboundKind::Inline => (p.outbound.tag.clone(), String::new()),
        OutboundKind::Direct => {
            let tag = synthesized_direct_tag(&p.name);
            (tag.clone(), tag)
        }
    }
}

/// `buildDefaultDNSOptions` (`dns.go:424`): the
/// synthesised DoH resolver — one https server,
/// IP-literal 1.1.1.1, path /dns-query, detour as given.
/// The key order matches the migrate-time interim
/// authoring (`tag` first).
fn build_default_dns_options(detour: &str) -> (Vec<DnsServer>, String) {
    (
        vec![DnsServer {
            tag: DEFAULT_DNS_SERVER_TAG.to_string(),
            typ: "https".to_string(),
            server: "1.1.1.1".to_string(),
            server_port: 443,
            path: "/dns-query".to_string(),
            detour: detour.to_string(),
        }],
        DEFAULT_DNS_SERVER_TAG.to_string(),
    )
}

/// `buildWireGuardDNSOptions` (`dns.go:440`): one udp
/// server per listed DNS address, all detouring through
/// the WireGuard endpoint tag. Port 53 is sing-box's
/// default for udp servers.
fn build_wireguard_dns_options(endpoint_tag: &str, servers: &[String]) -> (Vec<DnsServer>, String) {
    let mut out = Vec::new();
    for (i, srv) in servers.iter().enumerate() {
        out.push(DnsServer {
            tag: format!("{DEFAULT_DNS_SERVER_TAG}-{}", i + 1),
            typ: "udp".to_string(),
            server: srv.clone(),
            server_port: 53,
            path: String::new(),
            detour: endpoint_tag.to_string(),
        });
    }
    (out, format!("{DEFAULT_DNS_SERVER_TAG}-1"))
}

/// `wireGuardDNSForProfile` (`dns.go:458`): the WireGuard
/// endpoint tag and DNS servers for the profile's tunnel,
/// when the profile's outbound resolves (directly, or one
/// detour hop through an outbound) to a WireGuard endpoint
/// that carries DNS servers in `wireguard_dns`. BFS order,
/// cycle-guarded.
pub(crate) fn wireguard_dns_for_profile(
    prof: &Profile,
    single: &SingleConfig,
) -> Option<(String, Vec<String>)> {
    if single.wireguard_dns.is_empty() {
        return None;
    }
    let endpoints = endpoints_by_tag(single);
    let outbounds = outbounds_by_tag(single);
    let mut seeds: Vec<String> = Vec::new();
    match prof.outbound.kind {
        OutboundKind::Tag => seeds.push(prof.outbound.tag.clone()),
        OutboundKind::Inline => {
            if let Some(raw) = &prof.outbound.raw {
                seeds.extend(outbound_next_tags(raw));
            }
        }
        OutboundKind::Direct => {}
    }
    let mut visited: BTreeSet<String> = BTreeSet::new();
    let mut queue: VecDeque<String> = seeds.into_iter().collect();
    while let Some(tag) = queue.pop_front() {
        if !visited.insert(tag.clone()) {
            continue;
        }
        if let Some(ep) = endpoints.get(&tag) {
            if obj_str(ep, "type") == Some("wireguard")
                && let Some((_, servers)) = single.wireguard_dns.iter().find(|(t, _)| t == &tag)
                && !servers.is_empty()
            {
                return Some((tag.clone(), servers.clone()));
            }
            queue.extend(endpoint_next_tags(ep));
            continue;
        }
        if let Some(ob) = outbounds.get(&tag) {
            queue.extend(outbound_next_tags(ob));
        }
    }
    None
}

/// `ResolveProfileDNS` (`dns.go:172`): one profile's
/// effective resolver. Pure: reads only `prof` and
/// `single`, never the filesystem, never mutates either.
/// A `None` single (no single config file) yields
/// `DNSSourceNone`, preserving the historical fail-closed
/// path for config-less profiles.
pub fn resolve_profile_dns(
    prof: &Profile,
    single: Option<&SingleConfig>,
) -> Result<ResolvedDns, ConfigError> {
    let Some(single) = single else {
        return Ok(ResolvedDns {
            source: DnsSource::None,
            servers: Vec::new(),
            final_tag: String::new(),
            warning: String::new(),
            synthesized_direct_tag: String::new(),
            local_server_tag: String::new(),
        });
    };
    // (1) Own block.
    if prof.dns_present {
        if single.dns_raw.is_some() {
            return Err(config_errorf!(
                "profile {} has both a per-profile dns block and a top-level dns section: remove the top-level dns section (distribute it into profile entries by hand first, see docs/config.md)",
                go_quote(&prof.name)
            ));
        }
        let Some(raw) = &prof.dns else {
            return Err(config_errorf!(
                "profile {}: no dns options: cannot synthesise the local bootstrap server",
                go_quote(&prof.name)
            ));
        };
        let (servers, final_tag, rules) = parse_dns_block(raw);
        let servers = ensure_local_bootstrap_server(&prof.name, servers, &final_tag, &rules)?;
        let synth = servers
            .iter()
            .find(|s| s.detour == synthesized_direct_tag(&prof.name))
            .map(|s| s.detour.clone())
            .unwrap_or_default();
        return Ok(ResolvedDns {
            source: DnsSource::Profile,
            servers,
            final_tag,
            warning: String::new(),
            synthesized_direct_tag: synth,
            local_server_tag: LOCAL_BOOTSTRAP_SERVER_TAG.to_string(),
        });
    }
    // (2) WireGuard DNS through the profile's tunnel.
    if let Some((tag, servers)) = wireguard_dns_for_profile(prof, single) {
        let (servers, final_tag) = build_wireguard_dns_options(&tag, &servers);
        let servers = ensure_local_bootstrap_server(&prof.name, servers, &final_tag, &[])?;
        let warning = if single.dns_raw.is_some() {
            format!(
                "castctl: top-level dns section is ignored for profile {}: WireGuard DNS takes precedence; remove the top-level dns section by hand (see docs/config.md)",
                go_quote(&prof.name)
            )
        } else {
            String::new()
        };
        return Ok(ResolvedDns {
            source: DnsSource::WireGuard,
            servers,
            final_tag,
            warning,
            synthesized_direct_tag: String::new(),
            local_server_tag: LOCAL_BOOTSTRAP_SERVER_TAG.to_string(),
        });
    }
    // (3) Global-compat fallback, before the default.
    if let Some(raw) = &single.dns_raw {
        let (servers, final_tag, rules) = parse_dns_block(raw);
        let servers = ensure_local_bootstrap_server(&prof.name, servers, &final_tag, &rules)?;
        return Ok(ResolvedDns {
            source: DnsSource::GlobalCompat,
            servers,
            final_tag,
            warning: "castctl: top-level dns section is deprecated and will become an error in a later release: run \"config migrate --write\" to distribute it into profile entries (see docs/config.md)".to_string(),
            synthesized_direct_tag: String::new(),
            local_server_tag: LOCAL_BOOTSTRAP_SERVER_TAG.to_string(),
        });
    }
    // (4) Synthesised DoH default.
    let (detour, synth) = default_detour_for_profile(prof);
    let (servers, final_tag) = build_default_dns_options(&detour);
    let servers = ensure_local_bootstrap_server(&prof.name, servers, &final_tag, &[])?;
    Ok(ResolvedDns {
        source: DnsSource::Default,
        servers,
        final_tag,
        warning: String::new(),
        synthesized_direct_tag: synth,
        local_server_tag: LOCAL_BOOTSTRAP_SERVER_TAG.to_string(),
    })
}

/// `detourChain` (`internal/commands/runtime.go:662`):
/// the detour chain starting at `tag`, following `Detour`
/// fields through the single config's outbounds ONLY.
/// Cycles and missing tags terminate the chain; the chain
/// always starts with `tag` itself. Direct/empty tags
/// return `[tag]`.
pub fn detour_chain(single: Option<&SingleConfig>, tag: &str) -> Vec<String> {
    let mut chain = vec![tag.to_string()];
    let Some(single) = single else {
        return chain;
    };
    if tag.is_empty() || tag == "direct" {
        return chain;
    }
    let outbounds = outbounds_by_tag(single);
    let mut seen: BTreeSet<String> = BTreeSet::new();
    seen.insert(tag.to_string());
    let mut cur = tag.to_string();
    while let Some(ob) = outbounds.get(&cur) {
        let next = detour_of(ob);
        if next.is_empty() || seen.contains(next) {
            break;
        }
        seen.insert(next.to_string());
        chain.push(next.to_string());
        cur = next.to_string();
    }
    chain
}

fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    let sum = h.finalize();
    let mut s = String::with_capacity(64);
    for b in sum {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// `OutboundIdentityForConfig` (`internal/profile/identity.go`):
/// the S7 reconnect identity for the named profile — (tag,
/// sha256-hex of the canonical outbound JSON). For tag
/// references the tag resolves to the stored
/// outbound/endpoint object (raw JSON, compactly
/// re-encoded, key order and number literals preserved),
/// so editing the referenced object changes the identity
/// and forces a reconnect. Direct profiles hash the fixed
/// bytes `{"type":"direct","tag":"direct"}`.
///
/// The hash is over the RAW outbound JSON and may
/// therefore carry secret values (it changes when a secret
/// rotates): never hand it to a plugin, and never print
/// it. (`profile test` uses the tag only.)
pub fn outbound_identity_for_config(
    cfg: &SingleConfig,
    name: &str,
) -> Result<(String, String), ConfigError> {
    let Some(p) = cfg.profiles.get(name) else {
        return Err(config_errorf!(
            "profile {} does not exist in the single config file",
            go_quote(name)
        ));
    };
    match p.outbound.kind {
        OutboundKind::Direct => Ok((
            "direct".to_string(),
            sha256_hex(br#"{"type":"direct","tag":"direct"}"#),
        )),
        OutboundKind::Inline => {
            if p.outbound.tag.is_empty() {
                return Err(config_errorf!(
                    "profile {}: inline outbound has no tag",
                    go_quote(name)
                ));
            }
            let Some(raw) = &p.outbound.raw else {
                return Err(raw_io_error(
                    "inline outbound has neither raw json nor a parsed value",
                ));
            };
            let bytes = encode_ordered_json(raw)?;
            Ok((p.outbound.tag.clone(), sha256_hex(bytes.as_bytes())))
        }
        OutboundKind::Tag => {
            let tag = &p.outbound.tag;
            if tag.is_empty() {
                return Err(config_errorf!(
                    "profile {}: outbound tag reference is empty",
                    go_quote(name)
                ));
            }
            // Prefer the section the reference resolved
            // from, then search both: the tag namespace is
            // unique, so at most one matches.
            let mut sections: Vec<&Vec<JsonValue>> = vec![&cfg.outbounds_raw, &cfg.endpoints_raw];
            if p.outbound.from == "endpoint" {
                sections = vec![&cfg.endpoints_raw, &cfg.outbounds_raw];
            }
            for section in sections {
                for raw in section {
                    if obj_str(raw, "tag") == Some(tag.as_str()) {
                        let bytes = encode_ordered_json(raw)?;
                        return Ok((tag.clone(), sha256_hex(bytes.as_bytes())));
                    }
                }
            }
            Err(config_errorf!(
                "profile {}: outbound tag {} does not exist",
                go_quote(name),
                go_quote(tag)
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jsonvalue::decode_ordered_json;
    use crate::taggraph::validate_tag_graph;

    fn cfg_from(json: &str) -> SingleConfig {
        crate::config::parse_single_config(json.as_bytes(), "/tmp").unwrap()
    }

    fn prof(cfg: &SingleConfig, name: &str) -> Profile {
        cfg.profiles[name].clone()
    }

    #[test]
    fn default_dns_resolution_direct_and_tagged() {
        // Direct profile: detour is the synthesised tag.
        let cfg = cfg_from(r#"{"profiles":{"a":{}}}"#);
        let p = prof(&cfg, "a");
        let r = resolve_profile_dns(&p, Some(&cfg)).unwrap();
        assert_eq!(r.source, DnsSource::Default);
        assert_eq!(r.servers[0].tag, "castctl-doh");
        assert_eq!(r.servers[0].typ, "https");
        assert_eq!(r.servers[0].server, "1.1.1.1");
        assert_eq!(r.servers[0].server_port, 443);
        assert_eq!(r.servers[0].path, "/dns-query");
        assert_eq!(r.servers[0].detour, "castctl-direct:a");
        assert_eq!(r.synthesized_direct_tag, "castctl-direct:a");
        assert_eq!(r.final_tag, "castctl-doh");
        // Synthesised local bootstrap server appended last.
        assert_eq!(r.servers[1].tag, "local");
        assert_eq!(r.servers[1].typ, "local");
        assert_eq!(r.local_server_tag, "local");
        // Tagged profile: detour is the tag, no synth.
        let cfg = cfg_from(
            r#"{"profiles":{"a":{"outbound":"o1"}},"outbounds":[{"type":"socks","tag":"o1"}]}"#,
        );
        let p = prof(&cfg, "a");
        let r = resolve_profile_dns(&p, Some(&cfg)).unwrap();
        assert_eq!(r.servers[0].detour, "o1");
        assert_eq!(r.synthesized_direct_tag, "");
    }

    #[test]
    fn global_compat_branch_warns() {
        let cfg = cfg_from(
            r#"{"profiles":{"a":{}},"dns":{"servers":[{"tag":"s1","type":"https","server":"1.1.1.1","server_port":443,"detour":"x"}],"final":"s1"}}"#,
        );
        let p = prof(&cfg, "a");
        let r = resolve_profile_dns(&p, Some(&cfg)).unwrap();
        assert_eq!(r.source, DnsSource::GlobalCompat);
        assert!(r.warning.contains("deprecated"), "warning: {}", r.warning);
        assert_eq!(r.display_server_tag(), Some("s1"));
    }

    #[test]
    fn wireguard_dns_branch() {
        let cfg = cfg_from(
            r#"{"profiles":{"a":{"outbound":"wg1"}},"endpoints":[{"type":"wireguard","tag":"wg1"}],"wireguard_dns":{"wg1":["10.0.0.53"]}}"#,
        );
        let p = prof(&cfg, "a");
        let r = resolve_profile_dns(&p, Some(&cfg)).unwrap();
        assert_eq!(r.source, DnsSource::WireGuard);
        assert_eq!(r.servers[0].tag, "castctl-doh-1");
        assert_eq!(r.servers[0].typ, "udp");
        assert_eq!(r.servers[0].server, "10.0.0.53");
        assert_eq!(r.servers[0].server_port, 53);
        assert_eq!(r.servers[0].detour, "wg1");
        assert_eq!(r.final_tag, "castctl-doh-1");
        // Shadowing warning when a top-level section exists.
        let cfg = cfg_from(
            r#"{"profiles":{"a":{"outbound":"wg1"}},"endpoints":[{"type":"wireguard","tag":"wg1"}],"wireguard_dns":{"wg1":["10.0.0.53"]},"dns":{"servers":[{"tag":"s1","type":"https","server":"1.1.1.1","server_port":443}],"final":"s1"}}"#,
        );
        let p = prof(&cfg, "a");
        let r = resolve_profile_dns(&p, Some(&cfg)).unwrap();
        assert!(
            r.warning.contains("WireGuard DNS takes precedence"),
            "warning: {}",
            r.warning
        );
    }

    #[test]
    fn local_bootstrap_guards() {
        // Empty servers: refuse.
        let cfg = cfg_from(r#"{"profiles":{"a":{"dns":{"servers":[],"final":""}}}}"#);
        let p = prof(&cfg, "a");
        let e = resolve_profile_dns(&p, Some(&cfg)).unwrap_err();
        assert!(
            e.message.contains("has no servers"),
            "message: {}",
            e.message
        );
        // Final naming local with no user-defined local: refuse.
        let cfg = cfg_from(
            r#"{"profiles":{"a":{"dns":{"servers":[{"tag":"s1","type":"https","server":"1.1.1.1","server_port":443}],"final":"local"}}}}"#,
        );
        let p = prof(&cfg, "a");
        let e = resolve_profile_dns(&p, Some(&cfg)).unwrap_err();
        assert!(
            e.message
                .contains("names the reserved local bootstrap server"),
            "message: {}",
            e.message
        );
        // Non-local type tagged local: refuse.
        let cfg = cfg_from(
            r#"{"profiles":{"a":{"dns":{"servers":[{"tag":"local","type":"https","server":"1.1.1.1","server_port":443}],"final":"local"}}}}"#,
        );
        let p = prof(&cfg, "a");
        let e = resolve_profile_dns(&p, Some(&cfg)).unwrap_err();
        assert!(
            e.message.contains("is type \"https\", not \"local\""),
            "message: {}",
            e.message
        );
        // Clean user-defined local: reused, no synthesis.
        let cfg = cfg_from(
            r#"{"profiles":{"a":{"dns":{"servers":[{"tag":"local","type":"local"},{"tag":"s1","type":"https","server":"1.1.1.1","server_port":443}],"final":"s1"}}}}"#,
        );
        let p = prof(&cfg, "a");
        let r = resolve_profile_dns(&p, Some(&cfg)).unwrap();
        assert_eq!(r.servers.len(), 2);
        assert_eq!(r.servers[0].tag, "local");
    }

    #[test]
    fn validate_profile_dns_rules() {
        // Detour missing.
        let cfg = cfg_from(
            r#"{"profiles":{"a":{"dns":{"servers":[{"tag":"s1","type":"https","server":"1.1.1.1","server_port":443}],"final":"s1"}}}}"#,
        );
        let e = validate_profile_dns(&cfg).unwrap_err();
        assert!(
            e.message.contains("has no detour"),
            "message: {}",
            e.message
        );
        // Detour unreachable (another profile's inline tag).
        let mut cfg = cfg_from(
            r#"{"profiles":{"a":{"dns":{"servers":[{"tag":"s1","type":"https","server":"1.1.1.1","server_port":443,"detour":"profile:b"}],"final":"s1"}},"b":{"outbound":{"type":"socks","tag":"profile:b","server":"127.0.0.1","server_port":1080}}}}"#,
        );
        // Tag graph passes (inline tag exists); profile DNS
        // must refuse the foreign inline detour.
        validate_tag_graph(&mut cfg).unwrap();
        let e = validate_profile_dns(&cfg).unwrap_err();
        assert!(
            e.message.contains("is not reachable"),
            "message: {}",
            e.message
        );
        let _ = decode_ordered_json(b"{}");
    }

    #[test]
    fn validate_wireguard_dns_rules() {
        let cfg = cfg_from(
            r#"{"profiles":{"a":{"outbound":"wg1"}},"endpoints":[{"type":"wireguard","tag":"wg1"}],"wireguard_dns":{"ghost":["10.0.0.53"]}}"#,
        );
        let e = validate_wireguard_dns(&cfg).unwrap_err();
        assert_eq!(
            e.message,
            "profile: wireguard_dns: endpoint tag \"ghost\" does not exist"
        );
        let cfg = cfg_from(
            r#"{"profiles":{"a":{"outbound":"wg1"}},"endpoints":[{"type":"socks","tag":"wg1"}],"wireguard_dns":{"wg1":["10.0.0.53"]}}"#,
        );
        let e = validate_wireguard_dns(&cfg).unwrap_err();
        assert!(
            e.message.contains("not wireguard"),
            "message: {}",
            e.message
        );
    }

    #[test]
    fn wireguard_private_key_sharing() {
        // Same key, two profiles, different tags: error
        // naming both profiles and both tags, never the key.
        let cfg = cfg_from(
            r#"{"profiles":{"a":{"outbound":"wg1"},"b":{"outbound":"wg2"}},"endpoints":[{"type":"wireguard","tag":"wg1","private_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},{"type":"wireguard","tag":"wg2","private_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}]}"#,
        );
        let e = validate_wireguard_private_keys(&cfg).unwrap_err();
        assert_eq!(
            e.message,
            "profile: wireguard private key shared by profiles \"a\" and \"b\" (endpoints \"wg1\" and \"wg2\"); each profile must use a distinct wireguard private key"
        );
        assert!(!e.message.contains("AAAA"), "message: {}", e.message);
        // Padding-bit variants decode to the same bytes.
        let cfg = cfg_from(
            r#"{"profiles":{"a":{"outbound":"wg1"},"b":{"outbound":"wg2"}},"endpoints":[{"type":"wireguard","tag":"wg1","private_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},{"type":"wireguard","tag":"wg2","private_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB="}]}"#,
        );
        // Both decode to 32 zero bytes? "A...A=" vs "A...B=":
        // the last char differs in the padding bits; the
        // decoded bytes are both 32 zero bytes.
        let e = validate_wireguard_private_keys(&cfg).unwrap_err();
        assert!(
            e.message.contains("shared by profiles"),
            "message: {}",
            e.message
        );
        // Same tag shared by two profiles: STILL an error.
        // Go compares by key value, never by tag
        // (`wireguard.go`: "different tags, same key =
        // error"; the "same tag = one config" line covers a
        // profile's own outbound vs its own dns detour,
        // not two profiles). Verified live on cue: Go
        // `profile list` on this config exits 2 with the
        // same message.
        let cfg = cfg_from(
            r#"{"profiles":{"a":{"outbound":"wg1"},"b":{"outbound":"wg1"}},"endpoints":[{"type":"wireguard","tag":"wg1","private_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}]}"#,
        );
        let e = validate_wireguard_private_keys(&cfg).unwrap_err();
        assert_eq!(
            e.message,
            "profile: wireguard private key shared by profiles \"a\" and \"b\" (endpoints \"wg1\" and \"wg1\"); each profile must use a distinct wireguard private key"
        );
        // Empty key skipped.
        let cfg = cfg_from(
            r#"{"profiles":{"a":{"outbound":"wg1"},"b":{"outbound":"wg2"}},"endpoints":[{"type":"wireguard","tag":"wg1"},{"type":"wireguard","tag":"wg2"}]}"#,
        );
        validate_wireguard_private_keys(&cfg).unwrap();
    }

    #[test]
    fn detour_chain_follows_outbounds_only() {
        let cfg = cfg_from(
            r#"{"profiles":{"a":{"outbound":"o1"}},"outbounds":[{"type":"socks","tag":"o1","detour":"o2"},{"type":"socks","tag":"o2","detour":"o1"},{"type":"direct","tag":"o3"}]}"#,
        );
        // o1 -> o2 -> o1 cycle stops.
        assert_eq!(detour_chain(Some(&cfg), "o1"), vec!["o1", "o2"]);
        // Endpoint tag: not in outbounds, chain is [tag].
        assert_eq!(detour_chain(Some(&cfg), "wg1"), vec!["wg1"]);
        assert_eq!(detour_chain(Some(&cfg), "direct"), vec!["direct"]);
        assert_eq!(detour_chain(None, "o1"), vec!["o1"]);
    }

    #[test]
    fn outbound_identity_shapes() {
        let cfg = cfg_from(r#"{"profiles":{"a":{}}}"#);
        let (tag, hash) = outbound_identity_for_config(&cfg, "a").unwrap();
        assert_eq!(tag, "direct");
        assert_eq!(hash.len(), 64);
        // Direct hash is the fixed bytes.
        let mut h = Sha256::new();
        h.update(br#"{"type":"direct","tag":"direct"}"#);
        let sum = h.finalize();
        let mut expect = String::new();
        for b in sum {
            expect.push_str(&format!("{b:02x}"));
        }
        assert_eq!(hash, expect);
        // Tag reference hashes the stored object.
        let cfg = cfg_from(
            r#"{"profiles":{"a":{"outbound":"o1"}},"outbounds":[{"type":"socks","tag":"o1","server":"127.0.0.1","server_port":1080}]}"#,
        );
        let (tag, hash) = outbound_identity_for_config(&cfg, "a").unwrap();
        assert_eq!(tag, "o1");
        assert_eq!(hash.len(), 64);
        // Unknown profile errors.
        let e = outbound_identity_for_config(&cfg, "ghost").unwrap_err();
        assert_eq!(
            e.message,
            "profile: profile \"ghost\" does not exist in the single config file"
        );
    }
}
