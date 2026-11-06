// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Deferred sing-box blocks, stored raw with only the fixed
//! first-line shape checks (D-M2-1).
//!
//! Blocks in this module (`outbounds`, `endpoints`, `dns`,
//! `wireguard_dns`, `keeper`, `webui`, `plugins`, `credentials`) are
//! preserved verbatim for rendering. Deep sing-box validation
//! (`validateTagGraph`, G1 coexistence, `validateProfileDNS`,
//! `validateWireGuardDNS`, `validateWireGuardPrivateKeys`,
//! `validateKeeper`, `validateCredentialRefs`) is DEFERRED: a config
//! that is invalid only under those checks parses successfully here
//! but fails in Go. The deferred Go tests are listed in PORTING.md.
//!
//! The checks implemented here are exactly the fixed-message
//! first-line shape checks of the Go parse functions, plus the
//! tag/profile checks of `parsePluginsBlock` /
//! `parseCredentialsBlock` / `validatePlugins` /
//! `validateCredentials`, which need only string fields.
//!
//! Sources at base `dev-rust` `85a8d5e`: `internal/profile/config.go`
//! (block dispatch), `dns.go` (`parseWireGuardDNSMap`),
//! `keeper.go` (`parseKeeperBlock` shape), `webui.go`
//! (`parseWebUIBlock` shape), `plugins.go`, `credentials.go`,
//! `keeper.go:381` (`ValidateKeeperTag`).

use crate::errors::{ConfigError, config_error};
use crate::gostr::{go_quote, go_trim_space};
use crate::jsonvalue::JsonValue;
use crate::profile::validate_profile_name;

/// `ValidateKeeperTag` (`internal/profile/keeper.go:381`): non-empty,
/// no surrounding whitespace, not `.`/`..`, no `/`, `\`, or control
/// characters. Returns the plain error text; callers wrap it.
pub fn validate_keeper_tag(tag: &str) -> Result<(), String> {
    if tag.is_empty() {
        return Err("keeper tag must not be empty".to_string());
    }
    if tag != go_trim_space(tag) {
        return Err(format!(
            "keeper tag {} has surrounding whitespace",
            go_quote(tag)
        ));
    }
    if tag == "." || tag == ".." {
        return Err(format!("keeper tag {} is a path component", go_quote(tag)));
    }
    for ch in tag.chars() {
        if ch == '/' || ch == '\\' || ch.is_control() {
            return Err(format!(
                "keeper tag {} contains a forbidden character",
                go_quote(tag)
            ));
        }
    }
    Ok(())
}

/// `boundEcho` (`internal/profile/plugins.go:120`): truncate names
/// longer than 64 runes to 64 runes + `…` for error messages.
fn bound_echo(s: &str) -> String {
    if s.chars().count() > 64 {
        let mut out: String = s.chars().take(64).collect();
        out.push('…');
        out
    } else {
        s.to_string()
    }
}

/// The plugin tag/type rule (`internal/profile/plugins.go:61`):
/// `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$` (1-128 chars, ASCII only).
/// Implemented by hand: the pattern uses only a character class and
/// a bounded repetition, which the `regex` crate would also express,
/// but no new dependency is needed for one class check.
pub fn valid_plugin_id(s: &str) -> bool {
    let mut chars = s.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !first.is_ascii_alphanumeric() {
        return false;
    }
    let mut len = 1;
    for ch in chars {
        if !(ch.is_ascii_alphanumeric() || ch == '.' || ch == '_' || ch == '-') {
            return false;
        }
        len += 1;
        if len > 128 {
            return false;
        }
    }
    true
}

/// `validatePluginTag` (`plugins.go:128`).
pub fn validate_plugin_tag(tag: &str) -> Result<(), ConfigError> {
    if !valid_plugin_id(tag) {
        return Err(crate::config_errorf!(
            "invalid plugin tag {}",
            go_quote(&bound_echo(tag))
        ));
    }
    Ok(())
}

/// `validatePluginType` (`plugins.go:138`): the same rule.
pub fn validate_plugin_type(typ: &str) -> Result<(), ConfigError> {
    if !valid_plugin_id(typ) {
        return Err(crate::config_errorf!(
            "invalid plugin type {}",
            go_quote(&bound_echo(typ))
        ));
    }
    Ok(())
}

/// One parsed `plugins` entry: tag and type only. Other keys are
/// never inspected; they survive verbatim in the raw block value.
///
/// Source: `internal/profile/plugins.go` (`PluginEntry`, tag/type
/// fields only; `fragment`/`raw` are the stored raw JSON).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginEntry {
    /// Entry tag.
    pub tag: String,
    /// Entry type.
    pub typ: String,
}

/// One parsed `credentials` entry: tag and profile only. Username
/// and password values are validated for presence/shape and then
/// dropped: they are secrets and no M2 code needs them (rendering
/// uses the raw block value).
///
/// Source: `internal/profile/credentials.go` (`CredentialEntry`,
/// tag/profile fields only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialEntry {
    /// Entry tag.
    pub tag: String,
    /// Linked profile name.
    pub profile: String,
}

/// Parsed `plugins` block (presence only; entries in file order).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PluginsBlock {
    /// Entries in file order.
    pub entries: Vec<PluginEntry>,
}

/// Parsed `credentials` block (presence only; entries in file order).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CredentialsBlock {
    /// Entries in file order.
    pub entries: Vec<CredentialEntry>,
}

/// One stored login credential (username + password) for a
/// profile. This is the ONLY value-read shape for credentials:
/// presence checks use `CredentialsBlock` (tag/profile only)
/// and never materialise a value.
///
/// Source: `internal/profile/credentials.go:239`
/// (`CredentialForProfile` returns `LoginCredential`).
#[derive(Clone, PartialEq, Eq)]
pub struct LoginCredential {
    /// Login username.
    pub username: String,
    /// Login password.
    pub password: String,
}

impl LoginCredential {
    /// Clear the credential in place (Go
    /// `LoginCredential.Clear`, `credentials.go:225-228`):
    /// assign the empty string to both fields. Go does
    /// NOT zero the backing bytes — and neither does
    /// this: `String::clear` keeps the capacity, so the
    /// old bytes stay in the allocation until it is
    /// dropped. No `unsafe` is used.
    pub fn clear(&mut self) {
        self.username.clear();
        self.password.clear();
    }
}

impl std::fmt::Debug for LoginCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Values are secrets: Debug never prints them.
        f.debug_struct("LoginCredential")
            .field("username", &"[redacted]")
            .field("password", &"[redacted]")
            .finish()
    }
}

/// Read the stored login credential for a profile from the
/// retained raw `credentials` value: the first entry whose
/// `profile` matches wins, exactly like Go's
/// `CredentialForProfile` loop (`credentials.go:239`). The
/// parsed block holds tag/profile only, so the raw value is
/// the only value source. Entries are validated at parse time
/// (username/password are non-empty strings); a matching entry
/// whose values are not strings yields `None` defensively
/// rather than panicking.
pub fn credential_from_raw(raw: &JsonValue, profile: &str) -> Option<LoginCredential> {
    let arr = match raw {
        JsonValue::Array(arr) => arr,
        _ => return None,
    };
    for elem in arr {
        let JsonValue::Object(obj) = elem else {
            continue;
        };
        let Some(JsonValue::Str(p)) = obj.get("profile") else {
            continue;
        };
        if p != profile {
            continue;
        }
        let (Some(JsonValue::Str(username)), Some(JsonValue::Str(password))) =
            (obj.get("username"), obj.get("password"))
        else {
            return None;
        };
        return Some(LoginCredential {
            username: username.clone(),
            password: password.clone(),
        });
    }
    None
}

/// `parseWireGuardDNSMap` (`internal/profile/dns.go`): shape only —
/// an object mapping endpoint tag to an array of server-address
/// strings. Tag existence and endpoint type are deferred
/// (`validateWireGuardDNS`). Key order is preserved in the returned
/// vector (Go uses a map; render order for the non-raw path is a
/// documented deviation, P-7).
pub fn parse_wireguard_dns_map(
    value: &JsonValue,
) -> Result<Vec<(String, Vec<String>)>, ConfigError> {
    let obj = match value {
        JsonValue::Object(obj) => obj,
        _ => return Err(config_error("\"wireguard_dns\" must be an object")),
    };
    let mut out = Vec::with_capacity(obj.len());
    for (tag, val) in obj.iter() {
        let arr = match val {
            JsonValue::Array(arr) => arr,
            _ => {
                return Err(crate::config_errorf!(
                    "wireguard_dns: endpoint {} must map to an array of server addresses",
                    go_quote(tag)
                ));
            }
        };
        let mut servers = Vec::with_capacity(arr.len());
        for elem in arr {
            match elem {
                JsonValue::Str(s) => servers.push(s.clone()),
                _ => {
                    return Err(crate::config_errorf!(
                        "wireguard_dns: endpoint {} has a non-string dns server",
                        go_quote(tag)
                    ));
                }
            }
        }
        out.push((tag.clone(), servers));
    }
    Ok(out)
}

/// Shape check for the `webui` block: object only. Deeper validation
/// (listen rule, token whitespace, `ui_dir` overlap) is deferred.
///
/// Source: `internal/profile/webui.go` (`parseWebUIBlock` head).
pub fn check_webui_shape(value: &JsonValue) -> Result<(), ConfigError> {
    match value {
        JsonValue::Object(_) => Ok(()),
        _ => Err(config_error("\"webui\" must be an object")),
    }
}

/// `parsePluginsBlock` (`internal/profile/plugins.go:150`), tag/type
/// presence and shape only: other keys are never inspected.
pub fn parse_plugins_block(value: &JsonValue) -> Result<PluginsBlock, ConfigError> {
    let arr = match value {
        JsonValue::Array(arr) => arr,
        _ => return Err(config_error("\"plugins\" must be an array of entries")),
    };
    let mut block = PluginsBlock::default();
    let mut seen_tags: Vec<String> = Vec::new();
    for (i, elem) in arr.iter().enumerate() {
        let obj = match elem {
            JsonValue::Object(obj) => obj,
            _ => {
                return Err(crate::config_errorf!(
                    "\"plugins\" entry {} must be an object",
                    i
                ));
            }
        };
        let mut entry = PluginEntry {
            tag: String::new(),
            typ: String::new(),
        };
        for (k, val) in obj.iter() {
            match k.as_str() {
                "tag" => match val {
                    JsonValue::Str(s) if !go_trim_space(s).is_empty() => {
                        // Go embeds the inner ConfigError's message
                        // WITH its "profile: " prefix via %v, so the
                        // outer message carries the prefix twice.
                        validate_plugin_tag(s).map_err(|e| {
                            crate::config_errorf!(
                                "\"plugins\" entry {}: invalid \"tag\": {}",
                                i,
                                e.message
                            )
                        })?;
                        entry.tag = s.clone();
                    }
                    _ => {
                        return Err(crate::config_errorf!(
                            "\"plugins\" entry {}: \"tag\" must be a non-empty string",
                            i
                        ));
                    }
                },
                "type" => match val {
                    JsonValue::Str(s) if !go_trim_space(s).is_empty() && *s == go_trim_space(s) => {
                        // Go embeds the inner ConfigError's message
                        // WITH its "profile: " prefix via %v (double prefix).
                        validate_plugin_type(s).map_err(|e| {
                            crate::config_errorf!(
                                "\"plugins\" entry {}: invalid \"type\": {}",
                                i,
                                e.message
                            )
                        })?;
                        entry.typ = s.clone();
                    }
                    _ => {
                        return Err(crate::config_errorf!(
                            "\"plugins\" entry {}: \"type\" must be a non-empty string",
                            i
                        ));
                    }
                },
                _ => {}
            }
        }
        if entry.tag.is_empty() {
            return Err(crate::config_errorf!(
                "\"plugins\" entry {}: \"tag\" must be a non-empty string",
                i
            ));
        }
        if entry.typ.is_empty() {
            return Err(crate::config_errorf!(
                "\"plugins\" entry {}: \"type\" must be a non-empty string",
                i
            ));
        }
        if seen_tags.contains(&entry.tag) {
            return Err(crate::config_errorf!(
                "duplicate plugin tag {}",
                go_quote(&entry.tag)
            ));
        }
        seen_tags.push(entry.tag.clone());
        block.entries.push(entry);
    }
    Ok(block)
}

/// `parseCredentialsBlock` (`internal/profile/credentials.go`),
/// shape + required keys only. Username/password values are checked
/// for non-empty-string shape and dropped.
pub fn parse_credentials_block(value: &JsonValue) -> Result<CredentialsBlock, ConfigError> {
    let arr = match value {
        JsonValue::Array(arr) => arr,
        _ => {
            return Err(config_error("\"credentials\" must be an array of entries"));
        }
    };
    let mut block = CredentialsBlock::default();
    let mut seen_tags: Vec<String> = Vec::new();
    for (i, elem) in arr.iter().enumerate() {
        let obj = match elem {
            JsonValue::Object(obj) => obj,
            _ => {
                return Err(crate::config_errorf!(
                    "\"credentials\" entry {} must be an object",
                    i
                ));
            }
        };
        let mut entry = CredentialEntry {
            tag: String::new(),
            profile: String::new(),
        };
        let mut username_set = false;
        let mut password_set = false;
        for (k, val) in obj.iter() {
            match k.as_str() {
                "tag" => match val {
                    JsonValue::Str(s) => {
                        validate_keeper_tag(s).map_err(|msg| {
                            crate::config_errorf!(
                                "\"credentials\" entry {}: invalid \"tag\": {}",
                                i,
                                msg
                            )
                        })?;
                        entry.tag = s.clone();
                    }
                    _ => {
                        return Err(crate::config_errorf!(
                            "\"credentials\" entry {}: \"tag\" must be a non-empty string",
                            i
                        ));
                    }
                },
                "profile" => match val {
                    JsonValue::Str(s) if !go_trim_space(s).is_empty() => {
                        if validate_profile_name(s).is_err() {
                            return Err(crate::config_errorf!(
                                "\"credentials\" entry {}: invalid profile name {}",
                                i,
                                go_quote(s)
                            ));
                        }
                        entry.profile = s.clone();
                    }
                    _ => {
                        return Err(crate::config_errorf!(
                            "\"credentials\" entry {}: \"profile\" must be a non-empty string",
                            i
                        ));
                    }
                },
                "username" => match val {
                    JsonValue::Str(s) if !go_trim_space(s).is_empty() => {
                        username_set = true;
                    }
                    _ => {
                        return Err(crate::config_errorf!(
                            "\"credentials\" entry {}: \"username\" must be a non-empty string",
                            i
                        ));
                    }
                },
                "password" => match val {
                    JsonValue::Str(s) if !go_trim_space(s).is_empty() => {
                        password_set = true;
                    }
                    _ => {
                        return Err(crate::config_errorf!(
                            "\"credentials\" entry {}: \"password\" must be a non-empty string",
                            i
                        ));
                    }
                },
                _ => {
                    return Err(crate::config_errorf!(
                        "unknown credentials config key {}",
                        go_quote(k)
                    ));
                }
            }
        }
        if entry.tag.is_empty() {
            return Err(crate::config_errorf!(
                "\"credentials\" entry {} requires a \"tag\" key",
                i
            ));
        }
        if entry.profile.is_empty() {
            return Err(crate::config_errorf!(
                "\"credentials\" entry {} requires a \"profile\" key",
                i
            ));
        }
        if !username_set {
            return Err(crate::config_errorf!(
                "\"credentials\" entry {} requires a \"username\" key",
                i
            ));
        }
        if !password_set {
            return Err(crate::config_errorf!(
                "\"credentials\" entry {} requires a \"password\" key",
                i
            ));
        }
        if seen_tags.contains(&entry.tag) {
            return Err(crate::config_errorf!(
                "\"credentials\" has duplicate tag {}",
                go_quote(&entry.tag)
            ));
        }
        seen_tags.push(entry.tag.clone());
        block.entries.push(entry);
    }
    Ok(block)
}

/// `validatePlugins` (`plugins.go:225`): re-check tag/type and
/// uniqueness on the parsed block.
pub fn validate_plugins(block: &PluginsBlock) -> Result<(), ConfigError> {
    let mut seen: Vec<&str> = Vec::new();
    for entry in &block.entries {
        if entry.tag.is_empty() || entry.typ.is_empty() {
            return Err(config_error(
                "plugin entry must have a non-empty tag and type",
            ));
        }
        validate_plugin_tag(&entry.tag)?;
        validate_plugin_type(&entry.typ)?;
        if seen.contains(&entry.tag.as_str()) {
            return Err(crate::config_errorf!(
                "duplicate plugin tag {}",
                go_quote(&entry.tag)
            ));
        }
        seen.push(&entry.tag);
    }
    Ok(())
}

/// `validateCredentials` (`credentials.go:173`): every entry's
/// profile must exist, and no two entries may name the same profile.
pub fn validate_credentials(
    block: &CredentialsBlock,
    profile_exists: impl Fn(&str) -> bool,
) -> Result<(), ConfigError> {
    let mut seen: Vec<(&str, &str)> = Vec::new();
    for entry in &block.entries {
        if !profile_exists(&entry.profile) {
            return Err(crate::config_errorf!(
                "credentials: entry {} names profile {}, which does not exist",
                go_quote(&entry.tag),
                go_quote(&entry.profile)
            ));
        }
        if let Some((prev, _)) = seen.iter().find(|(_, p)| *p == entry.profile) {
            return Err(crate::config_errorf!(
                "credentials: entries {} and {} both name profile {}",
                go_quote(prev),
                go_quote(&entry.tag),
                go_quote(&entry.profile)
            ));
        }
        seen.push((&entry.tag, &entry.profile));
    }
    Ok(())
}

/// Raw-field approximation of the Go endpoint check in
/// `ParseSingleConfig` (`config.go`): a wireguard endpoint object
/// with boolean `system: true` is rejected with the fixed message.
/// Any other shape (missing `type`, non-boolean `system`, unparseable
/// options) is deferred to sing-box parsing and accepted here.
pub fn check_endpoint_wireguard_system(value: &JsonValue) -> Result<(), ConfigError> {
    if let JsonValue::Object(obj) = value {
        let is_wireguard = matches!(obj.get("type"), Some(JsonValue::Str(s)) if s == "wireguard");
        let system_true = matches!(obj.get("system"), Some(JsonValue::Bool(true)));
        if is_wireguard && system_true {
            return Err(config_error(
                "wireguard endpoint \"system\": true is not supported; use userspace wireguard only",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jsonvalue::decode_ordered_json;

    fn value(input: &str) -> JsonValue {
        decode_ordered_json(input.as_bytes()).unwrap()
    }

    #[test]
    fn test_validate_keeper_tag() {
        assert!(validate_keeper_tag("k1").is_ok());
        assert_eq!(
            validate_keeper_tag("").unwrap_err(),
            "keeper tag must not be empty"
        );
        assert!(validate_keeper_tag(" a").is_err());
        assert!(validate_keeper_tag(".").is_err());
        assert!(validate_keeper_tag("a/b").is_err());
        assert!(validate_keeper_tag("a\\b").is_err());
        assert!(validate_keeper_tag("a\tb").is_err());
        assert!(validate_keeper_tag("a b").is_ok());
    }

    #[test]
    fn test_valid_plugin_id() {
        assert!(valid_plugin_id("a"));
        assert!(valid_plugin_id("a-b_c.d9"));
        assert!(!valid_plugin_id(""));
        assert!(!valid_plugin_id(".a"));
        assert!(!valid_plugin_id("-a"));
        assert!(!valid_plugin_id("a/b"));
        assert!(!valid_plugin_id("a b"));
        assert!(!valid_plugin_id(&"a".repeat(129)));
        assert!(valid_plugin_id(&"a".repeat(128)));
        assert!(!valid_plugin_id("é"));
    }

    #[test]
    fn test_wireguard_dns_map_shape() {
        let v = parse_wireguard_dns_map(&value("{\"ep1\":[\"1.1.1.1\",\"8.8.8.8\"]}")).unwrap();
        assert_eq!(
            v,
            vec![(
                "ep1".to_string(),
                vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()]
            )]
        );
        assert_eq!(
            parse_wireguard_dns_map(&value("[]")).unwrap_err().message,
            "profile: \"wireguard_dns\" must be an object"
        );
        assert_eq!(
            parse_wireguard_dns_map(&value("{\"ep1\":\"x\"}"))
                .unwrap_err()
                .message,
            "profile: wireguard_dns: endpoint \"ep1\" must map to an array of server addresses"
        );
        assert_eq!(
            parse_wireguard_dns_map(&value("{\"ep1\":[1]}"))
                .unwrap_err()
                .message,
            "profile: wireguard_dns: endpoint \"ep1\" has a non-string dns server"
        );
    }

    #[test]
    fn test_plugins_block_checks() {
        assert!(
            parse_plugins_block(&value("[{\"tag\":\"p1\",\"type\":\"t1\",\"extra\":1}]")).is_ok()
        );
        assert_eq!(
            parse_plugins_block(&value("[{\"tag\":\"p1\"}]"))
                .unwrap_err()
                .message,
            "profile: \"plugins\" entry 0: \"type\" must be a non-empty string"
        );
        assert_eq!(
            parse_plugins_block(&value(
                "[{\"tag\":\"p1\",\"type\":\"t\"},{\"tag\":\"p1\",\"type\":\"t\"}]"
            ))
            .unwrap_err()
            .message,
            "profile: duplicate plugin tag \"p1\""
        );
        assert_eq!(
            parse_plugins_block(&value("[{\"tag\":\"../x\",\"type\":\"t\"}]"))
                .unwrap_err()
                .message,
            "profile: \"plugins\" entry 0: invalid \"tag\": profile: invalid plugin tag \"../x\""
        );
    }

    #[test]
    fn test_credentials_block_checks() {
        let ok = "{\"tag\":\"c1\",\"profile\":\"default\",\"username\":\"u\",\"password\":\"p\"}";
        assert!(parse_credentials_block(&value(&format!("[{ok}]"))).is_ok());
        assert_eq!(
            parse_credentials_block(&value("[{\"tag\":\"c1\"}]"))
                .unwrap_err()
                .message,
            "profile: \"credentials\" entry 0 requires a \"profile\" key"
        );
        assert_eq!(
            parse_credentials_block(&value(&format!("[{ok},{ok}]")))
                .unwrap_err()
                .message,
            "profile: \"credentials\" has duplicate tag \"c1\""
        );
        assert_eq!(
            parse_credentials_block(&value(
                "[{\"tag\":\"c1\",\"profile\":\"default\",\"username\":\"u\",\"password\":\"p\",\"x\":1}]"
            ))
            .unwrap_err()
            .message,
            "profile: unknown credentials config key \"x\""
        );
    }

    #[test]
    fn test_validate_credentials_cross_refs() {
        let block = parse_credentials_block(&value(
            "[{\"tag\":\"c1\",\"profile\":\"default\",\"username\":\"u\",\"password\":\"p\"}]",
        ))
        .unwrap();
        assert!(validate_credentials(&block, |_| true).is_ok());
        assert!(validate_credentials(&block, |_| false).is_err());
    }

    #[test]
    fn test_endpoint_wireguard_system_raw_check() {
        assert!(
            check_endpoint_wireguard_system(&value(
                "{\"type\":\"wireguard\",\"tag\":\"w\",\"system\":true}"
            ))
            .is_err()
        );
        assert!(
            check_endpoint_wireguard_system(&value(
                "{\"type\":\"wireguard\",\"tag\":\"w\",\"system\":false}"
            ))
            .is_ok()
        );
        assert!(
            check_endpoint_wireguard_system(&value("{\"type\":\"wireguard\",\"tag\":\"w\"}"))
                .is_ok()
        );
    }

    // Ported from internal/profile/credentials.go
    // CredentialForProfile (first profile match wins) and
    // HasCredentialForProfile (presence-only). Values are
    // fake (never real credentials).
    #[test]
    fn test_credential_from_raw_first_match_wins() {
        let raw = value(
            "[{\"tag\":\"c1\",\"profile\":\"no1\",\"username\":\"alice\",\"password\":\"pw-one\"},{\"tag\":\"c2\",\"profile\":\"no1\",\"username\":\"bob\",\"password\":\"pw-two\"},{\"tag\":\"c3\",\"profile\":\"other\",\"username\":\"carol\",\"password\":\"pw-three\"}]",
        );
        assert_eq!(
            credential_from_raw(&raw, "no1"),
            Some(LoginCredential {
                username: "alice".to_string(),
                password: "pw-one".to_string(),
            })
        );
        assert_eq!(
            credential_from_raw(&raw, "other"),
            Some(LoginCredential {
                username: "carol".to_string(),
                password: "pw-three".to_string(),
            })
        );
        assert_eq!(credential_from_raw(&raw, "missing"), None);
        assert_eq!(credential_from_raw(&value("[]"), "no1"), None);
        assert_eq!(credential_from_raw(&value("{}"), "no1"), None);
        // A matching entry with non-string values yields None
        // (defensive; parse-time validation rejects this).
        let bad =
            value("[{\"tag\":\"c1\",\"profile\":\"no1\",\"username\":1,\"password\":\"pw\"}]");
        assert_eq!(credential_from_raw(&bad, "no1"), None);
    }

    #[test]
    fn test_login_credential_debug_never_prints_values() {
        let cred = LoginCredential {
            username: "alice".to_string(),
            password: "SECRET-PASSWORD".to_string(),
        };
        let rendered = format!("{cred:?}");
        assert!(!rendered.contains("alice"), "{rendered}");
        assert!(!rendered.contains("SECRET-PASSWORD"), "{rendered}");
        assert!(rendered.contains("[redacted]"), "{rendered}");
    }
}
