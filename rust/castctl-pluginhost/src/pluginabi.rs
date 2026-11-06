// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! The plugin contract: C ABI version, JSON envelope,
//! registration validation.
//!
//! Go source: `internal/pluginabi/pluginabi.go` (all of it).
//! The shape mirrors CLIProxyAPI's plugin ABI at pin
//! 250d5981, cut down to the v1 subset (see the Go file
//! header for what was deliberately not copied).

use serde::{Deserialize, Serialize};

use crate::error::PluginHostError;

/// C ABI version. Must match exactly: a plugin reporting
/// any other value is rejected, never adapted.
/// Source: `pluginabi.go:36`.
pub const ABI_VERSION: u32 = 1;
/// RPC JSON contract version, also the ceiling.
/// Source: `pluginabi.go:40`.
pub const SCHEMA_VERSION: u32 = 1;
/// The single C entry symbol a plugin must export.
/// Source: `pluginabi.go:46`.
pub const ENTRY_SYMBOL: &str = "castctl_plugin_init";

/// Method names. Source: `pluginabi.go:48-82`.
pub const METHOD_PLUGIN_REGISTER: &str = "plugin.register";
pub const METHOD_PLUGIN_RECONFIGURE: &str = "plugin.reconfigure";
pub const METHOD_PLUGIN_QUIESCE: &str = "plugin.quiesce";
pub const METHOD_PLUGIN_SHUTDOWN: &str = "plugin.shutdown";
pub const METHOD_PROVIDER_CALL: &str = "provider.call";
pub const METHOD_COMMAND_REGISTER: &str = "command.register";
pub const METHOD_COMMAND_EXECUTE: &str = "command.execute";
/// The ONLY reverse callback a plugin may call into the host.
/// Source: `pluginabi.go:80-82`.
pub const METHOD_HOST_LOG: &str = "host.log";

/// The JSON value exchanged across the C ABI in both
/// directions. Source: `pluginabi.go:86-90`.
/// (`result` is `Box<serde_json::value::RawValue>` here;
/// Go uses `json.RawMessage`: the raw bytes are
/// preserved verbatim — key order, whitespace, and an
/// explicit `null` (4 bytes) all survive, where a
/// `serde_json::Value` would re-serialise with sorted
/// keys and lose the null-vs-absent distinction.)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    /// `ok` — missing means `false`, like Go's zero
    /// value (`json.Unmarshal` leaves a missing field
    /// at its zero value).
    #[serde(default)]
    pub ok: bool,
    /// `result`, omitted when absent. An explicit JSON
    /// `null` deserialises to `Some(RawValue("null"))`,
    /// NOT to `None`: the custom deserialiser runs for
    /// every present field (absent fields take the
    /// `#[serde(default)]` instead), and `RawValue`
    /// captures `null` as 4 raw bytes.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_raw_result"
    )]
    pub result: Option<Box<serde_json::value::RawValue>>,
    /// `error`, omitted when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<PluginError>,
}

/// Deserialise a present `result` field as raw bytes.
/// Present-but-`null` becomes `Some(RawValue("null"))`;
/// only an absent field is `None` (via `#[serde(default)]`).
fn deserialize_raw_result<'de, D>(
    d: D,
) -> Result<Option<Box<serde_json::value::RawValue>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(Some(Box::<serde_json::value::RawValue>::deserialize(d)?))
}

/// Build a raw JSON value from a serialisable value.
/// Serialising a `serde_json::Value` cannot fail, so
/// `to_raw_value` cannot fail either; the fallback only
/// exists because the signature is infallible, and it
/// parses the literal `"null"`, which is valid JSON by
/// construction (`expect` on a literal, never on
/// external input).
#[must_use]
pub fn raw_value(v: &serde_json::Value) -> Box<serde_json::value::RawValue> {
    serde_json::value::to_raw_value(v).unwrap_or_else(|_| {
        serde_json::value::RawValue::from_string("null".to_string())
            .expect("literal null is valid JSON")
    })
}

/// The failure half of an [`Envelope`].
/// Source: `pluginabi.go:95-102`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginError {
    /// Stable error code.
    pub code: String,
    /// Redacted message only.
    pub message: String,
    /// Advisory only; the host decides retries.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub retryable: bool,
}

/// Build a failure envelope with the given code and message.
/// Source: `NewErrorEnvelope` (`pluginabi.go:105-107`).
#[must_use]
pub fn new_error_envelope(code: &str, message: &str) -> Envelope {
    Envelope {
        ok: false,
        result: None,
        error: Some(PluginError {
            code: code.to_string(),
            message: message.to_string(),
            retryable: false,
        }),
    }
}

/// Plugin identity. Source: `pluginabi.go:110-117`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Metadata {
    /// Plugin name (required).
    pub name: String,
    /// Plugin version (required).
    pub version: String,
    /// Plugin author (required).
    pub author: String,
    /// Optional repository URL (NOT required — castctl
    /// deliberately drops upstream's requirement).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub github_repository: String,
}

/// The v1 capability set: exactly two.
/// Source: `pluginabi.go:124-135`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Capabilities {
    /// Opaque JSON-envelope capability.
    #[serde(default)]
    pub provider: bool,
    /// Registers commands via the contract.
    #[serde(default)]
    pub command_provider: bool,
}

impl Capabilities {
    /// Whether at least one capability is declared.
    /// Source: `Capabilities.Any` (`pluginabi.go:138`).
    #[must_use]
    pub fn any(self) -> bool {
        self.provider || self.command_provider
    }
}

/// One command a CommandProvider plugin registers.
/// Source: `pluginabi.go:141-144`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Command {
    /// Command name.
    pub name: String,
    /// Optional usage text.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub usage: String,
}

/// The result of `plugin.register` / `plugin.reconfigure`.
/// Source: `pluginabi.go:148-163`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Registration {
    /// Schema version (0 = original contract, treated as 1).
    #[serde(default)]
    pub schema_version: u32,
    /// Plugin metadata.
    pub metadata: Metadata,
    /// Declared capabilities.
    pub capabilities: Capabilities,
    /// Commands (only with `command_provider`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub commands: Vec<Command>,
    /// Hosts the egress proxy injects the session cookie
    /// for. Bare hostnames only.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cookie_hosts: Vec<String>,
}

/// The opaque, secret-stripped identity core hands a plugin.
/// Source: `pluginabi.go:167-176`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Identity {
    /// Profile outbound tag.
    pub outbound_tag: String,
    /// SHA-256 of the secret-stripped canonical JSON.
    pub outbound_hash: String,
}

/// The core-owned per-session loopback proxy a plugin must
/// use for network traffic.
/// Source: `pluginabi.go:180-188`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Egress {
    /// Proxy URL.
    pub proxy_url: String,
    /// Ephemeral per-session username (omitted when absent).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub username: String,
    /// Ephemeral per-session password (omitted when absent).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub password: String,
}

/// The request core sends to `plugin.register` /
/// `plugin.reconfigure`. Source: `pluginabi.go:198-206`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterRequest {
    /// The plugin's config fragment VERBATIM (never
    /// scrubbed, never augmented).
    pub config_json: serde_json::Value,
    /// Host schema version.
    pub schema_version: u32,
    /// Plugin tag.
    pub tag: String,
    /// Plugin type.
    #[serde(rename = "type")]
    pub type_: String,
    /// Stripped identity (present only when supplied).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<Identity>,
    /// Egress proxy (present only when supplied).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub egress: Option<Egress>,
}

/// Whether `s` contains a control character (`< 0x20` or
/// `0x7f`), the Go `strings.ContainsFunc` rule used by
/// `ValidateRegistration` (`pluginabi.go:232-236,247-249`).
fn has_control_chars(s: &str) -> bool {
    s.chars().any(|c| (c as u32) < 0x20 || (c as u32) == 0x7f)
}

/// Apply the schema gate and the metadata / capability
/// rules to a registration response. Returns the
/// negotiated schema version. A missing schema_version
/// (0) is treated as the original contract, 1; a higher
/// version is rejected, never adapted.
/// Source: `ValidateRegistration` (`pluginabi.go:224-264`).
pub fn validate_registration(reg: &Registration) -> Result<u32, PluginHostError> {
    if reg.schema_version > SCHEMA_VERSION {
        return Err(PluginHostError::invalid(format!(
            "plugin schema version {} is not supported",
            reg.schema_version
        )));
    }
    let schema = if reg.schema_version == 0 {
        1
    } else {
        reg.schema_version
    };
    if reg.metadata.name.is_empty() {
        return Err(PluginHostError::invalid("plugin metadata name is required"));
    }
    if reg.metadata.version.is_empty() {
        return Err(PluginHostError::invalid(
            "plugin metadata version is required",
        ));
    }
    if reg.metadata.author.is_empty() {
        return Err(PluginHostError::invalid(
            "plugin metadata author is required",
        ));
    }
    for field in [
        &reg.metadata.name,
        &reg.metadata.version,
        &reg.metadata.author,
    ] {
        if has_control_chars(field) {
            return Err(PluginHostError::invalid(
                "plugin metadata must not contain control characters",
            ));
        }
    }
    if !reg.capabilities.any() {
        return Err(PluginHostError::invalid(
            "plugin declares no capabilities: at least one capability is required",
        ));
    }
    if !reg.commands.is_empty() && !reg.capabilities.command_provider {
        return Err(PluginHostError::invalid(
            "plugin declares commands without the command_provider capability",
        ));
    }
    for cmd in &reg.commands {
        if cmd.name.is_empty() {
            return Err(PluginHostError::invalid("plugin command name is required"));
        }
        if has_control_chars(&cmd.name) {
            return Err(PluginHostError::invalid(
                "plugin command name must not contain control characters",
            ));
        }
    }
    for host in &reg.cookie_hosts {
        if !valid_cookie_host(host) {
            return Err(PluginHostError::invalid(format!(
                "plugin cookie_hosts entry {host:?} is not a bare hostname"
            )));
        }
    }
    Ok(schema)
}

/// Whether `host` is a bare hostname usable in
/// `cookie_hosts`: lowercase letters, digits, dots, and
/// hyphens only; every label 1–63 chars, not starting or
/// ending with a hyphen; at most 253 chars total.
/// Source: `ValidCookieHost` (`pluginabi.go:273-298`).
pub fn valid_cookie_host(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    for label in host.split('.') {
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return false;
        }
        for c in label.chars() {
            if !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-') {
                return false;
            }
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn good_reg() -> Registration {
        Registration {
            schema_version: 1,
            metadata: Metadata {
                name: "demo".to_string(),
                version: "1.0.0".to_string(),
                author: "boss".to_string(),
                github_repository: String::new(),
            },
            capabilities: Capabilities {
                provider: true,
                command_provider: false,
            },
            commands: vec![],
            cookie_hosts: vec![],
        }
    }

    #[test]
    fn validate_registration_table() {
        // Valid, schema 1 and missing-schema-as-1.
        assert_eq!(validate_registration(&good_reg()), Ok(1));
        let mut reg = good_reg();
        reg.schema_version = 0;
        assert_eq!(validate_registration(&reg), Ok(1));
        // Schema 2 refuses.
        let mut reg = good_reg();
        reg.schema_version = 2;
        assert_eq!(
            validate_registration(&reg).unwrap_err().to_string(),
            "plugin schema version 2 is not supported"
        );
        // Missing metadata fields.
        for (mut reg, want) in [
            (
                {
                    let mut r = good_reg();
                    r.metadata.name = String::new();
                    r
                },
                "plugin metadata name is required",
            ),
            (
                {
                    let mut r = good_reg();
                    r.metadata.version = String::new();
                    r
                },
                "plugin metadata version is required",
            ),
            (
                {
                    let mut r = good_reg();
                    r.metadata.author = String::new();
                    r
                },
                "plugin metadata author is required",
            ),
        ] {
            assert_eq!(validate_registration(&reg).unwrap_err().to_string(), want);
            reg.metadata.name = "x".to_string();
        }
        // Control characters in metadata.
        let mut reg = good_reg();
        reg.metadata.name = "bad\nname".to_string();
        assert_eq!(
            validate_registration(&reg).unwrap_err().to_string(),
            "plugin metadata must not contain control characters"
        );
        // No capabilities.
        let mut reg = good_reg();
        reg.capabilities = Capabilities::default();
        assert_eq!(
            validate_registration(&reg).unwrap_err().to_string(),
            "plugin declares no capabilities: at least one capability is required"
        );
        // Commands without the capability.
        let mut reg = good_reg();
        reg.commands = vec![Command {
            name: "do".to_string(),
            usage: String::new(),
        }];
        assert_eq!(
            validate_registration(&reg).unwrap_err().to_string(),
            "plugin declares commands without the command_provider capability"
        );
        // Commands with the capability pass; empty name refuses.
        let mut reg = good_reg();
        reg.capabilities.command_provider = true;
        reg.commands = vec![Command {
            name: "do".to_string(),
            usage: String::new(),
        }];
        assert!(validate_registration(&reg).is_ok());
        reg.commands = vec![Command {
            name: String::new(),
            usage: String::new(),
        }];
        assert_eq!(
            validate_registration(&reg).unwrap_err().to_string(),
            "plugin command name is required"
        );
        // Bad cookie hosts.
        let mut reg = good_reg();
        reg.cookie_hosts = vec!["EXAMPLE.COM".to_string()];
        assert!(validate_registration(&reg).is_err());
        reg.cookie_hosts = vec!["ok.example.com".to_string()];
        assert!(validate_registration(&reg).is_ok());
    }

    #[test]
    fn valid_cookie_host_table() {
        for good in ["example.com", "a-b.c", "x", "a.b.c.d"] {
            assert!(valid_cookie_host(good), "{good}");
        }
        for bad in [
            "",
            "A.com",
            "a..b",
            "-a.b",
            "a-.b",
            "a_b",
            "*.example.com",
            "a:8080",
            "a/b",
            "a b",
            "éxample.com",
        ] {
            assert!(!valid_cookie_host(bad), "{bad}");
        }
        assert!(!valid_cookie_host(&"a".repeat(254)));
        assert!(valid_cookie_host(&"a".repeat(63)));
        assert!(!valid_cookie_host(&"a".repeat(64)));
    }

    #[test]
    fn envelope_json_round_trip() {
        let env = new_error_envelope("oops", "something failed");
        let json = serde_json::to_string(&env).unwrap();
        assert_eq!(
            json,
            r#"{"ok":false,"error":{"code":"oops","message":"something failed"}}"#
        );
        let back: Envelope = serde_json::from_str(&json).unwrap();
        assert_eq!(back, env);
        let ok_env = Envelope {
            ok: true,
            result: Some(raw_value(&serde_json::json!({"n": 1}))),
            error: None,
        };
        let json = serde_json::to_string(&ok_env).unwrap();
        assert_eq!(json, r#"{"ok":true,"result":{"n":1}}"#);
    }

    /// Red-team B4 (fix loop 1): Go's `json.Unmarshal`
    /// leaves a missing `ok` at its zero value (`false`)
    /// and keeps `result` as raw bytes — including an
    /// explicit `null` (4 bytes) and key order.
    #[test]
    fn envelope_missing_ok_and_null_result_match_go() {
        // No `"ok"`: the plugin error survives (the old
        // code failed with `missing field 'ok'`).
        let env: Envelope =
            serde_json::from_str(r#"{"error":{"code":"boom","message":"m"}}"#).unwrap();
        assert!(!env.ok);
        assert!(env.result.is_none());
        assert_eq!(env.error.as_ref().unwrap().code, "boom");
        // Explicit `"result":null`: 4 raw bytes, not absent.
        let env: Envelope = serde_json::from_str(r#"{"ok":true,"result":null}"#).unwrap();
        assert!(env.ok);
        assert_eq!(env.result.as_ref().unwrap().get(), "null");
        assert_eq!(env.result.as_ref().unwrap().get().as_bytes(), b"null");
        // Absent `result`: still `None`.
        let env: Envelope = serde_json::from_str(r#"{"ok":true}"#).unwrap();
        assert!(env.result.is_none());
        // Object result: raw bytes verbatim (key order kept).
        let env: Envelope =
            serde_json::from_str(r#"{"ok":true,"result":{"b":1,"a":2}}"#).unwrap();
        assert_eq!(env.result.as_ref().unwrap().get(), r#"{"b":1,"a":2}"#);
    }
}
