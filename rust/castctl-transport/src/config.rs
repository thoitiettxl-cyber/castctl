// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Sing-box outbound JSON → honk `Node` dispatch (M3 glue).
//!
//! Go sources: `internal/profile/outbound.go:96-138`
//! (`parseOutbound`, sing-box `option.Outbound` via the registry —
//! unknown types/fields are rejected there by sing-box `badjson`),
//! `internal/outbound/manager.go:243-272` (`CreateOutbound`) and
//! `:479-494` (`CreateEndpoint`, wireguard endpoint guard),
//! `internal/outbound/tls.go:16-76` (`GatewayTLSOptions`,
//! `BuildTLSConfig`), `internal/gateway/connector.go:237-...`
//! (WebSocket ALPN pin), and the sing-box v1.14.4
//! `option/tls.go` schema for `tls.utls` / `tls.reality`.
//!
//! Scope (plan decision D-M3-3): only the brief's subset is mapped
//! to honk — `socks`/`shadowsocks`/`vmess`/`vless`/`trojan`/
//! `hysteria2`/`tuic` → honk-outbound; `direct`/`block` as before;
//! `wireguard` → an explicit "→ M3d" error, never a silent mapping.
//! Every other sing-box type (`http`, `selector`, `urltest`,
//! `snell`, `naive`, `tor`, `ssh`, `shadowtls`, `anytls`, `juicity`,
//! SS plugin) → `Unsupported` fail-closed. `anytls`/`juicity` exist
//! in honk's registry but are NOT in the M3 scope, so they are not
//! mapped even though honk could dial them; adding them is a
//! scope decision for a later PR, not a silent extension here.
//!
//! Deviations from Go, recorded deliberately:
//! - Unknown JSON fields are IGNORED here, while sing-box
//!   `badjson` rejects them. M3 follows the M2 raw-preserve
//!   philosophy (D-M2-1) at the glue layer; strict sing-box
//!   validation is still deferred.
//! - `detour` chains are NOT resolved in M3: a non-empty `detour`
//!   is `Unsupported`. Go resolves detours through the manager;
//!   honk has no sing-box detour concept to map onto.
//! - The `socks` type name is translated to honk `socks5`
//!   (`NodeProtocol::from_str` accepts only `"socks5"`, never
//!   `"socks"`).

use std::collections::BTreeMap;
use std::sync::Arc;

use honk_config::node::{
    Hysteria2Config, Node, OutboundConfig, QuicOptions, ShadowsocksConfig, Socks5Config,
    StreamTransportOptions, TlsOptions, TrojanConfig, TuicConfig, VlessConfig, VmessConfig,
};

use crate::error::TransportError;
use crate::wireguard::{WireGuardDialer, parse_wireguard_endpoint};

/// What `dispatch` decided for one outbound object.
/// No derived Debug: the hand-written impl below prints
/// protocol/host/port only, never node credentials.
pub enum Dispatch {
    /// Dial through honk-outbound with this node.
    Honk(Box<Node>),
    /// Direct dial (no proxy protocol).
    Direct,
    /// Always fail-closed (honk `Block` handler semantics: dial
    /// fails; castctl has no `block` code of its own, the semantics
    /// come from the outbound type itself).
    Block,
    /// Userspace WireGuard endpoint (M3d): dial through the
    /// boringtun + smoltcp tunnel owned by this dialer. Declared
    /// in `endpoints`, never in `outbounds`.
    WireGuard(Arc<WireGuardDialer>),
}

/// TLS mode decision (plan decision D-M3-4). Honk's Chrome-mode is
/// process-global (`honk_outbound::tls::set_tls_mode` /
/// `set_utls_imitate`), not per-node: there is exactly one Chrome
/// profile, and two profiles with different fingerprints in one
/// process are an M3 limitation (see PORTING.md §M3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsMode {
    /// `set_tls_mode("utls")` + imitate chrome.
    UtlsChrome,
}

/// Decide the TLS mode from the castctl inputs, WITHOUT touching
/// global state (pure, unit-testable). Inputs:
/// - `utls_enabled`: `None` = no `tls.utls` block (sing-box
///   `OutboundUTLSOptions` is a pointer: nil means Go applies
///   its default, enabled + chrome); `Some(false)` = the block
///   is present and its plain-bool `enabled` field is false OR
///   absent (a missing field on a present block defaults to
///   false, exactly like an explicit disable) — in M3 this is
///   fail-closed `Unsupported` because honk has no per-node
///   "TLS without Chrome-mode" switch. NOTE: this is the
///   outbound path only. The gateway-dial path
///   (`internal/outbound/dialer.go` `DialTLS`) forces
///   `Enabled=true` when TLS is requested at all — a different
///   rule for a different call site, ported in M4, not here
///   (see PORTING.md §M3.3);
/// - `fingerprint`: the `tls.utls.fingerprint` value after the Go
///   default (empty means chrome);
/// - `profile_engine`: the castctl profile `tls_engine` value
///   (`utls`/`stdlib`/`cronet`, `internal/profile/fingerprint.go`).
///   `None` means "not supplied" and behaves like `utls`.
/// - `spider_x_present`: a `tls.reality.spider_x` value was supplied.
///   Honk's live REALITY path (`parse_reality_config`) does not read
///   `spider_x`, so silently accepting it would change the handshake
///   meaning — fail closed instead.
pub fn tls_mode_for(
    utls_enabled: Option<bool>,
    fingerprint: Option<&str>,
    profile_engine: Option<&str>,
    spider_x_present: bool,
) -> Result<TlsMode, TransportError> {
    if spider_x_present {
        return Err(TransportError::Unsupported {
            message: "tls.reality.spider_x is not supported by the honk REALITY path; refusing to map it silently".to_string(),
        });
    }
    if utls_enabled == Some(false) {
        return Err(TransportError::Unsupported {
            message: "tls.utls explicitly disabled is not supported by the honk transport (Chrome-mode is global); refusing to fall back silently".to_string(),
        });
    }
    match profile_engine {
        Some("utls") | None => {}
        Some(other) => {
            return Err(TransportError::Unsupported {
                message: format!(
                    "tls_engine {other} is not supported by the honk transport (only boring Chrome-mode exists)"
                ),
            });
        }
    }
    match fingerprint.map(str::trim) {
        None | Some("") | Some("chrome") => Ok(TlsMode::UtlsChrome),
        Some(other) => Err(TransportError::Unsupported {
            message: format!(
                "tls.utls.fingerprint {other} is not supported by the honk transport (only chrome exists; refusing to map it silently to chrome)"
            ),
        }),
    }
}

/// Apply the decided mode to honk's process-global TLS state.
/// Only ever sets utls+chrome (every other input errors in
/// `tls_mode_for` before this runs), so repeated calls are
/// idempotent.
pub fn apply_tls_mode(mode: TlsMode) -> Result<(), TransportError> {
    match mode {
        TlsMode::UtlsChrome => {
            honk_outbound::tls::set_tls_mode("utls");
            honk_outbound::tls::set_utls_imitate("chrome");
            Ok(())
        }
    }
}

/// Decode base64url (no padding required) into bytes. Written here
/// instead of adding a `base64` dependency for one validation: the
/// alphabet and padding rules are exactly RFC 4648 §5, with Go's
/// decoder strictness for the cases that matter for keys —
/// whitespace anywhere, a data length ≡ 1 mod 4, and non-zero
/// trailing bits are all rejected, as Go rejects them. One
/// deliberate fail-closed divergence: Go ignores `\r` and `\n`
/// but rejects other whitespace; this decoder rejects ALL
/// whitespace (a legitimate key never contains any, so the extra
/// strictness cannot reject a valid key). Padding, when present,
/// must be 1–2 trailing `=` with the matching data length
/// (1 pad ↔ data ≡ 3 mod 4, 2 pads ↔ data ≡ 2 mod 4); anything
/// after padding is rejected.
pub fn decode_base64url(input: &str) -> Result<Vec<u8>, TransportError> {
    let invalid = || TransportError::Validation {
        message: "reality public_key is not valid base64url".to_string(),
    };
    let mut values: Vec<u8> = Vec::with_capacity(input.len() * 3 / 4 + 3);
    let mut acc: u32 = 0;
    let mut nbits = 0u32;
    let mut data_len = 0usize;
    let mut padding = 0usize;
    for c in input.chars() {
        if c == '=' {
            padding += 1;
            if padding > 2 {
                return Err(invalid());
            }
            continue;
        }
        if padding > 0 {
            // Data after padding.
            return Err(invalid());
        }
        if c.is_whitespace() {
            return Err(invalid());
        }
        let v = match c {
            'A'..='Z' => c as u32 - 'A' as u32,
            'a'..='z' => c as u32 - 'a' as u32 + 26,
            '0'..='9' => c as u32 - '0' as u32 + 52,
            '-' => 62,
            '_' => 63,
            _ => return Err(invalid()),
        };
        data_len += 1;
        acc = (acc << 6) | v;
        nbits += 6;
        if nbits >= 8 {
            nbits -= 8;
            values.push((acc >> nbits) as u8);
        }
    }
    if data_len % 4 == 1 {
        return Err(invalid());
    }
    match (padding, data_len % 4) {
        (0, _) | (1, 3) | (2, 2) => {}
        _ => return Err(invalid()),
    }
    // Trailing bits of the final partial quantum must be zero
    // (Go rejects e.g. "AAB": the last value's low bits are 01).
    if nbits > 0 && (acc & ((1u32 << nbits) - 1)) != 0 {
        return Err(invalid());
    }
    Ok(values)
}

/// Validate a REALITY key/short-id pair the way honk's
/// `parse_reality_config` (`crates/honk-outbound/src/reality.rs:58-93`)
/// does: the public key must base64url-decode to exactly 32 bytes
/// (X25519), the short id must be even-length hex of at most 8
/// bytes (16 hex chars), zero-padded on the right. Anything else is
/// fail-closed — never a downgrade to plain TLS.
pub fn validate_reality(
    public_key: Option<&str>,
    short_id: Option<&str>,
) -> Result<(), TransportError> {
    match public_key {
        Some(key) if !key.trim().is_empty() => {
            let decoded = decode_base64url(key.trim())?;
            if decoded.len() != 32 {
                return Err(TransportError::Validation {
                    message: "tls.reality.public_key must decode to 32 bytes".to_string(),
                });
            }
            if let Some(sid) = short_id {
                let sid = sid.trim();
                if !sid.is_empty()
                    && (sid.len() > 16
                        || sid.len() % 2 != 0
                        || !sid.chars().all(|c| c.is_ascii_hexdigit()))
                {
                    return Err(TransportError::Validation {
                        message: "tls.reality.short_id must be even-length hex of at most 8 bytes"
                            .to_string(),
                    });
                }
            }
            Ok(())
        }
        _ => {
            if short_id.map(str::trim).is_some_and(|s| !s.is_empty()) {
                return Err(TransportError::Validation {
                    message: "tls.reality.short_id without tls.reality.public_key is rejected (REALITY requires reality_public_key)".to_string(),
                });
            }
            Ok(())
        }
    }
}

fn get_str<'a>(obj: &'a serde_json::Value, key: &str) -> Option<&'a str> {
    obj.get(key).and_then(|v| v.as_str())
}

fn get_u16(obj: &serde_json::Value, key: &str) -> Option<u16> {
    obj.get(key)
        .and_then(|v| v.as_u64())
        .and_then(|n| u16::try_from(n).ok())
}

fn get_bool(obj: &serde_json::Value, key: &str) -> Option<bool> {
    obj.get(key).and_then(|v| v.as_bool())
}

/// Build honk `TlsOptions` from a sing-box `tls` object, applying
/// the D-M3-4 mode decision (which also sets honk's global mode as
/// a side effect — see `apply_tls_mode`).
/// `transport_type` is the sing-box transport type (`"ws"` pins ALPN
/// to `["http/1.1"]`, Go `internal/gateway/connector.go:240`;
/// QUIC transports must NOT carry a TCP ALPN — honk's QUIC client
/// config rejects a non-empty `tls.alpn` on QUIC nodes, and
/// `TuicConfig`/`Hysteria2Config` carry no `TlsOptions` at all, so
/// only `skip_cert_verify` and `sni` are carried from this result
/// into `quic.tls` for hysteria2/tuic (M3e; see `dispatch_outbound`).
/// The result is computed for EVERY outbound (see `dispatch_outbound`
/// `:481`); the TCP/TLS arms use it whole, the QUIC arms use only
/// those two fields.
fn build_tls(
    tls: Option<&serde_json::Value>,
    server_host: &str,
    transport_type: &str,
    profile_engine: Option<&str>,
) -> Result<TlsOptions, TransportError> {
    let Some(tls) = tls else {
        return Ok(TlsOptions::default());
    };
    let enabled = get_bool(tls, "enabled").unwrap_or(false);
    let utls = tls.get("utls");
    // Presence matters, not just the value: sing-box
    // `OutboundUTLSOptions` is a POINTER, so a missing `utls`
    // block means "UTLS nil" (Go default: enabled + chrome,
    // `None` here), while a PRESENT block with a missing
    // `enabled` field means the plain-bool field defaults to
    // false (`Some(false)` here). Collapsing the two cases
    // (the old `and_then(get_bool)`) made a present-but-empty
    // block silently take the nil default.
    let utls_enabled = utls.map(|u| get_bool(u, "enabled").unwrap_or(false));
    let fingerprint = utls.and_then(|u| get_str(u, "fingerprint"));
    let reality = tls.get("reality");
    let spider_x_present = reality
        .and_then(|r| get_str(r, "spider_x"))
        .is_some_and(|s| !s.trim().is_empty());
    // The Go default (GatewayTLSOptions) applies whenever TLS is
    // enabled at all; when the whole tls object is disabled
    // (enabled=false) the caller passes no TLS to honk, and the
    // mode decision is skipped by returning defaults below.
    if enabled {
        let mode = tls_mode_for(utls_enabled, fingerprint, profile_engine, spider_x_present)?;
        apply_tls_mode(mode)?;
    } else if spider_x_present {
        return Err(TransportError::Unsupported {
            message: "tls.reality.spider_x is not supported by the honk REALITY path".to_string(),
        });
    }
    let reality_key = reality.and_then(|r| get_str(r, "public_key"));
    let reality_sid = reality.and_then(|r| get_str(r, "short_id"));
    // REALITY is on only when TLS itself is enabled AND the
    // reality block explicitly enables it (`field == Some(true)`).
    // The old `unwrap_or(true)` turned a missing `enabled` field
    // into REALITY-on, and the fields were filled even when TLS
    // was disabled — honk's `TlsOptions::is_secure()` (enabled OR
    // a reality key present) would then have run a REALITY
    // handshake for a TLS-disabled node. With this gate, TLS
    // disabled ⇒ reality fields None, whatever the block says.
    let reality_enabled = enabled && reality.and_then(|r| get_bool(r, "enabled")) == Some(true);
    if reality_enabled {
        validate_reality(reality_key, reality_sid)?;
    }
    let mut alpn: Vec<String> = tls
        .get("alpn")
        .and_then(|a| a.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    // WS-dial ALPN pin (Go connector.go:240): gorilla speaks
    // HTTP/1.1 only, so a WS transport negotiates http/1.1 even
    // when the profile would otherwise offer h2. This pin is
    // WS-dial-scoped in Go; here the whole node IS the WS dial.
    if transport_type == "ws" {
        alpn = vec!["http/1.1".to_string()];
    }
    if let Some(ech) = tls.get("ech")
        && (ech
            .get("config")
            .and_then(|v| v.as_str())
            .is_some_and(|s| !s.is_empty())
            || ech
                .get("config_path")
                .and_then(|v| v.as_str())
                .is_some_and(|s| !s.is_empty()))
    {
        return Err(TransportError::Unsupported {
            message: "tls.ech config values are not mapped in M3 (ECH GREASE via Chrome-mode only)"
                .to_string(),
        });
    }
    Ok(TlsOptions {
        enabled,
        sni: Some(
            get_str(tls, "server_name")
                .filter(|s| !s.is_empty())
                .unwrap_or(server_host)
                .to_string(),
        ),
        skip_cert_verify: get_bool(tls, "insecure").unwrap_or(false),
        ech_enabled: tls
            .get("ech")
            .and_then(|e| get_bool(e, "enabled"))
            .unwrap_or(false),
        ech_config: None,
        ech_config_path: None,
        reality_public_key: if reality_enabled {
            reality_key.map(str::to_string)
        } else {
            None
        },
        reality_short_id: if reality_enabled {
            reality_sid.map(str::to_string)
        } else {
            None
        },
        reality_spider_x: None,
        pin_sha256: None,
        alpn,
    })
}

/// Build honk `StreamTransportOptions` from a sing-box `transport`
/// object. Returns the transport type string (`"tcp"` default) and
/// the options. `xhttp`/`http` transports are `Unsupported` in M3
/// (sing-box `http` has no honk vocab entry; XHTTP needs an
/// H2-only ALPN contract this glue does not yet enforce).
fn build_transport(
    outbound: &serde_json::Value,
) -> Result<(String, StreamTransportOptions), TransportError> {
    let Some(transport) = outbound.get("transport") else {
        return Ok(("tcp".to_string(), StreamTransportOptions::default()));
    };
    let ttype = get_str(transport, "type").unwrap_or("tcp");
    match ttype {
        "" | "tcp" => Ok(("tcp".to_string(), StreamTransportOptions::default())),
        "ws" => {
            let mut headers = BTreeMap::new();
            if let Some(hdrs) = transport.get("headers").and_then(|h| h.as_object()) {
                for (k, v) in hdrs {
                    if let Some(s) = v.as_str() {
                        headers.insert(k.clone(), s.to_string());
                    }
                }
            }
            Ok((
                "ws".to_string(),
                StreamTransportOptions {
                    transport: "ws".to_string(),
                    ws_path: get_str(transport, "path").map(str::to_string),
                    ws_host: get_str(transport, "host").map(str::to_string),
                    ws_headers: headers,
                    grpc_service: None,
                    xhttp: None,
                },
            ))
        }
        "grpc" => Ok((
            "grpc".to_string(),
            StreamTransportOptions {
                transport: "grpc".to_string(),
                ws_path: None,
                ws_host: None,
                ws_headers: BTreeMap::new(),
                grpc_service: get_str(transport, "service_name").map(str::to_string),
                xhttp: None,
            },
        )),
        other => Err(TransportError::Unsupported {
            message: format!("stream transport {other} is not supported in M3"),
        }),
    }
}

/// Dispatch one sing-box outbound JSON object.
/// `profile_engine` is the castctl profile `tls_engine` value, when
/// the caller knows it (see `tls_mode_for`); `None` behaves as
/// `utls`. The returned `Node` has `derive_id` applied.
pub fn dispatch_outbound(
    outbound: &serde_json::Value,
    profile_engine: Option<&str>,
) -> Result<Dispatch, TransportError> {
    let otype = get_str(outbound, "type").ok_or_else(|| TransportError::Validation {
        message: "outbound is missing \"type\"".to_string(),
    })?;
    if get_str(outbound, "detour").is_some_and(|d| !d.is_empty()) {
        return Err(TransportError::Unsupported {
            message: "outbound detour chains are not resolved in M3".to_string(),
        });
    }
    match otype {
        "direct" => return Ok(Dispatch::Direct),
        "block" => return Ok(Dispatch::Block),
        "wireguard" => {
            return Err(TransportError::Unsupported {
                message: "wireguard outbound is not an outbound type (declare it in endpoints and reference its tag)".to_string(),
            });
        }
        _ => {}
    }
    let server = get_str(outbound, "server").ok_or_else(|| TransportError::Validation {
        message: format!("outbound type {otype} is missing \"server\""),
    })?;
    let port = get_u16(outbound, "server_port").ok_or_else(|| TransportError::Validation {
        message: format!("outbound type {otype} is missing \"server_port\""),
    })?;
    let (transport_type, transport) = build_transport(outbound)?;
    let tls = build_tls(outbound.get("tls"), server, &transport_type, profile_engine)?;
    let tag = get_str(outbound, "tag").unwrap_or("");
    let outbound_config = match otype {
        "socks" => {
            if let Some(v) = get_u64(outbound, "version")
                && v != 5
            {
                return Err(TransportError::Unsupported {
                    message: format!("socks version {v} is not supported (only socks5)"),
                });
            }
            OutboundConfig::Socks5(Socks5Config {
                username: get_str(outbound, "username").map(str::to_string),
                password: get_str(outbound, "password").map(str::to_string),
            })
        }
        "shadowsocks" => {
            if get_str(outbound, "plugin").is_some_and(|p| !p.is_empty()) {
                return Err(TransportError::Unsupported {
                    message: "shadowsocks plugin (SIP003) is not implemented in the honk dial path; refusing to ignore it silently".to_string(),
                });
            }
            OutboundConfig::Shadowsocks(ShadowsocksConfig {
                password: get_str(outbound, "password").map(str::to_string),
                encryption: get_str(outbound, "method").map(str::to_string),
                plugin: None,
                plugin_opts: None,
            })
        }
        "vmess" => OutboundConfig::Vmess(VmessConfig {
            uuid: get_str(outbound, "uuid").map(str::to_string),
            encryption: get_str(outbound, "security")
                .or_else(|| get_str(outbound, "encryption"))
                .map(str::to_string),
            network: get_str(outbound, "network").map(str::to_string),
            transport: transport.clone(),
            tls,
        }),
        "vless" => OutboundConfig::Vless(VlessConfig {
            uuid: get_str(outbound, "uuid").map(str::to_string),
            encryption: get_str(outbound, "encryption").map(str::to_string),
            udp_encoding: Default::default(),
            multiplex: Default::default(),
            flow: get_str(outbound, "flow").map(str::to_string),
            network: get_str(outbound, "network").map(str::to_string),
            transport: transport.clone(),
            tls,
        }),
        "trojan" => OutboundConfig::Trojan(TrojanConfig {
            password: get_str(outbound, "password").map(str::to_string),
            network: get_str(outbound, "network").map(str::to_string),
            transport: transport.clone(),
            tls,
        }),
        "hysteria2" => {
            let obfs = match outbound.get("obfs") {
                None => None,
                Some(v) => {
                    if let Some(s) = v.as_str() {
                        if s.is_empty() {
                            None
                        } else {
                            Some(s.to_string())
                        }
                    } else {
                        let otype = get_str(v, "type").unwrap_or("salamander");
                        if otype != "salamander" {
                            return Err(TransportError::Unsupported {
                                message: format!("hysteria2 obfs type {otype} is not supported"),
                            });
                        }
                        get_str(v, "password").map(str::to_string)
                    }
                }
            };
            OutboundConfig::Hysteria2(Hysteria2Config {
                auth: get_str(outbound, "password").map(str::to_string),
                obfs,
                up_mbps: get_u32(outbound, "up_mbps"),
                down_mbps: get_u32(outbound, "down_mbps"),
                port_hopping: None,
                hop_interval: None,
                init_stream_recv_window: None,
                init_conn_recv_window: None,
                disable_mtu_discovery: None,
                // M3e: map the QUIC-relevant TLS fields from the
                // `build_tls` result above. Only `skip_cert_verify`
                // (from `tls.insecure`, plain bool, default false,
                // gated on `tls.enabled` — fix-loop round 1, F1)
                // and `sni` (from `tls.server_name`, falling back to
                // the server host) are carried: honk's hysteria2
                // dial path takes the QUIC TLS server name from
                // `quic.tls.sni` (`honk-outbound/src/proxy/
                // hysteria2/mod.rs:606-610`), so leaving it unset
                // would silently drop the configured server name.
                // `alpn` is deliberately NOT copied: honk's QUIC
                // client config rejects a non-empty `tls.alpn`
                // (`honk-outbound/src/quic.rs:348-353`).
                // `skip_cert_verify` is gated on `tls.enabled`
                // (fix-loop round 1, F1): `enabled:false` +
                // `insecure:true` must stay false.
                quic: QuicOptions {
                    tls: TlsOptions {
                        skip_cert_verify: tls.enabled && tls.skip_cert_verify,
                        sni: tls.sni.clone(),
                        ..Default::default()
                    },
                    ..Default::default()
                },
            })
        }
        "tuic" => OutboundConfig::Tuic(TuicConfig {
            uuid: get_str(outbound, "uuid").map(str::to_string),
            password: get_str(outbound, "password").map(str::to_string),
            congestion: get_str(outbound, "congestion_control").map(str::to_string),
            alpn: get_str(outbound, "alpn").map(str::to_string),
            init_stream_recv_window: None,
            init_conn_recv_window: None,
            // M3e: same mapping as hysteria2 above — only
            // `skip_cert_verify` (gated on `tls.enabled`, F1) +
            // `sni` from `build_tls`; `alpn` stays empty (honk
            // rejects non-empty `tls.alpn` on QUIC nodes,
            // `honk-outbound/src/quic.rs:348-353`).
            // The tuic dial path likewise reads the QUIC TLS
            // server name from `quic.tls.sni`
            // (`honk-outbound/src/proxy/tuic.rs:457-462`).
            quic: QuicOptions {
                tls: TlsOptions {
                    skip_cert_verify: tls.enabled && tls.skip_cert_verify,
                    sni: tls.sni.clone(),
                    ..Default::default()
                },
                ..Default::default()
            },
        }),
        other => {
            return Err(TransportError::Unsupported {
                message: format!("outbound type {other} is not supported in M3"),
            });
        }
    };
    // Built with ..Default::default() (which stamps created_at/updated_at
    // via honk-config's own chrono use) so this crate needs no direct
    // chrono dependency for honk's timestamp fields.
    let mut node = Node {
        name: tag.to_string(),
        address: format!("{server}:{port}"),
        host: server.to_string(),
        port,
        outbound: outbound_config,
        ..Default::default()
    };
    // Stream-transport normalization (WS managed-header check,
    // transport vocab) — errors are validation errors, not panics.
    if let Err((field, msg)) = node.normalize_stream_transport() {
        return Err(TransportError::Validation {
            message: format!("stream transport {field}: {msg}"),
        });
    }
    node.id = node.derive_id();
    Ok(Dispatch::Honk(Box::new(node)))
}

fn get_u64(obj: &serde_json::Value, key: &str) -> Option<u64> {
    obj.get(key).and_then(|v| v.as_u64())
}

fn get_u32(obj: &serde_json::Value, key: &str) -> Option<u32> {
    obj.get(key)
        .and_then(|v| v.as_u64())
        .and_then(|n| u32::try_from(n).ok())
}

// Hand-written Debug for Dispatch: a honk Node's derived Debug
// prints the full outbound config, including passwords and keys.
// This crate must never print those through a derived Debug, so
// Dispatch prints protocol/host/port only.
impl std::fmt::Debug for Dispatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Dispatch::Honk(node) => f
                .debug_struct("Honk")
                .field("protocol", &node.protocol().as_str())
                .field("host", &node.host)
                .field("port", &node.port)
                .finish_non_exhaustive(),
            Dispatch::Direct => write!(f, "Direct"),
            Dispatch::Block => write!(f, "Block"),
            Dispatch::WireGuard(d) => f
                .debug_struct("WireGuard")
                .field("tag", &d.tag())
                .field("peer_host", &d.peer_host())
                .field("peer_port", &d.peer_port())
                .finish_non_exhaustive(),
        }
    }
}

/// Dispatch one sing-box WireGuard ENDPOINT object (M3d; Go:
/// `internal/outbound/manager.go:479-494` `CreateEndpoint`).
/// The endpoint JSON is flat (sing-box spellings); the DNS servers
/// for this endpoint's tag come from top-level `"wireguard_dns"`
/// (Go `internal/profile/dns.go` branch (2)) and are passed in as
/// plain strings (IP literal or hostname — a hostname bootstraps
/// once via the system resolver, see `wireguard.rs`).
/// `system:true` is rejected by `WireGuardDialer::new` with the
/// Go runtime text verbatim.
pub fn dispatch_endpoint(
    endpoint: &serde_json::Value,
    wireguard_dns: &[String],
) -> Result<Dispatch, TransportError> {
    let cfg = parse_wireguard_endpoint(endpoint, wireguard_dns)?;
    Ok(Dispatch::WireGuard(WireGuardDialer::shared(cfg)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn json(s: &str) -> serde_json::Value {
        serde_json::from_str(s).expect("INVARIANT: test fixture parses")
    }

    #[test]
    fn socks_maps_to_socks5_and_direct_block_wireguard() {
        let d = dispatch_outbound(&json(r#"{"type":"socks","server":"127.0.0.1","server_port":1080,"username":"u","password":"p"}"#), None)
            .expect("INVARIANT: socks dispatch works");
        assert!(matches!(d, Dispatch::Honk(_)));
        assert!(matches!(
            dispatch_outbound(&json(r#"{"type":"direct"}"#), None).expect("direct"),
            Dispatch::Direct
        ));
        assert!(matches!(
            dispatch_outbound(&json(r#"{"type":"block"}"#), None).expect("block"),
            Dispatch::Block
        ));
        let err = dispatch_outbound(
            &json(r#"{"type":"wireguard","server":"127.0.0.1","server_port":51820}"#),
            None,
        )
        .expect_err("wireguard must not dispatch in M3");
        assert!(matches!(err, TransportError::Unsupported { .. }));
        assert!(format!("{err}").contains("not an outbound type"));
        // And the endpoint path accepts the same shape as an
        // endpoint (tested fully in `wireguard.rs` / the
        // endpoint tests below). Fake keys: 32 bytes of 0x01 /
        // 0x02, never real key material.
        assert!(matches!(
            dispatch_endpoint(
                &json(
                    r#"{"type":"wireguard","tag":"wg1","private_key":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=","address":["10.0.0.2/32"],"peers":[{"public_key":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=","address":"127.0.0.1","port":51820,"allowed_ips":["0.0.0.0/0"]}]}"#
                ),
                &[]
            ),
            Ok(Dispatch::WireGuard(_))
        ));
    }

    #[test]
    fn unsupported_types_fail_closed() {
        for t in [
            "http",
            "selector",
            "urltest",
            "snell",
            "naive",
            "tor",
            "ssh",
            "shadowtls",
            "anytls",
            "juicity",
        ] {
            let err = dispatch_outbound(
                &json(&format!(
                    r#"{{"type":"{t}","server":"127.0.0.1","server_port":1080}}"#
                )),
                None,
            )
            .expect_err("unsupported type must fail");
            assert!(
                matches!(err, TransportError::Unsupported { .. }),
                "{t}: {err:?}"
            );
        }
    }

    #[test]
    fn tls_mode_decisions() {
        assert_eq!(
            tls_mode_for(None, None, None, false).expect("default"),
            TlsMode::UtlsChrome
        );
        assert_eq!(
            tls_mode_for(Some(true), Some("chrome"), Some("utls"), false).expect("chrome"),
            TlsMode::UtlsChrome
        );
        assert!(tls_mode_for(Some(true), Some("firefox"), None, false).is_err());
        assert!(tls_mode_for(Some(true), Some("chrome"), Some("stdlib"), false).is_err());
        assert!(tls_mode_for(Some(true), Some("chrome"), Some("cronet"), false).is_err());
        assert!(tls_mode_for(Some(false), Some("chrome"), None, false).is_err());
        assert!(tls_mode_for(Some(true), Some("chrome"), None, true).is_err());
    }

    #[test]
    fn reality_validation() {
        // 32 zero bytes as base64url (43 chars + '=').
        let key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        assert_eq!(decode_base64url(key).expect("key decodes").len(), 32);
        assert!(validate_reality(Some(key), Some("0123abcd")).is_ok());
        assert!(validate_reality(Some(key), Some("0123abc")).is_err()); // odd hex
        assert!(validate_reality(Some(key), Some("0123456789abcdef01")).is_err()); // >8 bytes
        assert!(validate_reality(Some("AAAA"), None).is_err()); // not 32 bytes
        assert!(validate_reality(None, Some("01")).is_err()); // sid without key
        assert!(validate_reality(None, None).is_ok());
    }

    #[test]
    fn tls_presence_block_vs_field() {
        // A `utls` block PRESENT but without an `enabled` field
        // means the plain-bool field defaults to false, i.e.
        // explicitly disabled → fail-closed Unsupported. It must
        // NOT silently take the block-absent (nil → chrome)
        // default.
        let err = dispatch_outbound(
            &json(r#"{"type":"trojan","server":"127.0.0.1","server_port":443,"password":"pw","tls":{"enabled":true,"server_name":"example.com","utls":{"fingerprint":"chrome"}}}"#),
            None,
        )
        .expect_err("present utls block without enabled must fail closed");
        assert!(matches!(err, TransportError::Unsupported { .. }));
        // A `utls` block ABSENT takes the default (chrome).
        let d = dispatch_outbound(
            &json(r#"{"type":"trojan","server":"127.0.0.1","server_port":443,"password":"pw","tls":{"enabled":true,"server_name":"example.com"}}"#),
            None,
        )
        .expect("absent utls block must take the default");
        assert!(matches!(d, Dispatch::Honk(_)));
        // A `reality` block PRESENT but without `enabled` means
        // REALITY off: the node carries no reality key.
        let key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let d = dispatch_outbound(
            &json(&format!(r#"{{"type":"trojan","server":"127.0.0.1","server_port":443,"password":"pw","tls":{{"enabled":true,"server_name":"example.com","utls":{{"enabled":true,"fingerprint":"chrome"}},"reality":{{"public_key":"{key}","short_id":"0123abcd"}}}}}}"#)),
            None,
        )
        .expect("reality without enabled dispatches");
        if let Dispatch::Honk(node) = d {
            assert_eq!(
                node.tls().expect("trojan has tls").reality_public_key,
                None,
                "reality without enabled must not set a key"
            );
        } else {
            panic!("expected Honk");
        }
        // TLS disabled + reality explicitly enabled: the node
        // still carries NO reality key (TLS off ⇒ REALITY off).
        let d = dispatch_outbound(
            &json(&format!(r#"{{"type":"trojan","server":"127.0.0.1","server_port":443,"password":"pw","tls":{{"enabled":false,"server_name":"example.com","utls":{{"enabled":true,"fingerprint":"chrome"}},"reality":{{"enabled":true,"public_key":"{key}","short_id":"0123abcd"}}}}}}"#)),
            None,
        )
        .expect("tls disabled dispatches");
        if let Dispatch::Honk(node) = d {
            let tls = node.tls().expect("trojan has tls");
            assert!(!tls.enabled);
            assert_eq!(
                tls.reality_public_key, None,
                "tls disabled must not set a reality key"
            );
        } else {
            panic!("expected Honk");
        }
        // Positive control: TLS on + reality on ⇒ key present.
        let d = dispatch_outbound(
            &json(&format!(r#"{{"type":"trojan","server":"127.0.0.1","server_port":443,"password":"pw","tls":{{"enabled":true,"server_name":"example.com","utls":{{"enabled":true,"fingerprint":"chrome"}},"reality":{{"enabled":true,"public_key":"{key}","short_id":"0123abcd"}}}}}}"#)),
            None,
        )
        .expect("reality enabled dispatches");
        if let Dispatch::Honk(node) = d {
            assert_eq!(
                node.tls()
                    .expect("trojan has tls")
                    .reality_public_key
                    .as_deref(),
                Some(key),
                "reality enabled must set the key"
            );
        } else {
            panic!("expected Honk");
        }
    }

    #[test]
    fn base64url_rejects_what_go_rejects() {
        // 2 zero bytes, trailing bits zero: valid.
        assert_eq!(decode_base64url("AAA").expect("AAA").len(), 2);
        // Non-zero trailing bits: Go rejects ("AAB" ends 01).
        assert!(decode_base64url("AAB").is_err());
        // Data length ≡ 1 mod 4: Go rejects.
        assert!(decode_base64url("A").is_err());
        // Whitespace anywhere: Go rejects space/tab; this
        // decoder additionally rejects \n (fail-closed — a real
        // key never contains any whitespace).
        assert!(decode_base64url("AA AA").is_err());
        assert!(decode_base64url("AA\tAA").is_err());
        assert!(decode_base64url("AA\nAA").is_err());
        // Data after padding: Go rejects.
        assert!(decode_base64url("AB=C").is_err());
        // Padding inconsistent with data length: Go rejects.
        assert!(decode_base64url("AAAA=").is_err());
    }

    #[test]
    fn ws_transport_pins_alpn_http11() {
        let d = dispatch_outbound(
            &json(r#"{"type":"trojan","server":"example.com","server_port":443,"password":"pw","transport":{"type":"ws","path":"/ws"},"tls":{"enabled":true,"server_name":"example.com","alpn":["h2","http/1.1"]}}"#),
            None,
        )
        .expect("trojan ws dispatch");
        if let Dispatch::Honk(node) = d {
            let tls = node.tls().expect("trojan has tls");
            assert_eq!(tls.alpn, vec!["http/1.1".to_string()]);
            assert_eq!(tls.sni.as_deref(), Some("example.com"));
        } else {
            panic!("expected Honk");
        }
    }

    #[test]
    fn vless_reality_node_and_ss_plugin_rejected() {
        let key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let d = dispatch_outbound(
            &json(&format!(r#"{{"type":"vless","server":"127.0.0.1","server_port":443,"uuid":"11111111-1111-1111-1111-111111111111","flow":"xtls-rprx-vision","tls":{{"enabled":true,"server_name":"example.com","utls":{{"enabled":true,"fingerprint":"chrome"}},"reality":{{"enabled":true,"public_key":"{key}","short_id":"0123abcd"}}}}}}"#)),
            None,
        )
        .expect("vless reality dispatch");
        assert!(matches!(d, Dispatch::Honk(_)));
        let err = dispatch_outbound(
            &json(r#"{"type":"shadowsocks","server":"127.0.0.1","server_port":8388,"method":"aes-256-gcm","password":"pw","plugin":"v2ray-plugin"}"#),
            None,
        )
        .expect_err("SS plugin must fail closed");
        assert!(matches!(err, TransportError::Unsupported { .. }));
    }

    #[test]
    fn dispatch_debug_never_prints_passwords() {
        let d = dispatch_outbound(
            &json(r#"{"type":"trojan","server":"example.com","server_port":443,"password":"SECRET-PW-123"}"#),
            None,
        )
        .expect("trojan dispatch");
        assert!(!format!("{d:?}").contains("SECRET-PW-123"));
    }

    /// M3e: `tls.insecure` maps to `quic.tls.skip_cert_verify` on the
    /// QUIC outbounds (hysteria2/tuic), and `tls.server_name` maps to
    /// `quic.tls.sni` — honk's hysteria2/tuic dial paths take the QUIC
    /// TLS server name from `quic.tls.sni` falling back to the node
    /// host (`honk-outbound/src/proxy/hysteria2/mod.rs:606-610`,
    /// `proxy/tuic.rs:457-462`), so leaving `sni` unset would silently
    /// drop the configured server name. `quic.tls.alpn` stays empty:
    /// honk's QUIC client config rejects a non-empty `tls.alpn`
    /// (`honk-outbound/src/quic.rs:348-353`).
    /// RED before the fix: both arms build `quic: Default::default()`,
    /// so `skip_cert_verify` is always false and `sni` always `None`.
    /// Fix-loop round 1 (F1): `skip_cert_verify` is gated on
    /// `tls.enabled` in the two QUIC arms — `enabled:false` +
    /// `insecure:true` stays false.
    #[test]
    fn quic_insecure_maps_to_skip_cert_verify() {
        // hysteria2, insecure:true -> skip true, sni = server_name.
        let d = dispatch_outbound(
            &json(r#"{"type":"hysteria2","server":"127.0.0.1","server_port":18900,"password":"pw","tls":{"enabled":true,"server_name":"localhost","insecure":true}}"#),
            None,
        )
        .expect("hysteria2 insecure dispatch");
        if let Dispatch::Honk(node) = d {
            let tls = node.tls().expect("hysteria2 has quic tls");
            assert!(
                tls.skip_cert_verify,
                "insecure:true must set skip_cert_verify"
            );
            assert_eq!(tls.sni.as_deref(), Some("localhost"));
            assert!(tls.alpn.is_empty(), "quic tls alpn must stay empty");
        } else {
            panic!("expected Honk");
        }
        // hysteria2, insecure absent -> fail-closed (skip false).
        let d = dispatch_outbound(
            &json(r#"{"type":"hysteria2","server":"127.0.0.1","server_port":18900,"password":"pw","tls":{"enabled":true,"server_name":"localhost"}}"#),
            None,
        )
        .expect("hysteria2 plain dispatch");
        if let Dispatch::Honk(node) = d {
            let tls = node.tls().expect("hysteria2 has quic tls");
            assert!(!tls.skip_cert_verify, "absent insecure must stay false");
            assert_eq!(tls.sni.as_deref(), Some("localhost"));
        } else {
            panic!("expected Honk");
        }
        // hysteria2, insecure:false -> skip false.
        let d = dispatch_outbound(
            &json(r#"{"type":"hysteria2","server":"127.0.0.1","server_port":18900,"password":"pw","tls":{"enabled":true,"server_name":"localhost","insecure":false}}"#),
            None,
        )
        .expect("hysteria2 insecure:false dispatch");
        if let Dispatch::Honk(node) = d {
            assert!(!node.tls().expect("hysteria2 has quic tls").skip_cert_verify);
        } else {
            panic!("expected Honk");
        }
        // hysteria2, enabled:false + insecure:true -> skip stays
        // false (F1 fix-loop round 1 regression case): the gate is
        // on `tls.enabled`, so an explicit insecure:true on a
        // disabled tls block must NOT skip verification. This case
        // FAILS on the pre-fix code (skip was true there).
        let d = dispatch_outbound(
            &json(r#"{"type":"hysteria2","server":"127.0.0.1","server_port":18900,"password":"pw","tls":{"enabled":false,"server_name":"localhost","insecure":true}}"#),
            None,
        )
        .expect("hysteria2 disabled+insecure dispatch");
        if let Dispatch::Honk(node) = d {
            assert!(
                !node.tls().expect("hysteria2 has quic tls").skip_cert_verify,
                "enabled:false + insecure:true must stay false"
            );
        } else {
            panic!("expected Honk");
        }
        // hysteria2, enabled:false + insecure absent -> skip false.
        let d = dispatch_outbound(
            &json(r#"{"type":"hysteria2","server":"127.0.0.1","server_port":18900,"password":"pw","tls":{"enabled":false,"server_name":"localhost"}}"#),
            None,
        )
        .expect("hysteria2 disabled dispatch");
        if let Dispatch::Honk(node) = d {
            assert!(!node.tls().expect("hysteria2 has quic tls").skip_cert_verify);
        } else {
            panic!("expected Honk");
        }
        // hysteria2, no tls block at all -> skip false; sni is None
        // (`build_tls` returns `TlsOptions::default()` when the tls
        // object is absent, so no server-name default is applied).
        // That is still correct at the honk layer: the hysteria2
        // dial path falls back to the node host when `quic.tls.sni`
        // is None (`honk-outbound/src/proxy/hysteria2/mod.rs:606-610`).
        let d = dispatch_outbound(
            &json(
                r#"{"type":"hysteria2","server":"127.0.0.1","server_port":18900,"password":"pw"}"#,
            ),
            None,
        )
        .expect("hysteria2 no-tls dispatch");
        if let Dispatch::Honk(node) = d {
            let tls = node.tls().expect("hysteria2 has quic tls");
            assert!(!tls.skip_cert_verify);
            assert_eq!(tls.sni.as_deref(), None);
        } else {
            panic!("expected Honk");
        }
        // hysteria2, tls.alpn set -> quic tls alpn still empty (honk rejects it).
        let d = dispatch_outbound(
            &json(r#"{"type":"hysteria2","server":"127.0.0.1","server_port":18900,"password":"pw","tls":{"enabled":true,"server_name":"localhost","insecure":true,"alpn":["h3"]}}"#),
            None,
        )
        .expect("hysteria2 alpn dispatch");
        if let Dispatch::Honk(node) = d {
            let tls = node.tls().expect("hysteria2 has quic tls");
            assert!(tls.skip_cert_verify);
            assert!(tls.alpn.is_empty(), "quic tls alpn must stay empty");
        } else {
            panic!("expected Honk");
        }
        // tuic, insecure:true -> skip true, sni = server_name.
        let d = dispatch_outbound(
            &json(r#"{"type":"tuic","server":"127.0.0.1","server_port":18900,"uuid":"11111111-1111-1111-1111-111111111111","password":"pw","tls":{"enabled":true,"server_name":"localhost","insecure":true}}"#),
            None,
        )
        .expect("tuic insecure dispatch");
        if let Dispatch::Honk(node) = d {
            let tls = node.tls().expect("tuic has quic tls");
            assert!(
                tls.skip_cert_verify,
                "tuic insecure:true must set skip_cert_verify"
            );
            assert_eq!(tls.sni.as_deref(), Some("localhost"));
            assert!(tls.alpn.is_empty(), "quic tls alpn must stay empty");
        } else {
            panic!("expected Honk");
        }
        // tuic, insecure absent -> fail-closed.
        let d = dispatch_outbound(
            &json(r#"{"type":"tuic","server":"127.0.0.1","server_port":18900,"uuid":"11111111-1111-1111-1111-111111111111","password":"pw","tls":{"enabled":true,"server_name":"localhost"}}"#),
            None,
        )
        .expect("tuic plain dispatch");
        if let Dispatch::Honk(node) = d {
            assert!(!node.tls().expect("tuic has quic tls").skip_cert_verify);
        } else {
            panic!("expected Honk");
        }
    }

    // (c) system:true rejected via `dispatch_endpoint` with the
    // exact Go runtime text (`internal/outbound/manager.go:486-488`).
    // Fake keys: 32 bytes of 0x01 / 0x02, never real key material.
    #[test]
    fn fake_dispatch_endpoint_system_true_rejected() {
        let err = dispatch_endpoint(
            &json(r#"{"type":"wireguard","tag":"wg-fake","system":true,"private_key":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=","address":["10.0.0.2/32"],"peers":[{"public_key":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=","address":"127.0.0.1","port":51820,"allowed_ips":["0.0.0.0/0"]}]}"#),
            &[],
        )
        .expect_err("system:true must fail");
        assert!(matches!(err, TransportError::Unsupported { .. }));
        assert!(
            format!("{err}").contains(
                "outbound: wireguard endpoint with system:true is rejected: userspace WireGuard only"
            ),
            "got {err}"
        );
    }

    #[test]
    fn fake_dispatch_endpoint_wg_quick_spelling_rejected() {
        let err = dispatch_endpoint(
            &json(r#"{"type":"wireguard","tag":"wg-fake","private_key":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=","address":["10.0.0.2/32"],"peers":[{"public_key":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=","address":"127.0.0.1","port":51820,"allowed_ips":["0.0.0.0/0"],"preshared_key":"AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM="}]}"#),
            &[],
        )
        .expect_err("wg-quick spelling must fail");
        assert!(matches!(err, TransportError::Validation { .. }));
        assert!(format!("{err}").contains("did you mean \"pre_shared_key\""));
    }

    #[test]
    fn fake_dispatch_endpoint_debug_never_prints_fake_keys() {
        let d = dispatch_endpoint(
            &json(r#"{"type":"wireguard","tag":"wg-fake","private_key":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=","address":["10.0.0.2/32"],"peers":[{"public_key":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=","address":"127.0.0.1","port":51820,"allowed_ips":["0.0.0.0/0"],"pre_shared_key":"AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM="}]}"#),
            &[],
        )
        .expect("fake endpoint dispatches");
        let text = format!("{d:?}");
        assert!(!text.contains("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="));
        assert!(!text.contains("AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM="));
        assert!(text.contains("wg-fake"));
    }
}
