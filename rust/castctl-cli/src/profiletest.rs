// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! `profile test`: the four phases (DNS / HTTPS / egress /
//! gateway) over the profile's runtime.
//!
//! Go sources: `internal/commands/profilecmd.go`
//! (`cmdProfileTest`, `finishProfileTest`,
//! `phaseExitCode`, `fetchEgressIP`,
//! `classifyEgressTransportError`, `redactMessage`),
//! `internal/commands/runtime.go` (`detourChain`,
//! `identityForProfile`, `defaultBuildRuntime` DNS
//! registration) and `internal/profile/dns.go`
//! (`ResolveProfileDNS`).
//!
//! How the phases map onto the Rust crates:
//!
//! * DNS: there is no `Runtime::resolve` (M3 deviation:
//!   the dialer uses the system resolver, no DNS router),
//!   so the phase resolves the effective DNS itself
//!   (`resolve_profile_dns`) and queries the chosen
//!   server directly: DoH (`https`) via the dialer's
//!   `HttpClient`, plain TCP (`tcp`) via the dialer, the
//!   system resolver for `local` (matching sing-box's
//!   local server), and nothing for `udp`/`tls`/
//!   `hosts`/`fakeip` — those are BLOCKED, never faked
//!   (the Dialer trait is TCP-only; there is no UDP
//!   dialer and no raw-TLS-stream seam). A server whose
//!   detour names another outbound gets a dialer built
//!   for that tag; the profile's own outbound (or its
//!   synthesised direct tag) reuses the runtime dialer.
//!   With no config file (`single == None`) Go builds
//!   no DNS client at all, so the phase resolves through
//!   the system resolver and reports no server/source.
//! * HTTPS: `FetchSessionInfo` over the runtime HTTP
//!   client; a missing/unparseable cookies file
//!   substitutes as the phase error (typed auth →
//!   exit 3), with no network call.
//! * Egress: `GET https://api64.ipify.org` through the
//!   same outbound; a failure is a warning, never fatal.
//! * Gateway: a fresh `GatewayConnector` connect (auth
//!   chain + WebSocket + Noise) then immediate close, no
//!   chat send. The profile's `node_id` is NOT passed:
//!   the gateway crate takes no node_id (its own
//!   behaviour), so Go's temporary-id substitution for
//!   a missing node_id has no Rust equivalent —
//!   [DEVIATION], recorded in the M7d report.
//!
//! The result JSON is built with the ordered encoder
//! (`writeJSON`, HTML unescaped); `egress_ip` is always
//! present (null when absent), `errors` is always an
//! array (possibly empty), `warnings`/`dns`/`https`/
//! `gateway` are omitted when empty/absent.
//!
//! No `unsafe`, no `unwrap()`/`expect()` on external input.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use castctl_config::config::{SingleConfig, load_profile, profile_exists};
use castctl_config::dnsvalidate::{
    DnsServer, DnsSource, ResolvedDns, detour_chain, outbound_identity_for_config,
    resolve_profile_dns,
};
use castctl_config::errors::ConfigError;
use castctl_config::gostr::go_quote;
use castctl_config::jsonvalue::{JsonValue, OrderedObject, encode_ordered_json};
use castctl_config::profile::{OutboundKind, Profile, synthesized_direct_tag};
use castctl_dns::wire::{QTYPE_A, QTYPE_AAAA, decode_message, encode_query};
use castctl_gateway::GATEWAY_USER_AGENT;
use castctl_gateway::auth::fetch_session_info;
use castctl_gateway::connector::GatewayConnector;
use castctl_transport::{DialTarget, Dialer, HttpClient, TransportError};
use http::Method;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::network::{summarize_transport_error, write_json_text};
use crate::parser::Parsed;
use crate::profilecmd::{explicit_profile_selected, load_single_validated, resolve_active};
use crate::run::{Ctx, FlowErr, GlobalOpts, config_err, msg, msg_empty, resolve_config};
use crate::runtime::{CookiesFailure, Runtime, build_runtime, dialer_for_tag};

/// `profileTestTimeouts` (`profilecmd.go`): the DNS
/// resolver's own 5s bound sits inside the DNS phase
/// bound.
const DNS_TIMEOUT: Duration = Duration::from_secs(10);
const DNS_QUERY_TIMEOUT: Duration = Duration::from_secs(5);
const HTTPS_TIMEOUT: Duration = Duration::from_secs(30);
const EGRESS_TIMEOUT: Duration = Duration::from_secs(15);
const NOISE_TIMEOUT: Duration = Duration::from_secs(60);

/// The recorded-only caveat carried by every result
/// (`profileTestNote`).
const TEST_NOTE: &str = "recorded-only: fingerprint and user_agent are stored values; the runtime always uses uTLS chrome until the TLS engine decision lands";

/// One phase failure: the redacted error text for the
/// JSON result and the `phaseExitCode` for the process.
struct PhaseError {
    text: String,
    code: i32,
}

fn phase_err(text: String, code: i32) -> PhaseError {
    PhaseError { text, code }
}

/// `phaseExitCode` (`profilecmd.go`): 4 timeout, 2
/// config, 3 gateway. Typed auth failures are gateway
/// failures (3) here: the phase reached the network.
fn phase_exit_code_transport(err: &TransportError) -> i32 {
    match err {
        TransportError::Timeout { .. } => 4,
        TransportError::Auth { .. } => 3,
        TransportError::Gateway(_) => 3,
        TransportError::Cancelled => 3,
        _ => 3,
    }
}

fn phase_exit_code_config(err: &ConfigError) -> i32 {
    err.code
}

fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    format!("{:x}", h.finalize())
}

/// `identityForProfile` (`runtime.go:167`): with a
/// single config, the tag + hash of the resolved stored
/// object (`OutboundIdentityForConfig`); without one,
/// the profile-only identity (`OutboundIdentity`).
/// The hash is NOT printed by `profile test` — only the
/// tag is — so its exact bytes are unobservable here;
/// the error cases are what matter (a missing profile
/// in the single file is exit 2, no JSON).
fn identity_for_profile(
    prof: &Profile,
    single: Option<&SingleConfig>,
) -> Result<(String, String), FlowErr> {
    match single {
        Some(cfg) => outbound_identity_for_config(cfg, &prof.name).map_err(config_err),
        None => match prof.outbound.kind {
            OutboundKind::Direct => Ok((
                "direct".to_string(),
                sha256_hex(br#"{"type":"direct","tag":"direct"}"#),
            )),
            OutboundKind::Inline => {
                if prof.outbound.tag.is_empty() {
                    return Err(config_err(castctl_config::config_error(format!(
                        "profile {}: inline outbound has no tag",
                        go_quote(&prof.name)
                    ))));
                }
                let Some(raw) = &prof.outbound.raw else {
                    return Err(msg(
                        1,
                        "inline outbound has neither raw json nor a parsed value",
                    ));
                };
                let bytes = encode_ordered_json(raw).map_err(config_err)?;
                Ok((prof.outbound.tag.clone(), sha256_hex(bytes.as_bytes())))
            }
            OutboundKind::Tag => {
                if prof.outbound.tag.is_empty() {
                    return Err(config_err(castctl_config::config_error(format!(
                        "profile {}: outbound tag reference is empty",
                        go_quote(&prof.name)
                    ))));
                }
                // Go `OutboundIdentity` for a tag hashes the
                // fixed shape {"kind":"tag","tag":..,"type":..}
                // (struct field order, encoding/json escaping).
                // Tag/type are validated charset, so no
                // escaping applies.
                let shape = format!(
                    "{{\"kind\":\"tag\",\"tag\":\"{}\",\"type\":\"{}\"}}",
                    prof.outbound.tag, prof.outbound.typ
                );
                Ok((prof.outbound.tag.clone(), sha256_hex(shape.as_bytes())))
            }
        },
    }
}

/// `outboundTypeOf` (`profilecmd.go`).
fn outbound_type_of(prof: &Profile) -> String {
    if !prof.outbound.typ.is_empty() {
        return prof.outbound.typ.clone();
    }
    if prof.outbound.kind == OutboundKind::Direct {
        return "direct".to_string();
    }
    String::new()
}

fn json_str(s: &str) -> JsonValue {
    JsonValue::Str(s.to_string())
}

fn json_num(n: i64) -> JsonValue {
    JsonValue::Number(n.to_string())
}

/// One phase's JSON block, built in Go struct field order.
struct DnsPhase {
    ok: bool,
    ms: i64,
    server: Option<String>,
    source: Option<String>,
    addresses: Vec<String>,
    error: Option<String>,
}

struct HttpsPhase {
    ok: bool,
    ms: i64,
    status: Option<u16>,
    error: Option<String>,
}

struct GatewayPhase {
    ok: bool,
    handshake_ms: i64,
    tls: Option<String>,
    error: Option<String>,
}

/// The accumulated `profileTestResult`
/// (`profilecmd.go`): field order is the struct order.
struct TestResult {
    profile: String,
    outbound_type: String,
    outbound_tag: String,
    detour_chain: Vec<String>,
    fingerprint: String,
    user_agent: String,
    note: String,
    dns: Option<DnsPhase>,
    https: Option<HttpsPhase>,
    egress_ip: Option<String>,
    egress_warning: Option<String>,
    gateway: Option<GatewayPhase>,
    ok: bool,
    errors: Vec<String>,
    warnings: Vec<String>,
}

impl TestResult {
    /// Test-only constructor (the production path builds
    /// `TestResult` field-by-field in `run_test`).
    #[cfg(test)]
    fn new(profile: &str, outbound_type: &str, outbound_tag: &str) -> Self {
        Self {
            profile: profile.to_string(),
            outbound_type: outbound_type.to_string(),
            outbound_tag: outbound_tag.to_string(),
            detour_chain: Vec::new(),
            fingerprint: "chrome".to_string(),
            user_agent: GATEWAY_USER_AGENT.to_string(),
            note: TEST_NOTE.to_string(),
            dns: None,
            https: None,
            egress_ip: None,
            egress_warning: None,
            gateway: None,
            ok: false,
            errors: Vec::new(),
            warnings: Vec::new(),
        }
    }

    fn render(&self) -> Result<String, FlowErr> {
        let mut outbound = OrderedObject::new();
        outbound.set("type", json_str(&self.outbound_type));
        outbound.set("tag", json_str(&self.outbound_tag));
        outbound.set(
            "detour_chain",
            JsonValue::Array(self.detour_chain.iter().map(|s| json_str(s)).collect()),
        );
        let mut top = OrderedObject::new();
        top.set("profile", json_str(&self.profile));
        top.set("outbound", JsonValue::Object(outbound));
        top.set("fingerprint", json_str(&self.fingerprint));
        top.set("user_agent", json_str(&self.user_agent));
        top.set("note", json_str(&self.note));
        if let Some(dns) = &self.dns {
            let mut o = OrderedObject::new();
            o.set("ok", JsonValue::Bool(dns.ok));
            o.set("ms", json_num(dns.ms));
            if let Some(s) = &dns.server {
                o.set("server", json_str(s));
            }
            if let Some(s) = &dns.source {
                o.set("source", json_str(s));
            }
            if !dns.addresses.is_empty() {
                o.set(
                    "addresses",
                    JsonValue::Array(dns.addresses.iter().map(|s| json_str(s)).collect()),
                );
            }
            if let Some(e) = &dns.error {
                o.set("error", json_str(e));
            }
            top.set("dns", JsonValue::Object(o));
        }
        if let Some(https) = &self.https {
            let mut o = OrderedObject::new();
            o.set("ok", JsonValue::Bool(https.ok));
            o.set("ms", json_num(https.ms));
            if let Some(s) = &https.status {
                o.set("status", json_num(i64::from(*s)));
            }
            if let Some(e) = &https.error {
                o.set("error", json_str(e));
            }
            top.set("https", JsonValue::Object(o));
        }
        match &self.egress_ip {
            Some(ip) => top.set("egress_ip", json_str(ip)),
            None => top.set("egress_ip", JsonValue::Null),
        }
        if let Some(w) = &self.egress_warning {
            top.set("egress_warning", json_str(w));
        }
        if let Some(gw) = &self.gateway {
            let mut o = OrderedObject::new();
            o.set("ok", JsonValue::Bool(gw.ok));
            o.set("handshake_ms", json_num(gw.handshake_ms));
            if let Some(t) = &gw.tls {
                o.set("tls", json_str(t));
            }
            if let Some(e) = &gw.error {
                o.set("error", json_str(e));
            }
            top.set("gateway", JsonValue::Object(o));
        }
        top.set("ok", JsonValue::Bool(self.ok));
        top.set(
            "errors",
            JsonValue::Array(self.errors.iter().map(|s| json_str(s)).collect()),
        );
        if !self.warnings.is_empty() {
            top.set(
                "warnings",
                JsonValue::Array(self.warnings.iter().map(|s| json_str(s)).collect()),
            );
        }
        let compact = encode_ordered_json(&JsonValue::Object(top)).map_err(config_err)?;
        Ok(write_json_text(&compact))
    }
}

/// `finishProfileTest` (`profilecmd.go`): print the
/// result JSON, then exit `code` with no stderr text.
fn finish(ctx: &mut Ctx<'_>, result: &TestResult, code: i32) -> Result<(), FlowErr> {
    let text = result.render()?;
    ctx.out.stdout.push_str(&text);
    if code != 0 {
        return Err(msg_empty(code));
    }
    Ok(())
}

/// The FlowErr code of a runtime-build failure, for the
/// `finishProfileTest` exit code (`classifyError` in Go).
fn flow_code(e: &FlowErr) -> i32 {
    match e {
        FlowErr::Msg { code, .. } => *code,
        FlowErr::Verbatim { code, .. } => *code,
        FlowErr::Exit(code) => *code,
        FlowErr::HelpShown => 0,
    }
}

/// The redacted text of a runtime-build failure, for the
/// JSON `errors` entry (`redactMessage` in Go: the
/// `FlowErr` message itself — a config/dispatch message
/// passes through `SafeString` verbatim).
fn flow_message(e: &FlowErr) -> String {
    match e {
        FlowErr::Msg { message, .. } => message.clone().unwrap_or_default(),
        FlowErr::Verbatim { text, .. } => text.clone(),
        FlowErr::Exit(_) => String::new(),
        FlowErr::HelpShown => String::new(),
    }
}

/// `cmdProfileTest` (`profilecmd.go:716`): the sync
/// prelude (resolve, existence gate, identity, detour
/// chain, node_id warning, runtime build) runs on the
/// calling thread; the four phases run on a fresh tokio
/// runtime, like `serve_webui` does.
pub(crate) fn run_test(ctx: &mut Ctx<'_>, g: &GlobalOpts, p: &Parsed) -> Result<(), FlowErr> {
    let loc = resolve_config(ctx, g, false)?;
    let active = resolve_active(ctx, g, &loc)?;
    let (name, explicit) = match p.positionals.first() {
        Some(n) => (n.clone(), true),
        None => (active.name.clone(), false),
    };
    let single = load_single_validated(&loc.config_dir)?;
    // Fail fast on an explicitly named profile that does
    // not exist, before LoadProfile can synthesise a
    // SourceNone default and the phases run against it.
    if explicit_profile_selected(ctx, g, explicit)
        && !profile_exists(&loc.config_dir, &name, single.as_ref())
    {
        return Err(msg(
            2,
            format!("profile {} does not exist", go_quote(&name)),
        ));
    }
    let prof = load_profile(&loc.config_dir, &name, ctx.getenv).map_err(config_err)?;
    let mut result = TestResult {
        profile: prof.name.clone(),
        outbound_type: String::new(),
        outbound_tag: String::new(),
        detour_chain: Vec::new(),
        fingerprint: prof.fingerprint.clone(),
        user_agent: GATEWAY_USER_AGENT.to_string(),
        note: TEST_NOTE.to_string(),
        dns: None,
        https: None,
        egress_ip: None,
        egress_warning: None,
        gateway: None,
        ok: false,
        errors: Vec::new(),
        warnings: Vec::new(),
    };
    // The identity failure returns the error directly:
    // no JSON is printed (`return err`, not
    // `finishProfileTest`).
    let (tag, _hash) = identity_for_profile(&prof, single.as_ref())?;
    result.outbound_type = outbound_type_of(&prof);
    result.outbound_tag = tag.clone();
    result.detour_chain = detour_chain(single.as_ref(), &tag);
    if prof.node_id.is_empty() {
        result.warnings.push(
            "node_id missing; using a temporary in-memory value for this test only (nothing written)"
                .to_string(),
        );
    }
    // Resolve the effective DNS BEFORE the runtime build:
    // Go resolves it inside `defaultBuildRuntime` (before
    // dispatch), prints a shadowing/deprecation warning
    // to stderr when present, and fails the build (exit 2,
    // JSON with the error, no phase) on a resolve error.
    // The resolved value is reused by the DNS phase.
    let resolved_dns: Option<ResolvedDns> = match single.as_ref() {
        Some(_) => match resolve_profile_dns(&prof, single.as_ref()) {
            Ok(resolved) => {
                if !resolved.warning.is_empty() {
                    ctx.out.stderr.push_str(&resolved.warning);
                    ctx.out.stderr.push('\n');
                }
                Some(resolved)
            }
            Err(e) => {
                result.errors.push(e.message.clone());
                let code = phase_exit_code_config(&e);
                return finish(ctx, &result, code);
            }
        },
        None => None,
    };
    let rt = match build_runtime(&loc, single.as_ref(), Some(&name), ctx.getenv) {
        Ok(rt) => rt,
        Err(e) => {
            // Build failure: config (2) or gateway (3) by
            // the error's own classification; the result
            // carries the failure and no phase ran. The
            // error text is reported only inside the JSON
            // result, not a second time on stderr.
            result.errors.push(flow_message(&e));
            let code = flow_code(&e);
            return finish(ctx, &result, code);
        }
    };
    let tokio_rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| msg(1, format!("failed to start async runtime: {e}")))?;
    let (result, code) = tokio_rt.block_on(run_phases(rt, single, resolved_dns, result));
    finish(ctx, &result, code)
}

/// The four phases, in Go order, stopping at the first
/// fatal failure (`cmdProfileTest`). The egress phase is
/// the only non-fatal one.
async fn run_phases(
    rt: Runtime,
    single: Option<SingleConfig>,
    resolved_dns: Option<ResolvedDns>,
    mut result: TestResult,
) -> (TestResult, i32) {
    // Phase 1: DNS via the outbound.
    let start = Instant::now();
    let mut dns = DnsPhase {
        ok: false,
        ms: 0,
        server: None,
        source: None,
        addresses: Vec::new(),
        error: None,
    };
    match dns_lookup(&rt, single.as_ref(), resolved_dns.as_ref()).await {
        Ok((addrs, server, source)) => {
            dns.ms = start.elapsed().as_millis() as i64;
            dns.ok = true;
            dns.addresses = addrs;
            dns.server = server;
            dns.source = source;
        }
        Err(e) => {
            dns.ms = start.elapsed().as_millis() as i64;
            dns.error = Some(e.text.clone());
            result.dns = Some(dns);
            result.errors.push(e.text);
            return (result, e.code);
        }
    }
    result.dns = Some(dns);

    // Phase 2: TLS + GET https://muse.ai/api/session.
    let (https, https_err) = https_phase(&rt).await;
    result.https = Some(https);
    if let Some(e) = https_err {
        result.errors.push(e.text);
        return (result, e.code);
    }

    // Phase 3: egress IP through the same outbound. A
    // failure reports null + warning and is NOT fatal.
    match egress_phase(&rt).await {
        Ok(ip) => result.egress_ip = Some(ip),
        Err(w) => result.egress_warning = Some(w),
    }

    // Phase 4: Noise handshake, then immediate close. No
    // chat send, no session creation, no file writes.
    let (gw, gw_err) = gateway_phase(&rt).await;
    result.gateway = Some(gw);
    if let Some(e) = gw_err {
        result.errors.push(e.text);
        return (result, e.code);
    }

    result.ok = true;
    (result, 0)
}

/// Phase 1: resolve `muse.ai` and report the effective
/// server/source (only when a single config exists —
/// Go sets them only under `single != nil`). With no
/// config file Go builds no DNS client, so the lookup
/// goes through the system resolver.
async fn dns_lookup(
    rt: &Runtime,
    single: Option<&SingleConfig>,
    resolved: Option<&ResolvedDns>,
) -> Result<(Vec<String>, Option<String>, Option<String>), PhaseError> {
    let (addrs, server, source) = match resolved {
        None => {
            let addrs = system_lookup("muse.ai").await?;
            (addrs, None, None)
        }
        Some(resolved) => {
            if resolved.servers.is_empty() {
                return Err(phase_err(
                    format!(
                        "profile {}: no dns servers configured",
                        go_quote(&rt.profile.name)
                    ),
                    2,
                ));
            }
            let server = pick_server(resolved, &rt.profile, single);
            let addrs = lookup_via_server(rt, single, server).await?;
            let reported_server = resolved.servers.first().map(|s| s.tag.clone());
            let reported_source = Some(resolved.source.as_str().to_string());
            (addrs, reported_server, reported_source)
        }
    };
    if addrs.is_empty() {
        return Err(phase_err("lookup muse.ai: no such host".to_string(), 3));
    }
    Ok((addrs, server, source))
}

/// Pick the server that resolves `muse.ai`: the first
/// matching route/evaluate rule's server, else the
/// final server. The REPORTED server is always
/// `servers[0]` (see `dns_lookup`); this only chooses
/// which server is queried.
fn pick_server<'a>(
    resolved: &'a ResolvedDns,
    prof: &Profile,
    single: Option<&SingleConfig>,
) -> &'a DnsServer {
    let raw = match resolved.source {
        DnsSource::Profile => prof.dns.as_ref(),
        DnsSource::GlobalCompat => single.and_then(|s| s.dns_raw.as_ref()),
        _ => None,
    };
    if let Some(raw) = raw
        && let Some(tag) = rule_server_for_domain(raw, "muse.ai")
        && let Some(s) = resolved.servers.iter().find(|s| s.tag == tag)
    {
        return s;
    }
    match resolved
        .servers
        .iter()
        .find(|s| s.tag == resolved.final_tag)
    {
        Some(s) => s,
        None => &resolved.servers[0],
    }
}

/// The first rule in a DNS block whose server resolves
/// `domain`. Only route/evaluate rules name a server (a
/// missing `action` with a `server` field is a route,
/// the sing-box default). A rule matches only when every
/// matcher on it is an evaluable domain matcher
/// (`domain` / `domain_suffix` / `domain_keyword`) and
/// all of them match (AND); any other matcher
/// (`domain_regex`, `geosite`, `ip_cidr`, `port`, ...)
/// makes the rule unevaluable here, so it is skipped and
/// the final server answers instead. This is a bounded
/// port of sing-box's rule evaluation: rules that only
/// use the domain family are exact; the rest fall
/// through to final rather than guessing.
fn rule_server_for_domain(raw: &JsonValue, domain: &str) -> Option<String> {
    let JsonValue::Object(obj) = raw else {
        return None;
    };
    let JsonValue::Array(rules) = obj.get("rules")? else {
        return None;
    };
    let domain_lower = domain.to_ascii_lowercase();
    for rule in rules {
        let JsonValue::Object(rule) = rule else {
            continue;
        };
        if let Some(JsonValue::Str(action)) = rule.get("action")
            && action != "route"
            && action != "evaluate"
        {
            continue;
        }
        let Some(JsonValue::Str(server)) = rule.get("server") else {
            continue;
        };
        if server.is_empty() {
            continue;
        }
        if !rule_matchers_domain_only(rule) {
            continue;
        }
        let matched = rule_domain_matches(rule, &domain_lower);
        let invert = matches!(rule.get("invert"), Some(JsonValue::Bool(true)));
        if matched != invert {
            return Some(server.clone());
        }
    }
    None
}

/// Whether every key on the rule is one this port
/// evaluates: `action`, `server`, `invert`, and the
/// three domain matcher families.
fn rule_matchers_domain_only(rule: &OrderedObject) -> bool {
    rule.keys().iter().all(|k| {
        matches!(
            k.as_str(),
            "action" | "server" | "invert" | "domain" | "domain_suffix" | "domain_keyword"
        )
    })
}

/// Whether the rule's domain matchers match `domain`
/// (lowercase). A rule with no domain matchers is a
/// catch-all and matches everything; otherwise every
/// present family must have at least one matching entry
/// (AND across families, OR within a family).
fn rule_domain_matches(rule: &OrderedObject, domain: &str) -> bool {
    for key in ["domain", "domain_suffix", "domain_keyword"] {
        let Some(JsonValue::Array(entries)) = rule.get(key) else {
            continue;
        };
        let mut family_hit = false;
        for entry in entries {
            if let JsonValue::Str(s) = entry {
                let e = s.to_ascii_lowercase();
                let hit = match key {
                    "domain" => e == domain,
                    "domain_suffix" => domain == e || domain.ends_with(&format!(".{e}")),
                    _ => domain.contains(e.as_str()),
                };
                if hit {
                    family_hit = true;
                    break;
                }
            }
        }
        if !family_hit {
            return false;
        }
    }
    true
}

/// The dialer a DNS server's traffic goes through: the
/// runtime dialer when the detour is the profile's own
/// outbound (or its synthesised direct tag, or empty),
/// else a dialer built for the detour tag. A detour
/// dialer built lazily here fails as a phase error
/// (exit 3, like Go's lazy detour init), not as a
/// build-time dispatch failure.
fn dialer_for_dns_server(
    rt: &Runtime,
    single: Option<&SingleConfig>,
    server: &DnsServer,
) -> Result<Arc<dyn Dialer>, PhaseError> {
    let detour = server.detour.as_str();
    if detour.is_empty() {
        return Ok(Arc::clone(&rt.dialer));
    }
    let own = match rt.profile.outbound.kind {
        OutboundKind::Direct => synthesized_direct_tag(&rt.profile.name),
        _ => rt.profile.outbound.tag.clone(),
    };
    if detour == own {
        return Ok(Arc::clone(&rt.dialer));
    }
    let Some(single) = single else {
        return Err(phase_err(
            format!("outbound tag {detour:?} cannot resolve without a config file"),
            3,
        ));
    };
    dialer_for_tag(single, detour, Some(rt.profile.tls_engine.as_str()))
        .map_err(|e| phase_err(flow_message(&e), 3))
}

/// Query one server for `muse.ai` (A + AAAA), inside the
/// 10s phase bound. `udp`/`tls`/`hosts`/`fakeip` and
/// unknown types are BLOCKED, never faked.
async fn lookup_via_server(
    rt: &Runtime,
    single: Option<&SingleConfig>,
    server: &DnsServer,
) -> Result<Vec<String>, PhaseError> {
    let fut = async {
        match server.typ.as_str() {
            "https" => {
                let dialer = dialer_for_dns_server(rt, single, server)?;
                let mut addrs = doh_lookup(&dialer, server, QTYPE_A).await?;
                let mut aaaa = doh_lookup(&dialer, server, QTYPE_AAAA).await?;
                addrs.append(&mut aaaa);
                Ok(addrs)
            }
            "tcp" => {
                let dialer = dialer_for_dns_server(rt, single, server)?;
                let mut addrs = tcp_lookup(&dialer, server, QTYPE_A).await?;
                let mut aaaa = tcp_lookup(&dialer, server, QTYPE_AAAA).await?;
                addrs.append(&mut aaaa);
                Ok(addrs)
            }
            "local" => system_lookup("muse.ai").await,
            "udp" => Err(phase_err(
                format!(
                    "dns: udp server {} requires a UDP dialer (not implemented in this build)",
                    go_quote(&server.tag)
                ),
                3,
            )),
            "tls" => Err(phase_err(
                format!(
                    "dns: tls server {} requires a raw TLS stream (not implemented in this build)",
                    go_quote(&server.tag)
                ),
                3,
            )),
            "hosts" | "fakeip" => Err(phase_err(
                format!(
                    "dns: server {} of type {} answers from a static map, not the network (not implemented in this build)",
                    go_quote(&server.tag),
                    server.typ
                ),
                3,
            )),
            other => Err(phase_err(
                format!("dns: unsupported server type {}", go_quote(other)),
                3,
            )),
        }
    };
    match tokio::time::timeout(DNS_TIMEOUT, fut).await {
        Ok(r) => r,
        Err(_) => Err(phase_err("context deadline exceeded".to_string(), 4)),
    }
}

/// One DoH query through the detour dialer: POST
/// `application/dns-message` to the server's path.
async fn doh_lookup(
    dialer: &Arc<dyn Dialer>,
    server: &DnsServer,
    qtype: u16,
) -> Result<Vec<String>, PhaseError> {
    let id: u16 = rand::random();
    let query = encode_query(id, "muse.ai", qtype)
        .map_err(|e| phase_err(format!("dns: encode query: {e}"), 3))?;
    let client = HttpClient::new(Arc::clone(dialer));
    let target = DialTarget::new(&server.server, server.server_port);
    let path = if server.path.is_empty() {
        "/dns-query"
    } else {
        server.path.as_str()
    };
    let headers = [
        (
            "Content-Type".to_string(),
            "application/dns-message".to_string(),
        ),
        ("Accept".to_string(), "application/dns-message".to_string()),
    ];
    let resp = tokio::time::timeout(
        DNS_QUERY_TIMEOUT,
        client.request_tls(
            Method::POST,
            &target,
            path,
            &headers,
            Some(Bytes::from(query)),
            DNS_QUERY_TIMEOUT,
        ),
    )
    .await
    .map_err(|_| phase_err("context deadline exceeded".to_string(), 4))?
    .map_err(|e| {
        let code = phase_exit_code_transport(&e);
        phase_err(summarize_transport_error(&e), code)
    })?;
    if resp.status.as_u16() != 200 {
        return Err(phase_err(
            format!(
                "dns: doh server {} returned status {}",
                go_quote(&server.tag),
                resp.status.as_u16()
            ),
            3,
        ));
    }
    decode_response(&resp.body, id, qtype)
}

/// One plain-TCP DNS query through the detour dialer:
/// the 2-byte length-prefixed framing from
/// `castctl-dns`'s TCP transport, over the dialed
/// stream instead of a direct `TcpStream`.
async fn tcp_lookup(
    dialer: &Arc<dyn Dialer>,
    server: &DnsServer,
    qtype: u16,
) -> Result<Vec<String>, PhaseError> {
    let id: u16 = rand::random();
    let query = encode_query(id, "muse.ai", qtype)
        .map_err(|e| phase_err(format!("dns: encode query: {e}"), 3))?;
    let target = DialTarget::new(&server.server, server.server_port);
    let mut stream = tokio::time::timeout(DNS_QUERY_TIMEOUT, dialer.dial(&target))
        .await
        .map_err(|_| phase_err("context deadline exceeded".to_string(), 4))?
        .map_err(|e| {
            let code = phase_exit_code_transport(&e);
            phase_err(summarize_transport_error(&e), code)
        })?;
    let mut framed = Vec::with_capacity(query.len() + 2);
    framed.extend_from_slice(&(query.len() as u16).to_be_bytes());
    framed.extend_from_slice(&query);
    let exchange = async {
        stream.write_all(&framed).await?;
        let mut len_buf = [0u8; 2];
        stream.read_exact(&mut len_buf).await?;
        let len = u16::from_be_bytes(len_buf) as usize;
        let mut resp = vec![0u8; len];
        stream.read_exact(&mut resp).await?;
        Ok::<Vec<u8>, std::io::Error>(resp)
    };
    let resp = tokio::time::timeout(DNS_QUERY_TIMEOUT, exchange)
        .await
        .map_err(|_| phase_err("context deadline exceeded".to_string(), 4))?
        .map_err(|e| phase_err(format!("dns: tcp exchange: {e}"), 3))?;
    decode_response(&resp, id, qtype)
}

/// One DNS response: id check, rcode mapping, then the
/// answer addresses for `qtype`.
fn decode_response(body: &[u8], id: u16, qtype: u16) -> Result<Vec<String>, PhaseError> {
    let msg =
        decode_message(body).map_err(|e| phase_err(format!("dns: decode response: {e}"), 3))?;
    if msg.id != id {
        return Err(phase_err(
            format!("dns: mismatched response id {} (want {id})", msg.id),
            3,
        ));
    }
    if msg.rcode == 3 {
        return Err(phase_err("lookup muse.ai: no such host".to_string(), 3));
    }
    if msg.rcode != 0 {
        return Err(phase_err(
            format!("dns: server returned rcode {}", msg.rcode),
            3,
        ));
    }
    Ok(extract_ips(&msg, qtype))
}

fn extract_ips(msg: &castctl_dns::wire::DnsMessage, qtype: u16) -> Vec<String> {
    msg.answers
        .iter()
        .filter(|a| a.rtype == qtype)
        .filter_map(|a| match (qtype, a.rdata.len()) {
            (QTYPE_A, 4) => {
                Some(IpAddr::from([a.rdata[0], a.rdata[1], a.rdata[2], a.rdata[3]]).to_string())
            }
            (QTYPE_AAAA, 16) => {
                let mut b = [0u8; 16];
                b.copy_from_slice(&a.rdata);
                Some(IpAddr::from(b).to_string())
            }
            _ => None,
        })
        .collect()
}

/// The system resolver (`local` servers, and the whole
/// phase when no config file exists — Go builds no DNS
/// client then). The error text is an approximation: Go
/// names the resolver address, which the Rust resolver
/// does not expose.
async fn system_lookup(domain: &str) -> Result<Vec<String>, PhaseError> {
    let addrs = tokio::time::timeout(
        DNS_QUERY_TIMEOUT,
        tokio::net::lookup_host(format!("{domain}:443")),
    )
    .await
    .map_err(|_| phase_err("context deadline exceeded".to_string(), 4))?
    .map_err(|e| phase_err(format!("lookup {domain}: {e}"), 3))?;
    Ok(addrs.map(|s| s.ip().to_string()).collect())
}

/// Phase 2: TLS + GET `https://muse.ai/api/session`.
/// The cookies read comes first, untimed, exactly like
/// Go: a cookies failure substitutes as the phase error
/// (typed auth → exit 3) with no network call and ~0ms.
async fn https_phase(rt: &Runtime) -> (HttpsPhase, Option<PhaseError>) {
    let cookies = match rt.cookies_raw() {
        Ok(c) => c,
        Err(CookiesFailure::Missing(m)) | Err(CookiesFailure::Parse(m)) => {
            let phase = HttpsPhase {
                ok: false,
                ms: 0,
                status: None,
                error: Some(m.clone()),
            };
            return (phase, Some(phase_err(m, 3)));
        }
    };
    let start = Instant::now();
    let outcome = tokio::time::timeout(HTTPS_TIMEOUT, fetch_session_info(&rt.http, &cookies)).await;
    let ms = start.elapsed().as_millis() as i64;
    match outcome {
        Ok(Ok(_info)) => (
            HttpsPhase {
                ok: true,
                ms,
                status: Some(200),
                error: None,
            },
            None,
        ),
        Ok(Err(e)) => {
            let text = summarize_transport_error(&e);
            let code = phase_exit_code_transport(&e);
            (
                HttpsPhase {
                    ok: false,
                    ms,
                    status: None,
                    error: Some(text.clone()),
                },
                Some(phase_err(text, code)),
            )
        }
        Err(_) => {
            let text = "context deadline exceeded".to_string();
            (
                HttpsPhase {
                    ok: false,
                    ms,
                    status: None,
                    error: Some(text.clone()),
                },
                Some(phase_err(text, 4)),
            )
        }
    }
}

/// `classifyEgressTransportError` (`profilecmd.go`):
/// the class/kind labels and check order mirror Go's,
/// but the classification is from the Rust transport
/// error's flattened message (substring match), not
/// from Go's error TYPE — an approximation, recorded in
/// the M7d report. Only the warning text is affected
/// (egress is never fatal).
fn classify_egress_transport_error(err: &TransportError) -> (&'static str, &'static str) {
    match err {
        TransportError::Cancelled => ("canceled", "context"),
        TransportError::Timeout { .. } => ("timeout", "deadline"),
        TransportError::ConnectionDown { message }
        | TransportError::ConnectionError { message } => {
            let m = message.to_ascii_lowercase();
            let is_dns = m.contains("dns")
                || m.contains("resolve")
                || m.contains("lookup")
                || m.contains("name or service");
            let is_timeout =
                m.contains("timed out") || m.contains("timeout") || m.contains("deadline");
            if is_dns && is_timeout {
                ("dns", "dns_timeout")
            } else if is_dns {
                ("dns", "dns")
            } else if is_timeout {
                ("timeout", "net_timeout")
            } else if m.contains("connection refused") {
                ("network", "connection_refused")
            } else if m.contains("connection reset") {
                ("network", "connection_reset")
            } else if m.contains("broken pipe") {
                ("network", "broken_pipe")
            } else if m.contains("host unreachable") || m.contains("no route to host") {
                ("network", "host_unreachable")
            } else if m.contains("network unreachable") || m.contains("network is unreachable") {
                ("network", "network_unreachable")
            } else if m.contains("tls") || m.contains("certificate") {
                ("tls", "tls")
            } else if m.contains("parse") || m.contains("malformed") {
                ("transport", "response_parse")
            } else if m.contains("dial") {
                ("network", "dial")
            } else if m.contains("read") {
                ("network", "read")
            } else if m.contains("write") {
                ("network", "write")
            } else if m.contains("connect") {
                ("network", "connect")
            } else {
                ("network", "net_error")
            }
        }
        _ => ("transport", "unknown"),
    }
}

/// `fetchEgressIP` (`profilecmd.go`): GET the ipify
/// endpoint through the outbound. `Ok` is the trimmed
/// IP; `Err` is the warning text (never fatal).
async fn egress_phase(rt: &Runtime) -> Result<String, String> {
    let target = DialTarget::new("api64.ipify.org", 443);
    let resp = tokio::time::timeout(
        EGRESS_TIMEOUT,
        rt.http
            .request_tls(Method::GET, &target, "/", &[], None, EGRESS_TIMEOUT),
    )
    .await
    .map_err(|_| "context deadline exceeded".to_string())?
    .map_err(|e| {
        let (class, kind) = classify_egress_transport_error(&e);
        format!("egress check: GET api64.ipify.org failed (class={class} kind={kind})")
    })?;
    if resp.status.as_u16() != 200 {
        return Err(format!(
            "egress check: ipify returned status {}",
            resp.status.as_u16()
        ));
    }
    validate_ipify_body(&resp.body)
}

/// The ipify body rules (`fetchEgressIP`): at most
/// 1024 bytes read, a single IP address after trimming;
/// the body itself is never echoed, only its length.
fn validate_ipify_body(body: &[u8]) -> Result<String, String> {
    let body = &body[..body.len().min(1024)];
    let ip = String::from_utf8_lossy(body);
    let ip = ip.trim();
    if ip.is_empty() || ip.contains([' ', '\t', '\r', '\n']) {
        return Err(format!(
            "egress check: unexpected ipify body body_length={}",
            body.len()
        ));
    }
    match ip.parse::<IpAddr>() {
        Ok(_) => Ok(ip.to_string()),
        Err(_) => Err(format!(
            "egress check: ipify response is not an IP address body_length={}",
            body.len()
        )),
    }
}

/// Phase 4: Noise handshake, then immediate close. No
/// chat send, no session creation, no file writes. The
/// connector is built fresh from the runtime dialer
/// (Go's `connectorConfig` + `env.newConnector`), so a
/// connect failure here is a phase error, not a build
/// failure.
async fn gateway_phase(rt: &Runtime) -> (GatewayPhase, Option<PhaseError>) {
    let start = Instant::now();
    let connector = GatewayConnector::new(Arc::clone(&rt.dialer));
    let outcome = tokio::time::timeout(
        NOISE_TIMEOUT,
        connector.connect(&rt.profile.cookies_file, &rt.profile.vm_id),
    )
    .await;
    let ms = start.elapsed().as_millis() as i64;
    match outcome {
        Ok(Ok(gw)) => {
            gw.close().await;
            (
                GatewayPhase {
                    ok: true,
                    handshake_ms: ms,
                    tls: Some("utls-chrome".to_string()),
                    error: None,
                },
                None,
            )
        }
        Ok(Err(e)) => {
            let text = summarize_transport_error(&e);
            let code = phase_exit_code_transport(&e);
            (
                GatewayPhase {
                    ok: false,
                    handshake_ms: ms,
                    tls: Some("utls-chrome".to_string()),
                    error: Some(text.clone()),
                },
                Some(phase_err(text, code)),
            )
        }
        Err(_) => {
            let text = "context deadline exceeded".to_string();
            (
                GatewayPhase {
                    ok: false,
                    handshake_ms: ms,
                    tls: Some("utls-chrome".to_string()),
                    error: Some(text.clone()),
                },
                Some(phase_err(text, 4)),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::run::Outcome;
    use castctl_config::jsonvalue::decode_ordered_json;
    use castctl_transport::BodySummary;
    use std::fs;

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "castctl-cli-profiletest-{tag}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A `Ctx` + `GlobalOpts` pair pointing `--config`
    /// at `dir/config.json`.
    fn ctx_for(dir: &std::path::Path) -> (Ctx<'static>, GlobalOpts) {
        (
            Ctx {
                out: Outcome::default(),
                getenv: None,
            },
            GlobalOpts {
                config_flag: dir.join("config.json").to_str().unwrap().to_string(),
                config_set: true,
                ..Default::default()
            },
        )
    }

    fn flow_code(e: &FlowErr) -> i32 {
        match e {
            FlowErr::Msg { code, .. } => *code,
            FlowErr::Verbatim { code, .. } => *code,
            FlowErr::Exit(code) => *code,
            FlowErr::HelpShown => 0,
        }
    }

    fn dns_block(rules: &str) -> JsonValue {
        decode_ordered_json(
            format!(
                "{{\"servers\":[{{\"tag\":\"s1\",\"type\":\"https\",\"server\":\"1.1.1.1\",\"server_port\":443,\"path\":\"/dns-query\",\"detour\":\"\"}}],\"rules\":{rules},\"final\":\"s1\"}}"
            )
            .as_bytes(),
        )
        .unwrap()
    }

    #[test]
    fn rule_server_exact_suffix_keyword() {
        let raw = dns_block(
            r#"[{"domain":["muse.ai"],"server":"s1"},{"domain_suffix":["example.com"],"server":"s2"},{"domain_keyword":["muse"],"server":"s3"}]"#,
        );
        assert_eq!(rule_server_for_domain(&raw, "muse.ai"), Some("s1".into()));
        assert_eq!(
            rule_server_for_domain(&raw, "x.example.com"),
            Some("s2".into())
        );
        // `muse.ai` hits the exact rule first, not the
        // keyword rule; a host that only contains the
        // keyword hits the keyword rule.
        assert_eq!(
            rule_server_for_domain(&raw, "api.musex.com"),
            Some("s3".into())
        );
        assert_eq!(rule_server_for_domain(&raw, "other.com"), None);
        // Exact does not match a subdomain — but the
        // keyword rule still does: "sub.muse.ai" contains
        // "muse", so the keyword rule routes it (sing-box
        // `domain_keyword` semantics).
        assert_eq!(
            rule_server_for_domain(&raw, "sub.muse.ai"),
            Some("s3".into())
        );
    }

    #[test]
    fn rule_server_invert_and_action() {
        // Inverted exact rule: matches everything EXCEPT
        // muse.ai.
        let raw = dns_block(r#"[{"domain":["muse.ai"],"invert":true,"server":"s1"}]"#);
        assert_eq!(rule_server_for_domain(&raw, "muse.ai"), None);
        assert_eq!(rule_server_for_domain(&raw, "other.com"), Some("s1".into()));
        // A `respond` rule names no route; a rule with no
        // action but a server is a route.
        let raw = dns_block(r#"[{"action":"respond","server":"s1"},{"server":"s2"}]"#);
        assert_eq!(rule_server_for_domain(&raw, "muse.ai"), Some("s2".into()));
    }

    #[test]
    fn rule_server_skips_unevaluable_matchers() {
        // `geosite` and `domain_regex` rules cannot be
        // proven here: they are skipped, not guessed.
        let raw = dns_block(
            r#"[{"geosite":["cn"],"server":"s1"},{"domain_regex":["^muse"],"server":"s2"},{"domain":["muse.ai"],"server":"s3"}]"#,
        );
        assert_eq!(rule_server_for_domain(&raw, "muse.ai"), Some("s3".into()));
        // A block whose only rules are unevaluable falls
        // through to final.
        let raw = dns_block(r#"[{"domain_regex":["^muse"],"server":"s1"}]"#);
        assert_eq!(rule_server_for_domain(&raw, "muse.ai"), None);
    }

    #[test]
    fn phase_exit_code_shapes() {
        assert_eq!(
            phase_exit_code_transport(&TransportError::Timeout {
                message: "x".into()
            }),
            4
        );
        assert_eq!(
            phase_exit_code_transport(&TransportError::Auth {
                message: "x".into(),
            }),
            3
        );
        assert_eq!(
            phase_exit_code_transport(&TransportError::Gateway(BodySummary::new(-1, None, ""))),
            3
        );
        assert_eq!(phase_exit_code_transport(&TransportError::Cancelled), 3);
        assert_eq!(
            phase_exit_code_transport(&TransportError::Validation {
                message: "x".into(),
            }),
            // Go `phaseExitCode` has no Validation case:
            // anything unlisted is 3.
            3
        );
        assert_eq!(
            phase_exit_code_transport(&TransportError::ConnectionDown {
                message: "x".into()
            }),
            3
        );
        assert_eq!(
            phase_exit_code_config(&castctl_config::config_error("boom")),
            2
        );
    }

    #[test]
    fn ipify_body_shapes() {
        assert_eq!(validate_ipify_body(b"1.2.3.4"), Ok("1.2.3.4".into()));
        assert_eq!(
            validate_ipify_body(b"  2001:db8::1\n"),
            Ok("2001:db8::1".into())
        );
        assert_eq!(
            validate_ipify_body(b""),
            Err("egress check: unexpected ipify body body_length=0".into())
        );
        assert_eq!(
            validate_ipify_body(b"1.2.3.4 extra"),
            Err("egress check: unexpected ipify body body_length=13".into())
        );
        assert_eq!(
            validate_ipify_body(b"not-an-ip"),
            Err("egress check: ipify response is not an IP address body_length=9".into())
        );
        // Only the first 1024 bytes count; after the trim
        // the remainder is a single non-IP token, so Go
        // reports "is not an IP address" (the "unexpected
        // body" message is only for empty/whitespace bodies).
        let mut big = vec![b'x'; 1100];
        big[1023] = b' ';
        assert_eq!(
            validate_ipify_body(&big),
            Err("egress check: ipify response is not an IP address body_length=1024".into())
        );
    }

    #[test]
    fn render_shape_egress_null_errors_always_present() {
        let mut r = TestResult::new("alpha", "direct", "");
        r.errors.push("boom".into());
        let text = r.render().unwrap();
        // Field order: profile, outbound, fingerprint,
        // user_agent, note, egress_ip, ok, errors.
        let order = [
            "\"profile\"",
            "\"outbound\"",
            "\"fingerprint\"",
            "\"user_agent\"",
            "\"note\"",
            "\"egress_ip\"",
            "\"ok\"",
            "\"errors\"",
        ];
        let mut pos = 0;
        for key in order {
            let idx = text[pos..].find(key).unwrap();
            pos += idx + key.len();
        }
        assert!(text.contains("\"egress_ip\": null"));
        assert!(text.contains("\"ok\": false"));
        assert!(!text.contains("\"warnings\""));
        assert!(!text.contains("\"dns\""));
        assert!(!text.contains("\"https\""));
        assert!(!text.contains("\"gateway\""));
    }

    #[test]
    fn finish_prints_json_and_code() {
        let (mut ctx, _g) = ctx_for(std::path::Path::new("/tmp"));
        let mut r = TestResult::new("alpha", "direct", "");
        r.ok = true;
        assert!(finish(&mut ctx, &r, 0).is_ok());
        assert!(ctx.out.stdout.contains("\"ok\": true"));
        assert!(ctx.out.stdout.ends_with('\n'));
        assert!(ctx.out.stderr.is_empty());
        // A nonzero code renders the same JSON, then
        // returns the exit code as the error.
        let err = finish(&mut ctx, &r, 3).unwrap_err();
        assert_eq!(flow_code(&err), 3);
    }

    /// End-to-end: a profile whose outbound is a dead
    /// SOCKS proxy on 127.0.0.1:1. The DNS phase fails
    /// fast (connection refused), exit 3, the JSON is
    /// printed with the dns phase and no https/gateway
    /// phases — matching Go's stop-at-first-failure.
    #[test]
    fn run_test_dead_socks_fails_dns_phase() {
        let dir = temp_dir("dead-socks");
        let cfg = r#"{"default_profile":"alpha","profiles":{"alpha":{"node_id":"0123456789abcdef","outbound":"proxy-sg"}},"outbounds":[{"type":"socks","tag":"proxy-sg","server":"127.0.0.1","server_port":1,"version":"5"}]}"#;
        fs::write(dir.join("config.json"), cfg).unwrap();
        let (mut ctx, g) = ctx_for(&dir);
        let err = run_test(&mut ctx, &g, &parsed(&[])).unwrap_err();
        assert_eq!(flow_code(&err), 3);
        let out = &ctx.out.stdout;
        assert!(out.contains("\"dns\""), "stdout: {out}");
        assert!(out.contains("\"ok\": false"), "stdout: {out}");
        assert!(!out.contains("\"https\""), "stdout: {out}");
        assert!(!out.contains("\"gateway\""), "stdout: {out}");
        // Go sets the DNS phase's server/source ONLY on
        // success (profilecmd.go: the `rerr != nil` return
        // precedes the Server/Source assignment), so a
        // failed DNS phase reports ms + error only — no
        // server/source keys.
        assert!(!out.contains("\"server\""), "stdout: {out}");
        assert!(!out.contains("\"source\""), "stdout: {out}");
        assert!(ctx.out.stderr.is_empty());
    }

    fn parsed(positionals: &[&str]) -> Parsed {
        Parsed {
            positionals: positionals.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }
}
