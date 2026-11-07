// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! API handlers (`internal/webui/handlers.go`): status,
//! profiles, login, outbounds, endpoints, config/DNS,
//! telegram, keeper, chats, settings, logs, plugins,
//! screencast — plus the chi route table.
//!
//! Routing is exact-segment matching, case-sensitive, on
//! the RAW path (chi routes on `r.URL.RawPath`: `%2F`
//! never splits a segment, an encoded static segment
//! never matches a route, and params stay raw —
//! `/profiles/a%2Fb` is one param `"a%2Fb"`, not two
//! segments). A trailing slash is a different path —
//! `/api/v1/status/` matches no route and falls through
//! to the shell. A known path with a wrong method is a
//! 405; an unknown path falls through to the 200 shell
//! (Go quirk — preserved, not "fixed"). The decoded path
//! (Go's `r.URL.Path`) is used only for the ui_dir
//! filesystem path (see `server::serve_static`). Static
//! segments win over `{param}` segments at the same
//! position (chi): e.g. `GET /chats/jobs/{job}` beats
//! `GET /chats/{profile}/{session}`, and `POST
//! /outbounds/validate` beats `POST /outbounds/{tag}`
//! (which has no POST route at all).
//!
//! Every handler renders Go's exact envelope: struct
//! payloads in declaration order, `map[string]any`
//! payloads with keys sorted, `nil` slices as `null` and
//! empty non-nil slices as `[]`. Response bodies are
//! built as [`JsonValue`] in Go emission order and
//! rendered by `encode_go_json_line` (HTML escaping on +
//! trailing `\n`).
//!
//! After every successful guarded save the live Bearer
//! comparator is refreshed from the [`SaveOutcome`]
//! (Go's `refreshTokenHash` inside `saveGuarded`).

use crate::chats::{chat_deps, chat_session_id, err_upstream_chat, require_chat_profile};
use crate::cookies::cookies_format;
use crate::endpoints::{parse_wireguard_conf, preview_endpoint, with_type_and_tag};
use crate::error::{
    ApiError, err_config_changed, err_internal, err_not_found, err_unavailable, err_validation,
    safe_message_str,
};
use crate::go_decode::decode_first_value;
use crate::keeper_status::{read_status, rfc3339_offset as keeper_rfc3339_offset};
use crate::logs::{handle_get_logs, handle_logs_delete_refused, parse_query, query_value};
use crate::merge::merge_node_at;
use crate::plugins::handle_get_plugins;
use crate::redact::{redact_raw_config, redact_value};
use crate::screencast::{
    handle_screencast_start, handle_screencast_status, handle_screencast_ws_http,
};
use crate::sections::{
    handle_get_keeper_settings, handle_get_webui_settings, handle_put_keeper_settings,
    handle_put_webui_settings,
};
use crate::server::{
    BODY_CAP_1M, BODY_CAP_64K, Resp, Server, api_error_resp, decode_body_json, decode_body_typed,
    envelope_resp, error_resp, req_bool, req_string,
};
use crate::store::{
    ConfigLoad, SaveOutcome, config_source, legacy_profile_names_in, load_config, parse_loaded,
    save_direct, save_merged, save_submitted, summarize_object, used_by_endpoint, used_by_outbound,
};
use crate::validate::parse_and_validate_config;
use castctl_config::config::SingleConfig;
use castctl_config::jsonvalue::{JsonValue, OrderedObject};
use castctl_config::profile::OutboundKind;
use castctl_config::profile::{profile_paths, validate_profile_name};
use std::path::Path;
use std::sync::Arc;

/// Routing outcome: a response, a 405 for a known path
/// with a wrong method, or a fallthrough to the shell.
pub enum RouteOutcome {
    Handled(Resp),
    MethodNotAllowed,
    Fallthrough,
}

/// Route one authenticated `/api/v1` request. `path` is
/// the RAW request path (`/api/v1/...`); segments are
/// matched exactly, keeping empty segments (a trailing
/// slash defeats the match, as in chi), and params keep
/// their raw percent-encoding (Go never decodes them:
/// `chi.URLParam` is a raw substring).
pub async fn route(
    server: &Arc<Server>,
    method: &hyper::Method,
    path: &str,
    uri: &hyper::Uri,
    _headers: &hyper::HeaderMap,
    _peer: std::net::SocketAddr,
    body: &[u8],
) -> RouteOutcome {
    use hyper::Method;
    let segs: Vec<&str> = path.split('/').collect();
    // segs = ["", "api", "v1", <rest...>]. The dispatch
    // layer already classified this as an API path.
    let rest: &[&str] = if segs.len() >= 3 { &segs[3..] } else { &[] };
    let m = method.clone();
    // `known` reports a 405 when the path matched but the
    // method did not; `None` means "right method, run it".
    let known = |want: Method| -> Option<RouteOutcome> {
        if m == want {
            None
        } else {
            Some(RouteOutcome::MethodNotAllowed)
        }
    };
    match rest {
        ["status"] => return known(Method::GET).unwrap_or_else(|| route_status(server)),
        ["profiles"] => {
            return match m {
                Method::GET => route_list_profiles(server),
                Method::POST => route_create_profile(server, body),
                _ => RouteOutcome::MethodNotAllowed,
            };
        }
        ["profiles", name] => {
            return match m {
                Method::GET => route_get_profile(server, name),
                Method::PATCH => route_patch_profile(server, name, body),
                Method::DELETE => route_delete_profile(server, name, body),
                _ => RouteOutcome::MethodNotAllowed,
            };
        }
        ["profiles", name, "rename"] => {
            return known(Method::POST).unwrap_or_else(|| route_rename_profile(server, name, body));
        }
        ["profiles", name, "set-default"] => {
            return known(Method::POST).unwrap_or_else(|| route_set_default_profile(server, name));
        }
        ["profiles", _name, "test"] => {
            return known(Method::POST).unwrap_or_else(|| {
                RouteOutcome::Handled(error_resp(
                    501,
                    "unavailable",
                    "profile test is available only via the castctl CLI in this build",
                ))
            });
        }
        ["profiles", name, "login", "status"] => {
            return known(Method::GET).unwrap_or_else(|| route_login_status(server, name));
        }
        ["profiles", name, "login", "import"] => {
            return known(Method::POST).unwrap_or_else(|| route_login_import(server, name, body));
        }
        ["profiles", name, "login", "restore"] => {
            return known(Method::POST).unwrap_or_else(|| route_login_restore(server, name));
        }
        ["outbounds"] => {
            return match m {
                Method::GET => route_list_outbounds(server),
                Method::POST => route_create_outbound(server, body),
                _ => RouteOutcome::MethodNotAllowed,
            };
        }
        ["outbounds", "validate"] => {
            return known(Method::POST).unwrap_or_else(|| route_validate_outbound(server, body));
        }
        ["outbounds", tag] => {
            return match m {
                Method::GET => route_get_outbound(server, tag),
                Method::PATCH => route_patch_outbound(server, tag, body),
                Method::DELETE => route_delete_outbound(server, tag),
                _ => RouteOutcome::MethodNotAllowed,
            };
        }
        ["outbounds", _tag, "test"] => {
            return known(Method::POST).unwrap_or_else(|| {
                RouteOutcome::Handled(error_resp(
                    501,
                    "unavailable",
                    "outbound test is available only via the castctl CLI in this build",
                ))
            });
        }
        ["endpoints"] => {
            return match m {
                Method::GET => route_list_endpoints(server),
                Method::POST => route_create_endpoint(server, body),
                _ => RouteOutcome::MethodNotAllowed,
            };
        }
        ["endpoints", "import"] => {
            return known(Method::POST).unwrap_or_else(|| route_import_endpoint(server, body));
        }
        ["endpoints", tag] => {
            return match m {
                Method::GET => route_get_endpoint(server, tag),
                Method::PATCH => route_patch_endpoint(server, tag, body),
                Method::DELETE => route_delete_endpoint(server, tag),
                _ => RouteOutcome::MethodNotAllowed,
            };
        }
        ["config"] => {
            return match m {
                Method::GET => route_get_config(server),
                Method::PUT => route_put_config(server, body),
                _ => RouteOutcome::MethodNotAllowed,
            };
        }
        ["config", "validate"] => {
            return known(Method::POST).unwrap_or_else(|| route_validate_config(server, body));
        }
        ["dns"] => {
            return match m {
                Method::GET => route_get_dns(server),
                Method::PUT => route_put_dns(server, body),
                _ => RouteOutcome::MethodNotAllowed,
            };
        }
        ["settings", "telegram"] => {
            return match m {
                Method::GET => route_get_telegram(server),
                Method::PUT => route_put_telegram(server, body),
                _ => RouteOutcome::MethodNotAllowed,
            };
        }
        ["settings", "keeper"] => {
            return match m {
                Method::GET => route_get_keeper_settings(server),
                Method::PUT => route_put_keeper_settings(server, body),
                _ => RouteOutcome::MethodNotAllowed,
            };
        }
        ["settings", "webui"] => {
            return match m {
                Method::GET => route_get_webui_settings(server),
                Method::PUT => route_put_webui_settings(server, body),
                _ => RouteOutcome::MethodNotAllowed,
            };
        }
        // Static "jobs" beats the {profile}/{session}
        // parameter route at the same position (chi).
        ["chats", "jobs", job] => {
            return known(Method::GET).unwrap_or_else(|| route_get_chat_job(server, job));
        }
        ["chats", profile] => {
            return match m {
                Method::GET => route_list_chats(server, profile, uri).await,
                Method::POST => route_start_chat(server, profile, body).await,
                _ => RouteOutcome::MethodNotAllowed,
            };
        }
        ["chats", profile, session] => {
            return match known(Method::GET) {
                Some(o) => o,
                None => route_get_chat_history(server, profile, session, uri).await,
            };
        }
        ["chats", profile, session, "send"] => {
            return match known(Method::POST) {
                Some(o) => o,
                None => route_send_chat(server, profile, session, body).await,
            };
        }
        ["chats", profile, session, "op"] => {
            return match known(Method::POST) {
                Some(o) => o,
                None => route_chat_session_op(server, profile, session, body).await,
            };
        }
        ["plugins"] => {
            return known(Method::GET)
                .unwrap_or_else(|| RouteOutcome::Handled(handle_get_plugins()));
        }
        ["logs"] => {
            return match m {
                Method::GET => route_get_logs(server, uri),
                Method::DELETE => RouteOutcome::Handled(handle_logs_delete_refused()),
                _ => RouteOutcome::MethodNotAllowed,
            };
        }
        ["keeper"] => {
            return known(Method::GET).unwrap_or_else(|| route_get_keeper(server));
        }
        ["screencast", "status"] => {
            return known(Method::GET).unwrap_or_else(|| route_screencast_status(server, uri));
        }
        ["screencast", profile, "start"] => {
            return known(Method::POST).unwrap_or_else(|| route_screencast_start(server, profile));
        }
        ["screencast", "ws"] => {
            return known(Method::GET).unwrap_or_else(|| route_screencast_ws(server, uri));
        }
        _ => {}
    }
    RouteOutcome::Fallthrough
}

/// Whether the handler for (method, raw path) reads a
/// request body in Go (`decodeBody`/`bodyJSON`). The
/// transport layer uses this to decide whether to read
/// the body at all: Go reads bodies only inside handlers
/// — a 405, an unknown path, a 501 test stub, restore,
/// set-default, screencast start, and DELETE
/// outbound/endpoint never touch the body. (DELETE
/// /profiles/{name} DOES read one: `handleDeleteProfile`
/// decodes a 64 KiB body.) The segment patterns mirror
/// `route()` exactly; keep the two in sync.
pub fn route_reads_body(method: &hyper::Method, path: &str) -> bool {
    route_body_cap(method, path).is_some()
}

/// The per-route body cap for (method, raw path): the
/// `maxBytes` argument Go passes to `decodeBody`/`bodyJSON`
/// in that handler (`internal/webui/server.go:643,661` and
/// the call sites in `handlers.go`/`chats.go`/
/// `endpoints.go`/`sections.go`), mirrored 1:1 from the
/// `decode_body_*` call sites in this crate. `None` means
/// the handler reads no body. The transport read enforces
/// this cap DURING the read (fix loop 3, L2): Go's
/// `MaxBytesReader` aborts at cap+1 while reading, so a
/// 900 KiB body to a 64 KiB route never holds more than
/// ~64 KiB; the old transport cap (1 MiB+1 for every route)
/// buffered the whole 900 KiB first and only rejected it
/// afterwards in `decode_body_*`. Same 400 either way —
/// the difference is allocation only, proven by the RSS
/// case in the parity harness. The segment patterns mirror
/// `route()` and `route_reads_body` exactly; keep the three
/// in sync.
pub fn route_body_cap(method: &hyper::Method, path: &str) -> Option<usize> {
    use hyper::Method;
    let segs: Vec<&str> = path.split('/').collect();
    let rest: &[&str] = if segs.len() >= 3 { &segs[3..] } else { &[] };
    match rest {
        ["profiles"] if *method == Method::POST => Some(BODY_CAP_64K),
        ["profiles", _] if matches!(method, &Method::PATCH | &Method::DELETE) => Some(BODY_CAP_64K),
        ["profiles", _, "rename"] if *method == Method::POST => Some(BODY_CAP_64K),
        ["profiles", _, "login", "import"] if *method == Method::POST => Some(BODY_CAP_1M),
        ["outbounds"] if *method == Method::POST => Some(BODY_CAP_1M),
        ["outbounds", "validate"] if *method == Method::POST => Some(BODY_CAP_1M),
        ["outbounds", _] if *method == Method::PATCH => Some(BODY_CAP_1M),
        ["endpoints"] if *method == Method::POST => Some(BODY_CAP_1M),
        ["endpoints", "import"] if *method == Method::POST => Some(BODY_CAP_64K),
        ["endpoints", _] if *method == Method::PATCH => Some(BODY_CAP_1M),
        ["config"] if *method == Method::PUT => Some(BODY_CAP_1M),
        ["config", "validate"] if *method == Method::POST => Some(BODY_CAP_1M),
        ["dns"] if *method == Method::PUT => Some(BODY_CAP_1M),
        ["settings", "telegram"] if *method == Method::PUT => Some(BODY_CAP_64K),
        ["settings", "keeper"] if *method == Method::PUT => Some(BODY_CAP_1M),
        ["settings", "webui"] if *method == Method::PUT => Some(BODY_CAP_64K),
        ["chats", _] if *method == Method::POST => Some(BODY_CAP_64K),
        ["chats", _, _, "send"] | ["chats", _, _, "op"] if *method == Method::POST => {
            Some(BODY_CAP_64K)
        }
        _ => None,
    }
}

// --- shared helpers -------------------------------------------

fn cfg_dir(server: &Server) -> &Path {
    &server.deps.config_dir
}

fn load(server: &Server) -> Result<ConfigLoad, ApiError> {
    load_config(cfg_dir(server))
}

/// Render a handler result: an error becomes its envelope.
fn done(result: Result<Resp, ApiError>) -> Resp {
    match result {
        Ok(resp) => resp,
        Err(e) => api_error_resp(&e),
    }
}

/// Refresh the live Bearer comparator after a successful
/// guarded save (Go's `refreshTokenHash` in `saveGuarded`).
fn refresh(server: &Server, outcome: &SaveOutcome) {
    server.refresh_token_hash(outcome.webui_token.clone(), outcome.stored_had_token);
}

fn obj_str(obj: &OrderedObject, key: &str) -> Option<String> {
    match obj.get(key) {
        Some(JsonValue::Str(s)) => Some(s.clone()),
        _ => None,
    }
}

/// `rawSections` (store.go): the stored document's
/// outbounds/endpoints arrays as generic objects. Empty
/// raw bytes give empty sections; a non-object document is
/// a validation error; non-array sections and non-object
/// elements are skipped.
fn raw_sections(load: &ConfigLoad) -> Result<(Vec<OrderedObject>, Vec<OrderedObject>), ApiError> {
    if load.raw.is_empty() {
        return Ok((Vec::new(), Vec::new()));
    }
    let text = String::from_utf8_lossy(&load.raw).into_owned();
    let doc = decode_first_value(text.as_bytes()).map_err(|e| {
        err_validation(format!(
            "stored config is invalid: {}",
            safe_message_str(&e.message)
        ))
    })?;
    let JsonValue::Object(root) = &doc else {
        return Err(err_validation("config document must be an object"));
    };
    Ok((
        generic_object_array(root.get("outbounds")),
        generic_object_array(root.get("endpoints")),
    ))
}

fn generic_object_array(v: Option<&JsonValue>) -> Vec<OrderedObject> {
    let Some(JsonValue::Array(items)) = v else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for elem in items {
        if let JsonValue::Object(obj) = elem {
            out.push(obj.clone());
        }
    }
    out
}

/// `cookiesPresent`: presence only, never a read.
fn cookies_present(path: &str) -> bool {
    if path.is_empty() {
        return false;
    }
    match std::fs::metadata(path) {
        Ok(md) => !md.is_dir(),
        Err(_) => false,
    }
}

/// `tagDefined`: the tag names an outbound or endpoint in
/// the stored document. Go uses `ParsedOutbounds` /
/// `ParsedEndpoints` (a section that fails to parse
/// contributes nothing); raw tag extraction is equivalent
/// for a parsed document.
fn tag_defined(cfg: &SingleConfig, tag: &str) -> bool {
    for raw in cfg.outbounds_raw.iter().chain(cfg.endpoints_raw.iter()) {
        if let JsonValue::Object(obj) = raw
            && obj_str(obj, "tag").as_deref() == Some(tag)
        {
            return true;
        }
    }
    false
}

// --- status ---------------------------------------------------

fn route_status(server: &Server) -> RouteOutcome {
    RouteOutcome::Handled(done(handle_status(server)))
}

fn handle_status(server: &Server) -> Result<Resp, ApiError> {
    let load = load(server)?;
    let mut source = "none".to_string();
    let mut default_profile = String::new();
    let mut profile_count = 0usize;
    let mut outbound_count = 0usize;
    let mut endpoint_count = 0usize;
    if load.state.found {
        match parse_and_validate_config(&load.raw, cfg_dir(server)) {
            Ok((cfg, _)) => {
                source = config_source(&load, cfg_dir(server), &cfg);
                default_profile = cfg.default_profile.clone();
                profile_count = cfg.profiles.len();
                outbound_count = cfg.outbounds_raw.len();
                endpoint_count = cfg.endpoints_raw.len();
            }
            Err(_) => {
                source = "invalid".to_string();
            }
        }
    } else if load.state.exists {
        // Go calls configSource(load, nil): no exclusions.
        source = config_source(&load, cfg_dir(server), &SingleConfig::default());
    }
    let mut map = OrderedObject::new();
    map.set("bundle_sha256", JsonValue::Str(server.bundle_sha256()));
    map.set("config_path", JsonValue::Str(server.config_path()));
    map.set("config_source", JsonValue::Str(source));
    map.set("default_profile", JsonValue::Str(default_profile));
    map.set(
        "endpoint_count",
        JsonValue::Number(endpoint_count.to_string()),
    );
    // Go reports the real runtime/sing-box versions; the
    // Rust build has no equivalent, so the documented
    // fallback strings are used (the parity harness checks
    // presence + type only).
    map.set("go_version", JsonValue::Str("unknown".to_string()));
    map.set(
        "listen_addr",
        JsonValue::Str(server.deps.listen_addr.clone()),
    );
    map.set(
        "outbound_count",
        JsonValue::Number(outbound_count.to_string()),
    );
    map.set(
        "profile_count",
        JsonValue::Number(profile_count.to_string()),
    );
    map.set("remote_exposure", JsonValue::Bool(false));
    map.set(
        "session_idle_timeout_seconds",
        JsonValue::Number(server.session_idle_timeout_seconds().to_string()),
    );
    map.set("singbox_version", JsonValue::Str("unknown".to_string()));
    map.set("version", JsonValue::Str(server.deps.version.clone()));
    Ok(envelope_resp(200, JsonValue::Object(map)))
}

// --- profiles -------------------------------------------------

/// `profileSummary` field order: name, default, source,
/// has_cookies, outbound_tag, fingerprint, dir.
fn profile_summary_json(
    name: &str,
    default: bool,
    source: &str,
    has_cookies: bool,
    outbound_tag: JsonValue,
    fingerprint: &str,
    dir: &str,
) -> JsonValue {
    let mut obj = OrderedObject::new();
    obj.set("name", JsonValue::Str(name.to_string()));
    obj.set("default", JsonValue::Bool(default));
    obj.set("source", JsonValue::Str(source.to_string()));
    obj.set("has_cookies", JsonValue::Bool(has_cookies));
    obj.set("outbound_tag", outbound_tag);
    obj.set("fingerprint", JsonValue::Str(fingerprint.to_string()));
    obj.set("dir", JsonValue::Str(dir.to_string()));
    JsonValue::Object(obj)
}

fn outbound_tag_json(p: &castctl_config::profile::Profile) -> JsonValue {
    match p.outbound.kind {
        OutboundKind::Direct => JsonValue::Null,
        OutboundKind::Tag | OutboundKind::Inline => JsonValue::Str(p.outbound.tag.clone()),
    }
}

fn fingerprint_or_default(p: &castctl_config::profile::Profile) -> String {
    if p.fingerprint.is_empty() {
        "chrome".to_string()
    } else {
        p.fingerprint.clone()
    }
}

fn profile_summaries(
    server: &Server,
    cfg: &SingleConfig,
    legacy_names: &[String],
) -> Vec<JsonValue> {
    let mut out: Vec<JsonValue> = Vec::new();
    for name in cfg.profile_names() {
        let Some(p) = cfg.profiles.get(&name) else {
            continue;
        };
        out.push(profile_summary_json(
            &name,
            name == cfg.default_profile,
            "single-file",
            cookies_present(&p.cookies_file),
            outbound_tag_json(p),
            &fingerprint_or_default(p),
            &p.dir,
        ));
    }
    for name in legacy_names {
        let (dir, has_cookies) = match profile_paths(&cfg_dir(server).to_string_lossy(), name) {
            Ok(paths) => (paths.dir.clone(), cookies_present(&paths.cookies)),
            Err(_) => (String::new(), false),
        };
        out.push(profile_summary_json(
            name,
            false,
            "legacy",
            has_cookies,
            JsonValue::Null,
            "",
            &dir,
        ));
    }
    out
}

/// `profileWarnings` (handlers.go, mirroring
/// internal/commands profileWarnings): cookies-file
/// presence/mode, config-file mode, dangling outbound tag.
fn profile_warnings(cfg: &SingleConfig, p: &castctl_config::profile::Profile) -> Vec<String> {
    use std::os::unix::fs::PermissionsExt;
    let mut warnings: Vec<String> = Vec::new();
    match std::fs::metadata(&p.cookies_file) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            warnings.push(format!("cookies file {} does not exist", p.cookies_file));
        }
        Ok(md) => {
            let mode = md.permissions().mode() & 0o7777;
            if mode != 0o600 {
                warnings.push(format!(
                    "cookies file {} has mode {:04o}, expected 0600",
                    p.cookies_file, mode
                ));
            }
        }
        Err(_) => {}
    }
    if !p.config_file.is_empty()
        && let Ok(md) = std::fs::metadata(&p.config_file)
    {
        let mode = md.permissions().mode() & 0o7777;
        if mode != 0o600 {
            warnings.push(format!(
                "config file {} has mode {:04o}, expected 0600",
                p.config_file, mode
            ));
        }
    }
    if p.outbound.kind == OutboundKind::Tag
        && !p.outbound.tag.is_empty()
        && p.outbound.tag != "direct"
        && !tag_defined(cfg, &p.outbound.tag)
    {
        warnings.push(format!(
            "outbound tag {:?} is not defined in the config",
            p.outbound.tag
        ));
    }
    warnings
}

/// `detailFor`: the frozen `profileDetail` shape (struct
/// order): name, default, source, has_cookies,
/// outbound_tag, fingerprint, dir, entry, paths, warnings.
/// `entry` is the redacted raw stored profile object
/// (`{}` when absent); `paths` is a sorted map.
fn detail_for(
    cfg: &SingleConfig,
    p: &castctl_config::profile::Profile,
    load: &ConfigLoad,
) -> JsonValue {
    let mut entry = JsonValue::Object(OrderedObject::new());
    if !load.raw.is_empty() {
        let text = String::from_utf8_lossy(&load.raw).into_owned();
        if let Ok(doc) = decode_first_value(text.as_bytes())
            && let JsonValue::Object(root) = &doc
            && let Some(JsonValue::Object(profiles)) = root.get("profiles")
            && let Some(JsonValue::Object(raw_entry)) = profiles.get(&p.name)
            && let JsonValue::Object(redacted) = redact_value(&JsonValue::Object(raw_entry.clone()))
        {
            entry = JsonValue::Object(redacted);
        }
    }
    let mut paths = OrderedObject::new();
    paths.set("chat_file", JsonValue::Str(p.chat_file.clone()));
    paths.set("config_file", JsonValue::Str(p.config_file.clone()));
    paths.set("cookies_file", JsonValue::Str(p.cookies_file.clone()));
    paths.set("dir", JsonValue::Str(p.dir.clone()));
    let warnings: Vec<JsonValue> = profile_warnings(cfg, p)
        .into_iter()
        .map(JsonValue::Str)
        .collect();
    let mut obj = OrderedObject::new();
    obj.set("name", JsonValue::Str(p.name.clone()));
    obj.set("default", JsonValue::Bool(p.name == cfg.default_profile));
    obj.set("source", JsonValue::Str("single-file".to_string()));
    obj.set(
        "has_cookies",
        JsonValue::Bool(cookies_present(&p.cookies_file)),
    );
    obj.set("outbound_tag", outbound_tag_json(p));
    obj.set("fingerprint", JsonValue::Str(fingerprint_or_default(p)));
    obj.set("dir", JsonValue::Str(p.dir.clone()));
    obj.set("entry", entry);
    obj.set("paths", JsonValue::Object(paths));
    obj.set("warnings", JsonValue::Array(warnings));
    JsonValue::Object(obj)
}

fn load_detail(server: &Server, name: &str) -> Result<JsonValue, ApiError> {
    let load = load(server)?;
    let (cfg, _) = parse_loaded(&load, cfg_dir(server))?;
    let Some(p) = cfg.profiles.get(name) else {
        return Err(err_not_found("profile not found"));
    };
    Ok(detail_for(&cfg, p, &load))
}

/// `profilesObject`: the doc's `profiles` object,
/// creating it when absent (create path on a fresh file).
fn profiles_object(doc: &mut OrderedObject) -> Result<OrderedObject, ApiError> {
    match doc.get("profiles") {
        Some(JsonValue::Object(obj)) => Ok(obj.clone()),
        Some(_) => Err(err_validation("\"profiles\" must be an object")),
        None => Ok(OrderedObject::new()),
    }
}

fn detail_summary(detail: &JsonValue) -> Result<JsonValue, ApiError> {
    let JsonValue::Object(d) = detail else {
        return Err(err_internal());
    };
    Ok(profile_summary_json(
        &obj_str(d, "name").unwrap_or_default(),
        matches!(d.get("default"), Some(JsonValue::Bool(true))),
        &obj_str(d, "source").unwrap_or_default(),
        matches!(d.get("has_cookies"), Some(JsonValue::Bool(true))),
        d.get("outbound_tag").cloned().unwrap_or(JsonValue::Null),
        &obj_str(d, "fingerprint").unwrap_or_default(),
        &obj_str(d, "dir").unwrap_or_default(),
    ))
}

fn route_list_profiles(server: &Server) -> RouteOutcome {
    RouteOutcome::Handled(done(handle_list_profiles(server)))
}

fn handle_list_profiles(server: &Server) -> Result<Resp, ApiError> {
    let load = load(server)?;
    let (cfg, _) = parse_loaded(&load, cfg_dir(server))?;
    // Display-only: an enumeration error degrades to no
    // legacy profiles shown.
    let legacy_names = legacy_profile_names_in(cfg_dir(server), &cfg).unwrap_or_default();
    let summaries = profile_summaries(server, &cfg, &legacy_names);
    Ok(envelope_resp(200, JsonValue::Array(summaries)))
}

fn route_get_profile(server: &Server, name: &str) -> RouteOutcome {
    RouteOutcome::Handled(done(
        load_detail(server, name).map(|d| envelope_resp(200, d)),
    ))
}

fn route_create_profile(server: &Server, body: &[u8]) -> RouteOutcome {
    RouteOutcome::Handled(done(handle_create_profile(server, body)))
}

fn handle_create_profile(server: &Server, body: &[u8]) -> Result<Resp, ApiError> {
    let (name, cookies_file, outbound, set_default) = decode_body_typed(
        body,
        BODY_CAP_64K,
        &["name", "cookies_file", "outbound", "set_default"],
        |obj| {
            let name = req_string(obj, "name")?.unwrap_or_default();
            let cookies_file = req_string(obj, "cookies_file")?;
            let outbound = req_string(obj, "outbound")?;
            let set_default = req_bool(obj, "set_default")?;
            Ok((name, cookies_file, outbound, set_default))
        },
    )?;
    if let Err(e) = validate_profile_name(&name) {
        return Err(err_validation(format!(
            "invalid profile name: {}",
            safe_message_str(&e.message)
        )));
    }
    let load = load(server)?;
    let (cfg, _) = parse_loaded(&load, cfg_dir(server))?;
    if cfg.profiles.contains_key(&name) {
        return Err(err_validation("profile already exists"));
    }
    let name_c = name.clone();
    let outcome = save_direct(&load, cfg_dir(server), move |doc| {
        let JsonValue::Object(doc_obj) = doc else {
            return Err(err_validation("config document must be a JSON object"));
        };
        let mut profiles = profiles_object(doc_obj)?;
        let mut entry = OrderedObject::new();
        if let Some(cf) = &cookies_file
            && !cf.is_empty()
        {
            entry.set("cookies_file".to_string(), JsonValue::Str(cf.clone()));
        }
        if let Some(ob) = &outbound
            && !ob.is_empty()
            && ob != "direct"
        {
            entry.set("outbound".to_string(), JsonValue::Str(ob.clone()));
        }
        profiles.set(name_c.clone(), JsonValue::Object(entry));
        doc_obj.set("profiles".to_string(), JsonValue::Object(profiles));
        if set_default == Some(true) {
            doc_obj.set(
                "default_profile".to_string(),
                JsonValue::Str(name_c.clone()),
            );
        }
        Ok(())
    })?;
    refresh(server, &outcome);
    // The frozen create response is a ProfileSummary.
    let detail = load_detail(server, &name)?;
    Ok(envelope_resp(200, detail_summary(&detail)?))
}

fn route_patch_profile(server: &Server, name: &str, body: &[u8]) -> RouteOutcome {
    RouteOutcome::Handled(done(handle_patch_profile(server, name, body)))
}

fn handle_patch_profile(server: &Server, name: &str, body: &[u8]) -> Result<Resp, ApiError> {
    let (auto_approve, auto_allow_once, outbound, fingerprint) = decode_body_typed(
        body,
        BODY_CAP_64K,
        &["auto_approve", "auto_allow_once", "outbound", "fingerprint"],
        |obj| {
            Ok((
                req_bool(obj, "auto_approve")?,
                req_bool(obj, "auto_allow_once")?,
                req_string(obj, "outbound")?,
                req_string(obj, "fingerprint")?,
            ))
        },
    )?;
    let load = load(server)?;
    let (cfg, _) = parse_loaded(&load, cfg_dir(server))?;
    if !cfg.profiles.contains_key(name) {
        return Err(err_not_found("profile not found"));
    }
    let name_c = name.to_string();
    let outcome = save_direct(&load, cfg_dir(server), move |doc| {
        let JsonValue::Object(doc_obj) = doc else {
            return Err(err_validation("config document must be a JSON object"));
        };
        let mut profiles = profiles_object(doc_obj)?;
        let Some(JsonValue::Object(entry)) = profiles.get(&name_c).cloned() else {
            return Err(err_validation("profile entry is invalid"));
        };
        let mut entry = entry;
        if let Some(b) = auto_approve {
            entry.set(
                "auto_approve".to_string(),
                JsonValue::Str(if b {
                    "always".to_string()
                } else {
                    "off".to_string()
                }),
            );
        }
        if let Some(b) = auto_allow_once {
            entry.set("auto_allow_once".to_string(), JsonValue::Bool(b));
        }
        if let Some(ob) = &outbound {
            if ob.is_empty() || ob == "direct" {
                entry.remove("outbound");
            } else {
                entry.set("outbound".to_string(), JsonValue::Str(ob.clone()));
            }
        }
        if let Some(fp) = &fingerprint {
            if fp.is_empty() {
                entry.remove("fingerprint");
            } else {
                entry.set("fingerprint".to_string(), JsonValue::Str(fp.clone()));
            }
        }
        profiles.set(name_c.clone(), JsonValue::Object(entry));
        doc_obj.set("profiles".to_string(), JsonValue::Object(profiles));
        Ok(())
    })?;
    refresh(server, &outcome);
    let detail = load_detail(server, name)?;
    Ok(envelope_resp(200, detail))
}

fn route_delete_profile(server: &Server, name: &str, body: &[u8]) -> RouteOutcome {
    RouteOutcome::Handled(done(handle_delete_profile(server, name, body)))
}

fn handle_delete_profile(server: &Server, name: &str, body: &[u8]) -> Result<Resp, ApiError> {
    let (confirm, del_name) = decode_body_typed(body, BODY_CAP_64K, &["confirm", "name"], |obj| {
        Ok((
            req_bool(obj, "confirm")?,
            req_string(obj, "name")?.unwrap_or_default(),
        ))
    })?;
    if confirm != Some(true) || del_name != name {
        return Err(err_validation("delete requires {confirm: true, name}"));
    }
    let load = load(server)?;
    let (cfg, _) = parse_loaded(&load, cfg_dir(server))?;
    if !cfg.profiles.contains_key(name) {
        return Err(err_not_found("profile not found"));
    }
    let name_c = name.to_string();
    let outcome = save_direct(&load, cfg_dir(server), move |doc| {
        let JsonValue::Object(doc_obj) = doc else {
            return Err(err_validation("config document must be a JSON object"));
        };
        let mut profiles = profiles_object(doc_obj)?;
        profiles.remove(&name_c);
        doc_obj.set("profiles".to_string(), JsonValue::Object(profiles));
        if let Some(JsonValue::Str(def)) = doc_obj.get("default_profile")
            && def == &name_c
        {
            doc_obj.remove("default_profile");
        }
        Ok(())
    })?;
    refresh(server, &outcome);
    let mut map = OrderedObject::new();
    map.set("deleted", JsonValue::Bool(true));
    Ok(envelope_resp(200, JsonValue::Object(map)))
}

fn route_rename_profile(server: &Server, name: &str, body: &[u8]) -> RouteOutcome {
    RouteOutcome::Handled(done(handle_rename_profile(server, name, body)))
}

/// `rewriteRenamedCookiesFile`: a renamed profile's own
/// cookies file spelling moves with it (same form —
/// relative stays relative, absolute stays absolute). Any
/// other value is left untouched for the save guard to
/// judge. The cookies file itself is NOT moved on disk.
fn rewrite_renamed_cookies_file(
    entry: &mut OrderedObject,
    config_dir: &Path,
    old_name: &str,
    new_name: &str,
) {
    let Some(JsonValue::Str(value)) = entry.get("cookies_file").cloned() else {
        return;
    };
    if value.trim().is_empty() {
        return;
    }
    let Ok(old_paths) = profile_paths(&config_dir.to_string_lossy(), old_name) else {
        return;
    };
    let Ok(new_paths) = profile_paths(&config_dir.to_string_lossy(), new_name) else {
        return;
    };
    let resolved = if Path::new(&value).is_absolute() {
        value.clone()
    } else {
        config_dir.join(&value).to_string_lossy().into_owned()
    };
    let cleaned = crate::contain::clean_path(Path::new(&resolved));
    if cleaned.to_string_lossy() != old_paths.cookies {
        return;
    }
    if Path::new(&value).is_absolute() {
        entry.set(
            "cookies_file".to_string(),
            JsonValue::Str(new_paths.cookies),
        );
        return;
    }
    if let Some(rel) = path_relative_to(config_dir, Path::new(&new_paths.cookies)) {
        entry.set("cookies_file".to_string(), JsonValue::Str(rel));
    }
}

/// `filepath.Rel` for two absolute, cleaned paths: the
/// remainder when `target` sits under `base`, else `None`.
fn path_relative_to(base: &Path, target: &Path) -> Option<String> {
    let rel = target.strip_prefix(base).ok()?;
    let mut out = String::new();
    for (i, comp) in rel.components().enumerate() {
        if i > 0 {
            out.push('/');
        }
        out.push_str(&comp.as_os_str().to_string_lossy());
    }
    Some(out)
}

fn handle_rename_profile(server: &Server, name: &str, body: &[u8]) -> Result<Resp, ApiError> {
    let to = decode_body_typed(body, BODY_CAP_64K, &["to"], |obj| {
        Ok(req_string(obj, "to")?.unwrap_or_default())
    })?;
    if let Err(e) = validate_profile_name(&to) {
        return Err(err_validation(format!(
            "invalid profile name: {}",
            safe_message_str(&e.message)
        )));
    }
    let load = load(server)?;
    let (cfg, _) = parse_loaded(&load, cfg_dir(server))?;
    if !cfg.profiles.contains_key(name) {
        return Err(err_not_found("profile not found"));
    }
    if cfg.profiles.contains_key(&to) {
        return Err(err_validation("profile already exists"));
    }
    let old_c = name.to_string();
    let to_c = to.clone();
    let dir_c = cfg_dir(server).to_path_buf();
    let outcome = save_direct(&load, cfg_dir(server), move |doc| {
        let JsonValue::Object(doc_obj) = doc else {
            return Err(err_validation("config document must be a JSON object"));
        };
        let mut profiles = profiles_object(doc_obj)?;
        let Some(entry_val) = profiles.get(&old_c).cloned() else {
            return Err(err_validation("profile entry is invalid"));
        };
        if let JsonValue::Object(mut entry) = entry_val.clone() {
            rewrite_renamed_cookies_file(&mut entry, &dir_c, &old_c, &to_c);
            profiles.remove(&old_c);
            profiles.set(to_c.clone(), JsonValue::Object(entry));
        } else {
            profiles.remove(&old_c);
            profiles.set(to_c.clone(), entry_val);
        }
        doc_obj.set("profiles".to_string(), JsonValue::Object(profiles));
        if let Some(JsonValue::Str(def)) = doc_obj.get("default_profile")
            && def == &old_c
        {
            doc_obj.set("default_profile".to_string(), JsonValue::Str(to_c.clone()));
        }
        Ok(())
    })?;
    refresh(server, &outcome);
    let detail = load_detail(server, &to)?;
    Ok(envelope_resp(200, detail_summary(&detail)?))
}

fn route_set_default_profile(server: &Server, name: &str) -> RouteOutcome {
    RouteOutcome::Handled(done(handle_set_default_profile(server, name)))
}

fn handle_set_default_profile(server: &Server, name: &str) -> Result<Resp, ApiError> {
    // No body decode (Go reads no body here).
    let load = load(server)?;
    let (cfg, _) = parse_loaded(&load, cfg_dir(server))?;
    if !cfg.profiles.contains_key(name) {
        return Err(err_not_found("profile not found"));
    }
    let name_c = name.to_string();
    let outcome = save_direct(&load, cfg_dir(server), move |doc| {
        let JsonValue::Object(doc_obj) = doc else {
            return Err(err_validation("config document must be a JSON object"));
        };
        doc_obj.set(
            "default_profile".to_string(),
            JsonValue::Str(name_c.clone()),
        );
        Ok(())
    })?;
    refresh(server, &outcome);
    let mut map = OrderedObject::new();
    map.set("default_profile", JsonValue::Str(name.to_string()));
    Ok(envelope_resp(200, JsonValue::Object(map)))
}

// --- login status / import / restore --------------------------

/// `ErrNoBackup` (handlers.go): the restore seam reports
/// a missing `.bak` with this message; the handler maps it
/// to 404. The Rust seam returns a plain `String` error,
/// so the message is the marker.
pub const ERR_NO_BACKUP_MSG: &str = "no backup cookies file";

/// `resolveCookiesFile`: a profile's cookies file from the
/// single-file document, else the legacy profile
/// directory's file. A parse failure is 400; an invalid
/// name is 400; anything else unknown is 404.
fn resolve_cookies_file(server: &Server, name: &str) -> Result<(String, bool), ApiError> {
    let load = load(server)?;
    if load.state.found {
        let (cfg, _) = parse_and_validate_config(&load.raw, cfg_dir(server)).map_err(|e| {
            err_validation(format!(
                "stored config is invalid: {}",
                safe_message_str(&e)
            ))
        })?;
        if let Some(p) = cfg.profiles.get(name) {
            return Ok((p.cookies_file.clone(), false));
        }
    }
    let paths = profile_paths(&cfg_dir(server).to_string_lossy(), name).map_err(|e| {
        err_validation(format!(
            "invalid profile name: {}",
            safe_message_str(&e.message)
        ))
    })?;
    let legacy_config = Path::new(&paths.dir).join("config.json");
    if std::fs::metadata(&legacy_config).is_ok() {
        return Ok((paths.cookies, true));
    }
    Err(err_not_found("profile not found"))
}

fn route_login_status(server: &Server, name: &str) -> RouteOutcome {
    RouteOutcome::Handled(done(handle_login_status(server, name)))
}

fn handle_login_status(server: &Server, name: &str) -> Result<Resp, ApiError> {
    let (cookies_file, _) = resolve_cookies_file(server, name)?;
    let present = cookies_present(&cookies_file);
    let mut format: JsonValue = JsonValue::Null;
    let mut parse_ok = false;
    if present && let Ok(data) = std::fs::read(&cookies_file) {
        // Values stay in-process: only the detected
        // form and the parse verdict leave this handler.
        let f = cookies_format(&data);
        if !f.is_empty() {
            format = JsonValue::Str(f.to_string());
            parse_ok = true;
        }
    }
    // Keeper state (no network): the logged-out flag and
    // the recorded expiries are metadata by name only,
    // never values. ReadStatus errors are ignored silently.
    let mut earliest_expiry: JsonValue = JsonValue::Null;
    let mut last_checked_at: JsonValue = JsonValue::Null;
    let mut logged_out = false;
    if let Ok(load) = load(server)
        && load.state.found
        && let Ok((_, entries)) = parse_loaded(&load, cfg_dir(server))
        && let Some(entry) = entries.iter().find(|e| e.profile == name)
        && let Ok(st) = read_status(cfg_dir(server), entry)
    {
        logged_out = st.logged_out;
        if let Some(t) = st.earliest_expiry {
            // Seconds-only with the stored offset (Go
            // `handlers.go:688` `Format(time.RFC3339)`); a
            // Go-written expiry is `Z`, a hand-edited
            // non-`Z` offset re-prints like Go (fix loop 1,
            // B6).
            earliest_expiry = JsonValue::Str(keeper_rfc3339_offset(t));
        }
        if let Some(t) = st.last_checked_at {
            // LOCAL field: seconds-only with the stored
            // offset (Go `handlers.go:691`
            // `Format(time.RFC3339)`).
            last_checked_at = JsonValue::Str(keeper_rfc3339_offset(t));
        }
    }
    let mut map = OrderedObject::new();
    map.set("cookies_format", format);
    map.set("cookies_present", JsonValue::Bool(present));
    map.set("expiry", earliest_expiry);
    map.set("last_checked_at", last_checked_at);
    map.set(
        "logged_in",
        JsonValue::Bool(present && parse_ok && !logged_out),
    );
    map.set("vm_id_prefix", JsonValue::Null);
    Ok(envelope_resp(200, JsonValue::Object(map)))
}

fn route_login_import(server: &Server, name: &str, body: &[u8]) -> RouteOutcome {
    RouteOutcome::Handled(done(handle_login_import(server, name, body)))
}

fn handle_login_import(server: &Server, name: &str, body: &[u8]) -> Result<Resp, ApiError> {
    let (format, content) = decode_body_typed(body, BODY_CAP_1M, &["format", "content"], |obj| {
        Ok((
            req_string(obj, "format")?.unwrap_or_default(),
            req_string(obj, "content")?.unwrap_or_default(),
        ))
    })?;
    if format != "text" && format != "file" {
        return Err(err_validation("format must be text or file"));
    }
    let (cookies_file, _) = resolve_cookies_file(server, name)?;
    if !crate::contain::contained_in_dir(&cookies_file, cfg_dir(server)) {
        // Web UI containment (Boss ruling 2026-10-31): the
        // import seam never writes outside the config dir,
        // even when the stored cookies_file (CLI-created)
        // points elsewhere. The seam is not called, so no
        // file is written and no .bak is created.
        return Err(err_validation(
            "cookies file is outside the config directory",
        ));
    }
    let Some(seam) = &server.deps.import_cookies else {
        return Err(err_unavailable(
            "cookie import is unavailable in this build",
        ));
    };
    if let Err(e) = seam(name, &content) {
        return Err(err_validation(safe_message_str(&e)));
    }
    // verified:false — this build performs no live
    // verification after import; claiming otherwise would
    // be a false pass.
    let mut map = OrderedObject::new();
    map.set("saved", JsonValue::Bool(true));
    map.set("verified", JsonValue::Bool(false));
    Ok(envelope_resp(200, JsonValue::Object(map)))
}

fn route_login_restore(server: &Server, name: &str) -> RouteOutcome {
    RouteOutcome::Handled(done(handle_login_restore(server, name)))
}

fn handle_login_restore(server: &Server, name: &str) -> Result<Resp, ApiError> {
    // No body decode (Go reads no body here).
    let (cookies_file, _) = resolve_cookies_file(server, name)?;
    if !crate::contain::contained_in_dir(&cookies_file, cfg_dir(server)) {
        // Same containment as login import: restore never
        // touches a cookies file outside the config dir.
        return Err(err_validation(
            "cookies file is outside the config directory",
        ));
    }
    let Some(seam) = &server.deps.restore_cookies else {
        return Err(err_unavailable(
            "cookie restore is unavailable in this build",
        ));
    };
    match seam(name) {
        Err(e) => {
            if e == ERR_NO_BACKUP_MSG {
                return Err(err_not_found("no backup cookies file"));
            }
            Err(err_validation(safe_message_str(&e)))
        }
        Ok(restored) => {
            let mut map = OrderedObject::new();
            map.set("restored", JsonValue::Bool(restored));
            Ok(envelope_resp(200, JsonValue::Object(map)))
        }
    }
}

// --- outbounds / endpoints ------------------------------------

/// `outboundSummary` / `endpointSummary` field order: tag,
/// type, summary, used_by. `used_by` is `null` when the
/// list is empty (Go's nil `[]string`).
fn section_summary_json(tag: &str, typ: &str, summary: &str, used_by: Vec<String>) -> JsonValue {
    let mut obj = OrderedObject::new();
    obj.set("tag", JsonValue::Str(tag.to_string()));
    obj.set("type", JsonValue::Str(typ.to_string()));
    obj.set("summary", JsonValue::Str(summary.to_string()));
    if used_by.is_empty() {
        obj.set("used_by", JsonValue::Null);
    } else {
        obj.set(
            "used_by",
            JsonValue::Array(used_by.into_iter().map(JsonValue::Str).collect()),
        );
    }
    JsonValue::Object(obj)
}

fn outbound_summary_for(
    cfg: &SingleConfig,
    raw: &OrderedObject,
    raw_by_tag: &std::collections::HashMap<String, OrderedObject>,
) -> JsonValue {
    let tag = obj_str(raw, "tag").unwrap_or_default();
    let typ = obj_str(raw, "type").unwrap_or_default();
    let summary = match raw_by_tag.get(&tag) {
        Some(obj) => summarize_object(obj),
        None => typ.clone(),
    };
    section_summary_json(&tag, &typ, &summary, used_by_outbound(cfg, &tag))
}

fn endpoint_summary_for(
    cfg: &SingleConfig,
    raw: &OrderedObject,
    raw_outbounds: &[OrderedObject],
    raw_by_tag: &std::collections::HashMap<String, OrderedObject>,
) -> JsonValue {
    let tag = obj_str(raw, "tag").unwrap_or_default();
    let typ = obj_str(raw, "type").unwrap_or_default();
    let summary = match raw_by_tag.get(&tag) {
        Some(obj) => summarize_object(obj),
        None => typ.clone(),
    };
    let _ = raw_outbounds;
    section_summary_json(&tag, &typ, &summary, used_by_endpoint(cfg, &tag))
}

fn raw_by_tag(raw: &[OrderedObject]) -> std::collections::HashMap<String, OrderedObject> {
    let mut map = std::collections::HashMap::new();
    for obj in raw {
        if let Some(tag) = obj_str(obj, "tag") {
            map.insert(tag, obj.clone());
        }
    }
    map
}

fn route_list_outbounds(server: &Server) -> RouteOutcome {
    RouteOutcome::Handled(done(handle_list_outbounds(server)))
}

fn handle_list_outbounds(server: &Server) -> Result<Resp, ApiError> {
    let load = load(server)?;
    let (cfg, _) = parse_loaded(&load, cfg_dir(server))?;
    let (raw_outbounds, _) = raw_sections(&load)?;
    let by_tag = raw_by_tag(&raw_outbounds);
    let mut out: Vec<JsonValue> = Vec::new();
    for raw in &cfg.outbounds_raw {
        if let JsonValue::Object(obj) = raw {
            out.push(outbound_summary_for(&cfg, obj, &by_tag));
        }
    }
    Ok(envelope_resp(200, JsonValue::Array(out)))
}

fn route_get_outbound(server: &Server, tag: &str) -> RouteOutcome {
    RouteOutcome::Handled(done(handle_get_outbound(server, tag)))
}

fn handle_get_outbound(server: &Server, tag: &str) -> Result<Resp, ApiError> {
    let load = load(server)?;
    let _ = parse_loaded(&load, cfg_dir(server))?;
    let (raw_outbounds, _) = raw_sections(&load)?;
    for obj in &raw_outbounds {
        if obj_str(obj, "tag").as_deref() == Some(tag) {
            return Ok(envelope_resp(
                200,
                redact_value(&JsonValue::Object(obj.clone())),
            ));
        }
    }
    Err(err_not_found("outbound not found"))
}

/// `outboundSummaryAfter`: re-loads; any load/parse
/// failure degrades to `{Tag}` only.
fn outbound_summary_after(server: &Server, tag: &str) -> JsonValue {
    let tag_only = || section_summary_json(tag, "", "", Vec::new());
    let Ok(load) = load(server) else {
        return tag_only();
    };
    let Ok((cfg, _)) = parse_loaded(&load, cfg_dir(server)) else {
        return tag_only();
    };
    let (raw_outbounds, _) = raw_sections(&load).unwrap_or_default();
    let by_tag = raw_by_tag(&raw_outbounds);
    for raw in &cfg.outbounds_raw {
        if let JsonValue::Object(obj) = raw
            && obj_str(obj, "tag").as_deref() == Some(tag)
        {
            return outbound_summary_for(&cfg, obj, &by_tag);
        }
    }
    tag_only()
}

/// `endpointSummaryAfter`: same degradation as outbounds.
fn endpoint_summary_after(server: &Server, tag: &str) -> JsonValue {
    let tag_only = || section_summary_json(tag, "", "", Vec::new());
    let Ok(load) = load(server) else {
        return tag_only();
    };
    let Ok((cfg, _)) = parse_loaded(&load, cfg_dir(server)) else {
        return tag_only();
    };
    let (raw_outbounds, raw_endpoints) = raw_sections(&load).unwrap_or_default();
    let by_tag = raw_by_tag(&raw_endpoints);
    for raw in &cfg.endpoints_raw {
        if let JsonValue::Object(obj) = raw
            && obj_str(obj, "tag").as_deref() == Some(tag)
        {
            return endpoint_summary_for(&cfg, obj, &raw_outbounds, &by_tag);
        }
    }
    tag_only()
}

/// Decode a `{outbound: ...}` / `{endpoint: ...}` body.
/// Missing key → `None` (the 400 "must be an object" is
/// the caller's); a present non-object → a decode error.
fn section_body(body: &[u8], key: &str) -> Result<Option<JsonValue>, ApiError> {
    decode_body_typed(body, BODY_CAP_1M, &[key], |obj| Ok(obj.get(key).cloned()))
}

fn route_create_outbound(server: &Server, body: &[u8]) -> RouteOutcome {
    RouteOutcome::Handled(done(handle_create_outbound(server, body)))
}

fn handle_create_outbound(server: &Server, body: &[u8]) -> Result<Resp, ApiError> {
    let section = section_body(body, "outbound")?;
    let Some(JsonValue::Object(outbound)) = section else {
        return Err(err_validation("outbound must be an object"));
    };
    let tag = obj_str(&outbound, "tag").unwrap_or_default();
    if tag.trim().is_empty() {
        return Err(err_validation("outbound requires a tag"));
    }
    let load = load(server)?;
    let tag_c = tag.clone();
    let outbound_c = JsonValue::Object(outbound);
    let outcome = save_direct(&load, cfg_dir(server), move |doc| {
        let JsonValue::Object(doc_obj) = doc else {
            return Err(err_validation("config document must be a JSON object"));
        };
        let mut arr: Vec<JsonValue> = match doc_obj.get("outbounds") {
            Some(JsonValue::Array(items)) => items.clone(),
            _ => Vec::new(),
        };
        for elem in &arr {
            if let JsonValue::Object(obj) = elem
                && obj_str(obj, "tag").as_deref() == Some(tag_c.as_str())
            {
                return Err(err_validation("outbound already exists"));
            }
        }
        // A new element has no stored counterpart: any
        // sentinel inside it rejects (adoptNew semantics).
        let merged = merge_node_at(None, &outbound_c, "outbounds").map_err(|rej| {
            err_validation(format!(
                "redacted value at {} has no stored value to keep",
                rej.path
            ))
        })?;
        arr.push(merged);
        doc_obj.set("outbounds".to_string(), JsonValue::Array(arr));
        Ok(())
    })?;
    refresh(server, &outcome);
    Ok(envelope_resp(200, outbound_summary_after(server, &tag)))
}

fn route_patch_outbound(server: &Server, tag: &str, body: &[u8]) -> RouteOutcome {
    RouteOutcome::Handled(done(handle_patch_outbound(server, tag, body)))
}

fn handle_patch_outbound(server: &Server, tag: &str, body: &[u8]) -> Result<Resp, ApiError> {
    let section = section_body(body, "outbound")?;
    let Some(JsonValue::Object(outbound)) = section else {
        return Err(err_validation("outbound must be an object"));
    };
    // PATCH is a full-object replacement with the sentinel
    // merge: the client sends the complete redacted object
    // from the detail view. The tag must stay identical.
    if obj_str(&outbound, "tag").as_deref().unwrap_or("") != tag {
        return Err(err_validation(
            "outbound tag must not change; delete and recreate to rename",
        ));
    }
    let load = load(server)?;
    let tag_c = tag.to_string();
    let outbound_c = JsonValue::Object(outbound);
    let outcome = save_direct(&load, cfg_dir(server), move |doc| {
        let JsonValue::Object(doc_obj) = doc else {
            return Err(err_validation("config document must be a JSON object"));
        };
        let mut arr: Vec<JsonValue> = match doc_obj.get("outbounds") {
            Some(JsonValue::Array(items)) => items.clone(),
            _ => Vec::new(),
        };
        for (i, elem) in arr.iter().enumerate() {
            let JsonValue::Object(obj) = elem else {
                continue;
            };
            if obj_str(obj, "tag").as_deref() == Some(tag_c.as_str()) {
                let merged = merge_node_at(Some(elem), &outbound_c, &format!("outbounds[{i}]"))
                    .map_err(|rej| {
                        err_validation(format!(
                            "redacted value at {} has no stored value to keep",
                            rej.path
                        ))
                    })?;
                arr[i] = merged;
                doc_obj.set("outbounds".to_string(), JsonValue::Array(arr));
                return Ok(());
            }
        }
        Err(err_not_found("outbound not found"))
    })?;
    refresh(server, &outcome);
    Ok(envelope_resp(200, outbound_summary_after(server, tag)))
}

fn route_delete_outbound(server: &Server, tag: &str) -> RouteOutcome {
    RouteOutcome::Handled(done(handle_delete_outbound(server, tag)))
}

fn handle_delete_outbound(server: &Server, tag: &str) -> Result<Resp, ApiError> {
    let load = load(server)?;
    let tag_c = tag.to_string();
    let outcome = save_direct(&load, cfg_dir(server), move |doc| {
        let JsonValue::Object(doc_obj) = doc else {
            return Err(err_validation("config document must be a JSON object"));
        };
        let arr: Vec<JsonValue> = match doc_obj.get("outbounds") {
            Some(JsonValue::Array(items)) => items.clone(),
            _ => Vec::new(),
        };
        let mut kept: Vec<JsonValue> = Vec::new();
        let mut found = false;
        for elem in arr {
            if let JsonValue::Object(obj) = &elem
                && obj_str(obj, "tag").as_deref() == Some(tag_c.as_str())
            {
                found = true;
                continue;
            }
            kept.push(elem);
        }
        if !found {
            return Err(err_not_found("outbound not found"));
        }
        // An empty array is kept (not a deleted key).
        doc_obj.set("outbounds".to_string(), JsonValue::Array(kept));
        Ok(())
    })?;
    refresh(server, &outcome);
    let mut map = OrderedObject::new();
    map.set("deleted", JsonValue::Bool(true));
    Ok(envelope_resp(200, JsonValue::Object(map)))
}

fn route_validate_outbound(server: &Server, body: &[u8]) -> RouteOutcome {
    RouteOutcome::Handled(done(handle_validate_outbound(server, body)))
}

fn handle_validate_outbound(server: &Server, body: &[u8]) -> Result<Resp, ApiError> {
    let section = section_body(body, "outbound")?;
    let Some(JsonValue::Object(outbound)) = section else {
        return Err(err_validation("outbound must be an object"));
    };
    let load = load(server)?;
    // Validate by appending to a COPY of the stored
    // document and parsing the whole: no write happens on
    // any path.
    let mut stored = JsonValue::Object(OrderedObject::new());
    if !load.raw.is_empty() {
        let text = String::from_utf8_lossy(&load.raw).into_owned();
        stored = decode_first_value(text.as_bytes()).map_err(|e| {
            err_validation(format!(
                "stored config is invalid: {}",
                safe_message_str(&e.message)
            ))
        })?;
    }
    let JsonValue::Object(mut stored_obj) = stored else {
        return Err(err_validation("config document must be a JSON object"));
    };
    if let Err(rej) = merge_node_at(None, &JsonValue::Object(outbound.clone()), "outbounds") {
        return Ok(valid_resp(
            false,
            &[format!(
                "redacted value at {} has no stored value to keep",
                rej.path
            )],
        ));
    }
    let mut arr: Vec<JsonValue> = match stored_obj.get("outbounds") {
        Some(JsonValue::Array(items)) => items.clone(),
        _ => Vec::new(),
    };
    arr.push(JsonValue::Object(outbound));
    stored_obj.set("outbounds".to_string(), JsonValue::Array(arr));
    let merged = castctl_config::jsonvalue::encode_ordered_json(&JsonValue::Object(stored_obj))
        .map_err(|e| err_validation(e.message))?;
    match parse_and_validate_config(merged.as_bytes(), cfg_dir(server)) {
        Ok(_) => Ok(valid_resp(true, &[])),
        Err(e) => Ok(valid_resp(false, &[safe_message_str(&e)])),
    }
}

/// `{errors, valid}` (sorted keys), for the validate
/// endpoints: validity is a 200, never an error status.
fn valid_resp(valid: bool, errors: &[String]) -> Resp {
    let mut map = OrderedObject::new();
    map.set(
        "errors",
        JsonValue::Array(errors.iter().map(|e| JsonValue::Str(e.clone())).collect()),
    );
    map.set("valid", JsonValue::Bool(valid));
    envelope_resp(200, JsonValue::Object(map))
}

fn route_list_endpoints(server: &Server) -> RouteOutcome {
    RouteOutcome::Handled(done(handle_list_endpoints(server)))
}

fn handle_list_endpoints(server: &Server) -> Result<Resp, ApiError> {
    let load = load(server)?;
    let (cfg, _) = parse_loaded(&load, cfg_dir(server))?;
    let (raw_outbounds, raw_endpoints) = raw_sections(&load)?;
    let by_tag = raw_by_tag(&raw_endpoints);
    let mut out: Vec<JsonValue> = Vec::new();
    for raw in &cfg.endpoints_raw {
        if let JsonValue::Object(obj) = raw {
            out.push(endpoint_summary_for(&cfg, obj, &raw_outbounds, &by_tag));
        }
    }
    Ok(envelope_resp(200, JsonValue::Array(out)))
}

fn route_get_endpoint(server: &Server, tag: &str) -> RouteOutcome {
    RouteOutcome::Handled(done(handle_get_endpoint(server, tag)))
}

fn handle_get_endpoint(server: &Server, tag: &str) -> Result<Resp, ApiError> {
    let load = load(server)?;
    let _ = parse_loaded(&load, cfg_dir(server))?;
    let (_, raw_endpoints) = raw_sections(&load)?;
    for obj in &raw_endpoints {
        if obj_str(obj, "tag").as_deref() == Some(tag) {
            return Ok(envelope_resp(
                200,
                redact_value(&JsonValue::Object(obj.clone())),
            ));
        }
    }
    Err(err_not_found("endpoint not found"))
}

fn route_create_endpoint(server: &Server, body: &[u8]) -> RouteOutcome {
    RouteOutcome::Handled(done(handle_create_endpoint(server, body)))
}

fn handle_create_endpoint(server: &Server, body: &[u8]) -> Result<Resp, ApiError> {
    let section = section_body(body, "endpoint")?;
    let Some(JsonValue::Object(endpoint)) = section else {
        return Err(err_validation("endpoint must be an object"));
    };
    let tag = obj_str(&endpoint, "tag").unwrap_or_default();
    if tag.trim().is_empty() {
        return Err(err_validation("endpoint requires a tag"));
    }
    let load = load(server)?;
    let tag_c = tag.clone();
    let endpoint_c = JsonValue::Object(endpoint);
    let outcome = save_direct(&load, cfg_dir(server), move |doc| {
        let JsonValue::Object(doc_obj) = doc else {
            return Err(err_validation("config document must be a JSON object"));
        };
        let mut arr: Vec<JsonValue> = match doc_obj.get("endpoints") {
            Some(JsonValue::Array(items)) => items.clone(),
            _ => Vec::new(),
        };
        for elem in &arr {
            if let JsonValue::Object(obj) = elem
                && obj_str(obj, "tag").as_deref() == Some(tag_c.as_str())
            {
                return Err(err_validation("endpoint already exists"));
            }
        }
        let merged = merge_node_at(None, &endpoint_c, "endpoints").map_err(|rej| {
            err_validation(format!(
                "redacted value at {} has no stored value to keep",
                rej.path
            ))
        })?;
        arr.push(merged);
        doc_obj.set("endpoints".to_string(), JsonValue::Array(arr));
        Ok(())
    })?;
    refresh(server, &outcome);
    Ok(envelope_resp(200, endpoint_summary_after(server, &tag)))
}

fn route_patch_endpoint(server: &Server, tag: &str, body: &[u8]) -> RouteOutcome {
    RouteOutcome::Handled(done(handle_patch_endpoint(server, tag, body)))
}

fn handle_patch_endpoint(server: &Server, tag: &str, body: &[u8]) -> Result<Resp, ApiError> {
    let section = section_body(body, "endpoint")?;
    let Some(JsonValue::Object(endpoint)) = section else {
        return Err(err_validation("endpoint must be an object"));
    };
    if obj_str(&endpoint, "tag").as_deref().unwrap_or("") != tag {
        return Err(err_validation(
            "endpoint tag must not change; delete and recreate to rename",
        ));
    }
    let load = load(server)?;
    let tag_c = tag.to_string();
    let endpoint_c = JsonValue::Object(endpoint);
    let outcome = save_direct(&load, cfg_dir(server), move |doc| {
        let JsonValue::Object(doc_obj) = doc else {
            return Err(err_validation("config document must be a JSON object"));
        };
        let mut arr: Vec<JsonValue> = match doc_obj.get("endpoints") {
            Some(JsonValue::Array(items)) => items.clone(),
            _ => Vec::new(),
        };
        for (i, elem) in arr.iter().enumerate() {
            let JsonValue::Object(obj) = elem else {
                continue;
            };
            if obj_str(obj, "tag").as_deref() == Some(tag_c.as_str()) {
                let merged = merge_node_at(Some(elem), &endpoint_c, &format!("endpoints[{i}]"))
                    .map_err(|rej| {
                        err_validation(format!(
                            "redacted value at {} has no stored value to keep",
                            rej.path
                        ))
                    })?;
                arr[i] = merged;
                doc_obj.set("endpoints".to_string(), JsonValue::Array(arr));
                return Ok(());
            }
        }
        Err(err_not_found("endpoint not found"))
    })?;
    refresh(server, &outcome);
    Ok(envelope_resp(200, endpoint_summary_after(server, tag)))
}

fn route_delete_endpoint(server: &Server, tag: &str) -> RouteOutcome {
    RouteOutcome::Handled(done(handle_delete_endpoint(server, tag)))
}

fn handle_delete_endpoint(server: &Server, tag: &str) -> Result<Resp, ApiError> {
    let load = load(server)?;
    let tag_c = tag.to_string();
    let outcome = save_direct(&load, cfg_dir(server), move |doc| {
        let JsonValue::Object(doc_obj) = doc else {
            return Err(err_validation("config document must be a JSON object"));
        };
        let arr: Vec<JsonValue> = match doc_obj.get("endpoints") {
            Some(JsonValue::Array(items)) => items.clone(),
            _ => Vec::new(),
        };
        let mut kept: Vec<JsonValue> = Vec::new();
        let mut found = false;
        for elem in arr {
            if let JsonValue::Object(obj) = &elem
                && obj_str(obj, "tag").as_deref() == Some(tag_c.as_str())
            {
                found = true;
                continue;
            }
            kept.push(elem);
        }
        if !found {
            return Err(err_not_found("endpoint not found"));
        }
        doc_obj.set("endpoints".to_string(), JsonValue::Array(kept));
        Ok(())
    })?;
    refresh(server, &outcome);
    let mut map = OrderedObject::new();
    map.set("deleted", JsonValue::Bool(true));
    Ok(envelope_resp(200, JsonValue::Object(map)))
}

fn route_import_endpoint(server: &Server, body: &[u8]) -> RouteOutcome {
    RouteOutcome::Handled(done(handle_import_endpoint(server, body)))
}

fn handle_import_endpoint(server: &Server, body: &[u8]) -> Result<Resp, ApiError> {
    let (tag, conf_text, save) =
        decode_body_typed(body, BODY_CAP_64K, &["tag", "conf_text", "save"], |obj| {
            let tag = req_string(obj, "tag")?.unwrap_or_default();
            let conf_text = req_string(obj, "conf_text")?.unwrap_or_default();
            let save = req_bool(obj, "save")?.unwrap_or(false);
            Ok((tag, conf_text, save))
        })?;
    if tag.trim().is_empty() {
        return Err(err_validation("endpoint tag is required"));
    }
    if tag.trim() != tag {
        return Err(err_validation(
            "endpoint tag must not have surrounding whitespace",
        ));
    }
    let parsed =
        parse_wireguard_conf(conf_text.as_bytes()).map_err(|e| err_validation(e.message()))?;
    let mut endpoint = parsed.endpoint.clone();
    with_type_and_tag(&mut endpoint, &tag);
    if !save {
        // Preview: the redacted endpoint object as JSON text.
        let preview = preview_endpoint(&endpoint);
        let mut map = OrderedObject::new();
        map.set("preview", JsonValue::Str(preview));
        return Ok(envelope_resp(200, JsonValue::Object(map)));
    }
    let load = load(server)?;
    let tag_c = tag.clone();
    let dns_servers = parsed.dns_servers.clone();
    let outcome = save_direct(&load, cfg_dir(server), move |doc| {
        let JsonValue::Object(doc_obj) = doc else {
            return Err(err_validation("config document must be a JSON object"));
        };
        let mut arr: Vec<JsonValue> = match doc_obj.get("endpoints") {
            Some(JsonValue::Array(items)) => items.clone(),
            _ => Vec::new(),
        };
        for elem in &arr {
            if let JsonValue::Object(obj) = elem
                && obj_str(obj, "tag").as_deref() == Some(tag_c.as_str())
            {
                return Err(err_validation("endpoint already exists"));
            }
        }
        arr.push(endpoint.clone());
        doc_obj.set("endpoints".to_string(), JsonValue::Array(arr));
        if !dns_servers.is_empty() {
            let mut wg_dns: OrderedObject = match doc_obj.get("wireguard_dns") {
                Some(JsonValue::Object(o)) => o.clone(),
                _ => OrderedObject::new(),
            };
            wg_dns.set(
                tag_c.clone(),
                JsonValue::Array(
                    dns_servers
                        .iter()
                        .map(|s| JsonValue::Str(s.clone()))
                        .collect(),
                ),
            );
            doc_obj.set("wireguard_dns".to_string(), JsonValue::Object(wg_dns));
        }
        Ok(())
    })?;
    refresh(server, &outcome);
    Ok(envelope_resp(200, endpoint_summary_after(server, &tag)))
}

// --- config / dns ----------------------------------------------

fn route_get_config(server: &Server) -> RouteOutcome {
    RouteOutcome::Handled(done(handle_get_config(server)))
}

fn handle_get_config(server: &Server) -> Result<Resp, ApiError> {
    let load = load(server)?;
    if load.state.exists && !load.state.found {
        return Err(err_validation(
            "legacy layout: run castctl config migrate in the CLI; the web UI does not migrate",
        ));
    }
    if !load.state.found {
        return Err(err_not_found("no config file"));
    }
    let (cfg, _) = parse_loaded(&load, cfg_dir(server))?;
    let redacted = redact_raw_config(&load.raw).map_err(|e| {
        err_validation(format!(
            "stored config is invalid: {}",
            safe_message_str(&e)
        ))
    })?;
    let mut map = OrderedObject::new();
    map.set("content", JsonValue::Str(redacted));
    map.set("sha256", JsonValue::Str(load.hash.clone()));
    map.set(
        "source",
        JsonValue::Str(config_source(&load, cfg_dir(server), &cfg)),
    );
    Ok(envelope_resp(200, JsonValue::Object(map)))
}

fn route_put_config(server: &Server, body: &[u8]) -> RouteOutcome {
    RouteOutcome::Handled(done(handle_put_config(server, body)))
}

fn handle_put_config(server: &Server, body: &[u8]) -> Result<Resp, ApiError> {
    let (content, base_sha) =
        decode_body_typed(body, BODY_CAP_1M, &["content", "base_sha256"], |obj| {
            Ok((
                req_string(obj, "content")?.unwrap_or_default(),
                req_string(obj, "base_sha256")?.unwrap_or_default(),
            ))
        })?;
    let submitted = decode_first_value(content.as_bytes())
        .map_err(|_| err_validation("config content is not valid JSON"))?;
    let load = load(server)?;
    let outcome = save_submitted(&load, cfg_dir(server), &base_sha, &submitted)?;
    refresh(server, &outcome);
    let mut map = OrderedObject::new();
    map.set("sha256", JsonValue::Str(outcome.sha256));
    Ok(envelope_resp(200, JsonValue::Object(map)))
}

fn route_validate_config(server: &Server, body: &[u8]) -> RouteOutcome {
    RouteOutcome::Handled(done(handle_validate_config(server, body)))
}

fn handle_validate_config(server: &Server, body: &[u8]) -> Result<Resp, ApiError> {
    let content = decode_body_typed(body, BODY_CAP_1M, &["content"], |obj| {
        Ok(req_string(obj, "content")?.unwrap_or_default())
    })?;
    match parse_and_validate_config(content.as_bytes(), cfg_dir(server)) {
        Ok(_) => Ok(valid_resp(true, &[])),
        Err(e) => Ok(valid_resp(false, &[safe_message_str(&e)])),
    }
}

fn route_get_dns(server: &Server) -> RouteOutcome {
    RouteOutcome::Handled(done(handle_get_dns(server)))
}

fn handle_get_dns(server: &Server) -> Result<Resp, ApiError> {
    let load = load(server)?;
    let _ = parse_loaded(&load, cfg_dir(server))?;
    let mut dns = JsonValue::Object(OrderedObject::new());
    if !load.raw.is_empty() {
        let text = String::from_utf8_lossy(&load.raw).into_owned();
        if let Ok(doc) = decode_first_value(text.as_bytes())
            && let JsonValue::Object(root) = &doc
            && let Some(JsonValue::Object(section)) = root.get("dns")
        {
            dns = JsonValue::Object(section.clone());
        }
    }
    let mut map = OrderedObject::new();
    map.set("dns", redact_value(&dns));
    map.set("sha256", JsonValue::Str(load.hash.clone()));
    Ok(envelope_resp(200, JsonValue::Object(map)))
}

fn route_put_dns(server: &Server, body: &[u8]) -> RouteOutcome {
    RouteOutcome::Handled(done(handle_put_dns(server, body)))
}

fn handle_put_dns(server: &Server, body: &[u8]) -> Result<Resp, ApiError> {
    // decodeBody with DisallowUnknownFields would reject the
    // open-ended dns object, so decode generically here.
    let value = decode_body_json(body, BODY_CAP_1M)?;
    let JsonValue::Object(obj) = &value else {
        return Err(err_validation("request body must be a JSON object"));
    };
    let base_sha = obj_str(obj, "base_sha256").unwrap_or_default();
    let Some(submitted) = obj.get("dns").cloned() else {
        return Err(err_validation("dns is required"));
    };
    if !matches!(submitted, JsonValue::Null) && !matches!(submitted, JsonValue::Object(_)) {
        return Err(err_validation("dns must be an object or null"));
    }
    let load = load(server)?;
    if load.hash != base_sha {
        return Err(err_config_changed());
    }
    let mut stored_section: Option<JsonValue> = None;
    if !load.raw.is_empty() {
        let text = String::from_utf8_lossy(&load.raw).into_owned();
        if let Ok(doc) = decode_first_value(text.as_bytes())
            && let JsonValue::Object(root) = &doc
            && let Some(section) = root.get("dns")
        {
            stored_section = Some(section.clone());
        }
    }
    let merged_section: Option<JsonValue> = if matches!(submitted, JsonValue::Null) {
        None
    } else {
        let merged = merge_node_at(stored_section.as_ref(), &submitted, "dns").map_err(|rej| {
            err_validation(format!(
                "redacted value at {} has no stored value to keep",
                rej.path
            ))
        })?;
        Some(merged)
    };
    let outcome = save_merged(&load, cfg_dir(server), &base_sha, move |doc| {
        let JsonValue::Object(doc_obj) = doc else {
            return Err(err_validation("config document must be a JSON object"));
        };
        match &merged_section {
            None => {
                doc_obj.remove("dns");
            }
            Some(section) => {
                doc_obj.set("dns".to_string(), section.clone());
            }
        }
        Ok(())
    })?;
    refresh(server, &outcome);
    let mut map = OrderedObject::new();
    map.set("sha256", JsonValue::Str(outcome.sha256));
    Ok(envelope_resp(200, JsonValue::Object(map)))
}

// --- telegram ---------------------------------------------------

/// `telegramView` field order: configured, masked,
/// profile, allowed_user_ids, auto_approve,
/// auto_allow_once.
fn telegram_view_json(
    configured: bool,
    masked: &str,
    profile: &str,
    allowed_user_ids: &[i64],
    auto_approve: bool,
    auto_allow_once: bool,
) -> JsonValue {
    let mut obj = OrderedObject::new();
    obj.set("configured", JsonValue::Bool(configured));
    obj.set("masked", JsonValue::Str(masked.to_string()));
    obj.set("profile", JsonValue::Str(profile.to_string()));
    obj.set(
        "allowed_user_ids",
        JsonValue::Array(
            allowed_user_ids
                .iter()
                .map(|id| JsonValue::Number(id.to_string()))
                .collect(),
        ),
    );
    obj.set("auto_approve", JsonValue::Bool(auto_approve));
    obj.set("auto_allow_once", JsonValue::Bool(auto_allow_once));
    JsonValue::Object(obj)
}

fn telegram_view_from(cfg: &SingleConfig) -> JsonValue {
    match &cfg.telegram {
        Some(t) => telegram_view_json(
            true,
            "***",
            &t.profile,
            &t.allowed_user_ids,
            t.auto_approve,
            t.auto_allow_once,
        ),
        None => telegram_view_json(false, "", "", &[], false, false),
    }
}

fn route_get_telegram(server: &Server) -> RouteOutcome {
    RouteOutcome::Handled(done(handle_get_telegram(server)))
}

fn handle_get_telegram(server: &Server) -> Result<Resp, ApiError> {
    let load = load(server)?;
    let (cfg, _) = parse_loaded(&load, cfg_dir(server))?;
    Ok(envelope_resp(200, telegram_view_from(&cfg)))
}

fn route_put_telegram(server: &Server, body: &[u8]) -> RouteOutcome {
    RouteOutcome::Handled(done(handle_put_telegram(server, body)))
}

fn handle_put_telegram(server: &Server, body: &[u8]) -> Result<Resp, ApiError> {
    let (profile, token, ids_raw, auto_approve, auto_allow_once) = decode_body_typed(
        body,
        BODY_CAP_64K,
        &[
            "profile",
            "token",
            "allowed_user_ids",
            "auto_approve",
            "auto_allow_once",
        ],
        |obj| {
            let profile = req_string(obj, "profile")?;
            let token = req_string(obj, "token")?;
            // Go decodes JSON null into a nil slice: `null` means
            // absent (ids unchanged), not an error.
            let ids_raw = match obj.get("allowed_user_ids") {
                Some(JsonValue::Null) | None => None,
                Some(v) => Some(v.clone()),
            };
            let auto_approve = req_bool(obj, "auto_approve")?;
            let auto_allow_once = req_bool(obj, "auto_allow_once")?;
            Ok((profile, token, ids_raw, auto_approve, auto_allow_once))
        },
    )?;
    let mut ids: Vec<i64> = Vec::new();
    let ids_set = ids_raw.is_some();
    if let Some(JsonValue::Array(items)) = &ids_raw {
        for item in items {
            let JsonValue::Number(lit) = item else {
                return Err(err_validation("invalid JSON in request body"));
            };
            let id: i64 = lit
                .parse()
                .map_err(|_| err_validation("invalid JSON in request body"))?;
            if id <= 0 {
                return Err(err_validation(
                    "telegram.allowed_user_ids must contain positive integers only",
                ));
            }
            ids.push(id);
        }
        if ids.is_empty() {
            return Err(err_validation(
                "telegram.allowed_user_ids must not be empty",
            ));
        }
    } else if ids_raw.is_some() {
        return Err(err_validation("invalid JSON in request body"));
    }
    let load = load(server)?;
    let (cfg, _) = parse_loaded(&load, cfg_dir(server))?;
    let default_profile = cfg.default_profile.clone();
    let outcome = save_direct(&load, cfg_dir(server), move |doc| {
        let JsonValue::Object(doc_obj) = doc else {
            return Err(err_validation("config document must be a JSON object"));
        };
        let (mut section, creating) = match doc_obj.get("telegram") {
            Some(JsonValue::Object(o)) => (o.clone(), false),
            _ => (OrderedObject::new(), true),
        };
        if let Some(p) = &profile {
            if p.trim().is_empty() {
                return Err(err_validation("telegram.profile must not be empty"));
            }
            section.set("profile".to_string(), JsonValue::Str(p.clone()));
        } else if creating {
            // Documented zero-value: a created block links
            // the default profile when the body names none.
            if default_profile.is_empty() {
                return Err(err_validation(
                    "telegram.profile is required when no default profile exists",
                ));
            }
            section.set(
                "profile".to_string(),
                JsonValue::Str(default_profile.clone()),
            );
        }
        if let Some(t) = &token {
            // Empty token = unchanged (write-only field).
            // A non-empty token replaces the stored one; its
            // shape is validated by the full-config parse.
            if !t.trim().is_empty() {
                let token = t.trim().to_string();
                // A placeholder is never a token: accepting
                // one would lock the bot out with the
                // redaction marker as its credential.
                if token == "***" || token == crate::auth::REDACTED_MARKER {
                    return Err(err_validation(
                        "telegram.token must be a real bot token, not a placeholder",
                    ));
                }
                section.set("token".to_string(), JsonValue::Str(token));
            } else if creating {
                return Err(err_validation("telegram.token is required"));
            }
        } else if creating {
            return Err(err_validation("telegram.token is required"));
        }
        if ids_set {
            let arr: Vec<JsonValue> = ids
                .iter()
                .map(|id| JsonValue::Number(id.to_string()))
                .collect();
            section.set("allowed_user_ids".to_string(), JsonValue::Array(arr));
        } else if creating {
            return Err(err_validation("telegram.allowed_user_ids is required"));
        }
        if let Some(b) = auto_approve {
            section.set("auto_approve".to_string(), JsonValue::Bool(b));
        }
        if let Some(b) = auto_allow_once {
            section.set("auto_allow_once".to_string(), JsonValue::Bool(b));
        }
        doc_obj.set("telegram".to_string(), JsonValue::Object(section));
        Ok(())
    })?;
    refresh(server, &outcome);
    // Re-read for the response view (masked only, never
    // the token).
    let load2 = load_config(cfg_dir(server))?;
    let (cfg2, _) = parse_loaded(&load2, cfg_dir(server))?;
    Ok(envelope_resp(200, telegram_view_from(&cfg2)))
}

// --- keeper -----------------------------------------------------

fn route_get_keeper(server: &Server) -> RouteOutcome {
    RouteOutcome::Handled(done(handle_get_keeper(server)))
}

fn handle_get_keeper(server: &Server) -> Result<Resp, ApiError> {
    let load = load(server)?;
    let (_, entries) = parse_loaded(&load, cfg_dir(server))?;
    // Go `handleGetKeeper` (handlers.go:1629-1655) wraps each
    // entry in `keeperEntryView{tag, profile, browser,
    // interval_seconds, notify, status}` and sorts by tag.
    // The bare `Status` objects previously pushed here are
    // the wrong document: the frontend reads
    // `entry.browser` / `entry.status.*` from the wrapper.
    let mut views: Vec<(String, JsonValue)> = Vec::new();
    for entry in &entries {
        // A ReadStatus error is a 500 (Go writes the plain
        // error through writeAPIError: 500 internal_error
        // with the safe message). A corrupt state file is
        // NOT an error — read_status returns a status with
        // state_corrupt set.
        let st = read_status(cfg_dir(server), entry)
            .map_err(|e| ApiError::new(500, "internal_error", safe_message_str(&e)))?;
        let mut view = OrderedObject::new();
        view.set("tag", JsonValue::Str(entry.tag.clone()));
        view.set("profile", JsonValue::Str(entry.profile.clone()));
        view.set("browser", JsonValue::Str(entry.browser.clone()));
        view.set(
            "interval_seconds",
            JsonValue::Number((entry.effective_interval_ns() / 1_000_000_000).to_string()),
        );
        view.set("notify", JsonValue::Str(entry.notify.clone()));
        view.set("status", st.to_json());
        views.push((entry.tag.clone(), JsonValue::Object(view)));
    }
    views.sort_by(|a, b| a.0.cmp(&b.0));
    let out: Vec<JsonValue> = views.into_iter().map(|(_, v)| v).collect();
    Ok(envelope_resp(200, JsonValue::Array(out)))
}

// --- chats ------------------------------------------------------

fn query_pairs(uri: &hyper::Uri) -> Vec<(String, String)> {
    parse_query(uri.query().unwrap_or(""))
}

async fn route_list_chats(server: &Arc<Server>, profile: &str, uri: &hyper::Uri) -> RouteOutcome {
    RouteOutcome::Handled(done(handle_list_chats(server, profile, uri).await))
}

async fn handle_list_chats(
    server: &Arc<Server>,
    profile: &str,
    uri: &hyper::Uri,
) -> Result<Resp, ApiError> {
    require_chat_profile(cfg_dir(server), profile)?;
    let deps = chat_deps(&server.deps.chats)?;
    let query = query_pairs(uri);
    let include_archived = matches!(
        query_value(&query, "include_archived").as_deref(),
        Some("1")
    ) || query_value(&query, "include_archived")
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let sessions = (deps.list_sessions)(profile.to_string(), include_archived)
        .await
        .map_err(|_| err_upstream_chat())?;
    let out: Vec<JsonValue> = sessions.iter().map(|s| s.to_json()).collect();
    Ok(envelope_resp(200, JsonValue::Array(out)))
}

async fn route_start_chat(server: &Arc<Server>, profile: &str, body: &[u8]) -> RouteOutcome {
    RouteOutcome::Handled(done(handle_start_chat(server, profile, body).await))
}

async fn handle_start_chat(
    server: &Arc<Server>,
    profile: &str,
    body: &[u8],
) -> Result<Resp, ApiError> {
    require_chat_profile(cfg_dir(server), profile)?;
    let title = decode_body_typed(body, BODY_CAP_64K, &["title"], |obj| {
        Ok(req_string(obj, "title")?.unwrap_or_default())
    })?;
    let deps = chat_deps(&server.deps.chats)?;
    let id = (deps.start_session)(profile.to_string(), title)
        .await
        .map_err(|_| err_upstream_chat())?;
    let mut map = OrderedObject::new();
    map.set("session_id", JsonValue::Str(id));
    Ok(envelope_resp(201, JsonValue::Object(map)))
}

async fn route_get_chat_history(
    server: &Arc<Server>,
    profile: &str,
    session: &str,
    uri: &hyper::Uri,
) -> RouteOutcome {
    RouteOutcome::Handled(done(
        handle_get_chat_history(server, profile, session, uri).await,
    ))
}

async fn handle_get_chat_history(
    server: &Arc<Server>,
    profile: &str,
    session: &str,
    uri: &hyper::Uri,
) -> Result<Resp, ApiError> {
    require_chat_profile(cfg_dir(server), profile)?;
    let query = query_pairs(uri);
    let mut limit: i64 = 50;
    if let Some(raw) = query_value(&query, "limit") {
        let n: i64 = raw
            .parse()
            .map_err(|_| err_validation("limit must be an integer from 1 to 200"))?;
        if !(1..=200).contains(&n) {
            return Err(err_validation("limit must be an integer from 1 to 200"));
        }
        limit = n;
    }
    let deps = chat_deps(&server.deps.chats)?;
    let events = (deps.get_history)(profile.to_string(), chat_session_id(session), limit)
        .await
        .map_err(|_| err_upstream_chat())?;
    let out: Vec<JsonValue> = events.iter().map(|e| e.to_json()).collect();
    Ok(envelope_resp(200, JsonValue::Array(out)))
}

async fn route_send_chat(
    server: &Arc<Server>,
    profile: &str,
    session: &str,
    body: &[u8],
) -> RouteOutcome {
    RouteOutcome::Handled(done(handle_send_chat(server, profile, session, body).await))
}

async fn handle_send_chat(
    server: &Arc<Server>,
    profile: &str,
    session: &str,
    body: &[u8],
) -> Result<Resp, ApiError> {
    require_chat_profile(cfg_dir(server), profile)?;
    let text = decode_body_typed(body, BODY_CAP_64K, &["text"], |obj| {
        Ok(req_string(obj, "text")?.unwrap_or_default())
    })?;
    if text.trim().is_empty() {
        return Err(err_validation("text must not be empty"));
    }
    let deps = chat_deps(&server.deps.chats)?;
    let session_id = chat_session_id(session);
    let job = server.job_store.create(profile, &session_id)?;
    // The job runs detached from the request: the 30 s API
    // timeout cancels the request context, but a turn
    // legitimately runs longer. The job's own 150 s budget
    // bounds it instead. A panic on the send path fails the
    // job, never the server (the recoverer runs on the
    // request task only).
    let server_c = Arc::clone(server);
    let deps_c = Arc::clone(&deps);
    let profile_c = profile.to_string();
    let job_id = job.id.clone();
    tokio::spawn(async move {
        use futures_util::FutureExt;
        let fut = (deps_c.send_chat)(profile_c, session_id, text);
        let guarded = std::panic::AssertUnwindSafe(fut).catch_unwind();
        match tokio::time::timeout(
            std::time::Duration::from_secs(crate::chats::CHAT_JOB_TIMEOUT_SECS),
            guarded,
        )
        .await
        {
            Err(_) => {
                server_c.job_store.finish(&job_id, None, "send timed out");
            }
            Ok(Err(_)) => {
                server_c.job_store.finish(&job_id, None, "upstream error");
            }
            Ok(Ok(Err(_))) => {
                server_c.job_store.finish(&job_id, None, "upstream error");
            }
            Ok(Ok(Ok(result))) => {
                server_c.job_store.finish(&job_id, Some(result), "");
            }
        }
    });
    Ok(envelope_resp(202, job.view()))
}

fn route_get_chat_job(server: &Server, job: &str) -> RouteOutcome {
    RouteOutcome::Handled(done(handle_get_chat_job(server, job)))
}

fn handle_get_chat_job(server: &Server, job: &str) -> Result<Resp, ApiError> {
    // No profile check, no seam: the store alone answers.
    match server.job_store.get(job) {
        Some(j) => Ok(envelope_resp(200, j.view())),
        None => Err(err_not_found("job not found")),
    }
}

async fn route_chat_session_op(
    server: &Arc<Server>,
    profile: &str,
    session: &str,
    body: &[u8],
) -> RouteOutcome {
    RouteOutcome::Handled(done(
        handle_chat_session_op(server, profile, session, body).await,
    ))
}

async fn handle_chat_session_op(
    server: &Arc<Server>,
    profile: &str,
    session: &str,
    body: &[u8],
) -> Result<Resp, ApiError> {
    require_chat_profile(cfg_dir(server), profile)?;
    let (op, title) = decode_body_typed(body, BODY_CAP_64K, &["op", "title"], |obj| {
        Ok((
            req_string(obj, "op")?.unwrap_or_default(),
            req_string(obj, "title")?.unwrap_or_default(),
        ))
    })?;
    if !matches!(
        op.as_str(),
        "rename" | "pin" | "unpin" | "archive" | "unarchive" | "delete"
    ) {
        return Err(err_validation(
            "op must be one of rename, pin, unpin, archive, unarchive, delete",
        ));
    }
    let session_id = chat_session_id(session);
    if session_id.is_empty() {
        return Err(err_validation(
            "session operations do not apply to the main chat",
        ));
    }
    if op == "rename" && title.trim().is_empty() {
        return Err(err_validation("title must not be empty for rename"));
    }
    let deps = chat_deps(&server.deps.chats)?;
    (deps.session_op)(profile.to_string(), session_id, op, title)
        .await
        .map_err(|_| err_upstream_chat())?;
    let mut map = OrderedObject::new();
    map.set("ok", JsonValue::Bool(true));
    Ok(envelope_resp(200, JsonValue::Object(map)))
}

// --- settings ---------------------------------------------------

fn route_get_keeper_settings(server: &Server) -> RouteOutcome {
    RouteOutcome::Handled(done((|| {
        let load = load(server)?;
        handle_get_keeper_settings(cfg_dir(server), &load)
    })()))
}

fn route_put_keeper_settings(server: &Server, body: &[u8]) -> RouteOutcome {
    RouteOutcome::Handled(
        match (|| {
            let load = load(server)?;
            handle_put_keeper_settings(cfg_dir(server), &load, body)
        })() {
            Ok((resp, outcome)) => {
                refresh(server, &outcome);
                resp
            }
            Err(e) => api_error_resp(&e),
        },
    )
}

fn route_get_webui_settings(server: &Server) -> RouteOutcome {
    RouteOutcome::Handled(done((|| {
        let load = load(server)?;
        handle_get_webui_settings(cfg_dir(server), &load)
    })()))
}

fn route_put_webui_settings(server: &Server, body: &[u8]) -> RouteOutcome {
    RouteOutcome::Handled(
        match (|| {
            let load = load(server)?;
            handle_put_webui_settings(cfg_dir(server), &load, body)
        })() {
            Ok((resp, outcome)) => {
                refresh(server, &outcome);
                resp
            }
            Err(e) => api_error_resp(&e),
        },
    )
}

// --- logs -------------------------------------------------------

fn route_get_logs(server: &Server, uri: &hyper::Uri) -> RouteOutcome {
    RouteOutcome::Handled(done((|| {
        let load = load(server)?;
        handle_get_logs(cfg_dir(server), &load, &query_pairs(uri))
    })()))
}

// --- screencast -------------------------------------------------

fn route_screencast_status(server: &Server, uri: &hyper::Uri) -> RouteOutcome {
    RouteOutcome::Handled(done((|| {
        let load = load(server)?;
        handle_screencast_status(cfg_dir(server), &load, &query_pairs(uri))
    })()))
}

fn route_screencast_start(server: &Server, profile: &str) -> RouteOutcome {
    let resp = (|| {
        let load = load(server)?;
        Ok::<Resp, ApiError>(handle_screencast_start(
            cfg_dir(server),
            &server.sessions,
            &load,
            profile,
            server.deps.screencast_starter.is_some(),
        ))
    })();
    RouteOutcome::Handled(done(resp))
}

fn route_screencast_ws(server: &Server, uri: &hyper::Uri) -> RouteOutcome {
    // Plain-HTTP GET /screencast/ws (no Upgrade header):
    // the WS upgrade itself is intercepted in
    // server.rs before routing. This branch answers the
    // same pre-upgrade checks over plain HTTP.
    let query = query_pairs(uri);
    let session = query_value(&query, "session").unwrap_or_default();
    RouteOutcome::Handled(handle_screencast_ws_http(
        &server.sessions,
        &session,
        server.deps.screencast_starter.is_some(),
    ))
}

// --- handler unit tests -----------------------------------------
// Behaviour pinned 1:1 from Go's *_test.go where the
// behaviour is observable without a live gateway. Live
// parity (status + headers + body) is the cue gate in
// PORTING.md §M6b, not these tests.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::Server;

    fn test_server(dir: &std::path::Path) -> Arc<Server> {
        let token_hash = crate::auth::hash_token("plain-token").expect("hash test token");
        Server::new(crate::server::Deps {
            config_dir: dir.to_path_buf(),
            version: "0.9.0".to_string(),
            listen_addr: "127.0.0.1:18318".to_string(),
            token_hash,
            has_token: true,
            bundle_sha256: crate::static_shell::bundle_sha256(),
            ui_dir: None,
            cookies_files: Vec::new(),
            import_cookies: None,
            restore_cookies: None,
            screencast_available: None,
            screencast_starter: None,
            chats: None,
        })
        .expect("test server builds")
    }

    fn write_config(dir: &std::path::Path, text: &str) {
        std::fs::write(dir.join("config.json"), text).expect("write fixture config");
    }

    const FIXTURE: &str = r#"{
  "default_profile": "muse01",
  "profiles": {
    "muse01": {
      "cookies_file": "profiles/muse01/cookies.txt",
      "outbound": "proxy-eu",
      "fingerprint": "chrome"
    }
  },
  "outbounds": [
    {"type": "trojan", "tag": "proxy-eu", "server": "203.0.113.10", "server_port": 443, "password": "SECRET-TROJAN"}
  ],
  "endpoints": [
    {"type": "wireguard", "tag": "wg-home", "address": ["10.0.0.2/32"], "private_key": "SECRET-WG", "peers": [{"address": "203.0.113.10", "port": 51820, "public_key": "SECRET-PUB", "allowed_ips": ["0.0.0.0/0"]}]}
  ],
  "dns": {"servers": [{"tag": "dns1", "type": "tcp", "server": "127.0.0.1", "server_port": 5353}], "final": "dns1"},
  "webui": {"listen": "127.0.0.1:18318", "token": "plain-token", "login_rate_limit": {"attempts": 100, "window": "5m"}}
}"#;

    #[test]
    fn status_shape_counts_and_no_secret() {
        let dir = std::env::temp_dir().join(format!("m6b-handlers-status-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        write_config(&dir, FIXTURE);
        let server = test_server(&dir);
        let resp = handle_status(&server).expect("status renders");
        assert_eq!(resp.status, 200);
        let body = String::from_utf8(resp.body).unwrap();
        assert!(body.contains("\"profile_count\":1"), "{body}");
        assert!(body.contains("\"outbound_count\":1"), "{body}");
        assert!(body.contains("\"endpoint_count\":1"), "{body}");
        assert!(body.contains("\"default_profile\":\"muse01\""), "{body}");
        assert!(!body.contains("SECRET-TROJAN"), "{body}");
        assert!(!body.contains("SECRET-WG"), "{body}");
        assert!(!body.contains("plain-token"), "{body}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn outbound_list_redacts_and_counts_used_by() {
        let dir =
            std::env::temp_dir().join(format!("m6b-handlers-outbounds-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        write_config(&dir, FIXTURE);
        let server = test_server(&dir);
        let resp = handle_list_outbounds(&server).expect("list renders");
        let body = String::from_utf8(resp.body).unwrap();
        assert!(body.contains("\"tag\":\"proxy-eu\""), "{body}");
        assert!(body.contains("\"used_by\":[\"muse01\"]"), "{body}");
        assert!(!body.contains("SECRET-TROJAN"), "{body}");
        let resp = handle_get_outbound(&server, "proxy-eu").expect("get renders");
        let body = String::from_utf8(resp.body).unwrap();
        assert!(
            body.contains("\"password\":\"\\u003credacted\\u003e\""),
            "{body}"
        );
        assert!(!body.contains("SECRET-TROJAN"), "{body}");
        let err = handle_get_outbound(&server, "nope").unwrap_err();
        assert_eq!(err.status, 404);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn config_get_redacts_token_and_reports_sha() {
        let dir = std::env::temp_dir().join(format!("m6b-handlers-config-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        write_config(&dir, FIXTURE);
        let server = test_server(&dir);
        let resp = handle_get_config(&server).expect("config renders");
        let body = String::from_utf8(resp.body).unwrap();
        assert!(!body.contains("plain-token"), "{body}");
        assert!(body.contains("\"source\":\"single-file\""), "{body}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn telegram_view_unconfigured_shape() {
        let dir =
            std::env::temp_dir().join(format!("m6b-handlers-telegram-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        write_config(&dir, FIXTURE);
        let server = test_server(&dir);
        let resp = handle_get_telegram(&server).expect("telegram renders");
        let body = String::from_utf8(resp.body).unwrap();
        assert!(body.contains("\"configured\":false"), "{body}");
        assert!(body.contains("\"allowed_user_ids\":[]"), "{body}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn keeper_view_wraps_and_sorts_by_tag() {
        // R1: Go returns keeperEntryView{tag, profile,
        // browser, interval_seconds, notify, status}
        // sorted by tag — not bare Status objects in
        // config order. Two entries, stored out of order.
        let dir = std::env::temp_dir().join(format!("m6b-handlers-keeper2-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let fixture = FIXTURE.replacen(
            r#""webui":"#,
            r#""keeper": [{"tag": "b", "profile": "muse01", "browser": "http://127.0.0.1:9222", "interval": "1h", "notify": "telegram"}, {"tag": "a", "profile": "muse02", "browser": "http://127.0.0.1:9223"}], "telegram": {"profile": "muse01", "token": "123456789:ABCDEFGHIJKLMNOPQRST", "allowed_user_ids": [1]}, "webui":"#,
            1,
        );
        // Go's config validation forbids two keeper entries
        // naming the same profile, so entry "a" uses a
        // second profile added to this test's fixture only.
        let fixture = fixture.replacen(
            "\"fingerprint\": \"chrome\"\n    }\n  },",
            "\"fingerprint\": \"chrome\"\n    },\n    \"muse02\": {\n      \"cookies_file\": \"profiles/muse02/cookies.txt\",\n      \"outbound\": \"proxy-eu\",\n      \"fingerprint\": \"chrome\"\n    }\n  },",
            1,
        );
        write_config(&dir, &fixture);
        let server = test_server(&dir);
        let resp = handle_get_keeper(&server).expect("keeper renders");
        let body = String::from_utf8(resp.body).unwrap();
        // Sorted by tag: "a" (default 24h interval) first.
        let a = body.find(r#""tag":"a""#).expect("entry a present");
        let b = body.find(r#""tag":"b""#).expect("entry b present");
        assert!(a < b, "entries must be sorted by tag: {body}");
        assert!(
            body.contains(r#""browser":"http://127.0.0.1:9223""#),
            "{body}"
        );
        assert!(body.contains(r#""interval_seconds":86400"#), "{body}");
        assert!(body.contains(r#""interval_seconds":3600"#), "{body}");
        assert!(body.contains(r#""notify":"telegram""#), "{body}");
        // The status is NESTED under "status", with the
        // fresh-entry outcome.
        assert!(body.contains(r#""status":{"tag":"a""#), "{body}");
        assert!(body.contains(r#""last_tick_outcome":"never""#), "{body}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn keeper_view_empty_when_no_block() {
        let dir = std::env::temp_dir().join(format!("m6b-handlers-keeper-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        write_config(&dir, FIXTURE);
        let server = test_server(&dir);
        let resp = handle_get_keeper(&server).expect("keeper renders");
        let body = String::from_utf8(resp.body).unwrap();
        assert!(body.contains("\"data\":[]"), "{body}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn chats_unknown_profile_404_without_seam() {
        let dir = std::env::temp_dir().join(format!("m6b-handlers-chats-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        write_config(&dir, FIXTURE);
        let server = test_server(&dir);
        let uri: hyper::Uri = "/api/v1/chats/nope".parse().unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let err = rt
            .block_on(handle_list_chats(&server, "nope", &uri))
            .unwrap_err();
        assert_eq!(err.status, 404);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
