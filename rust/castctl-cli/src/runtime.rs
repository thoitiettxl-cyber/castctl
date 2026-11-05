// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Per-profile runtime for the M4b network path: profile
//! resolution, outbound dispatch into a dialer, the dialer HTTP
//! client, and the shared gateway connection.
//!
//! Go sources: `internal/commands/runtime.go`
//! (`defaultBuildRuntime`, `connectorConfig`,
//! `identityForProfile`, `Runtime.Cookies`,
//! `requireCookiesFile`, `Runtime.HTTPClient`) and
//! `internal/commands/commands.go:1023` (`runWithProfile`).
//!
//! Only the pieces the 13 read-only commands need are built:
//! no logging factory (logging stays OFF, so stderr carries
//! only the typed JSON error, as Go does with no log block),
//! no DNS router (M3 deviation carries over: `DirectDialer`
//! uses the system resolver), no outbound manager, no
//! heartbeat (Go starts none for unary read commands), no
//! keeper. The build order mirrors Go's: config parse →
//! active-profile resolution → dialer dispatch. Dispatch
//! failures (config parse, unknown tag, `Unsupported` from
//! `dispatch_outbound`/`dispatch_endpoint`, unbuildable
//! `HonkDialer`) are exit 2 — Q8 option (b): only config
//! parse/dispatch errors map to exit 2; call-time errors use
//! `TransportError::exit_code` in `network::classify_error`.
//!
//! No `unsafe`, no `unwrap()`/`expect()` on external input.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use castctl_config::config::{SingleConfig, resolve_active_profile};
use castctl_config::configlocation::ConfigLocation;
use castctl_config::configlocation::Getenv;
use castctl_config::jsonvalue::JsonValue as ConfigJsonValue;
use castctl_config::profile::{OutboundKind, Profile};
use castctl_gateway::Gateway;
use castctl_gateway::connector::GatewayConnector;
use castctl_gateway::shared::{Connector, SharedConn};
use castctl_transport::{
    BlockDialer, Dialer, DirectDialer, Dispatch, HonkDialer, HttpClient, TransportError,
    dispatch_endpoint, dispatch_outbound,
};

use crate::network::{classify_auth_message, typed};
use crate::run::{FlowErr, config_err, msg};
use castctl_gateway::cookies::{CookieLoadError, load_cookies};

/// The wired runtime for one invocation: the resolved profile,
/// the outbound dialer's HTTP client (all HTTPS in commands
/// goes through it; `http.DefaultClient` is never used), and
/// the shared gateway connection.
pub(crate) struct Runtime {
    /// The resolved active profile.
    pub profile: Profile,
    /// The dialer's HTTP client (HTTPS auth chain,
    /// `FetchSubscription`, `FetchSessionInfo`).
    pub http: HttpClient,
    /// The shared connection (retry across reconnects, no
    /// heartbeat — Go starts none for unary read commands).
    pub shared: Arc<SharedConn>,
}

/// Adapts `GatewayConnector` (whose `connect` takes the
/// cookies file and vm id) to the `Connector` trait (whose
/// `connect` takes nothing): the adapter owns both values.
struct ProfileConnector {
    inner: GatewayConnector,
    cookies_file: String,
    vm_id: String,
}

impl Connector for ProfileConnector {
    fn connect(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<Arc<Gateway>, TransportError>> + Send + '_>> {
        let cookies_file = self.cookies_file.clone();
        let vm_id = self.vm_id.clone();
        let inner = &self.inner;
        Box::pin(async move { inner.connect(&cookies_file, &vm_id).await })
    }
}

/// Convert a `castctl-config` ordered JSON value to a
/// `serde_json::Value` for `dispatch_outbound` /
/// `dispatch_endpoint` (`castctl-config` has no dependencies,
/// so the converter lives here, at the use site). Number
/// literals are re-parsed (the config parser already
/// validated them); object key order is lost (serde_json
/// `Map` is a `BTreeMap`, as in Go's `json.Marshal` on a
/// `map[string]any` — dispatch reads fields by name, so
/// order is unobservable here).
pub(crate) fn config_to_serde(v: &ConfigJsonValue) -> serde_json::Value {
    match v {
        ConfigJsonValue::Null => serde_json::Value::Null,
        ConfigJsonValue::Bool(b) => serde_json::Value::Bool(*b),
        ConfigJsonValue::Str(s) => serde_json::Value::String(s.clone()),
        ConfigJsonValue::Number(lit) => {
            serde_json::from_str::<serde_json::Value>(lit).unwrap_or(serde_json::Value::Null)
        }
        ConfigJsonValue::Array(items) => {
            serde_json::Value::Array(items.iter().map(config_to_serde).collect())
        }
        ConfigJsonValue::Object(obj) => {
            let mut map = serde_json::Map::new();
            for (k, val) in obj.iter() {
                map.insert(k.clone(), config_to_serde(val));
            }
            serde_json::Value::Object(map)
        }
    }
}

/// Find a raw outbound/endpoint entry by its `tag` field.
fn find_raw<'a>(entries: &'a [ConfigJsonValue], tag: &str) -> Option<&'a ConfigJsonValue> {
    entries.iter().find(|e| {
        matches!(e, ConfigJsonValue::Object(obj)
            if obj.get("tag").is_some_and(|t| matches!(t, ConfigJsonValue::Str(s) if s == tag)))
    })
}

/// A dispatch failure is exit 2 (Q8 option (b)): the config
/// named something unbuildable. The display text is the
/// dispatch error's, truncated to 200 chars by `Display`.
fn dispatch_err(e: TransportError) -> FlowErr {
    msg(2, e.to_string())
}

/// Build the dialer for the profile's outbound selection (Go
/// `defaultBuildRuntime` → `createOutbounds` /
/// `connectorConfig` → `identityForProfile`): `Direct` →
/// `DirectDialer`; `Tag` → the named entry in `outbounds`
/// (via `dispatch_outbound`) or `endpoints` (via
/// `dispatch_endpoint`, with the tag's `wireguard_dns`
/// servers); `Inline` → the raw object (via
/// `dispatch_outbound`). `Block` builds into a dialer that
/// fails at dial time (exit 1), matching Go: sing-box's
/// block outbound builds fine and returns `syscall.EPERM`
/// on dial (fix loop 1; was exit 2 at dispatch).
fn build_dialer(
    single: Option<&SingleConfig>,
    profile: &Profile,
) -> Result<Arc<dyn Dialer>, FlowErr> {
    let dispatch = match profile.outbound.kind {
        OutboundKind::Direct => Dispatch::Direct,
        OutboundKind::Tag => {
            let tag = profile.outbound.tag.as_str();
            let single = single.ok_or_else(|| {
                msg(
                    2,
                    format!("outbound tag {tag:?} cannot resolve without a config file"),
                )
            })?;
            if let Some(raw) = find_raw(&single.outbounds_raw, tag) {
                dispatch_outbound(&config_to_serde(raw), Some(profile.tls_engine.as_str()))
                    .map_err(dispatch_err)?
            } else if let Some(raw) = find_raw(&single.endpoints_raw, tag) {
                let servers: Vec<String> = single
                    .wireguard_dns
                    .iter()
                    .find(|(t, _)| t == tag)
                    .map(|(_, s)| s.clone())
                    .unwrap_or_default();
                dispatch_endpoint(&config_to_serde(raw), &servers).map_err(dispatch_err)?
            } else {
                return Err(msg(2, format!("outbound tag {tag:?} not found")));
            }
        }
        OutboundKind::Inline => {
            let raw = profile
                .outbound
                .raw
                .as_ref()
                .ok_or_else(|| msg(2, "inline outbound is missing its object"))?;
            dispatch_outbound(&config_to_serde(raw), Some(profile.tls_engine.as_str()))
                .map_err(dispatch_err)?
        }
    };
    match dispatch {
        Dispatch::Direct => Ok(Arc::new(DirectDialer::new())),
        Dispatch::Honk(node) => HonkDialer::shared(*node)
            .map(|d| -> Arc<dyn Dialer> { d })
            .map_err(dispatch_err),
        Dispatch::WireGuard(d) => Ok(d),
        Dispatch::Block => Ok(Arc::new(BlockDialer::new())),
    }
}

/// Build the runtime (Go `defaultBuildRuntime`, reduced to
/// the read-command path): config parse already happened in
/// `resolve_and_load_single`; active-profile resolution,
/// then dialer dispatch, then the HTTP client and the shared
/// connection over the profile's gateway connector.
pub(crate) fn build_runtime(
    loc: &ConfigLocation,
    single: Option<&SingleConfig>,
    profile_flag: Option<&str>,
    getenv: Getenv<'_>,
) -> Result<Runtime, FlowErr> {
    let profile =
        resolve_active_profile(&loc.config_dir, profile_flag, getenv).map_err(config_err)?;
    let dialer = build_dialer(single, &profile)?;
    let http = HttpClient::new(Arc::clone(&dialer));
    let connector = GatewayConnector::new(Arc::clone(&dialer));
    let adapter = ProfileConnector {
        inner: connector,
        cookies_file: profile.cookies_file.clone(),
        vm_id: profile.vm_id.clone(),
    };
    let shared = Arc::new(SharedConn::new(Arc::new(adapter)));
    Ok(Runtime {
        profile,
        http,
        shared,
    })
}

impl Runtime {
    /// `Runtime.Cookies` (`runtime.go`): the file must exist
    /// and be non-empty, then parse. Failures are typed
    /// `cookies_missing` (exit 2) so dispatch never prints a
    /// cookie value and never exits 0 on failed auth. The
    /// typed JSON's `error` field is the plain message text
    /// for the stat/empty/read cases (Go's `typedAuthError`
    /// wrapping a plain error renders through `SafeString`,
    /// i.e. the text itself) and the `Auth` log summary for
    /// the parse case (Go's `classifyAuthMessage` on the
    /// `AuthError`).
    pub(crate) fn cookies(&self) -> Result<String, FlowErr> {
        let path = &self.profile.cookies_file;
        match std::fs::metadata(path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(typed(
                    "cookies_missing",
                    "cookies_missing: no cookies file (run `castctl auth export` for guidance)",
                ));
            }
            Err(_) => {
                return Err(typed(
                    "cookies_missing",
                    "cookies_missing: cannot access cookies file",
                ));
            }
            Ok(m) if m.len() == 0 => {
                return Err(typed(
                    "cookies_missing",
                    "cookies_missing: cookies file is empty",
                ));
            }
            Ok(_) => {}
        }
        match load_cookies(path) {
            Ok(c) => {
                if c.trim().is_empty() {
                    return Err(typed(
                        "cookies_missing",
                        "cookies_missing: cookies file is empty",
                    ));
                }
                Ok(c)
            }
            Err(CookieLoadError::Read(m)) => Err(typed("cookies_missing", &m)),
            Err(CookieLoadError::Parse(m)) => Err(classify_auth_message(&m)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use castctl_config::config::load_single_config;
    use castctl_config::jsonvalue::decode_ordered_json;

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("castctl-cli-runtime-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_config(dir: &std::path::Path, text: &str) {
        std::fs::write(dir.join("config.json"), text).unwrap();
    }

    /// Load the single config + resolve profile `no1` from a
    /// fixture directory.
    fn load_fixture(dir: &std::path::Path) -> (Option<SingleConfig>, Profile) {
        let (single, _found) = load_single_config(dir.to_str().unwrap()).unwrap();
        let profile = resolve_active_profile(dir.to_str().unwrap(), Some("no1"), None).unwrap();
        (single, profile)
    }

    fn flow_code(e: &FlowErr) -> i32 {
        match e {
            FlowErr::Msg { code, .. } => *code,
            FlowErr::Verbatim { code, .. } => *code,
            FlowErr::Exit(code) => *code,
            FlowErr::HelpShown => 0,
        }
    }

    fn verbatim_text(e: &FlowErr) -> String {
        match e {
            FlowErr::Verbatim { text, .. } => text.clone(),
            _ => panic!("want Verbatim, got {e:?}"),
        }
    }

    #[test]
    fn config_to_serde_round_trip() {
        let v = decode_ordered_json(
            r#"{"tag":"t1","server_port":1080,"ratio":1.50,"on":true,"off":null}"#.as_bytes(),
        )
        .unwrap();
        let s = config_to_serde(&v);
        assert_eq!(s.get("tag").and_then(|v| v.as_str()), Some("t1"));
        assert_eq!(s.get("server_port").and_then(|v| v.as_i64()), Some(1080));
        // Number literal spelling is not preserved (serde_json
        // re-parses), but the value is identical.
        assert_eq!(s.get("ratio").and_then(|v| v.as_f64()), Some(1.5));
        assert_eq!(s.get("on").and_then(|v| v.as_bool()), Some(true));
        assert!(s.get("off").unwrap().is_null());
    }

    #[test]
    fn find_raw_by_tag() {
        let entries = vec![
            decode_ordered_json(r#"{"tag":"a","type":"direct"}"#.as_bytes()).unwrap(),
            decode_ordered_json(r#"{"tag":"b","type":"socks"}"#.as_bytes()).unwrap(),
        ];
        assert!(find_raw(&entries, "b").is_some());
        assert!(find_raw(&entries, "zzz").is_none());
    }

    #[test]
    fn build_dialer_direct_ok() {
        let dir = temp_dir("direct");
        write_config(&dir, r#"{"profiles":{"no1":{"outbound":"direct"}}}"#);
        let (single, profile) = load_fixture(&dir);
        assert!(build_dialer(single.as_ref(), &profile).is_ok());
    }

    #[test]
    fn build_dialer_detour_is_exit_2() {
        let dir = temp_dir("detour");
        write_config(
            &dir,
            r#"{"profiles":{"no1":{"outbound":"t1"}},"outbounds":[{"tag":"t1","type":"direct","detour":"t2"}]}"#,
        );
        let (single, profile) = load_fixture(&dir);
        let err = build_dialer(single.as_ref(), &profile)
            .err()
            .expect("want dispatch error");
        assert_eq!(flow_code(&err), 2);
    }

    #[test]
    fn build_dialer_unknown_tag_is_exit_2() {
        let dir = temp_dir("unknown-tag");
        write_config(&dir, r#"{"profiles":{"no1":{"outbound":"nope"}}}"#);
        let (single, profile) = load_fixture(&dir);
        let err = build_dialer(single.as_ref(), &profile)
            .err()
            .expect("want dispatch error");
        assert_eq!(flow_code(&err), 2);
    }

    /// F4 (fix loop 1): a `Block` outbound BUILDS (Go builds
    /// it — sing-box `protocol/block/outbound.go:37-40`
    /// returns `syscall.EPERM` only at dial time) and fails
    /// at DIAL time with `ConnectionDown`, which
    /// `classify_error` maps to exit 1 — matching Go's
    /// dial-time failure. The old behaviour (exit 2 at
    /// dispatch) was deviation 9, now removed.
    #[test]
    fn build_dialer_block_builds_then_fails_at_dial() {
        let dir = temp_dir("block");
        write_config(
            &dir,
            r#"{"profiles":{"no1":{"outbound":"t1"}},"outbounds":[{"tag":"t1","type":"block"}]}"#,
        );
        let (single, profile) = load_fixture(&dir);
        let dialer = build_dialer(single.as_ref(), &profile)
            .expect("a Block outbound must build; it fails at dial time, not dispatch");
        let target = castctl_transport::DialTarget::new("127.0.0.1", 1);
        let err = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(dialer.dial(&target))
            .expect_err("dialing through a Block outbound must fail");
        assert!(
            matches!(err, TransportError::ConnectionDown { .. }),
            "want ConnectionDown at dial time, got {err:?}"
        );
        assert_eq!(
            flow_code(&crate::network::classify_error(&err)),
            1,
            "a dial-time Block failure is a runtime error (exit 1), not a dispatch error"
        );
    }

    #[test]
    fn cookies_missing_file_is_typed_json() {
        let dir = temp_dir("cookies-missing");
        write_config(&dir, r#"{"profiles":{"no1":{"outbound":"direct"}}}"#);
        let (single, _profile) = load_fixture(&dir);
        let loc = ConfigLocation {
            config_dir: dir.to_str().unwrap().to_string(),
            config_file: dir.join("config.json").to_str().unwrap().to_string(),
            explicit: true,
            warnings: Vec::new(),
        };
        let rt = build_runtime(&loc, single.as_ref(), Some("no1"), None).unwrap();
        let err = rt.cookies().unwrap_err();
        assert_eq!(flow_code(&err), 2);
        assert_eq!(
            verbatim_text(&err),
            "{\"error\":\"cookies_missing: no cookies file (run `castctl auth export` for guidance)\",\"type\":\"cookies_missing\"}"
        );
    }

    #[test]
    fn cookies_empty_file_is_typed_json() {
        let dir = temp_dir("cookies-empty");
        write_config(&dir, r#"{"profiles":{"no1":{"outbound":"direct"}}}"#);
        let (single, _profile) = load_fixture(&dir);
        // The profile's cookies file lives under
        // profiles/no1/cookies.txt by default.
        let cookies = dir.join("profiles/no1/cookies.txt");
        std::fs::create_dir_all(cookies.parent().unwrap()).unwrap();
        std::fs::write(&cookies, "").unwrap();
        let loc = ConfigLocation {
            config_dir: dir.to_str().unwrap().to_string(),
            config_file: dir.join("config.json").to_str().unwrap().to_string(),
            explicit: true,
            warnings: Vec::new(),
        };
        let rt = build_runtime(&loc, single.as_ref(), Some("no1"), None).unwrap();
        assert_eq!(rt.profile.cookies_file, cookies.to_str().unwrap());
        let err = rt.cookies().unwrap_err();
        assert_eq!(flow_code(&err), 2);
        assert_eq!(
            verbatim_text(&err),
            "{\"error\":\"cookies_missing: cookies file is empty\",\"type\":\"cookies_missing\"}"
        );
    }

    #[test]
    fn cookies_unparseable_is_auth_summary() {
        let dir = temp_dir("cookies-bad");
        write_config(&dir, r#"{"profiles":{"no1":{"outbound":"direct"}}}"#);
        let (single, _profile) = load_fixture(&dir);
        let cookies = dir.join("profiles/no1/cookies.txt");
        std::fs::create_dir_all(cookies.parent().unwrap()).unwrap();
        // Non-empty, no `=`/`;`, not JSON, not a jar: the
        // Netscape path finds zero parts.
        std::fs::write(&cookies, "garbage-no-equals").unwrap();
        let loc = ConfigLocation {
            config_dir: dir.to_str().unwrap().to_string(),
            config_file: dir.join("config.json").to_str().unwrap().to_string(),
            explicit: true,
            warnings: Vec::new(),
        };
        let rt = build_runtime(&loc, single.as_ref(), Some("no1"), None).unwrap();
        let err = rt.cookies().unwrap_err();
        assert_eq!(flow_code(&err), 2);
        let msg = format!("could not parse cookies file {}", cookies.to_str().unwrap());
        assert_eq!(
            verbatim_text(&err),
            format!(
                "{{\"error\":\"conn: auth_failed message_length={}\",\"type\":\"cookies_missing\"}}",
                msg.len()
            )
        );
    }
}
