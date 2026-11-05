// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Gateway RPC client over HTTP (`call_json`).
//!
//! Plan decision D-M3-2: this is an HTTP-over-outbound RPC client
//! (tested against a fake HTTP server), NOT a port of the internal
//! gateway transport (WebSocket + Noise + protobuf frames in
//! `internal/gateway` + `internal/conn`). The internal gateway
//! port is deferred; this module ports the parts of the Go
//! `CallJSON` contract that survive the transport change — route
//! lookup, path building, GET-body-to-query, envelope handling,
//! number handling, allowlist error summaries, retry policy and
//! exit-code mapping — and documents the parts that do not
//! (below).
//!
//! Go sources ported here:
//! - `internal/gateway/calls.go:26-31` (`DefaultRequestTimeout =
//!   30s`, `DefaultDownloadTimeout = 300s` — only the 30s request
//!   timeout is used here; there is no DownloadFile in M3),
//!   `:34-45` (`effectiveTimeout`: caller value, ≤0 → default,
//!   capped by an earlier context deadline — M3 has no context
//!   object, so the request timeout IS the cap),
//!   `:186-220` (`CallJSON` envelope + empty-body → `{}`),
//!   `:97-183` (`Request` status/summary rules, adapted from
//!   stream frames to HTTP statuses);
//! - `internal/gateway/jsonutil.go:28-48` (`decodeJSONValue`:
//!   numbers stay integers/`json.Number`, never `float64` —
//!   `serde_json::Number` with the `arbitrary_precision`
//!   feature preserves the literal the same way, including
//!   numbers outside the i64/u64 range, and trailing data
//!   after a JSON value is an error),
//!   `:98-118` (GET body → query, nil dropped, top-level bool
//!   as Python `True`/`False`, nested values via `pythonStr`
//!   `%v`), `:70-96` (`encodeBody`: nil → no
//!   bytes, raw bytes/string → verbatim, else JSON marshal);
//! - `internal/gateway/stream.go:188-208` (`buildPath`),
//!   `:213-220` (`resolveRoute`: explicit override wins, unknown
//!   method → `ValidationError`);
//! - `internal/gateway/summary.go:213-224`
//!   (`gatewayErrorFromSummary`: status + allowlist summary, no
//!   body bytes) — the outdated `calls.go:72` comment claiming
//!   `payload[:500]` is NOT followed (the real code uses
//!   `summarizeBody`);
//! - `internal/conn/shared.go:148-221` (`retryCall`, via
//!   `retry.rs`);
//! - `internal/commands/commands.go:268-337` (`classifyError`,
//!   via `error::TransportError::exit_code`).
//!
//! NOT ported in M3 (deferred, not silently dropped):
//! - The WebSocket+Noise+protobuf gateway transport itself
//!   (`internal/gateway/stream.go` `open`, stream phases
//!   `PhaseNotSent`/`PhaseSentNoReply`/`PhaseStreaming`): an HTTP
//!   client has no stream phases, so phases are not faked.
//! - `RequestOptions` fields with no HTTP equivalent: `Route`
//!   override (M3 always uses the table — an override parameter
//!   would be a new API, not a port), `Query` as a separate
//!   input (M3 derives query only from a GET body, as Go's
//!   `Request` does when query is nil), `Deadline` as an
//!   absolute time (M3's timeout is a duration), `Track`.
//! - `DownloadFile` (300s timeout), `Ping` (10s, body
//!   `{"presence":"away"}`), subscriptions, `CancelStream`.
//! - The `phaseExitCode` table (`profilecmd.go:901-929`).
//!
//! Base URL: routes carry no host (see `routes.rs`), so the
//! caller supplies the gateway HTTP base (`host` + `port`) at
//! construction. This crate never invents a host.

use std::sync::Arc;
use std::time::Duration;

use http::Method;
use serde_json::{Map, Value};

use crate::dialer::{DialTarget, Dialer};
use crate::error::{BodySummary, TransportError, validate_error_code};
use crate::http::HttpClient;
use crate::retry::{RetryPolicy, run_with_retry, safe_to_repeat};
use crate::routes::{RouteTable, build_path};

/// Default per-call timeout, Go `DefaultRequestTimeout`
/// (`internal/gateway/calls.go:26`).
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Gateway RPC client: `call_json(method, body, path_params)`.
///
/// `body` is a JSON value (or `None` for no body). Numbers keep
/// their literal form through `serde_json::Number` — they are
/// never converted through `f64`, mirroring Go's `UseNumber`
/// decoding. `path_params` are `(name, value)` pairs for `{name}`
/// placeholders in the route path.
pub struct RpcClient {
    http: HttpClient,
    target: DialTarget,
    routes: RouteTable,
    timeout: Duration,
    policy: RetryPolicy,
}

// Hand-written Debug: no credentials live here (no token field
// exists at all — the caller owns auth headers), but Debug is
// still written by hand so a future field cannot leak through a
// derived Debug.
impl std::fmt::Debug for RpcClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RpcClient")
            .field("host", &self.target.host)
            .field("port", &self.target.port)
            .finish_non_exhaustive()
    }
}

impl RpcClient {
    /// Build a client over a dialer (one profile outbound), a
    /// gateway HTTP target, and a route table. Timeout and retry
    /// policy default to the Go values (30s request timeout,
    /// 30s retry budget); use the `with_*` constructors in tests
    /// to inject smaller ones.
    pub fn new(dialer: Arc<dyn Dialer>, target: DialTarget, routes: RouteTable) -> Self {
        Self {
            http: HttpClient::new(dialer),
            target,
            routes,
            timeout: DEFAULT_REQUEST_TIMEOUT,
            policy: RetryPolicy::default_policy(),
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn with_retry_policy(mut self, policy: RetryPolicy) -> Self {
        self.policy = policy;
        self
    }

    /// The route table (for callers that need `safe_to_repeat`
    /// without a call, e.g. tests).
    pub fn routes(&self) -> &RouteTable {
        &self.routes
    }

    /// Call a gateway method. Returns the decoded JSON value,
    /// following Go `CallJSON` exactly: only a BOOLEAN false
    /// `ok` is an error (`GatewayError(-1, summary)` where the
    /// summary carries only the enum-gated `error` field); any
    /// other object with a `result` field returns `result`
    /// (whether `ok` is true, non-bool, or absent); otherwise
    /// the whole decoded value; an empty body → `{}`.
    pub async fn call_json(
        &self,
        method: &str,
        body: Option<Value>,
        path_params: &[(String, String)],
    ) -> Result<Value, TransportError> {
        let route = self
            .routes
            .lookup_route(method)
            .ok_or_else(|| TransportError::Validation {
                message: format!("unknown method: {method}"),
            })?;
        let safe = safe_to_repeat(method, Some(route));
        let http_method = parse_http_method(&route.http)?;
        // GET body → query (Go `Request`: only when the route is
        // GET, the body is non-nil, and no explicit query exists —
        // M3 has no explicit query input, so the condition reduces
        // to GET + non-nil body).
        let (query, send_body) = if http_method == Method::GET {
            match &body {
                None => (Vec::new(), None),
                Some(value) => (body_to_query(value)?, None),
            }
        } else {
            (Vec::new(), body)
        };
        let path = build_path(&route.path, path_params, &query);
        let (body_bytes, content_type) = match &send_body {
            None => (None, None),
            Some(value) => (
                Some(
                    serde_json::to_vec(value).map_err(|_| TransportError::Validation {
                        message: "request body is not valid JSON".to_string(),
                    })?,
                ),
                Some("application/json"),
            ),
        };
        let headers: Vec<(String, String)> = match content_type {
            Some(ct) => vec![("content-type".to_string(), ct.to_string())],
            None => Vec::new(),
        };
        let policy = self.policy;
        let timeout = self.timeout;
        // Owned per-attempt state: the retry closure must return
        // a future that owns everything it uses (a borrowing
        // future does not fit `FnMut() -> Fut`), so each attempt
        // clones the client handle / target / path / headers /
        // body instead of borrowing them.
        let http = self.http.clone();
        let target = self.target.clone();
        let path = path.clone();
        // Overall cap: the retry loop's per-attempt timeout
        // resets every attempt, so without this wrapper a slow
        // peer could stretch the call past the request timeout
        // (accumulated pauses + one full attempt). Go bounds the
        // whole call by the context deadline (`effectiveTimeout`,
        // `calls.go:34-45`); this wrapper is that deadline.
        // Expiry is a `Timeout` error, never retried.
        let response = tokio::time::timeout(
            timeout,
            run_with_retry(policy, safe, move || {
                let http = http.clone();
                let target = target.clone();
                let path = path.clone();
                let headers = headers.clone();
                let body_bytes = body_bytes.clone();
                let method = http_method.clone();
                async move {
                    http.request(
                        method,
                        &target,
                        &path,
                        &headers,
                        body_bytes.map(bytes::Bytes::from),
                        timeout,
                    )
                    .await
                }
            }),
        )
        .await
        .map_err(|_| TransportError::Timeout {
            message: "request timed out".to_string(),
        })??;
        // Status outside 200–299 → GatewayError(status, summary).
        // The body bytes are measured for the summary, never
        // kept in the error.
        if !(200..=299).contains(&response.status.as_u16()) {
            let mut summary = response.summary();
            summary.error_code = extract_error_field(&response.body);
            return Err(TransportError::Gateway(summary));
        }
        decode_response(&response.body)
    }
}

/// Parse an HTTP verb from the route table. Unknown verbs are a
/// caller-side validation error (Go: an unknown HTTP method is
/// never a route — see `routes.rs`).
fn parse_http_method(verb: &str) -> Result<Method, TransportError> {
    match verb.to_ascii_uppercase().as_str() {
        "GET" => Ok(Method::GET),
        "POST" => Ok(Method::POST),
        "PATCH" => Ok(Method::PATCH),
        "DELETE" => Ok(Method::DELETE),
        "PUT" => Ok(Method::PUT),
        "HEAD" => Ok(Method::HEAD),
        other => Err(TransportError::Validation {
            message: format!("unknown HTTP method in route table: {other}"),
        }),
    }
}

/// Convert a GET body to query pairs (Go `bodyToQuery` +
/// `pythonStr`, `internal/gateway/jsonutil.go`): the body must be
/// a JSON object; null values are dropped; top-level bools render
/// Python `True`/`False`; numbers render as their literal;
/// strings pass through; nested values render with Go's `%v`
/// default branch of `pythonStr` (arrays `[elem elem]`, objects
/// `map[k:v …]` with keys sorted as Go's `fmt` sorts map keys,
/// nested bools `true`/`false`, nested null `<nil>`).
pub fn body_to_query(body: &Value) -> Result<Vec<(String, String)>, TransportError> {
    let obj = body.as_object().ok_or_else(|| TransportError::Validation {
        message: "GET body must be a map to convert to query".to_string(),
    })?;
    let mut out = Vec::new();
    for (k, v) in obj {
        match v {
            Value::Null => {}
            Value::Bool(b) => out.push((
                k.clone(),
                if *b {
                    "True".to_string()
                } else {
                    "False".to_string()
                },
            )),
            Value::Number(n) => out.push((k.clone(), n.to_string())),
            Value::String(s) => out.push((k.clone(), s.clone())),
            Value::Array(_) | Value::Object(_) => out.push((k.clone(), python_str(v))),
        }
    }
    Ok(out)
}

/// Render a nested value the way Go's `fmt.Sprintf("%v", v)`
/// renders it (the default branch of `pythonStr`). Note the
/// top-level/nested asymmetry, which mirrors Go exactly:
/// top-level bools are Python `True`/`False` (handled in
/// `body_to_query`), but a bool NESTED inside an array or object
/// goes through `%v` and renders `true`/`false`; nested null
/// renders `<nil>` (Go prints a nil interface that way), while
/// top-level null is dropped before it can reach here. Map keys
/// are sorted explicitly (Go's `fmt` sorts map keys) rather than
/// relying on `serde_json::Map` ordering.
fn python_str(v: &Value) -> String {
    match v {
        Value::Null => "<nil>".to_string(),
        Value::Bool(b) => {
            if *b {
                "true".to_string()
            } else {
                "false".to_string()
            }
        }
        Value::Number(n) => n.to_string(),
        Value::String(s) => s.clone(),
        Value::Array(items) => {
            let parts: Vec<String> = items.iter().map(python_str).collect();
            format!("[{}]", parts.join(" "))
        }
        Value::Object(map) => {
            let mut pairs: Vec<(&String, &Value)> = map.iter().collect();
            pairs.sort_by(|a, b| a.0.cmp(b.0));
            let parts: Vec<String> = pairs
                .iter()
                .map(|(k, v)| format!("{k}:{}", python_str(v)))
                .collect();
            format!("map[{}]", parts.join(" "))
        }
    }
}

/// Extract the enum-gated `error` field from a JSON body, if the
/// body is a JSON object with a string `error` field that passes
/// the gate. Non-JSON bodies and failing gates yield `None` —
/// never body bytes.
fn extract_error_field(body: &[u8]) -> Option<String> {
    let value: Value = serde_json::from_slice(body).ok()?;
    let code = value.get("error")?.as_str()?;
    validate_error_code(code)
}

/// Decode a successful response body (Go `CallJSON` decode,
/// `internal/gateway/calls.go:186-220`, in Go's order):
/// empty body → `{}`; JSON value → the value, with numbers kept
/// as literals; trailing data after the value → error;
/// non-JSON → `GatewayError(-1, summary)` (label + length only);
/// `{"ok":false}` with `ok` a BOOLEAN false → `GatewayError(-1,
/// summary)` with the gated `error` field; any other object
/// with a `result` field → `result` (whether `ok` is true,
/// non-bool, or absent); otherwise the whole value.
pub fn decode_response(body: &[u8]) -> Result<Value, TransportError> {
    if body.is_empty() {
        return Ok(Value::Object(Map::new()));
    }
    let value: Value = serde_json::from_slice(body).map_err(|_| {
        // Non-JSON: summary only (body length, no bytes).
        TransportError::Gateway(BodySummary::new(-1, Some(body), ""))
    })?;
    if let Some(obj) = value.as_object() {
        // Only a BOOLEAN false `ok` is an error. Every other
        // shape falls through to the `result` rule below.
        if obj.get("ok").and_then(Value::as_bool) == Some(false) {
            let mut summary = BodySummary::new(-1, Some(body), "");
            summary.error_code = obj
                .get("error")
                .and_then(|e| e.as_str())
                .and_then(validate_error_code);
            return Err(TransportError::Gateway(summary));
        }
        if let Some(result) = obj.get("result") {
            return Ok(result.clone());
        }
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_envelope_rules() {
        // Empty body -> {}.
        assert_eq!(
            decode_response(b"").expect("empty"),
            Value::Object(Map::new())
        );
        // ok:true with result -> result.
        assert_eq!(
            decode_response(br#"{"ok":true,"result":{"a":1}}"#).expect("ok result"),
            serde_json::json!({"a": 1})
        );
        // ok:true without result -> whole value.
        assert_eq!(
            decode_response(br#"{"ok":true,"x":2}"#).expect("ok whole"),
            serde_json::json!({"ok": true, "x": 2})
        );
        // ok:false -> GatewayError(-1) with gated error field.
        let err = decode_response(br#"{"ok":false,"error":"bad_request"}"#)
            .expect_err("ok:false must fail");
        match err {
            TransportError::Gateway(summary) => {
                assert_eq!(summary.status, -1);
                assert_eq!(summary.error_code.as_deref(), Some("bad_request"));
                // The gated error field IS allowed in the summary;
                // other body content is not.
                assert!(summary.render().contains("error=bad_request"));
            }
            other => panic!("wrong variant: {other:?}"),
        }
        // ok non-bool -> whole value.
        assert_eq!(
            decode_response(br#"{"ok":"yes"}"#).expect("ok non-bool"),
            serde_json::json!({"ok": "yes"})
        );
        // Non-JSON -> GatewayError(-1), no body bytes in the error.
        let err = decode_response(b"not json at all").expect_err("non-JSON must fail");
        assert!(!format!("{err}").contains("not json"));
        // Trailing data -> error (serde_json rejects it).
        assert!(decode_response(br#"{"a":1} trailing"#).is_err());
        // Numbers keep their literal (no float64 round-trip).
        let value = decode_response(b"{\"n\": 9007199254740993}").expect("big int");
        assert_eq!(value["n"].as_i64(), Some(9007199254740993));
    }

    #[test]
    fn decode_result_without_ok_and_with_non_bool_ok() {
        // Go `CallJSON`: only a BOOLEAN false `ok` is an error.
        // An object with `result` but no `ok` returns `result`.
        assert_eq!(
            decode_response(br#"{"result":{"a":1}}"#).expect("result without ok"),
            serde_json::json!({"a": 1})
        );
        // Same for a non-bool `ok`: `result` still wins.
        assert_eq!(
            decode_response(br#"{"ok":"yes","result":42}"#).expect("result with non-bool ok"),
            serde_json::json!(42)
        );
    }

    #[test]
    fn decode_numbers_beyond_u64_keep_literal() {
        // Without `arbitrary_precision`, a number above u64::MAX
        // decodes as f64 and its literal is lost (2^64 becomes
        // 1.8446744073709552e19). With it, the literal survives.
        // NOTE: `serde_json::json!` cannot build such a number
        // (its macro only makes i64/u64/f64), so the fixture is
        // raw JSON text parsed by `decode_response` itself.
        let value = decode_response(br#"{"n": 18446744073709551616}"#).expect("2^64");
        assert_eq!(value["n"].to_string(), "18446744073709551616");
        let value =
            decode_response(br#"{"d": 1.123456789012345678901234567890}"#).expect("long decimal");
        assert_eq!(value["d"].to_string(), "1.123456789012345678901234567890");
    }

    #[test]
    fn get_body_to_query_rules() {
        let q = body_to_query(&serde_json::json!({"a": 1, "b": true, "c": null, "d": "x"}))
            .expect("query");
        assert!(q.contains(&("a".to_string(), "1".to_string())));
        assert!(q.contains(&("b".to_string(), "True".to_string())));
        assert!(q.contains(&("d".to_string(), "x".to_string())));
        assert!(!q.iter().any(|(k, _)| k == "c"));
        assert!(body_to_query(&serde_json::json!([1, 2])).is_err());
    }

    #[test]
    fn get_body_to_query_nested_python_str() {
        // Go `pythonStr` default branch (`fmt %v`): nested
        // values render, they are NOT rejected.
        let q = body_to_query(
            &serde_json::json!({"a": {"x": 1, "y": true}, "b": [1, 2], "c": null, "d": true}),
        )
        .expect("query");
        assert!(q.contains(&("a".to_string(), "map[x:1 y:true]".to_string())));
        assert!(q.contains(&("b".to_string(), "[1 2]".to_string())));
        assert!(q.contains(&("d".to_string(), "True".to_string())));
        assert!(!q.iter().any(|(k, _)| k == "c"));
        // Map keys sort (Go `fmt` sorts map keys); nested bools
        // use `%v` (`true`/`false`, NOT Python `True`/`False`);
        // nested null renders `<nil>`.
        let q = body_to_query(&serde_json::json!({"z": {"b": 2, "a": 1}, "n": [null, false]}))
            .expect("query");
        assert!(q.contains(&("z".to_string(), "map[a:1 b:2]".to_string())));
        assert!(q.contains(&("n".to_string(), "[<nil> false]".to_string())));
    }

    #[test]
    fn unknown_method_is_validation_exit_2() {
        let routes = RouteTable::parse(r#"[]"#).expect("empty table");
        let client = RpcClient::new(
            Arc::new(crate::dialer::DirectDialer::new()),
            DialTarget::new("127.0.0.1", 1),
            routes,
        );
        // Call synchronously via a runtime the test owns: the
        // lookup fails before any dial, so the runtime is only
        // needed to drive the future.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("INVARIANT: test runtime builds");
        let err = rt
            .block_on(client.call_json("no.such.method", None, &[]))
            .expect_err("unknown method must fail");
        assert!(matches!(err, TransportError::Validation { .. }));
        assert_eq!(err.exit_code(), 2);
    }
}
