// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Subscription / usage via the Next.js server action
//! `fetchSubscriptionAction` — port of
//! `internal/gateway/subscription.go`.
//!
//! This is NOT a REST route or a VM gateway method: a server
//! action is a POST to a settings page with a `Next-Action:
//! <id>` header, and the id changes when the web app is
//! redeployed, so it is re-discovered from the JS bundles when
//! the known one stops working.
//!
//! `FetchSubscription` tries the configured id, then the
//! default id, then scans the JS bundles for a fresh id. A
//! 401/403 anywhere is an AuthError. A result that is not
//! `{"success":true,"subscription":{...}}` is a
//! `GatewayError(-1)` built from the allowlist summary of the
//! parsed RSC result (the wire RSC body length threaded
//! through `callAction`, never the summary-text length).
//!
//! Differences from Go, all unobservable in CLI output (Go's
//! `GatewayError.Error()` never prints the Payload text — see
//! `summary.rs`): the "could not find ..." and
//! "subscription is not an object" Gateway errors carry no
//! payload text on the Rust error (there is no field for
//! free-text payload); the CLI prints the same status-only
//! rendering Go prints. RSC numbers decode as
//! `serde_json::Value` numbers (not Go `json.Number` literals);
//! nothing in PR2 re-encodes them.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use bytes::Bytes;
use castctl_transport::{HttpClient, TransportError};
use http::Method;
use regex::Regex;

use crate::auth::{HATCH_MAX_BODY, request_url};
use crate::dial::GATEWAY_USER_AGENT;
use crate::summary::{summarize_parsed_body, summary_to_body_summary};

/// The server action's name.
pub const SUBSCRIPTION_ACTION_NAME: &str = "fetchSubscriptionAction";

/// The last-known action id, tried after a configured id and
/// before a bundle scan.
pub const DEFAULT_SUBSCRIPTION_ACTION_ID: &str = "4029ac5c4bd03136487d91ebde5de39c64b35229b4";

/// The page the action is posted to.
pub const SUBSCRIPTION_PAGE: &str = "https://muse.ai/settings";

/// Bounds each server-action / chunk fetch (30s in Go).
pub const ACTION_TIMEOUT: Duration = Duration::from_secs(30);

/// At most this many chunk files are fetched by one scan.
pub const MAX_CHUNK_FILES: usize = 3000;

/// Chunk fetches run this many at a time, preserving batch
/// order in the result.
pub const CHUNK_POOL: usize = 16;

/// The injectable cache for the subscription action id.
/// `Get` returns the stored id (`""` when none); `Set`
/// persists a newly discovered id. `FetchSubscription`
/// consults the store when no explicit id is given, and
/// stores a newly discovered id best-effort: a `Set` failure
/// never fails the subscription read itself.
pub trait ActionIDStore: Send + Sync {
    fn get_action_id(&self) -> String;
    fn set_action_id(&self, id: &str) -> Result<(), String>;
}

/// `FetchSubscription`'s arguments.
#[derive(Default)]
pub struct SubscriptionOptions {
    /// An explicit action id to try first (the configured
    /// `subscription_action_id`). Empty means "ask the store,
    /// then the default".
    pub action_id: String,
    /// Mirrors the page's `includeAgreement` arg.
    pub include_agreement: bool,
    /// Caches a newly discovered action id. `None` means "no
    /// cache".
    pub store: Option<Arc<dyn ActionIDStore>>,
    /// Overrides the settings page URL (tests only).
    /// `""` means [`SUBSCRIPTION_PAGE`].
    pub page: String,
}

/// One `callAction` outcome: the parsed RSC result (`None`
/// when the call produced no result — stale id), the wire
/// byte length of the RSC body it parsed (the wire length of
/// the body it READ on the non-200 / non-x-component branch
/// too), and whether that length is known (true whenever a
/// body was read, including a 0-byte body; false when no body
/// was read at all).
pub struct CallActionOutcome {
    pub result: Option<serde_json::Value>,
    pub body_len: usize,
    pub body_len_known: bool,
}

/// Returns the action's return value from a text/x-component
/// (RSC) body, ported verbatim from Go `ParseRSCResult`:
/// rows are the lines whose value starts with `{` or `[`,
/// parsed as JSON; row `"0"` holds a reference `{a:$@1}` to
/// the result row; otherwise row `"1"`, else the head row
/// itself. `None` is Go's `nil` — including a JSON `null`
/// result, which Go cannot distinguish from "no row".
pub fn parse_rsc_result(text: &str) -> Option<serde_json::Value> {
    let mut rows: HashMap<String, serde_json::Value> = HashMap::new();
    for line in text.split('\n') {
        let Some((key, val)) = line.split_once(':') else {
            continue;
        };
        if !(val.starts_with('{') || val.starts_with('[')) {
            continue;
        }
        // Go's Decoder.Decode reads ONE value and ignores
        // trailing data; a streaming deserializer does the same.
        let mut stream = serde_json::Deserializer::from_str(val).into_iter::<serde_json::Value>();
        if let Some(Ok(v)) = stream.next() {
            rows.insert(key.to_string(), v);
        }
    }
    let head = rows.get("0").cloned();
    if let Some(serde_json::Value::Object(hm)) = &head
        && let Some(serde_json::Value::String(r)) = hm.get("a")
        && let Some(rest) = r.strip_prefix("$@")
    {
        return match rows.get(rest) {
            Some(serde_json::Value::Null) | None => None,
            Some(v) => Some(v.clone()),
        };
    }
    if let Some(v) = rows.get("1") {
        return match v {
            serde_json::Value::Null => None,
            v => Some(v.clone()),
        };
    }
    match head {
        Some(serde_json::Value::Null) | None => None,
        Some(v) => Some(v),
    }
}

/// Posts one server-action call. A 401/403 is an AuthError. A
/// non-200 status or a response without `x-component` in its
/// content type returns a `None` result with the wire length
/// known: most likely a stale action id, and the caller tries
/// the next id. Transport errors pass through unchanged.
pub async fn call_action(
    client: &HttpClient,
    cookies: &str,
    action_id: &str,
    include_agreement: bool,
    page: &str,
) -> Result<CallActionOutcome, TransportError> {
    let body = Bytes::from(format!("[{{\"includeAgreement\":{include_agreement}}}]"));
    let mut headers = crate::auth::hatch_headers(cookies, "");
    // Go's h.Set replaces Accept/Content-Type in place.
    for (k, v) in headers.iter_mut() {
        if k == "Accept" {
            *v = "text/x-component".to_string();
        } else if k == "Content-Type" {
            *v = "text/plain;charset=UTF-8".to_string();
        }
    }
    headers.push(("Next-Action".to_string(), action_id.to_string()));
    let resp = request_url(
        client,
        Method::POST,
        page,
        &headers,
        Some(body),
        ACTION_TIMEOUT,
    )
    .await?;
    let mut data = resp.body.to_vec();
    data.truncate(HATCH_MAX_BODY);
    let status = resp.status.as_u16();
    if status == 401 || status == 403 {
        return Err(TransportError::Auth {
            message: format!("server action -> {status} (cookies expired? re-export)"),
        });
    }
    let ct = resp
        .headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if status != 200 || !ct.contains("x-component") {
        return Ok(CallActionOutcome {
            result: None,
            body_len: data.len(),
            body_len_known: true,
        });
    }
    let text = String::from_utf8_lossy(&data);
    Ok(CallActionOutcome {
        result: parse_rsc_result(&text),
        body_len: data.len(),
        body_len_known: true,
    })
}

/// Scans the web app's JS chunks for a server action's id
/// (slow: ~1k files). At most [`MAX_CHUNK_FILES`] chunk files
/// are fetched, [`CHUNK_POOL`] at a time. Chunk URLs
/// discovered inside fetched chunks are queued for the next
/// round. Iteration order is sorted (Go iterates a set
/// nondeterministically via a sorted batch here — only the
/// found id matters). Fetch failures yield empty text and are
/// skipped. The chunk base is derived from the page URL's
/// scheme+authority (Go hardcodes `https://muse.ai`, which is
/// identical in production).
pub async fn find_action_id(
    client: &HttpClient,
    cookies: &str,
    name: &str,
    page: &str,
) -> Result<String, TransportError> {
    let pat = action_id_pattern(name);
    // The page GET carries UA + Cookie; chunk GETs carry only
    // the browser UA, as in Python (no Cookie on chunk GETs).
    let page_headers = vec![
        ("User-Agent".to_string(), GATEWAY_USER_AGENT.to_string()),
        ("Cookie".to_string(), cookies.to_string()),
    ];
    let html = fetch_text(client, page, &page_headers, ACTION_TIMEOUT).await?;
    let base = url_base(page).ok_or_else(|| TransportError::Validation {
        message: format!("invalid page URL: {page}"),
    })?;
    let mut todo: BTreeSet<String> = BTreeSet::new();
    for m in chunk_ref_pattern().find_iter(&html) {
        todo.insert(m.as_str().to_string());
    }
    let mut seen: HashSet<String> = HashSet::new();
    let chunk_headers = vec![("User-Agent".to_string(), GATEWAY_USER_AGENT.to_string())];
    while !todo.is_empty() && seen.len() < MAX_CHUNK_FILES {
        // Sorted batch (BTreeSet order); Go sorts its batch.
        let batch: Vec<String> = todo.iter().cloned().collect();
        todo.clear();
        for p in &batch {
            seen.insert(p.clone());
        }
        let texts = fetch_all(client, &base, &batch, &chunk_headers, CHUNK_POOL).await;
        for text in &texts {
            if let Some(caps) = pat.captures(text) {
                return Ok(caps[1].to_string());
            }
            for c in chunk_ref_bare_pattern().find_iter(text) {
                let p = format!("/_next/{}", c.as_str());
                if !seen.contains(&p) {
                    todo.insert(p);
                }
            }
        }
    }
    Ok(String::new())
}

/// Returns the plan + usage object the Settings page shows,
/// and the action id that produced it.
pub async fn fetch_subscription(
    client: &HttpClient,
    cookies: &str,
    opts: SubscriptionOptions,
) -> Result<(serde_json::Map<String, serde_json::Value>, String), TransportError> {
    let page = if opts.page.is_empty() {
        SUBSCRIPTION_PAGE.to_string()
    } else {
        opts.page.clone()
    };
    let mut candidates: Vec<String> = vec![opts.action_id.clone()];
    if let Some(store) = &opts.store
        && opts.action_id.is_empty()
    {
        candidates[0] = store.get_action_id();
    }
    candidates.push(DEFAULT_SUBSCRIPTION_ACTION_ID.to_string());
    let mut tried: Vec<String> = Vec::new();
    let mut res: Option<serde_json::Value> = None;
    let mut aid = String::new();
    let mut res_len = 0usize;
    let mut res_len_known = false;
    for cand in &candidates {
        if cand.is_empty() {
            continue;
        }
        if tried.iter().any(|t| t == cand) {
            continue;
        }
        tried.push(cand.clone());
        let out = call_action(client, cookies, cand, opts.include_agreement, &page).await?;
        if out.result.is_some() {
            res = out.result;
            aid = cand.clone();
            res_len = out.body_len;
            res_len_known = out.body_len_known;
            break;
        }
    }
    if res.is_none() {
        let found = find_action_id(client, cookies, SUBSCRIPTION_ACTION_NAME, &page).await?;
        if found.is_empty() {
            // Go's Payload text ("could not find ... in the
            // web app bundle") is never printed by Go's
            // Error() either; the Rust error carries the same
            // status-only rendering.
            return Err(TransportError::Gateway(castctl_transport::BodySummary {
                status: -1,
                body_length: None,
                content_type: None,
                error_code: None,
            }));
        }
        let out = call_action(client, cookies, &found, opts.include_agreement, &page).await?;
        res = out.result;
        aid = found;
        res_len = out.body_len;
        res_len_known = out.body_len_known;
    }
    // Shape check: {"success":true,"subscription":{...}}.
    // A JSON null subscription is Go-nil (missing).
    let shape_ok = match &res {
        Some(serde_json::Value::Object(m)) => {
            m.get("success") == Some(&serde_json::Value::Bool(true))
                && matches!(m.get("subscription"), Some(v) if *v != serde_json::Value::Null)
        }
        _ => false,
    };
    if !shape_ok {
        // The "error" value is peer-controlled: only an
        // enum-shaped string parsed by key may be emitted.
        // A non-map result has no keys to parse.
        let err_map: Option<&serde_json::Map<String, serde_json::Value>> = match &res {
            Some(serde_json::Value::Object(m)) => match m.get("error") {
                Some(serde_json::Value::Object(em)) => Some(em),
                _ => Some(m),
            },
            _ => None,
        };
        let sum = summarize_parsed_body(
            "fetchSubscriptionAction failed",
            res_len,
            res_len_known,
            err_map,
            &["error"],
        );
        return Err(TransportError::Gateway(summary_to_body_summary(-1, &sum)));
    }
    let serde_json::Value::Object(m) = res.unwrap() else {
        unreachable!("shape_ok implies an object result")
    };
    let Some(serde_json::Value::Object(sub_map)) = m.get("subscription").cloned() else {
        // Same literal-payload case as "could not find" above:
        // Go's Payload text is never printed by Error().
        return Err(TransportError::Gateway(castctl_transport::BodySummary {
            status: -1,
            body_length: None,
            content_type: None,
            error_code: None,
        }));
    };
    if let Some(store) = &opts.store
        && !aid.is_empty()
        && aid != store.get_action_id()
    {
        let _ = store.set_action_id(&aid); // best-effort cache
    }
    Ok((sub_map, aid))
}

/// GETs one URL and returns its body as text, truncated at
/// 4 MiB like Go's `LimitReader`. Transport errors pass
/// through unchanged.
async fn fetch_text(
    client: &HttpClient,
    url: &str,
    headers: &[(String, String)],
    timeout: Duration,
) -> Result<String, TransportError> {
    let resp = request_url(client, Method::GET, url, headers, None, timeout).await?;
    let mut data = resp.body.to_vec();
    data.truncate(HATCH_MAX_BODY);
    // Go's string(data) holds arbitrary bytes; a chunk/page
    // body is text, so invalid UTF-8 is replaced (U+FFFD).
    Ok(String::from_utf8_lossy(&data).into_owned())
}

/// Fetches paths (relative to `base`) with a worker pool of
/// size `pool`, preserving batch order in the result.
/// Failures yield `""`.
async fn fetch_all(
    client: &HttpClient,
    base: &str,
    paths: &[String],
    headers: &[(String, String)],
    pool: usize,
) -> Vec<String> {
    use futures_util::stream::{self, StreamExt};
    let futures = paths.iter().map(|p| {
        let url = format!("{base}{p}");
        let headers = headers.to_vec();
        async move {
            fetch_text(client, &url, &headers, ACTION_TIMEOUT)
                .await
                .unwrap_or_default()
        }
    });
    // `buffered` (not `buffer_unordered`): batch order is
    // preserved in the result, like Go's indexed output.
    stream::iter(futures).buffered(pool).collect().await
}

/// The `createServerReference)("...",...,"<name>")` pattern
/// for one action name.
fn action_id_pattern(name: &str) -> Regex {
    Regex::new(&format!(
        "createServerReference\\)\\(\"([0-9a-f]{{20,}})\",[^)]{{0,120}}\"{}\"",
        regex::escape(name)
    ))
    .expect("action id pattern is static")
}

/// `/_next/static/chunks/<name>.js` references.
fn chunk_ref_pattern() -> &'static Regex {
    static PAT: OnceLock<Regex> = OnceLock::new();
    PAT.get_or_init(|| {
        Regex::new(r"/_next/static/chunks/[A-Za-z0-9_.-]+\.js").expect("static chunk pattern")
    })
}

/// Bare `static/chunks/<name>.js` references inside chunks.
fn chunk_ref_bare_pattern() -> &'static Regex {
    static PAT: OnceLock<Regex> = OnceLock::new();
    PAT.get_or_init(|| {
        Regex::new(r"static/chunks/[A-Za-z0-9_.-]+\.js").expect("static chunk pattern")
    })
}

/// Derives `scheme://authority` from a page URL (the chunk
/// base). `None` for an unparseable URL.
fn url_base(page: &str) -> Option<String> {
    let (scheme, rest) = page.split_once("://")?;
    if scheme != "https" && scheme != "http" {
        return None;
    }
    let authority = rest.split('/').next()?;
    if authority.is_empty() {
        return None;
    }
    Some(format!("{scheme}://{authority}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_rsc_result_cases() {
        // Port of Go TestParseRSCResult
        // (invite_subscription_test.go). Comparison is by
        // re-encoded JSON (Go's deepEqualJSON marshals both
        // sides).
        let cases: Vec<(&str, &str, Option<&str>)> = vec![
            (
                "ref row",
                "0:{\"a\":\"$@1\"}\n1:{\"success\":true,\"subscription\":{\"tier\":\"pro\"}}\n",
                // Compared by re-encoded JSON, like Go's
                // deepEqualJSON — object keys sort.
                Some(r#"{"subscription":{"tier":"pro"},"success":true}"#),
            ),
            (
                "row1 fallback",
                "0:{\"x\":1}\n1:{\"success\":true}\n",
                Some(r#"{"success":true}"#),
            ),
            (
                "head only",
                "0:{\"success\":true}\n",
                Some(r#"{"success":true}"#),
            ),
            (
                "bad json line skipped",
                "0:not json\n1:{\"a\":1}\n",
                Some(r#"{"a":1}"#),
            ),
            ("empty", "", None),
            ("array row", "0:[1,2]\n", Some("[1,2]")),
            // A JSON null result is Go-nil (no result).
            ("null row", "0:null\n", None),
            // A dangling reference resolves to nil.
            ("dangling ref", "0:{\"a\":\"$@9\"}\n", None),
        ];
        for (name, text, want) in cases {
            let got = parse_rsc_result(text);
            let got_json = got.as_ref().map(|v| serde_json::to_string(v).unwrap());
            assert_eq!(got_json.as_deref(), want, "{name}");
        }
    }

    #[test]
    fn action_id_pattern_cases() {
        let pat = action_id_pattern("fetchSubscriptionAction");
        let hit =
            "createServerReference)(\"abcdef1234567890abcdef\",{},\"fetchSubscriptionAction\")";
        let caps = pat.captures(hit).unwrap();
        assert_eq!(&caps[1], "abcdef1234567890abcdef");
        // Too short an id does not match (needs 20+ hex).
        assert!(
            pat.captures("createServerReference)(\"abc123\",{},\"fetchSubscriptionAction\")")
                .is_none()
        );
        // Another action name does not match.
        assert!(
            pat.captures("createServerReference)(\"abcdef1234567890abcdef\",{},\"otherAction\")")
                .is_none()
        );
        // The 120-char gap bound: a longer gap does not match.
        let gap = "x".repeat(121);
        assert!(pat
            .captures(&format!(
                "createServerReference)(\"abcdef1234567890abcdef\",{gap},\"fetchSubscriptionAction\")"
            ))
            .is_none());
    }

    #[test]
    fn chunk_ref_patterns() {
        let html = r#"<script src="/_next/static/chunks/abc-1.js"></script>"#;
        let found: Vec<&str> = chunk_ref_pattern()
            .find_iter(html)
            .map(|m| m.as_str())
            .collect();
        assert_eq!(found, ["/_next/static/chunks/abc-1.js"]);
        // The bare pattern matches inside fetched chunks.
        let chunk = "import(\"static/chunks/def_2.js\")";
        let found: Vec<&str> = chunk_ref_bare_pattern()
            .find_iter(chunk)
            .map(|m| m.as_str())
            .collect();
        assert_eq!(found, ["static/chunks/def_2.js"]);
    }

    #[test]
    fn url_base_cases() {
        assert_eq!(
            url_base("https://muse.ai/settings"),
            Some("https://muse.ai".to_string())
        );
        assert_eq!(
            url_base("http://127.0.0.1:1234/settings"),
            Some("http://127.0.0.1:1234".to_string())
        );
        assert_eq!(url_base("not a url"), None);
    }
}
