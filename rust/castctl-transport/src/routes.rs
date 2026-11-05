// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Route table for gateway RPC.
//!
//! Go sources: `internal/proto/routes.json` (the data, 258 entries at
//! the M3 base), `internal/gateway/routes.go:78-116`
//! (`DefaultRoutes`, `ParseRoutes`, `RouteTable.LookupRoute`),
//! `internal/conn/gateway.go:132-137` (`Route` shape) and
//! `:316-318` (the `Gateway.LookupRoute` interface method).
//!
//! The table is embedded at compile time from the Go file itself
//! (`include_str!` of `internal/proto/routes.json`), not copied into
//! a Rust literal: the JSON stays the single source of truth, and a
//! drift in the Go table fails the count test below until PORTING.md
//! is updated. A route is method → HTTP verb + path template +
//! service only; there is NO host in a route (the brief's "host"
//! belongs to the gateway connection / dial target, not the table).
//!
//! Service mapping (`internal/gateway/routes.go:20-32` `serviceID`):
//! `sentinel`/`vault`/`authd` map to their own ids; every other name
//! — and an absent `service` field, which is 219 of 258 entries —
//! maps to `daemon` (0). Absent service is NOT an error.

use crate::error::TransportError;

/// One route entry: method → HTTP verb + path template + service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    pub method: String,
    /// HTTP verb as written in `routes.json` (`GET`/`POST`/…).
    pub http: String,
    /// Path template, e.g. `/api/chat/{thread_id}/seen`.
    pub path: String,
    /// Service id; absent in JSON means `daemon`.
    pub service: Service,
}

/// Service ids from Go `internal/gateway/routes.go:20-32`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Service {
    Daemon,
    Sentinel,
    Vault,
    Authd,
}

impl Service {
    /// Map a JSON service name to an id. No Go function counterpart
    /// for this constructor itself; the mapping is Go
    /// `serviceID(name)` — every name other than the three listed
    /// below, including absent, falls through to `Daemon`.
    pub fn from_name(name: Option<&str>) -> Self {
        match name {
            Some("sentinel") => Service::Sentinel,
            Some("vault") => Service::Vault,
            Some("authd") => Service::Authd,
            _ => Service::Daemon,
        }
    }
}

/// The parsed route table. Parse once at construction; a parse error
/// is a construction error, never a per-call error (Go
/// `DefaultRoutes` uses `sync.Once` the same way).
#[derive(Debug, Clone)]
pub struct RouteTable {
    entries: Vec<Route>,
}

impl RouteTable {
    /// Parse the embedded `routes.json` (the Go file, via
    /// `include_str!`). Entries without a `method` are skipped;
    /// on a duplicate method the FIRST entry wins, but duplicates
    /// still count toward the total (Go `ParseRoutes`).
    pub fn default_routes() -> Result<Self, TransportError> {
        // Path is relative to this file: src/ -> crate root ->
        // rust/ -> repo root -> internal/proto/routes.json.
        let data = include_str!("../../../internal/proto/routes.json");
        Self::parse(data)
    }

    /// Parse route JSON in the `routes.json` shape (a list of
    /// objects with `method`, `http`, `path`, optional `service`).
    /// Extra fields (`aliases`, `noiseOnly`, `streamMode`, …) are
    /// ignored, exactly as Go `ParseRoutes` ignores them.
    pub fn parse(data: &str) -> Result<Self, TransportError> {
        let value: serde_json::Value =
            serde_json::from_str(data).map_err(|e| TransportError::Validation {
                message: format!("route table parse: {e}"),
            })?;
        let list = value.as_array().ok_or_else(|| TransportError::Validation {
            message: "route table is not a JSON array".to_string(),
        })?;
        let mut entries: Vec<Route> = Vec::new();
        for entry in list {
            let Some(method) = entry.get("method").and_then(|m| m.as_str()) else {
                continue;
            };
            if entries.iter().any(|e| e.method == method) {
                continue; // first wins, duplicates still counted by caller
            }
            let http = entry
                .get("http")
                .and_then(|h| h.as_str())
                .unwrap_or("")
                .to_string();
            let path = entry
                .get("path")
                .and_then(|p| p.as_str())
                .unwrap_or("")
                .to_string();
            entries.push(Route {
                method: method.to_string(),
                http,
                path,
                service: Service::from_name(entry.get("service").and_then(|s| s.as_str())),
            });
        }
        Ok(Self { entries })
    }

    /// Look up a method. Unknown methods return `None` — never a
    /// synthesized route (Go `LookupRoute` returns `false`).
    pub fn lookup_route(&self, method: &str) -> Option<&Route> {
        self.entries.iter().find(|e| e.method == method)
    }

    /// Number of distinct (first-win) entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when the table holds no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Percent-encode one path parameter value the way Go
/// `internal/gateway/media.go:19-35` `quotePython(v, "")` does:
/// unreserved `[A-Za-z0-9_.-~]` pass through, everything else —
/// including `/` — becomes `%XX` uppercase hex, byte by byte over
/// the UTF-8 encoding.
pub fn quote_path_param(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for &b in value.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Build a request path from a template: replace every `{k}` with
/// the quoted parameter, then append the query string (keys sorted,
/// standard encoding) with `?` or `&` when the template already
/// contains `?`. Go: `internal/gateway/stream.go:188-208`
/// `buildPath` (query via `url.Values.Encode`, which sorts keys).
pub fn build_path(
    template: &str,
    path_params: &[(String, String)],
    query: &[(String, String)],
) -> String {
    let mut path = template.to_string();
    for (k, v) in path_params {
        path = path.replace(&format!("{{{k}}}"), &quote_path_param(v));
    }
    if !query.is_empty() {
        let mut sorted: Vec<(&String, &String)> = query.iter().map(|(k, v)| (k, v)).collect();
        sorted.sort_by(|a, b| a.0.cmp(b.0));
        let qs = sorted
            .iter()
            .map(|(k, v)| format!("{}={}", url_encode(k), url_encode(v)))
            .collect::<Vec<_>>()
            .join("&");
        if path.contains('?') {
            path.push('&');
        } else {
            path.push('?');
        }
        path.push_str(&qs);
    }
    path
}

/// Query-string encoding matching Go `url.Values.Encode` closely
/// enough for RPC query values: unreserved pass, space becomes `+`,
/// everything else `%XX` uppercase.
fn url_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for &b in value.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-' | b'~') {
            out.push(b as char);
        } else if b == b' ' {
            out.push('+');
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_table_parses_and_counts() {
        let table = RouteTable::default_routes().expect("INVARIANT: embedded routes.json parses");
        // Count measured at the M3 base (dev-rust 664f263) from
        // internal/proto/routes.json; a drift here means the Go
        // table changed and PORTING.md §M3 must be updated.
        assert_eq!(table.len(), 258);
        let route = table
            .lookup_route("chat.history")
            .expect("INVARIANT: chat.history is in routes.json");
        assert_eq!(route.http, "GET");
        assert_eq!(route.path, "/chat/history");
        assert_eq!(route.service, Service::Daemon);
        let seen = table
            .lookup_route("chat.mark_seen")
            .expect("INVARIANT: chat.mark_seen is in routes.json");
        assert_eq!(seen.http, "POST");
        assert_eq!(seen.path, "/api/chat/{thread_id}/seen");
        assert!(table.lookup_route("no.such.method").is_none());
    }

    #[test]
    fn service_absent_is_daemon_and_duplicates_first_wins() {
        let table = RouteTable::parse(
            r#"[{"method":"a.b","http":"GET","path":"/x"},
                {"method":"a.b","http":"POST","path":"/y"},
                {"method":"c.d","http":"GET","path":"/z","service":"sentinel"},
                {"http":"GET","path":"/no-method"}]"#,
        )
        .expect("INVARIANT: test fixture parses");
        assert_eq!(table.len(), 2);
        assert_eq!(
            table.lookup_route("a.b").map(|r| r.path.as_str()),
            Some("/x")
        );
        assert_eq!(
            table.lookup_route("c.d").map(|r| r.service),
            Some(Service::Sentinel)
        );
    }

    #[test]
    fn path_param_quoting_escapes_slash() {
        assert_eq!(quote_path_param("a/b c"), "a%2Fb%20c");
        assert_eq!(
            build_path(
                "/api/chat/{thread_id}/seen",
                &[("thread_id".to_string(), "t/1".to_string())],
                &[]
            ),
            "/api/chat/t%2F1/seen"
        );
        assert_eq!(
            build_path(
                "/x",
                &[],
                &[
                    ("b".to_string(), "2".to_string()),
                    ("a".to_string(), "1".to_string())
                ]
            ),
            "/x?a=1&b=2"
        );
    }
}
