// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Origin check (`internal/webui/origin.go` `allowedOrigin`
//! and `internal/webui/screencast.go` `originHost` /
//! `isLoopbackHost` / WS `CheckOrigin`).
//!
//! The two checks are DIFFERENT and must not be unified:
//! - API (`allowedOrigin`): `url.Parse` first (error, empty
//!   host, or userinfo → reject), then loopback via
//!   `isLoopbackHost(originHost(...))`, then the URL
//!   hostname compared to the request host with the port
//!   stripped, case-insensitive.
//! - WS (`CheckOrigin`): no URL parse; `originHost` (WITH
//!   port) is loopback, or exactly equals `r.Host`
//!   (port-sensitive).
//!
//! Both run after auth. The API check runs only on
//! POST/PUT/PATCH/DELETE; no `Origin` header → allowed in
//! both. A rejected API origin is a fixed 403 `forbidden` /
//! `cross-origin request rejected` with no value echo.

/// `originHost` (`screencast.go`): strip scheme, then
/// path/query/fragment. The port and brackets are KEPT
/// (e.g. `http://[::1]:3000/x` → `[::1]:3000`).
pub fn origin_host(origin: &str) -> String {
    let rest = match origin.find("://") {
        Some(idx) => &origin[idx + 3..],
        None => origin,
    };
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    rest[..end].to_string()
}

/// `isLoopbackHost` (`screencast.go`): strip the port at
/// the LAST `:`, trim leading/trailing `[`/`]`, then
/// `localhost` or `net.ParseIP(...).IsLoopback()`.
/// Note the Go quirk: a bare `::1` (no port, no brackets)
/// strips to `:` → trimmed to `""` → NOT loopback. A URL
/// origin never carries a bare `::1`, so this is inert in
/// practice — but it is replicated, not "fixed".
pub fn is_loopback_host(host: &str) -> bool {
    let mut h = host;
    if let Some(idx) = h.rfind(':') {
        h = &h[..idx];
    }
    let h = h.trim_matches(|c| c == '[' || c == ']');
    if h == "localhost" {
        return true;
    }
    match h.parse::<std::net::IpAddr>() {
        Ok(ip) => ip.is_loopback(),
        Err(_) => false,
    }
}

/// Parsed Origin authority for the API check: the raw host
/// (with port, brackets kept) and the hostname (port and
/// brackets stripped). `None` when Go's `url.Parse` would
/// error or `u.Host` would be empty, or when userinfo is
/// present (`u.User != nil` → reject).
fn parse_origin_authority(origin: &str) -> Option<(String, String)> {
    // Control characters and spaces make url.Parse fail.
    if origin.bytes().any(|b| b < 0x20 || b == 0x7f || b == b' ') {
        return None;
    }
    let rest = if let Some(idx) = origin.find("://") {
        &origin[idx + 3..]
    } else {
        origin.strip_prefix("//")?
    };
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..end];
    if authority.is_empty() {
        return None;
    }
    // Any '@' in the authority is userinfo: Go rejects.
    if authority.contains('@') {
        return None;
    }
    // Hostname: brackets for IPv6, then an optional
    // :port that must be all digits (Go's
    // validOptionalPort; no range check at parse time).
    let hostname = if let Some(bracketed) = authority.strip_prefix('[') {
        let close = bracketed.find(']')?;
        let host = &bracketed[..close];
        let after = &bracketed[close + 1..];
        if after.is_empty() {
            host.to_string()
        } else {
            let port = after.strip_prefix(':')?;
            if port.is_empty() || port.bytes().all(|b| b.is_ascii_digit()) {
                host.to_string()
            } else {
                return None;
            }
        }
    } else {
        match authority.rfind(':') {
            Some(idx) => {
                let port = &authority[idx + 1..];
                if port.is_empty() || port.bytes().all(|b| b.is_ascii_digit()) {
                    authority[..idx].to_string()
                } else {
                    return None;
                }
            }
            None => authority.to_string(),
        }
    };
    if hostname.is_empty() {
        return None;
    }
    Some((authority.to_string(), hostname))
}

/// API origin check (`allowedOrigin`): true when the
/// request is allowed through. `origin` is the raw
/// `Origin` header value (or `None` when absent);
/// `host` is the request `Host` header.
pub fn api_origin_allowed(origin: Option<&str>, host: &str) -> bool {
    let Some(origin) = origin else {
        return true;
    };
    let Some((_, hostname)) = parse_origin_authority(origin) else {
        return false;
    };
    if is_loopback_host(&origin_host(origin)) {
        return true;
    }
    if hostname.is_empty() {
        return false;
    }
    // Request host: SplitHostPort when possible, then trim
    // brackets; compare case-insensitively.
    let mut req_host = host;
    if let Some(idx) = host.rfind(':') {
        let (h, port) = (&host[..idx], &host[idx + 1..]);
        if !h.contains(':') && port.bytes().all(|b| b.is_ascii_digit()) {
            req_host = h;
        }
    }
    let req_host = req_host.trim_matches(|c| c == '[' || c == ']');
    hostname.eq_ignore_ascii_case(req_host)
}

/// WS `CheckOrigin` (`screencast.go`): true when the origin
/// host (WITH port) is loopback or exactly equals the
/// request `Host`. Port-sensitive by design.
pub fn ws_origin_allowed(origin: Option<&str>, host: &str) -> bool {
    let Some(origin) = origin else {
        return true;
    };
    let hostport = origin_host(origin);
    if hostport.is_empty() {
        return false;
    }
    is_loopback_host(&hostport) || hostport == host
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin_host_keeps_port_and_brackets() {
        assert_eq!(origin_host("http://[::1]:3000/x"), "[::1]:3000");
        assert_eq!(origin_host("https://127.0.0.1:3000"), "127.0.0.1:3000");
        assert_eq!(origin_host("https://example.com/a?b#c"), "example.com");
        assert_eq!(origin_host(""), "");
    }

    #[test]
    fn is_loopback_host_strips_port() {
        assert!(is_loopback_host("127.0.0.1:3000"));
        assert!(is_loopback_host("[::1]:3000"));
        assert!(is_loopback_host("localhost:3000"));
        assert!(is_loopback_host("127.0.0.1"));
        assert!(!is_loopback_host("192.168.1.1:3000"));
        assert!(!is_loopback_host("example.com:3000"));
        // Go quirk: a bare ::1 strips to "" and is NOT
        // loopback under this helper.
        assert!(!is_loopback_host("::1"));
    }

    #[test]
    fn api_origin_rules() {
        // No Origin: allowed.
        assert!(api_origin_allowed(None, "127.0.0.1:8317"));
        // Loopback origins, any port: allowed.
        assert!(api_origin_allowed(
            Some("http://127.0.0.1:3000"),
            "127.0.0.1:8317"
        ));
        assert!(api_origin_allowed(
            Some("http://localhost:3000"),
            "127.0.0.1:8317"
        ));
        assert!(api_origin_allowed(
            Some("http://[::1]:3000"),
            "127.0.0.1:8317"
        ));
        // Same host (port stripped): allowed.
        assert!(api_origin_allowed(
            Some("https://example.com"),
            "example.com:8317"
        ));
        assert!(api_origin_allowed(
            Some("https://EXAMPLE.com"),
            "example.com:8317"
        ));
        // Cross-origin: rejected.
        assert!(!api_origin_allowed(
            Some("https://evil.example"),
            "127.0.0.1:8317"
        ));
        assert!(!api_origin_allowed(
            Some("https://evil.example"),
            "example.com:8317"
        ));
        // Opaque "null" origin, userinfo, malformed: rejected.
        assert!(!api_origin_allowed(Some("null"), "127.0.0.1:8317"));
        assert!(!api_origin_allowed(
            Some("https://user@127.0.0.1"),
            "127.0.0.1:8317"
        ));
        assert!(!api_origin_allowed(
            Some("http://example.com:abc"),
            "example.com:8317"
        ));
        assert!(!api_origin_allowed(Some("example.com"), "example.com:8317"));
    }

    #[test]
    fn ws_origin_is_port_sensitive() {
        // Same host AND port: allowed.
        assert!(ws_origin_allowed(
            Some("http://127.0.0.1:8317"),
            "127.0.0.1:8317"
        ));
        // Loopback is allowed regardless of port (the
        // loopback branch, not the equality branch).
        assert!(ws_origin_allowed(
            Some("http://127.0.0.1:3000"),
            "127.0.0.1:8317"
        ));
        // Non-loopback, same host, different port: the WS
        // check compares WITH the port, so this is rejected
        // — unlike the API check, which strips the port.
        assert!(!ws_origin_allowed(
            Some("https://example.com:3000"),
            "example.com:8317"
        ));
        assert!(ws_origin_allowed(
            Some("https://example.com:8317"),
            "example.com:8317"
        ));
        // No Origin: allowed. Empty origin host: rejected.
        assert!(ws_origin_allowed(None, "127.0.0.1:8317"));
        assert!(!ws_origin_allowed(Some(""), "127.0.0.1:8317"));
    }

    #[test]
    fn fail_before_origin_check() {
        // If the check were dropped, a cross-origin POST
        // would reach the handler; this pins the 403.
        assert!(!api_origin_allowed(
            Some("https://evil.example"),
            "127.0.0.1:8317"
        ));
        assert!(!ws_origin_allowed(
            Some("https://evil.example:9999"),
            "127.0.0.1:8317"
        ));
    }
}
