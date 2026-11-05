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
        Ok(ip) => {
            // Go's `net.ParseIP(host).IsLoopback()` maps
            // an IPv4-mapped IPv6 address
            // (`::ffff:127.0.0.1`) through `To4()` first,
            // so it is loopback; std's `is_loopback()` on
            // the V6 form is false.
            if let std::net::IpAddr::V6(v6) = ip
                && let Some(v4) = v6.to_ipv4_mapped()
            {
                return v4.is_loopback();
            }
            ip.is_loopback()
        }
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
    // Request host: `net.SplitHostPort` when possible,
    // then trim brackets; compare case-insensitively.
    // On a split error Go keeps the host as-is.
    let req_host = split_host_port(host).unwrap_or(host);
    let req_host = req_host.trim_matches(|c| c == '[' || c == ']');
    hostname.eq_ignore_ascii_case(req_host)
}

/// `net.SplitHostPort` for a request Host: a bracketed
/// IPv6 host yields the text up to `]`; a bare host splits
/// at the last `:` only when the port is all digits and the
/// host part holds no `:`. `None` when Go would error
/// (missing port, non-digit port, missing `]`, bare IPv6
/// with too many colons) — the caller then keeps the host
/// as-is, exactly as Go does on error.
fn split_host_port(host: &str) -> Option<&str> {
    if let Some(bracketed) = host.strip_prefix('[') {
        let close = bracketed.find(']')?;
        let after = &bracketed[close + 1..];
        if after.is_empty() {
            return None;
        }
        let port = after.strip_prefix(':')?;
        if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        Some(&bracketed[..close])
    } else {
        let idx = host.rfind(':')?;
        let h = &host[..idx];
        let port = &host[idx + 1..];
        if h.contains(':') || port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        Some(h)
    }
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
    #[test]
    fn mapped_v6_loopback_is_loopback() {
        // F-A2: Go's net.ParseIP(...).IsLoopback() maps
        // ::ffff:127.0.0.1 through To4() first.
        assert!(is_loopback_host("::ffff:127.0.0.1"));
        assert!(is_loopback_host("::ffff:127.0.0.1:3000"));
        assert!(api_origin_allowed(
            Some("http://[::ffff:127.0.0.1]:3000"),
            "127.0.0.1:8317"
        ));
        // A mapped non-loopback address is not loopback.
        assert!(!is_loopback_host("::ffff:192.0.2.1"));
    }

    #[test]
    fn ipv6_request_host_with_port() {
        // F-A4: Go's SplitHostPort on the request Host:
        // [::1]:8317 compares as ::1.
        assert!(api_origin_allowed(
            Some("http://[::1]:3000"),
            "[::1]:8317"
        ));
        assert!(api_origin_allowed(
            Some("http://127.0.0.1:3000"),
            "127.0.0.1:8317"
        ));
        // A bare ::1 request host (no port) is kept as-is
        // by Go's SplitHostPort error path and still
        // matches after trimming.
        assert!(api_origin_allowed(Some("http://[::1]:3000"), "[::1]"));
    }

    #[test]
    fn uppercase_scheme_origin_is_parsed() {
        // Safety L-2 premise check: the reviewer assumed
        // an uppercase scheme (`HTTP://...`) defeats the
        // scheme strip. It does not — `find("://")`
        // matches the (lowercase) separator symbols, so
        // the origin parses and the loopback rule applies.
        // Recorded, not "fixed": the check is already
        // scheme-agnostic and fail-closed either way.
        assert!(api_origin_allowed(
            Some("HTTP://127.0.0.1:3000"),
            "127.0.0.1:8317"
        ));
        assert!(api_origin_allowed(
            Some("HTTP://[::1]:3000"),
            "[::1]:8317"
        ));
    }

}
