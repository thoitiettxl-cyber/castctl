// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! The `keeper` config block — port of
//! `internal/profile/keeper.go`.
//!
//! One parsed `keeper` list entry per profile, with the
//! documented zero-value defaults and the `Effective*`
//! accessors the keeper reads. Validation runs at parse
//! time in the `ParseSingleConfig` tail, after
//! `validateTagGraph`, mirroring `validateTelegram`.
//!
//! Sources: `internal/profile/keeper.go` (base
//! `dev-rust` `07e1c0d`).

use std::time::Duration;

use crate::errors::ConfigError;
use crate::gostr::{go_quote, go_trim_space};
use crate::jsonvalue::{JsonValue, OrderedObject};
use crate::profile::validate_profile_name;

/// The documented zero-value cadence for a keeper entry
/// whose `interval` key is absent or empty: 24h
/// (`keeper.go:195`).
pub const DEFAULT_KEEPER_INTERVAL: Duration = Duration::from_secs(24 * 3600);
/// Bounds a configured `interval`
/// (`keeper.go:201`).
pub const MAX_KEEPER_INTERVAL: Duration = Duration::from_secs(365 * 24 * 3600);
/// Bounds a configured `proxy_dial_timeout`
/// (`keeper.go:207`).
pub const MAX_PROXY_DIAL_TIMEOUT: Duration = Duration::from_secs(60);
/// Bounds a configured `relogin_match_timeout`,
/// `relogin_cookie_timeout`, `observe_settle_timeout`,
/// and `observe_timeout` (`keeper.go:216`).
pub const MAX_RELOGIN_WAIT_TIMEOUT: Duration = Duration::from_secs(10 * 60);
/// Bounds a configured `relogin_poll_interval`
/// (`keeper.go:222`).
pub const MAX_RELOGIN_POLL_INTERVAL: Duration = Duration::from_secs(60);
/// The documented zero-value transient retry ladder
/// (`keeper.go:230`): 5m, 15m, 45m, max 3 retries.
pub const DEFAULT_RETRY_BACKOFF: [Duration; 3] = [
    Duration::from_secs(5 * 60),
    Duration::from_secs(15 * 60),
    Duration::from_secs(45 * 60),
];
/// Bounds a configured `retry_backoff` list
/// (`keeper.go:236`).
pub const MAX_RETRY_BACKOFF_STEPS: usize = 8;
/// The documented zero-value "expiring" window
/// (`keeper.go:241`): 72h.
pub const DEFAULT_EXPIRING_WITHIN: Duration = Duration::from_secs(72 * 3600);
/// The documented zero-value cap for `wake_attempts` and
/// `relogin_attempts` (`keeper.go:246`): 3.
pub const DEFAULT_KEEPER_ATTEMPTS: i64 = 3;
/// Bounds a configured `wake_attempts` /
/// `relogin_attempts` value (`keeper.go:250`).
pub const MAX_KEEPER_ATTEMPTS: i64 = 10;
/// S10 operational defaults (`keeper.go:260-270`).
pub const DEFAULT_PROXY_DIAL_TIMEOUT: Duration = Duration::from_secs(30);
pub const DEFAULT_PROXY_MAX_HEADER_BYTES: i64 = 64 << 10;
pub const DEFAULT_PROXY_MAX_BODY_BYTES: i64 = 16 << 20;
pub const DEFAULT_RELOGIN_MATCH_TIMEOUT: Duration = Duration::from_secs(30);
pub const DEFAULT_RELOGIN_COOKIE_TIMEOUT: Duration = Duration::from_secs(30);
pub const DEFAULT_RELOGIN_POLL_INTERVAL: Duration = Duration::from_millis(500);
pub const DEFAULT_RELOGIN_ATTACH_TIMEOUT: Duration = Duration::from_secs(10);
pub const DEFAULT_RELOGIN_CANCEL_TIMEOUT: Duration = Duration::from_secs(10);
pub const DEFAULT_OBSERVE_SETTLE_TIMEOUT: Duration = Duration::from_secs(15);
pub const DEFAULT_OBSERVE_TIMEOUT: Duration = Duration::from_secs(90);
pub const DEFAULT_OBSERVE_INVENTORY_CAP: i64 = 200;
/// The documented zero-value S2 proxy allowlist
/// (`keeper.go:283`).
pub const DEFAULT_PROXY_ALLOWED_HOSTS: [&str; 5] = [
    "auth.muse.ai",
    "muse.ai",
    "www.facebook.com",
    "www.instagram.com",
    "auth.meta.com",
];
/// Schema bounds (`keeper.go:295-297`): not themselves
/// configurable.
pub const MAX_PROXY_HEADER_BYTES: i64 = 1 << 20;
pub const MAX_PROXY_BODY_BYTES: i64 = 1 << 30;
pub const MAX_OBSERVE_INVENTORY_CAP: i64 = 10000;

/// One parsed `keeper` list entry
/// (`keeper.go:299-380`).
#[derive(Debug, Clone, Default)]
pub struct KeeperEntry {
    pub tag: String,
    pub profile: String,
    pub browser: String,
    pub interval: Duration,
    /// Whether the `interval` key was present with a
    /// non-empty value. A zero `interval` with
    /// `interval_set` false means "use
    /// `DEFAULT_KEEPER_INTERVAL`".
    pub interval_set: bool,
    /// `""` (no notification) or `"telegram"`.
    pub notify: String,
    /// `""` (no auto re-login) or the tag of a
    /// `credentials` entry naming this profile.
    pub credentials: String,
    /// Whether the `wake_on_gateway_failure` key was
    /// present; absent means true.
    pub wake_on_gateway_failure: bool,
    pub wake_set: bool,
    pub retry_backoff: Vec<Duration>,
    pub retry_backoff_set: bool,
    pub expiring_within: Duration,
    pub expiring_set: bool,
    pub wake_attempts: i64,
    pub wake_attempts_set: bool,
    pub relogin_attempts: i64,
    pub relogin_set: bool,
    pub proxy_dial_timeout: Duration,
    pub proxy_dial_set: bool,
    pub proxy_max_header_bytes: i64,
    pub proxy_max_header_set: bool,
    pub proxy_max_body_bytes: i64,
    pub proxy_max_body_set: bool,
    pub proxy_allowed_hosts: Vec<String>,
    pub proxy_hosts_set: bool,
    pub relogin_match_timeout: Duration,
    pub relogin_match_set: bool,
    pub relogin_cookie_timeout: Duration,
    pub relogin_cookie_set: bool,
    pub relogin_poll_interval: Duration,
    pub relogin_poll_set: bool,
    pub relogin_attach_timeout: Duration,
    pub relogin_attach_set: bool,
    pub relogin_cancel_timeout: Duration,
    pub relogin_cancel_set: bool,
    pub observe_settle_timeout: Duration,
    pub observe_settle_set: bool,
    pub observe_timeout: Duration,
    pub observe_timeout_set: bool,
    pub observe_inventory_cap: i64,
    pub observe_inventory_set: bool,
}

/// One parsed top-level `keeper` block: the list of
/// entries in file order. `None` means the block was
/// absent (`keeper.go:414-419`).
#[derive(Debug, Clone, Default)]
pub struct KeeperConfig {
    pub entries: Vec<KeeperEntry>,
}

const KEEPER_ENTRY_KEYS: [&str; 23] = [
    "tag",
    "profile",
    "browser",
    "interval",
    "notify",
    "credentials",
    "wake_on_gateway_failure",
    "retry_backoff",
    "expiring_within",
    "wake_attempts",
    "relogin_attempts",
    "proxy_dial_timeout",
    "proxy_max_header_bytes",
    "proxy_max_body_bytes",
    "proxy_allowed_hosts",
    "relogin_match_timeout",
    "relogin_cookie_timeout",
    "relogin_poll_interval",
    "relogin_attach_timeout",
    "relogin_cancel_timeout",
    "observe_settle_timeout",
    "observe_timeout",
    "observe_inventory_cap",
];

// ---------------------------------------------------------------------------
// Go duration strings
// ---------------------------------------------------------------------------

/// Parse a Go `time.ParseDuration` string, returning
/// nanoseconds (`i64`). Mirrors Go `time/format.go`
/// (`ParseDuration`, `leadingInt`, `leadingFraction`,
/// go1.27) exactly, including its overflow shape: the
/// accumulator is `u64`, the integer part errors when it
/// would exceed `1<<63`, the fraction is `f64`
/// (`f * (unit / scale)`, digits past the `u64` limit
/// are dropped AND stop growing the scale), the sign is
/// applied last (so `-9223372036854775808ns` is
/// `i64::MIN`). Errors never echo the input.
pub fn parse_go_duration(s: &str) -> Result<i64, String> {
    let mut rest = s;
    let mut neg = false;
    if !rest.is_empty() {
        let c = rest.as_bytes()[0];
        if c == b'-' || c == b'+' {
            neg = c == b'-';
            rest = &rest[1..];
        }
    }
    // Special case: if all that is left is "0", this is
    // zero — after the sign is stripped, so "-0"/"+0"
    // are 0 (Go `ParseDuration`).
    if rest == "0" {
        return Ok(0);
    }
    if rest.is_empty() {
        return Err("time: invalid duration".to_string());
    }
    let mut d: u64 = 0;
    while !rest.is_empty() {
        let b0 = rest.as_bytes()[0];
        if !(b0 == b'.' || b0.is_ascii_digit()) {
            return Err("time: invalid duration".to_string());
        }
        let (mut v, rem) = leading_int(rest)?;
        let pre = rem.len() != rest.len();
        rest = rem;
        let mut f: u64 = 0;
        let mut scale: f64 = 1.0;
        let mut post = false;
        if !rest.is_empty() && rest.as_bytes()[0] == b'.' {
            rest = &rest[1..];
            let (f0, scale0, rem2) = leading_fraction(rest);
            f = f0;
            scale = scale0;
            post = rem2.len() != rest.len();
            rest = rem2;
        }
        if !pre && !post {
            // No digits (e.g. ".s" or "-.s").
            return Err("time: invalid duration".to_string());
        }
        // Consume unit (up to the next '.' or digit).
        let mut i = 0usize;
        let rb = rest.as_bytes();
        while i < rb.len() {
            let c = rb[i];
            if c == b'.' || c.is_ascii_digit() {
                break;
            }
            i += 1;
        }
        if i == 0 {
            return Err("time: missing unit in duration".to_string());
        }
        let u = &rest[..i];
        rest = &rest[i..];
        let unit: u64 = match u {
            "ns" => 1,
            "us" | "µs" | "μs" => 1_000,
            "ms" => 1_000_000,
            "s" => 1_000_000_000,
            "m" => 60_000_000_000,
            "h" => 3_600_000_000_000,
            _ => return Err("time: unknown unit".to_string()),
        };
        if v > (1u64 << 63) / unit {
            return Err("time: invalid duration".to_string());
        }
        v *= unit;
        if f > 0 {
            // `f < scale` always (f has at most as many
            // digits as scale's exponent), so this is
            // `< unit <= 3.6e12` — safely in `u64` range.
            v += (f as f64 * (unit as f64 / scale)) as u64;
            if v > 1u64 << 63 {
                return Err("time: invalid duration".to_string());
            }
        }
        // Go adds into a `u64` and checks `d > 1<<63`:
        // the sum can only wrap at exactly `2^64`
        // (`d == v == 1<<63`), which Go reads back as 0.
        // `wrapping_add` mirrors that arithmetic.
        d = d.wrapping_add(v);
        if d > 1u64 << 63 {
            return Err("time: invalid duration".to_string());
        }
    }
    if neg {
        // `d == 1<<63` negates to `i64::MIN` (Go
        // `-Duration(d)`); `wrapping_neg` is exact here.
        return Ok((d as i64).wrapping_neg());
    }
    if d > (1u64 << 63) - 1 {
        return Err("time: invalid duration".to_string());
    }
    Ok(d as i64)
}

/// Go `leadingInt`: consume `[0-9]*`, erroring when the
/// value would exceed `1<<63` (the check is `>` on both
/// the pre-multiply guard and the result, so exactly
/// `1<<63` is accepted and rejected later by the unit
/// / final checks).
fn leading_int(s: &str) -> Result<(u64, &str), String> {
    let b = s.as_bytes();
    let mut i = 0usize;
    let mut x: u64 = 0;
    while i < b.len() && b[i].is_ascii_digit() {
        if x > (1u64 << 63) / 10 {
            return Err("time: invalid duration".to_string());
        }
        x = x * 10 + (b[i] - b'0') as u64;
        if x > 1u64 << 63 {
            return Err("time: invalid duration".to_string());
        }
        i += 1;
    }
    Ok((x, &s[i..]))
}

/// Go `leadingFraction`: consume `[0-9]*`; on overflow
/// it stops accumulating precision — the extra digits
/// are dropped AND the scale stops growing.
fn leading_fraction(s: &str) -> (u64, f64, &str) {
    let b = s.as_bytes();
    let mut i = 0usize;
    let mut x: u64 = 0;
    let mut scale: f64 = 1.0;
    let mut overflow = false;
    while i < b.len() && b[i].is_ascii_digit() {
        if overflow {
            i += 1;
            continue;
        }
        if x > ((1u64 << 63) - 1) / 10 {
            overflow = true;
            i += 1;
            continue;
        }
        let y = x * 10 + (b[i] - b'0') as u64;
        if y > 1u64 << 63 {
            overflow = true;
            i += 1;
            continue;
        }
        x = y;
        scale *= 10.0;
        i += 1;
    }
    (x, scale, &s[i..])
}

/// Format nanoseconds the way Go `time.Duration.String`
/// does (`"24h0m0s"`, `"500ms"`, `"1m30s"`, `"0s"`).
pub fn format_go_duration(ns: i64) -> String {
    if ns == 0 {
        return "0s".to_string();
    }
    let neg = ns < 0;
    let u: u64 = if neg {
        (ns as i128).unsigned_abs() as u64
    } else {
        ns as u64
    };
    let mut out = String::new();
    if u < 1_000_000_000 {
        // Sub-second: smallest unit with a fraction.
        let (prec, suffix): (u32, &str) = if u == 0 {
            (0, "s")
        } else if u < 1_000 {
            (0, "ns")
        } else if u < 1_000_000 {
            (3, "µs")
        } else {
            (6, "ms")
        };
        let (frac, whole) = fmt_frac(u, prec);
        out.push_str(&whole.to_string());
        if !frac.is_empty() {
            out.push('.');
            out.push_str(&frac);
        }
        out.push_str(suffix);
    } else {
        // Seconds and above: h/m/s with a fraction on the
        // seconds.
        let (frac, secs) = fmt_frac(u, 9);
        let s = secs % 60;
        let mut m = secs / 60;
        let mut parts = String::new();
        if !frac.is_empty() {
            parts.push('.');
            parts.push_str(&frac);
        }
        parts.push('s');
        let mut head = s.to_string();
        head.push_str(&parts);
        if m > 0 {
            let mins = m % 60;
            m /= 60;
            head = format!("{mins}m{head}");
            if m > 0 {
                head = format!("{m}h{head}");
            }
        }
        out.push_str(&head);
    }
    if neg { format!("-{out}") } else { out }
}

/// Split `v` (nanoseconds) into (fraction digits,
/// whole part) at `prec` decimal places, trimming
/// trailing zeros — Go `fmtFrac`: divide `v` by 10
/// `prec` times, collecting digits; the remainder is
/// the integer part.
fn fmt_frac(v: u64, prec: u32) -> (String, u64) {
    let mut v = v;
    let mut digits = String::new();
    let mut print = false;
    for _ in 0..prec {
        let digit = v % 10;
        print = print || digit != 0;
        if print {
            digits.insert(0, char::from(b'0' + digit as u8));
        }
        v /= 10;
    }
    (digits, v)
}

// ---------------------------------------------------------------------------
// Host normalisation
// ---------------------------------------------------------------------------

/// Validate one `proxy_allowed_hosts` entry and return
/// its match form: lowercased, all trailing dots removed
/// (`keeper.go:441-470`). Errors never echo the entry:
/// the caller names the element index.
pub fn normalize_allowed_host(raw: &str) -> Result<String, String> {
    if raw.is_empty() {
        return Err("host must not be empty".to_string());
    }
    if raw != go_trim_space(raw) {
        return Err("host entry has surrounding whitespace".to_string());
    }
    let mut s = raw.to_lowercase();
    while s.ends_with('.') {
        s.pop();
    }
    if s.is_empty() {
        return Err("host must not be empty".to_string());
    }
    for ch in s.chars() {
        match ch {
            '/' | ':' | '@' | '?' | '#' | '[' | ']' | '*' => {
                return Err("host entry contains a forbidden character".to_string());
            }
            _ if ch.is_whitespace() || ch.is_control() => {
                return Err("host entry contains a forbidden character".to_string());
            }
            _ => {}
        }
    }
    Ok(s)
}

/// Validate a `proxy_allowed_hosts` value: a non-empty
/// array of host strings, each passing
/// `normalize_allowed_host` (`keeper.go:472-491`). The
/// returned list is in file order, normalized,
/// duplicates kept.
fn parse_allowed_hosts(v: &JsonValue) -> Result<Vec<String>, ConfigError> {
    let arr = match v {
        JsonValue::Array(arr) if !arr.is_empty() => arr,
        _ => {
            return Err(crate::config_error(
                "\"proxy_allowed_hosts\" must be a non-empty array of host strings",
            ));
        }
    };
    let mut hosts = Vec::with_capacity(arr.len());
    for (i, elem) in arr.iter().enumerate() {
        let s = match elem {
            JsonValue::Str(s) => s,
            _ => {
                return Err(crate::config_errorf!(
                    "\"proxy_allowed_hosts\" element {} must be a string",
                    i
                ));
            }
        };
        let h = normalize_allowed_host(s)
            .map_err(|e| crate::config_errorf!("\"proxy_allowed_hosts\" element {}: {}", i, e))?;
        hosts.push(h);
    }
    Ok(hosts)
}

// ---------------------------------------------------------------------------
// Browser URL
// ---------------------------------------------------------------------------

/// Enforce the loopback-only CDP URL rule
/// (`keeper.go:744-782`). It names the rule violated,
/// never the URL's credentials. Query strings and
/// fragments are rejected: a CDP debug URL carries
/// neither. Mirrors Go's `url.Parse` shape by hand:
/// scheme is case-insensitive (Go lowercases it);
/// userinfo is an `@` in the AUTHORITY only (Go
/// `u.User != nil` — an `@` in the path is accepted);
/// a `?` rejects even with an empty query (Go
/// `ForceQuery`); a `#` rejects only with a non-empty
/// fragment (Go `Fragment != ""`); a non-numeric port
/// is unparseable (Go `validOptionalPort`), a numeric
/// port out of 1..=65535 is out of range.
pub fn validate_keeper_browser_url(raw: &str) -> Result<(), String> {
    let s = go_trim_space(raw);
    if s.bytes()
        .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
    {
        return Err("unparseable URL".to_string());
    }
    let (scheme, rest) = match s.split_once("://") {
        Some((sc, r)) => (sc, r),
        None => return Err("unparseable URL".to_string()),
    };
    if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("ws") {
        return Err("scheme must be http or ws".to_string());
    }
    let (authority, tail) = match rest.split_once('/') {
        Some((a, t)) => (a, format!("/{t}")),
        None => (rest, String::new()),
    };
    if authority.contains('@') {
        return Err("must not carry userinfo".to_string());
    }
    let (before_frag, frag) = match tail.split_once('#') {
        Some((b, f)) => (b, Some(f)),
        None => (tail.as_str(), None),
    };
    if let Some(f) = frag
        && !f.is_empty()
    {
        return Err("must not carry a query or fragment".to_string());
    }
    if before_frag.contains('?') {
        return Err("must not carry a query or fragment".to_string());
    }
    if !valid_percent_escapes(before_frag) {
        return Err("unparseable URL".to_string());
    }
    if authority.is_empty() {
        return Err("missing host".to_string());
    }
    // Split host / port (IPv6 bracketed form supported).
    let (host, port) = if let Some(h) = authority.strip_prefix('[') {
        match h.split_once(']') {
            Some((ip, after)) => {
                let p = after.strip_prefix(':').unwrap_or("");
                (ip.to_string(), p.to_string())
            }
            None => return Err("unparseable URL".to_string()),
        }
    } else if let Some((h, p)) = authority.rsplit_once(':') {
        (h.to_string(), p.to_string())
    } else {
        (authority.to_string(), String::new())
    };
    if host.is_empty() {
        return Err("missing host".to_string());
    }
    if port.is_empty() {
        return Err("missing port".to_string());
    }
    if !port.bytes().all(|b| b.is_ascii_digit()) {
        return Err("unparseable URL".to_string());
    }
    let port_n: i64 = match port.parse() {
        Ok(n) => n,
        Err(_) => return Err("port out of range".to_string()),
    };
    if !(1..=65535).contains(&port_n) {
        return Err("port out of range".to_string());
    }
    if is_loopback_ip(&host) {
        return Ok(());
    }
    if host.parse::<std::net::IpAddr>().is_ok() {
        return Err("host must be loopback".to_string());
    }
    if host.eq_ignore_ascii_case("localhost") {
        return Ok(());
    }
    Err("host must be loopback".to_string())
}

/// Go `net.ParseIP(host)` + `ip.IsLoopback()`
/// (`keeper.go:774-779`): `std::net::IpAddr`'s parser
/// rejects leading-zero octets and octets > 255
/// exactly like Go's `parseIPv4`, and the explicit
/// v4-mapped check covers `::ffff:127.x` (Go
/// `IsLoopback` is true for it; `std`'s
/// `Ipv6Addr::is_loopback` is `::1` only). Shared by
/// the CDP discovery validator (`castctl-keeper`).
pub fn is_loopback_ip(host: &str) -> bool {
    let Ok(ip) = host.parse::<std::net::IpAddr>() else {
        return false;
    };
    match ip {
        std::net::IpAddr::V4(v4) => v4.is_loopback(),
        std::net::IpAddr::V6(v6) => {
            v6.is_loopback() || v6.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback())
        }
    }
}

/// Every `%` in `s` must start a two-hex-digit escape
/// (Go `url.Parse` rejects bad escapes).
fn valid_percent_escapes(s: &str) -> bool {
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let ok = b.get(i + 1).is_some_and(|c| c.is_ascii_hexdigit())
                && b.get(i + 2).is_some_and(|c| c.is_ascii_hexdigit());
            if !ok {
                return false;
            }
            i += 3;
        } else {
            i += 1;
        }
    }
    true
}

/// Percent-decode a path the way Go's `url.Parse`
/// fills `u.Path`: `%XX` → byte, `+` stays `+`.
/// `None` on a bad escape or non-UTF-8 bytes (the
/// caller falls back to the raw string, like Go
/// `canonicalBrowser`).
fn decode_path(path: &str) -> Option<String> {
    let b = path.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let d1 = (*b.get(i + 1)? as char).to_digit(16)?;
            let d2 = (*b.get(i + 2)? as char).to_digit(16)?;
            out.push((d1 * 16 + d2) as u8);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// Render the duplicate-browser dedup key for a
/// validated browser URL: normalized host, port, and
/// path (`keeper.go:784-821`). The scheme is NOT part of
/// the key: `http://` and `ws://` spellings denote the
/// same DevTools endpoint. `localhost` and `127.0.0.1`
/// are deliberately NOT merged. Go uses `u.Path` (the
/// percent-DECODED path) with ONE trailing slash
/// stripped (`TrimSuffix`).
pub fn canonical_browser_url(raw: &str) -> Result<String, String> {
    validate_keeper_browser_url(raw)?;
    let s = go_trim_space(raw);
    let (_, rest) = s.split_once("://").unwrap();
    let (hostport, path) = match rest.split_once('/') {
        Some((hp, p)) => (hp, format!("/{p}")),
        None => (rest, String::new()),
    };
    let (host, port) = if let Some(h) = hostport.strip_prefix('[') {
        let (ip, after) = h.split_once(']').unwrap();
        (
            ip.to_lowercase(),
            after.strip_prefix(':').unwrap_or("").to_string(),
        )
    } else if let Some((h, p)) = hostport.rsplit_once(':') {
        (h.to_lowercase(), p.to_string())
    } else {
        (hostport.to_lowercase(), String::new())
    };
    let host = if host.parse::<std::net::IpAddr>().is_ok() {
        // Normalise IP spelling (Go `ip.String()`):
        // v4-mapped `::ffff:127.0.0.1` renders
        // `127.0.0.1`, expanded `::1` renders `::1`.
        normalize_ip(&host)
    } else {
        host
    };
    let port_n: i64 = port.parse().map_err(|_| "port out of range".to_string())?;
    // The path ends at the fragment (`#` starts it in
    // Go; validation already allows only an empty one).
    let path = path.split('#').next().unwrap_or("");
    let path = decode_path(path).ok_or_else(|| "unparseable URL".to_string())?;
    let path = path.strip_suffix('/').unwrap_or(&path);
    Ok(format!("{host}:{port_n}{path}"))
}

fn normalize_ip(host: &str) -> String {
    match host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(v4)) => v4.to_string(),
        Ok(std::net::IpAddr::V6(v6)) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.to_string(),
            None => v6.to_string(),
        },
        Err(_) => host.to_string(),
    }
}

/// `canonical_browser_url` with a raw-string fallback:
/// `validateKeeper` also runs over hand-built configs
/// whose browser URLs never passed parse-time validation,
/// and dedup must not fail on them — it keys on the raw
/// string instead (`keeper.go:823-830`).
pub fn canonical_browser(raw: &str) -> String {
    canonical_browser_url(raw).unwrap_or_else(|_| raw.to_string())
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

fn dur_ns(d: Duration) -> i64 {
    d.as_nanos() as i64
}

fn ns_to_duration(ns: i64) -> Duration {
    Duration::from_nanos(ns as u64)
}

/// Parse one decoded `keeper` value (an array of entry
/// objects) into a `KeeperConfig`
/// (`keeper.go:493-741`). Wrong shapes, wrong types,
/// unknown keys, missing required keys, duplicate tags,
/// and invalid browser URLs are all config errors (exit
/// 2). Cross-entry and cross-block references are checked
/// by `validate_keeper`, not here.
pub fn parse_keeper_block(v: &JsonValue) -> Result<KeeperConfig, ConfigError> {
    let arr = match v {
        JsonValue::Array(arr) => arr,
        _ => {
            return Err(crate::config_error(
                "\"keeper\" must be an array of entries",
            ));
        }
    };
    let mut cfg = KeeperConfig::default();
    let mut seen_tags: Vec<String> = Vec::new();
    for (i, elem) in arr.iter().enumerate() {
        let obj = match elem {
            JsonValue::Object(obj) => obj,
            _ => {
                return Err(crate::config_errorf!(
                    "\"keeper\" entry {} must be an object",
                    i
                ));
            }
        };
        let mut entry = KeeperEntry::default();
        for (k, val) in obj.iter() {
            if !KEEPER_ENTRY_KEYS.contains(&k.as_str()) {
                return Err(crate::config_errorf!(
                    "unknown keeper config key {}",
                    go_quote(k)
                ));
            }
            match k.as_str() {
                "tag" => {
                    let s = match val {
                        JsonValue::Str(s) => s,
                        _ => {
                            return Err(crate::config_errorf!(
                                "\"keeper\" entry {}: \"tag\" must be a non-empty string",
                                i
                            ));
                        }
                    };
                    crate::blocks::validate_keeper_tag(s).map_err(|e| {
                        crate::config_errorf!("\"keeper\" entry {}: invalid \"tag\": {}", i, e)
                    })?;
                    entry.tag = s.clone();
                }
                "profile" => {
                    let s = match val {
                        JsonValue::Str(s) => s,
                        _ => {
                            return Err(crate::config_errorf!(
                                "\"keeper\" entry {}: \"profile\" must be a non-empty string",
                                i
                            ));
                        }
                    };
                    if go_trim_space(s).is_empty() {
                        return Err(crate::config_errorf!(
                            "\"keeper\" entry {}: \"profile\" must be a non-empty string",
                            i
                        ));
                    }
                    validate_profile_name(s).map_err(|_| {
                        crate::config_errorf!(
                            "\"keeper\" entry {}: invalid profile name {}",
                            i,
                            go_quote(s)
                        )
                    })?;
                    entry.profile = s.clone();
                }
                "browser" => {
                    let s = match val {
                        JsonValue::Str(s) => s,
                        _ => {
                            return Err(crate::config_errorf!(
                                "\"keeper\" entry {}: \"browser\" must be a non-empty CDP URL",
                                i
                            ));
                        }
                    };
                    if go_trim_space(s).is_empty() {
                        return Err(crate::config_errorf!(
                            "\"keeper\" entry {}: \"browser\" must be a non-empty CDP URL",
                            i
                        ));
                    }
                    validate_keeper_browser_url(s).map_err(|e| {
                        crate::config_errorf!(
                            "\"keeper\" entry {}: invalid \"browser\" URL: {}",
                            i,
                            e
                        )
                    })?;
                    entry.browser = go_trim_space(s).to_string();
                }
                "interval" | "expiring_within" => {
                    let s = match val {
                        JsonValue::Str(s) => s,
                        _ => {
                            return Err(crate::config_errorf!(
                                "\"keeper\" entry {}: {:?} must be a duration string",
                                i,
                                k
                            ));
                        }
                    };
                    if !go_trim_space(s).is_empty() {
                        let d = parse_go_duration(s)
                            .ok()
                            .filter(|&d| d > 0 && d <= dur_ns(MAX_KEEPER_INTERVAL));
                        let Some(d) = d else {
                            return Err(crate::config_errorf!(
                                "\"keeper\" entry {}: {:?} must be a positive duration string of at most {}",
                                i,
                                k,
                                format_go_duration(dur_ns(MAX_KEEPER_INTERVAL))
                            ));
                        };
                        if k == "interval" {
                            entry.interval = ns_to_duration(d);
                            entry.interval_set = true;
                        } else {
                            entry.expiring_within = ns_to_duration(d);
                            entry.expiring_set = true;
                        }
                    }
                }
                "notify" => {
                    let s = match val {
                        JsonValue::Str(s) => s,
                        _ => {
                            return Err(crate::config_errorf!(
                                "\"keeper\" entry {}: \"notify\" must be a string",
                                i
                            ));
                        }
                    };
                    entry.notify = s.clone();
                }
                "credentials" => {
                    let s = match val {
                        JsonValue::Str(s) => s,
                        _ => {
                            return Err(crate::config_errorf!(
                                "\"keeper\" entry {}: \"credentials\" must be a non-empty tag string",
                                i
                            ));
                        }
                    };
                    if go_trim_space(s).is_empty() {
                        return Err(crate::config_errorf!(
                            "\"keeper\" entry {}: \"credentials\" must be a non-empty tag string",
                            i
                        ));
                    }
                    crate::blocks::validate_keeper_tag(s).map_err(|e| {
                        crate::config_errorf!(
                            "\"keeper\" entry {}: invalid \"credentials\" tag: {}",
                            i,
                            e
                        )
                    })?;
                    entry.credentials = s.clone();
                }
                "wake_on_gateway_failure" => {
                    let b = match val {
                        JsonValue::Bool(b) => *b,
                        _ => {
                            return Err(crate::config_errorf!(
                                "\"keeper\" entry {}: \"wake_on_gateway_failure\" must be a boolean",
                                i
                            ));
                        }
                    };
                    entry.wake_on_gateway_failure = b;
                    entry.wake_set = true;
                }
                "retry_backoff" => {
                    let steps = match val {
                        JsonValue::Array(arr) if !arr.is_empty() => arr,
                        _ => {
                            return Err(crate::config_errorf!(
                                "\"keeper\" entry {}: \"retry_backoff\" must be a non-empty array of duration strings",
                                i
                            ));
                        }
                    };
                    if steps.len() > MAX_RETRY_BACKOFF_STEPS {
                        return Err(crate::config_errorf!(
                            "\"keeper\" entry {}: \"retry_backoff\" must have at most {} steps",
                            i,
                            MAX_RETRY_BACKOFF_STEPS
                        ));
                    }
                    for (j, elem) in steps.iter().enumerate() {
                        let s = match elem {
                            JsonValue::Str(s) => s,
                            _ => {
                                return Err(crate::config_errorf!(
                                    "\"keeper\" entry {}: \"retry_backoff\" element {} must be a duration string",
                                    i,
                                    j
                                ));
                            }
                        };
                        if go_trim_space(s).is_empty() {
                            return Err(crate::config_errorf!(
                                "\"keeper\" entry {}: \"retry_backoff\" element {} must be a duration string",
                                i,
                                j
                            ));
                        }
                        let d = parse_go_duration(s)
                            .ok()
                            .filter(|&d| d > 0 && d <= dur_ns(MAX_KEEPER_INTERVAL));
                        let Some(d) = d else {
                            return Err(crate::config_errorf!(
                                "\"keeper\" entry {}: \"retry_backoff\" element {} must be a positive duration string of at most {}",
                                i,
                                j,
                                format_go_duration(dur_ns(MAX_KEEPER_INTERVAL))
                            ));
                        };
                        entry.retry_backoff.push(ns_to_duration(d));
                    }
                    entry.retry_backoff_set = true;
                }
                "wake_attempts" | "relogin_attempts" => {
                    let n = match val {
                        JsonValue::Number(n) => n,
                        _ => {
                            return Err(crate::config_errorf!(
                                "\"keeper\" entry {}: {:?} must be a positive integer",
                                i,
                                k
                            ));
                        }
                    };
                    let iv: i64 = match n.parse() {
                        Ok(v) => v,
                        Err(_) => {
                            return Err(crate::config_errorf!(
                                "\"keeper\" entry {}: {:?} must be a positive integer of at most {}",
                                i,
                                k,
                                MAX_KEEPER_ATTEMPTS
                            ));
                        }
                    };
                    if iv <= 0 || iv > MAX_KEEPER_ATTEMPTS {
                        return Err(crate::config_errorf!(
                            "\"keeper\" entry {}: {:?} must be a positive integer of at most {}",
                            i,
                            k,
                            MAX_KEEPER_ATTEMPTS
                        ));
                    }
                    if k == "wake_attempts" {
                        entry.wake_attempts = iv;
                        entry.wake_attempts_set = true;
                    } else {
                        entry.relogin_attempts = iv;
                        entry.relogin_set = true;
                    }
                }
                "proxy_dial_timeout"
                | "relogin_match_timeout"
                | "relogin_cookie_timeout"
                | "relogin_poll_interval"
                | "relogin_attach_timeout"
                | "relogin_cancel_timeout"
                | "observe_settle_timeout"
                | "observe_timeout" => {
                    let s = match val {
                        JsonValue::Str(s) => s,
                        _ => {
                            return Err(crate::config_errorf!(
                                "\"keeper\" entry {}: {:?} must be a duration string",
                                i,
                                k
                            ));
                        }
                    };
                    let max_dur = match k.as_str() {
                        "proxy_dial_timeout"
                        | "relogin_attach_timeout"
                        | "relogin_cancel_timeout" => MAX_PROXY_DIAL_TIMEOUT,
                        "relogin_poll_interval" => MAX_RELOGIN_POLL_INTERVAL,
                        _ => MAX_RELOGIN_WAIT_TIMEOUT,
                    };
                    let d = parse_go_duration(s)
                        .ok()
                        .filter(|&d| d > 0 && d <= dur_ns(max_dur));
                    let Some(d) = d else {
                        return Err(crate::config_errorf!(
                            "\"keeper\" entry {}: {:?} must be a positive duration string of at most {}",
                            i,
                            k,
                            format_go_duration(dur_ns(max_dur))
                        ));
                    };
                    let dv = ns_to_duration(d);
                    match k.as_str() {
                        "proxy_dial_timeout" => {
                            entry.proxy_dial_timeout = dv;
                            entry.proxy_dial_set = true;
                        }
                        "relogin_match_timeout" => {
                            entry.relogin_match_timeout = dv;
                            entry.relogin_match_set = true;
                        }
                        "relogin_cookie_timeout" => {
                            entry.relogin_cookie_timeout = dv;
                            entry.relogin_cookie_set = true;
                        }
                        "relogin_poll_interval" => {
                            entry.relogin_poll_interval = dv;
                            entry.relogin_poll_set = true;
                        }
                        "relogin_attach_timeout" => {
                            entry.relogin_attach_timeout = dv;
                            entry.relogin_attach_set = true;
                        }
                        "relogin_cancel_timeout" => {
                            entry.relogin_cancel_timeout = dv;
                            entry.relogin_cancel_set = true;
                        }
                        "observe_settle_timeout" => {
                            entry.observe_settle_timeout = dv;
                            entry.observe_settle_set = true;
                        }
                        _ => {
                            entry.observe_timeout = dv;
                            entry.observe_timeout_set = true;
                        }
                    }
                }
                "proxy_max_header_bytes" => {
                    let iv = parse_positive_int(
                        val,
                        i,
                        "proxy_max_header_bytes",
                        MAX_PROXY_HEADER_BYTES,
                    )?;
                    entry.proxy_max_header_bytes = iv;
                    entry.proxy_max_header_set = true;
                }
                "proxy_max_body_bytes" => {
                    let iv =
                        parse_positive_int(val, i, "proxy_max_body_bytes", MAX_PROXY_BODY_BYTES)?;
                    entry.proxy_max_body_bytes = iv;
                    entry.proxy_max_body_set = true;
                }
                "observe_inventory_cap" => {
                    let iv = parse_positive_int(
                        val,
                        i,
                        "observe_inventory_cap",
                        MAX_OBSERVE_INVENTORY_CAP,
                    )?;
                    entry.observe_inventory_cap = iv;
                    entry.observe_inventory_set = true;
                }
                "proxy_allowed_hosts" => {
                    let hosts = parse_allowed_hosts(val)
                        .map_err(|e| crate::config_errorf!("\"keeper\" entry {}: {}", i, e))?;
                    entry.proxy_allowed_hosts = hosts;
                    entry.proxy_hosts_set = true;
                }
                _ => unreachable!(),
            }
        }
        if entry.tag.is_empty() {
            return Err(crate::config_errorf!(
                "\"keeper\" entry {} requires a \"tag\" key",
                i
            ));
        }
        if entry.profile.is_empty() {
            return Err(crate::config_errorf!(
                "\"keeper\" entry {} requires a \"profile\" key",
                i
            ));
        }
        if seen_tags.contains(&entry.tag) {
            return Err(crate::config_errorf!(
                "\"keeper\" has duplicate tag {}",
                go_quote(&entry.tag)
            ));
        }
        seen_tags.push(entry.tag.clone());
        cfg.entries.push(entry);
    }
    Ok(cfg)
}

fn parse_positive_int(val: &JsonValue, i: usize, key: &str, max: i64) -> Result<i64, ConfigError> {
    let n = match val {
        JsonValue::Number(n) => n,
        _ => {
            return Err(crate::config_errorf!(
                "\"keeper\" entry {}: {:?} must be a positive integer",
                i,
                key
            ));
        }
    };
    // Go `strconv.Atoi` rejects fractions and signs
    // beyond the integer grammar; a JSON number literal
    // with `.` or `e` is not an integer here.
    if !n
        .bytes()
        .all(|b| b.is_ascii_digit() || (b == b'-' && n.starts_with('-')))
    {
        return Err(crate::config_errorf!(
            "\"keeper\" entry {}: {:?} must be a positive integer of at most {}",
            i,
            key,
            max
        ));
    }
    let iv: i64 = match n.parse() {
        Ok(v) => v,
        Err(_) => {
            return Err(crate::config_errorf!(
                "\"keeper\" entry {}: {:?} must be a positive integer of at most {}",
                i,
                key,
                max
            ));
        }
    };
    if iv <= 0 || iv > max {
        return Err(crate::config_errorf!(
            "\"keeper\" entry {}: {:?} must be a positive integer of at most {}",
            i,
            key,
            max
        ));
    }
    Ok(iv)
}

// ---------------------------------------------------------------------------
// Cross-reference validation
// ---------------------------------------------------------------------------

/// Enforce the block's cross-references
/// (`keeper.go:832-866`): every entry's profile must
/// name a profile, no two entries may name the same
/// profile or share a browser URL, and a
/// `notify: "telegram"` entry requires the `telegram`
/// block to exist. It names profiles/tags only, never
/// values. A `None` block is valid (feature off).
pub fn validate_keeper(
    cfg: Option<&KeeperConfig>,
    profile_exists: impl Fn(&str) -> bool,
    has_telegram: bool,
) -> Result<(), ConfigError> {
    let Some(k) = cfg else {
        return Ok(());
    };
    let mut seen_profiles: Vec<(String, String)> = Vec::new();
    let mut seen_browsers: Vec<(String, String)> = Vec::new();
    for e in &k.entries {
        if !profile_exists(&e.profile) {
            return Err(crate::config_errorf!(
                "keeper: entry {} names profile {}, which does not exist",
                go_quote(&e.tag),
                go_quote(&e.profile)
            ));
        }
        if let Some((prev, _)) = seen_profiles.iter().find(|(_, p)| p == &e.profile) {
            return Err(crate::config_errorf!(
                "keeper: entries {} and {} both name profile {}",
                go_quote(prev),
                go_quote(&e.tag),
                go_quote(&e.profile)
            ));
        }
        seen_profiles.push((e.tag.clone(), e.profile.clone()));
        if !e.browser.is_empty() {
            let key = canonical_browser(&e.browser);
            if let Some((prev, _)) = seen_browsers.iter().find(|(_, b)| b == &key) {
                return Err(crate::config_errorf!(
                    "keeper: entries {} and {} share one browser URL",
                    go_quote(prev),
                    go_quote(&e.tag)
                ));
            }
            seen_browsers.push((e.tag.clone(), key));
        }
        match e.notify.as_str() {
            "" | "telegram" => {}
            _ => {
                return Err(crate::config_errorf!(
                    "keeper: entry {} has unknown notify {} (only \"telegram\" is supported)",
                    go_quote(&e.tag),
                    go_quote(&e.notify)
                ));
            }
        }
        if e.notify == "telegram" && !has_telegram {
            return Err(crate::config_errorf!(
                "keeper: entry {} notifies \"telegram\" but no \"telegram\" block exists",
                go_quote(&e.tag)
            ));
        }
    }
    Ok(())
}

/// Check a keeper entry's `credentials` reference
/// against the parsed credentials block: the tag must
/// exist, and the referenced entry must name the keeper
/// entry's own profile (a credential for another
/// profile must never be submitted for this one).
/// Go `validateCredentialRefs`
/// (`credentials.go:303-332`), called from the
/// `ParseSingleConfig` tail (after `validateKeeper` +
/// `validateCredentials`, `config.go:451`) and from
/// `ResolveKeeper` (`keeper.go:870`). A nil
/// credentials block with a reference present is a
/// dangling reference. Messages name tags/profiles
/// only, never values.
pub fn validate_credential_refs(
    keeper: Option<&KeeperConfig>,
    credentials: Option<&crate::blocks::CredentialsBlock>,
) -> Result<(), ConfigError> {
    let Some(k) = keeper else {
        return Ok(());
    };
    for e in &k.entries {
        if e.credentials.is_empty() {
            continue;
        }
        let Some(block) = credentials else {
            return Err(crate::config_errorf!(
                "keeper: entry {} references credentials {}, but no \"credentials\" block exists",
                go_quote(&e.tag),
                go_quote(&e.credentials)
            ));
        };
        let Some(cred) = block.entries.iter().find(|c| c.tag == e.credentials) else {
            return Err(crate::config_errorf!(
                "keeper: entry {} references credentials {}, which does not exist",
                go_quote(&e.tag),
                go_quote(&e.credentials)
            ));
        };
        if cred.profile != e.profile {
            return Err(crate::config_errorf!(
                "keeper: entry {} references credentials {} for profile {}, not {}",
                go_quote(&e.tag),
                go_quote(&e.credentials),
                go_quote(&cred.profile),
                go_quote(&e.profile)
            ));
        }
    }
    Ok(())
}

/// Return the keeper entry for a profile name, or `None`
/// when no entry names it (`keeper.go:887-897`).
pub fn keeper_entry_for_profile<'a>(
    cfg: Option<&'a KeeperConfig>,
    profile_name: &str,
) -> Option<&'a KeeperEntry> {
    cfg?.entries.iter().find(|e| e.profile == profile_name)
}

// ---------------------------------------------------------------------------
// Effective* accessors
// ---------------------------------------------------------------------------

fn effective_duration(set: bool, v: Duration, def: Duration) -> Duration {
    if set && !v.is_zero() && v <= MAX_KEEPER_INTERVAL {
        v
    } else {
        def
    }
}

impl KeeperEntry {
    /// The entry's base cadence: the parsed `interval`
    /// when set, `DEFAULT_KEEPER_INTERVAL` otherwise
    /// (`keeper.go:900-906`).
    pub fn effective_interval(&self) -> Duration {
        if self.interval_set && !self.interval.is_zero() {
            self.interval
        } else {
            DEFAULT_KEEPER_INTERVAL
        }
    }

    /// The entry's auto-wake setting: the parsed value
    /// when set, `true` otherwise (`keeper.go:908-914`).
    pub fn effective_wake_on_gateway_failure(&self) -> bool {
        if self.wake_set {
            self.wake_on_gateway_failure
        } else {
            true
        }
    }

    /// The entry's transient-retry ladder: the parsed list
    /// when set, `DEFAULT_RETRY_BACKOFF` otherwise. The
    /// returned list is a copy (`keeper.go:916-927`).
    pub fn effective_retry_backoff(&self) -> Vec<Duration> {
        if self.retry_backoff_set && !self.retry_backoff.is_empty() {
            self.retry_backoff.clone()
        } else {
            DEFAULT_RETRY_BACKOFF.to_vec()
        }
    }

    /// The entry's "expiring" window
    /// (`keeper.go:929-937`).
    pub fn effective_expiring_within(&self) -> Duration {
        if self.expiring_set && !self.expiring_within.is_zero() {
            self.expiring_within
        } else {
            DEFAULT_EXPIRING_WITHIN
        }
    }

    /// The entry's per-incident wake cap
    /// (`keeper.go:939-946`).
    pub fn effective_wake_attempts(&self) -> i64 {
        if self.wake_attempts_set && self.wake_attempts > 0 {
            self.wake_attempts
        } else {
            DEFAULT_KEEPER_ATTEMPTS
        }
    }

    /// The entry's per-incident re-login cap
    /// (`keeper.go:948-955`).
    pub fn effective_relogin_attempts(&self) -> i64 {
        if self.relogin_set && self.relogin_attempts > 0 {
            self.relogin_attempts
        } else {
            DEFAULT_KEEPER_ATTEMPTS
        }
    }

    pub fn effective_proxy_dial_timeout(&self) -> Duration {
        effective_duration(
            self.proxy_dial_set,
            self.proxy_dial_timeout,
            DEFAULT_PROXY_DIAL_TIMEOUT,
        )
    }

    pub fn effective_proxy_max_header_bytes(&self) -> i64 {
        if self.proxy_max_header_set
            && self.proxy_max_header_bytes > 0
            && self.proxy_max_header_bytes <= MAX_PROXY_HEADER_BYTES
        {
            self.proxy_max_header_bytes
        } else {
            DEFAULT_PROXY_MAX_HEADER_BYTES
        }
    }

    pub fn effective_proxy_max_body_bytes(&self) -> i64 {
        if self.proxy_max_body_set
            && self.proxy_max_body_bytes > 0
            && self.proxy_max_body_bytes <= MAX_PROXY_BODY_BYTES
        {
            self.proxy_max_body_bytes
        } else {
            DEFAULT_PROXY_MAX_BODY_BYTES
        }
    }

    /// The entry's S2 proxy allowlist: the parsed list
    /// when set, `DEFAULT_PROXY_ALLOWED_HOSTS` otherwise.
    /// The returned list is a copy. Hand-built entries
    /// are normalized defensively (invalid entries
    /// dropped); an empty result means the default list
    /// (`keeper.go:1007-1026`).
    pub fn effective_proxy_allowed_hosts(&self) -> Vec<String> {
        if self.proxy_hosts_set && !self.proxy_allowed_hosts.is_empty() {
            let mut out = Vec::new();
            for h in &self.proxy_allowed_hosts {
                if let Ok(norm) = normalize_allowed_host(h) {
                    out.push(norm);
                }
            }
            if !out.is_empty() {
                return out;
            }
        }
        DEFAULT_PROXY_ALLOWED_HOSTS
            .iter()
            .map(|s| s.to_string())
            .collect()
    }

    pub fn effective_relogin_match_timeout(&self) -> Duration {
        effective_duration(
            self.relogin_match_set,
            self.relogin_match_timeout,
            DEFAULT_RELOGIN_MATCH_TIMEOUT,
        )
    }

    pub fn effective_relogin_cookie_timeout(&self) -> Duration {
        effective_duration(
            self.relogin_cookie_set,
            self.relogin_cookie_timeout,
            DEFAULT_RELOGIN_COOKIE_TIMEOUT,
        )
    }

    pub fn effective_relogin_poll_interval(&self) -> Duration {
        effective_duration(
            self.relogin_poll_set,
            self.relogin_poll_interval,
            DEFAULT_RELOGIN_POLL_INTERVAL,
        )
    }

    pub fn effective_relogin_attach_timeout(&self) -> Duration {
        effective_duration(
            self.relogin_attach_set,
            self.relogin_attach_timeout,
            DEFAULT_RELOGIN_ATTACH_TIMEOUT,
        )
    }

    pub fn effective_relogin_cancel_timeout(&self) -> Duration {
        effective_duration(
            self.relogin_cancel_set,
            self.relogin_cancel_timeout,
            DEFAULT_RELOGIN_CANCEL_TIMEOUT,
        )
    }

    pub fn effective_observe_settle_timeout(&self) -> Duration {
        effective_duration(
            self.observe_settle_set,
            self.observe_settle_timeout,
            DEFAULT_OBSERVE_SETTLE_TIMEOUT,
        )
    }

    pub fn effective_observe_timeout(&self) -> Duration {
        effective_duration(
            self.observe_timeout_set,
            self.observe_timeout,
            DEFAULT_OBSERVE_TIMEOUT,
        )
    }

    pub fn effective_observe_inventory_cap(&self) -> i64 {
        if self.observe_inventory_set
            && self.observe_inventory_cap > 0
            && self.observe_inventory_cap <= MAX_OBSERVE_INVENTORY_CAP
        {
            self.observe_inventory_cap
        } else {
            DEFAULT_OBSERVE_INVENTORY_CAP
        }
    }
}

// ---------------------------------------------------------------------------
// Encoding (save)
// ---------------------------------------------------------------------------

/// Render a `KeeperConfig` for save when no raw JSON was
/// captured: entries in order, canonical key order, the
/// interval as a duration string, `browser` omitted when
/// empty (keep-alive-only entry), `notify`/`credentials`
/// omitted when empty, `wake_on_gateway_failure` omitted
/// when unset (default true), `retry_backoff`/
/// `expiring_within`/attempt caps omitted when unset.
/// The S10 proxy/driver/observe keys are likewise
/// omitted when unset (`keeper.go:1048-1115`).
pub fn encode_keeper_block(cfg: &KeeperConfig) -> JsonValue {
    let mut arr = Vec::new();
    for e in &cfg.entries {
        let mut entry = OrderedObject::new();
        entry.set("tag".to_string(), JsonValue::Str(e.tag.clone()));
        entry.set("profile".to_string(), JsonValue::Str(e.profile.clone()));
        if !e.browser.is_empty() {
            entry.set("browser".to_string(), JsonValue::Str(e.browser.clone()));
        }
        if e.interval_set && !e.interval.is_zero() {
            entry.set(
                "interval".to_string(),
                JsonValue::Str(format_go_duration(dur_ns(e.interval))),
            );
        }
        if !e.notify.is_empty() {
            entry.set("notify".to_string(), JsonValue::Str(e.notify.clone()));
        }
        if !e.credentials.is_empty() {
            entry.set(
                "credentials".to_string(),
                JsonValue::Str(e.credentials.clone()),
            );
        }
        if e.wake_set {
            entry.set(
                "wake_on_gateway_failure".to_string(),
                JsonValue::Bool(e.wake_on_gateway_failure),
            );
        }
        if e.retry_backoff_set && !e.retry_backoff.is_empty() {
            let steps: Vec<JsonValue> = e
                .retry_backoff
                .iter()
                .map(|d| JsonValue::Str(format_go_duration(dur_ns(*d))))
                .collect();
            entry.set("retry_backoff".to_string(), JsonValue::Array(steps));
        }
        if e.expiring_set && !e.expiring_within.is_zero() {
            entry.set(
                "expiring_within".to_string(),
                JsonValue::Str(format_go_duration(dur_ns(e.expiring_within))),
            );
        }
        if e.wake_attempts_set && e.wake_attempts > 0 {
            entry.set(
                "wake_attempts".to_string(),
                JsonValue::Number(e.wake_attempts.to_string()),
            );
        }
        if e.relogin_set && e.relogin_attempts > 0 {
            entry.set(
                "relogin_attempts".to_string(),
                JsonValue::Number(e.relogin_attempts.to_string()),
            );
        }
        if e.proxy_dial_set && !e.proxy_dial_timeout.is_zero() {
            entry.set(
                "proxy_dial_timeout".to_string(),
                JsonValue::Str(format_go_duration(dur_ns(e.proxy_dial_timeout))),
            );
        }
        if e.proxy_max_header_set && e.proxy_max_header_bytes > 0 {
            entry.set(
                "proxy_max_header_bytes".to_string(),
                JsonValue::Number(e.proxy_max_header_bytes.to_string()),
            );
        }
        if e.proxy_max_body_set && e.proxy_max_body_bytes > 0 {
            entry.set(
                "proxy_max_body_bytes".to_string(),
                JsonValue::Number(e.proxy_max_body_bytes.to_string()),
            );
        }
        if e.proxy_hosts_set && !e.proxy_allowed_hosts.is_empty() {
            let hosts: Vec<JsonValue> = e
                .proxy_allowed_hosts
                .iter()
                .map(|h| JsonValue::Str(h.clone()))
                .collect();
            entry.set("proxy_allowed_hosts".to_string(), JsonValue::Array(hosts));
        }
        if e.relogin_match_set && !e.relogin_match_timeout.is_zero() {
            entry.set(
                "relogin_match_timeout".to_string(),
                JsonValue::Str(format_go_duration(dur_ns(e.relogin_match_timeout))),
            );
        }
        if e.relogin_cookie_set && !e.relogin_cookie_timeout.is_zero() {
            entry.set(
                "relogin_cookie_timeout".to_string(),
                JsonValue::Str(format_go_duration(dur_ns(e.relogin_cookie_timeout))),
            );
        }
        if e.relogin_poll_set && !e.relogin_poll_interval.is_zero() {
            entry.set(
                "relogin_poll_interval".to_string(),
                JsonValue::Str(format_go_duration(dur_ns(e.relogin_poll_interval))),
            );
        }
        if e.relogin_attach_set && !e.relogin_attach_timeout.is_zero() {
            entry.set(
                "relogin_attach_timeout".to_string(),
                JsonValue::Str(format_go_duration(dur_ns(e.relogin_attach_timeout))),
            );
        }
        if e.relogin_cancel_set && !e.relogin_cancel_timeout.is_zero() {
            entry.set(
                "relogin_cancel_timeout".to_string(),
                JsonValue::Str(format_go_duration(dur_ns(e.relogin_cancel_timeout))),
            );
        }
        if e.observe_settle_set && !e.observe_settle_timeout.is_zero() {
            entry.set(
                "observe_settle_timeout".to_string(),
                JsonValue::Str(format_go_duration(dur_ns(e.observe_settle_timeout))),
            );
        }
        if e.observe_timeout_set && !e.observe_timeout.is_zero() {
            entry.set(
                "observe_timeout".to_string(),
                JsonValue::Str(format_go_duration(dur_ns(e.observe_timeout))),
            );
        }
        if e.observe_inventory_set && e.observe_inventory_cap > 0 {
            entry.set(
                "observe_inventory_cap".to_string(),
                JsonValue::Number(e.observe_inventory_cap.to_string()),
            );
        }
        arr.push(JsonValue::Object(entry));
    }
    JsonValue::Array(arr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jsonvalue::decode_ordered_json;

    fn parse_json(s: &str) -> JsonValue {
        decode_ordered_json(s.as_bytes()).unwrap()
    }

    #[test]
    fn go_duration_round_trip() {
        assert_eq!(parse_go_duration("24h").unwrap(), 86_400_000_000_000);
        assert_eq!(parse_go_duration("500ms").unwrap(), 500_000_000);
        assert_eq!(parse_go_duration("1h30m").unwrap(), 5_400_000_000_000);
        assert_eq!(parse_go_duration("1.5s").unwrap(), 1_500_000_000);
        assert_eq!(parse_go_duration("0").unwrap(), 0);
        assert!(parse_go_duration("").is_err());
        assert!(parse_go_duration("5").is_err());
        assert!(parse_go_duration("5x").is_err());
        assert_eq!(
            parse_go_duration("9223372036854775807ns").unwrap(),
            i64::MAX
        );
        assert!(parse_go_duration("9223372036854775808ns").is_err());
    }

    #[test]
    fn go_duration_go_parity_pins() {
        // K-2: Go `time.ParseDuration` accepts all of
        // these; the pre-fix parser rejected them.
        assert_eq!(parse_go_duration(".5s").unwrap(), 500_000_000);
        assert_eq!(parse_go_duration("1.s").unwrap(), 1_000_000_000);
        assert_eq!(parse_go_duration("-0").unwrap(), 0);
        assert_eq!(parse_go_duration("+0").unwrap(), 0);
        assert_eq!(
            parse_go_duration("-9223372036854775808ns").unwrap(),
            i64::MIN
        );
        // Fraction of only zeros: Go's `leadingFraction`
        // never overflows on zeros, so this is 1s (the
        // pre-fix `10i128.pow(45)` panicked/wrapped).
        assert_eq!(
            parse_go_duration("1.000000000000000000000000000000000000000000000s").unwrap(),
            1_000_000_000
        );
        // Integer part past 2^63: Go errors.
        assert!(parse_go_duration("100000000000000000000000000000000000000h").is_err());
        // u64 wrap quirk, probed against Go 1.27 on cue:
        // two 2^63ns parts wrap the u64 accumulator to 0
        // with NO error (Go `ParseDuration` adds into a
        // `uint64` and only checks `d > 1<<63` after each
        // part — the second add wraps exactly to 0).
        assert_eq!(
            parse_go_duration("9223372036854775808ns9223372036854775808ns").unwrap(),
            0
        );
        assert!(parse_go_duration(".s").is_err());
        assert!(parse_go_duration("-").is_err());
        assert!(parse_go_duration("1").is_err());
    }

    #[test]
    fn go_duration_string() {
        assert_eq!(format_go_duration(0), "0s");
        assert_eq!(format_go_duration(86_400_000_000_000), "24h0m0s");
        assert_eq!(format_go_duration(500_000_000), "500ms");
        assert_eq!(format_go_duration(1_500_000_000), "1.5s");
        assert_eq!(format_go_duration(90_000_000_000), "1m30s");
        assert_eq!(format_go_duration(1_000), "1µs");
        assert_eq!(format_go_duration(-5_000_000_000), "-5s");
    }

    #[test]
    fn parse_minimal_entry() {
        let v = parse_json(r#"[{"tag":"no.0","profile":"no.0"}]"#);
        let cfg = parse_keeper_block(&v).unwrap();
        assert_eq!(cfg.entries.len(), 1);
        let e = &cfg.entries[0];
        assert_eq!(e.tag, "no.0");
        assert_eq!(e.effective_interval(), DEFAULT_KEEPER_INTERVAL);
        assert!(e.effective_wake_on_gateway_failure());
        assert_eq!(e.effective_retry_backoff(), DEFAULT_RETRY_BACKOFF.to_vec());
        assert_eq!(e.effective_wake_attempts(), 3);
        assert_eq!(
            e.effective_proxy_allowed_hosts(),
            DEFAULT_PROXY_ALLOWED_HOSTS
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn parse_rejects_unknown_key_and_dup_tag() {
        let v = parse_json(r#"[{"tag":"a","profile":"p","nope":1}]"#);
        assert!(parse_keeper_block(&v).is_err());
        let v = parse_json(r#"[{"tag":"a","profile":"p"},{"tag":"a","profile":"q"}]"#);
        assert!(parse_keeper_block(&v).is_err());
        let v = parse_json(r#"[{"profile":"p"}]"#);
        assert!(parse_keeper_block(&v).is_err());
    }

    #[test]
    fn browser_url_rules() {
        assert!(validate_keeper_browser_url("http://127.0.0.1:9222").is_ok());
        assert!(validate_keeper_browser_url("ws://localhost:9222").is_ok());
        assert!(validate_keeper_browser_url("http://example.com:9222").is_err());
        assert!(validate_keeper_browser_url("http://127.0.0.1").is_err());
        assert!(validate_keeper_browser_url("http://127.0.0.1:9222/?x=1").is_err());
        assert_eq!(
            canonical_browser_url("http://LOCALHOST:9222/").unwrap(),
            "localhost:9222"
        );
        assert_eq!(
            canonical_browser_url("ws://127.0.0.1:9222").unwrap(),
            "127.0.0.1:9222"
        );
        // localhost and 127.0.0.1 are deliberately NOT merged.
        assert_ne!(
            canonical_browser_url("http://localhost:9222").unwrap(),
            canonical_browser_url("http://127.0.0.1:9222").unwrap()
        );
    }

    #[test]
    fn browser_url_go_parity_pins() {
        // K-3: Go `net.ParseIP` rejects leading-zero
        // octets and octets > 255; `std::net::IpAddr`
        // does the same.
        assert!(validate_keeper_browser_url("http://127.0.0.01:9222").is_err());
        assert!(validate_keeper_browser_url("http://127.0.0.256:9222").is_err());
        assert!(validate_keeper_browser_url("http://127.0.0.999:9222").is_err());
        // K-3: IPv4-mapped loopback is loopback in Go
        // (`ip.IsLoopback`).
        assert!(validate_keeper_browser_url("http://[::ffff:127.0.0.1]:9222").is_ok());
        assert!(validate_keeper_browser_url("http://[::1]:9222").is_ok());
        assert!(validate_keeper_browser_url("http://[0:0:0:0:0:0:0:1]:9222").is_ok());
        assert!(validate_keeper_browser_url("http://[::ffff:192.168.0.1]:9222").is_err());
        // K-3: an '@' in the PATH is not userinfo (Go
        // `u.User == nil`); an '@' in the authority is.
        assert!(validate_keeper_browser_url("http://127.0.0.1:9222/@x").is_ok());
        assert!(validate_keeper_browser_url("http://user@127.0.0.1:9222/").is_err());
        // Scheme is case-insensitive (Go lowercases it).
        assert!(validate_keeper_browser_url("HTTP://127.0.0.1:9222").is_ok());
        assert!(validate_keeper_browser_url("WS://localhost:9222").is_ok());
        // A bare '?' rejects (Go `ForceQuery`); a bare
        // '#' does not (Go `Fragment == ""`).
        assert!(validate_keeper_browser_url("http://127.0.0.1:9222/?").is_err());
        assert!(validate_keeper_browser_url("http://127.0.0.1:9222/#").is_ok());
        assert!(validate_keeper_browser_url("http://127.0.0.1:9222/#x").is_err());
        // Bad percent-escape in the path: Go `url.Parse`
        // rejects it.
        assert!(validate_keeper_browser_url("http://127.0.0.1:9222/%zz").is_err());
        // Non-numeric port: Go `validOptionalPort`
        // rejects it at parse time.
        assert!(validate_keeper_browser_url("http://127.0.0.1:abc").is_err());
        assert!(validate_keeper_browser_url("http://127.0.0.1:0").is_err());
        assert!(validate_keeper_browser_url("http://127.0.0.1:65536").is_err());
        assert!(validate_keeper_browser_url("http://127.0.0.1:65535").is_ok());
        // A "127.0.0.1.evil.com" suffix host is not
        // loopback (Go `ParseIP` returns nil, not
        // `localhost`).
        assert!(validate_keeper_browser_url("http://127.0.0.1.evil.com:9222").is_err());
        // K-4: canonical strips ONE trailing slash and
        // uses the percent-decoded path (Go `u.Path` +
        // `TrimSuffix`).
        assert_eq!(
            canonical_browser_url("http://127.0.0.1:9222//").unwrap(),
            "127.0.0.1:9222/"
        );
        assert_eq!(
            canonical_browser_url("http://127.0.0.1:9222/a//").unwrap(),
            "127.0.0.1:9222/a/"
        );
        assert_eq!(
            canonical_browser_url("http://127.0.0.1:9222/a%2Fb").unwrap(),
            "127.0.0.1:9222/a/b"
        );
        assert_eq!(
            canonical_browser_url("http://[::ffff:127.0.0.1]:9222").unwrap(),
            "127.0.0.1:9222"
        );
        assert_eq!(
            canonical_browser_url("http://[0:0:0:0:0:0:0:1]:9222").unwrap(),
            "::1:9222"
        );
    }

    #[test]
    fn validate_cross_refs() {
        let v = parse_json(
            r#"[{"tag":"a","profile":"p","notify":"telegram"},{"tag":"b","profile":"p"}]"#,
        );
        let cfg = parse_keeper_block(&v).unwrap();
        // Same profile twice.
        assert!(validate_keeper(Some(&cfg), |n| n == "p", true).is_err());
        let v = parse_json(r#"[{"tag":"a","profile":"p","notify":"telegram"}]"#);
        let cfg = parse_keeper_block(&v).unwrap();
        // Telegram notify without a telegram block.
        assert!(validate_keeper(Some(&cfg), |n| n == "p", false).is_err());
        assert!(validate_keeper(Some(&cfg), |n| n == "p", true).is_ok());
        // Missing profile.
        assert!(validate_keeper(Some(&cfg), |_| false, true).is_err());
    }

    #[test]
    fn encode_round_trip() {
        let v = parse_json(
            r#"[{"tag":"a","profile":"p","interval":"12h","retry_backoff":["5m","15m"]}]"#,
        );
        let cfg = parse_keeper_block(&v).unwrap();
        let out = encode_keeper_block(&cfg);
        let cfg2 = parse_keeper_block(&out).unwrap();
        assert_eq!(cfg2.entries[0].interval, Duration::from_secs(12 * 3600));
        assert_eq!(cfg2.entries[0].retry_backoff.len(), 2);
    }
}
