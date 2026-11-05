// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Netscape jar handling: parse, serialise, and merge — port
//! of `internal/keeper/jar.go`.
//!
//! Format (verified from code, `jar.go:14-24, 252-280`):
//! 7 tab-separated columns `domain, flag, path, secure,
//! expires, name, value`, LF endings, a single trailing
//! newline, header `# Netscape HTTP Cookie File`. `flag` is
//! `TRUE` iff the domain has a leading dot. `expires` is an
//! integer epoch, 0 for a session cookie. HttpOnly is NOT
//! preserved across a jar round-trip (no column for it; a
//! `#HttpOnly_` row is a comment and is dropped).
//!
//! Strictness divergence (intentional, `jar.go:52-62`):
//! [`parse_jar`] requires EXACTLY 7 columns per row, while
//! the lenient reader [`parse_cookies_lenient`] (the
//! `gateway.ParseCookies` analogue) accepts >= 7. The two
//! parsers are deliberately NOT aligned.
//!
//! Attributes beyond name/value/domain/path/secure/HttpOnly/
//! expiry (SameSite, Priority, Partitioned, `__Secure`-/
//! `__Host`-prefix rules) are NOT modeled (loop-2 N14).

use std::collections::BTreeMap;
use std::fmt;

use chrono::{DateTime, TimeZone, Utc};

use crate::error::KeeperError;
use crate::setcookie::ParsedCookie;

/// Filtered domains: only cookies belonging to the Muse
/// session are ever merged or written (`jar.go:66`).
pub const FILTERED_DOMAINS: &[&str] = &["muse.ai", "auth.muse.ai"];

/// One explicit cookie: the merge unit for Set-Cookie updates
/// and CDP exports (`jar.go:73-84`). The leading dot on
/// `domain` carries the host-only vs domain-scoped
/// distinction; the merge key is dot-insensitive.
#[derive(Clone, PartialEq, Eq)]
pub struct StoredCookie {
    /// Cookie name.
    pub name: String,
    /// Cookie value. SECRET MATERIAL: never logged or
    /// printed — the hand-written `Debug` redacts it.
    pub value: String,
    /// Leading dot = domain-scoped; bare = host-only.
    pub domain: String,
    /// Cookie path.
    pub path: String,
    /// Secure flag.
    pub secure: bool,
    /// HttpOnly flag (does NOT survive a jar round-trip).
    pub http_only: bool,
    /// Epoch expiry, 0 for a session cookie.
    pub expires: i64,
}

impl StoredCookie {
    /// `true` when the cookie has no expiry.
    pub fn is_session(&self) -> bool {
        self.expires == 0
    }

    fn key(&self) -> (String, String, String) {
        (
            self.name.clone(),
            self.domain.trim_start_matches('.').to_lowercase(),
            self.path.clone(),
        )
    }
}

impl fmt::Debug for StoredCookie {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Values are secrets: Debug never prints them.
        f.debug_struct("StoredCookie")
            .field("name", &self.name)
            .field("value", &"[redacted]")
            .field("domain", &self.domain)
            .field("path", &self.path)
            .field("secure", &self.secure)
            .field("http_only", &self.http_only)
            .field("expires", &self.expires)
            .finish()
    }
}

/// One parsed Set-Cookie or CDP cookie after effective
/// domain/path/expiry resolution (`jar.go:284-292`). `delete`
/// marks an explicit server deletion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CookieUpdate {
    /// Resolved cookie.
    pub cookie: StoredCookie,
    /// `true` = delete the matching stored entry.
    pub delete: bool,
}

/// Whether the cookie belongs to the Muse session: its
/// domain is `muse.ai` or `auth.muse.ai`, or a subdomain of
/// one of them (`jar.go:122-131`).
pub fn in_filtered_domain(c: &StoredCookie) -> bool {
    let d = c.domain.trim_start_matches('.').to_lowercase();
    FILTERED_DOMAINS
        .iter()
        .any(|base| d == *base || d.ends_with(&format!(".{base}")))
}

fn reject_cookie_field(field: &str, value: &str) -> Result<(), KeeperError> {
    if value.contains(['\t', '\n', '\r']) {
        return Err(KeeperError::Other(format!(
            "cookie {field} contains a tab, newline, or carriage return"
        )));
    }
    Ok(())
}

fn validate_stored_cookie(c: &StoredCookie) -> Result<(), KeeperError> {
    if c.name.is_empty() {
        return Err(KeeperError::Other("cookie with an empty name".to_string()));
    }
    if c.domain.is_empty() {
        return Err(KeeperError::Other(format!(
            "cookie {:?} with an empty domain",
            c.name
        )));
    }
    if c.expires < 0 {
        return Err(KeeperError::Other(format!(
            "cookie {:?} with a negative expiry",
            c.name
        )));
    }
    reject_cookie_field("name", &c.name)?;
    reject_cookie_field("domain", &c.domain)?;
    reject_cookie_field("path", &c.path)?;
    reject_cookie_field("value", &c.value)?;
    Ok(())
}

/// Parse Netscape jar bytes (`jar.go:155-207`). `#` lines
/// (including `#HttpOnly_` rows) are comments and are
/// dropped. A malformed row fails closed with its line
/// number only — never the row contents. Duplicate keys:
/// last row wins.
pub fn parse_jar(data: &[u8]) -> Result<Vec<StoredCookie>, KeeperError> {
    let mut out: Vec<StoredCookie> = Vec::new();
    for (i, raw_line) in data.split(|b| *b == b'\n').enumerate() {
        let raw_line = raw_line.strip_suffix(b"\r").unwrap_or(raw_line);
        if raw_line.is_empty() || raw_line.first() == Some(&b'#') {
            // Comments (including `#HttpOnly_` rows) are
            // dropped before any decoding, as in Go — a
            // stray non-UTF-8 byte in a comment is skipped,
            // not an error.
            continue;
        }
        // Go `string(data)` keeps arbitrary bytes, but a
        // Rust `StoredCookie` is UTF-8: a data row that is
        // not valid UTF-8 fails closed with its line
        // number, instead of lossy-converting the bytes
        // to U+FFFD and silently corrupting the value on
        // the next serialise (J-2).
        let line = std::str::from_utf8(raw_line)
            .map_err(|_| KeeperError::JarParse(format!("jar line {}: invalid UTF-8", i + 1)))?;
        let fields: Vec<&str> = line.split('\t').collect();
        if fields.len() != 7 {
            return Err(KeeperError::JarParse(format!(
                "jar line {}: want 7 tab-separated fields, got {}",
                i + 1,
                fields.len()
            )));
        }
        let secure = parse_jar_bool(fields[3]).ok_or_else(|| {
            KeeperError::JarParse(format!("jar line {}: invalid secure flag", i + 1))
        })?;
        parse_jar_bool(fields[1]).ok_or_else(|| {
            KeeperError::JarParse(format!("jar line {}: invalid domain flag", i + 1))
        })?;
        let expires: i64 = fields[4]
            .parse()
            .map_err(|_| KeeperError::JarParse(format!("jar line {}: invalid expiry", i + 1)))?;
        if expires < 0 {
            return Err(KeeperError::JarParse(format!(
                "jar line {}: invalid expiry",
                i + 1
            )));
        }
        let c = StoredCookie {
            domain: fields[0].to_string(),
            path: fields[2].to_string(),
            secure,
            expires,
            name: fields[5].to_string(),
            value: fields[6].to_string(),
            http_only: false,
        };
        validate_stored_cookie(&c)
            .map_err(|e| KeeperError::JarParse(format!("jar line {}: {}", i + 1, e)))?;
        out.push(c);
    }
    // Duplicate keys: last row wins, keeping first position
    // (Go `ParseJar` replaces in place).
    let mut seen: BTreeMap<(String, String, String), usize> = BTreeMap::new();
    let mut uniq: Vec<StoredCookie> = Vec::with_capacity(out.len());
    for c in out {
        let k = c.key();
        if let Some(&idx) = seen.get(&k) {
            uniq[idx] = c;
            continue;
        }
        seen.insert(k, uniq.len());
        uniq.push(c);
    }
    Ok(uniq)
}

fn parse_jar_bool(s: &str) -> Option<bool> {
    if s.eq_ignore_ascii_case("TRUE") {
        Some(true)
    } else if s.eq_ignore_ascii_case("FALSE") {
        Some(false)
    } else {
        None
    }
}

/// Render cookies in deterministic `(domain, path, name)`
/// order (`jar.go:252-280`). An empty set renders the header
/// line only. Values are verbatim.
pub fn serialize_jar(cookies: &[StoredCookie]) -> Result<Vec<u8>, KeeperError> {
    let mut sorted: Vec<StoredCookie> = cookies.to_vec();
    for c in &sorted {
        validate_stored_cookie(c)?;
    }
    sorted.sort_by(|a, b| {
        let ad = a.domain.to_lowercase();
        let bd = b.domain.to_lowercase();
        ad.cmp(&bd)
            .then_with(|| a.path.cmp(&b.path))
            .then_with(|| a.name.cmp(&b.name))
    });
    let mut out = String::from("# Netscape HTTP Cookie File\n");
    for c in &sorted {
        let flag = if c.domain.starts_with('.') {
            "TRUE"
        } else {
            "FALSE"
        };
        let secure = if c.secure { "TRUE" } else { "FALSE" };
        out.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
            c.domain, flag, c.path, secure, c.expires, c.name, c.value
        ));
    }
    Ok(out.into_bytes())
}

/// Resolve one parsed Set-Cookie value to its merge form
/// against the request URL, per RFC 6265 §5.1.3/§5.1.4 and
/// the frozen deletion rules (`jar.go:294-348`).
///
/// - Domain attribute present: domain-scoped, stored with a
///   leading dot when the attribute has none; absent:
///   host-only, the request host.
/// - Path attribute present: as given; absent: the RFC
///   default-path of the request URL.
/// - Max-Age > 0 wins over Expires; expiry =
///   `received_at + Max-Age`, computed in wrapping i64
///   nanoseconds exactly like Go (`time.Duration(MaxAge) *
///   time.Second`): a Max-Age large enough to overflow wraps
///   to a past expiry, fail-closed, no clamp (N13).
/// - Max-Age < 0, or an Expires at/past `received_at`,
///   deletes.
/// - Empty value + future expiry REPLACES (freeze (c)).
/// - Empty value + no expiry information deletes (the
///   Max-Age=0 clear shape; Go's parser cannot distinguish
///   Max-Age=0 from an absent Max-Age).
pub fn effective_set_cookie(
    c: &ParsedCookie,
    req_url: &str,
    received_at: DateTime<Utc>,
) -> CookieUpdate {
    let (req_host, req_path) = split_url_host_path(req_url);
    let domain = if let Some(d) = &c.domain {
        if d.starts_with('.') {
            d.clone()
        } else {
            format!(".{d}")
        }
    } else {
        req_host.to_lowercase()
    };
    let path = match &c.path {
        Some(p) if !p.is_empty() => p.clone(),
        _ => default_path(&req_path),
    };
    let mut upd = CookieUpdate {
        cookie: StoredCookie {
            name: c.name.clone(),
            value: c.value.clone(),
            domain,
            path,
            secure: c.secure,
            http_only: c.http_only,
            expires: 0,
        },
        delete: false,
    };
    let max_age = c.max_age.unwrap_or(0);
    let received_unix = received_at.timestamp();
    if max_age < 0 {
        upd.delete = true;
    } else if max_age > 0 {
        // Go: receivedAt.Add(time.Duration(MaxAge) *
        // time.Second) — wrapping i64 nanosecond arithmetic.
        let nanos = (max_age).wrapping_mul(1_000_000_000);
        let received_nanos = received_unix
            .wrapping_mul(1_000_000_000)
            .wrapping_add(received_at.timestamp_subsec_nanos() as i64);
        upd.cookie.expires = received_nanos.wrapping_add(nanos).div_euclid(1_000_000_000);
    } else if let Some(exp) = c.expires {
        if exp <= received_unix {
            upd.delete = true;
        } else {
            upd.cookie.expires = exp;
        }
    } else if c.value.is_empty() {
        upd.delete = true;
    }
    upd
}

/// Split a URL into (host, path) without a URL parser: the
/// caller passes `https://host/path` request URLs only.
fn split_url_host_path(url: &str) -> (String, String) {
    let after_scheme = url.split("://").nth(1).unwrap_or(url);
    let (hostport, path) = match after_scheme.find('/') {
        Some(i) => (&after_scheme[..i], &after_scheme[i..]),
        None => (after_scheme, "/"),
    };
    let host = hostport.split('@').next_back().unwrap_or(hostport);
    let host = host.split(':').next().unwrap_or(host);
    (host.to_string(), path.to_string())
}

/// RFC 6265 §5.1.4 default-path (`jar.go:351-361`).
fn default_path(req_path: &str) -> String {
    if req_path.is_empty() || !req_path.starts_with('/') {
        return "/".to_string();
    }
    if req_path.matches('/').count() <= 1 {
        return "/".to_string();
    }
    req_path[..req_path.rfind('/').unwrap_or(0)].to_string()
}

/// Apply ordered Set-Cookie updates to the stored set, in
/// order, keyed by `(name, domain, path)` (`jar.go:366-395`).
/// Deletions remove; anything else upserts. Callers filter
/// by domain BEFORE calling.
pub fn apply_updates(stored: &[StoredCookie], updates: &[CookieUpdate]) -> Vec<StoredCookie> {
    let mut out: Vec<StoredCookie> = stored.to_vec();
    let rebuild = |out: &[StoredCookie]| -> BTreeMap<(String, String, String), usize> {
        out.iter().enumerate().map(|(i, c)| (c.key(), i)).collect()
    };
    let mut idx = rebuild(&out);
    for u in updates {
        let k = u.cookie.key();
        if u.delete {
            if let Some(&i) = idx.get(&k) {
                out.remove(i);
                idx = rebuild(&out);
            }
            continue;
        }
        if let Some(&i) = idx.get(&k) {
            out[i] = u.cookie.clone();
        } else {
            idx.insert(k, out.len());
            out.push(u.cookie.clone());
        }
    }
    out
}

/// Replace the filtered domain set with the validated CDP
/// export (`jar.go:407-440`): stored entries outside the
/// filter are kept verbatim (including expired ones), every
/// stored entry inside the filter is dropped, and the export
/// set takes its place. Returns the new set and the number
/// of stored entries dropped.
pub fn replace_with_export(
    stored: &[StoredCookie],
    exported: &[StoredCookie],
) -> (Vec<StoredCookie>, usize) {
    let mut kept: Vec<StoredCookie> = Vec::new();
    let mut dropped = 0;
    for c in stored {
        if in_filtered_domain(c) {
            dropped += 1;
            continue;
        }
        kept.push(c.clone());
    }
    let mut uniq: Vec<StoredCookie> = Vec::new();
    let mut seen: BTreeMap<(String, String, String), usize> = BTreeMap::new();
    for c in exported {
        let k = c.key();
        if let Some(&i) = seen.get(&k) {
            uniq[i] = c.clone();
            continue;
        }
        seen.insert(k, uniq.len());
        uniq.push(c.clone());
    }
    kept.extend(uniq);
    (kept, dropped)
}

/// Convert an epoch expiry to a `DateTime<Utc>` the way
/// Go `time.Unix(sec, 0)` would: Go never panics on
/// out-of-range seconds, but chrono's range is ±262,143
/// years, so values outside it saturate to `MAX_UTC` /
/// `MIN_UTC`. Ordering is preserved (a far-future expiry
/// still sorts after every in-range one), and the
/// expired/not-expired decision at any realistic `now`
/// is unchanged: a far-future cookie is NOT treated as
/// expired, a far-past one IS — exactly as Go decides.
/// (F1: the previous `.expect("valid epoch")` panicked
/// on a jar row with `expires=10^14` or `i64::MAX`,
/// which `parse_jar` accepts.)
pub fn epoch_to_datetime(expires: i64) -> DateTime<Utc> {
    match Utc.timestamp_opt(expires, 0) {
        chrono::LocalResult::Single(dt) => dt,
        _ => {
            if expires > 0 {
                DateTime::<Utc>::MAX_UTC
            } else {
                DateTime::<Utc>::MIN_UTC
            }
        }
    }
}

/// Earliest non-session expiry in the set, or `None` when
/// the set has no dated cookie (`jar.go:442-455`). Past
/// expiries count.
pub fn earliest_expiry(cookies: &[StoredCookie]) -> Option<DateTime<Utc>> {
    cookies
        .iter()
        .filter(|c| !c.is_session())
        .map(|c| epoch_to_datetime(c.expires))
        .min()
}

/// `earliest_expiry` over the filtered domains only.
pub fn earliest_filtered_expiry(cookies: &[StoredCookie]) -> Option<DateTime<Utc>> {
    earliest_expiry(
        &cookies
            .iter()
            .filter(|c| in_filtered_domain(c))
            .cloned()
            .collect::<Vec<_>>(),
    )
}

/// Driving-cookie resolution (freeze (b), `jar.go:460-475`):
/// `hatch_sess` when present with a non-session expiry, else
/// the earliest dated cookie. Returns the cookie name and its
/// expiry, or `("", None)` when no dated cookie exists.
pub fn driving_cookie(cookies: &[StoredCookie]) -> (String, Option<DateTime<Utc>>) {
    for c in cookies {
        if c.name == "hatch_sess" && !c.is_session() {
            return (c.name.clone(), Some(epoch_to_datetime(c.expires)));
        }
    }
    let earliest = earliest_expiry(cookies);
    let Some(earliest) = earliest else {
        return (String::new(), None);
    };
    for c in cookies {
        if !c.is_session() && epoch_to_datetime(c.expires) == earliest {
            return (c.name.clone(), Some(earliest));
        }
    }
    (String::new(), Some(earliest))
}

/// Build the Cookie request header from stored cookies:
/// non-expired entries only (session cookies included),
/// deterministic order, `name=value` pairs (`jar.go:476-490`).
pub fn cookie_header(cookies: &[StoredCookie], now: DateTime<Utc>) -> String {
    let mut parts: Vec<String> = Vec::new();
    for c in cookies {
        if !c.is_session() && !epoch_to_datetime(c.expires).gt(&now) {
            continue;
        }
        parts.push(format!("{}={}", c.name, c.value));
    }
    parts.sort();
    parts.join("; ")
}

/// Apply updates to a one-line Cookie header for the second
/// chain step (`tick.go:103-122`). Domain/path do not matter
/// for the wire header, only name=value pairs.
pub fn merge_cookie_header(header: &str, updates: &[CookieUpdate], now: DateTime<Utc>) -> String {
    let mut stored: Vec<StoredCookie> = Vec::new();
    for pair in header.split(';') {
        let pair = pair.trim();
        if pair.is_empty() {
            continue;
        }
        let (name, value) = match pair.split_once('=') {
            Some((n, v)) => (n.trim(), v),
            None => (pair.trim(), ""),
        };
        if name.is_empty() {
            continue;
        }
        stored.push(StoredCookie {
            name: name.to_string(),
            value: value.to_string(),
            domain: "muse.ai".to_string(),
            path: "/".to_string(),
            secure: false,
            http_only: false,
            expires: 0,
        });
    }
    cookie_header(&apply_updates(&stored, updates), now)
}

/// Lenient cookies-file reader — the `gateway.ParseCookies`
/// analogue (`internal/gateway/cookies.go`), used ONLY by
/// `classify_cookies_file` for non-jar files. Three forms:
/// JSON object (`{"cookies": {...}}` or flat), one-line
/// `a=b; c=d` (containing `hatch_sess=` or `datr=`), or a
/// Netscape jar (>= 7 columns, name/value in columns 6/7).
/// Returned cookies carry the placeholder domain `muse.ai`
/// and path `/`: the form does not record them. An empty
/// result is `Ok` for the JSON/one-line forms; the jar-lines
/// form errors when it yields nothing.
pub fn parse_cookies_lenient(raw: &str) -> Result<Vec<StoredCookie>, KeeperError> {
    let trimmed = raw.trim();
    if trimmed.starts_with('{')
        && let Ok(castctl_config::jsonvalue::JsonValue::Object(obj)) =
            castctl_config::jsonvalue::decode_ordered_json(trimmed.as_bytes())
    {
        let target = match obj.get("cookies") {
            Some(castctl_config::jsonvalue::JsonValue::Object(inner)) => inner.clone(),
            _ => obj,
        };
        return Ok(target
            .iter()
            .map(|(k, v)| StoredCookie {
                name: k.clone(),
                value: cookie_value_string(v),
                domain: "muse.ai".to_string(),
                path: "/".to_string(),
                secure: false,
                http_only: false,
                expires: 0,
            })
            .collect());
    }
    if trimmed.contains("hatch_sess=") || trimmed.contains("datr=") {
        for line in trimmed.split('\n') {
            let line = line.trim();
            if !line.is_empty()
                && !line.starts_with('#')
                && line.contains('=')
                && line.contains(';')
            {
                return Ok(split_header_pairs(line));
            }
        }
        let collapsed = trimmed.split_whitespace().collect::<Vec<_>>().join(" ");
        return Ok(split_header_pairs(&collapsed));
    }
    let mut parts: Vec<StoredCookie> = Vec::new();
    for line in trimmed.split('\n') {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let cols: Vec<&str> = line.split('\t').collect();
        if cols.len() >= 7 {
            parts.push(StoredCookie {
                name: cols[5].to_string(),
                value: cols[6].to_string(),
                domain: "muse.ai".to_string(),
                path: "/".to_string(),
                secure: false,
                http_only: false,
                expires: 0,
            });
        }
    }
    if parts.is_empty() {
        return Err(KeeperError::CookiesUnparseable(
            "could not parse cookies file".to_string(),
        ));
    }
    Ok(parts)
}

fn split_header_pairs(header: &str) -> Vec<StoredCookie> {
    let mut out = Vec::new();
    for pair in header.split(';') {
        let pair = pair.trim();
        if pair.is_empty() {
            continue;
        }
        let (name, value) = match pair.split_once('=') {
            Some((n, v)) => (n.trim(), v),
            None => (pair, ""),
        };
        if name.is_empty() {
            continue;
        }
        out.push(StoredCookie {
            name: name.to_string(),
            value: value.to_string(),
            domain: "muse.ai".to_string(),
            path: "/".to_string(),
            secure: false,
            http_only: false,
            expires: 0,
        });
    }
    out
}

/// Render one JSON cookie value as Python's `f"{v}"`
/// (`castctl-gateway/src/cookies.rs`: strings verbatim,
/// numbers literal, booleans `True`/`False`, null `None`,
/// non-scalars compact JSON with Go escaping).
fn cookie_value_string(v: &castctl_config::jsonvalue::JsonValue) -> String {
    use castctl_config::jsonvalue::JsonValue;
    match v {
        JsonValue::Str(s) => s.clone(),
        JsonValue::Number(lit) => lit.clone(),
        JsonValue::Bool(true) => "True".to_string(),
        JsonValue::Bool(false) => "False".to_string(),
        JsonValue::Null => "None".to_string(),
        _ => encode_cookie_json_value(v),
    }
}

fn encode_cookie_json_value(v: &castctl_config::jsonvalue::JsonValue) -> String {
    use castctl_config::jsonvalue::JsonValue;
    match v {
        JsonValue::Null => "null".to_string(),
        JsonValue::Bool(true) => "true".to_string(),
        JsonValue::Bool(false) => "false".to_string(),
        JsonValue::Str(s) => castctl_gateway_escape_go_json_string(s),
        JsonValue::Number(lit) => lit.clone(),
        JsonValue::Array(items) => {
            let inner: Vec<String> = items.iter().map(encode_cookie_json_value).collect();
            format!("[{}]", inner.join(","))
        }
        JsonValue::Object(obj) => {
            let inner: Vec<String> = obj
                .iter()
                .map(|(k, val)| {
                    format!(
                        "{}:{}",
                        castctl_gateway_escape_go_json_string(k),
                        encode_cookie_json_value(val)
                    )
                })
                .collect();
            format!("{{{}}}", inner.join(","))
        }
    }
}

/// Escape one string exactly as Go's `json.Marshal` does
/// (mirrors `castctl-gateway/src/cookies.rs`
/// `escape_go_json_string`).
fn castctl_gateway_escape_go_json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '<' => out.push_str("\\u003c"),
            '>' => out.push_str("\\u003e"),
            '&' => out.push_str("\\u0026"),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Convert an exported (CDP) cookie to merge form
/// (`tick.go:139-156`): a session cookie has expiry 0;
/// `Expires <= 0` or `Session` means 0; an empty path means
/// `/`. CDP snapshots are FAITHFUL: an empty value with a
/// future expiry is written verbatim, NOT a deletion.
pub fn from_exported_cookie(c: &ExportedCookie) -> StoredCookie {
    let expires: i64 = if !c.session && c.expires > 0.0 {
        c.expires as i64
    } else {
        0
    };
    let path = if c.path.is_empty() {
        "/".to_string()
    } else {
        c.path.clone()
    };
    StoredCookie {
        name: c.name.clone(),
        value: c.value.clone(),
        domain: c.domain.clone(),
        path,
        secure: c.secure,
        http_only: c.http_only,
        expires,
    }
}

/// One cookie read from the browser over CDP, in
/// transport-neutral form (`tick.go:127-137`). `expires` is
/// a float64 epoch, -1 or <= 0 for a session cookie. The
/// hand-written `Debug` redacts `value`.
#[derive(Clone, PartialEq)]
pub struct ExportedCookie {
    /// Cookie name.
    pub name: String,
    /// Cookie value. SECRET MATERIAL.
    pub value: String,
    /// Cookie domain (Chromium reports domain cookies with
    /// the leading dot).
    pub domain: String,
    /// Cookie path.
    pub path: String,
    /// Epoch expiry as float seconds; -1 or <= 0 = session.
    pub expires: f64,
    /// Secure flag.
    pub secure: bool,
    /// HttpOnly flag.
    pub http_only: bool,
    /// Session cookie.
    pub session: bool,
}

impl fmt::Debug for ExportedCookie {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExportedCookie")
            .field("name", &self.name)
            .field("value", &"[redacted]")
            .field("domain", &self.domain)
            .field("path", &self.path)
            .field("expires", &self.expires)
            .field("secure", &self.secure)
            .field("http_only", &self.http_only)
            .field("session", &self.session)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn utc(y: i32, mo: u32, d: u32, h: u32, mi: u32, s: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(y, mo, d, h, mi, s).unwrap()
    }

    fn cookie(name: &str, domain: &str, path: &str, expires: i64) -> StoredCookie {
        StoredCookie {
            name: name.to_string(),
            value: format!("v-{name}"),
            domain: domain.to_string(),
            path: path.to_string(),
            secure: false,
            http_only: false,
            expires,
        }
    }

    #[test]
    fn jar_round_trip_literal() {
        // Literal expected text (from Go `jar.go` rules), not
        // recomputed by the code under test.
        let input = "# Netscape HTTP Cookie File\n\
                     .muse.ai\tTRUE\t/\tFALSE\t1790000000\thatch_sess\tv-hatch_sess\n\
                     muse.ai\tFALSE\t/\tTRUE\t0\tdatr\tv-datr\n";
        let parsed = parse_jar(input.as_bytes()).expect("parses");
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].name, "hatch_sess");
        assert_eq!(parsed[0].domain, ".muse.ai");
        assert_eq!(parsed[0].expires, 1790000000);
        assert_eq!(parsed[1].name, "datr");
        assert!(parsed[1].is_session());
        let back = serialize_jar(&parsed).expect("serialises");
        assert_eq!(String::from_utf8(back).unwrap(), input);
    }

    #[test]
    fn jar_parse_errors_carry_line_numbers_only() {
        let bad = "# Netscape HTTP Cookie File\nmuse.ai\tFALSE\t/\tTRUE\t0\tonly-six\n";
        let err = parse_jar(bad.as_bytes()).unwrap_err();
        assert!(
            err.to_string()
                .contains("jar line 2: want 7 tab-separated fields, got 6")
        );
        // No row contents (which could carry a value) in the error.
        assert!(!err.to_string().contains("only-six"));
        let bad_exp = "muse.ai\tFALSE\t/\tTRUE\t-5\tx\ty\n";
        assert!(parse_jar(bad_exp.as_bytes()).is_err());
        let bad_flag = "muse.ai\tFALSE\t/\tMAYBE\t0\tx\ty\n";
        assert!(parse_jar(bad_flag.as_bytes()).is_err());
    }

    #[test]
    fn non_utf8_jar_row_fails_closed() {
        // J-2: a non-UTF-8 byte in a data row fails
        // closed with the line number (never lossy U+FFFD
        // corruption); the same byte in a comment line is
        // skipped, as in Go.
        let mut bad = b"# Netscape HTTP Cookie File\n.muse.ai\tTRUE\t/\tFALSE\t1790000000\thatch_sess\tv-\xff\n"
            .to_vec();
        let err = parse_jar(&bad).unwrap_err();
        assert!(
            err.to_string().contains("jar line 2: invalid UTF-8"),
            "{}",
            err
        );
        bad = b"# comment with a bad byte \xff\n.muse.ai\tTRUE\t/\tFALSE\t1790000000\thatch_sess\tv-ok\n"
            .to_vec();
        let parsed = parse_jar(&bad).expect("comment byte skipped");
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].value, "v-ok");
    }

    #[test]
    fn far_future_expiry_does_not_panic() {
        // F1: a jar row with `expires=i64::MAX` (or
        // `10^14`, from the CDP f64→i64 saturation path)
        // parses, and no tick-time expiry read panics:
        // Go `time.Unix` never panics, so the value
        // saturates to chrono's MAX and still counts as
        // unexpired.
        let input = "# Netscape HTTP Cookie File\n\
                     .muse.ai\tTRUE\t/\tFALSE\t9223372036854775807\thatch_sess\tv-hatch_sess\n\
                     .muse.ai\tTRUE\t/\tFALSE\t100000000000000\tother\tv-other\n";
        let parsed = parse_jar(input.as_bytes()).expect("parses");
        assert_eq!(parsed.len(), 2);
        let now = utc(2026, 11, 5, 0, 0, 0);
        assert_eq!(earliest_expiry(&parsed), Some(DateTime::<Utc>::MAX_UTC));
        let (name, exp) = driving_cookie(&parsed);
        assert_eq!(name, "hatch_sess");
        assert_eq!(exp, Some(DateTime::<Utc>::MAX_UTC));
        let header = cookie_header(&parsed, now);
        assert!(header.contains("hatch_sess="), "{header}");
        assert!(header.contains("other="), "{header}");
        // A far-past expiry saturates to MIN and counts
        // as expired (skipped from the header).
        let past = vec![cookie("old", ".muse.ai", "/", -100_000_000_000_000)];
        assert_eq!(earliest_expiry(&past), Some(DateTime::<Utc>::MIN_UTC));
        assert_eq!(cookie_header(&past, now), "");
        assert_eq!(epoch_to_datetime(i64::MAX), DateTime::<Utc>::MAX_UTC);
        assert_eq!(epoch_to_datetime(i64::MIN), DateTime::<Utc>::MIN_UTC);
        assert_eq!(
            epoch_to_datetime(1_790_000_000),
            Utc.with_ymd_and_hms(2026, 9, 21, 14, 13, 20).unwrap()
        );
    }

    #[test]
    fn jar_http_only_rows_are_comments() {
        let input = "# Netscape HTTP Cookie File\n#HttpOnly_.muse.ai\tTRUE\t/\tFALSE\t1790000000\thatch_sess\tx\nmuse.ai\tFALSE\t/\tFALSE\t0\tdatr\ty\n";
        let parsed = parse_jar(input.as_bytes()).expect("parses");
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].name, "datr");
    }

    #[test]
    fn jar_duplicate_key_last_wins() {
        let input =
            "muse.ai\tFALSE\t/\tFALSE\t0\ta\tfirst\n.muse.ai\tTRUE\t/\tFALSE\t0\ta\tsecond\n";
        let parsed = parse_jar(input.as_bytes()).expect("parses");
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].value, "second");
        assert_eq!(parsed[0].domain, ".muse.ai");
    }

    #[test]
    fn jar_empty_set_renders_header_only() {
        assert_eq!(
            serialize_jar(&[]).unwrap(),
            b"# Netscape HTTP Cookie File\n"
        );
        assert!(parse_jar(b"").unwrap().is_empty());
    }

    #[test]
    fn effective_set_cookie_domain_path_expiry() {
        let now = utc(2026, 11, 5, 0, 0, 0);
        // Domain attr present -> domain-scoped with dot added.
        let c = ParsedCookie {
            name: "hatch_sess".into(),
            value: "v".into(),
            domain: Some("muse.ai".into()),
            path: None,
            expires: Some(now.timestamp() + 3600),
            max_age: None,
            secure: true,
            http_only: true,
        };
        let u = effective_set_cookie(&c, "https://muse.ai/api/session", now);
        assert!(!u.delete);
        assert_eq!(u.cookie.domain, ".muse.ai");
        assert_eq!(u.cookie.path, "/api");
        assert_eq!(u.cookie.expires, now.timestamp() + 3600);
        // No domain -> host-only request host, lowercased.
        let c2 = ParsedCookie {
            domain: None,
            path: Some("/x".into()),
            ..c.clone()
        };
        let u2 = effective_set_cookie(&c2, "https://MUSE.AI/api/session", now);
        assert_eq!(u2.cookie.domain, "muse.ai");
        assert_eq!(u2.cookie.path, "/x");
        // Max-Age wins over Expires.
        let c3 = ParsedCookie {
            max_age: Some(600),
            expires: Some(now.timestamp() + 99999),
            ..c.clone()
        };
        let u3 = effective_set_cookie(&c3, "https://muse.ai/", now);
        assert_eq!(u3.cookie.expires, now.timestamp() + 600);
        // Max-Age < 0 deletes; Expires in the past deletes.
        let c4 = ParsedCookie {
            max_age: Some(-1),
            ..c.clone()
        };
        assert!(effective_set_cookie(&c4, "https://muse.ai/", now).delete);
        let c5 = ParsedCookie {
            expires: Some(now.timestamp() - 1),
            max_age: None,
            ..c.clone()
        };
        assert!(effective_set_cookie(&c5, "https://muse.ai/", now).delete);
        // Empty value + future expiry REPLACES (freeze (c)).
        let c6 = ParsedCookie {
            value: String::new(),
            expires: Some(now.timestamp() + 60),
            max_age: None,
            ..c.clone()
        };
        let u6 = effective_set_cookie(&c6, "https://muse.ai/", now);
        assert!(!u6.delete);
        assert_eq!(u6.cookie.value, "");
        // Empty value + no expiry deletes (Max-Age=0 shape).
        let c7 = ParsedCookie {
            value: String::new(),
            expires: None,
            max_age: None,
            ..c.clone()
        };
        assert!(effective_set_cookie(&c7, "https://muse.ai/", now).delete);
        // Session cookie (no expiry info, non-empty value).
        let c8 = ParsedCookie {
            expires: None,
            max_age: None,
            ..c.clone()
        };
        let u8 = effective_set_cookie(&c8, "https://muse.ai/", now);
        assert!(!u8.delete);
        assert_eq!(u8.cookie.expires, 0);
    }

    #[test]
    fn effective_set_cookie_max_age_overflow_wraps() {
        // Go: time.Duration(MaxAge) * time.Second wraps in i64
        // nanoseconds (N13). Max-Age = 10^10 s -> nanos 10^19
        // wraps (10^19 - 2^64 = -8446744073709551616 ns, about
        // -8446744074 s) -> past expiry -> the cookie is
        // SKIPPED by CookieHeader (fail-closed). (Max-Age =
        // 10^12 would NOT wrap negative: 10^21 mod 2^64 is
        // +3.9e18 ns.)
        let now = utc(2026, 11, 5, 0, 0, 0);
        let c = ParsedCookie {
            name: "hatch_sess".into(),
            value: "v".into(),
            domain: Some("muse.ai".into()),
            path: None,
            expires: None,
            max_age: Some(10_000_000_000),
            secure: false,
            http_only: false,
        };
        let u = effective_set_cookie(&c, "https://muse.ai/", now);
        assert!(!u.delete);
        // -8446744073709551616 ns = -8446744073.71 s; the
        // div_euclid seconds step floors to -8446744074.
        assert_eq!(u.cookie.expires, now.timestamp() - 8_446_744_074);
        assert_eq!(cookie_header(std::slice::from_ref(&u.cookie), now), "");
    }

    #[test]
    fn apply_updates_and_replace() {
        let stored = vec![
            cookie("hatch_sess", ".muse.ai", "/", 1790000000),
            cookie("other", "example.com", "/", 1790000000),
        ];
        let del = CookieUpdate {
            cookie: cookie("hatch_sess", "muse.ai", "/", 0),
            delete: true,
        };
        let out = apply_updates(&stored, &[del]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].name, "other");
        // ReplaceWithExport drops filtered, keeps the rest.
        let exported = vec![cookie("hatch_sess", ".muse.ai", "/", 1790003600)];
        let (merged, dropped) = replace_with_export(&stored, &exported);
        assert_eq!(dropped, 1);
        assert_eq!(merged.len(), 2);
        assert_eq!(merged[1].expires, 1790003600);
    }

    #[test]
    fn cookie_header_skips_expired_and_sorts() {
        let now = utc(2026, 11, 5, 0, 0, 0);
        let cookies = vec![
            cookie("b", "muse.ai", "/", now.timestamp() + 60),
            cookie("a", "muse.ai", "/", now.timestamp() - 60),
            cookie("c", "muse.ai", "/", 0),
        ];
        assert_eq!(cookie_header(&cookies, now), "b=v-b; c=v-c");
    }

    #[test]
    fn driving_cookie_prefers_hatch_sess() {
        let now = utc(2026, 11, 5, 0, 0, 0);
        let cookies = vec![
            cookie("datr", "muse.ai", "/", now.timestamp() + 60),
            cookie("hatch_sess", ".muse.ai", "/", now.timestamp() + 3600),
        ];
        let (name, exp) = driving_cookie(&cookies);
        assert_eq!(name, "hatch_sess");
        assert_eq!(exp, Some(utc(2026, 11, 5, 1, 0, 0)));
        let (name2, _) = driving_cookie(&cookies[..1]);
        assert_eq!(name2, "datr");
        assert_eq!(driving_cookie(&[]), (String::new(), None));
    }

    #[test]
    fn lenient_forms() {
        let one_line = parse_cookies_lenient("hatch_sess=abc; datr=def").unwrap();
        assert_eq!(one_line.len(), 2);
        assert_eq!(one_line[0].domain, "muse.ai");
        let json = parse_cookies_lenient(r#"{"hatch_sess": "abc", "datr": "def"}"#).unwrap();
        assert_eq!(json.len(), 2);
        assert_eq!(json[0].value, "abc");
        let json_nested = parse_cookies_lenient(r#"{"cookies": {"hatch_sess": "abc"}}"#).unwrap();
        assert_eq!(json_nested.len(), 1);
        // Non-string JSON scalars render Python-style, numbers
        // keeping their literal spelling (config JsonValue
        // `Number(String)`, M2 — NOT the shared JsonValue the
        // M4c bridge changed; verified by grep: neither
        // castctl-config nor castctl-keeper depends on
        // castctl-shared).
        let json_scalars =
            parse_cookies_lenient(r#"{"n": 42, "f": 1.50, "b": true, "z": null}"#).unwrap();
        assert_eq!(json_scalars.len(), 4);
        assert_eq!(json_scalars[0].value, "42");
        assert_eq!(json_scalars[1].value, "1.50");
        assert_eq!(json_scalars[2].value, "True");
        assert_eq!(json_scalars[3].value, "None");
        assert!(parse_cookies_lenient("garbage without equals").is_err());
    }

    #[test]
    fn from_exported_cookie_faithful_empty_value() {
        let c = ExportedCookie {
            name: "hatch_sess".into(),
            value: String::new(),
            domain: ".muse.ai".into(),
            path: String::new(),
            expires: 1790000000.0,
            secure: false,
            http_only: false,
            session: false,
        };
        let s = from_exported_cookie(&c);
        assert_eq!(s.value, "");
        assert_eq!(s.expires, 1790000000);
        assert_eq!(s.path, "/");
        let sess = ExportedCookie {
            session: true,
            expires: 1790000000.0,
            ..c
        };
        assert_eq!(from_exported_cookie(&sess).expires, 0);
    }
}
