// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Release selection, redirect policy, URL validation, error taxonomy.
//!
//! Go sources: `internal/update/update.go:602-857` (selection,
//! `decide`, `fallbackTag`, `validateDownloadURL`),
//! `update.go:330-360` (`flavourFromBuildInfo`),
//! `update.go:383-458` (client + redirect policy),
//! `update.go:168-236` (`classifyTransportError` / `isTLSError`).
//!
//! The pure parts are ported 1:1. The HTTP-carrying parts
//! (`fetchRelease`, `fallbackLatest`, `fallbackSelection`)
//! live in `run.rs` and call these helpers.

use crate::error::UpdateError;
use crate::semver::{Version, compare_versions};

/// One asset of a release.
/// Source: Go `releaseAsset{name, url, size, state}`
/// (`internal/update/update.go:575-580`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseAsset {
    /// Asset file name.
    pub name: String,
    /// `browser_download_url`.
    pub url: String,
    /// Asset size in bytes (0 when unknown, fallback mode).
    pub size: i64,
    /// Upload state (`""` or `"uploaded"` when usable).
    pub state: String,
}

/// One fetched release.
/// Source: Go `releaseInfo` (`internal/update/update.go:582-587`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseInfo {
    /// `tag_name` from the release JSON.
    pub tag: String,
    /// `draft` flag.
    pub draft: bool,
    /// `prerelease` flag.
    pub prerelease: bool,
    /// Assets (order untrusted).
    pub assets: Vec<ReleaseAsset>,
}

/// A resolved selection: what to download and from where.
/// Source: Go `selection` (`internal/update/update.go:596-604`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Selection {
    /// Target version (parsed).
    pub target: Version,
    /// Canonical tag: `"v" + target.AssetVersion()`.
    pub tag: String,
    /// Expected asset file name.
    pub asset_name: String,
    /// Asset download URL.
    pub asset_url: String,
    /// Asset size (0 when unknown, fallback mode).
    pub asset_size: i64,
    /// `checksums.txt` download URL.
    pub checksums_url: String,
    /// True when the current version already equals the target.
    pub noop: bool,
}

/// Expected asset name: `castctl_<AssetVersion>_linux_<goarch>[ _no-plugin].tar.gz`.
/// Source: `expectedAssetName` (`internal/update/update.go:602-608`).
pub fn expected_asset_name(v: &Version, flavour: &str, goarch: &str) -> String {
    let suffix = if flavour == "no-plugin" {
        "_no-plugin"
    } else {
        ""
    };
    format!(
        "castctl_{}_linux_{}{}.tar.gz",
        v.asset_version(),
        goarch,
        suffix
    )
}

/// Find exactly one asset with the expected name. Zero or
/// multiple matches fail closed; asset ordering is never trusted.
/// Source: `selectAsset` (`internal/update/update.go:717-744`).
pub fn select_asset<'a>(
    rel: &'a ReleaseInfo,
    expected: &str,
) -> Result<&'a ReleaseAsset, UpdateError> {
    let mut found: Option<&ReleaseAsset> = None;
    let mut count = 0;
    for a in &rel.assets {
        if a.name != expected {
            continue;
        }
        count += 1;
        if !a.state.is_empty() && a.state != "uploaded" {
            return Err(UpdateError::usage(
                "update: the matching release asset is not uploaded",
            ));
        }
        if a.size <= 0 {
            return Err(UpdateError::usage(
                "update: the matching release asset has no usable size",
            ));
        }
        if !validate_download_url(&a.url) {
            return Err(UpdateError::failure(
                "update: the matching release asset has an unusable download URL",
            ));
        }
        found = Some(a);
    }
    if count == 0 {
        return Err(UpdateError::usage(
            "update: no release asset matches this platform and build flavour",
        ));
    }
    if count > 1 {
        return Err(UpdateError::usage(
            "update: ambiguous release assets: the asset name appears more than once",
        ));
    }
    Ok(found.expect("count == 1 implies found is Some"))
}

/// Find exactly one `checksums.txt` asset.
/// Source: `selectChecksumsAsset` (`internal/update/update.go:746-772`).
pub fn select_checksums_asset(rel: &ReleaseInfo) -> Result<&ReleaseAsset, UpdateError> {
    let mut found: Option<&ReleaseAsset> = None;
    let mut count = 0;
    for a in &rel.assets {
        if a.name != "checksums.txt" {
            continue;
        }
        count += 1;
        if !validate_download_url(&a.url) {
            return Err(UpdateError::failure(
                "update: the checksums file has an unusable download URL",
            ));
        }
        found = Some(a);
    }
    if count == 0 {
        return Err(UpdateError::failure(
            "update: the release has no checksums file; refusing to install without verification",
        ));
    }
    if count > 1 {
        return Err(UpdateError::failure(
            "update: ambiguous checksums files in the release",
        ));
    }
    Ok(found.expect("count == 1 implies found is Some"))
}

/// Apply the version policy and select the exact asset.
/// Guard order (load-bearing, `update.go:682-715`):
/// downgrade → equal-version no-op → prerelease-tag guard →
/// asset selection. The prerelease guard sits AFTER the
/// no-op return, so an equal prerelease version is a no-op,
/// not a refusal.
/// Source: `decide` (`internal/update/update.go:682-715`).
#[allow(clippy::too_many_arguments)]
pub fn decide(
    current: &Version,
    target: Version,
    tag: String,
    flavour: &str,
    goarch: &str,
    github_base: &str,
    rel: Option<&ReleaseInfo>,
    fallback: bool,
    allow_downgrade: bool,
    allow_prerelease: bool,
) -> Result<Selection, UpdateError> {
    let cmp = compare_versions(&target, current);
    if cmp < 0 && !allow_downgrade {
        return Err(UpdateError::usage(format!(
            "update: refusing downgrade from {} to {}; pass --allow-downgrade to install it",
            current, target
        )));
    }
    if cmp == 0 {
        return Ok(Selection {
            target,
            tag,
            asset_name: String::new(),
            asset_url: String::new(),
            asset_size: 0,
            checksums_url: String::new(),
            noop: true,
        });
    }
    if !target.prerelease().is_empty() && !allow_prerelease {
        return Err(UpdateError::usage(format!(
            "update: the target release {} is a prerelease; pass --allow-prerelease to install it",
            target
        )));
    }
    let asset_name = expected_asset_name(&target, flavour, goarch);
    if fallback {
        let base = github_base.trim_end_matches('/');
        return Ok(Selection {
            asset_url: format!(
                "{base}/thoitiettxl-cyber/castctl/releases/download/{tag}/{asset_name}"
            ),
            checksums_url: format!(
                "{base}/thoitiettxl-cyber/castctl/releases/download/{tag}/checksums.txt"
            ),
            target,
            tag,
            asset_name,
            asset_size: 0,
            noop: false,
        });
    }
    // Primary mode always passes a release; a caller
    // that passes `None` with `fallback=false` gets an
    // error, never a panic (`decide` is pub).
    let Some(rel) = rel else {
        return Err(UpdateError::failure(
            "update: the release information is missing",
        ));
    };
    let asset = select_asset(rel, &asset_name)?;
    let checksums = select_checksums_asset(rel)?;
    Ok(Selection {
        target,
        tag,
        asset_name,
        asset_url: asset.url.clone(),
        asset_size: asset.size,
        checksums_url: checksums.url.clone(),
        noop: false,
    })
}

/// Map the `CGO_ENABLED` build setting to the release flavour.
/// Go reads `debug.BuildInfo.Settings`; Rust binaries have no
/// `debug.BuildInfo`, so the caller passes the settings as
/// `(key, value)` pairs and this pure function applies Go's
/// rule. A missing setting, conflicting duplicates, or any
/// other value means "unknown": never guess.
/// Source: `flavourFromBuildInfo` (`internal/update/update.go:330-360`).
pub fn flavour_from_cgo_settings(settings: &[(String, String)]) -> Option<&'static str> {
    let mut seen = false;
    let mut value = "";
    for (k, v) in settings {
        if k != "CGO_ENABLED" {
            continue;
        }
        if seen && v != value {
            return None;
        }
        seen = true;
        value = v;
    }
    if !seen {
        return None;
    }
    match value {
        "1" => Some("glibc"),
        "0" => Some("no-plugin"),
        _ => None,
    }
}

// --- Minimal URL parsing (for policy decisions only) ---

/// A parsed URL, split into the pieces the redirect and
/// download-URL policies inspect. This is NOT a general URL
/// parser: it handles absolute `http`/`https` URLs with an
/// optional userinfo, host, port, path, and query — the only
/// shapes the update flow ever feeds it. Anything else is
/// refused by the callers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedUrl {
    /// Lowercased scheme (`"https"`, `"http"`, or other) —
    /// Go's `url.Parse` lowercases the scheme.
    pub scheme: String,
    /// Whether a `user@` userinfo part is present.
    pub has_userinfo: bool,
    /// Host without port, case PRESERVED: Go's
    /// `URL.Hostname()` does not lowercase, and the
    /// redirect policy compares hosts case-sensitively
    /// (`update.go:442-448`) — an uppercase spelling of
    /// an allowlisted host is refused by Go, so this
    /// port must not lowercase it away. DNS lookup and
    /// the TLS SNI lowercase separately at dial time
    /// (DNS names are case-insensitive).
    pub host: String,
    /// Port as written, `""` when absent.
    pub port: String,
    /// Path as written (may be empty).
    pub path: String,
    /// Query as written, without the leading `?`
    /// (`""` when absent). Go sends the query
    /// (`RawQuery`); the request line carries it.
    pub query: String,
    /// The raw input, kept for error-free display only
    /// (never rendered into an error message).
    pub raw: String,
}

impl ParsedUrl {
    /// The host:port authority as written (no userinfo).
    /// An IPv6 literal host gets its brackets back:
    /// `parse_url` strips them for the loopback check,
    /// but the wire `Host:` header needs them
    /// (RFC 9112 §3.2.2 — `Host: ::1:PORT` without
    /// brackets is malformed, even though Go's server
    /// happens to accept it).
    #[must_use]
    pub fn authority(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        if self.port.is_empty() {
            host
        } else {
            format!("{host}:{}", self.port)
        }
    }

    /// The request-target path: path plus query when
    /// present (`/x?y=1`), `/` when both are empty.
    #[must_use]
    pub fn request_target(&self) -> String {
        let path = if self.path.is_empty() {
            "/".to_string()
        } else {
            self.path.clone()
        };
        if self.query.is_empty() {
            path
        } else {
            format!("{path}?{}", self.query)
        }
    }
}

/// Parse an absolute URL into its policy pieces. Returns
/// `None` when the input is not an absolute URL with a host.
/// No direct Go function counterpart: this is the Rust-side
/// shape of Go's `net/url.Parse` + `URL.Hostname()` /
/// `URL.Port()` / `URL.User` as used by `validateDownloadURL`
/// and `checkRedirectPolicy` (`internal/update/update.go:423-458,774-793`).
///
/// Control characters (`< 0x20`, `0x7f`) are refused
/// anywhere in the raw URL, mirroring Go's
/// `net/url: invalid control character in URL` (probed on
/// cue 2026-11-05: CR/LF and DEL in path/authority refuse;
/// see the `parse_url_rejects_control_characters` test).
/// Space is refused too — stricter than Go, which accepts
/// a space in the PATH (`url.Parse` succeeds, the client
/// percent-encodes it on send). This port has no URL
/// escaper: sending a raw space would corrupt the request
/// line, so refusing is the safe choice ([DEVIATION] 28
/// in PORTING.md §M6c.2).
pub fn parse_url(raw: &str) -> Option<ParsedUrl> {
    // Reject control bytes, DEL, and space before any
    // splitting: they must never reach the request line
    // or the `Host:` header (header injection via a
    // hostile release JSON or redirect `Location`).
    if raw.bytes().any(|b| b < 0x20 || b == 0x7f || b == b' ') {
        return None;
    }
    let (scheme, rest) = raw.split_once("://")?;
    if scheme.is_empty()
        || !scheme
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'-' || b == b'.')
    {
        return None;
    }
    // Authority runs to the first '/', '?', or '#'.
    let auth_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..auth_end];
    let after = &rest[auth_end..];
    if authority.is_empty() {
        return None;
    }
    let (userinfo, hostport) = match authority.rfind('@') {
        Some(i) => (true, &authority[i + 1..]),
        None => (false, authority),
    };
    if hostport.is_empty() {
        return None;
    }
    // Split host / port. An IPv6 literal in brackets
    // stores its inner part in `host` (no brackets);
    // `authority()` adds them back for the wire.
    let (host, port) = if let Some(stripped) = hostport.strip_prefix('[') {
        let end = stripped.find(']')?;
        let host = &stripped[..end];
        let rest = &stripped[end + 1..];
        let port = rest.strip_prefix(':').unwrap_or("");
        (host.to_string(), port.to_string())
    } else if let Some(i) = hostport.rfind(':') {
        (hostport[..i].to_string(), hostport[i + 1..].to_string())
    } else {
        (hostport.to_string(), String::new())
    };
    // Go's `url.Parse` refuses a non-numeric port
    // (`invalid port ":abc" after host`, probed on cue
    // 2026-11-05); an empty port (`"h:"`) and any
    // all-digit port (even > 65535, which fails later at
    // dial, like Go) are accepted.
    if !port.is_empty() && !port.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    // Split the remainder into path / query / fragment.
    // The fragment never reaches the wire.
    let after = after.split('#').next().unwrap_or("");
    let (path, query) = match after.split_once('?') {
        Some((p, q)) => (p, q),
        None => (after, ""),
    };
    Some(ParsedUrl {
        scheme: scheme.to_ascii_lowercase(),
        has_userinfo: userinfo,
        host,
        port,
        path: path.to_string(),
        query: query.to_string(),
        raw: raw.to_string(),
    })
}

/// Whether `host` is a loopback host: `localhost`, or an IP
/// whose loopback test passes (`127.0.0.0/8`, `::1`).
/// Source: `isLoopbackHost` (`internal/update/update.go:411-418`).
pub fn is_loopback_host(host: &str) -> bool {
    if host == "localhost" {
        return true;
    }
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return ip.is_loopback();
    }
    false
}

/// Require an absolute `https` URL, or `http` to a loopback
/// host (httptest only). Relative, `javascript:`, `file:`,
/// and other schemes never reach the network. A URL carrying
/// userinfo is refused before any request: the stdlib client
/// would otherwise send an `Authorization` header derived
/// from the URL.
///
/// Returns `bool`, not `Result<(), ()>`: Go's
/// `validateDownloadURL` returns one fixed error
/// (`"invalid download URL"`, `update.go:774-793`) for every
/// refusal, and every caller only tests accept/refuse.
/// Source: `validateDownloadURL` (`internal/update/update.go:774-793`).
pub fn validate_download_url(raw: &str) -> bool {
    let Some(parsed) = parse_url(raw) else {
        return false;
    };
    if parsed.host.is_empty() || parsed.has_userinfo {
        return false;
    }
    if parsed.scheme == "https" {
        return true;
    }
    if parsed.scheme == "http" && is_loopback_host(&parsed.host) {
        return true;
    }
    false
}

/// Redirect-policy refusal reasons.
/// Source: `errTooManyRedirects` / `errRedirectForbidden` /
/// `errRedirectUserinfo` (`internal/update/update.go:380-382`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedirectRefusal {
    /// More than 4 redirects followed.
    TooManyRedirects,
    /// Target host/scheme/port outside the allowlist.
    Forbidden,
    /// Target URL carries userinfo.
    Userinfo,
}

/// Redirect policy: at most 4 redirects followed, HTTPS only
/// (HTTP only back to a loopback origin, for httptest), no
/// redirect target carrying userinfo, and the redirect target
/// host must be the origin host or one of `github.com`,
/// `release-assets.githubusercontent.com`,
/// `objects.githubusercontent.com`. Anything else aborts
/// before dialing. `via` is the chain so far (first element
/// = the origin request); the policy applies to redirects
/// only, never to the initial URL.
/// Source: `checkRedirectPolicy` (`internal/update/update.go:423-458`).
/// Note (R1 Q3): `len(via) >= 5` refuses the 5th redirect,
/// i.e. exactly 4 follows are allowed.
pub fn check_redirect_policy(target: &ParsedUrl, via: &[ParsedUrl]) -> Result<(), RedirectRefusal> {
    if target.has_userinfo {
        return Err(RedirectRefusal::Userinfo);
    }
    if via.len() >= 5 {
        return Err(RedirectRefusal::TooManyRedirects);
    }
    if target.scheme != "https" {
        if !is_loopback_host(&target.host) {
            return Err(RedirectRefusal::Forbidden);
        }
        if !via.is_empty() && via[0].scheme == "https" {
            return Err(RedirectRefusal::Forbidden); // scheme downgrade
        }
    }
    if !target.port.is_empty() && target.port != "443" && !is_loopback_host(&target.host) {
        return Err(RedirectRefusal::Forbidden);
    }
    if !via.is_empty() && target.host == via[0].host {
        return Ok(());
    }
    match target.host.as_str() {
        "github.com" | "release-assets.githubusercontent.com" | "objects.githubusercontent.com" => {
            Ok(())
        }
        _ => Err(RedirectRefusal::Forbidden),
    }
}

/// Transport-error class vocabulary.
/// Source: `classifyTransportError` (`internal/update/update.go:168-199`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportErrorKind {
    /// Redirect-policy refusal.
    Redirect,
    /// Deadline exceeded / cancelled.
    Timeout,
    /// `ECONNREFUSED`.
    ConnectionRefused,
    /// `ECONNRESET`.
    ConnectionReset,
    /// DNS lookup failure.
    Dns,
    /// TLS failure (see the [DEVIATION] note on
    /// [`classify_transport_error`]).
    Tls,
    /// Dial-phase `net.OpError` that is none of the above.
    Dial,
    /// Anything else.
    Transport,
}

/// Classify a transport failure into Go's bounded vocabulary.
///
/// Source: `classifyTransportError` (`internal/update/update.go:168-199`).
///
/// [DEVIATION] — the TLS arm: Go classifies a REAL handshake
/// failure as `"transport"`, not `"tls"`, because its
/// `isTLSError` only matches specific `x509.*` VALUE types
/// and a real failure surfaces as a value
/// `x509.UnknownAuthorityError` inside
/// `*tls.CertificateVerificationError`, which its
/// `errors.As` target (`*x509.UnknownAuthorityError`)
/// does not match (pinned by
/// `TestClassifyTransportErrorRealHandshake`,
/// `edge_test.go:973-991`). That asymmetry is a Go
/// type-system artifact with no Rust analogue: rustls
/// reports handshake failures as typed `rustls::Error`
/// values, so this port maps every rustls handshake/
/// verification failure to `"tls"`. The Go
/// `TestClassifyTransportErrorTLSForms` value-vs-pointer
/// table therefore has no Rust equivalent and is NOT
/// ported case-for-case; the Rust mapping is pinned by
/// `classify_transport_error_tls_forms` below instead.
pub fn classify_transport_error(kind: TransportErrorKind) -> &'static str {
    match kind {
        TransportErrorKind::Redirect => "redirect",
        TransportErrorKind::Timeout => "timeout",
        TransportErrorKind::ConnectionRefused => "connection_refused",
        TransportErrorKind::ConnectionReset => "connection_reset",
        TransportErrorKind::Dns => "dns",
        TransportErrorKind::Tls => "tls",
        TransportErrorKind::Dial => "dial",
        TransportErrorKind::Transport => "transport",
    }
}

/// Classify an HTTP status into the `fetchBytes` /
/// `downloadAsset` class vocabulary.
/// Source: `fetchBytes` (`internal/update/update.go:486-494`).
pub fn http_status_class(status: u16) -> &'static str {
    match status {
        404 => "not_found",
        403 | 429 => "rate_limited",
        500..=599 => "server_error",
        _ => "http_error",
    }
}

/// Extract the tag from a fallback-redirect `Location` path.
/// The redirect target must stay on the base host (checked
/// by the caller); the path must contain `/releases/tag/`;
/// the tag is `PathUnescape`d, and empty or `/`-containing
/// tags refuse.
/// Source: the tail of `fallbackTag` (`internal/update/update.go:844-852`).
/// `PathUnescape` here is the Rust-side equivalent for the
/// tag shapes in play: `%XX` sequences are percent-decoded,
/// `+` stays `+` (path segment, not a query), and a bad
/// escape refuses (R1 Q9: `%2F` decodes to `/` and then
/// refuses, exactly like Go).
pub fn fallback_tag_from_location_path(escaped_path: &str) -> Option<String> {
    let idx = escaped_path.rfind("/releases/tag/")?;
    let encoded = &escaped_path[idx + "/releases/tag/".len()..];
    let tag = percent_decode_path(encoded)?;
    if tag.is_empty() || tag.contains('/') {
        return None;
    }
    Some(tag)
}

fn percent_decode_path(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return None;
            }
            let hi = (bytes[i + 1] as char).to_digit(16)?;
            let lo = (bytes[i + 2] as char).to_digit(16)?;
            out.push((hi * 16 + lo) as u8);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::semver::parse_version;

    fn good_asset() -> ReleaseAsset {
        ReleaseAsset {
            name: "castctl_0.6.4_linux_amd64.tar.gz".to_string(),
            url: "https://github.com/x/y".to_string(),
            size: 10,
            state: "uploaded".to_string(),
        }
    }

    fn rel(assets: Vec<ReleaseAsset>) -> ReleaseInfo {
        ReleaseInfo {
            tag: "v0.6.4".to_string(),
            draft: false,
            prerelease: false,
            assets,
        }
    }

    /// Port of `TestSelectAssetUnits`
    /// (`internal/update/edge_test.go:541-582`).
    #[test]
    fn select_asset_units() {
        let good = good_asset();
        assert!(select_asset(&rel(vec![good.clone()]), &good.name).is_ok());
        let cases: Vec<ReleaseInfo> = vec![
            rel(vec![]),
            rel(vec![ReleaseAsset {
                name: "castctl_0.6.4_linux_arm64.tar.gz".to_string(),
                url: "https://github.com/x".to_string(),
                size: 10,
                state: "uploaded".to_string(),
            }]),
            rel(vec![good.clone(), good.clone()]),
            rel(vec![ReleaseAsset {
                state: "created".to_string(),
                ..good.clone()
            }]),
            rel(vec![ReleaseAsset {
                size: 0,
                ..good.clone()
            }]),
            rel(vec![ReleaseAsset {
                url: "/download/x".to_string(),
                ..good.clone()
            }]),
            rel(vec![ReleaseAsset {
                url: "javascript:alert(1)".to_string(),
                ..good.clone()
            }]),
            rel(vec![ReleaseAsset {
                url: "file:///etc/passwd".to_string(),
                ..good.clone()
            }]),
            rel(vec![ReleaseAsset {
                name: "castctl_0.6.4_linux_amd64.tar.gz.bak".to_string(),
                ..good.clone()
            }]),
        ];
        for r in cases {
            assert!(select_asset(&r, &good.name).is_err());
        }
        // Checksums selection: missing and duplicate refuse.
        assert!(select_checksums_asset(&rel(vec![good.clone()])).is_err());
        let chk = ReleaseAsset {
            name: "checksums.txt".to_string(),
            url: "https://github.com/x/c".to_string(),
            size: 10,
            state: "uploaded".to_string(),
        };
        assert!(select_checksums_asset(&rel(vec![good.clone(), chk.clone()])).is_ok());
        assert!(select_checksums_asset(&rel(vec![chk.clone(), chk])).is_err());
    }

    /// Port of the unit half of `TestDownloadURLWithUserinfoRefuses`
    /// (`internal/update/update_test.go:691-711`): 3 userinfo
    /// URLs refuse, 2 clean URLs pass.
    #[test]
    fn validate_download_url_table() {
        for bad in [
            "https://user:pass@github.com/x/y",
            "https://user@github.com/x/y",
            "http://user:pass@127.0.0.1:9/x",
        ] {
            assert!(!validate_download_url(bad), "{bad}");
        }
        for good in ["https://github.com/x/y", "http://127.0.0.1:9/x"] {
            assert!(validate_download_url(good), "{good}");
        }
        for bad in [
            "/download/x",
            "javascript:alert(1)",
            "file:///etc/passwd",
            "http://example.com/x",
            "https://",
        ] {
            assert!(!validate_download_url(bad), "{bad}");
        }
    }

    /// `decide` guard order (R1 §3.4): downgrade → no-op →
    /// prerelease guard → asset selection. Equal prerelease
    /// is a no-op, not a refusal.
    #[test]
    fn decide_guard_order() {
        let current = parse_version("0.6.3").unwrap();
        let target = parse_version("0.6.4").unwrap();
        let rel = rel(vec![
            good_asset(),
            ReleaseAsset {
                name: "checksums.txt".to_string(),
                url: "https://github.com/x/c".to_string(),
                size: 10,
                state: "uploaded".to_string(),
            },
        ]);
        let sel = decide(
            &current,
            target.clone(),
            "v0.6.4".to_string(),
            "glibc",
            "amd64",
            "https://github.com",
            Some(&rel),
            false,
            false,
            false,
        )
        .unwrap();
        assert!(!sel.noop);
        assert_eq!(sel.asset_name, "castctl_0.6.4_linux_amd64.tar.gz");
        assert_eq!(sel.asset_url, "https://github.com/x/y");
        // Equal version → no-op, even when it is a prerelease.
        let pre = parse_version("0.6.4-rc.1").unwrap();
        let sel = decide(
            &pre,
            pre.clone(),
            "v0.6.4-rc.1".to_string(),
            "glibc",
            "amd64",
            "https://github.com",
            Some(&rel),
            false,
            false,
            false,
        )
        .unwrap();
        assert!(sel.noop);
        // Downgrade refuses without the flag.
        assert!(
            decide(
                &target,
                current.clone(),
                "v0.6.3".to_string(),
                "glibc",
                "amd64",
                "https://github.com",
                Some(&rel),
                false,
                false,
                false,
            )
            .is_err()
        );
        // Prerelease target refuses without the flag.
        assert!(
            decide(
                &current,
                pre,
                "v0.6.4-rc.1".to_string(),
                "glibc",
                "amd64",
                "https://github.com",
                Some(&rel),
                false,
                false,
                false,
            )
            .is_err()
        );
        // Fallback mode constructs URLs, size unknown.
        let sel = decide(
            &current,
            target,
            "v0.6.4".to_string(),
            "glibc",
            "amd64",
            "https://github.com",
            None,
            true,
            false,
            false,
        )
        .unwrap();
        assert_eq!(sel.asset_size, 0);
        assert_eq!(
            sel.asset_url,
            "https://github.com/thoitiettxl-cyber/castctl/releases/download/v0.6.4/castctl_0.6.4_linux_amd64.tar.gz"
        );
    }

    #[test]
    fn flavour_from_cgo_settings_table() {
        let one = |v: &str| vec![("CGO_ENABLED".to_string(), v.to_string())];
        assert_eq!(flavour_from_cgo_settings(&one("1")), Some("glibc"));
        assert_eq!(flavour_from_cgo_settings(&one("0")), Some("no-plugin"));
        assert_eq!(flavour_from_cgo_settings(&one("")), None);
        assert_eq!(flavour_from_cgo_settings(&one("2")), None);
        assert_eq!(flavour_from_cgo_settings(&one("yes")), None);
        assert_eq!(flavour_from_cgo_settings(&[]), None);
        // Conflicting duplicates refuse.
        assert_eq!(
            flavour_from_cgo_settings(&[
                ("CGO_ENABLED".to_string(), "1".to_string()),
                ("CGO_ENABLED".to_string(), "0".to_string()),
            ]),
            None
        );
        // Identical duplicates are fine.
        assert_eq!(
            flavour_from_cgo_settings(&[
                ("CGO_ENABLED".to_string(), "1".to_string()),
                ("CGO_ENABLED".to_string(), "1".to_string()),
            ]),
            Some("glibc")
        );
    }

    /// Redirect policy (R1 §3.5): 4 follows allowed, the 5th
    /// refuses; userinfo refuses before dial; foreign hosts
    /// refuse; loopback http is allowed only without a
    /// downgrade from https.
    #[test]
    fn redirect_policy_table() {
        let origin = parse_url("https://api.github.com/repos/x").unwrap();
        let via = [origin.clone()];
        // Same-host https redirect: allowed.
        let same = parse_url("https://api.github.com/other").unwrap();
        assert!(check_redirect_policy(&same, &via).is_ok());
        // Allowlisted object host: allowed.
        let obj = parse_url("https://release-assets.githubusercontent.com/x").unwrap();
        assert!(check_redirect_policy(&obj, &via).is_ok());
        // Foreign host: refused.
        let foreign = parse_url("https://evil.example.com/x").unwrap();
        assert_eq!(
            check_redirect_policy(&foreign, &via),
            Err(RedirectRefusal::Forbidden)
        );
        // Userinfo: refused.
        let user = parse_url("https://user:pass@github.com/x").unwrap();
        assert_eq!(
            check_redirect_policy(&user, &via),
            Err(RedirectRefusal::Userinfo)
        );
        // http to a non-loopback host: refused.
        let plain = parse_url("http://github.com/x").unwrap();
        assert!(check_redirect_policy(&plain, &via).is_err());
        // http loopback from an http origin: allowed.
        let http_origin = parse_url("http://127.0.0.1:9/a").unwrap();
        let http_next = parse_url("http://127.0.0.1:9/b").unwrap();
        assert!(check_redirect_policy(&http_next, &[http_origin]).is_ok());
        // https → http loopback downgrade: refused.
        let down = parse_url("http://127.0.0.1:9/b").unwrap();
        assert_eq!(
            check_redirect_policy(&down, &via),
            Err(RedirectRefusal::Forbidden)
        );
        // Non-443 port on a non-loopback host: refused.
        let port = parse_url("https://github.com:8443/x").unwrap();
        assert!(check_redirect_policy(&port, &via).is_err());
        // Boundary (Q3): exactly 4 follows allowed, 5th refuses.
        let chain: Vec<ParsedUrl> = (0..4).map(|_| origin.clone()).collect();
        assert!(check_redirect_policy(&same, &chain).is_ok());
        let chain5: Vec<ParsedUrl> = (0..5).map(|_| origin.clone()).collect();
        assert_eq!(
            check_redirect_policy(&same, &chain5),
            Err(RedirectRefusal::TooManyRedirects)
        );
    }

    /// The Rust transport-error taxonomy (the Go
    /// value-vs-pointer table has no Rust equivalent; see
    /// the [DEVIATION] note on `classify_transport_error`).
    #[test]
    fn classify_transport_error_tls_forms() {
        assert_eq!(classify_transport_error(TransportErrorKind::Tls), "tls");
        assert_eq!(
            classify_transport_error(TransportErrorKind::Redirect),
            "redirect"
        );
        assert_eq!(
            classify_transport_error(TransportErrorKind::Timeout),
            "timeout"
        );
        assert_eq!(
            classify_transport_error(TransportErrorKind::ConnectionRefused),
            "connection_refused"
        );
        assert_eq!(
            classify_transport_error(TransportErrorKind::ConnectionReset),
            "connection_reset"
        );
        assert_eq!(classify_transport_error(TransportErrorKind::Dns), "dns");
        assert_eq!(classify_transport_error(TransportErrorKind::Dial), "dial");
        assert_eq!(
            classify_transport_error(TransportErrorKind::Transport),
            "transport"
        );
    }

    /// `fallbackTag` path extraction (R1 Q9): `%2F`
    /// decodes to `/` and then refuses, like Go.
    #[test]
    fn fallback_tag_from_location_path_table() {
        assert_eq!(
            fallback_tag_from_location_path("/thoitiettxl-cyber/castctl/releases/tag/v0.6.4"),
            Some("v0.6.4".to_string())
        );
        assert_eq!(
            fallback_tag_from_location_path("/releases/tag/v1.0.0%2Fevil"),
            None
        );
        assert_eq!(
            fallback_tag_from_location_path("/releases/tag/v0.6.4%2Bbuild"),
            Some("v0.6.4+build".to_string())
        );
        assert_eq!(fallback_tag_from_location_path("/releases/latest"), None);
        assert_eq!(fallback_tag_from_location_path("/releases/tag/"), None);
    }

    /// Safety B1 (fix loop 1): `parse_url` refuses
    /// control characters, DEL, and space anywhere in
    /// the raw URL — Go refuses CR/LF/DEL with
    /// `net/url: invalid control character in URL`
    /// (probed on cue with `go run` 2026-11-05), so a
    /// hostile release JSON or redirect `Location` can
    /// never smuggle a header into the request line.
    #[test]
    fn parse_url_rejects_control_characters() {
        for bad in [
            "https://api.github.com/foo\r\nX-Injected: 1",
            "https://api.github.com:443\r\nX: y/foo",
            "https://github.com/a\tb",
            "https://github.com/a\x7fb",
            "https://github.com/a\x00b",
            "https://github.com/a b",
        ] {
            assert!(parse_url(bad).is_none(), "{bad:?}");
            assert!(!validate_download_url(bad), "{bad:?}");
        }
        // Clean URLs still parse.
        assert!(parse_url("https://github.com/x/y").is_some());
        assert!(parse_url("https://release-assets.githubusercontent.com/x").is_some());
    }

    /// Technical F-c (fix loop 1): port validation
    /// matches Go's `url.Parse` (probed on cue
    /// 2026-11-05): non-numeric refuses, empty and
    /// all-digit ports accept (even > 65535, which
    /// fails later at dial, like Go).
    #[test]
    fn parse_url_port_validation_matches_go() {
        assert!(parse_url("https://github.com:abc/").is_none());
        assert!(parse_url("https://github.com:80x/").is_none());
        assert!(parse_url("https://github.com:443/x").is_some());
        assert!(parse_url("https://github.com:99999/").is_some());
        assert!(parse_url("https://h:/").is_some());
        assert!(parse_url("https://[::1]:abc/x").is_none());
        assert!(parse_url("https://[::1]:8080/x").is_some());
    }

    /// Technical F-c (fix loop 1): Go's `url.Parse`
    /// lowercases the scheme but preserves host case
    /// (probed on cue 2026-11-05: `HTTPS://…` parses
    /// with scheme `"https"`; `GITHUB.COM` stays
    /// `"GITHUB.COM"`). The redirect policy therefore
    /// refuses an uppercase spelling of an allowlisted
    /// host, exactly like Go's case-sensitive
    /// comparison (`update.go:442-448`).
    #[test]
    fn parse_url_case_matches_go() {
        let u = parse_url("HTTPS://github.com/x").unwrap();
        assert_eq!(u.scheme, "https");
        let u = parse_url("https://GITHUB.COM/x").unwrap();
        assert_eq!(u.host, "GITHUB.COM");
        // Uppercase allowlisted host: refused by the
        // redirect policy (Go refuses it too).
        let origin = parse_url("https://api.github.com/repos/x").unwrap();
        let upper = parse_url("https://GITHUB.COM/x").unwrap();
        assert_eq!(
            check_redirect_policy(&upper, &[origin]),
            Err(RedirectRefusal::Forbidden)
        );
    }

    /// Technical F-d (fix loop 1): the query survives
    /// parsing and rides the request target; Go sends
    /// `RawQuery` (`url.Parse` probe, cue 2026-11-05).
    #[test]
    fn parse_url_keeps_query() {
        let u = parse_url("https://github.com/x?y=1&z=2").unwrap();
        assert_eq!(u.path, "/x");
        assert_eq!(u.query, "y=1&z=2");
        assert_eq!(u.request_target(), "/x?y=1&z=2");
        let u = parse_url("https://github.com/x").unwrap();
        assert_eq!(u.query, "");
        assert_eq!(u.request_target(), "/x");
        let u = parse_url("https://github.com").unwrap();
        assert_eq!(u.request_target(), "/");
    }

    /// Red-team IPv6 note (fix loop 1): the bracketed
    /// host is stored bare for the loopback check, but
    /// `authority()` puts the brackets back, so the
    /// wire `Host:` header is RFC 9112 well-formed.
    #[test]
    fn ipv6_authority_keeps_brackets() {
        let u = parse_url("http://[::1]:8080/x").unwrap();
        assert_eq!(u.host, "::1");
        assert_eq!(u.authority(), "[::1]:8080");
        assert!(is_loopback_host(&u.host));
        let u = parse_url("http://[::1]/x").unwrap();
        assert_eq!(u.authority(), "[::1]");
    }

    /// Safety F3 (fix loop 1): `decide(None, false)`
    /// errors instead of panicking on the old `expect`.
    #[test]
    fn decide_missing_release_errors_not_panics() {
        let current = parse_version("0.6.3").unwrap();
        let target = parse_version("0.6.4").unwrap();
        assert!(
            decide(
                &current,
                target,
                "v0.6.4".to_string(),
                "glibc",
                "amd64",
                "https://github.com",
                None,
                false,
                false,
                false,
            )
            .is_err()
        );
    }
}
