//! Free-form error-string redaction, ported from Go
//! `internal/redact` (decision D-redact, D4 a+).
//!
//! Source: `internal/redact/string.go` and `internal/redact/redact.go`
//! at `origin/main` `1396697`. Only the string functions are
//! ported; `redact.Value` (reflection over structured values) is
//! out of scope for M1. Markers are deliberately split, as in Go:
//! URL userinfo uses [`MARKER`] (`<redacted>`), every other step
//! uses [`REDACTED`] (`[redacted]`).

use regex::Regex;
use std::sync::OnceLock;

/// Marker for URL userinfo: `<redacted>`.
/// Source: `internal/redact/redact.go` (`Marker`).
pub const MARKER: &str = "<redacted>";

/// Marker for every other redaction: `[redacted]`.
/// Source: `internal/redact/redact.go` (`Redacted`).
pub const REDACTED: &str = "[redacted]";

fn re_query_token() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // Go `\s` is ASCII-only (RE2).
        Regex::new(
            r"(?i)([?&](?:auth_token|access_token|hatch_token|token|session)=)[^&\t\n\f\r ]*",
        )
        .expect("reQueryToken")
    })
}

fn re_fragment_token() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)(#(?:auth_token|access_token|hatch_token|token|session)=)[^&\t\n\f\r ]*")
            .expect("reFragmentToken")
    })
}

fn re_cookie_token() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // Go RE2 `\b` is ASCII-only: `ésession=` matches
        // (boundary between non-ASCII `é` and `s`) while
        // `xsession=` does not. `(?-u:\b)` spells the ASCII
        // boundary; `(?i)` stays Unicode.
        Regex::new(r"(?i)(?-u:\b)(hatch_sess|datr|session)=[^;\t\n\f\r ]*").expect("reCookieToken")
    })
}

fn re_json_cookie() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?i)("(?:hatch_sess|datr|session)"[\t\n\f\r ]*:[\t\n\f\r ]*")[^"]*"#)
            .expect("reJSONCookie")
    })
}

fn re_labelled_bearer() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)(Authorization:[\t\n\f\r ]*Bearer[\t\n\f\r ]+)[^\t\n\f\r ]+")
            .expect("reBearer")
    })
}

fn re_bare_bearer() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)(?-u:\b)(Bearer[\t\n\f\r ]+)[A-Za-z0-9_\-.~+/=]{8,}")
            .expect("reBareBearer")
    })
}

fn re_url_userinfo() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // Go `\s` is ASCII-only (RE2); greedy to the LAST `@`
        // before the first `/`, `?`, or `#`.
        Regex::new(r"(?i)([a-z][a-z0-9+.-]*://)[^/\t\n\f\r ?#]+@").expect("reURLUserinfo")
    })
}

/// Strips credentials from a free-form error string: URL
/// userinfo, token query parameters (including in fragments),
/// cookie fragments (including JSON form), and Bearer tokens,
/// labelled or bare. Idempotent. A `vm_id` query value, a
/// `{"password": ...}` fragment, and plain email text survive.
/// Source: `internal/redact/string.go:47` (`String`).
pub fn redact_string(s: &str) -> String {
    if s.is_empty() {
        return s.to_string();
    }
    let s = redact_url_userinfo(s);
    let s = re_query_token().replace_all(&s, |caps: &regex::Captures<'_>| {
        format!("{}[redacted]", caps.get(1).map_or("", |g| g.as_str()))
    });
    let s = re_fragment_token().replace_all(&s, |caps: &regex::Captures<'_>| {
        format!("{}[redacted]", caps.get(1).map_or("", |g| g.as_str()))
    });
    let s = re_cookie_token().replace_all(&s, |caps: &regex::Captures<'_>| {
        format!("{}=[redacted]", caps.get(1).map_or("", |g| g.as_str()))
    });
    let s = re_json_cookie().replace_all(&s, |caps: &regex::Captures<'_>| {
        format!("{}[redacted]", caps.get(1).map_or("", |g| g.as_str()))
    });
    let s = re_labelled_bearer().replace_all(&s, |caps: &regex::Captures<'_>| {
        format!("{}[redacted]", caps.get(1).map_or("", |g| g.as_str()))
    });
    let s = re_bare_bearer().replace_all(&s, |caps: &regex::Captures<'_>| {
        format!("{}[redacted]", caps.get(1).map_or("", |g| g.as_str()))
    });
    s.into_owned()
}

/// Replaces the userinfo of every URL embedded in `s` with
/// [`MARKER`], keeping scheme, host, and everything after the
/// host byte-identical. Only a `scheme://...@` pattern is
/// redacted; an empty userinfo, a plain email, and an `@` in a
/// path/query/fragment are unchanged. Idempotent.
/// Source: `internal/redact/redact.go:119` (`RedactURLUserinfo`).
pub fn redact_url_userinfo(s: &str) -> String {
    if s.is_empty() {
        return s.to_string();
    }
    re_url_userinfo()
        .replace_all(s, |caps: &regex::Captures<'_>| {
            format!("{}<redacted>@", caps.get(1).map_or("", |g| g.as_str()))
        })
        .into_owned()
}

/// The exact-after-lowercase secret-key set.
/// Source: `internal/redact/value.go:44` (`secretKeys`).
const SECRET_KEYS: &[&str] = &[
    "access_key",
    "access_key_secret",
    "account_key",
    "api_key",
    "api_token",
    "auth",
    "auth_key",
    "auth_str",
    "auth_token",
    "authorization",
    "certificate",
    "client_certificate",
    "client_key",
    "client_key_password",
    "client_secret",
    "cookie",
    "key",
    "mac_key",
    "mca_key",
    "mca_key_password",
    "mesh_psk",
    "node_id",
    "obfs",
    "origin_ca_key",
    "password",
    "pre_shared_key",
    "private_key",
    "private_key_passphrase",
    "psk",
    "public_key",
    "secret",
    "security_token",
    "session_key",
    "short_id",
    "static_key",
    "submission_key",
    "subscription_action_id",
    "token",
    "userkey",
    "username",
    "uuid",
    "vm_id",
    "zone_token",
];

/// Reports whether `key` names secret material. The comparison
/// is case-insensitive and exact after lowercasing: `"Password"`
/// matches, `"my_token"` and `"vmid"` do not.
/// Source: `internal/redact/value.go:92` (`IsSecretKey`).
pub fn is_secret_key(key: &str) -> bool {
    // Go `strings.ToLower`: simple per-rune folding.
    let lower: String = key.chars().flat_map(|c| c.to_lowercase().next()).collect();
    SECRET_KEYS.contains(&lower.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Ported from Go `internal/redact/string_test.go`
    // (`TestString`, 21 cases). Each case is ALSO checked for
    // idempotence, exactly as Go does.
    #[test]
    fn test_string() {
        let cases: [(&str, &str, &str); 21] = [
            (
                "url userinfo uses angle marker",
                "dial socks5://user:s3cret@proxy.invalid:1080: refused",
                "dial socks5://<redacted>@proxy.invalid:1080: refused",
            ),
            (
                "url user only",
                "get https://bob@host.example/x failed",
                "get https://<redacted>@host.example/x failed",
            ),
            (
                "token query param uses bracket marker and vm_id survives",
                "wss://hatch.metaaivm.com/v1/noise?vm_id=v1&auth_token=tok123 failed",
                "wss://hatch.metaaivm.com/v1/noise?vm_id=v1&auth_token=[redacted] failed",
            ),
            (
                "all token query keys",
                "?token=a&access_token=b&hatch_token=c&session=d",
                "?token=[redacted]&access_token=[redacted]&hatch_token=[redacted]&session=[redacted]",
            ),
            (
                "fragment token",
                "redirect https://host.example/x#auth_token=abcdefgh12345678",
                "redirect https://host.example/x#auth_token=[redacted]",
            ),
            (
                "cookie fragments",
                "cookie: hatch_sess=ABCDEF; datr=XYZ",
                "cookie: hatch_sess=[redacted]; datr=[redacted]",
            ),
            (
                "json cookie",
                r#"{"hatch_sess":"abcdefgh12345678","other":1}"#,
                r#"{"hatch_sess":"[redacted]","other":1}"#,
            ),
            (
                "json session with space",
                r#"{"session": "abcdefgh12345678"}"#,
                r#"{"session": "[redacted]"}"#,
            ),
            (
                "labelled bearer",
                "Authorization: Bearer sekrit-token-here",
                "Authorization: Bearer [redacted]",
            ),
            (
                "bare bearer token like",
                "dial failed: Bearer abcdefgh12345678",
                "dial failed: Bearer [redacted]",
            ),
            (
                "bare bearer lowercase",
                "error: bearer ABCDEFGH12345678 in plain text",
                "error: bearer [redacted] in plain text",
            ),
            (
                "bearer prose untouched",
                "the bearer of bad news",
                "the bearer of bad news",
            ),
            (
                "short bearer value untouched",
                "Bearer short",
                "Bearer short",
            ),
            (
                "already redacted is idempotent",
                "Authorization: Bearer [redacted] and ?token=[redacted]",
                "Authorization: Bearer [redacted] and ?token=[redacted]",
            ),
            (
                "plain error untouched",
                "plain error, no credentials, https://example.com/path?q=1",
                "plain error, no credentials, https://example.com/path?q=1",
            ),
            (
                "plain email untouched",
                "contact bob@example.com for help",
                "contact bob@example.com for help",
            ),
            (
                "multiple urls",
                "a https://user:pass@one.example/x and socks5://bob@two.example:1080 end",
                "a https://<redacted>@one.example/x and socks5://<redacted>@two.example:1080 end",
            ),
            (
                "combined steps",
                "dial https://u:p@h/x?token=t failed: hatch_sess=XYZ; Authorization: Bearer abcdefgh12345678",
                "dial https://<redacted>@h/x?token=[redacted] failed: hatch_sess=[redacted]; Authorization: Bearer [redacted]",
            ),
            (
                "labelled bearer consumes trailing semicolon",
                "Authorization: Bearer abcdefgh12345678;",
                "Authorization: Bearer [redacted]",
            ),
            (
                "json password fragment is not key redacted",
                r#"{"password": "x"}"#,
                r#"{"password": "x"}"#,
            ),
            ("empty string", "", ""),
        ];
        for (name, input, want) in cases {
            assert_eq!(redact_string(input), want, "case {name}");
            assert_eq!(redact_string(want), want, "idempotence case {name}");
        }
    }

    // Ported from Go `internal/redact/redact_test.go`
    // (`TestRedactURLUserinfo`, 24 cases — the source file has
    // 24, not the 25 R2 estimated).
    #[test]
    fn test_redact_url_userinfo() {
        let cases: [(&str, &str, &str); 24] = [
            (
                "userinfo in an arbitrary string value",
                "proxy is socks5://user:s3cret@proxy.invalid:1080, see docs",
                "proxy is socks5://<redacted>@proxy.invalid:1080, see docs",
            ),
            (
                "user only no password",
                "get https://bob@host.example/x failed",
                "get https://<redacted>@host.example/x failed",
            ),
            (
                "password containing a colon",
                "https://user:pa:ss@host.example/x",
                "https://<redacted>@host.example/x",
            ),
            (
                "password containing an at sign",
                "https://user:p@ss@host.example/x",
                "https://<redacted>@host.example/x",
            ),
            (
                "password containing two at signs",
                "https://u:a@b@c@host.example/x",
                "https://<redacted>@host.example/x",
            ),
            (
                "at sign in query or fragment does not extend userinfo",
                "https://user:pass@host.example/x?next=a@b#frag@c",
                "https://<redacted>@host.example/x?next=a@b#frag@c",
            ),
            (
                "empty user with password",
                "https://:pass@host.example/x",
                "https://<redacted>@host.example/x",
            ),
            (
                "multiple urls in one string",
                "a https://user:pass@one.example/x and socks5://bob@two.example:1080 end",
                "a https://<redacted>@one.example/x and socks5://<redacted>@two.example:1080 end",
            ),
            (
                "second url embedded in a query string",
                "https://host.example/?next=https://user:pass@other.example/x",
                "https://host.example/?next=https://<redacted>@other.example/x",
            ),
            (
                "url without userinfo unchanged",
                "plain error, no credentials, https://example.com/path?q=1",
                "plain error, no credentials, https://example.com/path?q=1",
            ),
            (
                "url with port but no userinfo unchanged",
                "dial https://example.com:8443/path",
                "dial https://example.com:8443/path",
            ),
            (
                "uppercase scheme preserved",
                "HTTPS://user:pass@host.example/x",
                "HTTPS://<redacted>@host.example/x",
            ),
            (
                "plain email without scheme unchanged",
                "contact bob@example.com for help",
                "contact bob@example.com for help",
            ),
            (
                "bare email like text unchanged",
                "user@example.com",
                "user@example.com",
            ),
            (
                "at sign in url path unchanged",
                "https://example.com/@user/profile",
                "https://example.com/@user/profile",
            ),
            (
                "empty userinfo unchanged",
                "https://@host.example/x",
                "https://@host.example/x",
            ),
            (
                "at sign with no scheme unchanged",
                "a@b and user:pass@host are not urls",
                "a@b and user:pass@host are not urls",
            ),
            (
                "already redacted is idempotent",
                "https://<redacted>@host.example/x",
                "https://<redacted>@host.example/x",
            ),
            (
                "bare url with userinfo and no path",
                "https://user:pass@host.example",
                "https://<redacted>@host.example",
            ),
            (
                "userinfo before query only",
                "https://user:pass@host.example?next=1",
                "https://<redacted>@host.example?next=1",
            ),
            (
                "userinfo before fragment only",
                "https://user:pass@host.example#frag",
                "https://<redacted>@host.example#frag",
            ),
            (
                "scheme with plus dot hyphen",
                "my+scheme.v2://user@host.example/x",
                "my+scheme.v2://<redacted>@host.example/x",
            ),
            ("empty string", "", ""),
            (
                "no url at all unchanged",
                "nothing to redact here",
                "nothing to redact here",
            ),
        ];
        for (name, input, want) in cases {
            assert_eq!(redact_url_userinfo(input), want, "case {name}");
        }
    }

    // Ported from Go `internal/redact/value_test.go`
    // (`TestIsSecretKey` only: 43 true keys + the 13-true /
    // 16-false case table = 43 + 29 assertions). The remaining
    // `TestValue*` functions need Go's reflection-based
    // `redact.Value` and are excluded as Go-only; see
    // PORTING.md.
    #[test]
    fn test_is_secret_key() {
        let secret = [
            "password",
            "private_key",
            "public_key",
            "pre_shared_key",
            "uuid",
            "short_id",
            "token",
            "certificate",
            "key",
            "obfs",
            "psk",
            "private_key_passphrase",
            "auth",
            "auth_str",
            "auth_key",
            "vm_id",
            "node_id",
            "subscription_action_id",
            "authorization",
            "secret",
            "cookie",
            "api_token",
            "access_key_secret",
            "account_key",
            "client_key_password",
            "mca_key",
            "mesh_psk",
            "security_token",
            "static_key",
            "submission_key",
            "zone_token",
            "origin_ca_key",
            "client_key",
            "client_certificate",
            "userkey",
            "mca_key_password",
            "mac_key",
            "api_key",
            "auth_token",
            "client_secret",
            "session_key",
            "access_key",
            "username",
        ];
        assert_eq!(secret.len(), 43);
        for k in secret {
            assert!(is_secret_key(k), "IsSecretKey({k:?}) = false, want true");
        }
        let cases: [(&str, bool); 29] = [
            ("Password", true),
            ("PASSWORD", true),
            ("Authorization", true),
            ("AUTHORIZATION", true),
            ("Auth_Str", true),
            ("Vm_Id", true),
            ("Api_Token", true),
            ("CLIENT_KEY", true),
            ("Client_Certificate", true),
            ("MAC_KEY", true),
            ("UserKey", true),
            ("Username", true),
            ("USERNAME", true),
            ("server", false),
            ("type", false),
            ("tag", false),
            ("my_token", false),
            ("tokenize", false),
            ("password2", false),
            ("vmid", false),
            ("vmId", false),
            ("auth-token", false),
            ("obfs_password", false),
            ("api_token2", false),
            ("my_api_token", false),
            ("client_key_path", false),
            ("key_id", false),
            ("access_key_id", false),
            ("", false),
        ];
        for (key, want) in cases {
            assert_eq!(is_secret_key(key), want, "IsSecretKey({key:?})");
        }
    }
}
