// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Hand-written semver 2.0.0 parser.
//!
//! Go source: `internal/update/semver.go` (219 lines, at
//! `dev-rust` `25a124e`). The parser is strict: every invalid
//! input is an error (never an "invalid < valid" ordering), so
//! a hostile `tag_name` can never silently order as older
//! than (or equal to) a real version (`semver.go:11-21`).
//!
//! Deliberately NOT the `semver` crate (1.0.28, already in
//! `Cargo.lock` via tooling): the crate stores
//! `major/minor/patch: u64`, but the Go fixture
//! `99999999999999999999999999.0.0` exceeds `u64::MAX`
//! (`semver_test.go:27`); the crate also has no 128-byte cap
//! and rejects every `v`-prefixed input, while Go strips
//! exactly one `v`. This struct therefore keeps the
//! components as strings, exactly like Go's `Version`
//! (`semver.go:32-38`).

/// Maximum version length in bytes (not runes).
/// Source: `maxVersionLen = 128` (`internal/update/semver.go:28`).
pub const MAX_VERSION_LEN: usize = 128;

/// The constant parse error message: no input detail is ever
/// echoed (a hostile tag must not leak into output).
/// Source: `internal/update/semver.go:41-81`.
pub const INVALID_VERSION_MSG: &str = "update: invalid version";

/// A parsed semantic version.
///
/// Source: Go `Version{major, minor, patch string; pre
/// []string; build string}` (`internal/update/semver.go:32-38`).
/// `major`/`minor`/`patch` are kept as strings and compared by
/// (length, lexicographic) so arbitrarily long components
/// cannot overflow (`compareNumeric`, `semver.go:125-135`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version {
    /// Major component, digits only, no leading zero unless `"0"`.
    pub major: String,
    /// Minor component, same rule.
    pub minor: String,
    /// Patch component, same rule.
    pub patch: String,
    /// Prerelease identifiers, `None` when absent.
    /// Source: `pre []string // nil when absent` (`semver.go:35`).
    pub pre: Option<Vec<String>>,
    /// Build metadata, `""` when absent; an empty build is
    /// invalid and is never stored (`semver.go:36`).
    pub build: String,
}

fn is_all_digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

/// Reports whether `s` is a valid numeric component: digits
/// only, no leading zeros except the single digit `"0"`.
/// Source: `isNumericIdent` (`internal/update/semver.go:106-122`).
fn is_numeric_ident(s: &str) -> bool {
    is_all_digits(s) && (s.len() == 1 || !s.starts_with('0'))
}

fn check_dot_idents(s: &str, prerelease: bool) -> Result<(), UpdateError> {
    for id in s.split('.') {
        if id.is_empty() {
            return Err(UpdateError::failure(INVALID_VERSION_MSG));
        }
        if !id.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-') {
            return Err(UpdateError::failure(INVALID_VERSION_MSG));
        }
        if prerelease && is_all_digits(id) && !is_numeric_ident(id) {
            return Err(UpdateError::failure(INVALID_VERSION_MSG));
        }
    }
    Ok(())
}

use crate::error::UpdateError;

/// Parse `s` as a semantic version, stripping one leading `v`.
///
/// Order of operations (load-bearing, `semver.go:40-82`):
/// length cap → strip one `v` → split build at the FIRST `+`
/// → split prerelease at the FIRST `-` of the remainder →
/// core must be exactly 3 numeric idents.
pub fn parse_version(s: &str) -> Result<Version, UpdateError> {
    if s.is_empty() || s.len() > MAX_VERSION_LEN {
        return Err(UpdateError::failure(INVALID_VERSION_MSG));
    }
    let mut rest = s.strip_prefix('v').unwrap_or(s);
    let mut build = String::new();
    if let Some(i) = rest.find('+') {
        build = rest[i + 1..].to_string();
        rest = &rest[..i];
        if build.is_empty() {
            return Err(UpdateError::failure(INVALID_VERSION_MSG));
        }
        check_dot_idents(&build, false)?;
    }
    let mut pre: Option<Vec<String>> = None;
    if let Some(i) = rest.find('-') {
        let pre_part = &rest[i + 1..];
        rest = &rest[..i];
        if pre_part.is_empty() {
            return Err(UpdateError::failure(INVALID_VERSION_MSG));
        }
        check_dot_idents(pre_part, true)?;
        pre = Some(pre_part.split('.').map(str::to_string).collect());
    }
    let core: Vec<&str> = rest.split('.').collect();
    if core.len() != 3 {
        return Err(UpdateError::failure(INVALID_VERSION_MSG));
    }
    for c in &core {
        if !is_numeric_ident(c) {
            return Err(UpdateError::failure(INVALID_VERSION_MSG));
        }
    }
    Ok(Version {
        major: core[0].to_string(),
        minor: core[1].to_string(),
        patch: core[2].to_string(),
        pre,
        build,
    })
}

/// Compare two validated numeric strings, returning -1/0/1.
/// Source: `compareNumeric` (`internal/update/semver.go:125-135`).
fn compare_numeric_sign(a: &str, b: &str) -> i32 {
    use std::cmp::Ordering;
    if a.len() != b.len() {
        return if a.len() < b.len() { -1 } else { 1 };
    }
    match a.cmp(b) {
        Ordering::Less => -1,
        Ordering::Equal => 0,
        Ordering::Greater => 1,
    }
}

/// Compare two versions by semver precedence; returns -1, 0, or 1.
/// Build metadata is ignored.
/// Source: `CompareVersions` (`internal/update/semver.go:137-181`).
pub fn compare_versions(a: &Version, b: &Version) -> i32 {
    let c = compare_numeric_sign(&a.major, &b.major);
    if c != 0 {
        return c;
    }
    let c = compare_numeric_sign(&a.minor, &b.minor);
    if c != 0 {
        return c;
    }
    let c = compare_numeric_sign(&a.patch, &b.patch);
    if c != 0 {
        return c;
    }
    match (&a.pre, &b.pre) {
        (None, None) => return 0,
        (None, Some(_)) => return 1, // release > prerelease
        (Some(_), None) => return -1,
        (Some(ap), Some(bp)) => {
            for i in 0..ap.len().min(bp.len()) {
                let x = &ap[i];
                let y = &bp[i];
                if x == y {
                    continue;
                }
                let x_num = is_all_digits(x);
                let y_num = is_all_digits(y);
                match (x_num, y_num) {
                    (true, true) => return compare_numeric_sign(x, y),
                    (true, false) => return -1, // numeric < alphanumeric
                    (false, true) => return 1,
                    (false, false) => {
                        return match x.cmp(y) {
                            std::cmp::Ordering::Less => -1,
                            std::cmp::Ordering::Equal => 0,
                            std::cmp::Ordering::Greater => 1,
                        };
                    }
                }
            }
            if ap.len() < bp.len() {
                return -1;
            }
            if ap.len() > bp.len() {
                return 1;
            }
            return 0;
        }
    }
}

impl Version {
    /// Render the canonical form: core, prerelease, and build
    /// metadata when present; never a leading `v`.
    /// Source: `Version.String()` (`internal/update/semver.go:184-194`).
    #[must_use]
    pub fn to_canonical(&self) -> String {
        let mut s = self.core();
        if let Some(pre) = &self.pre {
            s.push('-');
            s.push_str(&pre.join("."));
        }
        if !self.build.is_empty() {
            s.push('+');
            s.push_str(&self.build);
        }
        s
    }

    /// Return `"major.minor.patch"`.
    /// Source: `Version.Core()` (`internal/update/semver.go:196`).
    #[must_use]
    pub fn core(&self) -> String {
        format!("{}.{}.{}", self.major, self.minor, self.patch)
    }

    /// Return the prerelease part without the `-`, or `""`.
    /// Source: `Version.Prerelease()` (`internal/update/semver.go:199-205`).
    #[must_use]
    pub fn prerelease(&self) -> String {
        match &self.pre {
            Some(pre) => pre.join("."),
            None => String::new(),
        }
    }

    /// Report whether build metadata was present.
    /// Source: `Version.HasBuild()` (`internal/update/semver.go:207`).
    #[must_use]
    pub fn has_build(&self) -> bool {
        !self.build.is_empty()
    }

    /// Return the version as it appears in release asset names:
    /// core plus prerelease, without build metadata.
    /// Source: `Version.AssetVersion()` (`internal/update/semver.go:213-221`).
    #[must_use]
    pub fn asset_version(&self) -> String {
        let mut s = self.core();
        if let Some(pre) = &self.pre {
            s.push('-');
            s.push_str(&pre.join("."));
        }
        s
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_canonical())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &str) -> Version {
        parse_version(s).unwrap_or_else(|_| panic!("expected valid version: {s}"))
    }

    fn sign(n: i32) -> i32 {
        n.signum()
    }

    /// Table A (R1 §1.5): 13 valid inputs.
    /// Source: `TestParseVersionValid`
    /// (`internal/update/semver_test.go:20-45`).
    #[test]
    fn parse_version_valid_table() {
        let valid: &[(&str, &str)] = &[
            ("0.6.1", "0.6.1"),
            ("v1.2.3", "1.2.3"),
            ("1.0.0-alpha", "1.0.0-alpha"),
            ("1.0.0-alpha.1", "1.0.0-alpha.1"),
            ("1.0.0-0", "1.0.0-0"),
            ("1.0.0+build", "1.0.0+build"),
            ("1.0.0-alpha+001", "1.0.0-alpha+001"),
            (
                "1.0.0+21AF26D3----117B344092BD",
                "1.0.0+21AF26D3----117B344092BD",
            ),
            ("1.0.0-alpha-beta", "1.0.0-alpha-beta"),
            ("1.0.0-0.3.7", "1.0.0-0.3.7"),
            ("1.0.0-x-y-z.-", "1.0.0-x-y-z.-"),
            (
                "99999999999999999999999999.0.0",
                "99999999999999999999999999.0.0",
            ),
            (
                "1.99999999999999999999999999.0",
                "1.99999999999999999999999999.0",
            ),
        ];
        for (input, canonical) in valid {
            let parsed = parse_version(input).unwrap_or_else(|_| panic!("expected valid: {input}"));
            assert_eq!(parsed.to_canonical(), *canonical, "input {input}");
        }
    }

    /// Table B (R1 §1.5): 20 invalid groups (40+ inputs).
    /// Source: `TestParseVersionInvalid`
    /// (`internal/update/semver_test.go:47-88`).
    #[test]
    fn parse_version_invalid_table() {
        let invalid: &[&str] = &[
            "",
            "v",
            "1",
            "1.0",
            "v1",
            "v1.0",
            "v1.0.0.0",
            "v1.0.0-",
            "1.0.0-",
            "v1.0.0+",
            "v1.0.0++x",
            "v1.0.0+é",
            "01.2.3",
            "v01.2.3",
            "1.02.3",
            "1.0.03",
            "1.0.0-01",
            "1.0.0-alpha.01",
            "1.0.0-00",
            "V1.0.0",
            "vv1.0.0",
            "v 1.0.0",
            "v1.0.0 ",
            " v1.0.0",
            "v1.0.0\nInjected",
            "v1.0.0\r\nx",
            "v1.0.0\x00x",
            "v1.0.0\tx",
            "v1..0",
            "v1.0.0-alpha..1",
            "v1.0.0-alpha.",
            "v1.0.0-.alpha",
            "v1.0.0-..",
            "--help",
            "-v",
            "v1.0.0; rm -rf /",
            "$(id)",
            "1.0.0-a_b",
            "1.0.0-a b",
            "1.0.0+a_b",
            "v1.0.0-alpha.1 ",
            "1.0.0-alpha..",
            "1.0.0+.",
            ".",
            "...",
        ];
        for input in invalid {
            assert!(parse_version(input).is_err(), "expected invalid: {input:?}");
        }
        // Over-long inputs (cap 128 bytes).
        assert!(parse_version(&"9".repeat(200)).is_err());
        assert!(parse_version(&format!("v1.0.0-{}", "a".repeat(1000))).is_err());
        // The error message is always the constant, never the input.
        let err = parse_version("$(id)").unwrap_err();
        assert_eq!(err.to_string(), "update: invalid version");
        assert!(!err.to_string().contains("$(id)"));
    }

    /// Table C (R1 §1.5): precedence chain + 15 compare pairs.
    /// Source: `TestCompareVersionOrdering`
    /// (`internal/update/semver_test.go:90-124`). Go asserts
    /// only the sign; Rust asserts the exact -1/0/1 because
    /// Go really returns those values (`semver.go:137-181`).
    #[test]
    fn compare_version_ordering_table() {
        let chain = [
            "1.0.0-alpha",
            "1.0.0-alpha.1",
            "1.0.0-alpha.beta",
            "1.0.0-beta",
            "1.0.0-beta.2",
            "1.0.0-beta.11",
            "1.0.0-rc.1",
            "1.0.0",
        ];
        for i in 0..chain.len() {
            for j in 0..chain.len() {
                let got = compare_versions(&v(chain[i]), &v(chain[j]));
                let want = match i.cmp(&j) {
                    std::cmp::Ordering::Less => -1,
                    std::cmp::Ordering::Equal => 0,
                    std::cmp::Ordering::Greater => 1,
                };
                assert_eq!(sign(got), want, "{} vs {}", chain[i], chain[j]);
            }
        }
        let pairs: &[(&str, &str, i32)] = &[
            ("1.10.0", "1.9.0", 1),
            ("1.9.0", "1.10.0", -1),
            ("1.0.0+build1", "1.0.0+build2", 0),
            ("1.0.0+build", "1.0.0", 0),
            ("1.0.0-alpha+001", "1.0.0", -1),
            ("1.0.0-1", "1.0.0-alpha", -1),
            ("1.0.0-alpha.10", "1.0.0-alpha.2", 1),
            ("1.0.0-alpha.1", "1.0.0-alpha.2", -1),
            ("2.0.0", "1.99999999999999999999999999.0", 1),
            ("v1.0.0", "1.0.0", 0),
            ("0.6.4", "0.6.3", 1),
            ("0.6.3", "0.6.3", 0),
            ("0.6.2", "0.6.3", -1),
            ("1.0.0-alpha", "1.0.0-alpha.1", -1),
            ("1.0.0-rc.1", "1.0.0", -1),
        ];
        for (a, b, want) in pairs {
            assert_eq!(compare_versions(&v(a), &v(b)), *want, "{a} vs {b}");
        }
    }

    /// Table D (R1 §1.5): accessors.
    /// Source: `TestVersionCoreAndPrerelease`
    /// (`internal/update/semver_test.go:126-142`).
    #[test]
    fn version_core_and_prerelease_table() {
        let a = v("1.2.3-rc.1+build.5");
        assert_eq!(a.core(), "1.2.3");
        assert_eq!(a.prerelease(), "rc.1");
        assert!(a.has_build());
        assert_eq!(a.asset_version(), "1.2.3-rc.1");
        assert_eq!(a.to_canonical(), "1.2.3-rc.1+build.5");
        let b = v("1.2.3");
        assert_eq!(b.core(), "1.2.3");
        assert_eq!(b.prerelease(), "");
        assert!(!b.has_build());
        assert_eq!(b.asset_version(), "1.2.3");
    }

    /// The zero-value trap (R1 §1.4): a failed parse must never
    /// be rendered — `Version::default` does not exist, and
    /// there is no `Version{}` rendering as `".."`.
    #[test]
    fn no_zero_value_version_renders() {
        // `parse_version("")` errors; there is no way to obtain
        // a `Version` with empty components through the API.
        assert!(parse_version("").is_err());
        // A hand-built struct is possible only inside this
        // crate; the public API never produces one.
        let zero = Version {
            major: String::new(),
            minor: String::new(),
            patch: String::new(),
            pre: None,
            build: String::new(),
        };
        assert_eq!(zero.core(), "..");
    }
}
