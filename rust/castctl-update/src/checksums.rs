// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! `checksums.txt` parsing (update flavour).
//!
//! Go source: `internal/update/checksums.go` (112 lines).
//! Format: GNU `sha256sum` output. The release workflow
//! generates it over the four archives, sorted by filename;
//! the live separator was measured on cue 2026-11-05
//! (Q2): two spaces, text mode, LF endings — see
//! `rust/PORTING.md` §M6c. The parser accepts every
//! standard shape anyway (two-space text mode, the ` *`
//! binary-mode marker, single-space/tab separators).
//!
//! Pinned rules: uppercase hex is accepted only because it
//! decodes to the same bytes (comparison is over decoded
//! bytes, never hex strings); identical duplicates are
//! idempotent; conflicting or malformed duplicates refuse
//! the whole file; CRLF, missing trailing newline, and
//! blank lines are tolerated; one leading UTF-8 BOM is
//! stripped; NUL bytes, invalid UTF-8, escaped
//! (`\`-prefixed) lines, and any malformed line refuse the
//! whole file; extra entries are ignored; lookup is by
//! EXACT filename only.
//!
//! Trap (kept, not "fixed"): the separator is a run of
//! spaces/tabs then ONE optional `*` — a filename starting
//! with `*` in text mode (`"hash  *foo"`) loses its `*` and
//! parses as `foo`, exactly like Go (`checksums.go:45-78`).

use std::collections::BTreeMap;

use crate::error::UpdateError;

/// Maximum checksums file size: the real file is four lines
/// (~416 bytes). Source: `maxChecksumsBytes = 64 * 1024`
/// (`internal/update/checksums.go:41`).
pub const MAX_CHECKSUMS_BYTES: usize = 64 * 1024;

/// Parse `sha256sum`-format data into filename → digest bytes.
/// The returned digests are always 32 bytes.
/// Source: `ParseChecksums` (`internal/update/checksums.go:45-78`).
pub fn parse_checksums(data: &[u8]) -> Result<BTreeMap<String, [u8; 32]>, UpdateError> {
    if data.len() > MAX_CHECKSUMS_BYTES {
        return Err(UpdateError::failure("update: checksums file too large"));
    }
    if data.contains(&0) {
        return Err(UpdateError::failure(
            "update: checksums file contains NUL bytes",
        ));
    }
    let text = std::str::from_utf8(data)
        .map_err(|_| UpdateError::failure("update: checksums file is not valid UTF-8"))?;
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut out: BTreeMap<String, [u8; 32]> = BTreeMap::new();
    for line in text.split('\n') {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.trim_matches(|c| c == ' ' || c == '\t').is_empty() {
            continue; // blank line
        }
        let (name, digest) = parse_checksums_line(line)?;
        if let Some(prev) = out.get(&name) {
            if prev != &digest {
                return Err(UpdateError::failure(
                    "update: checksums file has conflicting entries",
                ));
            }
            continue; // identical duplicate: idempotent
        }
        out.insert(name, digest);
    }
    if out.is_empty() {
        return Err(UpdateError::failure(
            "update: checksums file has no entries",
        ));
    }
    Ok(out)
}

fn parse_checksums_line(line: &str) -> Result<(String, [u8; 32]), UpdateError> {
    let malformed = || UpdateError::failure("update: malformed checksums line");
    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() && bytes[i] != b' ' && bytes[i] != b'\t' {
        i += 1;
    }
    let hash_str = &line[..i];
    if hash_str.len() != 64 || i >= bytes.len() {
        return Err(malformed());
    }
    let decoded = hex::decode(hash_str).map_err(|_| malformed())?;
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&decoded);
    // Skip the separator run, then one optional '*' binary marker.
    let mut j = i;
    while j < bytes.len() && (bytes[j] == b' ' || bytes[j] == b'\t') {
        j += 1;
    }
    if j < bytes.len() && bytes[j] == b'*' {
        j += 1;
    }
    let name = &line[j..];
    if name.is_empty() {
        return Err(malformed());
    }
    if name.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err(malformed());
    }
    Ok((name.to_string(), digest))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    const TEST_ASSET_NAME: &str = "castctl_0.6.4_linux_amd64.tar.gz";
    const TEST_ASSET_HEX: &str =
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    fn body(lines: &[&str]) -> Vec<u8> {
        format!("{}\n", lines.join("\n")).into_bytes()
    }

    fn want_digest() -> [u8; 32] {
        let mut d = [0u8; 32];
        d.copy_from_slice(&hex::decode(TEST_ASSET_HEX).unwrap());
        d
    }

    /// Port of `TestParseChecksumsShapes`
    /// (`internal/update/checksums_test.go:36-60`).
    #[test]
    fn parse_checksums_shapes() {
        let shapes = [
            format!("{TEST_ASSET_HEX}  {TEST_ASSET_NAME}"),
            format!("{TEST_ASSET_HEX} *{TEST_ASSET_NAME}"),
            format!("{TEST_ASSET_HEX} {TEST_ASSET_NAME}"),
            format!("{TEST_ASSET_HEX}\t{TEST_ASSET_NAME}"),
        ];
        for line in shapes {
            let m = parse_checksums(format!("{line}\n").as_bytes())
                .unwrap_or_else(|_| panic!("line {line:?}"));
            assert_eq!(m[TEST_ASSET_NAME], want_digest());
        }
    }

    /// Port of `TestParseChecksumsLineEndingsAndBlanks`
    /// (`checksums_test.go:62-81`).
    #[test]
    fn parse_checksums_line_endings_and_blanks() {
        let bodies: Vec<Vec<u8>> = vec![
            format!("{TEST_ASSET_HEX}  {TEST_ASSET_NAME}\r\n").into_bytes(),
            format!("{TEST_ASSET_HEX}  {TEST_ASSET_NAME}").into_bytes(),
            format!("{TEST_ASSET_HEX}  {TEST_ASSET_NAME}\n\n").into_bytes(),
            format!("\n{TEST_ASSET_HEX}  {TEST_ASSET_NAME}\n").into_bytes(),
            format!("\u{feff}{TEST_ASSET_HEX}  {TEST_ASSET_NAME}\n").into_bytes(),
        ];
        for b in bodies {
            let m = parse_checksums(&b)
                .unwrap_or_else(|_| panic!("body {b:?}"));
            assert!(m.contains_key(TEST_ASSET_NAME));
        }
    }

    /// Port of `TestParseChecksumsUppercaseHex`
    /// (`checksums_test.go:84-95`).
    #[test]
    fn parse_checksums_uppercase_hex() {
        let upper = format!(
            "{}  {}\n",
            TEST_ASSET_HEX.to_uppercase(),
            TEST_ASSET_NAME
        );
        let m = parse_checksums(upper.as_bytes()).unwrap();
        assert_eq!(m[TEST_ASSET_NAME], want_digest());
    }

    /// Port of `TestParseChecksumsExactMatchOnly`
    /// (`checksums_test.go:97-127`).
    #[test]
    fn parse_checksums_exact_match_only() {
        let other = hex::encode(Sha256::digest(b"other"));
        let lines = [
            format!("{other}  x{TEST_ASSET_NAME}"),
            format!("{other}  {TEST_ASSET_NAME}.bak"),
            format!("{other}  ./{TEST_ASSET_NAME}"),
            format!("{other}  {TEST_ASSET_NAME} "),
        ];
        let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
        let m = parse_checksums(&body(&refs)).unwrap();
        assert!(!m.contains_key(TEST_ASSET_NAME));
        let spaced = body(&[&format!("{TEST_ASSET_HEX}  castctl 0.6.4.tar.gz")]);
        let m = parse_checksums(&spaced).unwrap();
        assert!(!m.contains_key(TEST_ASSET_NAME));
        assert!(m.contains_key("castctl 0.6.4.tar.gz"));
    }

    /// Port of `TestParseChecksumsDuplicates`
    /// (`checksums_test.go:129-155`).
    #[test]
    fn parse_checksums_duplicates() {
        let other = hex::encode(Sha256::digest(b"other"));
        let m = parse_checksums(&body(&[
            &format!("{TEST_ASSET_HEX}  {TEST_ASSET_NAME}"),
            &format!("{TEST_ASSET_HEX}  {TEST_ASSET_NAME}"),
        ]))
        .unwrap();
        assert_eq!(m.len(), 1);
        for lines in [
            [
                format!("{TEST_ASSET_HEX}  {TEST_ASSET_NAME}"),
                format!("{other}  {TEST_ASSET_NAME}"),
            ],
            [
                format!("{other}  {TEST_ASSET_NAME}"),
                format!("{TEST_ASSET_HEX}  {TEST_ASSET_NAME}"),
            ],
        ] {
            let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
            assert!(parse_checksums(&body(&refs)).is_err());
        }
        assert!(
            parse_checksums(&body(&[
                &format!("{TEST_ASSET_HEX}  {TEST_ASSET_NAME}"),
                &format!("abc  {TEST_ASSET_NAME}"),
            ]))
            .is_err()
        );
    }

    /// Port of `TestParseChecksumsMalformed`
    /// (`checksums_test.go:157-181`).
    #[test]
    fn parse_checksums_malformed() {
        let bad: Vec<Vec<u8>> = vec![
            b"".to_vec(),
            format!("abc  {TEST_ASSET_NAME}\n").into_bytes(),
            format!("{TEST_ASSET_HEX}a  {TEST_ASSET_NAME}\n").into_bytes(),
            format!("{}  {TEST_ASSET_NAME}\n", "g".repeat(64)).into_bytes(),
            format!("  {TEST_ASSET_NAME}\n").into_bytes(),
            format!("-  {TEST_ASSET_NAME}\n").into_bytes(),
            format!("{TEST_ASSET_HEX}  \n").into_bytes(),
            format!("\\{TEST_ASSET_HEX}  {TEST_ASSET_NAME}\n").into_bytes(),
            {
                let mut v = format!("{TEST_ASSET_HEX}  {TEST_ASSET_NAME}").into_bytes();
                v.extend_from_slice(b"\x00x\n");
                v
            },
            {
                let mut v = vec![0xff, 0xfe];
                v.extend_from_slice(
                    format!("{TEST_ASSET_HEX}  {TEST_ASSET_NAME}\n").as_bytes(),
                );
                v
            },
            format!("{TEST_ASSET_HEX}  {TEST_ASSET_NAME}\ngarbage line without hash\n")
                .into_bytes(),
        ];
        for b in bad {
            assert!(parse_checksums(&b).is_err(), "body {b:?}");
        }
        let huge = vec![b'a'; MAX_CHECKSUMS_BYTES + 1];
        assert!(parse_checksums(&huge).is_err());
    }

    /// Port of `TestParseChecksumsExtraEntriesIgnored`
    /// (`checksums_test.go:183-198`).
    #[test]
    fn parse_checksums_extra_entries_ignored() {
        let other = hex::encode(Sha256::digest(b"other"));
        let m = parse_checksums(&body(&[
            &format!("{TEST_ASSET_HEX}  {TEST_ASSET_NAME}"),
            &format!("{other}  checksums.txt"),
            &format!("{other}  README.md"),
            &format!("{other}  evil.tar.gz"),
        ]))
        .unwrap();
        assert!(m.contains_key(TEST_ASSET_NAME));
    }

    /// Port of `TestParseChecksumsRealShape`
    /// (`checksums_test.go:200-223`): the live v0.9.0 shape
    /// (two spaces, text mode) measured on cue, Q2.
    #[test]
    fn parse_checksums_real_shape() {
        let asset = |name: &str, content: &str| -> String {
            format!("{}  {}", hex::encode(Sha256::digest(content)), name)
        };
        let m = parse_checksums(&body(&[
            &asset("castctl_0.6.4_linux_amd64.tar.gz", "amd64"),
            &asset("castctl_0.6.4_linux_amd64_no-plugin.tar.gz", "amd64np"),
            &asset("castctl_0.6.4_linux_arm64.tar.gz", "arm64"),
            &asset("castctl_0.6.4_linux_arm64_no-plugin.tar.gz", "arm64np"),
        ]))
        .unwrap();
        assert_eq!(m.len(), 4);
        let want = Sha256::digest(b"amd64");
        assert_eq!(m["castctl_0.6.4_linux_amd64.tar.gz"][..], want[..]);
    }

    /// The `*`-marker trap (R1 §4.1): a filename starting
    /// with `*` in text mode loses the `*`, exactly like Go.
    #[test]
    fn star_filename_loses_marker_like_go() {
        let m = parse_checksums(
            format!("{TEST_ASSET_HEX}  *foo\n").as_bytes(),
        )
        .unwrap();
        assert!(m.contains_key("foo"));
        assert!(!m.contains_key("*foo"));
    }
}
