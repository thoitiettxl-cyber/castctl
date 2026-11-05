// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Manifest + checksums verification for local-directory plugins.
//!
//! Go source: `internal/pluginhost/checksum.go` (all of it).
//!
//! NOTE: this manifest format DIFFERS from the update
//! flavour (`castctl-update/src/checksums.rs`): blank lines
//! and `#`-comments are skipped, a leading `*` on the name
//! is stripped, hex is lowercased, and names must be bare
//! base names (no `/`, `\`, `..`, absolute, or duplicates).
//! Verification happens at load time, on the SHADOW-COPY
//! bytes about to be loaded, when the caller supplies a
//! manifest path. Errors never embed the shadow path.

use std::collections::BTreeMap;
use std::path::Path;

use crate::error::PluginHostError;
use crate::paths::{open_plugin_source, refuse_symlinked_components};

/// Parse a checksums.txt body: one
/// `"<sha256-hex>  <name>"` per line, blank lines and
/// `#`-comments skipped, a leading `*` on the name
/// stripped (sha256sum `-b` form). Duplicate names,
/// absolute names, and names containing a path separator
/// or `..` are rejected.
/// Source: `ParseChecksums` (`checksum.go:48-82`).
pub fn parse_checksums(data: &[u8]) -> Result<BTreeMap<String, String>, PluginHostError> {
    let text = String::from_utf8_lossy(data);
    let mut out = BTreeMap::new();
    for (index, raw_line) in text.split('\n').enumerate() {
        let line_number = index + 1;
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 2 {
            return Err(PluginHostError::invalid(format!(
                "line {line_number}: invalid checksum entry"
            )));
        }
        let hash = fields[0].trim().to_ascii_lowercase();
        if hash.len() != 64 {
            return Err(PluginHostError::invalid(format!(
                "line {line_number}: invalid sha256 length"
            )));
        }
        if hex::decode(&hash).is_err() {
            return Err(PluginHostError::invalid(format!(
                "line {line_number}: invalid sha256"
            )));
        }
        let name = fields[1]
            .trim()
            .strip_prefix('*')
            .unwrap_or(fields[1].trim());
        if let Err(e) = validate_manifest_name(name) {
            return Err(PluginHostError::invalid(format!("line {line_number}: {e}")));
        }
        if out.contains_key(name) {
            return Err(PluginHostError::invalid(format!(
                "line {line_number}: duplicate checksum entry for {name:?}"
            )));
        }
        out.insert(name.to_string(), hash);
    }
    Ok(out)
}

/// A manifest entry names exactly one base name in the
/// plugin directory.
/// Source: `validateManifestName` (`checksum.go:84-95`).
pub fn validate_manifest_name(name: &str) -> Result<(), PluginHostError> {
    if name.is_empty() || name == "." || name == ".." {
        return Err(PluginHostError::invalid(format!(
            "invalid checksum name {name:?}"
        )));
    }
    if Path::new(name).is_absolute() || name.contains(['/', '\\']) || name.contains("..") {
        return Err(PluginHostError::invalid(format!(
            "invalid checksum name {name:?}"
        )));
    }
    if Path::new(name)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        != Some(name.to_string())
    {
        return Err(PluginHostError::invalid(format!(
            "invalid checksum name {name:?}"
        )));
    }
    Ok(())
}

/// Check `data` against the manifest entry for `name`.
/// A missing entry and a mismatch are both errors naming
/// the file only, never a hash value.
/// Source: `VerifyChecksum` (`checksum.go:100-110`).
pub fn verify_checksum(
    name: &str,
    data: &[u8],
    checksums: &BTreeMap<String, String>,
) -> Result<(), PluginHostError> {
    let expected = checksums
        .get(name)
        .map(|s| s.trim().to_ascii_lowercase())
        .unwrap_or_default();
    if expected.is_empty() {
        return Err(PluginHostError::invalid(format!(
            "checksum for {name} not found"
        )));
    }
    use sha2::{Digest, Sha256};
    let actual = hex::encode(Sha256::digest(data));
    if actual != expected {
        return Err(PluginHostError::invalid(format!(
            "checksum mismatch for {name}"
        )));
    }
    Ok(())
}

/// Verify the plugin file at `plugin_path` against the
/// checksums.txt manifest at `manifest_path`. The manifest
/// entry is looked up by the plugin file's base name.
/// Both files are opened refusing symlinks (final
/// component and every path component): the symlink
/// refusal fires BEFORE the missing-entry error.
/// Source: `VerifyFileChecksum` (`checksum.go:119-139`).
pub fn verify_file_checksum(
    plugin_path: &Path,
    manifest_path: &Path,
) -> Result<(), PluginHostError> {
    refuse_symlinked_components(plugin_path)?;
    refuse_symlinked_components(manifest_path)?;
    let data = read_regular_file(plugin_path)?;
    let manifest = read_regular_file(manifest_path)
        .map_err(|_| PluginHostError::failed("read plugin checksums manifest"))?;
    let checksums = parse_checksums(&manifest)?;
    let name = plugin_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    verify_checksum(&name, &data, &checksums)
}

/// Verify the shadow-copy bytes at `shadow_path` against
/// the checksums.txt manifest at `manifest_path`, looking
/// the entry up by `entry_name` (the base name of the
/// original plugin file — the shadow file's own name is
/// content-derived and never appears in a manifest). The
/// shadow file is hashed through a single open
/// (`O_NOFOLLOW`) with a regular-file re-check. A
/// residual window remains between this verification and
/// load (no fd pin); see docs/plugins.md "Known limits" (U1).
/// Source: `VerifyShadowFileChecksum` (`checksum.go:148-180`).
pub fn verify_shadow_file_checksum(
    shadow_path: &Path,
    manifest_path: &Path,
    entry_name: &str,
) -> Result<(), PluginHostError> {
    validate_manifest_name(entry_name)?;
    refuse_symlinked_components(manifest_path)?;
    let manifest = read_regular_file(manifest_path)
        .map_err(|_| PluginHostError::failed("read plugin checksums manifest"))?;
    let checksums = parse_checksums(&manifest)?;
    let expected = checksums
        .get(entry_name)
        .map(|s| s.trim().to_ascii_lowercase())
        .unwrap_or_default();
    if expected.is_empty() {
        return Err(PluginHostError::invalid(format!(
            "checksum for {entry_name} not found"
        )));
    }
    let mut f = open_plugin_source(shadow_path).map_err(|e| {
        // `openErrorWithoutPath`: the error must not carry
        // the shadow path (`compat.go:24-30`).
        PluginHostError::failed(format!("open plugin shadow file: {e}"))
    })?;
    let info = f
        .metadata()
        .map_err(|_| PluginHostError::invalid("plugin shadow file is not a regular file"))?;
    if !info.is_file() {
        return Err(PluginHostError::invalid(
            "plugin shadow file is not a regular file",
        ));
    }
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    {
        use std::io::Read;
        let mut chunk = [0u8; 32 << 10];
        loop {
            match f.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => hasher.update(&chunk[..n]),
                Err(_) => {
                    return Err(PluginHostError::failed("hash plugin shadow file"));
                }
            }
        }
    }
    if hex::encode(hasher.finalize()) != expected {
        return Err(PluginHostError::invalid(format!(
            "checksum mismatch for {entry_name}"
        )));
    }
    Ok(())
}

/// Read a whole file through an open with a
/// regular-file re-check (`O_NOFOLLOW`), refusing symlinks.
/// Source: `readRegularFile` (`checksum.go:183-193`).
fn read_regular_file(path: &Path) -> Result<Vec<u8>, PluginHostError> {
    let mut f = open_plugin_source(path)
        .map_err(|e| PluginHostError::failed(format!("cannot open file: {e}")))?;
    let info = f
        .metadata()
        .map_err(|_| PluginHostError::invalid(format!("file {path:?} is not a regular file")))?;
    if !info.is_file() {
        return Err(PluginHostError::invalid(format!(
            "file {path:?} is not a regular file"
        )));
    }
    use std::io::Read;
    let mut data = Vec::new();
    f.read_to_end(&mut data)
        .map_err(|e| PluginHostError::failed(format!("cannot read file: {e}")))?;
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::path::PathBuf;

    fn write_manifest(dir: &Path, name: &str, data: &[u8]) -> PathBuf {
        let sum = hex::encode(Sha256::digest(data));
        let manifest = dir.join("checksums.txt");
        std::fs::write(&manifest, format!("{sum}  {name}\n")).unwrap();
        manifest
    }

    /// Port of `TestParseChecksumsRejectsDuplicatesAndTraversal`
    /// (`checksum_test.go:25-42`).
    #[test]
    fn parse_checksums_rejects_duplicates_and_traversal() {
        let sum = "a".repeat(64);
        for manifest in [
            format!("{sum}  echo.so\n{sum}  echo.so\n"),
            format!("{sum}  ../evil.so\n"),
            format!("{sum}  /abs/evil.so\n"),
            format!("{sum}  sub/echo.so\n"),
        ] {
            assert!(parse_checksums(manifest.as_bytes()).is_err(), "{manifest}");
        }
        assert!(parse_checksums(format!("{sum}  echo.so\n").as_bytes()).is_ok());
        // Blank lines, comments, `*` marker, uppercase hex.
        let mixed = format!("# comment\n\n{}  *echo.so\n", sum.to_uppercase());
        let m = parse_checksums(mixed.as_bytes()).unwrap();
        assert!(m.contains_key("echo.so"));
    }

    /// Port of `TestVerifyShadowFileChecksumTamperAndSymlink`
    /// (`checksum_test.go:44-78`).
    #[test]
    fn verify_shadow_file_checksum_tamper_and_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let data = b"shadow-bytes-v1";
        let shadow = dir.path().join("castctl-plugin-echo-abc.so");
        std::fs::write(&shadow, data).unwrap();
        let manifest = write_manifest(dir.path(), "echo.so", data);
        assert!(verify_shadow_file_checksum(&shadow, &manifest, "echo.so").is_ok());
        std::fs::write(&shadow, b"shadow-bytes-v2").unwrap();
        let err = verify_shadow_file_checksum(&shadow, &manifest, "echo.so").unwrap_err();
        assert!(err.to_string().contains("mismatch"));
        // A symlinked shadow path is refused.
        let real = dir.path().join("real.so");
        std::fs::write(&real, data).unwrap();
        let link = dir.path().join("link.so");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(verify_shadow_file_checksum(&link, &manifest, "echo.so").is_err());
    }

    /// Port of `TestVerifyFileChecksumRefusesSymlink`
    /// (`checksum_test.go:80-101`): the symlink refusal
    /// fires first, before the missing-entry error.
    #[test]
    fn verify_file_checksum_refuses_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let data = b"plugin-bytes";
        let real = dir.path().join("echo.so");
        std::fs::write(&real, data).unwrap();
        let manifest = write_manifest(dir.path(), "echo.so", data);
        assert!(verify_file_checksum(&real, &manifest).is_ok());
        let link = dir.path().join("via.so");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let err = verify_file_checksum(&link, &manifest).unwrap_err();
        assert!(
            err.to_string().contains("symlink"),
            "got: {}",
            err.to_string()
        );
    }

    /// Port of `TestVerifyShadowFileChecksumNoShadowPathLeak`
    /// (`checksum_test.go:103-130`).
    #[test]
    fn verify_shadow_file_checksum_no_shadow_path_leak() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = write_manifest(dir.path(), "echo.so", b"shadow-bytes");
        let shadow = dir
            .path()
            .join("castctl-pluginhost")
            .join("pid-424242")
            .join("castctl-plugin-echo-abc.so");
        let err = verify_shadow_file_checksum(&shadow, &manifest, "echo.so").unwrap_err();
        assert!(!err.to_string().contains("pid-424242"));
        assert!(!err.to_string().contains("castctl-pluginhost"));
        // Non-regular shadow file (a directory): same rule.
        let shadow_dir = dir
            .path()
            .join("castctl-pluginhost")
            .join("pid-424243")
            .join("castctl-plugin-echo-def.so");
        std::fs::create_dir_all(&shadow_dir).unwrap();
        let err = verify_shadow_file_checksum(&shadow_dir, &manifest, "echo.so").unwrap_err();
        assert!(!err.to_string().contains("pid-424243"));
        assert!(!err.to_string().contains("castctl-pluginhost"));
    }
}
