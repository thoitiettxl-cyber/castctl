// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Embedded frontend shell (`webui/embed.go` + `server.go`
//! `serveShell`).
//!
//! The shell is the committed single-file frontend,
//! `webui/dist/index.html`, embedded verbatim via
//! `include_bytes!` — zero dependencies, byte-identical by
//! construction. `BundleSHA256` is computed from the same
//! bytes, never hardcoded. The shell is served
//! unauthenticated: it contains no secrets, and the login
//! page needs it to enter the token.
//!
//! Headers: `Content-Type: text/html; charset=utf-8`,
//! `Cache-Control: no-store`,
//! `X-Content-Type-Options: nosniff`. No Content-Length
//! is set here: Go's net/http sends bodies over its
//! 2048-byte sniff buffer chunked (see [`crate::server`]
//! `body_for_go_compat`), and the shell is 964 KiB.

use sha2::{Digest, Sha256};

/// The embedded frontend shell, byte-identical to
/// `webui/dist/index.html` at build time
/// (`//go:embed dist/index.html` in Go).
pub static SHELL_BYTES: &[u8] = include_bytes!("../../../webui/dist/index.html");

/// `BundleSHA256()`: the lowercase hex SHA-256 of the
/// embedded shell bytes.
pub fn bundle_sha256() -> String {
    sha256_hex(SHELL_BYTES)
}

/// SHA-256 of arbitrary bytes (the on-disk `index.html`
/// hash when `ui_dir` is active).
pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let sum = hasher.finalize();
    let mut out = String::with_capacity(64);
    for b in sum {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embed_is_byte_identical_to_dist() {
        // The embedded bytes must be exactly the file on
        // disk: a stale embed would serve a different shell
        // than the committed frontend.
        let on_disk = std::fs::read(
            concat!(env!("CARGO_MANIFEST_DIR"), "/../../webui/dist/index.html"),
        )
        .expect("webui/dist/index.html must exist");
        assert_eq!(SHELL_BYTES, on_disk.as_slice());
        assert_eq!(bundle_sha256(), sha256_hex(&on_disk));
    }

    #[test]
    fn bundle_hash_matches_measured_value() {
        // Measured 2026-11-05 on the committed file; a
        // mismatch means the dist changed and the embed
        // must be re-checked, not the hash re-pinned.
        assert_eq!(
            bundle_sha256(),
            "cd11d39afd03f48a8a96a576a03b2f2891963a1f56773ba2cf3745b4720c6cc7"
        );
    }
}
