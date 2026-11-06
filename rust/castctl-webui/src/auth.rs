// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Bearer-token auth: bcrypt hash + verify.
//!
//! Source: `internal/profile/webui_secret.go`
//! (`HashWebUIToken`, `LooksLikeBcryptHash`,
//! `VerifyWebUIToken`, `webUITokenBytes`) and
//! `internal/webui/server.go` (`validateBearerToken`,
//! `refreshTokenHash`).
//!
//! Rules, verbatim:
//! - Hash cost is Go `bcrypt.DefaultCost` = **10**, never the
//!   crate's `DEFAULT_COST` (12): a cost-12 hash would still
//!   verify, but the stored bytes would differ from Go's and
//!   the parity harness compares stored-token prefixes.
//! - The 72-byte limit is on BYTES of the token (not chars).
//! - `LooksLikeBcryptHash`: length > 4 and a `$2a$` / `$2b$` /
//!   `$2y$` prefix.
//! - Verify errors (malformed hash, wrong token) are all
//!   `false`: a missing, malformed or wrong token produces
//!   the same fixed 401. There is no `PasswordTooLong` on
//!   the verify path — Go's `CompareHashAndPassword`
//!   truncates an over-72-byte password to its first 72
//!   bytes (x/crypto/bcrypt only ever reads 18 key words
//!   in `expandKeyWithSalt`), and the bcrypt crate's
//!   `verify` truncates identically. The 72-byte rejection
//!   lives in `hash_token` only, matching Go's
//!   `GenerateFromPassword`.
//! - The token is never logged or echoed; only the bcrypt
//!   hash is ever persisted.

/// Go `bcrypt.DefaultCost`.
pub const BCRYPT_COST: u32 = 10;

/// Maximum token length in bytes (Go `webUITokenBytes`).
pub const MAX_TOKEN_BYTES: usize = 72;

/// Sentinel for a kept secret value in request bodies and
/// redacted responses (`internal/redact/value.go` `Marker`).
pub const REDACTED_MARKER: &str = "<redacted>";

/// Placeholder accepted by `GET /settings/telegram`'s
/// `masked` field and rejected as a real token on PUT.
pub const MASKED_PLACEHOLDER: &str = "***";

/// Reports whether `hash` looks like a bcrypt hash: length >
/// 4 and a `$2a$` / `$2b$` / `$2y$` prefix
/// (`internal/profile/webui_secret.go` `LooksLikeBcryptHash`).
pub fn looks_like_bcrypt_hash(hash: &str) -> bool {
    hash.len() > 4
        && (hash.starts_with("$2a$") || hash.starts_with("$2b$") || hash.starts_with("$2y$"))
}

/// Hash a plaintext token with bcrypt cost 10. Returns an
/// error for an empty token or one over 72 bytes
/// (`HashWebUIToken`).
pub fn hash_token(token: &str) -> Result<String, String> {
    if token.is_empty() {
        return Err("token must not be empty".to_string());
    }
    if token.len() > MAX_TOKEN_BYTES {
        return Err("token is too long (max 72 bytes)".to_string());
    }
    bcrypt::hash(token, BCRYPT_COST).map_err(|e| e.to_string())
}

/// Verify a presented token against a stored hash. Every
/// failure — wrong token, malformed hash — is `false`
/// (`VerifyWebUIToken`). There is deliberately NO length
/// pre-check here: Go's `CompareHashAndPassword` truncates
/// a >72-byte password to its first 72 bytes, so a 73-byte
/// token whose first 72 bytes match verifies; the bcrypt
/// crate's `verify` truncates identically. The 72-byte
/// rejection lives in `hash_token` only, matching Go's
/// `GenerateFromPassword`.
pub fn verify_token(token: &str, hash: &str) -> bool {
    bcrypt::verify(token, hash).unwrap_or(false)
}

/// Validate an `Authorization` header the way Go's
/// `validateBearerToken` does: it must start exactly with
/// `"Bearer "`, the presented token must be non-empty and
/// contain no space, tab, CR or LF. Returns the presented
/// token, or `None` for a malformed header. (A well-formed
/// header with a wrong token still reaches `verify_token`
/// and fails there; both paths produce the same fixed 401.)
pub fn parse_bearer_header(header: &str) -> Option<&str> {
    let presented = header.strip_prefix("Bearer ")?;
    if presented.is_empty() || presented.contains([' ', '\t', '\r', '\n']) {
        return None;
    }
    Some(presented)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_and_verify_round_trip() {
        let hash = hash_token("test-token-123").expect("hash");
        assert!(looks_like_bcrypt_hash(&hash));
        assert!(verify_token("test-token-123", &hash));
        assert!(!verify_token("wrong-token", &hash));
        // Verify errors are false, never a panic or an error
        // that leaks into the response.
        assert!(!verify_token("test-token-123", "not-a-hash"));
        assert!(!verify_token("test-token-123", ""));
    }

    #[test]
    fn fail_before_cost_is_ten() {
        // Go hashes with DefaultCost 10. If this crate ever
        // hashes at the bcrypt crate's DEFAULT_COST (12),
        // the stored bytes differ from Go's — this pins 10.
        let hash = hash_token("cost-check").expect("hash");
        assert!(hash.starts_with("$2b$10$"), "hash was {hash}");
    }

    #[test]
    fn verify_truncates_over_72_bytes() {
        // F-A1: Go's CompareHashAndPassword truncates a
        // >72-byte password to its first 72 bytes, so a
        // 73-byte token whose first 72 bytes match verifies
        // (even when byte 73 differs); a token differing
        // inside the first 72 does not.
        let hash = hash_token(&"a".repeat(72)).expect("hash");
        assert!(verify_token(&"a".repeat(73), &hash));
        assert!(verify_token(&format!("{}b", "a".repeat(72)), &hash));
        assert!(!verify_token(&format!("b{}", "a".repeat(71)), &hash));
    }

    #[test]
    fn token_length_limit_is_bytes() {
        assert!(hash_token(&"a".repeat(72)).is_ok());
        assert!(hash_token(&"a".repeat(73)).is_err());
        // 72-byte limit on bytes, not chars: 25 three-byte
        // chars = 75 bytes -> too long.
        assert!(hash_token(&"€".repeat(25)).is_err());
        assert!(hash_token(&"€".repeat(24)).is_ok());
        assert!(hash_token("").is_err());
    }

    #[test]
    fn bearer_header_parsing() {
        assert_eq!(parse_bearer_header("Bearer abc"), Some("abc"));
        assert_eq!(parse_bearer_header("Bearer "), None);
        assert_eq!(parse_bearer_header("Bearer"), None);
        assert_eq!(parse_bearer_header("Basic abc"), None);
        assert_eq!(parse_bearer_header("Bearer a b"), None);
        assert_eq!(parse_bearer_header("Bearer a\tb"), None);
        assert_eq!(parse_bearer_header("bearer abc"), None);
    }

    #[test]
    fn looks_like_bcrypt_hash_shapes() {
        assert!(looks_like_bcrypt_hash("$2a$10$abcdefghijklmnopqrstuu"));
        assert!(looks_like_bcrypt_hash("$2b$10$abcdefghijklmnopqrstuu"));
        assert!(looks_like_bcrypt_hash("$2y$10$abcdefghijklmnopqrstuu"));
        assert!(!looks_like_bcrypt_hash("$2a$"));
        assert!(!looks_like_bcrypt_hash("plaintext"));
        assert!(!looks_like_bcrypt_hash(""));
    }
}
