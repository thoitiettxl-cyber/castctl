//! Fingerprint / TLS-engine recording: storage and data validation
//! only, no wiring (FINGERPRINT-HOLD).
//!
//! Source: `internal/profile/fingerprint.go` at base `dev-rust`
//! `85a8d5e`.

/// Default fingerprint preset when the key is absent.
///
/// Source: `internal/profile/fingerprint.go` (`DefaultFingerprint`).
pub const DEFAULT_FINGERPRINT: &str = "chrome";

/// Default TLS engine when the key is absent.
///
/// Source: `internal/profile/fingerprint.go` (`DefaultTLSEngine`).
pub const DEFAULT_TLS_ENGINE: &str = "utls";

/// Accepted `fingerprint` values, in Go order.
///
/// Source: `internal/profile/fingerprint.go` (`validFingerprints`).
pub const VALID_FINGERPRINTS: [&str; 4] = ["chrome", "firefox", "ios", "safari"];

/// Accepted `tls_engine` values, in Go order.
///
/// Source: `internal/profile/fingerprint.go` (`validTLSEngines`).
pub const VALID_TLS_ENGINES: [&str; 3] = ["cronet", "stdlib", "utls"];

/// Accepted `fingerprint` values, sorted (Go `SupportedFingerprints`
/// returns a clone of the fixed list, which is already sorted).
pub fn supported_fingerprints() -> Vec<&'static str> {
    VALID_FINGERPRINTS.to_vec()
}

/// Accepted `tls_engine` values (Go `SupportedTLSEngines`).
pub fn supported_tls_engines() -> Vec<&'static str> {
    VALID_TLS_ENGINES.to_vec()
}

/// `validateFingerprintValue` (`fingerprint.go`): exact match, no
/// case folding, no trimming. Returns the plain (unprefixed) error
/// text; callers wrap it with `profile %q: `.
pub fn validate_fingerprint_value(v: &str) -> Result<(), String> {
    if VALID_FINGERPRINTS.contains(&v) {
        Ok(())
    } else {
        Err(format!(
            "fingerprint must be one of {}",
            VALID_FINGERPRINTS.join(", ")
        ))
    }
}

/// `validateTLSEngineValue` (`fingerprint.go`): exact match only.
pub fn validate_tls_engine_value(v: &str) -> Result<(), String> {
    if VALID_TLS_ENGINES.contains(&v) {
        Ok(())
    } else {
        Err(format!(
            "tls_engine must be one of {}",
            VALID_TLS_ENGINES.join(", ")
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fingerprint_exact_match_only() {
        assert!(validate_fingerprint_value("chrome").is_ok());
        assert!(validate_fingerprint_value("Chrome").is_err());
        assert!(validate_fingerprint_value(" chrome").is_err());
        assert!(validate_fingerprint_value("random").is_err());
        assert_eq!(
            validate_fingerprint_value("x").unwrap_err(),
            "fingerprint must be one of chrome, firefox, ios, safari"
        );
    }

    #[test]
    fn test_tls_engine_exact_match_only() {
        assert!(validate_tls_engine_value("utls").is_ok());
        assert!(validate_tls_engine_value("UTLS").is_err());
        assert_eq!(
            validate_tls_engine_value("x").unwrap_err(),
            "tls_engine must be one of cronet, stdlib, utls"
        );
    }
}
