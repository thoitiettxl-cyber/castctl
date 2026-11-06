// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Plugin-chosen text sanitising: cap-before-redact,
//! control-character stripping, and the single shared
//! plugin-call error construction.
//!
//! Go source: `internal/pluginhost/text.go` (all of it).
//!
//! `maxPluginTextLen` (4096) is THE cap for
//! plugin-chosen text that reaches output: envelope
//! error messages, loader error strings, skip reasons,
//! host.log messages, and plugin check output. The cap
//! runs BEFORE redaction: `SafeString`'s cost is
//! superlinear (measured in Go: 64 KB ~178 ms, 5 MB
//! killed after ~4 minutes), so redacting first would
//! let a plugin stall the host.

use crate::error::PluginHostError;

/// THE cap for plugin-chosen text that reaches output.
/// Source: `maxPluginTextLen` (`text.go:17`).
pub const MAX_PLUGIN_TEXT_LEN: usize = 4096;
/// Bound for a host-callback method name (the C ABI
/// carries no length for it).
/// Source: `maxHostMethodLen` (`text.go:24`).
pub const MAX_HOST_METHOD_LEN: usize = 256;

/// Cut `s` at the largest rune boundary at or below
/// `max` bytes, in O(1): it backs up at most 3 bytes
/// from `max` to a rune start. It never scans the whole
/// string, so truncating a 50 MB input costs nothing.
/// Source: `truncateRunes` (`text.go:34-46`).
#[must_use]
pub fn truncate_runes(s: &str, max: usize) -> &str {
    if max == 0 {
        return "";
    }
    if s.len() <= max {
        return s;
    }
    let mut cut = max;
    while cut > 0 && cut > max.saturating_sub(4) && !s.is_char_boundary(cut) {
        cut -= 1;
    }
    &s[..cut]
}

/// Truncate `s` to `MAX_PLUGIN_TEXT_LEN` bytes at a rune
/// boundary, with an explicit marker. It never invents
/// content: over-long text is cut, not summarised.
/// Source: `capPluginText` (`text.go:52-58`).
#[must_use]
pub fn cap_plugin_text(s: &str) -> String {
    if s.len() > MAX_PLUGIN_TEXT_LEN {
        format!("{}…", truncate_runes(s, MAX_PLUGIN_TEXT_LEN))
    } else {
        s.to_string()
    }
}

/// Closers appended after a cap cut so the redaction
/// scanner sees a terminated value and replaces it
/// instead of writing the cut remainder verbatim.
/// Source: `redactClosers` (`text.go:71`).
const REDACT_CLOSERS: &str = "\"\"''\\\"\\\"\\'\\'";

/// Truncate `s` to `max` bytes at a rune boundary and,
/// only when truncated, append `REDACT_CLOSERS` so a
/// secret value straddling the cut is still redacted.
/// Short inputs pass through unchanged.
/// Source: `capBeforeRedact` (`text.go:79-85`).
#[must_use]
pub fn cap_before_redact(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    format!("{}{}", truncate_runes(s, max), REDACT_CLOSERS)
}

/// Redact plugin-chosen free-form text for output and
/// cap it at `MAX_PLUGIN_TEXT_LEN`. The cap runs BEFORE
/// redaction (see the module docs).
/// Source: `safePluginText` (`text.go:94-96`).
#[must_use]
pub fn safe_plugin_text(s: &str) -> String {
    cap_plugin_text(&castctl_log_redact::safe_string(&cap_before_redact(
        s,
        MAX_PLUGIN_TEXT_LEN,
    )))
}

/// Decode one rune from the front of `b`, Go
/// `utf8.DecodeRuneInString` semantics: an invalid or
/// truncated sequence decodes to U+FFFD consuming 1 byte.
/// `pub(crate)` so `compat::go_quote_bytes` can share
/// the exact rule instead of re-implementing it.
#[must_use]
pub(crate) fn decode_rune(b: &[u8]) -> (char, usize) {
    if b.is_empty() {
        return ('\u{FFFD}', 0);
    }
    for len in 1..=4.min(b.len()) {
        if let Ok(s) = std::str::from_utf8(&b[..len])
            && let Some(c) = s.chars().next()
            && c.len_utf8() == len
        {
            return (c, len);
        }
    }
    ('\u{FFFD}', 1)
}

/// THE single sanitizer for plugin-chosen text that
/// reaches output. Newline/CR/tab become a space and
/// all other C0 controls, DEL, and C1 controls
/// (U+0080–U+009F) are dropped, so plugin-chosen text
/// can never forge a second output line or inject
/// terminal control sequences. An ESC that starts a CSI
/// sequence (ESC `[` ... final byte) drops the whole
/// sequence, as does a C1 CSI sequence (U+009B ...
/// final byte). A bare ESC, or a bare C1 control with
/// no CSI following it, is dropped alone. Invalid UTF-8
/// bytes decode to U+FFFD and are re-encoded as such, so
/// a raw 0x80–0x9F byte can never survive as a raw byte.
/// Source: `StripControlChars` (`text.go:124-169`).
#[must_use]
pub fn strip_control_chars_bytes(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len());
    let mut s = input;
    while !s.is_empty() {
        let (r, size) = decode_rune(s);
        let esc_csi = r == '\u{1b}' && s.len() > size && s[size] == b'[';
        if esc_csi || r == '\u{9b}' {
            // Skip the CSI sequence through its final
            // byte (0x40-0x7e); an unterminated sequence
            // drops to end of input.
            if esc_csi {
                s = &s[size + 1..];
            } else {
                s = &s[size..];
            }
            while !s.is_empty() && !(0x40..=0x7e).contains(&s[0]) {
                let (_, n) = decode_rune(s);
                s = &s[n..];
            }
            if !s.is_empty() {
                let (_, n) = decode_rune(s);
                s = &s[n..];
            }
            continue;
        }
        match r {
            '\n' | '\r' | '\t' => out.push(' '),
            _ => {
                if r < '\u{20}' || r == '\u{7f}' || ('\u{80}'..='\u{9f}').contains(&r) {
                    // Dropped: other C0 controls, DEL, C1
                    // controls, and a bare ESC.
                } else {
                    out.push(r);
                }
            }
        }
        s = &s[size..];
    }
    out
}

/// `strip_control_chars_bytes` over a valid UTF-8 string.
#[must_use]
pub fn strip_control_chars(s: &str) -> String {
    strip_control_chars_bytes(s.as_bytes())
}

/// The error for a plugin call that returned a non-zero
/// rc with non-envelope bytes: THE single error
/// construction shared by the unix and windows loaders.
/// The raw bytes go through the single sanitizer and
/// the cap/redact path, so no C0/C1/DEL/ESC byte can
/// reach output and the error stays one line.
/// Source: `pluginCallError` (`text.go:114-118`).
#[must_use]
pub fn plugin_call_error(method: &str, rc: i32, out: &[u8]) -> PluginHostError {
    PluginHostError::failed(format!(
        "plugin call {method} returned {rc}: {}",
        safe_plugin_text(&strip_control_chars_bytes(out))
    ))
}

/// Replace occurrences of the shadow path in loader
/// error text with the operator-supplied source path,
/// so user-facing errors never leak the shadow directory
/// layout or pid.
/// Source: `scrubShadowPath` (`text.go:173-179`).
#[must_use]
pub fn scrub_shadow_path(text: &str, shadow_path: &str, display_path: &str) -> String {
    if shadow_path.is_empty() || display_path.is_empty() || shadow_path == display_path {
        return text.to_string();
    }
    text.replace(shadow_path, display_path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    /// Port of `TestSafePluginTextCapBeforeRedact`
    /// (`text_test.go:12-62`).
    #[test]
    fn safe_plugin_text_cap_before_redact() {
        let secret = "SECRET-VALUE-1234567890";
        let pad = |n: usize| "p".repeat(n);
        let cases = [
            format!("{{\"api_key\":\"{secret}\"}}"),
            format!("{{'api_key':'{secret}'}}"),
            format!("{{\"api_key\":\"ab\\{secret}\"}}"),
            format!("\\\"api_key\\\": \\\"{secret}\\\""),
        ];
        for (i, body) in cases.iter().enumerate() {
            // Pad BEFORE the pair so the pair itself
            // straddles the 4096 cap.
            let s = pad(MAX_PLUGIN_TEXT_LEN - 8) + body;
            let got = safe_plugin_text(&s);
            assert!(
                !got.contains(secret) && !got.contains("SECRET-VALUE"),
                "case {i} leaked straddling secret: {got:?}"
            );
            assert!(
                got.len() <= MAX_PLUGIN_TEXT_LEN + "…".len(),
                "case {i} len = {}, want <= {}",
                got.len(),
                MAX_PLUGIN_TEXT_LEN + "…".len()
            );
            assert!(got.ends_with('…'), "case {i} missing cap marker: {got:?}");
        }
        // Small inputs are unchanged (redaction still applies).
        let got = safe_plugin_text("{\"api_key\":\"abc123\"}");
        assert!(!got.contains("abc123"), "small input leaked: {got:?}");
        assert_eq!(safe_plugin_text("plain ok"), "plain ok");
        // Rune-safe: a multi-byte rune straddling the cap
        // is not split, and the result is valid UTF-8.
        let s = "é".repeat(3000); // 6000 bytes
        let got = safe_plugin_text(&s);
        assert!(got.ends_with('…'), "multi-byte input missing marker");
    }

    /// Port of `TestSafePluginTextLargeInputBounded`
    /// (`text_test.go:64-86`): 5 MB and 50 MB inputs
    /// through the capped path must finish in seconds
    /// with <=4096+marker output. This also measures the
    /// `safe_string` cost on cue (R3 §2.15).
    #[test]
    fn safe_plugin_text_large_input_bounded() {
        let secret = "SECRET-VALUE-1234567890";
        for size in [5usize << 20, 50usize << 20] {
            let s = format!(
                "{{\"api_key\":\"{secret}\",\"pad\":\"{}\"}}",
                "x".repeat(size)
            );
            let start = Instant::now();
            let got = safe_plugin_text(&s);
            let elapsed = start.elapsed();
            assert!(
                elapsed.as_secs() < 5,
                "size {size} took {elapsed:?}, want < 5s"
            );
            assert!(
                got.len() <= MAX_PLUGIN_TEXT_LEN + "…".len(),
                "size {size} outlen = {}, want <= {}",
                got.len(),
                MAX_PLUGIN_TEXT_LEN + "…".len()
            );
            assert!(!got.contains(secret), "size {size} leaked secret");
        }
    }

    /// Port of `TestStripControlCharsDropsC1Controls`
    /// (`text_test.go:88-105`).
    #[test]
    fn strip_control_chars_drops_c1_controls() {
        let input = "a\u{80}b\u{85}c\u{9b}31md\u{9c}e";
        let got = strip_control_chars(input);
        for r in got.chars() {
            assert!(
                !(('\u{80}'..='\u{9f}').contains(&r)),
                "kept C1 control U+{:04X}: {got:?}",
                r as u32
            );
        }
        assert!(!got.contains(['\n', '\r', '\u{1b}']));
        assert!(!got.contains("[31m"));
        assert_eq!(got, "abcde");
    }

    /// Port of `TestPluginCallErrorStripsExactC1ByteSequences`
    /// (`text_test.go:107-141`).
    #[test]
    fn plugin_call_error_strips_exact_c1_byte_sequences() {
        let csi_seq: &[u8] = &[0xc2, 0x9b, 0x5b, 0x33, 0x31, 0x6d];
        let nel_seq: &[u8] = &[0xc2, 0x85];
        let mut raw = b"raw boom ".to_vec();
        raw.extend_from_slice(csi_seq);
        raw.extend_from_slice(b"RED");
        raw.extend_from_slice(nel_seq);
        raw.extend_from_slice(b"TAIL\nFORGED\x1b[31m\x7f\x01END");
        let err = plugin_call_error("provider.call", 1, &raw);
        let got = err.to_string();
        assert!(!got.as_bytes().windows(csi_seq.len()).any(|w| w == csi_seq));
        assert!(!got.as_bytes().windows(nel_seq.len()).any(|w| w == nel_seq));
        for r in got.chars() {
            assert!(
                !(r < '\u{20}' || r == '\u{7f}' || ('\u{80}'..='\u{9f}').contains(&r)),
                "kept control U+{:04X}: {got:?}",
                r as u32
            );
        }
        assert!(!got.contains(['\n', '\r', '\u{1b}']));
        assert!(!got.contains("[31m"));
        assert_eq!(
            got,
            "plugin call provider.call returned 1: raw boom 31mREDTAIL FORGEDEND"
        );
    }

    /// Port of `TestCapPluginTextRuneSafe`
    /// (`text_test.go:143-155`).
    #[test]
    fn cap_plugin_text_rune_safe() {
        let s = "é".repeat(3000);
        let got = cap_plugin_text(&s);
        assert!(got.ends_with('…'), "cap missing marker: len={}", got.len());
        assert_eq!(cap_plugin_text("short"), "short");
    }

    /// Port of `TestStripControlCharsExactC1ByteSequences`
    /// (`text_test.go:157-196`).
    #[test]
    fn strip_control_chars_exact_c1_byte_sequences() {
        let csi_seq: &[u8] = &[0xc2, 0x9b, 0x5b, 0x33, 0x31, 0x6d];
        let nel_seq: &[u8] = &[0xc2, 0x85];
        let mut input = b"raw boom ".to_vec();
        input.extend_from_slice(csi_seq);
        input.extend_from_slice(b"RED");
        input.extend_from_slice(nel_seq);
        input.extend_from_slice(b"TAIL");
        let got = strip_control_chars_bytes(&input);
        assert!(!got.as_bytes().windows(csi_seq.len()).any(|w| w == csi_seq));
        assert!(!got.as_bytes().windows(nel_seq.len()).any(|w| w == nel_seq));
        for r in got.chars() {
            assert!(
                !(('\u{80}'..='\u{9f}').contains(&r)),
                "kept C1 control U+{:04X}: {got:?}",
                r as u32
            );
        }
        assert!(!got.contains("[31m"));
        // CSI grammar: '[' (0x5b) is the final byte of
        // the U+009B CSI sequence, so it is consumed and
        // the remaining "31m" is inert plain text.
        assert_eq!(got, "raw boom 31mREDTAIL");
        assert_eq!(strip_control_chars("a\u{85}b"), "ab");
        // Raw (invalid UTF-8) 0x9b / 0x85 bytes must be
        // replaced, never survive as raw bytes.
        let raw: &[u8] = &[b'x', 0x9b, b'y', 0x85, b'z'];
        let got = strip_control_chars_bytes(raw);
        assert!(!got.as_bytes().contains(&0x9b));
        assert!(!got.as_bytes().contains(&0x85));
        assert_eq!(got, "x\u{FFFD}y\u{FFFD}z");
    }
}
