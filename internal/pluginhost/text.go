// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package pluginhost

import (
	"strings"
	"unicode/utf8"

	"github.com/thoitiettxl-cyber/castctl/internal/logging"
)

// maxPluginTextLen is THE cap for plugin-chosen text that
// reaches output: envelope error messages, loader error
// strings, skip reasons, host.log messages, and plugin
// check output. Every surface truncates at the same length
// through safePluginText, with an explicit "…" marker. A
// plugin returning a 5 MB payload can therefore never make
// host output 5 MB.
const maxPluginTextLen = 4096

// maxHostMethodLen bounds the host-callback method name a
// plugin passes to the host (the C ABI carries no length
// for it). A method with no NUL within this bound is
// rejected instead of being read unbounded (which could
// segfault the host on an unterminated pointer).
const maxHostMethodLen = 256

// truncateRunes cuts s at the largest rune boundary at or
// below max bytes, in O(1): it backs up at most 3 bytes
// from max to a rune start. It never scans the whole
// string, so truncating a 50 MB input costs nothing.
// Input is assumed valid UTF-8 (all plugin-text surfaces
// here are JSON-decoded strings): on invalid input the
// backup can cut mid-sequence, leaving a partial rune in
// display-only output.
func truncateRunes(s string, max int) string {
	if max <= 0 {
		return ""
	}
	if len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && cut > max-4 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

// capPluginText truncates s to maxPluginTextLen bytes at
// a rune boundary, with an explicit marker. It never
// invents content: over-long text is cut, not summarised.
func capPluginText(s string) string {
	if len(s) > maxPluginTextLen {
		return truncateRunes(s, maxPluginTextLen) + "…"
	}
	return s
}

// redactClosers close a possibly-open quoted value after a
// cap cut, so the redaction scanner sees a terminated value
// and replaces it instead of writing the cut remainder
// verbatim (its unterminated-value branch). All four forms
// are needed: double-quoted, single-quoted, and %q-escaped
// pairs in both quote styles. Measured with a probe over
// the logging scanner: `""` alone leaks single-quoted and
// escaped values cut at the cap; the full sequence redacts
// every cut form. A stray closer remnant may survive in the
// output of hostile payloads; it is display-only quote
// bytes, never a secret value.
const redactClosers = `""''\"\"\'\'`

// capBeforeRedact truncates s to max bytes at a rune
// boundary and, only when truncated, appends redactClosers
// so a secret value straddling the cut is still redacted.
// Short inputs pass through unchanged: the closers are a
// cap-cut repair, not a general scanner fix.
func capBeforeRedact(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return truncateRunes(s, max) + redactClosers
}

// safePluginText redacts plugin-chosen free-form text for
// output (SafeString strips secret-keyed shapes, cookie
// fragments, Bearer tokens, and URL userinfo) and caps it
// at maxPluginTextLen. The cap runs BEFORE redaction:
// SafeString's cost is superlinear (measured: 64 KB ~178 ms,
// 5 MB killed after ~4 minutes), so redacting first would
// let a plugin stall the host. Every loader/host/plugin-check
// error path that can carry plugin text goes through it.
func safePluginText(s string) string {
	return capPluginText(logging.SafeString(capBeforeRedact(s, maxPluginTextLen)))
}

// StripControlChars is THE single sanitizer for
// plugin-chosen text that reaches output, shared by every
// output path (host.log messages, envelope error text,
// skip reasons, the loader's non-envelope error path, and
// `plugin check` output via this exported function).
// It works on decoded runes: newline/CR/tab become a
// space and all other C0 controls, DEL, and C1 controls
// (U+0080-U+009F) are dropped, so plugin-chosen text can
// never forge a second output line or inject terminal
// control sequences. An ESC that starts a CSI sequence
// (ESC [ ... final byte) drops the whole sequence, as
// does a C1 CSI sequence (U+009B ... final byte): only
// stripping the introducer would leave a "[31m" remnant
// in the output. A bare ESC, or a bare C1 control with
// no CSI following it, is dropped alone. Invalid UTF-8
// bytes decode to U+FFFD and are re-encoded as such, so
// a raw 0x80-0x9F byte can never survive as a raw byte.
// Shared by host.log messages, envelope error text (see
// dispatchHostCall, parseEnvelope), and skip reasons
// (see shortErr).
func StripControlChars(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for len(s) > 0 {
		r, size := utf8.DecodeRuneInString(s)
		escCSI := r == 0x1b && len(s) > size && s[size] == '['
		if escCSI || r == 0x9b {
			// Skip the CSI sequence through its final
			// byte (0x40-0x7e); an unterminated sequence
			// drops to end of input.
			if escCSI {
				s = s[size+1:]
			} else {
				s = s[size:]
			}
			for len(s) > 0 && !(s[0] >= 0x40 && s[0] <= 0x7e) {
				_, n := utf8.DecodeRuneInString(s)
				s = s[n:]
			}
			if len(s) > 0 {
				_, n := utf8.DecodeRuneInString(s)
				s = s[n:]
			}
			continue
		}
		switch r {
		case '\n', '\r', '\t':
			b.WriteRune(' ')
		default:
			if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
				// Dropped: other C0 controls, DEL, C1
				// controls, and a bare ESC.
			} else {
				b.WriteRune(r)
			}
		}
		s = s[size:]
	}
	return b.String()
}

// scrubShadowPath replaces occurrences of the shadow path
// in loader error text with the operator-supplied source
// path, so user-facing errors never leak the shadow
// directory layout or pid.
func scrubShadowPath(text, shadowPath, displayPath string) string {
	if shadowPath == "" || displayPath == "" || shadowPath == displayPath {
		return text
	}
	return strings.ReplaceAll(text, shadowPath, displayPath)
}
