// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

// Package logging owns castctl's single log-filtering path: one
// resolved level governs both sing-box factory logs and castctl's
// own slog-bridged lines, and every castctl log field passes the
// redaction boundary in this package before it is emitted.
//
// Redaction model (load-bearing, read before adding a log line):
// secret-bearing fields are excluded BY CONSTRUCTION from every log
// emission — no log line ever carries a full URL, a header value, a
// cookie/token, an outbound Options value, or a config hash. The
// boundary functions here are defence in depth for free-form text
// (notably error strings) that may embed such material, not the
// primary control. SafeString is deliberately STRICTER than
// redact.String: redact.String leaves a vm_id query value, a JSON
// {"password": ...} fragment, an unknown query key, and a bare
// key=value fragment byte-identical (documented boundary in
// internal/redact/string.go), because error strings have no
// key/value structure to trust. Log lines DO have that structure —
// the caller chose the fields — so the logging boundary may strip
// every query value and every secret-keyed JSON value it finds.
// redact.String itself is not changed: gateway tests pin vm_id
// surviving it.
//
// What SafeString cannot do: strip a BARE secret with no label (a
// lone WireGuard key, a lone header value, a lone token). No
// pattern distinguishes such a value from ordinary text. Callers
// must never place one in a log field; the capture-matrix tests
// prove the exclusion on every emission path.
//
// WireGuard public keys are the one labelled exception to
// full redaction: a `public_key` value is shortened to its FIRST
// 8 CHARS (plus an ellipsis), never logged in full — the peer
// identity a log line may carry is a prefix only. A
// `private_key` value is always fully redacted, as is a
// `preshared_key` value. The sing-box device logger's own
// abbreviated peer form, `peer(ABCD…WXYZ)`, is shortened the
// same way: the suffix half is stripped, leaving the first
// four characters plus the ellipsis (wireguard-go
// device/peer.go:198 String).
package logging

import (
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/thoitiettxl-cyber/castctl/internal/redact"
)

// reURL matches a URL-like substring (scheme://...) up to the next
// whitespace or quote. Every query value inside such a substring is
// replaced with [redacted], whatever the key: unlike redact.String's
// five named keys, the logging boundary trusts no query key.
var reURL = regexp.MustCompile(`[a-zA-Z][a-zA-Z0-9+.-]*://[^\s"']+`)

// secretKeyVocab is the substring vocabulary for secret-looking
// keys in JSON forms (double- and single-quoted). It covers
// snake_case and camelCase spellings alike: a server that
// answers {"privateKey": ...} is the same leak as one that
// answers {"private_key": ...}.
const secretKeyVocab = `password|token|secret|private_key|public_key|privateKey|publicKey|cookie|auth|vm_id|node_id|credential|passwd|apiKey|secretKey|sessionKey|clientSecret`

// redactJSONSecrets is the ONE mechanism that strips
// secret-keyed JSON values in free-form text, for every
// key/value quote combination (double/double,
// single/single, double/single, single/double). Two regexes
// used to cover three of the four combinations and drifted
// apart (the double-key/single-value form survived); Go's RE2
// has no backreferences, so a quote-matching regex cannot
// express "the value ends at its own closing quote" for all
// four combinations without also stopping early at an
// apostrophe inside a value. The scanner below parses one
// quoted key, the colon, and one value (quoted string or
// JSON scalar) with escape-aware quote matching, so a value
// containing the other quote type is stripped in full. The
// key match is a substring match over the secret vocabulary
// (password, token, secret, key, cookie, auth, vm_id, node_id,
// credential, passwd, plus camelCase forms), deliberately
// broader than redact.Value's exact-key rule: this runs on
// unstructured text where a key may carry a prefix or suffix,
// and over-redacting a log line is safe while leaking one is
// not. Non-secret values are left byte-identical. A key whose
// secret word is spelled with \u escapes ({"tok\u0065n": ...})
// or %XX escapes is recognised: escapes are decoded before
// the vocabulary match (the original key text is preserved in
// the output). A secret-keyed value that is a JSON scalar
// (number, boolean, null) is redacted like a string value;
// a composite value (object/array) is not redacted as a whole
// — the scanner recurses into it, so nested secret pairs
// inside it are still stripped.
var reSecretKeyVocab = regexp.MustCompile(`(?i)(?:` + secretKeyVocab + `)`)

// reJSONScalar matches a JSON number (integer, float, exponent,
// negative) for the scalar-value rule in redactJSONSecrets.
var reJSONScalar = regexp.MustCompile(`^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?$`)

// scanQuoted returns the index just past the closing quote of
// the quoted string starting at s[start] (quote q), and the raw
// inner content. Backslash escapes consume two bytes, so an
// escaped quote does not close the string; a literal newline
// or the end of input fails the scan, leaving the text to be
// copied verbatim by the caller.
func scanQuoted(s string, start int, q byte) (end int, inner string, ok bool) {
	i := start + 1
	for i < len(s) {
		c := s[i]
		if c == '\n' || c == '\r' {
			return 0, "", false
		}
		if c == '\\' {
			if i+1 >= len(s) {
				return 0, "", false
			}
			i += 2
			continue
		}
		if c == q {
			return i + 1, s[start+1 : i], true
		}
		i++
	}
	return 0, "", false
}

// parseHex parses s as exactly len(s) hexadecimal digits.
func parseHex(s string) (int, bool) {
	v := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		var d int
		switch {
		case c >= '0' && c <= '9':
			d = int(c - '0')
		case c >= 'a' && c <= 'f':
			d = int(c-'a') + 10
		case c >= 'A' && c <= 'F':
			d = int(c-'A') + 10
		default:
			return 0, false
		}
		v = v*16 + d
	}
	return v, true
}

// decodeQuotedKey decodes the escapes in a quoted JSON key for
// vocabulary matching only: \uXXXX (any hex case), the JSON
// single-letter escapes, and %XX percent escapes. The decoded
// form is never written out — the caller's output keeps the
// original key text byte-identical. A malformed escape is left
// literal, so it cannot manufacture a vocabulary match.
func decodeQuotedKey(raw string) string {
	if !strings.ContainsAny(raw, `\%`) {
		return raw
	}
	var b strings.Builder
	b.Grow(len(raw))
	for i := 0; i < len(raw); {
		c := raw[i]
		if c == '\\' && i+1 < len(raw) {
			n := raw[i+1]
			switch n {
			case 'u':
				if i+6 <= len(raw) {
					if v, ok := parseHex(raw[i+2 : i+6]); ok {
						b.WriteRune(rune(v))
						i += 6
						continue
					}
				}
				b.WriteByte(c)
				i++
				continue
			case 'n':
				b.WriteByte('\n')
			case 'r':
				b.WriteByte('\r')
			case 't':
				b.WriteByte('\t')
			case 'b':
				b.WriteByte('\b')
			case 'f':
				b.WriteByte('\f')
			default:
				b.WriteByte(n)
			}
			i += 2
			continue
		}
		if c == '%' && i+3 <= len(raw) {
			if v, ok := parseHex(raw[i+1 : i+3]); ok {
				b.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		b.WriteByte(c)
		i++
	}
	return b.String()
}

// isJSONScalar reports whether v is a JSON scalar literal that
// may follow a secret key: true, false, null, or a JSON number.
func isJSONScalar(v string) bool {
	switch v {
	case "true", "false", "null":
		return true
	}
	return reJSONScalar.MatchString(v)
}

// scanEscapedQuoted is scanQuoted for a string delimited by
// ESCAPED quotes (\"...\"), the form Go's %q produces for a
// payload embedded in an error string (GatewayError.Error()
// renders its payload %q, so a JSON pair inside it appears as
// {\"token\": \"...\"}). s[start] is the backslash of the
// opening delimiter; the return is the index just past the
// closing delimiter and the raw inner content.
func scanEscapedQuoted(s string, start int, q byte) (end int, inner string, ok bool) {
	i := start + 2
	for i+1 < len(s) {
		c := s[i]
		if c == '\n' || c == '\r' {
			return 0, "", false
		}
		if c == '\\' {
			if s[i+1] == q {
				return i + 2, s[start+2 : i], true
			}
			i += 2
			continue
		}
		i++
	}
	return 0, "", false
}

// tryEscapedPair parses one escaped JSON pair (\"key\":
// \"value\", or \"key\": scalar) starting at the backslash at
// s[i]. consumed=false means no escaped pair starts here.
// When consumed, out is the pair's text with a secret value
// redacted (or verbatim when the key is not secret), except
// for a composite value, where out runs only through the
// opening bracket so the scanner recurses into the composite
// and still finds nested pairs.
func tryEscapedPair(s string, i int, q byte) (end int, out string, consumed bool) {
	keyEnd, keyRaw, ok := scanEscapedQuoted(s, i, q)
	if !ok {
		return 0, "", false
	}
	j := keyEnd
	for j < len(s) && (s[j] == ' ' || s[j] == '\t' || s[j] == '\n' || s[j] == '\r') {
		j++
	}
	if j >= len(s) || s[j] != ':' {
		return 0, "", false
	}
	j++
	for j < len(s) && (s[j] == ' ' || s[j] == '\t' || s[j] == '\n' || s[j] == '\r') {
		j++
	}
	if j >= len(s) {
		return 0, "", false
	}
	decoded := decodeQuotedKey(keyRaw)
	secret := reSecretKeyVocab.MatchString(decoded)
	public := isPublicKeyLabel(strings.ToLower(decoded))
	if s[j] == '\\' && j+1 < len(s) && s[j+1] == q {
		vEnd, valRaw, vok := scanEscapedQuoted(s, j, q)
		if !vok {
			return 0, "", false
		}
		if !secret {
			return vEnd, s[i:vEnd], true
		}
		var b strings.Builder
		b.WriteString(s[i : j+2])
		if public {
			b.WriteString(wgKeyPrefix(valRaw))
		} else {
			b.WriteString("[redacted]")
		}
		b.WriteString(s[vEnd-2 : vEnd])
		return vEnd, b.String(), true
	}
	if s[j] == '{' || s[j] == '[' {
		return j + 1, s[i : j+1], true
	}
	if s[j] == '"' || s[j] == '\'' {
		// Plain-quoted value after an escaped key
		// (mixed escaping): strip it like the
		// escaped-quote value above.
		vEnd, valRaw, vok := scanQuoted(s, j, s[j])
		if !vok {
			return 0, "", false
		}
		if !secret {
			return vEnd, s[i:vEnd], true
		}
		var b strings.Builder
		b.WriteString(s[i : j+1])
		if public {
			b.WriteString(wgKeyPrefix(valRaw))
		} else {
			b.WriteString("[redacted]")
		}
		b.WriteByte(s[j])
		return vEnd, b.String(), true
	}
	vEnd := j
	for vEnd < len(s) && s[vEnd] != ',' && s[vEnd] != '}' && s[vEnd] != ']' && s[vEnd] != ' ' && s[vEnd] != '\t' && s[vEnd] != '\n' && s[vEnd] != '\r' {
		vEnd++
	}
	scalar := s[j:vEnd]
	if secret && isJSONScalar(scalar) {
		var b strings.Builder
		b.WriteString(s[i:j])
		if public {
			b.WriteString(wgKeyPrefix(scalar))
		} else {
			b.WriteString("[redacted]")
		}
		return vEnd, b.String(), true
	}
	return vEnd, s[i:vEnd], true
}

// redactJSONSecrets strips secret-keyed JSON string and scalar
// values from free-form text; see the reSecretKeyVocab comment
// for the mechanism and its guarantees. Quoted keys and values
// use either quote type, independently; spacing around the
// colon is preserved; the closing quote of a redacted string
// value survives, as in the regex mechanism this replaces.
// Escaped-quote pairs (\"key\": \"value\", as %q produces) are
// handled by the same scanner through tryEscapedPair.
func redactJSONSecrets(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	i := 0
	for i < len(s) {
		if s[i] == '\\' && i+1 < len(s) && (s[i+1] == '"' || s[i+1] == '\'') {
			if end, out, ok := tryEscapedPair(s, i, s[i+1]); ok {
				b.WriteString(out)
				i = end
				continue
			}
			b.WriteByte(s[i])
			i++
			continue
		}
		q := s[i]
		if q != '"' && q != '\'' {
			b.WriteByte(s[i])
			i++
			continue
		}
		keyEnd, keyRaw, ok := scanQuoted(s, i, q)
		if !ok {
			b.WriteByte(s[i])
			i++
			continue
		}
		j := keyEnd
		for j < len(s) && (s[j] == ' ' || s[j] == '\t' || s[j] == '\n' || s[j] == '\r') {
			j++
		}
		if j >= len(s) || s[j] != ':' {
			// Not a pair — but if the quoted string
			// contains escapes it may be a %q-quoted
			// payload enclosing escaped pairs (the
			// outer quote swallowed them). Consume
			// only the opening quote and re-scan
			// inside, where tryEscapedPair finds them;
			// a plain quoted string is consumed whole.
			if strings.ContainsRune(keyRaw, '\\') {
				b.WriteByte(s[i])
				i++
				continue
			}
			b.WriteString(s[i:keyEnd])
			i = keyEnd
			continue
		}
		j++
		for j < len(s) && (s[j] == ' ' || s[j] == '\t' || s[j] == '\n' || s[j] == '\r') {
			j++
		}
		if j >= len(s) {
			b.WriteString(s[i:keyEnd])
			i = keyEnd
			continue
		}
		decoded := decodeQuotedKey(keyRaw)
		secret := reSecretKeyVocab.MatchString(decoded)
		public := isPublicKeyLabel(strings.ToLower(decoded))
		vq := s[j]
		if vq == '"' || vq == '\'' {
			vEnd, valRaw, vok := scanQuoted(s, j, vq)
			if !vok {
				b.WriteString(s[i:])
				break
			}
			if !secret {
				b.WriteString(s[i:vEnd])
				i = vEnd
				continue
			}
			b.WriteString(s[i : j+1])
			if public {
				b.WriteString(wgKeyPrefix(valRaw))
			} else {
				b.WriteString("[redacted]")
			}
			b.WriteByte(vq)
			i = vEnd
			continue
		}
		if vq == '{' || vq == '[' {
			// Composite value: do not consume it — copy
			// through the opening bracket and let the
			// scanner find nested secret pairs inside.
			b.WriteString(s[i : j+1])
			i = j + 1
			continue
		}
		if vq == '\\' && j+1 < len(s) && (s[j+1] == '"' || s[j+1] == '\'') {
			// Escaped-quote value after a plain key
			// (mixed escaping): strip it like an
			// escaped pair's value.
			vEnd, valRaw, vok := scanEscapedQuoted(s, j, s[j+1])
			if !vok {
				b.WriteString(s[i:])
				break
			}
			if !secret {
				b.WriteString(s[i:vEnd])
				i = vEnd
				continue
			}
			b.WriteString(s[i : j+2])
			if public {
				b.WriteString(wgKeyPrefix(valRaw))
			} else {
				b.WriteString("[redacted]")
			}
			b.WriteString(s[vEnd-2 : vEnd])
			i = vEnd
			continue
		}
		vEnd := j
		for vEnd < len(s) && s[vEnd] != ',' && s[vEnd] != '}' && s[vEnd] != ']' && s[vEnd] != ' ' && s[vEnd] != '\t' && s[vEnd] != '\n' && s[vEnd] != '\r' {
			vEnd++
		}
		scalar := s[j:vEnd]
		if secret && isJSONScalar(scalar) {
			b.WriteString(s[i:j])
			if public {
				b.WriteString(wgKeyPrefix(scalar))
			} else {
				b.WriteString("[redacted]")
			}
			i = vEnd
			continue
		}
		b.WriteString(s[i:vEnd])
		i = vEnd
	}
	return b.String()
}

// secretLabelVocab is the vocabulary for bare label forms in
// free-form text: key=value fragments and key: value pairs.
// It is the reKeyValue vocabulary widened with the bare
// labels auth, secret, credential, and api_key, which carry
// no suffix to match on.
const secretLabelVocab = `private_key|privateKey|public_key|publicKey|preshared_key|pre_shared_key|password|passwd|auth_token|access_token|hatch_token|api_token|session_key|secret_key|client_secret|token|session|cookie|auth|secret|credential|api_key|apiKey|apikey|vm_id|node_id`

// reKeyColon matches a bare label: value pair in free-form
// text (private_key: ..., token: ...) — the colon spelling of
// the key=value fragment. Quoted keys (JSON forms) do not
// match: the quote sits between the label and the colon, and
// those forms are handled by redactJSONSecrets first.
var reKeyColon = regexp.MustCompile(`(?i)\b(` + secretLabelVocab + `)\s*:\s*["']?([^\s,;\"'}]+)["']?`)

// reKeyValue matches a bare key=value fragment in free-form text
// for the secret vocabulary (vm_id, node_id, private key,
// preshared key, password, token-like keys, session, cookie,
// plus the bare labels auth, secret, credential, api_key).
// The label is kept, the value is replaced. This is the free-text
// analogue of redact.Value's key rule; it runs AFTER
// redact.String so already redacted values (brackets outside the
// value alphabet) stay put. public_key is NOT in this pattern:
// it is handled by rePublicKey first, which keeps the first 8
// characters instead of redacting wholesale.
var reKeyValue = regexp.MustCompile(`(?i)\b(vm_id|node_id|private_key|privateKey|preshared_key|pre_shared_key|password|passwd|auth_token|access_token|hatch_token|api_token|session_key|secret_key|client_secret|token|session|cookie|auth|secret|credential|api_key|apiKey|apikey)\s*=\s*[^\s;&,]*`)

// rePublicKey matches a bare public_key=value fragment (either
// spelling). The
// value is shortened to its first 8 characters plus an
// ellipsis, never logged in full (see the package doc).
var rePublicKey = regexp.MustCompile(`(?i)\b(public_?key)\s*=\s*([^\s;&,]*)`)

// reAuthBasic matches a labelled Basic credential:
// Authorization: Basic <value> (or Proxy-Authorization).
// redact.String handles Bearer only; Basic is the same leak.
var reAuthBasic = regexp.MustCompile(`(?i)((?:proxy-)?authorization:\s*basic\s+)\S+`)

// reBareBasic matches an unlabelled Basic credential. The token
// must look base64-like (at least 8 characters) AND contain a
// digit, so ordinary prose ("basic training") is never
// redacted; the digit check lives in redactBareBasicMatch.
var reBareBasic = regexp.MustCompile(`(?i)\b(basic\s+)([A-Za-z0-9_+\-/=]{8,})`)

// rePctQuery matches a percent-encoded query separator in
// free-form text: ?auth_token%3D<value> (or %253D,
// double-encoded). url.Parse decodes %3D into the key, so the
// URL pass cannot see the separator; this pass catches the
// bare form (and any %3D the URL pass left behind).
var rePctQuery = regexp.MustCompile(`(?i)([?&][A-Za-z0-9_.\-]*(?:token|secret|auth|session|cookie|credential|password|passwd|key)[A-Za-z0-9_.\-]*)(?:%253d|%3d)[^\s&;,'"]*`)

// reBareFragment matches a bare URL fragment value: #<token>
// with no key, in free-form text. The rule is length-only: any
// fragment of 4 or more fragment characters is treated as
// credential-bearing and stripped, digit or not (see
// redactBareFragmentMatch) — a token-shaped fragment carries
// no label to match on, and under-redacting one is a leak
// while over-redacting one is only a lost anchor. Fragments
// shorter than 4 characters are ordinary anchors/issue refs
// (#42, #abc) and survive. URL fragments inside a scheme://
// URL are handled by redactURLAllQuery first, which strips
// fragments of any length.
var reBareFragment = regexp.MustCompile(`#[A-Za-z0-9_\-./=]{4,}`)

// secretLabelList is secretLabelVocab split into labels, for
// the boundary-aware label check in normalizePctLabels.
var secretLabelList = strings.Split(secretLabelVocab, "|")

// isSecretPctLabel reports whether decoded (a percent/escape
// decoded label word) carries a secret-vocabulary label at the
// start or after a separator character (_, ., -). A label
// buried mid-word (xauth_token) is not one: the downstream
// key=value/colon patterns would not match it either, so
// normalising it would claim a redaction that never happens.
func isSecretPctLabel(decoded string) bool {
	lower := strings.ToLower(decoded)
	for _, label := range secretLabelList {
		ll := strings.ToLower(label)
		for idx := 0; ; {
			pos := strings.Index(lower[idx:], ll)
			if pos < 0 {
				break
			}
			abs := idx + pos
			if abs == 0 || lower[abs-1] == '_' || lower[abs-1] == '.' || lower[abs-1] == '-' {
				return true
			}
			idx = abs + 1
		}
	}
	return false
}

// scanPctWord consumes one label word starting at s[start]:
// word characters and %XX escapes. It returns the end index,
// the decoded word, and whether any %XX escape was present.
// Runs longer than 128 decoded characters are not labels.
func scanPctWord(s string, start int) (end int, decoded string, encoded bool) {
	var b strings.Builder
	i := start
	for i < len(s) && b.Len() <= 128 {
		c := s[i]
		if c == '%' && i+3 <= len(s) {
			if v, ok := parseHex(s[i+1 : i+3]); ok {
				// A %XX spelling of a separator ('=' or
				// ':') ends the word: it is the
				// separator for scanPctSep, not part of
				// the label. So does a double-encoded
				// separator ("%253D"/"%253A"): the %25
				// must not be consumed as a literal '%'
				// inside the word either.
				if v == '=' || v == ':' {
					break
				}
				if v == '%' && i+5 <= len(s) {
					nxt := strings.ToLower(s[i+3 : i+5])
					if nxt == "3d" || nxt == "3a" {
						break
					}
				}
				b.WriteByte(byte(v))
				encoded = true
				i += 3
				continue
			}
		}
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '.' || c == '-' {
			b.WriteByte(c)
			i++
			continue
		}
		break
	}
	if b.Len() > 128 {
		return start, "", false
	}
	return i, b.String(), encoded
}

// scanPctSep returns the end index and the normalised separator
// ('=' or ':') when s[end] starts a key separator: a literal
// "=", a literal ":", or a percent-encoded (single or double)
// "%3D"/"%3A" form, matched case-insensitively. 0 means no
// separator follows.
func scanPctSep(s string, end int) (sepEnd int, sep byte) {
	if end >= len(s) {
		return 0, 0
	}
	switch s[end] {
	case '=':
		return end + 1, '='
	case ':':
		return end + 1, ':'
	}
	rest := s[end:]
	lower := strings.ToLower(rest)
	if strings.HasPrefix(lower, "%253d") {
		return end + 5, '='
	}
	if strings.HasPrefix(lower, "%3d") {
		return end + 3, '='
	}
	if strings.HasPrefix(lower, "%253a") {
		return end + 5, ':'
	}
	if strings.HasPrefix(lower, "%3a") {
		return end + 3, ':'
	}
	return 0, 0
}

// normalizePctLabels rewrites percent-encoded secret labels in
// bare key=value / key: value forms into their decoded label
// plus a literal separator, so the existing reKeyValue /
// reKeyColon passes can strip the value: %61uth_token=VAL,
// %61uth_token%3DVAL, and auth_token%3DVAL all become
// auth_token=VAL before those passes run. Only a word whose
// decoded form carries a secret label AND is immediately
// followed by a separator is rewritten, and only the label
// and separator bytes are touched — the value, and every
// non-secret encoded word, survive byte-identical. This pass
// runs after the URL pass (scheme:// URLs are already fully
// redacted there) and before redact.String, so a rewritten
// label is seen by every later pass.
func normalizePctLabels(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	i := 0
	for i < len(s) {
		c := s[i]
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '.' || c == '-' || c == '%') {
			b.WriteByte(c)
			i++
			continue
		}
		end, decoded, encoded := scanPctWord(s, i)
		if end == i || decoded == "" {
			b.WriteByte(c)
			i++
			continue
		}
		sepEnd, sep := scanPctSep(s, end)
		if sep == 0 || !isSecretPctLabel(decoded) {
			b.WriteString(s[i:end])
			i = end
			continue
		}
		if !encoded && sepEnd == end+1 && (s[end] == '=' || s[end] == ':') {
			// Plain label, literal separator: the downstream
			// passes already handle this form; leave it
			// byte-identical rather than rewriting it.
			b.WriteString(s[i:end])
			i = end
			continue
		}
		b.WriteString(decoded)
		b.WriteByte(sep)
		i = sepEnd
	}
	return b.String()
}

// reWGPeer matches the sing-box device logger's abbreviated peer
// form, peer(ABCD…WXYZ): four characters, an ellipsis, four
// characters. The suffix half is key material too, so it is
// stripped, leaving the first four characters plus the ellipsis.
var reWGPeer = regexp.MustCompile(`peer\(([A-Za-z0-9+/=]{4})(?:…|\.\.\.)([A-Za-z0-9+/=]{4})\)`)

// wgKeyPrefix returns the first 8 characters of key, plus an
// ellipsis when the key was longer. A key of 8 or fewer
// characters is returned unchanged: it is already at most a
// prefix.
func wgKeyPrefix(key string) string {
	r := []rune(key)
	if len(r) <= 8 {
		return key
	}
	return string(r[:8]) + "…"
}

// SafeString strips credentials from a free-form string for
// logging: every query value and fragment of every URL-like
// substring first (URL parsing must see the raw userinfo/query,
// before redact.String rewrites them into unparseable forms),
// then percent-encoded query separators, then redact.String
// (URL userinfo, named token query keys, cookie fragments,
// Bearer tokens), then secret-keyed JSON string values
// (double- and single-quoted, snake_case and camelCase),
// then bare secret label: value pairs, bare secret key=value
// fragments, Basic credentials, and bare #fragment values. It
// is idempotent. Ordinary prose, hostnames, and non-secret
// fields survive byte-identical.
// The JSON value rule (redactJSONSecrets, above): the label
// and spacing survive byte-identical; the value becomes
// [redacted] — except a public_key value, which becomes its
// first-8-char prefix (the WireGuard prefix rule, see the
// package doc). A private_key label always redacts wholesale:
// it contains "private_key", so the public_key branch never
// fires for it.

// isPublicKeyLabel reports whether a lower-cased key denotes a
// WireGuard public key (either spelling), excluding the
// private-key spellings, which contain "private".
func isPublicKeyLabel(key string) bool {
	if strings.Contains(key, "private_key") || strings.Contains(key, "privatekey") {
		return false
	}
	return strings.Contains(key, "public_key") || strings.Contains(key, "publickey")
}

// redactColonSecretMatch redacts one bare label: value pair.
// The label survives with normalised ": " spacing; a public-key
// label keeps its first-8-char prefix, every other label
// redacts wholesale.
func redactColonSecretMatch(m string) string {
	loc := reKeyColon.FindStringSubmatchIndex(m)
	if loc == nil || len(loc) < 6 {
		return m
	}
	label := m[loc[2]:loc[3]]
	value := m[loc[4]:loc[5]]
	lower := strings.ToLower(label)
	if lower == "public_key" || lower == "publickey" {
		return label + ": " + wgKeyPrefix(value)
	}
	return label + ": [redacted]"
}

// redactBareBasicMatch redacts an unlabelled Basic credential
// only when the token contains a digit (base64 credentials
// do; prose words do not). The label spelling survives.
func redactBareBasicMatch(m string) string {
	loc := reBareBasic.FindStringSubmatchIndex(m)
	if loc == nil || len(loc) < 6 {
		return m
	}
	if !strings.ContainsAny(m[loc[4]:loc[5]], "0123456789") {
		return m
	}
	return m[:loc[3]] + "[redacted]"
}

// redactBareFragmentMatch redacts every bare #fragment value
// matched by reBareFragment (4+ fragment characters, digit or
// not): a bare fragment carrying a token (a reset link, a
// hash) is a credential, and no label distinguishes it from
// an anchor, so length alone decides. Shorter fragments never
// reach this function (the regex floor excludes them).
func redactBareFragmentMatch(m string) string {
	return "#[redacted]"
}

func SafeString(s string) string {
	if s == "" {
		return s
	}
	s = reURL.ReplaceAllStringFunc(s, redactURLAllQuery)
	s = rePctQuery.ReplaceAllString(s, `${1}=[redacted]`)
	s = normalizePctLabels(s)
	s = redact.String(s)
	s = redactJSONSecrets(s)
	s = reKeyColon.ReplaceAllStringFunc(s, redactColonSecretMatch)
	s = rePublicKey.ReplaceAllStringFunc(s, func(m string) string {
		loc := rePublicKey.FindStringSubmatchIndex(m)
		if loc == nil || len(loc) < 6 {
			return m
		}
		return m[:loc[4]] + wgKeyPrefix(m[loc[4]:loc[5]])
	})
	s = reKeyValue.ReplaceAllString(s, `${1}=[redacted]`)
	s = reAuthBasic.ReplaceAllString(s, `${1}[redacted]`)
	s = reBareBasic.ReplaceAllStringFunc(s, redactBareBasicMatch)
	s = reBareFragment.ReplaceAllStringFunc(s, redactBareFragmentMatch)
	s = reWGPeer.ReplaceAllString(s, `peer($1…)`)
	return s
}

// redactURLAllQuery returns raw with every query value replaced by
// [redacted], userinfo replaced by [redacted], and any fragment
// replaced by [redacted] (a fragment carries credentials as
// readily as a query value; a bare #token has no key to match
// on). Scheme/host/path survive. The query is rebuilt by hand
// (not Values.Encode) so the marker stays the literal
// "[redacted]" instead of its percent-encoded form. A query
// separator may be a literal "=" or a percent-encoded "%3D"
// (or double-encoded "%253D"): url.Parse decodes "%3D" into
// the key, so the separator is found on the raw query text
// before decoding. An unparseable URL is replaced wholesale: a
// log line must never carry a half-parsed credential-bearing string.
func redactURLAllQuery(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		// Idempotence: a URL SafeString already redacted
		// carries "[redacted]" as userinfo, whose angle
		// brackets make url.Parse fail — a second pass
		// (Emit, then the sink writer) would collapse
		// the whole URL to [redacted-url] and lose the
		// host. Retry with the marker temporarily
		// replaced by a parse-safe placeholder, then
		// restore it in host/path positions (userinfo,
		// query, and fragment positions become [redacted]
		// by the normal logic below, so the placeholder
		// survives only where the marker already was).
		if strings.Contains(raw, "[redacted]") || strings.Contains(raw, "<redacted>") {
			sub := strings.ReplaceAll(strings.ReplaceAll(raw, "[redacted]", "REDACTED0"), "<redacted>", "REDACTED0")
			if u2, err2 := url.Parse(sub); err2 == nil {
				return strings.ReplaceAll(redactParsedURL(u2), "REDACTED0", "[redacted]")
			}
		}
		return "[redacted-url]"
	}
	return redactParsedURL(u)
}

// redactParsedURL applies the userinfo/query/fragment
// redaction to an already-parsed URL; see
// redactURLAllQuery.
func redactParsedURL(u *url.URL) string {
	if u.User != nil {
		u.User = url.User("[redacted]")
	}
	if u.RawQuery != "" {
		// Every key present, every value [redacted], keys escaped,
		// order preserved as parsed (Query() sorts; keep the
		// sorted order for determinism).
		keys := make([]string, 0)
		seen := map[string]bool{}
		for _, seg := range strings.Split(u.RawQuery, "&") {
			if seg == "" {
				continue
			}
			keyPart := seg
			if idx := querySepIndex(seg); idx >= 0 {
				keyPart = seg[:idx]
			}
			key, err := url.QueryUnescape(keyPart)
			if err != nil {
				key = keyPart
			}
			if !seen[key] {
				seen[key] = true
				keys = append(keys, key)
			}
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			parts = append(parts, url.QueryEscape(k)+"=[redacted]")
		}
		u.RawQuery = strings.Join(parts, "&")
	}
	if u.Fragment != "" {
		u.Fragment = "[redacted]"
	}
	return u.String()
}

// querySepIndex returns the index of the first query separator
// in one raw query segment: a literal "=", a percent-encoded
// "%3D", or a double-encoded "%253D". -1 when the segment has
// no separator (a bare key, whose value is empty).
func querySepIndex(seg string) int {
	best := -1
	if idx := strings.IndexByte(seg, '='); idx >= 0 {
		best = idx
	}
	lower := strings.ToLower(seg)
	for _, sep := range []string{"%253d", "%3d"} {
		if idx := strings.Index(lower, sep); idx >= 0 && (best < 0 || idx < best) {
			best = idx
		}
	}
	return best
}

// reHostSafe matches a bare host:port host component — a DNS
// name, an IPv4 literal, or a bracketed IPv6 literal. Anything
// else (a URL, a query string, userinfo, whitespace, a key=value
// fragment) is not a host and must never be logged as one.
var reHostSafe = regexp.MustCompile(`^[A-Za-z0-9._:\[\]-]+$`)

// SafeHost returns host unchanged when it is a bare host, or
// "[redacted]" when it is not host-shaped (a URL, query string,
// or other caller-supplied text smuggled into a host field). Dial
// events log destinations; this keeps a URL-shaped host from
// leaking query credentials through a host field.
func SafeHost(host string) string {
	if host != "" && reHostSafe.MatchString(host) {
		return host
	}
	return "[redacted]"
}

// It is SafeString applied to err.Error(): the error chain is not
// logged, only the (redacted) top-level text. Callers that need an
// error's type for a log field must classify with errors.As and
// log the type name, never the full chain.
func SafeErr(err error) string {
	if err == nil {
		return ""
	}
	return SafeString(err.Error())
}

// redactedError wraps an error so its printed form passes
// SafeString while errors.As/errors.Is still see the original
// chain (Unwrap). Use it at boundaries where sing-box/library
// errors enter castctl (outbound manager and DNS client
// construction/start): those errors may embed config material
// in their text — notably the WireGuard endpoint's IpcSet
// failure, whose error embeds the full IPC config including
// the private key, preshared key, and peer public keys
// (sing-box transport/wireguard/endpoint.go:253-254, built
// from the ipcConf at :54 and GenerateIpcLines at :345-360).
// Wrapping at the boundary keeps the printed/returned text
// safe no matter which logger or CLI error path prints it.
type redactedError struct{ err error }

// Error returns the SafeString-redacted error text.
func (e *redactedError) Error() string { return SafeString(e.err.Error()) }

// Unwrap exposes the original error.
func (e *redactedError) Unwrap() error { return e.err }

// WrapErr wraps err for safe printing, unless err is nil.
func WrapErr(err error) error {
	if err == nil {
		return nil
	}
	return &redactedError{err: err}
}
