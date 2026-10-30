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

// reJSONSecret matches a JSON string value under a secret-looking
// key in free-form text: "key": "value". The key match is a
// substring match over the secret vocabulary (password, token,
// secret, key, cookie, auth, vm_id, node_id, credential, passwd,
// plus camelCase forms),
// deliberately broader than redact.Value's exact-key rule: this
// runs on unstructured text where a key may carry a prefix or
// suffix, and over-redacting a log line is safe while leaking one
// is not. Non-secret string values are left byte-identical.
var reJSONSecret = regexp.MustCompile(`(?i)("(?:[^"]*(?:` + secretKeyVocab + `)[^"]*)"\s*:\s*")[^"]*`)

// reJSONSecretSingle is the single-quoted analogue: a server
// answering {'token': '...'} leaks exactly like the
// double-quoted form. The key and the value quote may each be
// single or double; the closing quote survives the match, so
// the replacement leaves it in place.
var reJSONSecretSingle = regexp.MustCompile(`(?i)('(?:[^']*(?:` + secretKeyVocab + `)[^']*)'\s*:\s*['"])[^'"]*`)

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
// those forms are handled by reJSONSecret/reJSONSecretSingle
// first.
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
// with no key, in free-form text. The token must be at least
// 16 characters and contain a digit (see
// redactBareFragmentMatch), so ordinary hashtags and short
// anchors survive. URL fragments inside a scheme:// URL are
// handled by redactURLAllQuery first.
var reBareFragment = regexp.MustCompile(`#[A-Za-z0-9_\-./=]{16,}`)

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
// redactJSONSecretMatch redacts one secret-keyed JSON string
// value matched by reJSONSecret. The label and spacing survive
// byte-identical; the value becomes [redacted] — except a
// public_key value, which becomes its first-8-char prefix
// (the WireGuard prefix rule, see the package doc). A
// private_key label always redacts wholesale: it contains
// "private_key", so the public_key branch never fires for it.
func redactJSONSecretMatch(m string) string {
	loc := reJSONSecret.FindStringSubmatchIndex(m)
	if loc == nil || len(loc) < 4 {
		return "[redacted]"
	}
	prefix := m[:loc[3]]
	key := strings.ToLower(m[loc[2]:loc[3]])
	value := m[loc[3]:]
	if isPublicKeyLabel(key) {
		return prefix + wgKeyPrefix(value)
	}
	return prefix + "[redacted]"
}

// redactJSONSecretSingleMatch is redactJSONSecretMatch for the
// single-quoted form: same prefix rule, same wholesale rule.
func redactJSONSecretSingleMatch(m string) string {
	loc := reJSONSecretSingle.FindStringSubmatchIndex(m)
	if loc == nil || len(loc) < 4 {
		return "[redacted]"
	}
	prefix := m[:loc[3]]
	key := strings.ToLower(m[loc[2]:loc[3]])
	value := m[loc[3]:]
	if isPublicKeyLabel(key) {
		return prefix + wgKeyPrefix(value)
	}
	return prefix + "[redacted]"
}

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

// redactBareFragmentMatch redacts a bare #fragment value only
// when it contains a digit: a bare fragment carrying a token
// (a reset link, a hash) is a credential; a word hashtag is
// not.
func redactBareFragmentMatch(m string) string {
	if !strings.ContainsAny(m, "0123456789") {
		return m
	}
	return "#[redacted]"
}

func SafeString(s string) string {
	if s == "" {
		return s
	}
	s = reURL.ReplaceAllStringFunc(s, redactURLAllQuery)
	s = rePctQuery.ReplaceAllString(s, `${1}=[redacted]`)
	s = redact.String(s)
	s = reJSONSecret.ReplaceAllStringFunc(s, redactJSONSecretMatch)
	s = reJSONSecretSingle.ReplaceAllStringFunc(s, redactJSONSecretSingleMatch)
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
		return "[redacted-url]"
	}
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
