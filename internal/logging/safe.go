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

// reJSONSecret matches a JSON string value under a secret-looking
// key in free-form text: "key": "value". The key match is a
// substring match over the secret vocabulary (password, token,
// secret, key, cookie, auth, vm_id, node_id, credential, passwd),
// deliberately broader than redact.Value's exact-key rule: this
// runs on unstructured text where a key may carry a prefix or
// suffix, and over-redacting a log line is safe while leaking one
// is not. Non-secret string values are left byte-identical.
var reJSONSecret = regexp.MustCompile(`(?i)("(?:[^"]*(?:password|token|secret|private_key|public_key|cookie|auth|vm_id|node_id|credential|passwd)[^"]*)"\s*:\s*")[^"]*`)

// reKeyValue matches a bare key=value fragment in free-form text
// for the secret vocabulary (vm_id, node_id, private key,
// preshared key, password, token-like keys, session, cookie).
// The label is kept, the value is replaced. This is the free-text
// analogue of redact.Value's key rule; it runs AFTER
// redact.String so already redacted values (brackets outside the
// value alphabet) stay put. public_key is NOT in this pattern:
// it is handled by rePublicKey first, which keeps the first 8
// characters instead of redacting wholesale.
var reKeyValue = regexp.MustCompile(`(?i)\b(vm_id|node_id|private_key|preshared_key|pre_shared_key|password|passwd|auth_token|access_token|hatch_token|api_token|token|session|cookie)\s*=\s*[^\s;&,]*`)

// rePublicKey matches a bare public_key=value fragment. The
// value is shortened to its first 8 characters plus an
// ellipsis, never logged in full (see the package doc).
var rePublicKey = regexp.MustCompile(`(?i)\b(public_key)\s*=\s*([^\s;&,]*)`)

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
// logging: every query value of every URL-like substring first
// (URL parsing must see the raw userinfo/query, before
// redact.String rewrites them into unparseable forms), then
// redact.String (URL userinfo, named token query keys, cookie
// fragments, Bearer tokens), then secret-keyed JSON string values,
// then bare secret key=value fragments. It is idempotent.
// Ordinary prose, hostnames, and non-secret fields survive
// byte-identical.
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
	if strings.Contains(key, "public_key") && !strings.Contains(key, "private_key") {
		return prefix + wgKeyPrefix(value)
	}
	return prefix + "[redacted]"
}

func SafeString(s string) string {
	if s == "" {
		return s
	}
	s = reURL.ReplaceAllStringFunc(s, redactURLAllQuery)
	s = redact.String(s)
	s = reJSONSecret.ReplaceAllStringFunc(s, redactJSONSecretMatch)
	s = rePublicKey.ReplaceAllStringFunc(s, func(m string) string {
		loc := rePublicKey.FindStringSubmatchIndex(m)
		if loc == nil || len(loc) < 6 {
			return m
		}
		return m[:loc[4]] + wgKeyPrefix(m[loc[4]:loc[5]])
	})
	s = reKeyValue.ReplaceAllString(s, `${1}=[redacted]`)
	s = reWGPeer.ReplaceAllString(s, `peer($1…)`)
	return s
}

// redactURLAllQuery returns raw with every query value replaced by
// [redacted], userinfo replaced by [redacted], and a key-bearing
// fragment replaced by [redacted]. Scheme/host/path survive. The
// query is rebuilt by hand (not Values.Encode) so the marker stays
// the literal "[redacted]" instead of its percent-encoded form. An
// unparseable URL is replaced wholesale: a log line must never
// carry a half-parsed credential-bearing string.
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
		for k := range u.Query() {
			if !seen[k] {
				seen[k] = true
				keys = append(keys, k)
			}
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			parts = append(parts, url.QueryEscape(k)+"=[redacted]")
		}
		u.RawQuery = strings.Join(parts, "&")
	}
	if strings.Contains(u.Fragment, "=") {
		u.Fragment = "[redacted]"
	}
	return u.String()
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
