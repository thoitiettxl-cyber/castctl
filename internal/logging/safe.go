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
// for the secret vocabulary (vm_id, node_id, private/public key,
// password, token-like keys, session, cookie). The label is kept,
// the value is replaced. This is the free-text analogue of
// redact.Value's key rule; it runs AFTER redact.String so already
// redacted values (brackets outside the value alphabet) stay put.
var reKeyValue = regexp.MustCompile(`(?i)\b(vm_id|node_id|private_key|public_key|password|passwd|auth_token|access_token|hatch_token|api_token|token|session|cookie)\s*=\s*[^\s;&,]*`)

// SafeString strips credentials from a free-form string for
// logging: every query value of every URL-like substring first
// (URL parsing must see the raw userinfo/query, before
// redact.String rewrites them into unparseable forms), then
// redact.String (URL userinfo, named token query keys, cookie
// fragments, Bearer tokens), then secret-keyed JSON string values,
// then bare secret key=value fragments. It is idempotent.
// Ordinary prose, hostnames, and non-secret fields survive
// byte-identical.
func SafeString(s string) string {
	if s == "" {
		return s
	}
	s = reURL.ReplaceAllStringFunc(s, redactURLAllQuery)
	s = redact.String(s)
	s = reJSONSecret.ReplaceAllString(s, `${1}[redacted]`)
	s = reKeyValue.ReplaceAllString(s, `${1}=[redacted]`)
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
