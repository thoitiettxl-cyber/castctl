// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package logging

// Hard-rule redaction tests for the logging boundary.
//
// Fixture vocabulary (invented here, never real values; every value
// carries the LOGFIX- prefix so an absence assertion can never pass
// by colliding with an existing test fixture):
//
//	COOKIE_VAL   LOGFIX-SESS-9d2e41
//	DATR_VAL     LOGFIX-DATR-51bc07
//	ACCESS_TOKEN LOGFIX-AT-83af10
//	HATCH_TOKEN  LOGFIX-HT-2c6e88
//	BEARER_VAL   LOGFIX-BEARER-1a8f33
//	HEADER_VAL   LOGFIX-HDR-77d4e9
//	WG_PRIV      LOGFIX-WGPRIV-6e19d0
//	WG_PUB       LOGFIX-WGPUB-4b77c2
//	VMID_VAL     LOGFIX-VMID-22d9f0
//	PASSWORD_VAL LOGFIX-PW-31c7aa
//
// What each test observes: the string returned by SafeString/SafeErr
// for one fixture-bearing input. What its red run catches: the
// documented gaps in redact.String (it does NOT strip a vm_id query
// value, WireGuard key material under a key, a JSON {"password":...}
// fragment, an unknown query key, or a header value), which the
// logging boundary must close because log lines are built from
// free-form strings, not structured values. redact.String itself is
// NOT changed here: gateway tests pin vm_id surviving it, and its
// boundary is documented in internal/redact. The logging boundary
// is stricter by design.
//
// A bare WireGuard key with no key label is NOT asserted stripped:
// no pattern distinguishes a bare 44-char base64 key from other
// text, so bare key material must be excluded from log fields by
// construction (never logged), never relied on redaction to catch.
// That exclusion is proven by the capture-matrix tests, not here.

import (
	"errors"
	"strings"
	"testing"
)

const (
	fixCookieVal   = "LOGFIX-SESS-9d2e41"
	fixDatrVal     = "LOGFIX-DATR-51bc07"
	fixAccessToken = "LOGFIX-AT-83af10"
	fixHatchToken  = "LOGFIX-HT-2c6e88"
	fixBearerVal   = "LOGFIX-BEARER-1a8f33"
	fixHeaderVal   = "LOGFIX-HDR-77d4e9"
	fixWGPriv      = "LOGFIX-WGPRIV-6e19d0"
	fixWGPub       = "LOGFIX-WGPUB-4b77c2"
	fixVMID        = "LOGFIX-VMID-22d9f0"
	fixPassword    = "LOGFIX-PW-31c7aa"
	fixProxyPass   = "LOGFIX-PASS-55aa01"
)

var fixValues = []string{
	fixCookieVal, fixDatrVal, fixAccessToken, fixHatchToken,
	fixBearerVal, fixHeaderVal, fixWGPriv, fixWGPub,
	fixVMID, fixPassword, fixProxyPass,
}

func assertNoFixture(t *testing.T, got string) {
	t.Helper()
	for _, v := range fixValues {
		if strings.Contains(got, v) {
			t.Errorf("SafeString output contains fixture value %q in %q", v, got)
		}
	}
}

// TestSafeStringWSURL is the vm_id case: redact.String alone leaves
// the vm_id query value byte-identical. The logging boundary must
// strip EVERY query value of a URL it is handed, whatever the key.
func TestSafeStringWSURL(t *testing.T) {
	in := "dial failed: wss://gateway.example.invalid/v1/noise?vm_id=" + fixVMID + "&auth_token=" + fixHatchToken
	got := SafeString(in)
	assertNoFixture(t, got)
	// Label survival: the URL shape survives, values do not.
	if !strings.Contains(got, "vm_id=[redacted]") || !strings.Contains(got, "auth_token=[redacted]") {
		t.Errorf("SafeString(%q) = %q, want vm_id/auth_token labels with [redacted] values", in, got)
	}
	if !strings.Contains(got, "wss://gateway.example.invalid/v1/noise") {
		t.Errorf("SafeString(%q) = %q, want scheme/host/path preserved", in, got)
	}
}

// TestSafeStringUnknownQueryKey: a credential under a key redact.String
// does not know must still not survive the logging boundary.
func TestSafeStringUnknownQueryKey(t *testing.T) {
	in := "https://example.invalid/cb?session_key=" + fixAccessToken + "&next=/ok"
	got := SafeString(in)
	assertNoFixture(t, got)
	if !strings.Contains(got, "session_key=[redacted]") {
		t.Errorf("SafeString(%q) = %q, want session_key label with [redacted] value", in, got)
	}
}

// TestSafeStringUserinfo: a proxy URL with userinfo must keep
// scheme/host/port and lose both userinfo parts.
func TestSafeStringUserinfo(t *testing.T) {
	in := "proxy https://LOGFIX-USER:" + fixProxyPass + "@proxy.example.invalid:8080 refused"
	got := SafeString(in)
	assertNoFixture(t, got)
	if !strings.Contains(got, "proxy.example.invalid:8080") {
		t.Errorf("SafeString(%q) = %q, want proxy host:port preserved", in, got)
	}
}

// TestSafeStringCookieAndBearer: the redact.String cases, kept as
// regression pins at the logging boundary.
func TestSafeStringCookieAndBearer(t *testing.T) {
	cases := []string{
		"Cookie: hatch_sess=" + fixCookieVal + "; datr=" + fixDatrVal,
		`{"hatch_sess": "` + fixCookieVal + `"}`,
		"Authorization: Bearer " + fixBearerVal,
		"Bearer " + fixBearerVal + " rejected",
	}
	for _, in := range cases {
		got := SafeString(in)
		assertNoFixture(t, got)
		if !strings.Contains(got, "[redacted]") {
			t.Errorf("SafeString(%q) = %q, want a [redacted] marker (positive control)", in, got)
		}
	}
}

// TestSafeStringJSONSecretFragment: a JSON {"password": "..."}
// fragment inside free-form text survives redact.String; the
// logging boundary strips secret-keyed JSON string values.
func TestSafeStringJSONSecretFragment(t *testing.T) {
	in := `server said {"password": "` + fixPassword + `", "user": "alice"} and {"private_key": "` + fixWGPriv + `"}`
	got := SafeString(in)
	assertNoFixture(t, got)
	if !strings.Contains(got, `"password": "[redacted]"`) {
		t.Errorf("SafeString(%q) = %q, want password label with [redacted] value", in, got)
	}
	if !strings.Contains(got, `"private_key": "[redacted]"`) {
		t.Errorf("SafeString(%q) = %q, want private_key label with [redacted] value", in, got)
	}
	if !strings.Contains(got, `"user": "alice"`) {
		t.Errorf("SafeString(%q) = %q, want non-secret field preserved", in, got)
	}
}

// TestSafeStringKeyValueFragment: key=value fragments under a
// secret-vocabulary key (WG keys, tokens) in free-form text must
// lose their values while keeping their labels. An arbitrary header
// NAME (e.g. x_custom) is NOT recognised in free text — header
// values must be excluded from log fields by construction, never
// relied on this boundary to catch. fixHeaderVal is driven here
// under api_token to pin the keyed form only.
func TestSafeStringKeyValueFragment(t *testing.T) {
	in := "private_key=" + fixWGPriv + " public_key=" + fixWGPub + " api_token=" + fixHeaderVal
	got := SafeString(in)
	assertNoFixture(t, got)
	if !strings.Contains(got, "private_key=[redacted]") || !strings.Contains(got, "public_key=[redacted]") {
		t.Errorf("SafeString(%q) = %q, want WG key labels with [redacted] values", in, got)
	}
}

// TestSafeStringBareHeaderValue is a NEGATIVE pin: a bare header
// value with no label cannot be recognised, so SafeString does not
// claim to strip it. Callers must never put a bare header value in
// a log field; this test documents the boundary instead of
// pretending otherwise. It asserts only that SafeString does not
// corrupt ordinary prose.
func TestSafeStringBareHeaderValue(t *testing.T) {
	in := "gateway said hello"
	if got := SafeString(in); got != in {
		t.Errorf("SafeString(%q) = %q, want byte-identical prose", in, got)
	}
}

// TestSafeStringIdempotent: applying the boundary twice changes
// nothing the second time (log lines pass through it at most once,
// but double application must never un-redact or mangle).
func TestSafeStringIdempotent(t *testing.T) {
	in := "wss://gateway.example.invalid/v1/noise?vm_id=" + fixVMID + "&auth_token=" + fixHatchToken +
		` {"password": "` + fixPassword + `"}`
	once := SafeString(in)
	twice := SafeString(once)
	if once != twice {
		t.Errorf("SafeString not idempotent:\n once: %q\ntwice: %q", once, twice)
	}
	assertNoFixture(t, twice)
}

// TestSafeHost pins the host-shape rule for dial events.
func TestSafeHost(t *testing.T) {
	for _, h := range []string{"gateway.test", "127.0.0.1", "[::1]", "proxy-sg.example.invalid", "a-b_c.example"} {
		if got := SafeHost(h); got != h {
			t.Errorf("SafeHost(%q) = %q, want unchanged", h, got)
		}
	}
	for _, h := range []string{"", "https://gateway.example.invalid/v1/noise?vm_id=" + fixVMID, "host?token=" + fixHatchToken, "user:pass@host", "ho st", "a=b"} {
		if got := SafeHost(h); got != "[redacted]" {
			t.Errorf("SafeHost(%q) = %q, want [redacted]", h, got)
		}
	}
}

// TestSafeErrNilAndPlain: nil stays empty; a plain error keeps its
// text; a fixture-bearing error is stripped the same way.
func TestSafeErrNilAndPlain(t *testing.T) {
	if got := SafeErr(nil); got != "" {
		t.Errorf("SafeErr(nil) = %q, want empty", got)
	}
	if got := SafeErr(errors.New("connection refused")); got != "connection refused" {
		t.Errorf("SafeErr(plain) = %q, want byte-identical", got)
	}
	err := errors.New("handshake: wss://gateway.example.invalid/v1/noise?vm_id=" + fixVMID + "&auth_token=" + fixHatchToken)
	assertNoFixture(t, SafeErr(err))
}
