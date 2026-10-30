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
	// The full public key must be absent, but its FIRST 8
	// CHARS survive as the peer prefix (Boss rule); the
	// private key is redacted wholesale.
	if strings.Contains(got, fixWGPub) {
		t.Errorf("SafeString(%q) = %q, want the full public key absent", in, got)
	}
	if strings.Contains(got, fixWGPriv) {
		t.Errorf("SafeString(%q) = %q, want the private key absent", in, got)
	}
	if !strings.Contains(got, "private_key=[redacted]") {
		t.Errorf("SafeString(%q) = %q, want private_key=[redacted]", in, got)
	}
	if !strings.Contains(got, "public_key="+fixWGPub[:8]) {
		t.Errorf("SafeString(%q) = %q, want public_key=<first 8 chars>", in, got)
	}
	if strings.Contains(got, fixHeaderVal) {
		t.Errorf("SafeString(%q) = %q, want the api_token value absent", in, got)
	}
}

// TestSafeStringWGPublicKeyForms: the 8-char prefix rule in
// every shape a public key can reach a log line — JSON value,
// bare key=value, and the sing-box device logger's abbreviated
// peer(ABCD…WXYZ) form (which keeps only the first four chars
// plus the ellipsis: the suffix half is key material too).
func TestSafeStringWGPublicKeyForms(t *testing.T) {
	prefix := fixWGPub[:8]
	jsonIn := `{"public_key": "` + fixWGPub + `", "private_key": "` + fixWGPriv + `"}`
	got := SafeString(jsonIn)
	if strings.Contains(got, fixWGPub) || strings.Contains(got, fixWGPriv) {
		t.Errorf("SafeString(%q) = %q, want both full keys absent", jsonIn, got)
	}
	if !strings.Contains(got, prefix) {
		t.Errorf("SafeString(%q) = %q, want the 8-char prefix present", jsonIn, got)
	}
	if !strings.Contains(got, `"private_key": "[redacted]"`) {
		t.Errorf("SafeString(%q) = %q, want private_key wholesale-redacted", jsonIn, got)
	}
	// peer(ABCD…WXYZ): first four + ellipsis survive, the
	// last four must not.
	peer := "peer(" + fixWGPub[:4] + "…" + fixWGPub[len(fixWGPub)-4:] + ") created"
	got = SafeString(peer)
	if strings.Contains(got, fixWGPub[len(fixWGPub)-4:]) && strings.Contains(got, "peer(") {
		t.Errorf("SafeString(%q) = %q, want the peer suffix half stripped", peer, got)
	}
	if !strings.Contains(got, "peer("+fixWGPub[:4]+"…") {
		t.Errorf("SafeString(%q) = %q, want peer(<first 4>…)", peer, got)
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

// TestSafeStringTwelveServerShapes drives the 12 server-text
// shapes from the loop-2 red-team A4 drive through SafeString.
// Shapes 1-9 survived the loop-2 boundary; shapes 10-12 are
// the ones the drive already showed stripped, derived here
// from the code paths that strip them (redactJSONSecrets,
// reKeyValue, redact.String Bearer) because no loop-2 report
// file survives in ~/workspace/tmp/logging/ to recover their
// exact spellings from — they are named explicitly, not
// invented as new shapes. Every shape's expected value is a
// literal fixture below, never recomputed from SafeString.
// The publicKey shapes keep the first-8-chars prefix rule:
// the FULL value must be absent, the prefix may survive.
func TestSafeStringTwelveServerShapes(t *testing.T) {
	t.Parallel()
	const (
		colonVal  = "LOGFIX-COLON-2c6e88"
		singleVal = "LOGFIX-SINGLE-51bc07"
		basicVal  = "QWxhZGRpbjpvcGVuIHNlc2FtZQ=="
		pctVal    = "LOGFIX-PCT-83af10"
		fragVal   = "LOGFIX-FRAG-9d2e41"
		authVal   = "LOGFIX-AUTH-77d4e9"
		secretVal = "LOGFIX-SECRET-22d9f0"
	)
	shapes := []struct {
		name       string
		inputs     []string
		forbidden  []string // full values that must be absent
		wantPrefix string   // first-8 prefix allowed to survive, else ""
		wantMarker bool     // a [redacted] marker must appear
	}{
		{"camelCase-privateKey-JSON",
			[]string{`{"privateKey": "` + fixWGPriv + `"}`},
			[]string{fixWGPriv}, "", true},
		{"camelCase-publicKey-JSON",
			[]string{`{"publicKey": "` + fixWGPub + `"}`},
			[]string{fixWGPub}, fixWGPub[:8], false},
		{"colon-form",
			[]string{"private_key: " + colonVal, "privateKey: " + colonVal},
			[]string{colonVal}, "", true},
		{"single-quote-JSON",
			[]string{`{'token': '` + singleVal + `'}`},
			[]string{singleVal}, "", true},
		{"authorization-basic",
			[]string{"Authorization: Basic " + basicVal, "Basic " + basicVal + " rejected"},
			[]string{basicVal}, "", true},
		{"percent-encoded-equals-query",
			[]string{"https://example.invalid/cb?auth_token%3D" + pctVal, "?auth_token%3D" + pctVal},
			[]string{pctVal}, "", true},
		{"bare-fragment",
			[]string{"https://example.invalid/reset#" + fragVal, "see #" + fragVal},
			[]string{fragVal}, "", false},
		{"bare-auth-equals",
			[]string{"auth=" + authVal},
			[]string{authVal}, "", true},
		{"bare-secret-equals",
			[]string{"secret=" + secretVal, "api_key=" + secretVal},
			[]string{secretVal}, "", true},
		{"double-quote-JSON-token (derived: already stripped)",
			[]string{`{"token": "` + fixAccessToken + `"}`},
			[]string{fixAccessToken}, "", true},
		{"bare-keyvalue-token (derived: already stripped)",
			[]string{"token=" + fixAccessToken},
			[]string{fixAccessToken}, "", true},
		{"bearer (derived: already stripped)",
			[]string{"Authorization: Bearer " + fixBearerVal},
			[]string{fixBearerVal}, "", true},
	}
	for _, sh := range shapes {
		t.Run(sh.name, func(t *testing.T) {
			for _, in := range sh.inputs {
				got := SafeString(in)
				for _, v := range sh.forbidden {
					if strings.Contains(got, v) {
						t.Errorf("SafeString(%q) = %q, want full value %q absent", in, got, v)
					}
				}
				if sh.wantPrefix != "" && !strings.Contains(got, sh.wantPrefix) {
					t.Errorf("SafeString(%q) = %q, want the 8-char public-key prefix %q present", in, got, sh.wantPrefix)
				}
				if sh.wantMarker && !strings.Contains(got, "[redacted]") {
					t.Errorf("SafeString(%q) = %q, want a [redacted] marker", in, got)
				}
				// Fragment marker: a URL fragment is
				// percent-encoded by url.String, so the
				// marker may appear in either spelling.
				if sh.name == "bare-fragment" && !strings.Contains(got, "#[redacted]") && !strings.Contains(got, "#%5Bredacted%5D") {
					t.Errorf("SafeString(%q) = %q, want a redacted fragment marker", in, got)
				}
			}
		})
	}
}

// TestSafeStringJSONQuoteCombinations (loop 4, (b)): all four
// key/value quote combinations must be stripped by ONE mechanism.
// The double-key/single-value form is the loop-3 survivor:
// {"token": 'VAL'} survived SafeString in all three paths.
// Non-secret JSON values survive byte-identical, and the key
// label survives with the value replaced.
func TestSafeStringJSONQuoteCombinations(t *testing.T) {
	t.Parallel()
	const val = "LOGFIX-QUOTECOMB-83af10"
	cases := []struct {
		name  string
		input string
	}{
		{"double-double", `{"token": "` + val + `"}`},
		{"single-single", `{'token': '` + val + `'}`},
		{"double-single", `{"token": '` + val + `'}`},
		{"single-double", `{'token': "` + val + `"}`},
		{"double-single-spaces", `{ "token" : '` + val + `' }`},
		{"single-double-spaces", `{ 'token' : "` + val + `" }`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := SafeString(tc.input)
			if strings.Contains(got, val) {
				t.Errorf("SafeString(%q) = %q, want fixture value absent", tc.input, got)
			}
			if !strings.Contains(got, "[redacted]") {
				t.Errorf("SafeString(%q) = %q, want a [redacted] marker", tc.input, got)
			}
			if !strings.Contains(got, "token") {
				t.Errorf("SafeString(%q) = %q, want the key label to survive", tc.input, got)
			}
		})
	}
	if got := SafeString(`{"name": "Alice", 'city': 'Lisbon'}`); got != `{"name": "Alice", 'city': 'Lisbon'}` {
		t.Errorf("non-secret JSON changed: %q", got)
	}
	// A value carrying the other quote type must still be
	// stripped in full: the value ends at its own closing
	// quote, not at an embedded apostrophe.
	if got := SafeString(`{"token": "LOGFIX-APOS-77d4e9don't"}`); strings.Contains(got, "LOGFIX-APOS-77d4e9") || strings.Contains(got, "don't") {
		t.Errorf("apostrophe value not stripped in full: %q", got)
	}
}

// TestSafeStringUnicodeEscapedKeys (loop 4, (c)(i)): a key whose
// secret word is spelled with \u escapes must be recognised:
// the escapes are decoded before the vocabulary match. A
// non-secret escaped key survives byte-identical.
func TestSafeStringUnicodeEscapedKeys(t *testing.T) {
	t.Parallel()
	const val = "LOGFIX-UNIESC-22d9f0"
	cases := []string{
		`{"tok\u0065n": "` + val + `"}`,
		`{"\u0074oken": "` + val + `"}`,
		`{"tok\u0065\u006e": "` + val + `"}`,
		`{"TOK\u0045N": "` + val + `"}`,
		`{'tok\u0065n': '` + val + `'}`,
	}
	for _, in := range cases {
		if got := SafeString(in); strings.Contains(got, val) {
			t.Errorf("SafeString(%q) = %q, want fixture value absent", in, got)
		}
	}
	if in := `{"na\u006de": "Alice"}`; SafeString(in) != in {
		t.Errorf("non-secret escaped key changed: SafeString(%q) = %q", in, SafeString(in))
	}
}

// TestSafeStringJSONScalarValues (loop 4, (c)(ii)): a
// secret-keyed JSON value of non-string type must be redacted.
// Covered: string, integer, float, negative, exponent,
// boolean, null. A non-secret numeric value survives.
func TestSafeStringJSONScalarValues(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		input  string
		absent string
	}{
		{"string", `{"token": "LOGFIX-SCALAR-83af10"}`, "LOGFIX-SCALAR-83af10"},
		{"integer", `{"token": 987654321}`, "987654321"},
		{"float", `{"token": 98765.4321}`, "98765.4321"},
		{"negative", `{"token": -987654321}`, "-987654321"},
		{"exponent", `{"token": 9.876e8}`, "9.876e8"},
		{"bool-true", `{"token": true}`, "true"},
		{"bool-false", `{"secret": false}`, "false"},
		{"null", `{"token": null}`, "null"},
		{"numeric-single-quote", `{'token': 987654321}`, "987654321"},
		{"numeric-publicKey-prefix", `{"publicKey": 98765432109}`, "98765432109"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := SafeString(tc.input)
			if strings.Contains(got, tc.absent) {
				t.Errorf("SafeString(%q) = %q, want %q absent", tc.input, got, tc.absent)
			}
			if !strings.Contains(got, "[redacted]") && tc.name != "numeric-publicKey-prefix" {
				t.Errorf("SafeString(%q) = %q, want a [redacted] marker", tc.input, got)
			}
		})
	}
	if got := SafeString(`{"publicKey": 98765432109}`); !strings.Contains(got, "98765432") || strings.Contains(got, "98765432109") {
		t.Errorf("publicKey numeric value = %q, want the first-8-chars prefix only", got)
	}
	if in := `{"count": 42, "ratio": 1.5}`; SafeString(in) != in {
		t.Errorf("non-secret numeric JSON changed: %q", SafeString(in))
	}
}

// TestSafeStringDigitlessFragments (loop 4, (c)(iii)): bare
// fragment handling must not depend on a digit floor. The rule
// (see safe.go): any bare fragment of 4+ fragment characters
// is stripped, digit or not. Fragments shorter than 4 are
// ordinary anchors/issue refs and survive.
func TestSafeStringDigitlessFragments(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		input  string
		absent string
	}{
		{"digitless-long", "see #LOGFIXFRAG-abcdef", "LOGFIXFRAG-abcdef"},
		{"digitless-mixed", "see #abcdef-ghijkl", "abcdef-ghijkl"},
		{"digit-long", "see #LOGFIXFRAG-123456", "LOGFIXFRAG-123456"},
		{"digitless-url", "https://example.invalid/reset#LOGFIXFRAG-abcdef", "LOGFIXFRAG-abcdef"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := SafeString(tc.input)
			if strings.Contains(got, tc.absent) {
				t.Errorf("SafeString(%q) = %q, want %q absent", tc.input, got, tc.absent)
			}
			if !strings.Contains(got, "#[redacted]") && !strings.Contains(got, "#%5Bredacted%5D") {
				t.Errorf("SafeString(%q) = %q, want a redacted fragment marker", tc.input, got)
			}
		})
	}
	if in := "see #abc and issue #42"; SafeString(in) != in {
		t.Errorf("short fragments changed: SafeString(%q) = %q", in, SafeString(in))
	}
}

// TestSafeStringPercentEncodedKeyNames (loop 4, (c)(iv)):
// percent-encoded key names must be decoded before matching,
// and an encoded equals separator must be recognised, in bare
// key=value and colon forms alike. A non-secret encoded key
// survives byte-identical.
func TestSafeStringPercentEncodedKeyNames(t *testing.T) {
	t.Parallel()
	const val = "LOGFIX-PCTKEY-51bc07"
	cases := []string{
		"%61uth_token=" + val,
		"%61uth_token%3D" + val,
		"%61uth_token%253D" + val,
		"auth_token%3D" + val,
		"auth%5Ftoken=" + val,
		"%74oken=" + val,
		"%74oken%3D" + val,
		"%74oken%3A " + val,
		"%70assword=" + val,
	}
	for _, in := range cases {
		if got := SafeString(in); strings.Contains(got, val) {
			t.Errorf("SafeString(%q) = %q, want fixture value absent", in, got)
		}
	}
	if in := "%6Eext=/ok"; SafeString(in) != in {
		t.Errorf("non-secret encoded key changed: SafeString(%q) = %q", in, SafeString(in))
	}
}

// TestSafeStringEscapedQuoteJSON (loop 4, (b)/(d)): a JSON pair
// inside a %q-escaped payload (GatewayError.Error() renders
// its payload %q, so the pair appears as {\"token\": ...})
// must be stripped like the unescaped form. The same scanner
// handles both; the escaped form must not leak through the
// error-string path.
func TestSafeStringEscapedQuoteJSON(t *testing.T) {
	t.Parallel()
	const val = "LOGFIX-ESCQ-83af10"
	cases := []string{
		`conn: gateway status=500 payload="{\"token\": \"` + val + `\"}"`,
		`conn: gateway status=500 payload="{\"token\": '` + val + `'}"`,
		`{"tok\u0065n": \"` + val + `\"}`,
		`payload="{\"token\": 987654321}"`,
	}
	for _, in := range cases {
		got := SafeString(in)
		if strings.Contains(got, val) || strings.Contains(got, "987654321") {
			t.Errorf("SafeString(%q) = %q, want the secret value absent", in, got)
		}
		if !strings.Contains(got, "[redacted]") {
			t.Errorf("SafeString(%q) = %q, want a [redacted] marker", in, got)
		}
	}
	if in := `payload="{\"name\": \"Alice\"}"`; SafeString(in) != in {
		t.Errorf("non-secret escaped JSON changed: SafeString(%q) = %q", in, SafeString(in))
	}
}

// TestSafeStringIdempotentUserinfoURL (loop 4, (a)): SafeString
// is idempotent even for a URL whose userinfo it already
// redacted: the "[redacted]" marker's angle brackets make
// url.Parse fail, and a second pass must keep the host, not
// collapse the URL to [redacted-url]. (The Emit + sink
// writer apply SafeString twice to every line.)
func TestSafeStringIdempotentUserinfoURL(t *testing.T) {
	t.Parallel()
	in := "see https://user:s3cret@example.com/x?auth_token=tok123"
	once := SafeString(in)
	if !strings.Contains(once, "example.com") {
		t.Fatalf("first pass %q, want the host to survive", once)
	}
	if strings.Contains(once, "s3cret") || strings.Contains(once, "tok123") {
		t.Fatalf("first pass %q leaks fixture values", once)
	}
	twice := SafeString(once)
	if once != twice {
		t.Errorf("SafeString not idempotent for a userinfo URL:\n once: %q\ntwice: %q", once, twice)
	}
}

// TestSafeStringLoop7Separators (loop 7, item R2): the
// separator between a secret label and its `=`/`:` must cover
// NBSP (U+00A0), EM SPACE (U+2003), and vertical tab, on the
// label side as well as the value side. The loop-6 bypass was
// the label-side separator: `token\u00A0=SECRET` survived
// because Go's \s does not match those characters.
func TestSafeStringLoop7Separators(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   string
		want string
	}{
		{name: "nbsp-equals-before", in: "token\u00A0=LOGFIX-SEP-1", want: "token=[redacted]"},
		{name: "emspace-equals-before", in: "token\u2003=LOGFIX-SEP-2", want: "token=[redacted]"},
		{name: "vtab-equals-before", in: "token\v=LOGFIX-SEP-3", want: "token=[redacted]"},
		{name: "nbsp-colon-before", in: "token\u00A0:LOGFIX-SEP-4", want: "token: [redacted]"},
		{name: "emspace-colon-before", in: "token\u2003:LOGFIX-SEP-5", want: "token: [redacted]"},
		{name: "vtab-colon-before", in: "token\v:LOGFIX-SEP-6", want: "token: [redacted]"},
		{name: "nbsp-equals-after", in: "token=\u00A0LOGFIX-SEP-7", want: "token=[redacted]"},
		{name: "emspace-colon-after", in: "token:\u2003LOGFIX-SEP-8", want: "token: [redacted]"},
		{name: "plain-equals", in: "token=LOGFIX-SEP-9", want: "token=[redacted]"},
		{name: "plain-colon", in: "token: LOGFIX-SEP-10", want: "token: [redacted]"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := SafeString(tc.in); got != tc.want {
				t.Errorf("SafeString(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
	// Non-secret prose carrying the same characters survives
	// byte-identical: the wider separator class must not
	// over-redact ordinary text.
	if in := "hello\u00A0world and a\u2003b"; SafeString(in) != in {
		t.Errorf("SafeString(%q) = %q, want it unchanged", in, SafeString(in))
	}
}

// TestSafeStringLoop7NewlineJSONValue (loop 7, item R2):
// scanQuoted must survive a literal newline inside a JSON
// string value, so a secret value spanning lines is still
// stripped instead of copied verbatim.
func TestSafeStringLoop7NewlineJSONValue(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   string
		want string
	}{
		{name: "double-quoted", in: "{\"token\": \"LOGFIX-NL-1\nTAIL\"}", want: "{\"token\": \"[redacted]\"}"},
		{name: "single-quoted", in: "{'token': 'LOGFIX-NL-2\nTAIL'}", want: "{'token': '[redacted]'}"},
		{name: "newline-in-key", in: "{\"tok\nen\": \"x\"}", want: "{\"tok\nen\": \"x\"}"},
		{name: "non-secret-newline", in: "{\"name\": \"Alice\nBob\"}", want: "{\"name\": \"Alice\nBob\"}"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := SafeString(tc.in); got != tc.want {
				t.Errorf("SafeString(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
