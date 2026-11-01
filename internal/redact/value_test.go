// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package redact

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestIsSecretKey(t *testing.T) {
	t.Parallel()
	secret := []string{
		"password", "private_key", "public_key", "pre_shared_key",
		"uuid", "short_id", "token", "certificate", "key", "obfs",
		"psk", "private_key_passphrase", "auth", "auth_str",
		"auth_key", "vm_id", "node_id", "subscription_action_id",
		"authorization", "secret", "cookie",
		// sing-box 1.14.4 schema fields (B1 fix): ACME/Origin CA,
		// OpenConnect, Tailscale, OpenVPN, TLS client material,
		// Snell. See TestValueNewSecretKeys for the schema cites.
		"api_token", "access_key_secret", "account_key",
		"client_key_password", "mca_key", "mesh_psk",
		"security_token", "static_key", "submission_key",
		"zone_token", "origin_ca_key", "client_key",
		"client_certificate", "userkey", "mca_key_password",
		"mac_key",
		// Plugin-era additions (loop 2): generic secret key
		// spellings plugins and sing-box-style fragments use.
		"api_key", "auth_token", "client_secret",
		"session_key", "access_key",
	}
	for _, k := range secret {
		if !IsSecretKey(k) {
			t.Errorf("IsSecretKey(%q) = false, want true", k)
		}
	}
	// Case-insensitive, exact match only.
	cases := []struct {
		key  string
		want bool
	}{
		{"Password", true},
		{"PASSWORD", true},
		{"Authorization", true},
		{"AUTHORIZATION", true},
		{"Auth_Str", true},
		{"Vm_Id", true},
		{"Api_Token", true},
		{"CLIENT_KEY", true},
		{"Client_Certificate", true},
		{"MAC_KEY", true},
		{"UserKey", true},
		{"username", false},
		{"server", false},
		{"type", false},
		{"tag", false},
		{"my_token", false},
		{"tokenize", false},
		{"password2", false},
		{"vmid", false},
		{"vmId", false},
		{"auth-token", false},
		{"obfs_password", false},
		{"api_token2", false},
		{"my_api_token", false},
		{"client_key_path", false},
		{"key_id", false},
		{"access_key_id", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := IsSecretKey(tc.key); got != tc.want {
			t.Errorf("IsSecretKey(%q) = %v, want %v", tc.key, got, tc.want)
		}
	}
}

func TestValue(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   any
		want any
	}{
		{
			name: "secret string replaced wholesale",
			in:   map[string]any{"password": "FAKE-SECRET-VALUE"},
			want: map[string]any{"password": Marker},
		},
		{
			name: "secret key case insensitive",
			in:   map[string]any{"Password": "x", "AUTHORIZATION": "Bearer abc"},
			want: map[string]any{"Password": Marker, "AUTHORIZATION": Marker},
		},
		{
			name: "secret object replaced wholesale",
			in:   map[string]any{"obfs": map[string]any{"type": "salamander", "password": "x"}},
			want: map[string]any{"obfs": Marker},
		},
		{
			name: "secret array replaced wholesale",
			in:   map[string]any{"token": []any{"a", "b"}},
			want: map[string]any{"token": Marker},
		},
		{
			name: "secret number and bool replaced wholesale",
			in:   map[string]any{"key": 42, "secret": true},
			want: map[string]any{"key": Marker, "secret": Marker},
		},
		{
			name: "secret nil replaced wholesale",
			in:   map[string]any{"password": nil},
			want: map[string]any{"password": Marker},
		},
		{
			name: "nested objects and users array",
			in: map[string]any{
				"tls":   map[string]any{"reality": map[string]any{"public_key": "PUB", "short_id": "SID"}},
				"users": []any{map[string]any{"username": "u", "password": "p"}},
			},
			want: map[string]any{
				"tls":   map[string]any{"reality": map[string]any{"public_key": Marker, "short_id": Marker}},
				"users": []any{map[string]any{"username": "u", "password": Marker}},
			},
		},
		{
			name: "url userinfo in any string value at any depth",
			in: map[string]any{
				"note": "see https://user:s3cret@host.example/x",
				"nested": map[string]any{
					"endpoint_url": "https://alice:pw@api.example/path",
				},
				"list": []any{"https://carol@three.example/x", "plain https://example.com/path"},
			},
			want: map[string]any{
				"note": "see https://<redacted>@host.example/x",
				"nested": map[string]any{
					"endpoint_url": "https://<redacted>@api.example/path",
				},
				"list": []any{"https://<redacted>@three.example/x", "plain https://example.com/path"},
			},
		},
		{
			name: "bare email and url without userinfo untouched",
			in:   map[string]any{"email": "bob@example.com", "server": "https://example.com:8443/path"},
			want: map[string]any{"email": "bob@example.com", "server": "https://example.com:8443/path"},
		},
		{
			name: "value does not strip query tokens or bearer tokens",
			in:   "https://host.example/x?vm_id=v1&auth_token=tok123",
			want: "https://host.example/x?vm_id=v1&auth_token=tok123",
		},
		{
			name: "value does not redact json password fragment in a string",
			in:   `{"password": "x"}`,
			want: `{"password": "x"}`,
		},
		{
			name: "non secret keys and scalars preserved",
			in:   map[string]any{"type": "socks", "server_port": 1080, "enabled": true, "note": nil},
			want: map[string]any{"type": "socks", "server_port": 1080, "enabled": true, "note": nil},
		},
		{
			name: "top level slice",
			in:   []any{"https://u:p@h/x", map[string]any{"uuid": "U"}, "plain"},
			want: []any{"https://<redacted>@h/x", map[string]any{"uuid": Marker}, "plain"},
		},
		{
			name: "top level string",
			in:   "https://u:p@h/x",
			want: "https://<redacted>@h/x",
		},
		{
			name: "nil stays nil",
			in:   nil,
			want: nil,
		},
		{
			name: "empty map stays empty",
			in:   map[string]any{},
			want: map[string]any{},
		},
		{
			name: "json number literal preserved",
			in:   map[string]any{"ratio": json.Number("1.50")},
			want: map[string]any{"ratio": json.Number("1.50")},
		},
		{
			name: "typed string map",
			in:   map[string]string{"password": "x", "note": "https://u:p@h/x"},
			want: map[string]string{"password": Marker, "note": "https://<redacted>@h/x"},
		},
		{
			name: "typed string slice",
			in:   []string{"https://u:p@h/x", "plain"},
			want: []string{"https://<redacted>@h/x", "plain"},
		},
		{
			name: "header map string slice secret key zeroed",
			in:   map[string][]string{"Authorization": {"Bearer abcdefgh"}},
			want: map[string][]string{"Authorization": nil},
		},
		{
			name: "string array",
			in:   [2]string{"https://u:p@h/x", "plain"},
			want: [2]string{"https://<redacted>@h/x", "plain"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := Value(tc.in); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("Value(%#v) = %#v, want %#v", tc.in, got, tc.want)
			}
		})
	}
}

// TestValueNewSecretKeys pins the 16 sing-box 1.14.4 secret keys
// added by the B1 fix, each nested inside a realistic
// outbound-shaped map. Schema cites (module cache,
// sing-box@v1.14.4/option):
//
//	api_token: origin_ca.go:15, tls_acme.go:105 (Cloudflare)
//	access_key_secret: tls_acme.go:99 (AliDNS)
//	account_key: acme.go:21
//	client_key_password: openconnect.go:104
//	mca_key: openconnect.go:107
//	mesh_psk: tailscale.go:90
//	security_token: tls_acme.go:101 (AliDNS)
//	static_key: openvpn.go:36,89
//	submission_key: openconnect.go:114
//	zone_token: tls_acme.go:106 (Cloudflare)
//	origin_ca_key: origin_ca.go:16
//	client_key: tls.go:123, openconnect.go:102, openvpn.go:129
//	client_certificate: tls.go:121, openconnect.go:100, openvpn.go:127
//	userkey: snell.go:81,137
//	mca_key_password: openconnect.go:109
//	mac_key: tls_acme.go:31 (ACMEExternalAccountOptions)
//
// For each key the redacted leaf must be exactly Marker, and the
// fake secret value must not appear anywhere in the JSON encoding
// of the redacted output (the key NAME itself stays: only values
// are redacted, as pinned by TestValue).
func TestValueNewSecretKeys(t *testing.T) {
	t.Parallel()
	fake := func(key string) string { return "FAKE-SECRET-" + strings.ToUpper(key) }
	cases := []struct {
		name         string
		key          string
		in           map[string]any
		path         []string
		siblingPath  []string
		siblingValue any
	}{
		{
			name: "api_token cloudflare dns01",
			key:  "api_token",
			in: map[string]any{"tls": map[string]any{"acme": map[string]any{
				"dns01_challenge": map[string]any{"provider": "cloudflare", "api_token": fake("api_token")},
			}}},
			path: []string{"tls", "acme", "dns01_challenge", "api_token"},
		},
		{
			name: "access_key_secret alidns dns01",
			key:  "access_key_secret",
			in: map[string]any{"tls": map[string]any{"acme": map[string]any{
				"dns01_challenge": map[string]any{"provider": "alidns", "access_key_secret": fake("access_key_secret")},
			}}},
			path: []string{"tls", "acme", "dns01_challenge", "access_key_secret"},
		},
		{
			name: "account_key acme provider",
			key:  "account_key",
			in: map[string]any{"tls": map[string]any{"certificate_provider": map[string]any{
				"provider": "acme", "account_key": fake("account_key"),
			}}},
			path: []string{"tls", "certificate_provider", "account_key"},
		},
		{
			name: "client_key_password openconnect",
			key:  "client_key_password",
			in:   map[string]any{"type": "openconnect", "client_key_password": fake("client_key_password")},
			path: []string{"client_key_password"},
		},
		{
			name: "mca_key openconnect list",
			key:  "mca_key",
			in:   map[string]any{"type": "openconnect", "mca_key": []any{fake("mca_key")}},
			path: []string{"mca_key"},
		},
		{
			name: "mesh_psk tailscale",
			key:  "mesh_psk",
			in:   map[string]any{"type": "tailscale", "mesh_psk": fake("mesh_psk")},
			path: []string{"mesh_psk"},
		},
		{
			name: "security_token alidns dns01",
			key:  "security_token",
			in: map[string]any{"tls": map[string]any{"acme": map[string]any{
				"dns01_challenge": map[string]any{"provider": "alidns", "security_token": fake("security_token")},
			}}},
			path: []string{"tls", "acme", "dns01_challenge", "security_token"},
		},
		{
			name: "static_key openvpn list",
			key:  "static_key",
			in:   map[string]any{"type": "openvpn", "static_key": []any{fake("static_key")}},
			path: []string{"static_key"},
		},
		{
			name: "submission_key openconnect",
			key:  "submission_key",
			in:   map[string]any{"type": "openconnect", "submission_key": fake("submission_key")},
			path: []string{"submission_key"},
		},
		{
			name: "zone_token cloudflare dns01",
			key:  "zone_token",
			in: map[string]any{"tls": map[string]any{"acme": map[string]any{
				"dns01_challenge": map[string]any{"provider": "cloudflare", "zone_token": fake("zone_token")},
			}}},
			path: []string{"tls", "acme", "dns01_challenge", "zone_token"},
		},
		{
			name: "origin_ca_key cloudflare origin ca",
			key:  "origin_ca_key",
			in: map[string]any{"tls": map[string]any{"certificate_provider": map[string]any{
				"provider": "cloudflare", "origin_ca_key": fake("origin_ca_key"),
			}}},
			path: []string{"tls", "certificate_provider", "origin_ca_key"},
		},
		{
			name: "client_key tls list",
			key:  "client_key",
			in:   map[string]any{"tls": map[string]any{"client_key": []any{fake("client_key")}}},
			path: []string{"tls", "client_key"},
		},
		{
			name: "client_certificate tls list",
			key:  "client_certificate",
			in:   map[string]any{"tls": map[string]any{"client_certificate": []any{fake("client_certificate")}}},
			path: []string{"tls", "client_certificate"},
		},
		{
			name: "userkey snell",
			key:  "userkey",
			in:   map[string]any{"type": "snell", "psk": "FAKE-PSK-ALREADY-COVERED", "userkey": fake("userkey")},
			path: []string{"userkey"},
		},
		{
			name: "mca_key_password openconnect",
			key:  "mca_key_password",
			in:   map[string]any{"type": "openconnect", "mca_key_password": fake("mca_key_password")},
			path: []string{"mca_key_password"},
		},
		{
			name: "mac_key acme external account",
			key:  "mac_key",
			in: map[string]any{"tls": map[string]any{"acme": map[string]any{
				"external_account": map[string]any{"key_id": "FAKE-KEY-ID-NOT-SECRET", "mac_key": fake("mac_key")},
			}}},
			path:         []string{"tls", "acme", "external_account", "mac_key"},
			siblingPath:  []string{"tls", "acme", "external_account", "key_id"},
			siblingValue: "FAKE-KEY-ID-NOT-SECRET",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := Value(tc.in)
			if leaf := valueAtPath(t, got, tc.path); leaf != Marker {
				t.Errorf("Value leaf %v = %#v, want Marker %q", tc.path, leaf, Marker)
			}
			if tc.siblingPath != nil {
				if leaf := valueAtPath(t, got, tc.siblingPath); leaf != tc.siblingValue {
					t.Errorf("Value sibling %v = %#v, want %#v (non-secret siblings survive)", tc.siblingPath, leaf, tc.siblingValue)
				}
			}
			encoded, err := json.Marshal(got)
			if err != nil {
				t.Fatalf("json.Marshal(redacted) = %v", err)
			}
			if strings.Contains(string(encoded), fake(tc.key)) {
				t.Errorf("redacted output still contains the fake %s value: %s", tc.key, encoded)
			}
		})
	}
}

// valueAtPath walks nested map[string]any values along path and
// returns the leaf. It fails the test when a step is missing or
// is not a map.
func valueAtPath(t *testing.T, v any, path []string) any {
	t.Helper()
	cur := v
	for i, k := range path {
		m, ok := cur.(map[string]any)
		if !ok {
			t.Fatalf("path %v: step %d (%q) is %T, want map[string]any", path, i, k, cur)
		}
		child, ok := m[k]
		if !ok {
			t.Fatalf("path %v: missing key %q at step %d", path, k, i)
		}
		cur = child
	}
	return cur
}

// TestValueHeaderMapsRedactedWholesale pins the fail-closed header
// rule: under a map key "headers" or "extra_headers" (exact after
// lowercasing, at any depth) EVERY value is replaced with Marker,
// whatever the header name — including a benign X-Custom value.
// Header NAMES (map keys) stay; only values are redacted.
func TestValueHeaderMapsRedactedWholesale(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   any
		want any
	}{
		{
			name: "http headers all names redacted including benign",
			in: map[string]any{"type": "http", "headers": map[string]any{
				"Proxy-Authorization": "FAKE-PROXY-AUTH",
				"X-Api-Key":           "FAKE-API-KEY",
				"Authorization":       "FAKE-AUTH",
				"Cookie":              "FAKE-COOKIE",
				"X-Custom":            "benign-value",
			}},
			want: map[string]any{"type": "http", "headers": map[string]any{
				"Proxy-Authorization": Marker,
				"X-Api-Key":           Marker,
				"Authorization":       Marker,
				"Cookie":              Marker,
				"X-Custom":            Marker,
			}},
		},
		{
			name: "extra_headers variant",
			in: map[string]any{"type": "naive", "extra_headers": map[string]any{
				"X-Custom":      "benign-value",
				"Authorization": "FAKE-AUTH",
			}},
			want: map[string]any{"type": "naive", "extra_headers": map[string]any{
				"X-Custom":      Marker,
				"Authorization": Marker,
			}},
		},
		{
			name: "header values as arrays redacted wholesale",
			in: map[string]any{"headers": map[string]any{
				"X-Api-Key": []any{"FAKE-KEY-1", "FAKE-KEY-2"},
				"X-Custom":  []any{"benign"},
			}},
			want: map[string]any{"headers": map[string]any{
				"X-Api-Key": Marker,
				"X-Custom":  Marker,
			}},
		},
		{
			name: "nested transport headers and capitalised key",
			in: map[string]any{"transport": map[string]any{"Headers": map[string]any{
				"X-Custom": "benign-value",
			}}},
			want: map[string]any{"transport": map[string]any{"Headers": map[string]any{
				"X-Custom": Marker,
			}}},
		},
		{
			name: "headers inside a slice element",
			in: map[string]any{"outbounds": []any{map[string]any{"headers": map[string]any{
				"X-Custom": "benign-value",
			}}}},
			want: map[string]any{"outbounds": []any{map[string]any{"headers": map[string]any{
				"X-Custom": Marker,
			}}}},
		},
		{
			name: "headers value that is a string is replaced wholesale",
			in:   map[string]any{"headers": "FAKE-HEADER-STRING"},
			want: map[string]any{"headers": Marker},
		},
		{
			name: "headers nil stays nil",
			in:   map[string]any{"headers": nil},
			want: map[string]any{"headers": nil},
		},
		{
			name: "header name fields are not header maps",
			in: map[string]any{
				"early_data_header_name":          "X-Custom",
				"proxy_protocol_accept_no_header": true,
				"custom_headers":                  map[string]any{"X-Api-Key": "keep-me"},
			},
			want: map[string]any{
				"early_data_header_name":          "X-Custom",
				"proxy_protocol_accept_no_header": true,
				"custom_headers":                  map[string]any{"X-Api-Key": "keep-me"},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := Value(tc.in); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("Value(%#v) = %#v, want %#v", tc.in, got, tc.want)
			}
			encoded, err := json.Marshal(Value(tc.in))
			if err != nil {
				t.Fatalf("json.Marshal(redacted) = %v", err)
			}
			for _, leaked := range []string{"FAKE-PROXY-AUTH", "FAKE-API-KEY", "FAKE-AUTH", "FAKE-COOKIE", "FAKE-KEY-1", "FAKE-HEADER-STRING"} {
				if strings.Contains(string(encoded), leaked) {
					t.Errorf("redacted output still contains %q: %s", leaked, encoded)
				}
			}
		})
	}
}

// TestValueHeaderMapsTypedAndOrdered pins the wholesale header rule
// for the typed-map (reflection) and OrderedMap shapes Value also
// handles: header values in a map[string]string become Marker, in a
// map[string][]string they are zeroed (the established convention
// for a secret value that cannot hold a Marker string), and an
// OrderedMap keeps its keys and order with Marker values.
func TestValueHeaderMapsTypedAndOrdered(t *testing.T) {
	t.Parallel()
	t.Run("typed string map", func(t *testing.T) {
		t.Parallel()
		in := map[string]any{"headers": map[string]string{
			"X-Custom":      "FAKE-HDR",
			"Authorization": "FAKE-HDR-2",
		}}
		want := map[string]any{"headers": map[string]string{
			"X-Custom":      Marker,
			"Authorization": Marker,
		}}
		if got := Value(in); !reflect.DeepEqual(got, want) {
			t.Errorf("Value(%#v) = %#v, want %#v", in, got, want)
		}
	})
	t.Run("typed string slice map zeroed", func(t *testing.T) {
		t.Parallel()
		in := map[string]any{"extra_headers": map[string][]string{
			"X-Custom": {"FAKE-HDR"},
		}}
		want := map[string]any{"extra_headers": map[string][]string{
			"X-Custom": nil,
		}}
		if got := Value(in); !reflect.DeepEqual(got, want) {
			t.Errorf("Value(%#v) = %#v, want %#v", in, got, want)
		}
	})
	t.Run("ordered map", func(t *testing.T) {
		t.Parallel()
		headers := newFakeOrderedMap()
		headers.OrderedSet("X-Custom", "benign-value")
		headers.OrderedSet("Authorization", "FAKE-AUTH")
		in := newFakeOrderedMap()
		in.OrderedSet("type", "http")
		in.OrderedSet("headers", headers)
		got, ok := Value(in).(*fakeOrderedMap)
		if !ok {
			t.Fatalf("Value(ordered) type = %T, want *fakeOrderedMap", Value(in))
		}
		if !reflect.DeepEqual(got.OrderedKeys(), []string{"type", "headers"}) {
			t.Errorf("ordered keys = %v, want [type headers]", got.OrderedKeys())
		}
		nested, ok := mustOrdered(t, got, "headers")
		if !ok {
			return
		}
		if !reflect.DeepEqual(nested.OrderedKeys(), []string{"X-Custom", "Authorization"}) {
			t.Errorf("header keys = %v, want header names preserved in order", nested.OrderedKeys())
		}
		for _, k := range []string{"X-Custom", "Authorization"} {
			if v, _ := nested.OrderedGet(k); v != Marker {
				t.Errorf("headers[%q] = %v, want Marker", k, v)
			}
		}
	})
}

func mustOrdered(t *testing.T, m *fakeOrderedMap, key string) (*fakeOrderedMap, bool) {
	t.Helper()
	v, ok := m.OrderedGet(key)
	if !ok {
		t.Errorf("missing key %q", key)
		return nil, false
	}
	nested, ok := v.(*fakeOrderedMap)
	if !ok {
		t.Errorf("key %q type = %T, want *fakeOrderedMap", key, v)
		return nil, false
	}
	return nested, true
}

func TestValueDoesNotMutateInput(t *testing.T) {
	t.Parallel()
	in := map[string]any{
		"password": "FAKE-SECRET",
		"nested": map[string]any{
			"note": "https://u:p@h/x",
			"list": []any{"https://u:p@h/x"},
		},
	}
	before := map[string]any{
		"password": "FAKE-SECRET",
		"nested": map[string]any{
			"note": "https://u:p@h/x",
			"list": []any{"https://u:p@h/x"},
		},
	}
	out := Value(in)
	if !reflect.DeepEqual(in, before) {
		t.Errorf("Value mutated its input: %#v, want %#v", in, before)
	}
	// Mutating the output must not reach back into the input.
	outMap, ok := out.(map[string]any)
	if !ok {
		t.Fatalf("Value(map) type = %T, want map[string]any", out)
	}
	outMap["password"] = "changed"
	if in["password"] != "FAKE-SECRET" {
		t.Errorf("output shares storage with input: password = %v", in["password"])
	}
}

func TestValueStructPassesThroughUnchanged(t *testing.T) {
	t.Parallel()
	type holder struct {
		Password string
		Note     string
	}
	in := holder{Password: "FAKE-SECRET", Note: "https://u:p@h/x"}
	got, ok := Value(in).(holder)
	if !ok {
		t.Fatalf("Value(struct) type = %T, want holder", Value(in))
	}
	if got != in {
		t.Errorf("Value(struct) = %#v, want %#v (structs must be marshalled first)", got, in)
	}
}

// fakeOrderedMap is a minimal OrderedMap for testing Value's
// ordered-object path without importing the profile package.
type fakeOrderedMap struct {
	keys   []string
	values map[string]any
}

func newFakeOrderedMap() *fakeOrderedMap {
	return &fakeOrderedMap{values: make(map[string]any)}
}

func (m *fakeOrderedMap) OrderedKeys() []string {
	out := make([]string, len(m.keys))
	copy(out, m.keys)
	return out
}

func (m *fakeOrderedMap) OrderedGet(key string) (any, bool) {
	v, ok := m.values[key]
	return v, ok
}

func (m *fakeOrderedMap) OrderedSet(key string, value any) {
	if _, ok := m.values[key]; !ok {
		m.keys = append(m.keys, key)
	}
	m.values[key] = value
}

func (m *fakeOrderedMap) NewOrderedMap() OrderedMap {
	return newFakeOrderedMap()
}

func TestValueOrderedMap(t *testing.T) {
	t.Parallel()
	in := newFakeOrderedMap()
	in.OrderedSet("zebra", "1")
	in.OrderedSet("password", "FAKE-SECRET")
	in.OrderedSet("apple", "2")
	nested := newFakeOrderedMap()
	nested.OrderedSet("uuid", "U")
	nested.OrderedSet("note", "https://u:p@h/x")
	in.OrderedSet("nested", nested)
	in.OrderedSet("list", []any{nested})

	got, ok := Value(in).(*fakeOrderedMap)
	if !ok {
		t.Fatalf("Value(ordered) type = %T, want *fakeOrderedMap", Value(in))
	}
	wantKeys := []string{"zebra", "password", "apple", "nested", "list"}
	if !reflect.DeepEqual(got.OrderedKeys(), wantKeys) {
		t.Errorf("ordered keys = %v, want %v", got.OrderedKeys(), wantKeys)
	}
	if v, _ := got.OrderedGet("password"); v != Marker {
		t.Errorf("password = %v, want %q", v, Marker)
	}
	if v, _ := got.OrderedGet("zebra"); v != "1" {
		t.Errorf("zebra = %v, want %q", v, "1")
	}
	nestedGot, ok := got.values["nested"].(*fakeOrderedMap)
	if !ok {
		t.Fatalf("nested type = %T, want *fakeOrderedMap", got.values["nested"])
	}
	if v, _ := nestedGot.OrderedGet("uuid"); v != Marker {
		t.Errorf("nested uuid = %v, want %q", v, Marker)
	}
	if v, _ := nestedGot.OrderedGet("note"); v != "https://<redacted>@h/x" {
		t.Errorf("nested note = %v, want redacted url", v)
	}
	// The input ordered map is not mutated.
	if v, _ := in.OrderedGet("password"); v != "FAKE-SECRET" {
		t.Errorf("Value mutated its ordered input: password = %v", v)
	}
}
