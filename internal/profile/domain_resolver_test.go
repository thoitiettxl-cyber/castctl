// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package profile

// ApplyDomainResolverDefault (R8): the pure runtime-only default
// for outbound server-address resolution. Table-driven over
// sing-box-parsed option.Outbound values; all fixtures fake.

import (
	"strings"
	"testing"

	"github.com/sagernet/sing-box/option"
)

func mustParseOutboundForDefault(t *testing.T, raw string) option.Outbound {
	t.Helper()
	ob, err := parseOutbound([]byte(raw))
	if err != nil {
		t.Fatalf("parseOutbound(%s): %v", raw, err)
	}
	return ob
}

func resolverOf(t *testing.T, ob option.Outbound) *option.DomainResolveOptions {
	t.Helper()
	w, ok := ob.Options.(option.DialerOptionsWrapper)
	if !ok {
		// Types without dialer options (selector, urltest,
		// ...) carry no DomainResolver: report unset.
		return nil
	}
	d := w.TakeDialerOptions()
	return d.DomainResolver
}

func TestApplyDomainResolverDefault(t *testing.T) {
	const local = LocalBootstrapServerTag
	cases := []struct {
		name     string
		raw      string
		localTag string
		want     string // "" means: DomainResolver must stay unset
	}{
		{
			name:     "hostname http unset gets local",
			raw:      `{"type":"http","tag":"p","server":"proxy.test","server_port":8080}`,
			localTag: local,
			want:     local,
		},
		{
			name:     "hostname socks unset gets local",
			raw:      `{"type":"socks","tag":"s","server":"proxy.test","server_port":1080,"version":"5"}`,
			localTag: local,
			want:     local,
		},
		{
			name:     "IP http unset untouched",
			raw:      `{"type":"http","tag":"p","server":"127.0.0.1","server_port":8080}`,
			localTag: local,
			want:     "",
		},
		{
			name:     "bracketed IPv6 unset untouched",
			raw:      `{"type":"http","tag":"p","server":"[::1]","server_port":8080}`,
			localTag: local,
			want:     "",
		},
		{
			name:     "explicit string resolver honoured",
			raw:      `{"type":"http","tag":"p","server":"proxy.test","server_port":8080,"domain_resolver":"dns1"}`,
			localTag: local,
			want:     "dns1",
		},
		{
			name:     "explicit object resolver honoured",
			raw:      `{"type":"http","tag":"p","server":"proxy.test","server_port":8080,"domain_resolver":{"server":"dns1","timeout":"5s"}}`,
			localTag: local,
			want:     "dns1",
		},
		{
			name:     "empty string resolver treated as unset",
			raw:      `{"type":"http","tag":"p","server":"proxy.test","server_port":8080,"domain_resolver":""}`,
			localTag: local,
			want:     local,
		},
		{
			name:     "empty object resolver treated as unset",
			raw:      `{"type":"http","tag":"p","server":"proxy.test","server_port":8080,"domain_resolver":{}}`,
			localTag: local,
			want:     local,
		},
		{
			name:     "trailing-dot hostname gets local",
			raw:      `{"type":"http","tag":"p","server":"proxy.test.","server_port":8080}`,
			localTag: local,
			want:     local,
		},
		{
			name:     "uppercase hostname gets local",
			raw:      `{"type":"http","tag":"p","server":"PROXY.TEST","server_port":8080}`,
			localTag: local,
			want:     local,
		},
		{
			name:     "selector untouched",
			raw:      `{"type":"selector","tag":"sel","outbounds":["a","b"]}`,
			localTag: local,
			want:     "",
		},
		{
			name:     "no local tag means no default",
			raw:      `{"type":"http","tag":"p","server":"proxy.test","server_port":8080}`,
			localTag: "",
			want:     "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ob := mustParseOutboundForDefault(t, tc.raw)
			// Snapshot the caller's resolver before the call:
			// the default must be applied to a copy only, for
			// every case (unset, empty, and explicit alike).
			before := resolverOf(t, ob)
			beforeServer := ""
			if before != nil {
				beforeServer = before.Server
			}
			got := ApplyDomainResolverDefault(ob, tc.localTag)
			if tc.name == "selector untouched" && got.Options != ob.Options {
				t.Fatalf("selector options were copied/replaced; want the input returned unchanged")
			}
			res := resolverOf(t, got)
			if tc.want == "" {
				if res != nil {
					t.Fatalf("DomainResolver = %+v, want unset", res)
				}
			} else {
				if res == nil || res.Server != tc.want {
					t.Fatalf("DomainResolver = %+v, want server %q", res, tc.want)
				}
			}
			after := resolverOf(t, ob)
			afterServer := ""
			if after != nil {
				afterServer = after.Server
			}
			if before == nil && after != nil && afterServer != "" {
				t.Fatalf("input mutated: DomainResolver = %+v, want unset", after)
			}
			if before != nil && afterServer != beforeServer {
				t.Fatalf("input mutated: DomainResolver server = %q, want %q", afterServer, beforeServer)
			}
		})
	}
}

func TestApplyDomainResolverDefaultDirectUntouched(t *testing.T) {
	// "direct" is never defaulted: its domain_resolver governs
	// request domains, not a server address. An explicit value
	// on direct is honoured as sing-box parses it (kept as-is).
	ob := mustParseOutboundForDefault(t, `{"type":"direct","tag":"d","domain_resolver":"dns1"}`)
	got := ApplyDomainResolverDefault(ob, LocalBootstrapServerTag)
	res := resolverOf(t, got)
	if res == nil || res.Server != "dns1" {
		t.Fatalf("direct DomainResolver = %+v, want server dns1 untouched", res)
	}
	ob2 := mustParseOutboundForDefault(t, `{"type":"direct","tag":"d"}`)
	got2 := ApplyDomainResolverDefault(ob2, LocalBootstrapServerTag)
	if res := resolverOf(t, got2); res != nil {
		t.Fatalf("direct DomainResolver = %+v, want unset", res)
	}
}

func TestApplyDomainResolverDefaultObjectFieldsPreserved(t *testing.T) {
	ob := mustParseOutboundForDefault(t, `{"type":"http","tag":"p","server":"proxy.test","server_port":8080,"domain_resolver":{"server":"dns1","timeout":"5s","strategy":"ipv4_only"}}`)
	got := ApplyDomainResolverDefault(ob, LocalBootstrapServerTag)
	res := resolverOf(t, got)
	if res == nil || res.Server != "dns1" || res.Strategy.String() != "ipv4_only" {
		t.Fatalf("object domain_resolver = %+v, want server dns1 + ipv4_only preserved", res)
	}
}

func TestApplyDomainResolverDefaultValueFormOptions(t *testing.T) {
	// Parsed options are pointers in practice; a struct-value
	// Options must still get the default on a copy, with the
	// caller's value untouched.
	opts := option.HTTPOutboundOptions{}
	opts.Server = "proxy.test"
	opts.ServerPort = 8080
	ob := option.Outbound{Type: "http", Tag: "p", Options: opts}
	got := ApplyDomainResolverDefault(ob, LocalBootstrapServerTag)
	res := resolverOf(t, got)
	if res == nil || res.Server != LocalBootstrapServerTag {
		t.Fatalf("DomainResolver = %+v, want server %q", res, LocalBootstrapServerTag)
	}
	orig, ok := ob.Options.(option.HTTPOutboundOptions)
	if !ok {
		t.Fatalf("input options type = %T", ob.Options)
	}
	if orig.DomainResolver != nil {
		t.Fatalf("input mutated: DomainResolver = %+v", orig.DomainResolver)
	}
}

// TestParseDomainResolverForms (R5f, corrected by probe): the
// empty-object and unknown-field shapes are probed here, not
// assumed. sing-box's stdlib UnmarshalJSON check ("empty
// domain_resolver.server", option/outbound.go:153) is bypassed
// by the UnmarshalJSONContext path castctl parses through, so
// {} parses; the runtime default then treats its empty server
// as unset. No new parse-time validation is added in this PR
// (Q4); the probe result is recorded for reviewers.
func TestParseDomainResolverForms(t *testing.T) {
	empty, err := parseOutbound([]byte(`{"type":"http","tag":"p","server":"proxy.test","server_port":8080,"domain_resolver":{}}`))
	if err != nil {
		t.Fatalf("empty object domain_resolver must parse on the UnmarshalJSONContext path: %v", err)
	}
	if res := resolverOf(t, empty); res != nil && res.Server != "" {
		t.Fatalf("empty object resolver = %+v, want nil or an empty-server DomainResolveOptions (treated as unset by the default)", res)
	}
	got := ApplyDomainResolverDefault(empty, LocalBootstrapServerTag)
	if res := resolverOf(t, got); res == nil || res.Server != LocalBootstrapServerTag {
		t.Fatalf("empty object resolver after default = %+v, want server %q", res, LocalBootstrapServerTag)
	}
	unknown, uerr := parseOutbound([]byte(`{"type":"http","tag":"p","server":"proxy.test","server_port":8080,"domain_resolver":{"server":"local","bogus_field":1}}`))
	t.Logf("unknown-field domain_resolver: parsed=%v err=%v", unknown.Type, uerr)
	if uerr == nil {
		t.Logf("unknown fields in domain_resolver are ACCEPTED on this parse path (no strict rejection); recorded, not asserted")
	}
	ob, err := parseOutbound([]byte(`{"type":"http","tag":"p","server":"proxy.test","server_port":8080,"domain_resolver":""}`))
	if err != nil {
		t.Fatalf("empty string domain_resolver must parse (treated as unset by the default): %v", err)
	}
	if res := resolverOf(t, ob); res == nil || res.Server != "" {
		t.Fatalf("empty string resolver = %+v, want an empty-server DomainResolveOptions", res)
	}
	// Object form round-trips byte-for-byte in raw form.
	raw := `{"type":"http","tag":"p","server":"proxy.test","server_port":8080,"domain_resolver":{"server":"dns1","timeout":"5s"}}`
	ob, err = parseOutbound([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	out, err := marshalSing(&ob)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), `"domain_resolver"`) || !strings.Contains(string(out), `"dns1"`) {
		t.Fatalf("marshalled outbound = %s; want the authored domain_resolver preserved", out)
	}
}

// TestRedactOutboundJSONKeepsDomainResolver (D6): redaction
// keeps the (non-secret) domain_resolver value visible while
// redacting credentials on the same object.
func TestRedactOutboundJSONKeepsDomainResolver(t *testing.T) {
	input := `{"type":"http","tag":"p","server":"proxy.test","server_port":8080,"username":"FAKE-USER","password":"FAKE-SECRET-PW","domain_resolver":{"server":"local","timeout":"5s"}}`
	out, err := RedactOutboundJSON([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if strings.Contains(s, "FAKE-SECRET-PW") {
		t.Fatalf("redacted output contains the password: %s", s)
	}
	if !strings.Contains(s, `"domain_resolver"`) || !strings.Contains(s, `"local"`) {
		t.Fatalf("redacted output lost domain_resolver: %s", s)
	}
	if !strings.Contains(s, `"<redacted>"`) {
		t.Fatalf("redacted output has no <redacted> marker: %s", s)
	}
}
