// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package profile

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/option"
	"github.com/thoitiettxl-cyber/muse-cli/go/internal/redact"
)

var proxyEnvNames = []string{
	"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
	"http_proxy", "https_proxy", "all_proxy", "no_proxy",
}

// clearProxyEnv empties every proxy variable: the ambient VM env sets
// real ones, so each test starts hermetic. No t.Parallel in this file:
// t.Setenv forbids it.
func clearProxyEnv(t *testing.T) {
	t.Helper()
	for _, name := range proxyEnvNames {
		t.Setenv(name, "")
	}
}

func setProxyEnv(t *testing.T, vars map[string]string) {
	t.Helper()
	clearProxyEnv(t)
	for name, value := range vars {
		t.Setenv(name, value)
	}
}

func httpOpts(t *testing.T, ob *option.Outbound) *option.HTTPOutboundOptions {
	t.Helper()
	opts, ok := ob.Options.(*option.HTTPOutboundOptions)
	if !ok {
		t.Fatalf("outbound options = %T; want *option.HTTPOutboundOptions", ob.Options)
	}
	return opts
}

func TestOutboundFromEnvUnset(t *testing.T) {
	clearProxyEnv(t)
	ob, err := OutboundFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if ob != nil {
		t.Errorf("OutboundFromEnv with no proxy env = %+v; want nil", ob)
	}
}

func TestOutboundFromEnvHTTPWithAuth(t *testing.T) {
	setProxyEnv(t, map[string]string{"HTTPS_PROXY": "http://proxy-user:FAKE-PW@proxy.example:3128"})
	ob, err := OutboundFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if ob == nil {
		t.Fatal("OutboundFromEnv = nil; want an http outbound")
	}
	if ob.Type != "http" || ob.Tag != EnvProxyOutboundTag {
		t.Errorf("outbound = type %q tag %q; want http/%s", ob.Type, ob.Tag, EnvProxyOutboundTag)
	}
	opts := httpOpts(t, ob)
	if opts.Server != "proxy.example" || opts.ServerPort != 3128 {
		t.Errorf("server = %s:%d; want proxy.example:3128", opts.Server, opts.ServerPort)
	}
	// Credentials are carried (the proxy needs them to dial)...
	if opts.Username != "proxy-user" || opts.Password != "FAKE-PW" {
		t.Errorf("auth = %q/%q; want proxy-user/FAKE-PW", opts.Username, opts.Password)
	}
	if opts.TLS != nil {
		t.Errorf("TLS = %+v; want nil for an http:// proxy url", opts.TLS)
	}
	// ...but never survive redaction of the serialised form.
	raw, err := marshalSing(ob)
	if err != nil {
		t.Fatal(err)
	}
	redacted, err := RedactOutboundJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(redacted), "FAKE-PW") {
		t.Errorf("redacted outbound leaks password: %s", redacted)
	}
	// username is not a secret key (it is not in the redaction list);
	// only the password must be gone.
	if !strings.Contains(string(redacted), `"password": "<redacted>"`) {
		t.Errorf("redacted outbound does not redact password: %s", redacted)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	redactedValue, err := json.Marshal(redact.Value(decoded))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(redactedValue), "FAKE-PW") {
		t.Errorf("redact.Value output leaks password: %s", redactedValue)
	}
}

func TestOutboundFromEnvHTTPSEnablesTLS(t *testing.T) {
	setProxyEnv(t, map[string]string{"HTTPS_PROXY": "https://proxy.example"})
	ob, err := OutboundFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	opts := httpOpts(t, ob)
	if opts.Server != "proxy.example" || opts.ServerPort != 443 {
		t.Errorf("server = %s:%d; want proxy.example:443 (https default)", opts.Server, opts.ServerPort)
	}
	if opts.TLS == nil || !opts.TLS.Enabled {
		t.Errorf("TLS = %+v; want enabled for an https:// proxy url", opts.TLS)
	}
	if opts.TLS != nil && opts.TLS.Insecure {
		t.Error("TLS.Insecure = true; verification must stay on (CA comes from config, never env)")
	}
}

func TestOutboundFromEnvPrecedence(t *testing.T) {
	cases := []struct {
		name   string
		vars   map[string]string
		server string
	}{
		{
			name:   "https wins over http and all",
			vars:   map[string]string{"HTTPS_PROXY": "http://https-proxy:1111", "HTTP_PROXY": "http://http-proxy:2222", "ALL_PROXY": "http://all-proxy:3333"},
			server: "https-proxy",
		},
		{
			name:   "http wins over all",
			vars:   map[string]string{"HTTP_PROXY": "http://http-proxy:2222", "ALL_PROXY": "http://all-proxy:3333"},
			server: "http-proxy",
		},
		{
			name:   "all alone",
			vars:   map[string]string{"ALL_PROXY": "http://all-proxy:3333"},
			server: "all-proxy",
		},
		{
			name:   "lowercase honoured",
			vars:   map[string]string{"https_proxy": "http://lower-proxy:4444"},
			server: "lower-proxy",
		},
		{
			name:   "uppercase wins within family",
			vars:   map[string]string{"HTTPS_PROXY": "http://upper-proxy:5555", "https_proxy": "http://lower-proxy:4444"},
			server: "upper-proxy",
		},
		{
			name:   "empty https skipped",
			vars:   map[string]string{"HTTPS_PROXY": "  ", "HTTP_PROXY": "http://http-proxy:2222"},
			server: "http-proxy",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setProxyEnv(t, tc.vars)
			ob, err := OutboundFromEnv()
			if err != nil {
				t.Fatal(err)
			}
			if ob == nil {
				t.Fatal("OutboundFromEnv = nil; want an outbound")
			}
			if got := httpOpts(t, ob).Server; got != tc.server {
				t.Errorf("server = %q; want %q", got, tc.server)
			}
		})
	}
}

func TestOutboundFromEnvDefaultsAndDrops(t *testing.T) {
	setProxyEnv(t, map[string]string{"HTTP_PROXY": "http://proxy.example/some/path?token=FAKE-TOKEN#frag"})
	ob, err := OutboundFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	opts := httpOpts(t, ob)
	if opts.ServerPort != 80 {
		t.Errorf("port = %d; want 80 (http default)", opts.ServerPort)
	}
	raw, err := marshalSing(ob)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "/some/path") || strings.Contains(string(raw), "FAKE-TOKEN") {
		t.Errorf("serialised outbound keeps url path/query: %s", raw)
	}
}

func TestOutboundFromEnvIPv6(t *testing.T) {
	setProxyEnv(t, map[string]string{"HTTP_PROXY": "http://[::1]:8080"})
	ob, err := OutboundFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if got := httpOpts(t, ob).Server; got != "::1" {
		t.Errorf("server = %q; want ::1", got)
	}
}

func TestOutboundFromEnvMalformed(t *testing.T) {
	cases := map[string]string{
		"socks scheme":   "socks5://proxy.example:1080",
		"ftp scheme":     "ftp://proxy.example:21",
		"bare host":      "proxy.example:3128",
		"no host":        "http:///path",
		"bad port":       "http://proxy.example:abc",
		"port too large": "http://proxy.example:99999",
		"port zero":      "http://proxy.example:0",
	}
	for name, value := range cases {
		t.Run(name, func(t *testing.T) {
			setProxyEnv(t, map[string]string{"HTTPS_PROXY": value})
			ob, err := OutboundFromEnv()
			if err == nil {
				t.Fatalf("OutboundFromEnv(%q) = %+v, nil; want error", value, ob)
			}
			if ExitCode(err) != 2 {
				t.Errorf("ExitCode = %d; want 2", ExitCode(err))
			}
		})
	}
}

func TestOutboundFromEnvErrorRedactsCredentials(t *testing.T) {
	// The parse error echoes the URL; the password must not survive.
	setProxyEnv(t, map[string]string{"HTTPS_PROXY": "http://proxy-user:FAKE-PW@proxy.example:abc"})
	_, err := OutboundFromEnv()
	if err == nil {
		t.Fatal("want error for bad port")
	}
	if strings.Contains(err.Error(), "FAKE-PW") || strings.Contains(err.Error(), "proxy-user:") {
		t.Errorf("error leaks credentials: %v", err)
	}
	if !strings.Contains(err.Error(), "HTTPS_PROXY") {
		t.Errorf("error does not name the variable: %v", err)
	}
}

func TestOutboundFromEnvNoProxyAndBypassSpellings(t *testing.T) {
	setProxyEnv(t, map[string]string{
		"HTTPS_PROXY": "http://proxy.example:3128",
		"NO_PROXY":    "*",
	})
	if ob, err := OutboundFromEnv(); err != nil || ob != nil {
		t.Errorf("NO_PROXY=* => ob=%+v err=%v; want nil, nil", ob, err)
	}

	// Per-host NO_PROXY entries are ignored (documented): the single
	// outbound cannot express per-host bypass.
	setProxyEnv(t, map[string]string{
		"HTTPS_PROXY": "http://proxy.example:3128",
		"NO_PROXY":    "localhost,127.0.0.1",
	})
	if ob, err := OutboundFromEnv(); err != nil || ob == nil {
		t.Errorf("per-host NO_PROXY => ob=%+v err=%v; want an outbound", ob, err)
	}

	for _, spelling := range []string{"direct", "none", "DIRECT"} {
		setProxyEnv(t, map[string]string{"HTTPS_PROXY": spelling})
		if ob, err := OutboundFromEnv(); err != nil || ob != nil {
			t.Errorf("HTTPS_PROXY=%q => ob=%+v err=%v; want nil, nil", spelling, ob, err)
		}
	}
}

func TestOutboundFromEnvParsesAsConfigOutbound(t *testing.T) {
	setProxyEnv(t, map[string]string{"HTTPS_PROXY": "https://proxy-user:FAKE-PW@proxy.example:8443"})
	ob, err := OutboundFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := marshalSing(ob)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := ParseSingleConfig([]byte(`{"profiles":{"p":{"outbound":`+string(raw)+`}}}`), "/base")
	if err != nil {
		t.Fatalf("env outbound rejected by ParseSingleConfig: %v (raw %s)", err, raw)
	}
	if cfg.Profiles["p"].Outbound.Kind != OutboundInline {
		t.Errorf("kind = %s; want inline", cfg.Profiles["p"].Outbound.Kind)
	}
}
