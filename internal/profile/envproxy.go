// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package profile

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/sagernet/sing-box/option"
	"github.com/thoitiettxl-cyber/muse-cli/go/internal/redact"
)

// EnvProxyOutboundTag is the tag of the outbound OutboundFromEnv
// builds. It is stable so the S7 outbound identity (see identity.go)
// is stable for a given proxy URL.
const EnvProxyOutboundTag = "env-proxy"

// OutboundFromEnv builds ONE explicit sing-box "http" outbound from
// the proxy environment variables. It is the ONLY place in product
// code that reads proxy env vars (grep for HTTP_PROXY/HTTPS_PROXY/
// ALL_PROXY/NO_PROXY in this package must show only this file); every
// other path treats "direct" as truly direct and never consults the
// environment implicitly (fail-closed, CLIProxyAPI notes §7 items
// 1-2, plan decision: env proxy modelled ONLY as an explicit http
// outbound).
//
// Mapping (from outbound/context.go, the PR1 decision):
//
//   - Variable precedence: HTTPS_PROXY/https_proxy, then
//     HTTP_PROXY/http_proxy, then ALL_PROXY/all_proxy. Within one
//     family the uppercase spelling wins. The first non-empty value
//     wins; empty values are skipped. The gateway is HTTPS, so the
//     HTTPS variable is the relevant one; HTTP_PROXY/ALL_PROXY are
//     fallbacks for environments that only set those.
//   - The URL's scheme must be http or https; anything else
//     (socks5, ftp, a bare host) is an error, never a silent
//     direct fallback. The literal values "direct" and "none"
//     (CLIProxyAPI's explicit bypass spellings) mean no outbound.
//   - server/server_port come from the URL host/port (default port
//     80 for http, 443 for https). Path, query, and fragment are
//     dropped: a CONNECT proxy has no use for them.
//   - Userinfo maps to username/password. The password is carried in
//     the returned options (the proxy needs it to dial) and must
//     never be logged or displayed: display paths go through
//     RedactOutboundJSON/redact.Value, and every error from this
//     function is passed through redact.String so a malformed URL
//     never echoes its credentials.
//   - An https:// URL sets tls.enabled (SNI defaults to the proxy
//     host; verification stays on). CA bytes/path come from config,
//     never from env vars, and tls.insecure is never set here: a
//     TLS-intercepting proxy is configured in the profile,
//     not smuggled in through the environment.
//   - NO_PROXY/no_proxy cannot be expressed in a single outbound
//     object (it is a per-host bypass list, and this builder is
//     given no target host). The only honoured form is "*": bypass
//     everything, i.e. no outbound. Any other entry is ignored and
//     documented as such: all profile traffic uses the one outbound,
//     fail-closed. This matches the egress proxy's need: the
//     public Muse hosts are never NO_PROXY entries, and loopback
//     bypass lists do not apply to profile traffic.
//
// It returns (nil, nil) when no proxy variable is set, when the
// chosen value is "direct"/"none", or when NO_PROXY is "*".
// A malformed URL is an error (exit 2 at command level).
func OutboundFromEnv() (*option.Outbound, error) {
	if noProxyBypass() {
		return nil, nil
	}
	raw, name, ok := firstProxyEnv()
	if !ok {
		return nil, nil
	}
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, nil
	}
	lowered := strings.ToLower(trimmed)
	if lowered == "direct" || lowered == "none" {
		return nil, nil
	}
	u, err := url.Parse(trimmed)
	if err != nil {
		return nil, envProxyError(name, trimmed, err)
	}
	if u == nil {
		return nil, envProxyError(name, trimmed, fmt.Errorf("empty url"))
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return nil, envProxyError(name, trimmed, fmt.Errorf("unsupported proxy scheme %q: want http or https", u.Scheme))
	}
	host := u.Hostname()
	if host == "" {
		return nil, envProxyError(name, trimmed, fmt.Errorf("proxy url has no host"))
	}
	port := 80
	if scheme == "https" {
		port = 443
	}
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return nil, envProxyError(name, trimmed, fmt.Errorf("invalid proxy port %q", p))
		}
		port = n
	}
	opts := &option.HTTPOutboundOptions{
		Username: "",
		Password: "",
	}
	opts.Server = host
	opts.ServerPort = uint16(port)
	if u.User != nil {
		opts.Username = u.User.Username()
		if pw, ok := u.User.Password(); ok {
			opts.Password = pw
		}
	}
	if scheme == "https" {
		opts.TLS = &option.OutboundTLSOptions{Enabled: true}
	}
	ob := option.Outbound{
		Type:    "http",
		Tag:     EnvProxyOutboundTag,
		Options: opts,
	}
	// Validate through sing-box's own parser, the same path
	// ParseSingleConfig uses, so the returned object is guaranteed
	// to be one a config file could have carried.
	rawJSON, err := marshalSing(&ob)
	if err != nil {
		return nil, err
	}
	parsed, err := parseOutbound(rawJSON)
	if err != nil {
		return nil, envProxyError(name, trimmed, err)
	}
	return &parsed, nil
}

// firstProxyEnv returns the first set, non-empty proxy variable in
// precedence order, with its name. Uppercase spellings win within a
// family.
func firstProxyEnv() (value, name string, ok bool) {
	for _, family := range [][2]string{
		{"HTTPS_PROXY", "https_proxy"},
		{"HTTP_PROXY", "http_proxy"},
		{"ALL_PROXY", "all_proxy"},
	} {
		for _, n := range family {
			if v, present := os.LookupEnv(n); present && strings.TrimSpace(v) != "" {
				return v, n, true
			}
		}
	}
	return "", "", false
}

// noProxyBypass reports whether NO_PROXY/no_proxy disables proxying
// entirely ("*"). Per-host entries are ignored (see OutboundFromEnv).
func noProxyBypass() bool {
	for _, n := range []string{"NO_PROXY", "no_proxy"} {
		if v, present := os.LookupEnv(n); present {
			for _, entry := range strings.Split(v, ",") {
				if strings.TrimSpace(entry) == "*" {
					return true
				}
			}
		}
	}
	return false
}

// envProxyError builds the error for a bad proxy URL. The raw URL and
// the parse error may both embed credentials (url.Parse echoes its
// input), so the whole message goes through redact.String; only the
// variable name is echoed unredacted.
func envProxyError(name, raw string, err error) error {
	msg := fmt.Sprintf("invalid proxy url in %s %q: %v", name, raw, err)
	return newConfigError(redact.String(msg))
}
