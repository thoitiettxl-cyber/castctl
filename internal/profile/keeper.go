// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package profile

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// The top-level `keeper` config block and its resolution.
//
// Schema (Boss decision 2026-10-31, D3): an optional LIST of entries.
// Each entry has exactly these keys; unknown keys are rejected, like
// every other strict section in this file:
//
//	{"tag": string, "profile": string, "browser": string,
//	 "interval": string, "notify": string,
//	 "credentials": string, "wake_on_gateway_failure": bool,
//	 "retry_backoff": [string], "expiring_within": string,
//	 "wake_attempts": number, "relogin_attempts": number,
//	 "proxy_dial_timeout": string, "proxy_max_header_bytes": number,
//	 "proxy_max_body_bytes": number, "proxy_allowed_hosts": [string],
//	 "relogin_match_timeout": string, "relogin_cookie_timeout": string,
//	 "relogin_poll_interval": string, "relogin_attach_timeout": string,
//	 "relogin_cancel_timeout": string, "observe_settle_timeout": string,
//	 "observe_timeout": string, "observe_inventory_cap": number}
//
//   - `tag` (required): unique name for the entry. Entries reference
//     each other by tag, sing-box style. Tags are exact: no
//     surrounding whitespace (rejected, never trimmed), no
//     `/`, `\`, or control characters, never "." or ".." —
//     tags name owner files under the profile directory.
//   - `profile` (required): the name of a key of SingleConfig.Profiles.
//     A name that is not a profile key is a dangling reference, exit
//     2, exactly like a dangling outbound tag in validateTagGraph.
//     One entry per profile: two entries naming the same profile is
//     a config error (two keepers would race one cookies file).
//   - `browser` (optional since the cookie keep-alive work): the CDP
//     debug URL of the already-running Chrome that holds the
//     profile's login, e.g. "http://127.0.0.1:9226/". Loopback
//     only: the host must be 127.0.0.1, ::1, or localhost, the
//     scheme http or ws, and a port must be present. A
//     non-loopback browser URL is a config error: the debug port
//     is an unauthenticated local privilege boundary and castctl
//     must never be told to reach a remote browser. Two entries
//     must not share one browser URL: one CDP endpoint is one
//     browser instance, and profiles must never share mutable
//     browser state. No default port is ever assumed. An entry
//     WITHOUT a browser key is a keep-alive-only entry: the tick
//     persists Set-Cookie rotations and wakes a sleeping VM, but
//     cannot re-export from a browser; when cookies die it stops
//     (or re-logs in headless, when a `credentials` reference is
//     present) and alerts instead of exporting.
//   - `credentials` (optional): the tag of an entry in the
//     top-level `credentials` block naming THIS profile. Absence
//     means no auto re-login: when cookies die the entry stops
//     and alerts. A dangling tag, or a tag naming another
//     profile, is a config error, exit 2.
//   - `wake_on_gateway_failure` (optional bool, default true):
//     when true, a tick whose cheap chain succeeds but whose
//     gateway handshake fails wakes the VM (bounded attempts)
//     before declaring the entry transient. When false, the
//     tick reports transient without waking.
//   - `retry_backoff` (optional): the transient-retry ladder as
//     a list of duration strings, e.g. ["5m", "15m", "45m"].
//     Zero value (key absent or empty) means the documented
//     default ladder ["5m", "15m", "45m"], max 3 retries. Every
//     element must parse, be positive, and be at most
//     MaxKeeperInterval; the list must have at least one and
//     at most MaxRetryBackoffSteps entries. No hardcoded ladder
//     remains: the tick reads the entry's ladder.
//   - `expiring_within` (optional): the window, as a duration
//     string, inside which a driving cookie's expiry counts as
//     "expiring" for `auth status` and for the tick's
//     keep-alive urgency. Zero value means the documented
//     default of 72h. Must parse, be positive, at most
//     MaxKeeperInterval.
//   - `wake_attempts` (optional number, default 3): the maximum
//     wake attempts per incident (a gateway-failure incident
//     in one tick). Must be a positive integer, at most
//     MaxKeeperAttempts.
//   - `relogin_attempts` (optional number, default 3): the
//     maximum headless re-login attempts per incident. Must be
//     a positive integer, at most MaxKeeperAttempts. (The
//     "1 re-login per tick" gate in G1 is enforced by the tick:
//     a tick performs at most one re-login sequence; the cap
//     bounds the sequence's internal retries.)
//   - `proxy_dial_timeout` (optional duration string, default
//     30s): one upstream dial through the S2 loopback proxy.
//     Positive, at most MaxProxyDialTimeout (1m).
//   - `proxy_max_header_bytes` (optional number, default
//     65536): the largest request header block the S2 proxy
//     accepts. Positive, at most MaxProxyHeaderBytes.
//   - `proxy_max_body_bytes` (optional number, default
//     16777216): the largest plain-HTTP request body the S2
//     proxy forwards. Positive, at most MaxProxyBodyBytes.
//   - `proxy_allowed_hosts` (optional array of host strings,
//     default ["auth.muse.ai", "muse.ai", "www.facebook.com",
//     "www.instagram.com", "auth.meta.com"]): the ONLY hosts
//     the S2 proxy dials. Entries are hostnames or IPv4
//     literals: no scheme, port, userinfo, path, query,
//     wildcard, or IPv6 literal. Matching is exact on the
//     lowercased host (trailing dots ignored). A target
//     whose host is not listed is refused without a dial,
//     and a literal IP in a loopback, link-local, or
//     private range is refused even
//     when it is explicitly listed: the range rule is
//     absolute and listing does NOT override it (the
//     default list contains no such address). The range rule
//     recognises canonical literals, trailing dots in any
//     number, and inet_aton-style shorthand (see
//     internal/outbound); other spellings match exactly as
//     hostnames. To reach a
//     refused-range address, list a hostname that resolves
//     to it at the egress.
//     An absent key — or an entry without one — means the
//     default list; an explicitly empty list is a config
//     error.
//   - `relogin_match_timeout` (optional duration string,
//     default 30s): how long the headless driver polls for
//     the login form (or a blocker) before declaring a
//     contract mismatch. Positive, at most
//     MaxReloginWaitTimeout (10m).
//   - `relogin_cookie_timeout` (optional duration string,
//     default 30s): how long the driver polls for the
//     harvested session cookie after submit. Positive, at
//     most MaxReloginWaitTimeout (10m).
//   - `relogin_poll_interval` (optional duration string,
//     default 500ms): the driver's snapshot poll cadence.
//     Positive, at most MaxReloginPollInterval (1m).
//   - `relogin_attach_timeout` (optional duration string,
//     default 10s): the dial timeout for attaching to an
//     already-running Chrome. Positive, at most
//     MaxProxyDialTimeout (1m).
//   - `relogin_cancel_timeout` (optional duration string,
//     default 10s): the bound on waiting for a launched
//     browser's cancel to reap it (a process that never
//     started is never reaped; the wait must not wedge the
//     tick). Positive, at most MaxProxyDialTimeout (1m).
//   - `observe_settle_timeout` (optional duration string,
//     default 15s): how long `auth observe-login` polls for
//     at least one form control before returning the
//     inventory. Positive, at most MaxReloginWaitTimeout
//     (10m).
//   - `observe_timeout` (optional duration string, default
//     90s): the whole `auth observe-login` run bound.
//     Positive, at most MaxReloginWaitTimeout (10m).
//   - `observe_inventory_cap` (optional number, default
//     200): the maximum form-control elements one observation
//     records. Positive, at most MaxObserveInventoryCap.
//
//   Every operational timeout, cap, and host above is a
//   config key with a documented default (Boss decision
//   S10, 2026-11-02): no hardcoded operational value
//   remains in the keeper-entry proxy/driver/observe code
//   paths these keys cover. Pre-existing timeouts outside
//   those paths (CDP discovery, keeper check, gateway
//   connect/heartbeat, Telegram notice send, single-flight
//   ownership, login-pause staleness, dialer transport)
//   stay as they were; see docs/config.md for the
//   inventory. The validation caps (MaxRetryBackoffSteps,
//   MaxKeeperAttempts, MaxProxyHeaderBytes,
//   MaxProxyBodyBytes, MaxObserveInventoryCap) are schema
//   bounds, not settings: they bound what a config value
//   may say, and are not themselves configurable.
//
// A nil *KeeperConfig on SingleConfig means the block was absent
// from the file, and the keeper is off: no behaviour changes, no
// ticking, no browser contact. An absent block is preserved on
// save (defaults stay runtime-only, the same presence precedent
// as the `log` block). A present block is preserved verbatim on
// save when its raw JSON was captured, exactly like `log` and
// `telegram`.
//
// Resolution is pure: it reads only its input, never the
// filesystem, never mutates. Validation runs at parse time in the
// ParseSingleConfig tail, after validateTagGraph, mirroring
// validateTelegram.

// DefaultKeeperInterval is the documented zero-value cadence for a
// keeper entry whose `interval` key is absent or empty: 24h. It is
// a stated default (docs/config.md), not a hidden hardcoded one:
// the adaptive rule in internal/keeper shortens it once an expiry
// is observed, and never lengthens beyond it.
const DefaultKeeperInterval = 24 * time.Hour

// MaxKeeperInterval bounds a configured `interval`: the
// ±20% jitter in the runner multiplies the delay as a
// float64, which overflows time.Duration (and wraps
// negative) above ~243 years. A 1-year cap keeps every
// jitter computation in range with wide margin; the 24h
// zero-value default is unchanged.
const MaxKeeperInterval = 365 * 24 * time.Hour

// MaxProxyDialTimeout bounds a configured
// `proxy_dial_timeout`: a dial through an outbound that
// takes longer than a minute is a broken path, not a slow
// one; the browser's own timeouts bound the rest.
const MaxProxyDialTimeout = time.Minute

// MaxReloginWaitTimeout bounds a configured
// `relogin_match_timeout`, `relogin_cookie_timeout`,
// `observe_settle_timeout`, and `observe_timeout`: ten
// minutes is far beyond any login page's settle time, and
// a longer wait would stall a tick past any useful alert
// window.
const MaxReloginWaitTimeout = 10 * time.Minute

// MaxReloginPollInterval bounds a configured
// `relogin_poll_interval`: a minute between polls is
// already a wedged browser. (The attach/cancel bounds use
// MaxProxyDialTimeout, the same 1m value, not this
// constant.)
const MaxReloginPollInterval = time.Minute

// DefaultRetryBackoff is the documented zero-value transient
// retry ladder for a keeper entry whose `retry_backoff` key is
// absent or empty: 5m, 15m, 45m, max 3 retries (Boss decision
// G1). It is a stated default (docs/config.md), not a hidden
// hardcoded one: the tick reads the entry's ladder, and this
// value is only the zero-value fallback.
var DefaultRetryBackoff = []time.Duration{5 * time.Minute, 15 * time.Minute, 45 * time.Minute}

// MaxRetryBackoffSteps bounds a configured `retry_backoff` list:
// more steps than this would let a transient incident stall the
// runner for longer than the backoff ladder can express
// usefully, and the bound keeps the config surface reviewable.
const MaxRetryBackoffSteps = 8

// DefaultExpiringWithin is the documented zero-value window for
// a keeper entry whose `expiring_within` key is absent or
// empty: 72h (Boss decision G1).
const DefaultExpiringWithin = 72 * time.Hour

// DefaultKeeperAttempts is the documented zero-value cap for
// `wake_attempts` and `relogin_attempts` when the key is absent:
// 3 attempts per incident (Boss decision G1).
const DefaultKeeperAttempts = 3

// MaxKeeperAttempts bounds a configured `wake_attempts` /
// `relogin_attempts` value.
const MaxKeeperAttempts = 10

// S10 operational defaults (Boss decision 2026-11-02): every
// timeout, cap, and host the keeper/driver/S2-proxy paths use
// is a keeper-entry key whose zero value is the constant
// below. The constants are the documented defaults
// (docs/config.md), not hidden hardcoded behaviour: the
// Effective* accessors return them only when the key is
// absent, and the driver/proxy read only the Effective*
// values.
const DefaultProxyDialTimeout = 30 * time.Second
const DefaultProxyMaxHeaderBytes = 64 << 10
const DefaultProxyMaxBodyBytes = 16 << 20
const DefaultReloginMatchTimeout = 30 * time.Second
const DefaultReloginCookieTimeout = 30 * time.Second
const DefaultReloginPollInterval = 500 * time.Millisecond
const DefaultReloginAttachTimeout = 10 * time.Second
const DefaultReloginCancelTimeout = 10 * time.Second
const DefaultObserveSettleTimeout = 15 * time.Second
const DefaultObserveTimeout = 90 * time.Second
const DefaultObserveInventoryCap = 200

// DefaultProxyAllowedHosts is the documented zero-value S2
// proxy allowlist: the login surface, proven load-blocking
// host by host by the 2026-11-03 read-only observation
// probe (each host's refusal failed the muse.ai page load
// until it was allowed): the app origin (muse.ai), the
// session/API host (auth.muse.ai), and the Meta Account
// login hosts the page needs to complete load
// (www.facebook.com, www.instagram.com, auth.meta.com).
// api.muse.ai is deliberately NOT listed: its refusal does
// not block the page load. No other host is reachable
// through the proxy unless the entry lists it.
var DefaultProxyAllowedHosts = []string{"auth.muse.ai", "muse.ai", "www.facebook.com", "www.instagram.com", "auth.meta.com"}

// MaxProxyHeaderBytes bounds a configured
// `proxy_max_header_bytes` value. MaxProxyBodyBytes bounds a
// configured `proxy_max_body_bytes` value.
// MaxObserveInventoryCap bounds a configured
// `observe_inventory_cap` value. These are schema bounds,
// not settings: they are not themselves configurable.
const MaxProxyHeaderBytes = 1 << 20
const MaxProxyBodyBytes = 1 << 30
const MaxObserveInventoryCap = 10000

// KeeperEntry is one parsed `keeper` list entry.
type KeeperEntry struct {
	Tag      string
	Profile  string
	Browser  string
	Interval time.Duration
	// IntervalSet reports whether the `interval` key was present
	// with a non-empty value. A zero Interval with IntervalSet
	// false means "use DefaultKeeperInterval".
	IntervalSet bool
	// Notify is "" (no notification) or "telegram".
	Notify string
	// Credentials is "" (no auto re-login) or the tag of a
	// `credentials` entry naming this profile.
	Credentials string
	// WakeOnGatewayFailure enables the auto-wake leg. WakeSet
	// reports whether the key was present; absent means true.
	WakeOnGatewayFailure bool
	WakeSet              bool
	// RetryBackoff is the entry's transient-retry ladder.
	// RetryBackoffSet reports whether the key was present
	// with a non-empty list; absent means DefaultRetryBackoff.
	RetryBackoff    []time.Duration
	RetryBackoffSet bool
	// ExpiringWithin is the "expiring" window. ExpiringSet
	// reports whether the key was present with a non-empty
	// value; absent means DefaultExpiringWithin.
	ExpiringWithin time.Duration
	ExpiringSet    bool
	// WakeAttempts / ReloginAttempts are the per-incident
	// attempt caps; the *Set flags report presence, absent
	// means DefaultKeeperAttempts.
	WakeAttempts    int
	WakeAttemptsSet bool
	ReloginAttempts int
	ReloginSet      bool
	// ProxyDialTimeout / ProxyMaxHeaderBytes /
	// ProxyMaxBodyBytes / ProxyAllowedHosts tune the S2
	// loopback proxy for launches from this entry. The *Set
	// flags report presence; absent means the S10 defaults.
	ProxyDialTimeout    time.Duration
	ProxyDialSet        bool
	ProxyMaxHeaderBytes int
	ProxyMaxHeaderSet   bool
	ProxyMaxBodyBytes   int
	ProxyMaxBodySet     bool
	ProxyAllowedHosts   []string
	ProxyHostsSet       bool
	// ReloginMatchTimeout / ReloginCookieTimeout /
	// ReloginPollInterval / ReloginAttachTimeout /
	// ReloginCancelTimeout tune the headless driver for
	// this entry. The *Set flags report presence; absent
	// means the S10 defaults.
	ReloginMatchTimeout  time.Duration
	ReloginMatchSet      bool
	ReloginCookieTimeout time.Duration
	ReloginCookieSet     bool
	ReloginPollInterval  time.Duration
	ReloginPollSet       bool
	ReloginAttachTimeout time.Duration
	ReloginAttachSet     bool
	ReloginCancelTimeout time.Duration
	ReloginCancelSet     bool
	// ObserveSettleTimeout / ObserveTimeout /
	// ObserveInventoryCap tune `auth observe-login` for
	// this entry's profile. The *Set flags report presence;
	// absent means the S10 defaults.
	ObserveSettleTimeout time.Duration
	ObserveSettleSet     bool
	ObserveTimeout       time.Duration
	ObserveTimeoutSet    bool
	ObserveInventoryCap  int
	ObserveInventorySet  bool

	raw []byte
}

// ValidateKeeperTag reports whether tag is a usable keeper
// entry tag. Tags name owner files ("keeper-<tag>.owner") and
// appear in stdout summaries, so they must be exact (no
// silent trimming: surrounding whitespace is REJECTED, not
// trimmed), contain no path separator, backslash, or control
// character (including newline), and must not be "." or ".."
// (path components). Interior spaces are allowed. The same
// rule is enforced at parse time and, as defence in depth,
// by AcquireSingleFlight for hand-built entries.
func ValidateKeeperTag(tag string) error {
	if tag == "" {
		return fmt.Errorf("keeper tag must not be empty")
	}
	if tag != strings.TrimSpace(tag) {
		return fmt.Errorf("keeper tag %q has surrounding whitespace", tag)
	}
	if tag == "." || tag == ".." {
		return fmt.Errorf("keeper tag %q is a path component", tag)
	}
	for _, r := range tag {
		if r == '/' || r == '\\' || unicode.IsControl(r) {
			return fmt.Errorf("keeper tag %q contains a forbidden character", tag)
		}
	}
	return nil
}

// entries in file order. A nil *KeeperConfig means the block was
// absent.
// KeeperConfig is one parsed top-level `keeper` block: the list of
// entries in file order. A nil *KeeperConfig means the block was absent.
type KeeperConfig struct {
	Entries []*KeeperEntry

	raw []byte
}

// RawKeeper returns a defensive copy of the raw `keeper` JSON when
// the block was parsed from a file, or nil. It mirrors the
// raw-preservation accessors used by other blocks.
func (c *SingleConfig) RawKeeper() []byte {
	if c == nil || len(c.rawKeeper) == 0 {
		return nil
	}
	cp := make([]byte, len(c.rawKeeper))
	copy(cp, c.rawKeeper)
	return cp
}

var keeperEntryKeys = map[string]bool{
	"tag": true, "profile": true, "browser": true, "interval": true, "notify": true,
	"credentials": true, "wake_on_gateway_failure": true, "retry_backoff": true,
	"expiring_within": true, "wake_attempts": true, "relogin_attempts": true,
	"proxy_dial_timeout": true, "proxy_max_header_bytes": true, "proxy_max_body_bytes": true,
	"proxy_allowed_hosts": true, "relogin_match_timeout": true, "relogin_cookie_timeout": true,
	"relogin_poll_interval": true, "relogin_attach_timeout": true, "relogin_cancel_timeout": true,
	"observe_settle_timeout": true, "observe_timeout": true, "observe_inventory_cap": true,
}

// normalizeAllowedHost validates one `proxy_allowed_hosts`
// entry and returns its match form: lowercased, all
// trailing dots removed (D12: every normalisation pass
// strips all dots, so a multi-dot entry collapses to the
// same form a request collapses to). Entries are hostnames or IPv4 literals only:
// no scheme, port, userinfo, path, query, fragment,
// wildcard, bracket, or whitespace. An entry that parses as
// a loopback/private/link-local IP is NOT rejected here: it
// is refused at dial time by the proxy's range rule, which
// is absolute — an explicit listing does NOT override the
// range refusal (see EffectiveProxyAllowedHosts and
// internal/outbound's guard); the default list contains no
// such address. Errors never echo the entry: the caller
// names the element index (R-13).
func normalizeAllowedHost(raw string) (string, error) {
	if raw == "" {
		return "", fmt.Errorf("host must not be empty")
	}
	if raw != strings.TrimSpace(raw) {
		return "", fmt.Errorf("host entry has surrounding whitespace")
	}
	s := strings.ToLower(raw)
	s = strings.TrimRight(s, ".")
	if s == "" {
		return "", fmt.Errorf("host must not be empty")
	}
	for _, r := range s {
		switch {
		case r == '/' || r == ':' || r == '@' || r == '?' || r == '#' || r == '[' || r == ']' || r == '*' || unicode.IsSpace(r) || unicode.IsControl(r):
			return "", fmt.Errorf("host entry contains a forbidden character")
		}
	}
	return s, nil
}

// parseAllowedHosts validates a `proxy_allowed_hosts` value:
// a non-empty array of host strings, each passing
// normalizeAllowedHost. The returned list is in file order,
// normalized, duplicates kept (harmless: matching is a set
// lookup).
func parseAllowedHosts(v any) ([]string, error) {
	arr, ok := v.([]any)
	if !ok || len(arr) == 0 {
		return nil, fmt.Errorf(`"proxy_allowed_hosts" must be a non-empty array of host strings`)
	}
	hosts := make([]string, 0, len(arr))
	for i, elem := range arr {
		s, ok := elem.(string)
		if !ok {
			return nil, fmt.Errorf(`"proxy_allowed_hosts" element %d must be a string`, i)
		}
		h, err := normalizeAllowedHost(s)
		if err != nil {
			return nil, fmt.Errorf(`"proxy_allowed_hosts" element %d: %v`, i, err)
		}
		hosts = append(hosts, h)
	}
	return hosts, nil
}

// parseKeeperBlock parses one decoded `keeper` value (an array of
// entry objects) into a KeeperConfig. Wrong shapes, wrong types,
// unknown keys, missing required keys, duplicate tags, and invalid
// browser URLs are all config errors (exit 2). Cross-entry and
// cross-block references (profile existence, notify target) are
// checked by validateKeeper, not here, so a hand-built
// SingleConfig gets the same refusal from ResolveKeeper.
func parseKeeperBlock(v any) (*KeeperConfig, error) {
	arr, ok := v.([]any)
	if !ok {
		return nil, newConfigError(`"keeper" must be an array of entries`)
	}
	cfg := &KeeperConfig{}
	seenTags := make(map[string]bool)
	for i, elem := range arr {
		obj, ok := elem.(*orderedObject)
		if !ok {
			return nil, newConfigErrorf(`"keeper" entry %d must be an object`, i)
		}
		raw, err := rawOf(elem)
		if err != nil {
			return nil, err
		}
		entry := &KeeperEntry{raw: raw}
		for _, k := range obj.keys {
			val := obj.values[k]
			switch k {
			case "tag":
				s, ok := val.(string)
				if !ok {
					return nil, newConfigErrorf(`"keeper" entry %d: "tag" must be a non-empty string`, i)
				}
				if err := ValidateKeeperTag(s); err != nil {
					return nil, newConfigErrorf(`"keeper" entry %d: invalid "tag": %v`, i, err)
				}
				entry.Tag = s
			case "profile":
				s, ok := val.(string)
				if !ok || strings.TrimSpace(s) == "" {
					return nil, newConfigErrorf(`"keeper" entry %d: "profile" must be a non-empty string`, i)
				}
				if _, err := ValidateProfileName(s); err != nil {
					return nil, newConfigErrorf(`"keeper" entry %d: invalid profile name %q`, i, s)
				}
				entry.Profile = s
			case "browser":
				s, ok := val.(string)
				if !ok || strings.TrimSpace(s) == "" {
					return nil, newConfigErrorf(`"keeper" entry %d: "browser" must be a non-empty CDP URL`, i)
				}
				if err := validateKeeperBrowserURL(s); err != nil {
					return nil, newConfigErrorf(`"keeper" entry %d: invalid "browser" URL: %v`, i, err)
				}
				entry.Browser = strings.TrimSpace(s)
			case "interval":
				s, ok := val.(string)
				if !ok {
					return nil, newConfigErrorf(`"keeper" entry %d: "interval" must be a duration string`, i)
				}
				if strings.TrimSpace(s) != "" {
					d, err := time.ParseDuration(s)
					if err != nil || d <= 0 || d > MaxKeeperInterval {
						return nil, newConfigErrorf(`"keeper" entry %d: "interval" must be a positive duration string of at most %v`, i, MaxKeeperInterval)
					}
					entry.Interval = d
					entry.IntervalSet = true
				}
			case "notify":
				s, ok := val.(string)
				if !ok {
					return nil, newConfigErrorf(`"keeper" entry %d: "notify" must be a string`, i)
				}
				entry.Notify = s
			case "credentials":
				s, ok := val.(string)
				if !ok || strings.TrimSpace(s) == "" {
					return nil, newConfigErrorf(`"keeper" entry %d: "credentials" must be a non-empty tag string`, i)
				}
				if err := ValidateKeeperTag(s); err != nil {
					return nil, newConfigErrorf(`"keeper" entry %d: invalid "credentials" tag: %v`, i, err)
				}
				entry.Credentials = s
			case "wake_on_gateway_failure":
				b, ok := val.(bool)
				if !ok {
					return nil, newConfigErrorf(`"keeper" entry %d: "wake_on_gateway_failure" must be a boolean`, i)
				}
				entry.WakeOnGatewayFailure = b
				entry.WakeSet = true
			case "retry_backoff":
				arr, ok := val.([]any)
				if !ok || len(arr) == 0 {
					return nil, newConfigErrorf(`"keeper" entry %d: "retry_backoff" must be a non-empty array of duration strings`, i)
				}
				if len(arr) > MaxRetryBackoffSteps {
					return nil, newConfigErrorf(`"keeper" entry %d: "retry_backoff" must have at most %d steps`, i, MaxRetryBackoffSteps)
				}
				for j, elem := range arr {
					s, ok := elem.(string)
					if !ok || strings.TrimSpace(s) == "" {
						return nil, newConfigErrorf(`"keeper" entry %d: "retry_backoff" element %d must be a duration string`, i, j)
					}
					d, err := time.ParseDuration(s)
					if err != nil || d <= 0 || d > MaxKeeperInterval {
						return nil, newConfigErrorf(`"keeper" entry %d: "retry_backoff" element %d must be a positive duration string of at most %v`, i, j, MaxKeeperInterval)
					}
					entry.RetryBackoff = append(entry.RetryBackoff, d)
				}
				entry.RetryBackoffSet = true
			case "expiring_within":
				s, ok := val.(string)
				if !ok {
					return nil, newConfigErrorf(`"keeper" entry %d: "expiring_within" must be a duration string`, i)
				}
				if strings.TrimSpace(s) != "" {
					d, err := time.ParseDuration(s)
					if err != nil || d <= 0 || d > MaxKeeperInterval {
						return nil, newConfigErrorf(`"keeper" entry %d: "expiring_within" must be a positive duration string of at most %v`, i, MaxKeeperInterval)
					}
					entry.ExpiringWithin = d
					entry.ExpiringSet = true
				}
			case "wake_attempts", "relogin_attempts":
				n, ok := val.(json.Number)
				if !ok {
					return nil, newConfigErrorf(`"keeper" entry %d: %q must be a positive integer`, i, k)
				}
				iv, err := strconv.Atoi(n.String())
				if err != nil || iv <= 0 || iv > MaxKeeperAttempts {
					return nil, newConfigErrorf(`"keeper" entry %d: %q must be a positive integer of at most %d`, i, k, MaxKeeperAttempts)
				}
				if k == "wake_attempts" {
					entry.WakeAttempts = iv
					entry.WakeAttemptsSet = true
				} else {
					entry.ReloginAttempts = iv
					entry.ReloginSet = true
				}
			case "proxy_dial_timeout", "relogin_match_timeout", "relogin_cookie_timeout", "relogin_poll_interval", "relogin_attach_timeout", "relogin_cancel_timeout", "observe_settle_timeout", "observe_timeout":
				s, ok := val.(string)
				if !ok {
					return nil, newConfigErrorf(`"keeper" entry %d: %q must be a duration string`, i, k)
				}
				d, err := time.ParseDuration(s)
				maxDur := MaxReloginWaitTimeout
				switch k {
				case "proxy_dial_timeout", "relogin_attach_timeout", "relogin_cancel_timeout":
					maxDur = MaxProxyDialTimeout
				case "relogin_poll_interval":
					maxDur = MaxReloginPollInterval
				}
				if err != nil || d <= 0 || d > maxDur {
					return nil, newConfigErrorf(`"keeper" entry %d: %q must be a positive duration string of at most %v`, i, k, maxDur)
				}
				switch k {
				case "proxy_dial_timeout":
					entry.ProxyDialTimeout = d
					entry.ProxyDialSet = true
				case "relogin_match_timeout":
					entry.ReloginMatchTimeout = d
					entry.ReloginMatchSet = true
				case "relogin_cookie_timeout":
					entry.ReloginCookieTimeout = d
					entry.ReloginCookieSet = true
				case "relogin_poll_interval":
					entry.ReloginPollInterval = d
					entry.ReloginPollSet = true
				case "relogin_attach_timeout":
					entry.ReloginAttachTimeout = d
					entry.ReloginAttachSet = true
				case "relogin_cancel_timeout":
					entry.ReloginCancelTimeout = d
					entry.ReloginCancelSet = true
				case "observe_settle_timeout":
					entry.ObserveSettleTimeout = d
					entry.ObserveSettleSet = true
				case "observe_timeout":
					entry.ObserveTimeout = d
					entry.ObserveTimeoutSet = true
				}
			case "proxy_max_header_bytes":
				n, ok := val.(json.Number)
				if !ok {
					return nil, newConfigErrorf(`"keeper" entry %d: "proxy_max_header_bytes" must be a positive integer`, i)
				}
				iv, err := strconv.Atoi(n.String())
				if err != nil || iv <= 0 || iv > MaxProxyHeaderBytes {
					return nil, newConfigErrorf(`"keeper" entry %d: "proxy_max_header_bytes" must be a positive integer of at most %d`, i, MaxProxyHeaderBytes)
				}
				entry.ProxyMaxHeaderBytes = iv
				entry.ProxyMaxHeaderSet = true
			case "proxy_max_body_bytes":
				n, ok := val.(json.Number)
				if !ok {
					return nil, newConfigErrorf(`"keeper" entry %d: "proxy_max_body_bytes" must be a positive integer`, i)
				}
				iv, err := strconv.Atoi(n.String())
				if err != nil || iv <= 0 || iv > MaxProxyBodyBytes {
					return nil, newConfigErrorf(`"keeper" entry %d: "proxy_max_body_bytes" must be a positive integer of at most %d`, i, MaxProxyBodyBytes)
				}
				entry.ProxyMaxBodyBytes = iv
				entry.ProxyMaxBodySet = true
			case "observe_inventory_cap":
				n, ok := val.(json.Number)
				if !ok {
					return nil, newConfigErrorf(`"keeper" entry %d: "observe_inventory_cap" must be a positive integer`, i)
				}
				iv, err := strconv.Atoi(n.String())
				if err != nil || iv <= 0 || iv > MaxObserveInventoryCap {
					return nil, newConfigErrorf(`"keeper" entry %d: "observe_inventory_cap" must be a positive integer of at most %d`, i, MaxObserveInventoryCap)
				}
				entry.ObserveInventoryCap = iv
				entry.ObserveInventorySet = true
			case "proxy_allowed_hosts":
				hosts, err := parseAllowedHosts(val)
				if err != nil {
					return nil, newConfigErrorf(`"keeper" entry %d: %v`, i, err)
				}
				entry.ProxyAllowedHosts = hosts
				entry.ProxyHostsSet = true
			default:
				return nil, newConfigErrorf(`unknown keeper config key %q`, k)
			}
		}
		if entry.Tag == "" {
			return nil, newConfigErrorf(`"keeper" entry %d requires a "tag" key`, i)
		}
		if entry.Profile == "" {
			return nil, newConfigErrorf(`"keeper" entry %d requires a "profile" key`, i)
		}
		if seenTags[entry.Tag] {
			return nil, newConfigErrorf(`"keeper" has duplicate tag %q`, entry.Tag)
		}
		seenTags[entry.Tag] = true
		cfg.Entries = append(cfg.Entries, entry)
	}
	return cfg, nil
}

// validateKeeperBrowserURL enforces the loopback-only CDP URL rule.
// It names the rule violated, never the URL's credentials (a CDP URL
// carries no credentials by construction, but the rule stays: the
// error never echoes the supplied value). Query strings and
// fragments are rejected: a CDP debug URL carries neither.
func validateKeeperBrowserURL(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("unparseable URL")
	}
	if u.User != nil {
		return fmt.Errorf("must not carry userinfo")
	}
	if u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return fmt.Errorf("must not carry a query or fragment")
	}
	if u.Scheme != "http" && u.Scheme != "ws" {
		return fmt.Errorf("scheme must be http or ws")
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("missing host")
	}
	if u.Port() == "" {
		return fmt.Errorf("missing port")
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("port out of range")
	}
	if ip := net.ParseIP(host); ip != nil {
		if !ip.IsLoopback() {
			return fmt.Errorf("host must be loopback")
		}
		return nil
	}
	if !strings.EqualFold(host, "localhost") {
		return fmt.Errorf("host must be loopback")
	}
	return nil
}

// canonicalBrowserURL renders the duplicate-browser dedup key
// for a validated browser URL: normalized host, port, and
// path. The scheme is NOT part of the key: http:// and ws://
// spellings denote the same DevTools endpoint (the discovery
// URL vs the direct WebSocket URL), so they canonicalise to
// one key and two entries cannot share a browser by spelling
// it with the other scheme. Spelling variants of one
// endpoint — trailing slash, host case, "localhost" case,
// IPv6 bracketing — canonicalise to one key, so two entries
// cannot share a browser by spelling it differently. The
// stored entry Browser value is NOT rewritten: only the
// dedup key is canonical. "localhost" and "127.0.0.1" are
// deliberately NOT merged: which loopback address localhost
// resolves to is resolver-dependent, and merging them would
// assert an identity the config did not state.
func canonicalBrowserURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", err
	}
	if err := validateKeeperBrowserURL(raw); err != nil {
		return "", err
	}
	host := strings.ToLower(u.Hostname())
	if ip := net.ParseIP(host); ip != nil {
		host = ip.String()
	}
	port, _ := strconv.Atoi(u.Port())
	path := strings.TrimSuffix(u.Path, "/")
	return fmt.Sprintf("%s:%d%s", host, port, path), nil
}

// canonicalBrowser is canonicalBrowserURL with a raw-string
// fallback: validateKeeper also runs over hand-built configs
// whose browser URLs never passed parse-time validation, and
// dedup must not fail on them — it keys on the raw string
// instead. Parse-time validation remains the enforcement
// point for real configs.
func canonicalBrowser(raw string) string {
	if c, err := canonicalBrowserURL(raw); err == nil {
		return c
	}
	return raw
}

// validateKeeper enforces the block's cross-references: every
// entry's profile must name a key of SingleConfig.Profiles, no two
// entries may name the same profile or share a browser URL, and a
// `notify: "telegram"` entry requires the `telegram` block to
// exist. It names profiles/tags only, never values. Called from
// the ParseSingleConfig tail after validateTagGraph; a nil block
// is valid (feature off).
func validateKeeper(cfg *SingleConfig) error {
	k := cfg.Keeper
	if k == nil {
		return nil
	}
	seenProfiles := make(map[string]string)
	seenBrowsers := make(map[string]string)
	for _, e := range k.Entries {
		if _, ok := cfg.Profiles[e.Profile]; !ok {
			return newConfigErrorf("keeper: entry %q names profile %q, which does not exist", e.Tag, e.Profile)
		}
		if prev, ok := seenProfiles[e.Profile]; ok {
			return newConfigErrorf("keeper: entries %q and %q both name profile %q", prev, e.Tag, e.Profile)
		}
		seenProfiles[e.Profile] = e.Tag
		if e.Browser != "" {
			if prev, ok := seenBrowsers[canonicalBrowser(e.Browser)]; ok {
				return newConfigErrorf("keeper: entries %q and %q share one browser URL", prev, e.Tag)
			}
			seenBrowsers[canonicalBrowser(e.Browser)] = e.Tag
		}
		switch e.Notify {
		case "", "telegram":
		default:
			return newConfigErrorf("keeper: entry %q has unknown notify %q (only \"telegram\" is supported)", e.Tag, e.Notify)
		}
		if e.Notify == "telegram" && cfg.Telegram == nil {
			return newConfigErrorf("keeper: entry %q notifies \"telegram\" but no \"telegram\" block exists", e.Tag)
		}
	}
	return nil
}

// ResolveKeeper returns the parsed `keeper` block, or nil when the
// block is absent (feature off) or there is no single config. It
// never reads the filesystem and never mutates its input. The
// cross-reference checks are re-run here so callers that receive a
// hand-built SingleConfig get the same dangling-reference refusal
// parse gives.
func ResolveKeeper(single *SingleConfig) (*KeeperConfig, error) {
	if single == nil || single.Keeper == nil {
		return nil, nil
	}
	if err := validateKeeper(single); err != nil {
		return nil, err
	}
	if err := validateCredentialRefs(single); err != nil {
		return nil, err
	}
	return single.Keeper, nil
}

// KeeperEntryForProfile returns the keeper entry for a profile
// name, or nil when no entry names it.
func (c *KeeperConfig) KeeperEntryForProfile(profileName string) *KeeperEntry {
	if c == nil {
		return nil
	}
	for _, e := range c.Entries {
		if e.Profile == profileName {
			return e
		}
	}
	return nil
}

// EffectiveInterval returns the entry's base cadence: the parsed
// `interval` when set, DefaultKeeperInterval otherwise.
func (e *KeeperEntry) EffectiveInterval() time.Duration {
	if e != nil && e.IntervalSet && e.Interval > 0 {
		return e.Interval
	}
	return DefaultKeeperInterval
}

// EffectiveWakeOnGatewayFailure returns the entry's auto-wake
// setting: the parsed value when set, true otherwise.
func (e *KeeperEntry) EffectiveWakeOnGatewayFailure() bool {
	if e != nil && e.WakeSet {
		return e.WakeOnGatewayFailure
	}
	return true
}

// EffectiveRetryBackoff returns the entry's transient-retry
// ladder: the parsed list when set, DefaultRetryBackoff
// otherwise. The returned slice is a copy; callers must not
// mutate the entry's ladder.
func (e *KeeperEntry) EffectiveRetryBackoff() []time.Duration {
	if e != nil && e.RetryBackoffSet && len(e.RetryBackoff) > 0 {
		out := make([]time.Duration, len(e.RetryBackoff))
		copy(out, e.RetryBackoff)
		return out
	}
	out := make([]time.Duration, len(DefaultRetryBackoff))
	copy(out, DefaultRetryBackoff)
	return out
}

// EffectiveExpiringWithin returns the entry's "expiring"
// window: the parsed value when set, DefaultExpiringWithin
// otherwise.
func (e *KeeperEntry) EffectiveExpiringWithin() time.Duration {
	if e != nil && e.ExpiringSet && e.ExpiringWithin > 0 {
		return e.ExpiringWithin
	}
	return DefaultExpiringWithin
}

// EffectiveWakeAttempts returns the entry's per-incident wake
// cap: the parsed value when set, DefaultKeeperAttempts
// otherwise.
func (e *KeeperEntry) EffectiveWakeAttempts() int {
	if e != nil && e.WakeAttemptsSet && e.WakeAttempts > 0 {
		return e.WakeAttempts
	}
	return DefaultKeeperAttempts
}

// EffectiveReloginAttempts returns the entry's per-incident
// re-login cap: the parsed value when set,
// DefaultKeeperAttempts otherwise.
func (e *KeeperEntry) EffectiveReloginAttempts() int {
	if e != nil && e.ReloginSet && e.ReloginAttempts > 0 {
		return e.ReloginAttempts
	}
	return DefaultKeeperAttempts
}

// effectiveDuration is the shared zero-value guard for the
// S10 duration keys: the parsed value when set and in
// range, the documented default otherwise. Callers nil-guard
// the entry first: evaluating a field on a nil entry would
// panic before this function ever runs.
func effectiveDuration(set bool, v, def time.Duration) time.Duration {
	if set && v > 0 && v <= MaxKeeperInterval {
		return v
	}
	return def
}

// EffectiveProxyDialTimeout returns the entry's S2 proxy
// dial timeout: the parsed value when set,
// DefaultProxyDialTimeout otherwise.
func (e *KeeperEntry) EffectiveProxyDialTimeout() time.Duration {
	if e == nil {
		return DefaultProxyDialTimeout
	}
	return effectiveDuration(e.ProxyDialSet, e.ProxyDialTimeout, DefaultProxyDialTimeout)
}

// EffectiveProxyMaxHeaderBytes returns the entry's S2 proxy
// header cap: the parsed value when set,
// DefaultProxyMaxHeaderBytes otherwise.
func (e *KeeperEntry) EffectiveProxyMaxHeaderBytes() int {
	if e != nil && e.ProxyMaxHeaderSet && e.ProxyMaxHeaderBytes > 0 && e.ProxyMaxHeaderBytes <= MaxProxyHeaderBytes {
		return e.ProxyMaxHeaderBytes
	}
	return DefaultProxyMaxHeaderBytes
}

// EffectiveProxyMaxBodyBytes returns the entry's S2 proxy
// body cap: the parsed value when set,
// DefaultProxyMaxBodyBytes otherwise.
func (e *KeeperEntry) EffectiveProxyMaxBodyBytes() int {
	if e != nil && e.ProxyMaxBodySet && e.ProxyMaxBodyBytes > 0 && e.ProxyMaxBodyBytes <= MaxProxyBodyBytes {
		return e.ProxyMaxBodyBytes
	}
	return DefaultProxyMaxBodyBytes
}

// EffectiveProxyAllowedHosts returns the entry's S2 proxy
// allowlist: the parsed list when set,
// DefaultProxyAllowedHosts otherwise. The returned slice is
// a copy. Hand-built entries are normalized defensively
// (invalid entries dropped); an empty result means the
// default list, exactly as parse treats an absent key.
func (e *KeeperEntry) EffectiveProxyAllowedHosts() []string {
	if e != nil && e.ProxyHostsSet && len(e.ProxyAllowedHosts) > 0 {
		out := make([]string, 0, len(e.ProxyAllowedHosts))
		for _, h := range e.ProxyAllowedHosts {
			if norm, err := normalizeAllowedHost(h); err == nil {
				out = append(out, norm)
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	out := make([]string, len(DefaultProxyAllowedHosts))
	copy(out, DefaultProxyAllowedHosts)
	return out
}

// EffectiveReloginMatchTimeout returns the entry's driver
// form-match wait: the parsed value when set,
// DefaultReloginMatchTimeout otherwise.
func (e *KeeperEntry) EffectiveReloginMatchTimeout() time.Duration {
	if e == nil {
		return DefaultReloginMatchTimeout
	}
	return effectiveDuration(e.ReloginMatchSet, e.ReloginMatchTimeout, DefaultReloginMatchTimeout)
}

// EffectiveReloginCookieTimeout returns the entry's driver
// cookie wait: the parsed value when set,
// DefaultReloginCookieTimeout otherwise.
func (e *KeeperEntry) EffectiveReloginCookieTimeout() time.Duration {
	if e == nil {
		return DefaultReloginCookieTimeout
	}
	return effectiveDuration(e.ReloginCookieSet, e.ReloginCookieTimeout, DefaultReloginCookieTimeout)
}

// EffectiveReloginPollInterval returns the entry's driver
// poll cadence: the parsed value when set,
// DefaultReloginPollInterval otherwise.
func (e *KeeperEntry) EffectiveReloginPollInterval() time.Duration {
	if e == nil {
		return DefaultReloginPollInterval
	}
	return effectiveDuration(e.ReloginPollSet, e.ReloginPollInterval, DefaultReloginPollInterval)
}

// EffectiveReloginAttachTimeout returns the entry's driver
// attach dial timeout: the parsed value when set,
// DefaultReloginAttachTimeout otherwise.
func (e *KeeperEntry) EffectiveReloginAttachTimeout() time.Duration {
	if e == nil {
		return DefaultReloginAttachTimeout
	}
	return effectiveDuration(e.ReloginAttachSet, e.ReloginAttachTimeout, DefaultReloginAttachTimeout)
}

// EffectiveReloginCancelTimeout returns the entry's driver
// cancel-wait bound: the parsed value when set,
// DefaultReloginCancelTimeout otherwise.
func (e *KeeperEntry) EffectiveReloginCancelTimeout() time.Duration {
	if e == nil {
		return DefaultReloginCancelTimeout
	}
	return effectiveDuration(e.ReloginCancelSet, e.ReloginCancelTimeout, DefaultReloginCancelTimeout)
}

// EffectiveObserveSettleTimeout returns the entry's
// observation settle wait: the parsed value when set,
// DefaultObserveSettleTimeout otherwise.
func (e *KeeperEntry) EffectiveObserveSettleTimeout() time.Duration {
	if e == nil {
		return DefaultObserveSettleTimeout
	}
	return effectiveDuration(e.ObserveSettleSet, e.ObserveSettleTimeout, DefaultObserveSettleTimeout)
}

// EffectiveObserveTimeout returns the entry's whole
// observation bound: the parsed value when set,
// DefaultObserveTimeout otherwise.
func (e *KeeperEntry) EffectiveObserveTimeout() time.Duration {
	if e == nil {
		return DefaultObserveTimeout
	}
	return effectiveDuration(e.ObserveTimeoutSet, e.ObserveTimeout, DefaultObserveTimeout)
}

// EffectiveObserveInventoryCap returns the entry's
// observation inventory cap: the parsed value when set,
// DefaultObserveInventoryCap otherwise.
func (e *KeeperEntry) EffectiveObserveInventoryCap() int {
	if e != nil && e.ObserveInventorySet && e.ObserveInventoryCap > 0 && e.ObserveInventoryCap <= MaxObserveInventoryCap {
		return e.ObserveInventoryCap
	}
	return DefaultObserveInventoryCap
}

// encodeKeeperBlock renders a KeeperConfig for save when no raw
// JSON was captured: entries in order, canonical key order, the
// interval as a duration string, `browser` omitted when empty
// (keep-alive-only entry), `notify`/`credentials` omitted when
// empty, `wake_on_gateway_failure` omitted when unset (default
// true), `retry_backoff`/`expiring_within`/attempt caps omitted
// when unset. The S10 proxy/driver/observe keys are likewise
// omitted when unset (their defaults stay runtime-only). The
// returned values are *orderedObject so the save encoder
// preserves key order.
func encodeKeeperBlock(cfg *KeeperConfig) ([]any, error) {
	arr := make([]any, 0, len(cfg.Entries))
	for _, e := range cfg.Entries {
		entry := newOrderedObject()
		entry.set("tag", e.Tag)
		entry.set("profile", e.Profile)
		if e.Browser != "" {
			entry.set("browser", e.Browser)
		}
		if e.IntervalSet && e.Interval > 0 {
			entry.set("interval", e.Interval.String())
		}
		if e.Notify != "" {
			entry.set("notify", e.Notify)
		}
		if e.Credentials != "" {
			entry.set("credentials", e.Credentials)
		}
		if e.WakeSet {
			entry.set("wake_on_gateway_failure", e.WakeOnGatewayFailure)
		}
		if e.RetryBackoffSet && len(e.RetryBackoff) > 0 {
			steps := make([]any, 0, len(e.RetryBackoff))
			for _, d := range e.RetryBackoff {
				steps = append(steps, d.String())
			}
			entry.set("retry_backoff", steps)
		}
		if e.ExpiringSet && e.ExpiringWithin > 0 {
			entry.set("expiring_within", e.ExpiringWithin.String())
		}
		if e.WakeAttemptsSet && e.WakeAttempts > 0 {
			entry.set("wake_attempts", json.Number(strconv.Itoa(e.WakeAttempts)))
		}
		if e.ReloginSet && e.ReloginAttempts > 0 {
			entry.set("relogin_attempts", json.Number(strconv.Itoa(e.ReloginAttempts)))
		}
		if e.ProxyDialSet && e.ProxyDialTimeout > 0 {
			entry.set("proxy_dial_timeout", e.ProxyDialTimeout.String())
		}
		if e.ProxyMaxHeaderSet && e.ProxyMaxHeaderBytes > 0 {
			entry.set("proxy_max_header_bytes", json.Number(strconv.Itoa(e.ProxyMaxHeaderBytes)))
		}
		if e.ProxyMaxBodySet && e.ProxyMaxBodyBytes > 0 {
			entry.set("proxy_max_body_bytes", json.Number(strconv.Itoa(e.ProxyMaxBodyBytes)))
		}
		if e.ProxyHostsSet && len(e.ProxyAllowedHosts) > 0 {
			hosts := make([]any, 0, len(e.ProxyAllowedHosts))
			for _, h := range e.ProxyAllowedHosts {
				hosts = append(hosts, h)
			}
			entry.set("proxy_allowed_hosts", hosts)
		}
		if e.ReloginMatchSet && e.ReloginMatchTimeout > 0 {
			entry.set("relogin_match_timeout", e.ReloginMatchTimeout.String())
		}
		if e.ReloginCookieSet && e.ReloginCookieTimeout > 0 {
			entry.set("relogin_cookie_timeout", e.ReloginCookieTimeout.String())
		}
		if e.ReloginPollSet && e.ReloginPollInterval > 0 {
			entry.set("relogin_poll_interval", e.ReloginPollInterval.String())
		}
		if e.ReloginAttachSet && e.ReloginAttachTimeout > 0 {
			entry.set("relogin_attach_timeout", e.ReloginAttachTimeout.String())
		}
		if e.ReloginCancelSet && e.ReloginCancelTimeout > 0 {
			entry.set("relogin_cancel_timeout", e.ReloginCancelTimeout.String())
		}
		if e.ObserveSettleSet && e.ObserveSettleTimeout > 0 {
			entry.set("observe_settle_timeout", e.ObserveSettleTimeout.String())
		}
		if e.ObserveTimeoutSet && e.ObserveTimeout > 0 {
			entry.set("observe_timeout", e.ObserveTimeout.String())
		}
		if e.ObserveInventorySet && e.ObserveInventoryCap > 0 {
			entry.set("observe_inventory_cap", json.Number(strconv.Itoa(e.ObserveInventoryCap)))
		}
		arr = append(arr, entry)
	}
	return arr, nil
}
