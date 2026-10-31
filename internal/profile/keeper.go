// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package profile

import (
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
//	 "interval": string, "notify": string}
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
//   - `browser` (required): the CDP debug URL of the already-running
//     Chrome that holds the profile's login, e.g.
//     "http://127.0.0.1:9226/". Loopback only: the host must be
//     127.0.0.1, ::1, or localhost, the scheme http or ws, and a port
//     must be present. A non-loopback browser URL is a config error:
//     the debug port is an unauthenticated local privilege boundary
//     and castctl must never be told to reach a remote browser.
//     Two entries must not share one browser URL: one CDP endpoint
//     is one browser instance, and profiles must never share
//     mutable browser state. No default port is ever assumed: an
//     entry without a browser key is a config error, and there is
//     no fallback to Chrome's conventional 9222.
//   - `interval` (optional): Go duration string ("24h", "30m").
//     Zero value (key absent or empty) means the documented default
//     cadence of 24h; see internal/keeper for the adaptive rule that
//     shortens it once a cookie expiry is observed. A present value
//     must parse with time.ParseDuration, be positive, and be at
//     most MaxKeeperInterval (1 year: the jitter arithmetic
//     bound). Bare JSON numbers are rejected:
//     seconds-vs-minutes has no in-band signal.
//   - `notify` (optional): the telegram-block reference. The only
//     accepted value is "telegram", naming the single top-level
//     `telegram` block. A `notify` value naming anything else, or a
//     `notify: "telegram"` entry when no `telegram` block exists,
//     is a dangling reference, exit 2.
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
		if entry.Browser == "" {
			return nil, newConfigErrorf(`"keeper" entry %d requires a "browser" key`, i)
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
		if prev, ok := seenBrowsers[canonicalBrowser(e.Browser)]; ok {
			return newConfigErrorf("keeper: entries %q and %q share one browser URL", prev, e.Tag)
		}
		seenBrowsers[canonicalBrowser(e.Browser)] = e.Tag
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

// encodeKeeperBlock renders a KeeperConfig for save when no raw
// JSON was captured: entries in order, canonical key order, the
// interval as a duration string, `notify` omitted when empty. The
// returned values are *orderedObject so the save encoder preserves
// key order.
func encodeKeeperBlock(cfg *KeeperConfig) ([]any, error) {
	arr := make([]any, 0, len(cfg.Entries))
	for _, e := range cfg.Entries {
		entry := newOrderedObject()
		entry.set("tag", e.Tag)
		entry.set("profile", e.Profile)
		entry.set("browser", e.Browser)
		if e.IntervalSet && e.Interval > 0 {
			entry.set("interval", e.Interval.String())
		}
		if e.Notify != "" {
			entry.set("notify", e.Notify)
		}
		arr = append(arr, entry)
	}
	return arr, nil
}
