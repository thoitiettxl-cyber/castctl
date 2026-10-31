// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package profile

// The top-level `telegram` config block and its resolution.
//
// Schema (exactly five keys; unknown keys are rejected, like every
// other strict section in this file):
//
//	{"profile": string, "token": string,
//	 "allowed_user_ids": [int64...],
//	 "auto_approve": bool, "auto_allow_once": bool}
//
// The block is optional. A nil *TelegramConfig on SingleConfig means
// the block was absent from the file, and the Telegram bot is off:
// no behaviour changes, no token is read, no polling starts. An
// absent block is preserved on save (defaults stay runtime-only,
// the same presence precedent as the `log` block).
//
// Field sources (Boss decisions, overnight item 4; no defaults
// invented beyond the stated sources):
//
//   - `profile` (required): the name of a key of SingleConfig.Profiles.
//     Blocks reference each other by tag (docs/architecture.md:53);
//     the profile's own outbound is the bot's only egress path
//     (internal/commands resolves the linked profile and builds
//     the runtime for it). A name that is not a profile key is a
//     dangling reference, exit 2, exactly like a dangling outbound
//     tag in validateTagGraph.
//   - `token` (required): the bot token, stored in config.json
//     (0600, via the same save path as every other block). The
//     shape check mirrors Python's TelegramAPI.__init__
//     (muse-cli 0.6.1, src/muse_cli/tgapi.py:49-52): digits, a
//     colon, then 20+ token characters; the value is stripped
//     before the check, exactly as Python strips it. The token
//     is NEVER echoed in an error, a log line, or display output:
//     parse errors name the key only, and RedactConfig redacts
//     the "token" key wholesale (internal/redact already carries
//     "token" in its secret-key set). There is no env-var, argv,
//     or separate-file token source in this build: the config
//     block is the only source (Python's telegram.json + stdin
//     setup flow is not ported; see NOT-INCLUDED in the PR draft).
//   - `allowed_user_ids` (required, non-empty): the allowlist.
//     Python's allowlist is `allowed_user_ids` plus `owner_id`,
//     checked on the SENDER's user id only, never on chat id or
//     chat type (src/muse_cli/tgbot.py:643-648, 989-1000). This
//     block carries the same key name and the same sender-id
//     semantics; there is no owner_id field in this build because
//     the owner-only gates in Python guard commands (raw, update,
//     login, profile) that are not wired in item 4. An empty or
//     missing allowlist is fail-closed (exit 2, no token use, no
//     polling). Ids must be positive integers; a non-positive,
//     fractional, or non-numeric id is a config error.
//   - `auto_approve`, `auto_allow_once` (optional, default false):
//     the two toggles the approval surface reads. The false
//     defaults come from the existing castctl defaults: the
//     profile entry's `auto_approve` defaults to "off" in
//     parseProfileEntry, and Python's bot state defaults
//     `auto_allow_once` to False (src/muse_cli/tgbot.py:630).
//     Both are bool-only in this block: the profile entry's
//     on/off-word spelling for auto_allow_once is not carried
//     over, so the schema has exactly one spelling per field.
//     The toggles are read from this block only; no CLI flag,
//     env var, or profile-entry value feeds a bot turn (Python
//     likewise reads only its own state value for turns,
//     src/muse_cli/tgbot.py:1292, cli.py:1330-1342).
//
// Resolution is pure (ResolveLogSettings / ResolveProfileDNS are
// the pattern): it reads only its input, never the filesystem,
// never mutates. Validation runs at parse time in the
// ParseSingleConfig tail, after validateTagGraph, mirroring
// validateProfileDNS.

import (
	"encoding/json"
	"regexp"
	"strings"
)

// TelegramConfig is one parsed `telegram` block. A nil
// *TelegramConfig on SingleConfig means the block was absent.
type TelegramConfig struct {
	Profile        string
	Token          string
	AllowedUserIDs []int64
	AutoApprove    bool
	AutoAllowOnce  bool
}

// telegramTokenShape is Python's token shape check
// (src/muse_cli/tgapi.py:49-52): r"\d+:[A-Za-z0-9_-]{20,}",
// fullmatch, applied to the stripped value.
var telegramTokenShape = regexp.MustCompile(`^[0-9]+:[A-Za-z0-9_-]{20,}$`)

func validTelegramTokenShape(token string) bool {
	return telegramTokenShape.MatchString(token)
}

// parseTelegramBlock parses one decoded `telegram` value into a
// TelegramConfig. Wrong shapes, wrong types, unknown keys, missing
// required keys, a dangling profile name (checked by
// validateTelegram, not here), an empty allowlist, and a
// malformed token are all config errors (exit 2). A supplied
// value is never echoed in an error: the token in particular
// must never appear in any error string.
func parseTelegramBlock(v any) (*TelegramConfig, error) {
	obj, ok := v.(*orderedObject)
	if !ok {
		return nil, newConfigError(`"telegram" must be an object`)
	}
	cfg := &TelegramConfig{}
	var profileSet, tokenSet, allowlistSet bool
	for _, k := range obj.keys {
		val := obj.values[k]
		switch k {
		case "profile":
			s, ok := val.(string)
			if !ok {
				return nil, newConfigError(`"telegram.profile" must be a string`)
			}
			if strings.TrimSpace(s) == "" {
				return nil, newConfigError(`"telegram.profile" must not be empty`)
			}
			cfg.Profile = s
			profileSet = true
		case "token":
			s, ok := val.(string)
			if !ok {
				return nil, newConfigError(`"telegram.token" must be a string`)
			}
			s = strings.TrimSpace(s)
			if !validTelegramTokenShape(s) {
				return nil, newConfigError(`"telegram.token" does not look like a bot token (expected digits, a colon, then 20 or more token characters)`)
			}
			cfg.Token = s
			tokenSet = true
		case "allowed_user_ids":
			arr, ok := val.([]any)
			if !ok {
				return nil, newConfigError(`"telegram.allowed_user_ids" must be an array of user ids`)
			}
			if len(arr) == 0 {
				return nil, newConfigError(`"telegram.allowed_user_ids" must not be empty: the bot refuses to start without an allowlist`)
			}
			ids := make([]int64, 0, len(arr))
			for _, elem := range arr {
				n, ok := elem.(json.Number)
				if !ok {
					return nil, newConfigError(`"telegram.allowed_user_ids" must contain integers only`)
				}
				id, err := n.Int64()
				if err != nil {
					return nil, newConfigError(`"telegram.allowed_user_ids" must contain integers only`)
				}
				if id <= 0 {
					return nil, newConfigError(`"telegram.allowed_user_ids" must contain positive user ids only`)
				}
				ids = append(ids, id)
			}
			cfg.AllowedUserIDs = ids
			allowlistSet = true
		case "auto_approve":
			b, ok := val.(bool)
			if !ok {
				return nil, newConfigError(`"telegram.auto_approve" must be a boolean`)
			}
			cfg.AutoApprove = b
		case "auto_allow_once":
			b, ok := val.(bool)
			if !ok {
				return nil, newConfigError(`"telegram.auto_allow_once" must be a boolean`)
			}
			cfg.AutoAllowOnce = b
		default:
			return nil, newConfigErrorf("unknown telegram config key %q", k)
		}
	}
	if !profileSet {
		return nil, newConfigError(`"telegram" requires a "profile" key naming a profile in "profiles"`)
	}
	if !tokenSet {
		return nil, newConfigError(`"telegram" requires a "token" key`)
	}
	if !allowlistSet {
		return nil, newConfigError(`"telegram" requires a non-empty "allowed_user_ids" key`)
	}
	return cfg, nil
}

// validateTelegram enforces the block's cross-reference: the
// `profile` value must name a key of SingleConfig.Profiles. It
// also re-checks the shape invariants defensively, so a
// SingleConfig built without going through parse cannot slip a
// malformed block past the gate. It names profiles/keys only,
// never values. Called from the ParseSingleConfig tail after
// validateTagGraph; a nil block is valid (feature off).
func validateTelegram(cfg *SingleConfig) error {
	tg := cfg.Telegram
	if tg == nil {
		return nil
	}
	if _, ok := cfg.Profiles[tg.Profile]; !ok {
		return newConfigErrorf("telegram: profile %q does not exist", tg.Profile)
	}
	if !validTelegramTokenShape(tg.Token) {
		return newConfigError(`"telegram.token" does not look like a bot token (expected digits, a colon, then 20 or more token characters)`)
	}
	if len(tg.AllowedUserIDs) == 0 {
		return newConfigError(`"telegram.allowed_user_ids" must not be empty: the bot refuses to start without an allowlist`)
	}
	for _, id := range tg.AllowedUserIDs {
		if id <= 0 {
			return newConfigError(`"telegram.allowed_user_ids" must contain positive user ids only`)
		}
	}
	return nil
}

// ResolveTelegram returns the parsed `telegram` block, or nil when
// the block is absent (feature off) or there is no single config.
// It never reads the filesystem and never mutates its input. The
// linked profile reference is re-checked here so callers that
// receive a hand-built SingleConfig get the same dangling-profile
// refusal parse gives; the error names the profile only.
func ResolveTelegram(single *SingleConfig) (*TelegramConfig, error) {
	if single == nil || single.Telegram == nil {
		return nil, nil
	}
	if err := validateTelegram(single); err != nil {
		return nil, err
	}
	return single.Telegram, nil
}
