// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package profile

import (
	"golang.org/x/crypto/bcrypt"
)

// Web UI secret hashing, following CLIProxyAPI's remote-management
// secret-key behavior (github.com/router-for-me/CLIProxyAPI,
// 250d5981): a plaintext configured secret is hashed with bcrypt
// on `webui serve` startup and written back into config.json; an
// already-hashed secret is used as-is; logins are compared
// against the hash, with no plaintext fallback. Deviations from
// upstream are deliberate and documented in docs/provenance.md:
// the write-back is atomic + mode 0600 and fails closed on
// error (upstream's load-path write-back ignores its error),
// and hashing also runs on API saves (hash-on-save) so a
// plaintext token set through the web UI never rests on disk.
//
// No function here ever returns, logs, or embeds the secret
// value: errors name the key and the rule only. Sing-box defines
// no secret hashing (its clash_api `secret` is compared as
// plaintext); do not cite sing-box for this behavior.

// LooksLikeBcryptHash reports whether s is already a bcrypt
// hash, using CLIProxyAPI's verbatim predicate: length > 4 and
// a $2a$, $2b$, or $2y$ prefix. Nothing else is checked: a
// malformed value with a valid prefix counts as hashed and
// can never authenticate, exactly as upstream.
func LooksLikeBcryptHash(s string) bool {
	return len(s) > 4 && (s[:4] == "$2a$" || s[:4] == "$2b$" || s[:4] == "$2y$")
}

// HashWebUIToken hashes a plaintext web UI token with bcrypt
// DefaultCost. An empty token and a token over bcrypt's 72-byte
// limit are errors naming the rule only, never the value.
func HashWebUIToken(plaintext string) (string, error) {
	if plaintext == "" {
		return "", newConfigError(`"webui.token" must not be empty`)
	}
	hashed, err := bcrypt.GenerateFromPassword([]byte(plaintext), bcrypt.DefaultCost)
	if err != nil {
		return "", newConfigError(`"webui.token" cannot be hashed`)
	}
	return string(hashed), nil
}

// CompareWebUIToken reports whether presented matches the stored
// bcrypt hash. Any comparison error — malformed hash, wrong
// token, empty input — is a rejection, never a fallback to a
// plaintext comparison.
func CompareWebUIToken(hash, presented string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(presented)) == nil
}

// ReplaceWebUIToken stores token as the webui block's token,
// editing the raw captured JSON in place when present so the
// write-back preserves every other key's order and value (the
// raw block wins on save: mutating the parsed value alone
// would not persist). With no raw capture it sets the parsed
// value only, and the synthesized block renders in canonical
// order. An absent block is an error: there is nowhere to
// store a token.
func (c *SingleConfig) ReplaceWebUIToken(token string) error {
	if c == nil || c.WebUI == nil {
		return newConfigError(`cannot store a "webui.token" with no "webui" block`)
	}
	c.WebUI.Token = token
	if len(c.rawWebUI) == 0 {
		return nil
	}
	v, err := decodeOrderedJSON(c.rawWebUI)
	if err != nil {
		return err
	}
	obj, ok := v.(*orderedObject)
	if !ok {
		return newConfigError(`"webui" must be an object`)
	}
	obj.set("token", token)
	raw, err := rawOf(obj)
	if err != nil {
		return err
	}
	c.rawWebUI = raw
	return nil
}
