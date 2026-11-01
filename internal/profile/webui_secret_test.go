// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package profile

import (
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// TestLooksLikeBcryptHash pins the CLIProxyAPI detection predicate
// verbatim: length > 4 and a $2a$/$2b$/$2y$ prefix, nothing else.
// Detection alone never authenticates: a malformed value with a
// valid prefix is detected as hashed and can never compare.
func TestLooksLikeBcryptHash(t *testing.T) {
	cases := []struct {
		name  string
		value string
		want  bool
	}{
		{"2a prefix", "$2a$10$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", true},
		{"2b prefix", "$2b$10$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", true},
		{"2y prefix", "$2y$10$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", true},
		{"2b garbage", "$2b$garbage", true},
		{"old 2 prefix", "$2$10$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", false},
		{"exactly 4 chars", "$2b$", false},
		{"empty", "", false},
		{"plaintext", "MARKER-PLAIN-TOKEN", false},
		{"plaintext with prefix later", "x$2b$10$abc", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := LooksLikeBcryptHash(tc.value); got != tc.want {
				t.Errorf("LooksLikeBcryptHash(%q) = %v, want %v", tc.value, got, tc.want)
			}
		})
	}
}

// TestHashWebUIToken pins the production hashing rule: bcrypt
// DefaultCost (10), embedded in the hash string. Fixture hashes in
// other tests may use MinCost for speed; this helper never does.
func TestHashWebUIToken(t *testing.T) {
	const plaintext = "MARKER-WEBUI-TOKEN"
	hashed, err := HashWebUIToken(plaintext)
	if err != nil {
		t.Fatalf("HashWebUIToken: %v", err)
	}
	if !LooksLikeBcryptHash(hashed) {
		t.Fatalf("hash %q is not detected as hashed", hashed)
	}
	parts := strings.Split(hashed, "$")
	if len(parts) != 4 || parts[2] != "10" {
		t.Fatalf("hash %q: want bcrypt cost 10", hashed)
	}
	if !CompareWebUIToken(hashed, plaintext) {
		t.Fatalf("hash does not compare against its plaintext")
	}
	if CompareWebUIToken(hashed, "MARKER-WRONG-TOKEN") {
		t.Fatalf("hash compares against a wrong token")
	}
	// A second hash of the same plaintext differs (salt) but
	// still compares: hashing is not deterministic.
	again, err := HashWebUIToken(plaintext)
	if err != nil {
		t.Fatalf("HashWebUIToken again: %v", err)
	}
	if again == hashed {
		t.Fatalf("two hashes of the same token are identical: salt missing")
	}
}

func TestHashWebUITokenLimits(t *testing.T) {
	if _, err := HashWebUIToken(""); err == nil {
		t.Error("empty token hashed, want an error")
	}
	// 72 bytes is the bcrypt limit: exactly 72 hashes, 73 fails.
	// The error must name the rule only, never the value.
	plain72 := "MARKER-72-" + strings.Repeat("x", 62)
	if len(plain72) != 72 {
		t.Fatalf("fixture length = %d, want 72", len(plain72))
	}
	if _, err := HashWebUIToken(plain72); err != nil {
		t.Errorf("72-byte token: unexpected error: %v", err)
	}
	plain73 := "MARKER-73-" + strings.Repeat("x", 63)
	if len(plain73) != 73 {
		t.Fatalf("fixture length = %d, want 73", len(plain73))
	}
	_, err := HashWebUIToken(plain73)
	if err == nil {
		t.Fatal("73-byte token hashed, want an error")
	}
	if strings.Contains(err.Error(), "MARKER-73-") {
		t.Fatalf("hash error echoes the token value: %v", err)
	}
}

// TestCompareWebUITokenFixtures covers the login seam: MinCost
// fixture hashes (as in upstream CLIProxyAPI tests) compare
// correctly, malformed hashes never compare, and an empty
// presented token never compares.
func TestCompareWebUITokenFixtures(t *testing.T) {
	hashBytes, err := bcrypt.GenerateFromPassword([]byte("MARKER-FIXTURE-TOKEN"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("fixture hash: %v", err)
	}
	hash := string(hashBytes)
	if !CompareWebUIToken(hash, "MARKER-FIXTURE-TOKEN") {
		t.Error("MinCost fixture hash does not compare")
	}
	if CompareWebUIToken(hash, "MARKER-WRONG-TOKEN") {
		t.Error("fixture hash compares against a wrong token")
	}
	if CompareWebUIToken(hash, "") {
		t.Error("fixture hash compares against an empty token")
	}
	if CompareWebUIToken("$2b$garbage", "MARKER-FIXTURE-TOKEN") {
		t.Error("malformed hash compares")
	}
	if CompareWebUIToken("", "MARKER-FIXTURE-TOKEN") {
		t.Error("empty hash compares")
	}
}

// TestReplaceWebUITokenRawInPlace pins the raw-capture rule: the
// write-back replaces the token value in place, preserving every
// other key's order and value, including a reordered input block.
func TestReplaceWebUITokenRawInPlace(t *testing.T) {
	cfg := parseWebUITestConfig(t, `{"profiles":{},"webui":{"token":"MARKER-OLD-TOKEN","listen":"127.0.0.1:8317","ui_dir":"/srv/MARKER-UIDIR"}}`)
	const hashed = "$2b$10$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	if err := cfg.ReplaceWebUIToken(hashed); err != nil {
		t.Fatalf("ReplaceWebUIToken: %v", err)
	}
	if cfg.WebUI == nil || cfg.WebUI.Token != hashed {
		t.Fatalf("parsed token = %+v, want the hash", cfg.WebUI)
	}
	encoded, err := encodeSingleConfig(cfg)
	if err != nil {
		t.Fatalf("encodeSingleConfig: %v", err)
	}
	got := string(encoded)
	if strings.Contains(got, "MARKER-OLD-TOKEN") {
		t.Fatalf("old token survives in the encoding:\n%s", got)
	}
	tokenAt := strings.Index(got, `"token"`)
	listenAt := strings.Index(got, `"listen"`)
	uiDirAt := strings.Index(got, `"ui_dir"`)
	if tokenAt < 0 || listenAt < 0 || uiDirAt < 0 {
		t.Fatalf("encoded block lost a key:\n%s", got)
	}
	if !(tokenAt < listenAt && listenAt < uiDirAt) {
		t.Fatalf("raw key order not preserved (token, listen, ui_dir):\n%s", got)
	}
	if !strings.Contains(got, `"listen": "127.0.0.1:8317"`) || !strings.Contains(got, `"ui_dir": "/srv/MARKER-UIDIR"`) {
		t.Fatalf("other keys changed:\n%s", got)
	}
}

// TestReplaceWebUITokenNoRaw covers a hand-built config with no
// raw capture: only the parsed value changes, and the synthesized
// block renders in canonical order.
func TestReplaceWebUITokenNoRaw(t *testing.T) {
	cfg := &SingleConfig{
		Profiles: map[string]*Profile{},
		WebUI:    &WebUIConfig{Listen: "127.0.0.1:9000", Token: "MARKER-OLD-TOKEN"},
	}
	const hashed = "$2b$10$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	if err := cfg.ReplaceWebUIToken(hashed); err != nil {
		t.Fatalf("ReplaceWebUIToken: %v", err)
	}
	encoded, err := encodeSingleConfig(cfg)
	if err != nil {
		t.Fatalf("encodeSingleConfig: %v", err)
	}
	got := string(encoded)
	if !strings.Contains(got, `"token": "`+hashed+`"`) {
		t.Fatalf("hash not in encoding:\n%s", got)
	}
	if strings.Index(got, `"listen"`) > strings.Index(got, `"token"`) {
		t.Fatalf("synthesized block not in canonical order:\n%s", got)
	}
}

// TestReplaceWebUITokenAbsentBlock fails closed: there is no
// webui block to store a token in.
func TestReplaceWebUITokenAbsentBlock(t *testing.T) {
	cfg := parseWebUITestConfig(t, `{"profiles":{}}`)
	if err := cfg.ReplaceWebUIToken("hash"); err == nil {
		t.Fatal("replacing the token of an absent block succeeded, want an error")
	}
}
