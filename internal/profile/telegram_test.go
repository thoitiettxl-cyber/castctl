// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package profile

// Tests for the top-level `telegram` config block.
//
// What each test observes: ParseSingleConfig / ResolveTelegram /
// buildSingleFileOrdered / cloneSingleConfig behaviour for a
// `telegram` block. What the red run catches: the block rejected as
// an unknown top-level key (singleTopLevelKeys has no "telegram"
// entry), a dangling profile reference accepted, an empty allowlist
// accepted, a malformed token echoed into an error, the block lost
// on save/migrate, or the token surviving RedactConfig.
//
// Fixture token: a FAKE value matching the Python shape check
// (src/muse_cli/tgapi.py:49-52: digits, colon, 20+ token
// characters). It names no real bot and must never appear in any
// error, log, or display output asserted below.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// fakeTelegramToken is a fixture only. Tests assert it never
// appears in errors or redacted display output.
const fakeTelegramToken = "123456:ABCDEFGHIJ0123456789ab"

func telegramJSON(t *testing.T, block string) *SingleConfig {
	t.Helper()
	data := `{"profiles":{"muse01":{}},"telegram":` + block + `}`
	cfg, err := ParseSingleConfig([]byte(data), "/base")
	if err != nil {
		t.Fatalf("ParseSingleConfig(%s) = %v", data, err)
	}
	return cfg
}

// telegramConfigsEqual compares two parsed blocks field by field
// (TelegramConfig contains a slice, so it is not ==-comparable).
func telegramConfigsEqual(a, b *TelegramConfig) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Profile == b.Profile && a.Token == b.Token &&
		slices.Equal(a.AllowedUserIDs, b.AllowedUserIDs) &&
		a.AutoApprove == b.AutoApprove && a.AutoAllowOnce == b.AutoAllowOnce
}

func TestParseTelegramBlockValid(t *testing.T) {
	t.Parallel()
	cfg := telegramJSON(t, `{"profile":"muse01","token":"`+fakeTelegramToken+`","allowed_user_ids":[111,222]}`)
	if cfg.Telegram == nil {
		t.Fatal("Telegram is nil; want parsed block")
	}
	tg := cfg.Telegram
	if tg.Profile != "muse01" || tg.Token != fakeTelegramToken {
		t.Errorf("Telegram profile/token = %q/<len %d>; want muse01/fixture", tg.Profile, len(tg.Token))
	}
	if len(tg.AllowedUserIDs) != 2 || tg.AllowedUserIDs[0] != 111 || tg.AllowedUserIDs[1] != 222 {
		t.Errorf("AllowedUserIDs = %v; want [111 222]", tg.AllowedUserIDs)
	}
	if tg.AutoApprove || tg.AutoAllowOnce {
		t.Errorf("toggles = %v/%v; want false/false (explicit-config defaults, see telegram.go)", tg.AutoApprove, tg.AutoAllowOnce)
	}
	// Toggles on parse; order preserved.
	cfg = telegramJSON(t, `{"profile":"muse01","token":"`+fakeTelegramToken+`","allowed_user_ids":[7],"auto_approve":true,"auto_allow_once":true}`)
	if !cfg.Telegram.AutoApprove || !cfg.Telegram.AutoAllowOnce {
		t.Errorf("toggles = %v/%v; want true/true", cfg.Telegram.AutoApprove, cfg.Telegram.AutoAllowOnce)
	}
	// Key order in the file does not matter.
	cfg = telegramJSON(t, `{"allowed_user_ids":[7],"auto_allow_once":false,"token":"`+fakeTelegramToken+`","profile":"muse01","auto_approve":false}`)
	if cfg.Telegram == nil || cfg.Telegram.Profile != "muse01" {
		t.Errorf("reordered block did not parse: %+v", cfg.Telegram)
	}
}

func TestParseTelegramBlockInvalid(t *testing.T) {
	t.Parallel()
	bad := []string{
		`{"profiles":{"muse01":{}},"telegram":"x"}`,                                                          // not an object
		`{"profiles":{"muse01":{}},"telegram":null}`,                                                         // null is not an object
		`{"profiles":{"muse01":{}},"telegram":{}}`,                                                           // empty: every required key missing
		`{"profiles":{"muse01":{}},"telegram":{"token":"` + fakeTelegramToken + `","allowed_user_ids":[1]}}`, // no profile
		`{"profiles":{"muse01":{}},"telegram":{"profile":"muse01","allowed_user_ids":[1]}}`,                  // no token
		`{"profiles":{"muse01":{}},"telegram":{"profile":"muse01","token":"` + fakeTelegramToken + `"}}`,     // no allowlist
		`{"profiles":{"muse01":{}},"telegram":{"profile":3,"token":"` + fakeTelegramToken + `","allowed_user_ids":[1]}}`,
		`{"profiles":{"muse01":{}},"telegram":{"profile":"","token":"` + fakeTelegramToken + `","allowed_user_ids":[1]}}`,
		`{"profiles":{"muse01":{}},"telegram":{"profile":"ghost","token":"` + fakeTelegramToken + `","allowed_user_ids":[1]}}`, // dangling profile
		`{"profiles":{"muse01":{}},"telegram":{"profile":"muse01","token":"","allowed_user_ids":[1]}}`,
		`{"profiles":{"muse01":{}},"telegram":{"profile":"muse01","token":"not-a-token","allowed_user_ids":[1]}}`,
		`{"profiles":{"muse01":{}},"telegram":{"profile":"muse01","token":"123:short","allowed_user_ids":[1]}}`, // suffix < 20 chars
		`{"profiles":{"muse01":{}},"telegram":{"profile":"muse01","token":42,"allowed_user_ids":[1]}}`,
		`{"profiles":{"muse01":{}},"telegram":{"profile":"muse01","token":"` + fakeTelegramToken + `","allowed_user_ids":[]}}`, // empty allowlist
		`{"profiles":{"muse01":{}},"telegram":{"profile":"muse01","token":"` + fakeTelegramToken + `","allowed_user_ids":"111"}}`,
		`{"profiles":{"muse01":{}},"telegram":{"profile":"muse01","token":"` + fakeTelegramToken + `","allowed_user_ids":[0]}}`, // non-positive id
		`{"profiles":{"muse01":{}},"telegram":{"profile":"muse01","token":"` + fakeTelegramToken + `","allowed_user_ids":[-5]}}`,
		`{"profiles":{"muse01":{}},"telegram":{"profile":"muse01","token":"` + fakeTelegramToken + `","allowed_user_ids":[1.5]}}`,
		`{"profiles":{"muse01":{}},"telegram":{"profile":"muse01","token":"` + fakeTelegramToken + `","allowed_user_ids":["111"]}}`,
		`{"profiles":{"muse01":{}},"telegram":{"profile":"muse01","token":"` + fakeTelegramToken + `","allowed_user_ids":[1],"auto_approve":"yes"}}`,
		`{"profiles":{"muse01":{}},"telegram":{"profile":"muse01","token":"` + fakeTelegramToken + `","allowed_user_ids":[1],"auto_allow_once":1}}`,
		`{"profiles":{"muse01":{}},"telegram":{"profile":"muse01","token":"` + fakeTelegramToken + `","allowed_user_ids":[1],"owner_id":111}}`, // unknown key
		`{"profiles":{"muse01":{}},"telegram":{"profile":"muse01","token":"` + fakeTelegramToken + `","allowed_user_ids":[1],"poll_timeout":25}}`,
	}
	for _, data := range bad {
		cfg, err := ParseSingleConfig([]byte(data), "/base")
		if err == nil {
			t.Errorf("ParseSingleConfig(%s) = %+v, want error (exit 2)", data, cfg)
			continue
		}
		if ExitCode(err) != 2 {
			t.Errorf("ParseSingleConfig(%s) exit code = %d, want 2", data, ExitCode(err))
		}
		if strings.Contains(err.Error(), fakeTelegramToken) {
			t.Errorf("ParseSingleConfig(%s) error echoes the fixture token: %v", data, err)
		}
	}
}

func TestParseTelegramBlockAbsent(t *testing.T) {
	t.Parallel()
	cfg, err := ParseSingleConfig([]byte(`{"profiles":{"muse01":{}}}`), "/base")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Telegram != nil {
		t.Errorf("Telegram = %+v; want nil (absent block = feature off)", cfg.Telegram)
	}
	tg, err := ResolveTelegram(cfg)
	if err != nil {
		t.Fatalf("ResolveTelegram(absent) = %v", err)
	}
	if tg != nil {
		t.Errorf("ResolveTelegram(absent) = %+v; want nil", tg)
	}
	// A nil SingleConfig resolves to no telegram block, never an error.
	tg, err = ResolveTelegram(nil)
	if err != nil || tg != nil {
		t.Errorf("ResolveTelegram(nil) = %+v, %v; want nil, nil", tg, err)
	}
}

func TestResolveTelegram(t *testing.T) {
	t.Parallel()
	cfg := telegramJSON(t, `{"profile":"muse01","token":"`+fakeTelegramToken+`","allowed_user_ids":[111]}`)
	tg, err := ResolveTelegram(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if tg == nil || tg.Profile != "muse01" {
		t.Fatalf("ResolveTelegram = %+v; want the parsed block", tg)
	}
	// ResolveTelegram returns the block itself (no copy, no mutation):
	// callers must not mutate it. A second call returns the same block.
	tg2, err := ResolveTelegram(cfg)
	if err != nil || tg2 != tg {
		t.Errorf("ResolveTelegram second call = %+v, %v; want same block", tg2, err)
	}
}

func TestTelegramBlockSaveRoundTrip(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfg := telegramJSON(t, `{"profile":"muse01","token":"`+fakeTelegramToken+`","allowed_user_ids":[111,222],"auto_approve":true,"auto_allow_once":false}`)
	if err := SaveSingleConfig(dir, cfg); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if err := json.Unmarshal(data, &root); err != nil {
		t.Fatal(err)
	}
	block, ok := root["telegram"].(map[string]any)
	if !ok {
		t.Fatalf("saved config has no telegram block: %s", data)
	}
	if block["profile"] != "muse01" || block["token"] != fakeTelegramToken || block["auto_approve"] != true || block["auto_allow_once"] != false {
		t.Errorf("saved telegram block = %v; want the authored values", block)
	}
	ids, ok := block["allowed_user_ids"].([]any)
	if !ok || len(ids) != 2 || ids[0] != float64(111) || ids[1] != float64(222) {
		t.Errorf("saved allowed_user_ids = %v; want [111 222]", block["allowed_user_ids"])
	}
	loaded, err := ParseSingleConfig(data, dir)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Telegram == nil || !telegramConfigsEqual(loaded.Telegram, cfg.Telegram) {
		t.Errorf("reloaded Telegram = %+v, want %+v", loaded.Telegram, cfg.Telegram)
	}

	// Absent stays absent on save.
	dir2 := t.TempDir()
	plain, err := ParseSingleConfig([]byte(`{"profiles":{"muse01":{}}}`), "/base")
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveSingleConfig(dir2, plain); err != nil {
		t.Fatal(err)
	}
	data2, err := os.ReadFile(filepath.Join(dir2, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data2), `"telegram"`) {
		t.Errorf("saved config without a telegram block gained one: %s", data2)
	}
}

func TestTelegramBlockStructRender(t *testing.T) {
	t.Parallel()
	// A SingleConfig built without raw JSON (e.g. by a mutation
	// command) must render the block field-by-field, not drop it.
	cfg := telegramJSON(t, `{"profile":"muse01","token":"`+fakeTelegramToken+`","allowed_user_ids":[9],"auto_approve":true}`)
	cfg.rawTelegram = nil
	root, err := buildSingleFileOrdered(cfg)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := encodeOrderedJSON(root)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"telegram"`) || !strings.Contains(string(raw), `"muse01"`) || !strings.Contains(string(raw), fakeTelegramToken) {
		t.Errorf("struct-rendered config lost the telegram block: %s", raw)
	}
}

func TestCloneSingleConfigCarriesTelegram(t *testing.T) {
	t.Parallel()
	cfg := telegramJSON(t, `{"profile":"muse01","token":"`+fakeTelegramToken+`","allowed_user_ids":[111,222]}`)
	cloned := cloneSingleConfig(cfg)
	if cloned == nil || cloned.Telegram == nil || !telegramConfigsEqual(cloned.Telegram, cfg.Telegram) {
		t.Fatalf("clone Telegram = %+v, want %+v", cloned.Telegram, cfg.Telegram)
	}
	// Mutating the clone must not mutate the original (slice copy).
	cloned.Telegram.AllowedUserIDs[0] = 999
	if cfg.Telegram.AllowedUserIDs[0] != 111 {
		t.Errorf("clone shares AllowedUserIDs with original: %v", cfg.Telegram.AllowedUserIDs)
	}
	root, err := buildSingleFileOrdered(cloneSingleConfig(cfg))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := encodeOrderedJSON(root)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"telegram"`) {
		t.Errorf("rendered clone has no telegram block: %s", raw)
	}
	// A clone of a telegram-less config renders no telegram block.
	plain, err := ParseSingleConfig([]byte(`{"profiles":{"muse01":{}}}`), "/base")
	if err != nil {
		t.Fatal(err)
	}
	root2, err := buildSingleFileOrdered(cloneSingleConfig(plain))
	if err != nil {
		t.Fatal(err)
	}
	raw2, err := encodeOrderedJSON(root2)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw2), `"telegram"`) {
		t.Errorf("rendered telegram-less clone gained a telegram block: %s", raw2)
	}
}

func TestRedactConfigHidesTelegramToken(t *testing.T) {
	t.Parallel()
	cfg := telegramJSON(t, `{"profile":"muse01","token":"`+fakeTelegramToken+`","allowed_user_ids":[111]}`)
	out, err := RedactConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), fakeTelegramToken) {
		t.Errorf("RedactConfig leaks the fixture token: %s", out)
	}
	var root map[string]any
	if err := json.Unmarshal(out, &root); err != nil {
		t.Fatal(err)
	}
	block, ok := root["telegram"].(map[string]any)
	if !ok {
		t.Fatalf("redacted config has no telegram block: %s", out)
	}
	if block["token"] != "<redacted>" {
		t.Errorf("redacted token = %v; want <redacted>", block["token"])
	}
	if block["profile"] != "muse01" {
		t.Errorf("redacted profile = %v; want muse01", block["profile"])
	}
	ids, ok := block["allowed_user_ids"].([]any)
	if !ok || len(ids) != 1 || ids[0] != float64(111) {
		t.Errorf("redacted allowed_user_ids = %v; want [111]", block["allowed_user_ids"])
	}
}
