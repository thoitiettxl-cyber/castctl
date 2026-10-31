// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package profile

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func keeperTestConfig(t *testing.T, keeper string) string {
	t.Helper()
	return `{"profiles": {"muse01": {}, "muse02": {}}, "telegram": {"profile": "muse01", "token": "123456:FAKE-TOKEN-0123456789ABCD", "allowed_user_ids": [111]}, "keeper": ` + keeper + `}`
}

func TestParseKeeperBlockValid(t *testing.T) {
	cfg, err := ParseSingleConfig([]byte(keeperTestConfig(t, `[{"tag": "k1", "profile": "muse01", "browser": "http://127.0.0.1:9226/", "interval": "30m", "notify": "telegram"}, {"tag": "k2", "profile": "muse02", "browser": "ws://127.0.0.1:9227/devtools/browser/FAKE-UUID"}]`)), t.TempDir())
	if err != nil {
		t.Fatalf("ParseSingleConfig: %v", err)
	}
	if cfg.Keeper == nil || len(cfg.Keeper.Entries) != 2 {
		t.Fatalf("Keeper entries = %v; want 2", cfg.Keeper)
	}
	e1 := cfg.Keeper.Entries[0]
	if e1.Tag != "k1" || e1.Profile != "muse01" || e1.Browser != "http://127.0.0.1:9226/" || e1.Interval != 30*time.Minute || !e1.IntervalSet || e1.Notify != "telegram" {
		t.Fatalf("entry 1 = %+v", e1)
	}
	e2 := cfg.Keeper.Entries[1]
	if e2.IntervalSet || e2.EffectiveInterval() != DefaultKeeperInterval {
		t.Fatalf("entry 2 zero-value interval: set=%v effective=%v; want unset/24h", e2.IntervalSet, e2.EffectiveInterval())
	}
	if got := cfg.Keeper.KeeperEntryForProfile("muse02"); got != e2 {
		t.Fatalf("KeeperEntryForProfile(muse02) = %v; want entry 2", got)
	}
	if got := cfg.Keeper.KeeperEntryForProfile("missing"); got != nil {
		t.Fatalf("KeeperEntryForProfile(missing) = %v; want nil", got)
	}
}

func TestParseKeeperBlockAbsent(t *testing.T) {
	cfg, err := ParseSingleConfig([]byte(`{"profiles": {"muse01": {}}}`), t.TempDir())
	if err != nil {
		t.Fatalf("ParseSingleConfig: %v", err)
	}
	if cfg.Keeper != nil {
		t.Fatalf("Keeper = %v; want nil (absent block)", cfg.Keeper)
	}
	if _, err := ResolveKeeper(cfg); err != nil {
		t.Fatalf("ResolveKeeper: %v", err)
	}
}

func TestParseKeeperBlockErrors(t *testing.T) {
	cases := []struct {
		name   string
		keeper string
	}{
		{"not array", `{}`},
		{"entry not object", `[1]`},
		{"unknown key", `[{"tag": "k", "profile": "muse01", "browser": "http://127.0.0.1:9226/", "enabled": true}]`},
		{"missing tag", `[{"profile": "muse01", "browser": "http://127.0.0.1:9226/"}]`},
		{"missing profile", `[{"tag": "k", "browser": "http://127.0.0.1:9226/"}]`},
		{"missing browser", `[{"tag": "k", "profile": "muse01"}]`},
		{"duplicate tag", `[{"tag": "k", "profile": "muse01", "browser": "http://127.0.0.1:9226/"}, {"tag": "k", "profile": "muse02", "browser": "http://127.0.0.1:9227/"}]`},
		{"dangling profile", `[{"tag": "k", "profile": "ghost", "browser": "http://127.0.0.1:9226/"}]`},
		{"duplicate profile", `[{"tag": "k1", "profile": "muse01", "browser": "http://127.0.0.1:9226/"}, {"tag": "k2", "profile": "muse01", "browser": "http://127.0.0.1:9227/"}]`},
		{"duplicate browser", `[{"tag": "k1", "profile": "muse01", "browser": "http://127.0.0.1:9226/"}, {"tag": "k2", "profile": "muse02", "browser": "http://127.0.0.1:9226/"}]`},
		{"non-loopback host", `[{"tag": "k", "profile": "muse01", "browser": "http://192.168.1.10:9226/"}]`},
		{"public host", `[{"tag": "k", "profile": "muse01", "browser": "http://example.com:9226/"}]`},
		{"https scheme", `[{"tag": "k", "profile": "muse01", "browser": "https://127.0.0.1:9226/"}]`},
		{"missing port", `[{"tag": "k", "profile": "muse01", "browser": "http://127.0.0.1/"}]`},
		{"userinfo", `[{"tag": "k", "profile": "muse01", "browser": "http://user@127.0.0.1:9226/"}]`},
		{"bad interval", `[{"tag": "k", "profile": "muse01", "browser": "http://127.0.0.1:9226/", "interval": "soon"}]`},
		{"zero interval", `[{"tag": "k", "profile": "muse01", "browser": "http://127.0.0.1:9226/", "interval": "0s"}]`},
		{"numeric interval", `[{"tag": "k", "profile": "muse01", "browser": "http://127.0.0.1:9226/", "interval": 60}]`},
		{"unknown notify", `[{"tag": "k", "profile": "muse01", "browser": "http://127.0.0.1:9226/", "notify": "email"}]`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseSingleConfig([]byte(keeperTestConfig(t, tc.keeper)), t.TempDir()); err == nil {
				t.Fatalf("ParseSingleConfig(%s) succeeded; want config error", tc.keeper)
			}
		})
	}
	// notify "telegram" without a telegram block is a dangling reference.
	noTG := `{"profiles": {"muse01": {}}, "keeper": [{"tag": "k", "profile": "muse01", "browser": "http://127.0.0.1:9226/", "notify": "telegram"}]}`
	if _, err := ParseSingleConfig([]byte(noTG), t.TempDir()); err == nil {
		t.Fatal("notify telegram without telegram block succeeded; want config error")
	}
	// localhost host is loopback-legal.
	cfg, err := ParseSingleConfig([]byte(keeperTestConfig(t, `[{"tag": "k", "profile": "muse01", "browser": "http://localhost:9226/"}]`)), t.TempDir())
	if err != nil {
		t.Fatalf("localhost browser URL rejected: %v", err)
	}
	if cfg.Keeper.Entries[0].Browser != "http://localhost:9226/" {
		t.Fatalf("browser = %q", cfg.Keeper.Entries[0].Browser)
	}
}

func TestKeeperBlockRoundTrip(t *testing.T) {
	base := t.TempDir()
	raw := keeperTestConfig(t, `[{"tag": "k1", "profile": "muse01", "browser": "http://127.0.0.1:9226/", "interval": "30m", "notify": "telegram"}]`)
	cfg, err := ParseSingleConfig([]byte(raw), base)
	if err != nil {
		t.Fatalf("ParseSingleConfig: %v", err)
	}
	// Raw preservation: re-encoding keeps the entry verbatim.
	enc, err := encodeSingleConfig(cfg)
	if err != nil {
		t.Fatalf("encodeSingleConfig: %v", err)
	}
	if !strings.Contains(string(enc), `"keeper"`) || !strings.Contains(string(enc), `"interval": "30m"`) {
		t.Fatalf("encoded config lost keeper block:\n%s", enc)
	}
	cfg2, err := ParseSingleConfig(enc, base)
	if err != nil {
		t.Fatalf("re-parse: %v", err)
	}
	if len(cfg2.Keeper.Entries) != 1 || cfg2.Keeper.Entries[0].Tag != "k1" {
		t.Fatalf("re-parsed keeper = %+v", cfg2.Keeper)
	}
	// Hand-built config (no raw) renders deterministically.
	hand := &SingleConfig{
		Profiles: map[string]*Profile{"muse01": {Name: "muse01"}},
		Keeper: &KeeperConfig{Entries: []*KeeperEntry{
			{Tag: "k1", Profile: "muse01", Browser: "http://127.0.0.1:9226/", Interval: 2 * time.Hour, IntervalSet: true},
		}},
	}
	enc2, err := encodeSingleConfig(hand)
	if err != nil {
		t.Fatalf("encodeSingleConfig(hand-built): %v", err)
	}
	cfg3, err := ParseSingleConfig(enc2, base)
	if err != nil {
		t.Fatalf("re-parse hand-built: %v", err)
	}
	if len(cfg3.Keeper.Entries) != 1 || cfg3.Keeper.Entries[0].Interval != 2*time.Hour {
		t.Fatalf("hand-built round-trip keeper = %+v", cfg3.Keeper)
	}
	// Absent block stays absent on save.
	cfg4, err := ParseSingleConfig([]byte(`{"profiles": {"muse01": {}}}`), base)
	if err != nil {
		t.Fatalf("ParseSingleConfig: %v", err)
	}
	if err := SaveSingleConfig(base, cfg4); err != nil {
		t.Fatalf("SaveSingleConfig: %v", err)
	}
	saved, err := os.ReadFile(filepath.Join(base, "config.json"))
	if err != nil {
		t.Fatalf("read saved config: %v", err)
	}
	if strings.Contains(string(saved), "keeper") {
		t.Fatalf("save wrote an absent keeper block:\n%s", saved)
	}
}

func TestCookiesFileLockTimeoutAndSerialisation(t *testing.T) {
	base := t.TempDir()
	cookiesPath := filepath.Join(base, "cookies.txt")
	release, err := LockCookiesFile(base, "default", cookiesPath, time.Second)
	if err != nil {
		t.Fatalf("LockCookiesFile: %v", err)
	}
	// Second acquisition with a short timeout must fail, not block.
	if _, err := LockCookiesFile(base, "default", cookiesPath, 50*time.Millisecond); !errors.Is(err, ErrCookiesLockTimeout) {
		t.Fatalf("second lock err = %v; want ErrCookiesLockTimeout", err)
	}
	release()
	// After release, acquisition succeeds again.
	release2, err := LockCookiesFile(base, "default", cookiesPath, time.Second)
	if err != nil {
		t.Fatalf("LockCookiesFile after release: %v", err)
	}
	release2()

	// Concurrent locked writes serialise: every write succeeds and
	// the final file is one complete payload, never torn.
	const writers = 16
	done := make(chan error, writers)
	for i := 0; i < writers; i++ {
		go func(i int) {
			payload := []byte("a=b; hatch_sess=FAKE-" + string(rune('A'+i)) + "\n")
			_, err := WriteCookiesFileLocked(base, "default", cookiesPath, payload, 5*time.Second)
			done <- err
		}(i)
	}
	for i := 0; i < writers; i++ {
		if err := <-done; err != nil {
			t.Fatalf("WriteCookiesFileLocked: %v", err)
		}
	}
	data, err := os.ReadFile(cookiesPath)
	if err != nil {
		t.Fatalf("read cookies: %v", err)
	}
	if len(data) == 0 || !strings.HasSuffix(string(data), "\n") || strings.Count(string(data), "\n") != 1 {
		t.Fatalf("final cookies file torn or malformed: %q", data)
	}
	st, err := os.Stat(cookiesPath)
	if err != nil {
		t.Fatalf("stat cookies: %v", err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("cookies mode = %o; want 600", st.Mode().Perm())
	}
	if st, err := os.Stat(cookiesPath + ".lock"); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("lock file stat = %v, %v; want present at 0600", st, err)
	}
}
