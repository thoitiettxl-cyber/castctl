// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package profile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const credentialsSentinelUser = "SENTINEL-USER-9f3a7c"
const credentialsSentinelPass = "SENTINEL-PASS-9f3a7c"

func credentialsTestConfig(t *testing.T, creds, keeper string) string {
	t.Helper()
	return `{"profiles": {"muse01": {}, "muse02": {}}, "credentials": ` + creds + `, "keeper": ` + keeper + `}`
}

// TestParseCredentialsBlockValid pins the credentials schema:
// parse, accessor, defaults, and the keeper cross-reference.
func TestParseCredentialsBlockValid(t *testing.T) {
	t.Parallel()
	cfg, err := ParseSingleConfig([]byte(credentialsTestConfig(t,
		`[{"tag": "cred1", "profile": "muse01", "username": "`+credentialsSentinelUser+`", "password": "`+credentialsSentinelPass+`"}]`,
		`[{"tag": "k1", "profile": "muse01", "credentials": "cred1"}]`)), t.TempDir())
	if err != nil {
		t.Fatalf("ParseSingleConfig: %v", err)
	}
	creds, err := ResolveCredentials(cfg)
	if err != nil {
		t.Fatalf("ResolveCredentials: %v", err)
	}
	if creds == nil || len(creds.Entries) != 1 {
		t.Fatalf("Credentials entries = %v; want 1", creds)
	}
	// The values are unexported: the only read path is the
	// accessor, and it returns exactly the stored values.
	cred, ok := creds.CredentialForProfile("muse01")
	if !ok {
		t.Fatal("CredentialForProfile(muse01) = false; want true")
	}
	if cred.Username != credentialsSentinelUser || cred.Password != credentialsSentinelPass {
		t.Fatal("CredentialForProfile returned wrong values (not compared by value here)")
	}
	if _, ok := creds.CredentialForProfile("muse02"); ok {
		t.Fatal("CredentialForProfile(muse02) = true; want false")
	}
	if got := creds.CredentialEntryForTag("cred1"); got == nil || got.Profile != "muse01" {
		t.Fatalf("CredentialEntryForTag(cred1) = %v; want muse01 entry", got)
	}
	if got := creds.CredentialEntryForTag("ghost"); got != nil {
		t.Fatalf("CredentialEntryForTag(ghost) = %v; want nil", got)
	}
	entry := cfg.Keeper.Entries[0]
	if entry.Credentials != "cred1" {
		t.Fatalf("keeper credentials ref = %q; want cred1", entry.Credentials)
	}
	// Defaults: wake on, default ladder, default window, 3 caps.
	if !entry.EffectiveWakeOnGatewayFailure() {
		t.Error("EffectiveWakeOnGatewayFailure = false; want true (default)")
	}
	if got := entry.EffectiveRetryBackoff(); len(got) != 3 || got[0] != 5*time.Minute || got[1] != 15*time.Minute || got[2] != 45*time.Minute {
		t.Errorf("EffectiveRetryBackoff = %v; want [5m 15m 45m]", got)
	}
	if entry.EffectiveExpiringWithin() != DefaultExpiringWithin {
		t.Errorf("EffectiveExpiringWithin = %v; want %v", entry.EffectiveExpiringWithin(), DefaultExpiringWithin)
	}
	if entry.EffectiveWakeAttempts() != DefaultKeeperAttempts || entry.EffectiveReloginAttempts() != DefaultKeeperAttempts {
		t.Errorf("attempt caps = %d/%d; want %d", entry.EffectiveWakeAttempts(), entry.EffectiveReloginAttempts(), DefaultKeeperAttempts)
	}
}

// TestCredentialsRedactedEverywhere pins G2: no display path
// may ever carry a credential value. RedactConfig renders the
// raw block through redact.Value; the sentinel values must
// not appear anywhere in the output.
func TestCredentialsRedactedEverywhere(t *testing.T) {
	t.Parallel()
	cfg, err := ParseSingleConfig([]byte(credentialsTestConfig(t,
		`[{"tag": "cred1", "profile": "muse01", "username": "`+credentialsSentinelUser+`", "password": "`+credentialsSentinelPass+`"}]`,
		`[{"tag": "k1", "profile": "muse01", "credentials": "cred1"}]`)), t.TempDir())
	if err != nil {
		t.Fatalf("ParseSingleConfig: %v", err)
	}
	out, err := RedactConfig(cfg)
	if err != nil {
		t.Fatalf("RedactConfig: %v", err)
	}
	if strings.Contains(string(out), credentialsSentinelUser) || strings.Contains(string(out), credentialsSentinelPass) {
		t.Fatalf("RedactConfig leaks a credential value:\n%s", out)
	}
	if !strings.Contains(string(out), "<redacted>") {
		t.Fatalf("RedactConfig output has no <redacted> marker:\n%s", out)
	}
	// RedactJSON over the saved file bytes: same guarantee —
	// the save encoder writes values, the display encoder
	// must redact them.
	base := BaseDir(t.TempDir())
	if err := SaveSingleConfig(base, cfg); err != nil {
		t.Fatalf("SaveSingleConfig: %v", err)
	}
	saved, err := os.ReadFile(filepath.Join(base, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	redacted, err := RedactJSON(saved)
	if err != nil {
		t.Fatalf("RedactJSON: %v", err)
	}
	if strings.Contains(string(redacted), credentialsSentinelUser) || strings.Contains(string(redacted), credentialsSentinelPass) {
		t.Fatalf("RedactJSON leaks a credential value:\n%s", redacted)
	}
}

// TestCredentialsRoundTrip pins save/load: credentials survive
// a guarded save verbatim (values intact, 0600, credentials
// block after webui in key order), and no .bak file appears.
func TestCredentialsRoundTrip(t *testing.T) {
	t.Parallel()
	base := BaseDir(t.TempDir())
	cfg, err := ParseSingleConfig([]byte(credentialsTestConfig(t,
		`[{"tag": "cred1", "profile": "muse01", "username": "`+credentialsSentinelUser+`", "password": "`+credentialsSentinelPass+`"}]`,
		`[{"tag": "k1", "profile": "muse01", "credentials": "cred1", "retry_backoff": ["1m", "2m"], "expiring_within": "48h", "wake_attempts": 2, "relogin_attempts": 1, "wake_on_gateway_failure": false}]`)), base)
	if err != nil {
		t.Fatalf("ParseSingleConfig: %v", err)
	}
	if err := SaveSingleConfig(base, cfg); err != nil {
		t.Fatalf("SaveSingleConfig: %v", err)
	}
	path := filepath.Join(base, "config.json")
	if mode := fileMode(t, path); mode != 0o600 {
		t.Errorf("saved config mode = %o; want 600", mode)
	}
	entries, err := os.ReadDir(base)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".bak") {
			t.Errorf("save wrote a backup file %q; want none", e.Name())
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Fixed key order: credentials after webui (absent here,
	// so after keeper), and the raw block is preserved.
	keeperIdx := strings.Index(string(data), `"keeper"`)
	credsIdx := strings.Index(string(data), `"credentials"`)
	if credsIdx < 0 || keeperIdx < 0 || credsIdx < keeperIdx {
		t.Errorf("saved key order wrong (keeper=%d credentials=%d):\n%s", keeperIdx, credsIdx, data)
	}
	cfg2, err := ParseSingleConfig(data, base)
	if err != nil {
		t.Fatalf("re-parse: %v", err)
	}
	creds2, err := ResolveCredentials(cfg2)
	if err != nil {
		t.Fatalf("ResolveCredentials: %v", err)
	}
	cred, ok := creds2.CredentialForProfile("muse01")
	if !ok || cred.Username != credentialsSentinelUser || cred.Password != credentialsSentinelPass {
		t.Fatal("credentials did not survive save/load")
	}
	e := cfg2.Keeper.Entries[0]
	if e.Browser != "" {
		t.Errorf("browser = %q; want empty (keep-alive-only entry)", e.Browser)
	}
	if got := e.EffectiveRetryBackoff(); len(got) != 2 || got[0] != time.Minute || got[1] != 2*time.Minute {
		t.Errorf("retry_backoff = %v; want [1m 2m]", got)
	}
	if e.EffectiveExpiringWithin() != 48*time.Hour {
		t.Errorf("expiring_within = %v; want 48h", e.EffectiveExpiringWithin())
	}
	if e.EffectiveWakeAttempts() != 2 || e.EffectiveReloginAttempts() != 1 {
		t.Errorf("attempt caps = %d/%d; want 2/1", e.EffectiveWakeAttempts(), e.EffectiveReloginAttempts())
	}
	if e.EffectiveWakeOnGatewayFailure() {
		t.Error("wake_on_gateway_failure = true; want false")
	}
}

// TestParseCredentialsBlockErrors pins every refusal: shape,
// unknown keys, empty values, duplicates, dangling refs,
// cross-profile refs, and one-entry-per-profile.
func TestParseCredentialsBlockErrors(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		creds   string
		keeper  string
		wantErr string
	}{
		{"not array", `{}`, `[]`, "array"},
		{"entry not object", `[42]`, `[]`, "object"},
		{"unknown key", `[{"tag":"c","profile":"muse01","username":"u","password":"p","extra":1}]`, `[]`, "unknown"},
		{"missing tag", `[{"profile":"muse01","username":"u","password":"p"}]`, `[]`, "tag"},
		{"missing profile", `[{"tag":"c","username":"u","password":"p"}]`, `[]`, "profile"},
		{"missing username", `[{"tag":"c","profile":"muse01","password":"p"}]`, `[]`, "username"},
		{"missing password", `[{"tag":"c","profile":"muse01","username":"u"}]`, `[]`, "password"},
		{"empty username", `[{"tag":"c","profile":"muse01","username":"","password":"p"}]`, `[]`, "username"},
		{"empty password", `[{"tag":"c","profile":"muse01","username":"u","password":""}]`, `[]`, "password"},
		{"whitespace username", `[{"tag":"c","profile":"muse01","username":"   ","password":"p"}]`, `[]`, "username"},
		{"whitespace password", `[{"tag":"c","profile":"muse01","username":"u","password":" \t\n "}]`, `[]`, "password"},
		{"duplicate tag", `[{"tag":"c","profile":"muse01","username":"u","password":"p"},{"tag":"c","profile":"muse02","username":"u","password":"p"}]`, `[]`, "duplicate"},
		{"dangling profile", `[{"tag":"c","profile":"ghost","username":"u","password":"p"}]`, `[]`, "does not exist"},
		{"two per profile", `[{"tag":"c1","profile":"muse01","username":"u","password":"p"},{"tag":"c2","profile":"muse01","username":"u","password":"p"}]`, `[]`, "both name"},
		{"keeper dangling ref", `[]`, `[{"tag":"k","profile":"muse01","credentials":"ghost"}]`, "does not exist"},
		{"keeper ref no block", `[]`, `[{"tag":"k","profile":"muse01","credentials":"c"}]`, "does not exist"},
		{"keeper cross-profile ref", `[{"tag":"c","profile":"muse02","username":"u","password":"p"}]`, `[{"tag":"k","profile":"muse01","credentials":"c"}]`, "not"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseSingleConfig([]byte(credentialsTestConfig(t, tc.creds, tc.keeper)), t.TempDir())
			if err == nil {
				t.Fatalf("ParseSingleConfig = nil error; want error containing %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %q; want it to contain %q", err.Error(), tc.wantErr)
			}
			if ExitCode(err) != 2 {
				t.Errorf("ExitCode = %d; want 2", ExitCode(err))
			}
			// The error must never carry a credential value.
			if strings.Contains(err.Error(), "SENTINEL") {
				t.Errorf("error leaks a sentinel: %q", err.Error())
			}
		})
	}
}

// TestKeeperNewKeysErrors pins refusals for the new keeper
// entry keys: bad ladder, bad window, bad caps, bad wake flag.
func TestKeeperNewKeysErrors(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		entry string
	}{
		{"empty ladder", `{"tag":"k","profile":"muse01","retry_backoff":[]}`},
		{"ladder number", `{"tag":"k","profile":"muse01","retry_backoff":[5]}`},
		{"ladder zero", `{"tag":"k","profile":"muse01","retry_backoff":["0s"]}`},
		{"ladder too long", `{"tag":"k","profile":"muse01","retry_backoff":["1m","1m","1m","1m","1m","1m","1m","1m","1m"]}`},
		{"expiring zero", `{"tag":"k","profile":"muse01","expiring_within":"0s"}`},
		{"expiring number", `{"tag":"k","profile":"muse01","expiring_within":72}`},
		{"wake_attempts zero", `{"tag":"k","profile":"muse01","wake_attempts":0}`},
		{"wake_attempts float", `{"tag":"k","profile":"muse01","wake_attempts":1.5}`},
		{"wake_attempts too big", `{"tag":"k","profile":"muse01","wake_attempts":11}`},
		{"relogin_attempts string", `{"tag":"k","profile":"muse01","relogin_attempts":"3"}`},
		{"wake flag string", `{"tag":"k","profile":"muse01","wake_on_gateway_failure":"yes"}`},
		{"credentials empty", `{"tag":"k","profile":"muse01","credentials":""}`},
		{"unknown key", `{"tag":"k","profile":"muse01","surprise":1}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := `{"profiles": {"muse01": {}}, "keeper": [` + tc.entry + `]}`
			if _, err := ParseSingleConfig([]byte(cfg), t.TempDir()); err == nil {
				t.Fatalf("ParseSingleConfig = nil error; want error for %s", tc.entry)
			} else if ExitCode(err) != 2 {
				t.Errorf("ExitCode = %d; want 2", ExitCode(err))
			}
		})
	}
}

// TestKeeperNoBrowserParses pins the keep-alive-only entry:
// an entry without a browser key parses and resolves.
func TestKeeperNoBrowserParses(t *testing.T) {
	t.Parallel()
	cfg, err := ParseSingleConfig([]byte(`{"profiles": {"muse01": {}}, "keeper": [{"tag": "k", "profile": "muse01", "interval": "12h"}]}`), t.TempDir())
	if err != nil {
		t.Fatalf("ParseSingleConfig: %v", err)
	}
	kcfg, err := ResolveKeeper(cfg)
	if err != nil {
		t.Fatalf("ResolveKeeper: %v", err)
	}
	if kcfg == nil || len(kcfg.Entries) != 1 || kcfg.Entries[0].Browser != "" {
		t.Fatalf("entries = %v; want one browser-less entry", kcfg)
	}
}

// TestCredentialsAbsent pins the nil-block case.
func TestCredentialsAbsent(t *testing.T) {
	t.Parallel()
	cfg, err := ParseSingleConfig([]byte(`{"profiles": {"muse01": {}}}`), t.TempDir())
	if err != nil {
		t.Fatalf("ParseSingleConfig: %v", err)
	}
	if cfg.Credentials != nil {
		t.Fatalf("Credentials = %v; want nil", cfg.Credentials)
	}
	creds, err := ResolveCredentials(cfg)
	if err != nil || creds != nil {
		t.Fatalf("ResolveCredentials = %v, %v; want nil, nil", creds, err)
	}
	if _, ok := creds.CredentialForProfile("muse01"); ok {
		t.Fatal("nil-block accessor returned a credential")
	}
}
