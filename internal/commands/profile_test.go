// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package commands

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/thoitiettxl-cyber/muse-cli/go/internal/gateway/gatewaytest"
	"github.com/thoitiettxl-cyber/muse-cli/go/internal/profile"
	pb "github.com/thoitiettxl-cyber/muse-cli/go/internal/proto"
)

// profileEnv runs commands with --config against a temp home; the
// profile commands never touch the network.
func profileEnv(t *testing.T, configFile string) (*Env, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	out, errb := &bytes.Buffer{}, &bytes.Buffer{}
	env := &Env{Stdout: out, Stderr: errb, Getenv: mapGetenv(nil)}
	_ = configFile
	return env, out, errb
}

func runProfile(t *testing.T, env *Env, out, errb *bytes.Buffer, configFile string, args ...string) int {
	t.Helper()
	out.Reset()
	errb.Reset()
	full := append([]string{"--config", configFile}, args...)
	return Run(context.Background(), full, env)
}

func TestProfileListShowAddRm(t *testing.T) {
	home, configFile := testHome(t, "")
	env, out, errb := profileEnv(t, configFile)

	if code := runProfile(t, env, out, errb, configFile, "profile", "list"); code != 0 {
		t.Fatalf("list: code=%d err=%q", code, errb.String())
	}
	var list struct {
		Active         string `json:"active"`
		DefaultProfile string `json:"default_profile"`
		Source         string `json:"source"`
		Profiles       []struct {
			Name string `json:"name"`
		} `json:"profiles"`
	}
	mustJSON(t, out.Bytes(), &list)
	if list.Active != "default" || list.DefaultProfile != "default" || list.Source != "single" {
		t.Errorf("list=%+v", list)
	}
	if len(list.Profiles) != 1 || list.Profiles[0].Name != "default" {
		t.Errorf("list profiles=%v", list.Profiles)
	}

	// show: paths + redacted config; the cookie value never leaks.
	if code := runProfile(t, env, out, errb, configFile, "profile", "show"); code != 0 {
		t.Fatalf("show: code=%d err=%q", code, errb.String())
	}
	if strings.Contains(out.String(), "FAKE") {
		t.Errorf("show leaked cookie material: %q", out.String())
	}
	if !strings.Contains(out.String(), "cookies.txt") {
		t.Errorf("show: %q", out.String())
	}

	// add: no cookies file is created; fingerprint/tls-engine stored.
	cookies2 := filepath.Join(home, "work-cookies.txt")
	if err := os.WriteFile(cookies2, []byte(fakeCookie), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := runProfile(t, env, out, errb, configFile, "profile", "add", "work",
		"--cookies-file", cookies2, "--fingerprint", "firefox", "--tls-engine", "stdlib", "--set-default"); code != 0 {
		t.Fatalf("add: code=%d err=%q", code, errb.String())
	}
	if _, err := os.Stat(filepath.Join(home, "profiles", "work", "cookies.txt")); err == nil {
		t.Error("add created a cookies file")
	}
	if code := runProfile(t, env, out, errb, configFile, "profile", "show", "work"); code != 0 {
		t.Fatalf("show work: code=%d err=%q", code, errb.String())
	}
	if !strings.Contains(out.String(), `"fingerprint": "firefox"`) || !strings.Contains(out.String(), `"tls_engine": "stdlib"`) {
		t.Errorf("show work: %q", out.String())
	}
	// Duplicate add refuses.
	if code := runProfile(t, env, out, errb, configFile, "profile", "add", "work"); code != 2 {
		t.Fatalf("add duplicate: code=%d, want 2", code)
	}
	// Invalid fingerprint / tls_engine refuse.
	if code := runProfile(t, env, out, errb, configFile, "profile", "add", "bad1", "--fingerprint", "random"); code != 2 {
		t.Fatalf("add bad fingerprint: code=%d, want 2", code)
	}
	if code := runProfile(t, env, out, errb, configFile, "profile", "add", "bad2", "--tls-engine", "magic"); code != 2 {
		t.Fatalf("add bad tls_engine: code=%d, want 2", code)
	}
	// rm without --yes refuses; rm --yes removes and clears default.
	if code := runProfile(t, env, out, errb, configFile, "profile", "rm", "work"); code != 2 {
		t.Fatalf("rm without --yes: code=%d, want 2", code)
	}
	if code := runProfile(t, env, out, errb, configFile, "profile", "rm", "--yes", "work"); code != 0 {
		t.Fatalf("rm --yes: code=%d err=%q", code, errb.String())
	}
	var rm struct {
		Removed        string  `json:"removed"`
		DefaultProfile *string `json:"default_profile"`
		Warning        string  `json:"warning"`
	}
	mustJSON(t, out.Bytes(), &rm)
	// Removing the default profile falls back to "default" with a
	// warning (the library's RemoveProfileResult semantics).
	if rm.Removed != "work" || rm.DefaultProfile == nil || *rm.DefaultProfile != "default" || rm.Warning == "" {
		t.Errorf("rm out=%q", out.String())
	}
	_ = home
}

// TestProfileShowRedactsHeaders pins NB12: an Authorization header
// value inside an outbound object must never appear in show output.
func TestProfileShowRedactsHeaders(t *testing.T) {
	home := t.TempDir()
	config := `{"default_profile":"default","profiles":{"default":{
		"outbound":{"type":"http","tag":"px","server":"127.0.0.1","server_port":8080,
		"username":"u","password":"TOPSECRET",
		"headers":{"Authorization":"Bearer HEADSECRET"}}}}}`
	configFile := filepath.Join(home, "config.json")
	if err := os.WriteFile(configFile, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "cookies.txt"), []byte(fakeCookie), 0o600); err != nil {
		t.Fatal(err)
	}
	env, out, errb := profileEnv(t, configFile)
	if code := runProfile(t, env, out, errb, configFile, "profile", "show"); code != 0 {
		t.Fatalf("show: code=%d err=%q", code, errb.String())
	}
	if strings.Contains(out.String(), "TOPSECRET") || strings.Contains(out.String(), "HEADSECRET") {
		t.Errorf("show leaked secret material: %q", out.String())
	}
	if !strings.Contains(out.String(), "redacted") {
		t.Errorf("show: no redaction marker in %q", out.String())
	}
}

func TestProfileAddOutboundFailureIsAtomic(t *testing.T) {
	// A bogus-type outbound file (RT-F4's probe) must fail the add
	// without leaving the profile behind: the config file stays
	// byte-identical and a re-add succeeds.
	_, configFile := testHome(t, "")
	env, out, errb := profileEnv(t, configFile)
	before, err := os.ReadFile(configFile)
	if err != nil {
		t.Fatal(err)
	}
	bogus := filepath.Join(t.TempDir(), "bogus.json")
	if err := os.WriteFile(bogus, []byte(`{"type":"not-a-real-outbound-type","tag":"bogus1"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := runProfile(t, env, out, errb, configFile, "profile", "add", "work", "--outbound", bogus); code != 2 {
		t.Fatalf("add bogus outbound: code=%d, want 2; err=%q out=%q", code, errb.String(), out.String())
	}
	after, err := os.ReadFile(configFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Errorf("config changed by failed add:\nbefore %q\nafter  %q", before, after)
	}
	if code := runProfile(t, env, out, errb, configFile, "profile", "add", "work"); code != 0 {
		t.Fatalf("re-add after failed add: code=%d, want 0; err=%q", code, errb.String())
	}
}

func TestProfileShowGhost(t *testing.T) {
	_, configFile := testHome(t, "")
	env, out, errb := profileEnv(t, configFile)
	// Positional ghost: exits 2 (existing behaviour, pinned).
	if code := runProfile(t, env, out, errb, configFile, "profile", "show", "ghost"); code != 2 {
		t.Fatalf("show ghost: code=%d, want 2", code)
	}
	if !strings.Contains(errb.String(), `profile "ghost" does not exist`) {
		t.Errorf("show ghost error: %q", errb.String())
	}
	// --profile ghost: the same existence check must apply when
	// the name comes from the flag, not only the positional.
	if code := runProfile(t, env, out, errb, configFile, "--profile", "ghost", "profile", "show"); code != 2 {
		t.Fatalf("--profile ghost show: code=%d, want 2; err=%q out=%q", code, errb.String(), out.String())
	}
	if !strings.Contains(errb.String(), `profile "ghost" does not exist`) {
		t.Errorf("--profile ghost show error: %q", errb.String())
	}
	// Positive control: an existing profile via the flag works.
	if code := runProfile(t, env, out, errb, configFile, "--profile", "default", "profile", "show"); code != 0 {
		t.Fatalf("--profile default show: code=%d, want 0; err=%q", code, errb.String())
	}
	// MUSE_CLI_PROFILE=ghost: the env-selected name is explicit
	// too, so the same check applies.
	env.Getenv = mapGetenv(map[string]string{"MUSE_CLI_PROFILE": "ghost"})
	if code := runProfile(t, env, out, errb, configFile, "profile", "show"); code != 2 {
		t.Fatalf("MUSE_CLI_PROFILE=ghost show: code=%d, want 2", code)
	}
	env.Getenv = mapGetenv(map[string]string{"MUSE_CLI_PROFILE": "default"})
	if code := runProfile(t, env, out, errb, configFile, "profile", "show"); code != 0 {
		t.Fatalf("MUSE_CLI_PROFILE=default show: code=%d, want 0; err=%q", code, errb.String())
	}
}

func TestProfileTestGhost(t *testing.T) {
	// `profile test <nonexistent>` must fail fast (exit 2) instead
	// of running phases on a synthetic default profile, and the
	// same check must apply via --profile. The single-file layout
	// is already caught by the identity lookup; the synthetic
	// path is the layout with NO single config file, where
	// LoadProfile invents a SourceNone profile — pinned here
	// with a default (non-explicit) config location and a
	// BuildRuntime guard that fails the test if phases start.
	t.Run("no single config", func(t *testing.T) {
		s := newFakeStack(t, nil, nil)
		home := t.TempDir()
		xdg := filepath.Join(home, "xdg")
		s.env.Getenv = mapGetenv(map[string]string{"XDG_CONFIG_HOME": xdg, "HOME": home})
		s.env.BuildRuntime = func(ctx context.Context, loc *profile.ConfigLocation, prof *profile.Profile, env *Env) (*Runtime, error) {
			t.Error("buildRuntime ran for a nonexistent profile; the existence check must fail first")
			return nil, errors.New("fake build must not run")
		}
		for _, args := range [][]string{{"profile", "test", "ghost"}, {"--profile", "ghost", "profile", "test"}} {
			if code := s.run(args...); code != 2 {
				t.Fatalf("profile test ghost %v: code=%d, want 2; err=%q out=%q", args, code, s.errb.String(), s.out.String())
			}
			if !strings.Contains(s.errb.String(), `profile "ghost" does not exist`) {
				t.Errorf("profile test ghost %v error: %q", args, s.errb.String())
			}
			if strings.Contains(s.out.String(), `"dns"`) {
				t.Errorf("profile test ghost %v ran phases: %q", args, s.out.String())
			}
		}
	})
	t.Run("single-file layout", func(t *testing.T) {
		s := newFakeStack(t, nil, nil)
		if code := s.run("profile", "test", "ghost"); code != 2 {
			t.Fatalf("profile test ghost: code=%d, want 2; err=%q out=%q", code, s.errb.String(), s.out.String())
		}
		if !strings.Contains(s.errb.String(), `profile "ghost" does not exist`) {
			t.Errorf("profile test ghost error: %q", s.errb.String())
		}
		if strings.Contains(s.out.String(), `"dns"`) {
			t.Errorf("profile test ghost ran phases: %q", s.out.String())
		}
		if code := s.run("--profile", "ghost", "profile", "test"); code != 2 {
			t.Fatalf("--profile ghost profile test: code=%d, want 2; err=%q out=%q", code, s.errb.String(), s.out.String())
		}
	})
	t.Run("existing profile via flag reaches phases", func(t *testing.T) {
		ipify := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, "203.0.113.7\n")
		})
		s := newFakeStack(t, gatewaytest.HandlerFunc(func(req *pb.ApplicationRequest, service pb.ServiceType) gatewaytest.Response {
			return gatewaytest.Response{Frames: []*pb.ServiceFrame{
				gatewaytest.ResponseFrame(0, 200, []byte(`{"ok":true,"result":{}}`), true),
			}}
		}), ipify)
		s.env.BuildRuntime = func(ctx context.Context, loc *profile.ConfigLocation, prof *profile.Profile, env *Env) (*Runtime, error) {
			rt, err := defaultBuildRuntime(ctx, loc, prof, env)
			if err != nil {
				return nil, err
			}
			rt.resolveFn = func(ctx context.Context, domain string) ([]netip.Addr, error) {
				return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
			}
			return rt, nil
		}
		if code := s.run("--profile", "default", "profile", "test"); code != 0 {
			t.Fatalf("--profile default profile test: code=%d, want 0; err=%q out=%q", code, s.errb.String(), s.out.String())
		}
	})
}

func TestConfigMigrateMissingExplicitDryRun(t *testing.T) {
	// Only --write may create a missing explicit --config file.
	// A dry-run against a missing explicit file exits 2 (the
	// documented RequirePresent gate); --write migrates.
	home := t.TempDir()
	legacyDir := filepath.Join(home, "profiles", "default")
	if err := os.MkdirAll(legacyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(legacyDir, "config.json"),
		[]byte(`{"cookies_file":"cookies.txt","vm_id":"vm-legacy","node_id":"0123456789abcdef"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "cookies.txt"), []byte(fakeCookie), 0o600); err != nil {
		t.Fatal(err)
	}
	configFile := filepath.Join(home, "config.json")
	env, out, errb := profileEnv(t, configFile)
	if code := runProfile(t, env, out, errb, configFile, "config", "migrate"); code != 2 {
		t.Fatalf("migrate dry-run missing explicit file: code=%d, want 2; err=%q out=%q", code, errb.String(), out.String())
	}
	if _, err := os.Stat(configFile); err == nil {
		t.Error("dry run created the config file")
	}
	if code := runProfile(t, env, out, errb, configFile, "config", "migrate", "--write"); code != 0 {
		t.Fatalf("migrate --write missing explicit file: code=%d, want 0; err=%q", code, errb.String())
	}
	if _, err := os.Stat(configFile); err != nil {
		t.Fatalf("migrate --write did not create the config: %v", err)
	}
}

func TestProfileSetStoredAndOutbound(t *testing.T) {
	_, configFile := testHome(t, "")
	env, out, errb := profileEnv(t, configFile)

	if code := runProfile(t, env, out, errb, configFile, "profile", "set-fingerprint", "default", "safari"); code != 0 {
		t.Fatalf("set-fingerprint: code=%d err=%q", code, errb.String())
	}
	if !strings.Contains(out.String(), "safari") {
		t.Errorf("set-fingerprint out: %q", out.String())
	}
	if code := runProfile(t, env, out, errb, configFile, "profile", "set-fingerprint", "default", "random"); code != 2 {
		t.Fatalf("set-fingerprint random: code=%d, want 2", code)
	}
	if code := runProfile(t, env, out, errb, configFile, "profile", "set-tls-engine", "default", "stdlib"); code != 0 {
		t.Fatalf("set-tls-engine: code=%d err=%q", code, errb.String())
	}
	// Empty value resets to the default (key removed).
	if code := runProfile(t, env, out, errb, configFile, "profile", "set-fingerprint", "default", ""); code != 0 {
		t.Fatalf("set-fingerprint reset: code=%d err=%q", code, errb.String())
	}
	if !strings.Contains(out.String(), "chrome") {
		t.Errorf("reset out: %q", out.String())
	}

	// set-outbound from stdin ("-"): one tagged direct object.
	env.Stdin = strings.NewReader(`{"type":"direct","tag":"d1"}`)
	if code := runProfile(t, env, out, errb, configFile, "profile", "set-outbound", "default", "-"); code != 0 {
		t.Fatalf("set-outbound: code=%d err=%q", code, errb.String())
	}
	if !strings.Contains(out.String(), "d1") {
		t.Errorf("set-outbound out: %q", out.String())
	}
	// The {"outbound":{...}} wrapper is rejected.
	env.Stdin = strings.NewReader(`{"outbound":{"type":"direct","tag":"d2"}}`)
	if code := runProfile(t, env, out, errb, configFile, "profile", "set-outbound", "default", "-"); code != 2 {
		t.Fatalf("set-outbound wrapper: code=%d, want 2", code)
	}
}

func TestProfileListRejectsSharedWireGuardPrivateKey(t *testing.T) {
	// Bullet 4 (profile-isolation invariant): two profiles whose
	// endpoint configs carry the same WireGuard private key are
	// rejected at config load. The CLI must surface the profile
	// library's config error as exit 2, and the key value must
	// never appear in the error.
	wg := func(tag, key string) string {
		return `{"type":"wireguard","tag":"` + tag + `","address":["10.0.0.2/32"],"private_key":"` + key + `","peers":[{"address":"203.0.113.10","port":51820,"public_key":"FAKE-PUBKEY","allowed_ips":["0.0.0.0/0"]}]}`
	}
	home := t.TempDir()
	configFile := filepath.Join(home, "config.json")
	if err := os.WriteFile(filepath.Join(home, "cookies.txt"), []byte(fakeCookie), 0o600); err != nil {
		t.Fatal(err)
	}
	env, out, errb := profileEnv(t, configFile)
	writeConfig := func(body string) {
		t.Helper()
		if err := os.WriteFile(configFile, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	shared := `{"default_profile":"alpha","profiles":{"alpha":{"outbound":"wg-a"},"beta":{"outbound":"wg-b"}},"endpoints":[` +
		wg("wg-a", "FAKE-PRIVATE-KEY-ALPHA") + `,` + wg("wg-b", "FAKE-PRIVATE-KEY-ALPHA") + `]}`
	writeConfig(shared)
	if code := runProfile(t, env, out, errb, configFile, "profile", "list"); code != 2 {
		t.Fatalf("shared key: code=%d, want 2; err=%q", code, errb.String())
	}
	if !strings.Contains(errb.String(), `wireguard private key shared by profiles "alpha" and "beta"`) {
		t.Errorf("shared key error: %q", errb.String())
	}
	if strings.Contains(errb.String(), "FAKE-PRIVATE-KEY-ALPHA") || strings.Contains(out.String(), "FAKE-PRIVATE-KEY-ALPHA") {
		t.Errorf("key value leaked into output: err=%q out=%q", errb.String(), out.String())
	}
	// Control: distinct keys load fine, so the rejection above is
	// the duplicate-key validation and nothing else.
	distinct := `{"default_profile":"alpha","profiles":{"alpha":{"outbound":"wg-a"},"beta":{"outbound":"wg-b"}},"endpoints":[` +
		wg("wg-a", "FAKE-PRIVATE-KEY-ALPHA") + `,` + wg("wg-b", "FAKE-PRIVATE-KEY-BETA") + `]}`
	writeConfig(distinct)
	if code := runProfile(t, env, out, errb, configFile, "profile", "list"); code != 0 {
		t.Fatalf("distinct keys: code=%d, want 0; err=%q", code, errb.String())
	}
}

func TestConfigMigrate(t *testing.T) {
	home := t.TempDir()
	// The legacy layout lives under the DEFAULT config home
	// (XDG_CONFIG_HOME), so the dry run needs no explicit
	// --config: a dry run against a missing EXPLICIT file exits
	// 2 (see TestConfigMigrateMissingExplicitDryRun).
	xdg := filepath.Join(home, "xdg")
	baseDir := filepath.Join(xdg, "muse-cli")
	legacyDir := filepath.Join(baseDir, "profiles", "default")
	if err := os.MkdirAll(legacyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(legacyDir, "config.json"),
		[]byte(`{"cookies_file":"cookies.txt","vm_id":"vm-legacy","node_id":"0123456789abcdef"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(baseDir, "cookies.txt"), []byte(fakeCookie), 0o600); err != nil {
		t.Fatal(err)
	}
	configFile := filepath.Join(baseDir, "config.json")
	env, out, errb := profileEnv(t, configFile)
	env.Getenv = mapGetenv(map[string]string{"XDG_CONFIG_HOME": xdg, "HOME": home})
	runDefault := func(args ...string) int {
		out.Reset()
		errb.Reset()
		return Run(context.Background(), args, env)
	}

	// Dry run: prints the plan, writes nothing.
	if code := runDefault("config", "migrate"); code != 0 {
		t.Fatalf("migrate dry-run: code=%d err=%q", code, errb.String())
	}
	if _, err := os.Stat(configFile); err == nil {
		t.Error("dry run wrote the single config")
	}
	if !strings.Contains(out.String(), `"would_write": true`) || !strings.Contains(out.String(), `"source": "legacy"`) {
		t.Errorf("migrate plan: %q", out.String())
	}
	// --write migrates; a second run reports already-migrated, exit 0.
	if code := runProfile(t, env, out, errb, configFile, "config", "migrate", "--write"); code != 0 {
		t.Fatalf("migrate --write: code=%d err=%q", code, errb.String())
	}
	if _, err := os.Stat(configFile); err != nil {
		t.Fatalf("migrate --write did not create the config: %v", err)
	}
	if code := runProfile(t, env, out, errb, configFile, "config", "migrate"); code != 0 {
		t.Fatalf("migrate again: code=%d err=%q", code, errb.String())
	}
	if !strings.Contains(out.String(), "already-migrated") {
		t.Errorf("second migrate: %q", out.String())
	}
	// The migrated profile lists and shows.
	if code := runProfile(t, env, out, errb, configFile, "profile", "list"); code != 0 {
		t.Fatalf("list after migrate: code=%d", code)
	}
	if !strings.Contains(out.String(), `"source": "single"`) {
		t.Errorf("list after migrate: %q", out.String())
	}
}

func TestDefaultPathRegression(t *testing.T) {
	// Under a controlled XDG_CONFIG_HOME, the default config path
	// is Join(UserConfigDir(), "muse-cli", "config.json"): a missing
	// default file is not an error for a read-only command, and
	// --config dir still exits 2. The default home holds no config,
	// so profile list must fail as "no config" rather than read a
	// real home.
	home := t.TempDir()
	xdg := filepath.Join(home, "xdg")
	env, out, errb := profileEnv(t, "")
	env.Getenv = mapGetenv(map[string]string{
		"XDG_CONFIG_HOME": xdg,
		"HOME":            home,
	})
	out.Reset()
	errb.Reset()
	code := Run(context.Background(), []string{"profile", "list"}, env)
	// A missing default config is not an error: list reports the
	// "none" source with the default profile (not existing). The
	// profile dir must be under the controlled XDG home, proving
	// the default path is Join(UserConfigDir(), "muse-cli").
	if code != 0 {
		t.Fatalf("no-config default: code=%d err=%q, want 0", code, errb.String())
	}
	if !strings.Contains(out.String(), `"source": "none"`) {
		t.Errorf("list: %q", out.String())
	}
	if !strings.Contains(out.String(), filepath.Join(xdg, "muse-cli")) {
		t.Errorf("profile dir should be under the XDG home: %q", out.String())
	}
}

func TestProfileTestPhases(t *testing.T) {
	ipify := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "203.0.113.7\n")
	})
	s := newFakeStack(t, gatewaytest.HandlerFunc(func(req *pb.ApplicationRequest, service pb.ServiceType) gatewaytest.Response {
		return gatewaytest.Response{Frames: []*pb.ServiceFrame{
			gatewaytest.ResponseFrame(0, 200, []byte(`{"ok":true,"result":{}}`), true),
		}}
	}), ipify)
	// Inject a fake DNS resolver answering muse.ai; the HTTPS,
	// egress and gateway phases already run on fakes via the
	// stack's NewConnector/HTTPClient hooks.
	s.env.BuildRuntime = func(ctx context.Context, loc *profile.ConfigLocation, prof *profile.Profile, env *Env) (*Runtime, error) {
		rt, err := defaultBuildRuntime(ctx, loc, prof, env)
		if err != nil {
			return nil, err
		}
		rt.resolveFn = func(ctx context.Context, domain string) ([]netip.Addr, error) {
			if domain != "muse.ai" {
				return nil, fmt.Errorf("unexpected domain %s", domain)
			}
			return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
		}
		return rt, nil
	}
	if code := s.run("profile", "test"); code != 0 {
		t.Fatalf("profile test: code=%d err=%q out=%q", code, s.errb.String(), s.out.String())
	}
	var result struct {
		Profile     string `json:"profile"`
		Fingerprint string `json:"fingerprint"`
		UserAgent   string `json:"user_agent"`
		Note        string `json:"note"`
		DNS         struct {
			OK        bool     `json:"ok"`
			Addresses []string `json:"addresses"`
		} `json:"dns"`
		HTTPS struct {
			OK     bool `json:"ok"`
			Status int  `json:"status"`
		} `json:"https"`
		EgressIP *string `json:"egress_ip"`
		Gateway  struct {
			OK  bool   `json:"ok"`
			TLS string `json:"tls"`
		} `json:"gateway"`
		OK bool `json:"ok"`
	}
	mustJSON(t, s.out.Bytes(), &result)
	if !result.OK || !result.DNS.OK || !result.HTTPS.OK || !result.Gateway.OK {
		t.Errorf("result=%+v", result)
	}
	if len(result.DNS.Addresses) != 1 || result.DNS.Addresses[0] != "93.184.216.34" {
		t.Errorf("dns addresses=%v", result.DNS.Addresses)
	}
	if result.EgressIP == nil || *result.EgressIP != "203.0.113.7" {
		t.Errorf("egress_ip=%v", result.EgressIP)
	}
	if result.Fingerprint != "chrome" || result.Gateway.TLS != "utls-chrome" || result.UserAgent == "" {
		t.Errorf("fingerprint=%q tls=%q ua=%q", result.Fingerprint, result.Gateway.TLS, result.UserAgent)
	}
	// The stored fingerprint/User-Agent carry a recorded-only
	// caveat: the runtime is always uTLS chrome.
	if !strings.Contains(result.Note, "recorded-only") || !strings.Contains(result.Note, "uTLS chrome") {
		t.Errorf("note=%q, want the recorded-only uTLS caveat", result.Note)
	}
}

func TestProfileTestDNSFailure(t *testing.T) {
	s := newFakeStack(t, nil, nil)
	s.env.BuildRuntime = func(ctx context.Context, loc *profile.ConfigLocation, prof *profile.Profile, env *Env) (*Runtime, error) {
		rt, err := defaultBuildRuntime(ctx, loc, prof, env)
		if err != nil {
			return nil, err
		}
		rt.resolveFn = func(ctx context.Context, domain string) ([]netip.Addr, error) {
			return nil, errors.New("fake resolver down")
		}
		return rt, nil
	}
	// The first failing phase decides the exit code; the result
	// still prints as JSON.
	if code := s.run("profile", "test"); code != 3 {
		t.Fatalf("dns failure: code=%d, want 3; err=%q out=%q", code, s.errb.String(), s.out.String())
	}
	if !strings.Contains(s.out.String(), `"dns"`) || !strings.Contains(s.out.String(), "fake resolver down") {
		t.Errorf("result: %q", s.out.String())
	}
}
