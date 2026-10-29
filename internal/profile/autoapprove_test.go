package profile

import (
	"testing"
)

func TestResolveAutoApprove(t *testing.T) {
	t.Parallel()
	// Config-only cases.
	cfg := &Profile{AutoApprove: "always", ConfigFile: "/base/config.json"}
	got, err := ResolveAutoApprove(cfg, nil, lookupEnv(map[string]string{}))
	if err != nil || !got.Enabled || got.Source != "config /base/config.json" {
		t.Errorf("config always = %+v, %v; want enabled, source config", got, err)
	}
	cfg = &Profile{AutoApprove: "off", ConfigFile: "/base/config.json"}
	got, err = ResolveAutoApprove(cfg, nil, lookupEnv(map[string]string{}))
	if err != nil || got.Enabled {
		t.Errorf("config off = %+v, %v; want disabled", got, err)
	}

	// Per-toggle env sets, exact Python sets (case-insensitive, stripped).
	onSet := []string{"always", "on", "1", "true", "yes", "ALWAYS", " Yes "}
	offSet := []string{"off", "0", "false", "no", "never", "", "OFF"}
	for _, v := range onSet {
		got, err := ResolveAutoApprove(cfg, nil, lookupEnv(map[string]string{"MUSE_AUTO_APPROVE": v}))
		if err != nil || !got.Enabled || got.Source != "env MUSE_AUTO_APPROVE" {
			t.Errorf("env %q = %+v, %v; want enabled", v, got, err)
		}
	}
	for _, v := range offSet {
		got, err := ResolveAutoApprove(cfg, nil, lookupEnv(map[string]string{"MUSE_AUTO_APPROVE": v}))
		if err != nil || got.Enabled {
			t.Errorf("env %q = %+v, %v; want disabled", v, got, err)
		}
	}
	for _, v := range []string{"maybe", "2", "enabled"} {
		if _, err := ResolveAutoApprove(cfg, nil, lookupEnv(map[string]string{"MUSE_AUTO_APPROVE": v})); err == nil {
			t.Errorf("env %q = nil error; want error", v)
		}
	}

	// Flag beats env beats config, per toggle.
	flag := true
	got, err = ResolveAutoApprove(cfg, &flag, lookupEnv(map[string]string{"MUSE_AUTO_APPROVE": "off"}))
	if err != nil || !got.Enabled || got.Source != "flag" {
		t.Errorf("flag true over env off = %+v, %v; want enabled, flag", got, err)
	}
	flag = false
	got, err = ResolveAutoApprove(&Profile{AutoApprove: "always"}, &flag, lookupEnv(map[string]string{"MUSE_AUTO_APPROVE": "always"}))
	if err != nil || got.Enabled || got.Source != "flag" {
		t.Errorf("flag false over env on = %+v, %v; want disabled, flag", got, err)
	}
}

func TestResolveAutoAllowOnce(t *testing.T) {
	t.Parallel()
	cfg := &Profile{AutoAllowOnce: true, ConfigFile: "/base/config.json"}
	got, err := ResolveAutoAllowOnce(cfg, nil, lookupEnv(map[string]string{}))
	if err != nil || !got.Enabled {
		t.Errorf("config true = %+v, %v; want enabled", got, err)
	}
	cfg = &Profile{AutoAllowOnce: false, ConfigFile: "/base/config.json"}
	// "always" is in the once on-set for env, but NOT in the approve on-set
	// distinction: once env "always" enables; approve env "" disables.
	for _, v := range []string{"on", "1", "true", "yes", "always", "ON"} {
		got, err := ResolveAutoAllowOnce(cfg, nil, lookupEnv(map[string]string{"MUSE_AUTO_ALLOW_ONCE": v}))
		if err != nil || !got.Enabled || got.Source != "env MUSE_AUTO_ALLOW_ONCE" {
			t.Errorf("once env %q = %+v, %v; want enabled", v, got, err)
		}
	}
	for _, v := range []string{"off", "0", "false", "no", "never", ""} {
		got, err := ResolveAutoAllowOnce(cfg, nil, lookupEnv(map[string]string{"MUSE_AUTO_ALLOW_ONCE": v}))
		if err != nil || got.Enabled {
			t.Errorf("once env %q = %+v, %v; want disabled", v, got, err)
		}
	}
	for _, v := range []string{"maybe", "2"} {
		if _, err := ResolveAutoAllowOnce(cfg, nil, lookupEnv(map[string]string{"MUSE_AUTO_ALLOW_ONCE": v})); err == nil {
			t.Errorf("once env %q = nil error; want error", v)
		}
	}
	flag := true
	got, err = ResolveAutoAllowOnce(cfg, &flag, lookupEnv(map[string]string{"MUSE_AUTO_ALLOW_ONCE": "off"}))
	if err != nil || !got.Enabled || got.Source != "flag" {
		t.Errorf("once flag true = %+v, %v; want enabled, flag", got, err)
	}
	// Env is independent per toggle: approve env does not affect once.
	got, err = ResolveAutoAllowOnce(cfg, nil, lookupEnv(map[string]string{"MUSE_AUTO_APPROVE": "always"}))
	if err != nil || got.Enabled {
		t.Errorf("approve env must not enable once = %+v, %v", got, err)
	}
}

func TestResolveAutoApproveDefaultsOff(t *testing.T) {
	t.Parallel()
	cfg := &Profile{}
	got, err := ResolveAutoApprove(cfg, nil, lookupEnv(map[string]string{}))
	if err != nil || got.Enabled {
		t.Errorf("empty profile approve = %+v, %v; want disabled (default off)", got, err)
	}
	got2, err := ResolveAutoAllowOnce(cfg, nil, lookupEnv(map[string]string{}))
	if err != nil || got2.Enabled {
		t.Errorf("empty profile once = %+v, %v; want disabled (default off)", got2, err)
	}
}
