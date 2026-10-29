package profile

import (
	"strings"
)

// ResolvedSetting is one toggle resolved with its source, so cmd can
// print it later (e.g. auto-approve status output).
type ResolvedSetting struct {
	Enabled bool
	Source  string
}

var autoApproveOn = map[string]bool{
	"always": true, "on": true, "1": true, "true": true, "yes": true,
}

var autoApproveOff = map[string]bool{
	"off": true, "0": true, "false": true, "no": true, "never": true, "": true,
}

var autoAllowOnceOn = map[string]bool{
	"on": true, "1": true, "true": true, "yes": true, "always": true,
}

var autoAllowOnceOff = map[string]bool{
	"off": true, "0": true, "false": true, "no": true, "never": true, "": true,
}

// ResolveAutoApprove resolves the auto-approve toggle: per-call flag >
// MUSE_AUTO_APPROVE > config. Defaults off. Each toggle is resolved
// separately; the other toggle's env var has no effect here.
func ResolveAutoApprove(cfg *Profile, flag *bool, getenv func(string) (string, bool)) (ResolvedSetting, error) {
	if flag != nil {
		return ResolvedSetting{Enabled: *flag, Source: "flag"}, nil
	}
	if getenv != nil {
		if env, ok := getenv("MUSE_AUTO_APPROVE"); ok {
			v := strings.ToLower(strings.TrimSpace(env))
			switch {
			case autoApproveOn[v]:
				return ResolvedSetting{Enabled: true, Source: "env MUSE_AUTO_APPROVE"}, nil
			case autoApproveOff[v]:
				return ResolvedSetting{Enabled: false, Source: "env MUSE_AUTO_APPROVE"}, nil
			default:
				return ResolvedSetting{}, newConfigErrorf("MUSE_AUTO_APPROVE must be always or off, not %q", env)
			}
		}
	}
	if cfg == nil {
		return ResolvedSetting{Enabled: false, Source: "config"}, nil
	}
	return ResolvedSetting{
		Enabled: strings.ToLower(strings.TrimSpace(cfg.AutoApprove)) == "always",
		Source:  "config " + cfg.ConfigFile,
	}, nil
}

// ResolveAutoAllowOnce resolves the auto_allow_once fallback toggle:
// per-call flag > MUSE_AUTO_ALLOW_ONCE > config. Defaults off. The
// config value is a bool (or an on/off word, normalised at parse time).
func ResolveAutoAllowOnce(cfg *Profile, flag *bool, getenv func(string) (string, bool)) (ResolvedSetting, error) {
	if flag != nil {
		return ResolvedSetting{Enabled: *flag, Source: "flag"}, nil
	}
	if getenv != nil {
		if env, ok := getenv("MUSE_AUTO_ALLOW_ONCE"); ok {
			v := strings.ToLower(strings.TrimSpace(env))
			switch {
			case autoAllowOnceOn[v]:
				return ResolvedSetting{Enabled: true, Source: "env MUSE_AUTO_ALLOW_ONCE"}, nil
			case autoAllowOnceOff[v]:
				return ResolvedSetting{Enabled: false, Source: "env MUSE_AUTO_ALLOW_ONCE"}, nil
			default:
				return ResolvedSetting{}, newConfigErrorf("MUSE_AUTO_ALLOW_ONCE must be on or off, not %q", env)
			}
		}
	}
	if cfg == nil {
		return ResolvedSetting{Enabled: false, Source: "config"}, nil
	}
	return ResolvedSetting{
		Enabled: cfg.AutoAllowOnce,
		Source:  "config " + cfg.ConfigFile,
	}, nil
}
