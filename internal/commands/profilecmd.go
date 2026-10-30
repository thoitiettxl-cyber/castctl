// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package commands

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/textproto"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/thoitiettxl-cyber/castctl/internal/conn"
	"github.com/thoitiettxl-cyber/castctl/internal/gateway"
	"github.com/thoitiettxl-cyber/castctl/internal/logging"
	"github.com/thoitiettxl-cyber/castctl/internal/outbound"
	"github.com/thoitiettxl-cyber/castctl/internal/profile"

	singjson "github.com/sagernet/sing/common/json"
)

func init() {
	registerCommand(&commandSpec{
		name:     "profile",
		help:     "manage profiles",
		helpText: profileHelpText,
		handler:  cmdProfile,
	})
	registerCommand(&commandSpec{
		name:     "config",
		help:     "config maintenance",
		helpText: configHelpText,
		handler:  cmdConfig,
	})
	registerFlags("profile", "profile <subcommand> [options]", nil)
	registerFlags("config", "config <subcommand> [options]", nil)
}

var profileSubcommands = []string{"list", "show", "add", "rm", "set-outbound", "set-fingerprint", "set-tls-engine", "test"}

func cmdProfile(ctx context.Context, env *Env, g *globalOpts, args []string) error {
	if len(args) == 0 {
		fmt.Fprintln(env.stderr(), "castctl: the following arguments are required: subcommand")
		fmt.Fprint(env.stderr(), profileHelpText)
		return errCode(2, nil)
	}
	switch args[0] {
	case "--help", "-h":
		fmt.Fprint(env.stdout(), profileHelpText)
		return errHelpShown
	case "list":
		return cmdProfileList(ctx, env, g, args[1:])
	case "show":
		return cmdProfileShow(ctx, env, g, args[1:])
	case "add":
		return cmdProfileAdd(ctx, env, g, args[1:])
	case "rm":
		return cmdProfileRm(ctx, env, g, args[1:])
	case "set-outbound":
		return cmdProfileSetOutbound(ctx, env, g, args[1:])
	case "set-fingerprint":
		return cmdProfileSetFingerprint(ctx, env, g, args[1:])
	case "set-tls-engine":
		return cmdProfileSetTLSEngine(ctx, env, g, args[1:])
	case "test":
		return cmdProfileTest(ctx, env, g, args[1:])
	default:
		fmt.Fprintf(env.stderr(), "castctl: argument subcommand: invalid choice: %q (choose from %s)\n", args[0], strings.Join(profileSubcommands, ", "))
		return errCode(2, nil)
	}
}

func profileParse(sub string, args []string, env *Env, defs []flagDef, helpText string) (*parsed, error) {
	ap := &argParser{defs: defs, helpText: helpText, prog: "castctl profile " + sub}
	p, helpShown, err := ap.parse(args, env.stdout())
	if err != nil {
		if pe, ok := err.(*parserError); ok {
			fmt.Fprintf(env.stderr(), "castctl: %s\n", pe.msg)
			return nil, errCode(2, pe)
		}
		return nil, err
	}
	if helpShown {
		return nil, errHelpShown
	}
	return p, nil
}

// profileListRow is one row of `profile list` output.
type profileListRow struct {
	Name        string `json:"name"`
	Dir         string `json:"dir"`
	Exists      bool   `json:"exists"`
	Cookies     bool   `json:"cookies"`
	CookiesFile string `json:"cookies_file"`
	Outbound    struct {
		Kind string `json:"kind"`
		Type string `json:"type"`
		Tag  string `json:"tag"`
	} `json:"outbound"`
	AutoApprove string `json:"auto_approve"`
	Source      string `json:"source"`
}

func cmdProfileList(ctx context.Context, env *Env, g *globalOpts, args []string) error {
	p, err := profileParse("list", args, env, nil, profileListHelpText)
	if err != nil {
		return err
	}
	if err := checkPositionals(p, nil, "profile list"); err != nil {
		return usageErr(err)
	}
	loc, err := resolveConfig(g, env, false)
	if err != nil {
		return err
	}
	active, err := resolveActive(loc, g, env)
	if err != nil {
		return err
	}
	single, found, err := profile.LoadSingleConfig(loc.ConfigDir)
	if err != nil {
		return err
	}
	if !found {
		single = nil
	}
	names, err := profile.DiscoverProfileNames(loc.ConfigDir)
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	var ordered []string
	for _, n := range names {
		if !seen[n] {
			seen[n] = true
			ordered = append(ordered, n)
		}
	}
	if single != nil {
		extra := make([]string, 0, len(single.Profiles))
		for n := range single.Profiles {
			if !seen[n] {
				seen[n] = true
				extra = append(extra, n)
			}
		}
		// Sorted, after the discovered names.
		for i := 0; i < len(extra); i++ {
			for j := i + 1; j < len(extra); j++ {
				if extra[j] < extra[i] {
					extra[i], extra[j] = extra[j], extra[i]
				}
			}
		}
		ordered = append(ordered, extra...)
	}
	if !seen[active.Name] {
		ordered = append(ordered, active.Name)
	}
	rows := make([]profileListRow, 0, len(ordered))
	for _, name := range ordered {
		prof, err := profile.LoadProfile(loc.ConfigDir, name, env.lookupEnv)
		if err != nil {
			return err
		}
		row := profileListRow{
			Name:        prof.Name,
			Dir:         prof.Dir,
			Exists:      prof.Exists,
			Cookies:     hasCookiesFile(prof.CookiesFile),
			CookiesFile: prof.CookiesFile,
			AutoApprove: prof.AutoApprove,
			Source:      string(prof.Source),
		}
		row.Outbound.Kind = string(prof.Outbound.Kind)
		row.Outbound.Type = prof.Outbound.Type
		row.Outbound.Tag = prof.Outbound.Tag
		rows = append(rows, row)
	}
	// The aggregate source is single when a single file exists,
	// else none. A legacy layout never reaches the aggregation:
	// LoadProfile refuses it above (whole-command error).
	source := "none"
	if single != nil {
		source = "single"
	}
	defaultProfile := "default"
	if single != nil && single.DefaultProfile != "" {
		defaultProfile = single.DefaultProfile
	}
	out := struct {
		Active         string           `json:"active"`
		DefaultProfile string           `json:"default_profile"`
		Source         string           `json:"source"`
		Profiles       []profileListRow `json:"profiles"`
	}{
		Active:         active.Name,
		DefaultProfile: defaultProfile,
		Source:         source,
		Profiles:       rows,
	}
	return writeJSON(env.stdout(), out)
}

func hasCookiesFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Size() > 0
}

func cmdProfileShow(ctx context.Context, env *Env, g *globalOpts, args []string) error {
	p, err := profileParse("show", args, env, nil, profileShowHelpText)
	if err != nil {
		return err
	}
	if len(p.positionals) > 1 {
		return usageErr(&parserError{msg: fmt.Sprintf("unrecognized arguments: %s", strings.Join(p.positionals[1:], " "))})
	}
	loc, err := resolveConfig(g, env, false)
	if err != nil {
		return err
	}
	active, err := resolveActive(loc, g, env)
	if err != nil {
		return err
	}
	name := active.Name
	explicit := false
	if len(p.positionals) == 1 {
		name, explicit = p.positionals[0], true
	}
	single, found, err := profile.LoadSingleConfig(loc.ConfigDir)
	if err != nil {
		return err
	}
	if !found {
		single = nil
	}
	// The existence check applies whenever the name was
	// explicitly selected — a positional, the --profile flag,
	// or CASTCTL_PROFILE — not only for a positional. An
	// implicitly resolved name (default_profile/"default" with
	// no config yet) may still synthesise a default profile.
	if explicitProfileSelected(g, env, explicit) && !profileExists(loc.ConfigDir, single, name) {
		return errCodef(2, "profile %q does not exist", name)
	}
	prof, err := profile.LoadProfile(loc.ConfigDir, name, env.lookupEnv)
	if err != nil {
		return err
	}
	redacted, err := profile.RedactProfile(prof)
	if err != nil {
		return err
	}
	warnings := profileWarnings(loc.ConfigDir, single, prof)
	paths := struct {
		Dir            string `json:"dir"`
		ConfigFile     string `json:"config_file"`
		CookiesFile    string `json:"cookies_file"`
		ChatFile       string `json:"chat_file"`
		TelegramConfig string `json:"telegram_config"`
		TelegramState  string `json:"telegram_state"`
	}{
		Dir:            prof.Dir,
		ConfigFile:     prof.ConfigFile,
		CookiesFile:    prof.CookiesFile,
		ChatFile:       prof.ChatFile,
		TelegramConfig: filepath.Join(prof.Dir, "telegram.json"),
		TelegramState:  filepath.Join(prof.Dir, "telegram-state.json"),
	}
	pathsJSON, err := json.Marshal(paths)
	if err != nil {
		return err
	}
	warningsJSON, err := json.Marshal(warnings)
	if err != nil {
		return err
	}
	// Splice the redacted profile JSON verbatim: it is already the
	// display rendering (secrets redacted by the profile library).
	var b strings.Builder
	b.WriteString("{\n  \"profile\": ")
	b.WriteString(strings.TrimSpace(string(redacted)))
	b.WriteString(",\n  \"paths\": ")
	b.Write(pathsJSON)
	b.WriteString(",\n  \"warnings\": ")
	b.Write(warningsJSON)
	b.WriteString("\n}\n")
	_, err = io.WriteString(env.stdout(), b.String())
	return err
}

// explicitProfileSelected reports whether the resolved profile
// name was explicitly selected: a positional argument, the
// --profile flag, or a non-empty CASTCTL_PROFILE. Implicitly
// resolved names (default_profile, then "default") are not
// explicit: with no config file yet they may synthesise a
// default profile instead of failing.
func explicitProfileSelected(g *globalOpts, env *Env, positional bool) bool {
	if positional || g.profileSet {
		return true
	}
	if v, ok := env.lookupEnv(profile.ProfileEnv); ok && strings.TrimSpace(v) != "" {
		return true
	}
	return false
}

func profileExists(baseDir string, single *profile.SingleConfig, name string) bool {
	// Existence counts a single-file entry, a per-profile config
	// file, or a bare profile directory (kept deliberately: the
	// directory is the profile's home, and LoadProfile
	// synthesises SourceNone defaults for it). A legacy config
	// file counts as existence here, but LoadProfile refuses to
	// read it, so this check never silently loads one.
	if single != nil {
		if _, ok := single.Profiles[name]; ok {
			return true
		}
	}
	paths, err := profile.ProfilePaths(baseDir, name)
	if err != nil {
		return false
	}
	if _, err := os.Stat(paths.Config); err == nil {
		return true
	}
	if _, err := os.Stat(paths.Dir); err == nil {
		return true
	}
	return false
}

// profileWarnings collects display warnings for `profile show`:
// missing cookies, non-0600 cookies/config files, and dangling
// outbound tag references.
func profileWarnings(baseDir string, single *profile.SingleConfig, prof *profile.Profile) []string {
	warnings := []string{}
	if _, err := os.Stat(prof.CookiesFile); err != nil {
		if os.IsNotExist(err) {
			warnings = append(warnings, fmt.Sprintf("cookies file %s does not exist", prof.CookiesFile))
		}
	} else if info, err := os.Stat(prof.CookiesFile); err == nil {
		if info.Mode().Perm() != 0o600 {
			warnings = append(warnings, fmt.Sprintf("cookies file %s has mode %04o, expected 0600", prof.CookiesFile, info.Mode().Perm()))
		}
	}
	if prof.ConfigFile != "" {
		if info, err := os.Stat(prof.ConfigFile); err == nil {
			if info.Mode().Perm() != 0o600 {
				warnings = append(warnings, fmt.Sprintf("config file %s has mode %04o, expected 0600", prof.ConfigFile, info.Mode().Perm()))
			}
		}
	}
	if prof.Outbound.Kind == profile.OutboundTag && prof.Outbound.Tag != "" && prof.Outbound.Tag != "direct" {
		if single != nil && !tagDefined(single, prof.Outbound.Tag) {
			warnings = append(warnings, fmt.Sprintf("outbound tag %q is not defined in the config", prof.Outbound.Tag))
		}
	}
	return warnings
}

func tagDefined(single *profile.SingleConfig, tag string) bool {
	obs, err := single.ParsedOutbounds()
	if err == nil {
		for _, ob := range obs {
			if ob.Tag == tag {
				return true
			}
		}
	}
	eps, err := single.ParsedEndpoints()
	if err == nil {
		for _, ep := range eps {
			if ep.Tag == tag {
				return true
			}
		}
	}
	return false
}

func cmdProfileAdd(ctx context.Context, env *Env, g *globalOpts, args []string) error {
	defs := []flagDef{
		{name: "cookies-file", kind: flagString},
		{name: "outbound", kind: flagString},
		{name: "set-default", kind: flagBool},
		{name: "outbound-from-env", kind: flagBool},
		{name: "fingerprint", kind: flagString},
		{name: "tls-engine", kind: flagString},
	}
	p, err := profileParse("add", args, env, defs, profileAddHelpText)
	if err != nil {
		return err
	}
	if err := checkPositionals(p, []string{"name"}, "profile add"); err != nil {
		return usageErr(err)
	}
	name := p.positionals[0]
	if p.strIsSet("outbound") && p.bool("outbound-from-env") {
		return errCodef(2, "--outbound and --outbound-from-env are mutually exclusive")
	}
	loc, err := resolveConfig(g, env, false)
	if err != nil {
		return err
	}
	if _, err := resolveActive(loc, g, env); err != nil {
		return err
	}
	var outboundData []byte
	outboundTag := ""
	if p.bool("outbound-from-env") {
		ob, err := profile.OutboundFromEnv()
		if err != nil {
			return errCode(2, err)
		}
		if ob == nil {
			return errCodef(2, "no proxy environment variables set: --outbound-from-env needs HTTPS_PROXY, HTTP_PROXY or ALL_PROXY")
		}
		// Marshal through the shared sing-box registry context
		// (the single construction site): the object must
		// round-trip through sing-box JSON exactly as the
		// profile library parses it.
		data, err := singjson.MarshalContext(outbound.RegistryContext(), ob)
		if err != nil {
			return err
		}
		outboundData = data
	} else if p.strIsSet("outbound") {
		value := p.str("outbound")
		switch {
		case value == "-":
			data, err := io.ReadAll(env.stdin())
			if err != nil {
				return err
			}
			outboundData = data
		case isExistingFile(value):
			data, err := os.ReadFile(value)
			if err != nil {
				return errCode(2, err)
			}
			outboundData = data
		default:
			outboundTag = value
		}
	}
	addOpts := profile.AddProfileOptions{
		CookiesFile: p.str("cookies-file"),
		OutboundTag: outboundTag,
		SetDefault:  p.bool("set-default"),
		Fingerprint: p.str("fingerprint"),
		TLSEngine:   p.str("tls-engine"),
	}
	// An outbound object must validate BEFORE the real file is
	// touched: AddProfile (write 1) followed by SetOutbound
	// (write 2) would otherwise leave the profile behind with a
	// direct outbound when write 2 fails validation. There is no
	// atomic add+outbound API in the profile library (a
	// single-closure merge would have to live there), so the pair
	// is pre-validated against a scratch copy of the single
	// config: a validation failure there rejects the add and the
	// real file stays byte-identical. A concurrent change
	// between pre-validation and the real writes can still leave
	// a partial profile; that window is inherent to the
	// two-write library API.
	if outboundData != nil {
		if err := prevalidateAddOutbound(loc.ConfigDir, name, addOpts, outboundData); err != nil {
			return err
		}
	}
	created, err := profile.AddProfile(loc.ConfigDir, name, addOpts)
	if err != nil {
		return err
	}
	updated := created
	if outboundData != nil {
		updated, err = profile.SetOutbound(loc.ConfigDir, name, outboundData)
		if err != nil {
			return err
		}
	}
	redacted, err := profile.RedactProfile(updated)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(env.stdout(), strings.TrimSpace(string(redacted)))
	return err
}

// prevalidateAddOutbound runs AddProfile followed by SetOutbound
// against a scratch copy of the single config file (or an empty
// scratch directory when no single file exists yet), so outbound
// validation failures surface before the real config is written.
// The scratch copy carries the same single-file bytes, so parse,
// tag-graph, and shared-WireGuard-key validation decide identically;
// the scratch directory has no legacy layout, but a real AddProfile
// refusal for an unmigrated layout writes nothing itself, so the
// scratch result never masks a real write. The scratch profile is
// discarded; only validation errors are returned.
func prevalidateAddOutbound(baseDir, name string, opts profile.AddProfileOptions, outboundData []byte) error {
	scratch, err := os.MkdirTemp("", "castctl-profile-add-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(scratch) }()
	configPath := filepath.Join(baseDir, "config.json")
	if data, err := os.ReadFile(configPath); err == nil {
		if err := os.WriteFile(filepath.Join(scratch, "config.json"), data, 0o600); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if _, err := profile.AddProfile(scratch, name, opts); err != nil {
		return err
	}
	if _, err := profile.SetOutbound(scratch, name, outboundData); err != nil {
		return err
	}
	return nil
}

func isExistingFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func cmdProfileRm(ctx context.Context, env *Env, g *globalOpts, args []string) error {
	defs := []flagDef{{name: "yes", kind: flagBool}}
	p, err := profileParse("rm", args, env, defs, profileRmHelpText)
	if err != nil {
		return err
	}
	if err := checkPositionals(p, []string{"name"}, "profile rm"); err != nil {
		return usageErr(err)
	}
	if !p.bool("yes") {
		return errCodef(2, "refusing to remove profile %q without --yes", p.positionals[0])
	}
	loc, err := resolveConfig(g, env, false)
	if err != nil {
		return err
	}
	if _, err := resolveActive(loc, g, env); err != nil {
		return err
	}
	result, err := profile.RemoveProfile(loc.ConfigDir, p.positionals[0])
	if err != nil {
		return err
	}
	var defaultProfile *string
	if result.DefaultProfile != "" {
		defaultProfile = &result.DefaultProfile
	}
	out := struct {
		Removed        string  `json:"removed"`
		DefaultProfile *string `json:"default_profile"`
		Warning        string  `json:"warning,omitempty"`
	}{
		Removed:        result.Name,
		DefaultProfile: defaultProfile,
		Warning:        result.Warning,
	}
	return writeJSON(env.stdout(), out)
}

func cmdProfileSetOutbound(ctx context.Context, env *Env, g *globalOpts, args []string) error {
	p, err := profileParse("set-outbound", args, env, nil, profileSetOutboundHelpText)
	if err != nil {
		return err
	}
	if err := checkPositionals(p, []string{"name", "file"}, "profile set-outbound"); err != nil {
		return usageErr(err)
	}
	name, source := p.positionals[0], p.positionals[1]
	var data []byte
	if source == "-" {
		data, err = io.ReadAll(env.stdin())
		if err != nil {
			return err
		}
	} else {
		data, err = os.ReadFile(source)
		if err != nil {
			return errCode(2, err)
		}
	}
	loc, err := resolveConfig(g, env, false)
	if err != nil {
		return err
	}
	if _, err := resolveActive(loc, g, env); err != nil {
		return err
	}
	updated, err := profile.SetOutbound(loc.ConfigDir, name, data)
	if err != nil {
		return err
	}
	return writeRedactedProfile(env, updated)
}

func cmdProfileSetFingerprint(ctx context.Context, env *Env, g *globalOpts, args []string) error {
	return cmdProfileSetStored(ctx, env, g, args, "set-fingerprint", profileSetFingerprintHelpText, profile.SetFingerprint)
}

func cmdProfileSetTLSEngine(ctx context.Context, env *Env, g *globalOpts, args []string) error {
	return cmdProfileSetStored(ctx, env, g, args, "set-tls-engine", profileSetTLSEngineHelpText, profile.SetTlsEngine)
}

func cmdProfileSetStored(ctx context.Context, env *Env, g *globalOpts, args []string, sub, helpText string, set func(baseDir, name, value string) (*profile.Profile, error)) error {
	p, err := profileParse(sub, args, env, nil, helpText)
	if err != nil {
		return err
	}
	if err := checkPositionals(p, []string{"name", "value"}, "profile "+sub); err != nil {
		return usageErr(err)
	}
	loc, err := resolveConfig(g, env, false)
	if err != nil {
		return err
	}
	if _, err := resolveActive(loc, g, env); err != nil {
		return err
	}
	updated, err := set(loc.ConfigDir, p.positionals[0], p.positionals[1])
	if err != nil {
		return err
	}
	return writeRedactedProfile(env, updated)
}

func writeRedactedProfile(env *Env, prof *profile.Profile) error {
	redacted, err := profile.RedactProfile(prof)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(env.stdout(), strings.TrimSpace(string(redacted)))
	return err
}

// ---------------------------------------------------------------------
// profile test
// ---------------------------------------------------------------------

type dnsPhase struct {
	OK        bool     `json:"ok"`
	MS        int64    `json:"ms"`
	Server    string   `json:"server,omitempty"`
	Source    string   `json:"source,omitempty"`
	Addresses []string `json:"addresses,omitempty"`
	Error     string   `json:"error,omitempty"`
}

type httpsPhase struct {
	OK     bool   `json:"ok"`
	MS     int64  `json:"ms"`
	Status int    `json:"status,omitempty"`
	Error  string `json:"error,omitempty"`
}

type gatewayPhase struct {
	OK          bool   `json:"ok"`
	HandshakeMS int64  `json:"handshake_ms"`
	TLS         string `json:"tls,omitempty"`
	Error       string `json:"error,omitempty"`
}

type profileTestResult struct {
	Profile  string `json:"profile"`
	Outbound struct {
		Type        string   `json:"type"`
		Tag         string   `json:"tag"`
		DetourChain []string `json:"detour_chain"`
	} `json:"outbound"`
	Fingerprint   string        `json:"fingerprint"`
	UserAgent     string        `json:"user_agent"`
	Note          string        `json:"note"`
	DNS           *dnsPhase     `json:"dns,omitempty"`
	HTTPS         *httpsPhase   `json:"https,omitempty"`
	EgressIP      *string       `json:"egress_ip"`
	EgressWarning string        `json:"egress_warning,omitempty"`
	Gateway       *gatewayPhase `json:"gateway,omitempty"`
	OK            bool          `json:"ok"`
	Errors        []string      `json:"errors"`
	Warnings      []string      `json:"warnings,omitempty"`
}

// profileTestNote is the recorded-only caveat carried by every
// `profile test` result: the stored fingerprint and User-Agent
// are recorded values, not the live handshake identity — the
// runtime always uses uTLS chrome until the TLS engine decision
// lands (see the README fingerprint section).
const profileTestNote = "recorded-only: fingerprint and user_agent are stored values; the runtime always uses uTLS chrome until the TLS engine decision lands"

// profileTestTimeouts bounds each phase externally: the DNS
// resolver's own 5s bound sits inside the DNS phase bound.
const (
	profileTestDNSTimeout    = 10 * time.Second
	profileTestHTTPSTimeout  = 30 * time.Second
	profileTestEgressTimeout = 15 * time.Second
	profileTestNoiseTimeout  = 60 * time.Second
)

func cmdProfileTest(ctx context.Context, env *Env, g *globalOpts, args []string) error {
	p, err := profileParse("test", args, env, nil, profileTestHelpText)
	if err != nil {
		return err
	}
	if len(p.positionals) > 1 {
		return usageErr(&parserError{msg: fmt.Sprintf("unrecognized arguments: %s", strings.Join(p.positionals[1:], " "))})
	}
	loc, err := resolveConfig(g, env, false)
	if err != nil {
		return err
	}
	active, err := resolveActive(loc, g, env)
	if err != nil {
		return err
	}
	name := active.Name
	explicitName := false
	if len(p.positionals) == 1 {
		name, explicitName = p.positionals[0], true
	}
	single, found, err := profile.LoadSingleConfig(loc.ConfigDir)
	if err != nil {
		return err
	}
	if !found {
		single = nil
	}
	// Fail fast on an explicitly named profile that does not
	// exist, before LoadProfile can synthesise a SourceNone
	// default and the phases run against it. The check covers
	// a positional, the --profile flag, and CASTCTL_PROFILE,
	// exactly like `profile show`.
	if explicitProfileSelected(g, env, explicitName) && !profileExists(loc.ConfigDir, single, name) {
		return errCodef(2, "profile %q does not exist", name)
	}
	prof, err := profile.LoadProfile(loc.ConfigDir, name, env.lookupEnv)
	if err != nil {
		return err
	}
	result := &profileTestResult{
		Profile:     prof.Name,
		Fingerprint: prof.Fingerprint,
		UserAgent:   gateway.UserAgent,
		Note:        profileTestNote,
		Errors:      []string{},
	}
	tag, _, err := identityForProfile(prof, single)
	if err != nil {
		return err
	}
	result.Outbound.Type = outboundTypeOf(prof)
	result.Outbound.Tag = tag
	result.Outbound.DetourChain = detourChain(single, tag)
	if prof.NodeID == "" {
		result.Warnings = append(result.Warnings, "node_id missing; using a temporary in-memory value for this test only (nothing written)")
	}

	rt, err := env.buildRuntime(ctx, loc, prof)
	if err != nil {
		// Build failure: config (2) or gateway (3) by the
		// error's own classification; the result carries the
		// failure and no phase ran. The error text is reported
		// only inside the JSON result, not a second time on
		// stderr.
		result.Errors = append(result.Errors, redactMessage(err))
		code, _ := classifyError(err)
		return finishProfileTest(env, result, code)
	}
	defer func() { _ = rt.Close() }()

	// Phase 1: DNS via the outbound.
	dnsRes := &dnsPhase{}
	result.DNS = dnsRes
	{
		phaseCtx, cancel := context.WithTimeout(ctx, profileTestDNSTimeout)
		start := time.Now()
		addrs, rerr := rt.Resolve(phaseCtx, "muse.ai")
		dnsRes.MS = time.Since(start).Milliseconds()
		cancel()
		if rerr != nil {
			dnsRes.Error = redactMessage(rerr)
			result.Errors = append(result.Errors, dnsRes.Error)
			return finishProfileTest(env, result, phaseExitCode(rerr))
		}
		dnsRes.OK = true
		for _, a := range addrs {
			dnsRes.Addresses = append(dnsRes.Addresses, a.String())
		}
		if single != nil {
			// Effective per-profile resolver, not the first
			// global server: the source names which precedence
			// branch produced it (profile / wireguard /
			// global-compat / default).
			if resolved, derr := profile.ResolveProfileDNS(prof, single); derr == nil && resolved != nil && resolved.Options != nil && len(resolved.Options.Servers) > 0 {
				dnsRes.Server = resolved.Options.Servers[0].Tag
				dnsRes.Source = string(resolved.Source)
			}
		}
	}

	// Phase 2: TLS + GET https://muse.ai/api/session.
	httpsRes := &httpsPhase{}
	result.HTTPS = httpsRes
	cookies, cerr := rt.Cookies()
	{
		phaseCtx, cancel := context.WithTimeout(ctx, profileTestHTTPSTimeout)
		start := time.Now()
		var ferr error
		if cerr == nil {
			_, ferr = gateway.FetchSessionInfo(phaseCtx, rt.HTTPClient(), cookies)
		} else {
			ferr = cerr
		}
		httpsRes.MS = time.Since(start).Milliseconds()
		cancel()
		if ferr != nil {
			httpsRes.Error = redactMessage(ferr)
			result.Errors = append(result.Errors, httpsRes.Error)
			return finishProfileTest(env, result, phaseExitCode(ferr))
		}
		httpsRes.OK = true
		httpsRes.Status = 200
	}

	// Phase 3: egress IP through the same outbound. A failure
	// reports null + warning and is NOT fatal.
	{
		phaseCtx, cancel := context.WithTimeout(ctx, profileTestEgressTimeout)
		ip, werr := fetchEgressIP(phaseCtx, rt.HTTPClient())
		cancel()
		if werr != nil {
			result.EgressWarning = redactMessage(werr)
		} else {
			result.EgressIP = &ip
		}
	}

	// Phase 4: Noise handshake, then immediate close. No chat
	// send, no session creation, no file writes.
	gwRes := &gatewayPhase{TLS: "utls-chrome"}
	result.Gateway = gwRes
	{
		phaseCtx, cancel := context.WithTimeout(ctx, profileTestNoiseTimeout)
		start := time.Now()
		cfg, cerr := connectorConfig(prof, single)
		var gw conn.Gateway
		var gerr error
		if cerr == nil {
			if prof.NodeID == "" {
				cfg.NodeID = tempNodeID()
			}
			connector := env.newConnector(rt.Dialer)
			gw, gerr = connector(phaseCtx, cfg)
		} else {
			gerr = cerr
		}
		gwRes.HandshakeMS = time.Since(start).Milliseconds()
		cancel()
		if gerr != nil {
			gwRes.Error = redactMessage(gerr)
			result.Errors = append(result.Errors, gwRes.Error)
			return finishProfileTest(env, result, phaseExitCode(gerr))
		}
		_ = gw.Close()
		gwRes.OK = true
	}

	result.OK = true
	return finishProfileTest(env, result, 0)
}

func finishProfileTest(env *Env, result *profileTestResult, code int) error {
	if err := writeJSON(env.stdout(), result); err != nil {
		return err
	}
	if code != 0 {
		return errCode(code, nil)
	}
	return nil
}

// phaseExitCode maps a phase failure to the profile-test exit
// contract: 4 timeout, 2 config, 3 gateway. Typed auth failures
// are gateway failures (3) here: the phase reached the network.
func phaseExitCode(err error) int {
	if err == nil {
		return 0
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return 4
	}
	var timeout *conn.TimeoutError
	if errors.As(err, &timeout) {
		return 4
	}
	var typed *typedAuthError
	if errors.As(err, &typed) {
		return 3
	}
	var auth *conn.AuthError
	if errors.As(err, &auth) {
		return 3
	}
	var perr *profile.Error
	if errors.As(err, &perr) {
		return profile.ExitCode(err)
	}
	var gw *conn.GatewayError
	if errors.As(err, &gw) {
		return 3
	}
	if errors.Is(err, outbound.ErrNoResolver) {
		return 2
	}
	return 3
}

func outboundTypeOf(prof *profile.Profile) string {
	if prof.Outbound.Type != "" {
		return prof.Outbound.Type
	}
	if prof.Outbound.Kind == profile.OutboundDirect {
		return "direct"
	}
	return ""
}

// egressTransportError is the commands-side equivalent of
// gateway.transportError (loop 7, item S1): a transport
// failure rendered as a typed summary — operation, error
// class, and net-error kind only, never peer text. Go's HTTP
// stack embeds the offending wire bytes in its errors (a
// malformed header line, a malformed status line), and the
// unwrapped *url.Error returned by client.Do passed that text
// through redactMessage/SummarizeErr verbatim. The original
// error stays reachable through Unwrap, so classification is
// unchanged; only the rendered text is summarised.
type egressTransportError struct {
	op    string
	class string
	kind  string
	err   error
}

func (e *egressTransportError) Error() string {
	return fmt.Sprintf("egress check: %s failed (class=%s kind=%s)", e.op, e.class, e.kind)
}

// Unwrap exposes the original transport error for classification.
func (e *egressTransportError) Unwrap() error { return e.err }

// wrapEgressTransportError wraps a transport error in its typed
// summary. A nil error stays nil.
func wrapEgressTransportError(err error) error {
	if err == nil {
		return nil
	}
	class, kind := classifyEgressTransportError(err)
	return &egressTransportError{op: "GET api64.ipify.org", class: class, kind: kind, err: err}
}

// classifyEgressTransportError mirrors
// gateway.classifyTransportError: the class/kind labels and
// the check order are the same, and must stay in sync with
// it. Classification is from the error's TYPE only — never
// from its text, which may embed peer bytes.
func classifyEgressTransportError(err error) (class, kind string) {
	switch {
	case errors.Is(err, context.Canceled):
		return "canceled", "context"
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, os.ErrDeadlineExceeded):
		return "timeout", "deadline"
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "timeout", "net_timeout"
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		if dnsErr.IsTimeout {
			return "dns", "dns_timeout"
		}
		return "dns", "dns"
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return "network", egressOpErrorKind(opErr.Op)
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return egressErrnoClassKind(errno)
	}
	var protoErr textproto.ProtocolError
	if errors.As(err, &protoErr) {
		return "transport", "response_parse"
	}
	var recErrPtr *tls.RecordHeaderError
	if errors.As(err, &recErrPtr) {
		return "tls", "tls"
	}
	var certErrPtr *tls.CertificateVerificationError
	if errors.As(err, &certErrPtr) {
		return "tls", "tls"
	}
	if errors.As(err, &ne) {
		return "network", "net_error"
	}
	return "transport", "unknown"
}

// egressOpErrorKind reduces a *net.OpError Op to a stable kind label.
func egressOpErrorKind(op string) string {
	switch op {
	case "dial", "read", "write", "accept", "listen", "connect":
		return op
	default:
		return "network_op"
	}
}

// egressErrnoClassKind maps a syscall errno to (class, kind).
func egressErrnoClassKind(errno syscall.Errno) (string, string) {
	switch errno {
	case syscall.ETIMEDOUT:
		return "timeout", "etimedout"
	case syscall.ECONNREFUSED:
		return "network", "connection_refused"
	case syscall.ECONNRESET:
		return "network", "connection_reset"
	case syscall.EPIPE:
		return "network", "broken_pipe"
	case syscall.EHOSTUNREACH:
		return "network", "host_unreachable"
	case syscall.ENETUNREACH:
		return "network", "network_unreachable"
	default:
		return "network", "syscall"
	}
}

// fetchEgressIP GETs the ipify endpoint through the outbound and
// returns the trimmed body. The exact URL is read from the plan
// delta: https://api64.ipify.org.
func fetchEgressIP(ctx context.Context, client *http.Client) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api64.ipify.org", nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", wrapEgressTransportError(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("egress check: ipify returned status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024))
	if err != nil {
		return "", err
	}
	ip := strings.TrimSpace(string(body))
	if ip == "" || strings.ContainsAny(ip, " \t\r\n") {
		// The ipify body is peer text: report its length
		// only, never its bytes (loop-5 allowlist rule).
		return "", fmt.Errorf("egress check: unexpected ipify body body_length=%d", len(body))
	}
	if _, err := netip.ParseAddr(ip); err != nil {
		return "", fmt.Errorf("egress check: ipify response is not an IP address body_length=%d", len(body))
	}
	return ip, nil
}

// ---------------------------------------------------------------------
// config migrate
// ---------------------------------------------------------------------

func cmdConfig(ctx context.Context, env *Env, g *globalOpts, args []string) error {
	if len(args) == 0 {
		fmt.Fprintln(env.stderr(), "castctl: the following arguments are required: subcommand")
		fmt.Fprint(env.stderr(), configHelpText)
		return errCode(2, nil)
	}
	switch args[0] {
	case "--help", "-h":
		fmt.Fprint(env.stdout(), configHelpText)
		return errHelpShown
	case "migrate":
		return cmdConfigMigrate(ctx, env, g, args[1:])
	default:
		fmt.Fprintf(env.stderr(), "castctl: argument subcommand: invalid choice: %q (choose from migrate)\n", args[0])
		return errCode(2, nil)
	}
}

func cmdConfigMigrate(ctx context.Context, env *Env, g *globalOpts, args []string) error {
	ap := &argParser{defs: []flagDef{{name: "write", kind: flagBool}, {name: "from", kind: flagString}}, helpText: configMigrateHelpText, prog: "castctl config migrate"}
	p, helpShown, err := ap.parse(args, env.stdout())
	if err != nil {
		if pe, ok := err.(*parserError); ok {
			fmt.Fprintf(env.stderr(), "castctl: %s\n", pe.msg)
			return errCode(2, pe)
		}
		return err
	}
	if helpShown {
		return errHelpShown
	}
	if err := checkPositionals(p, nil, "config migrate"); err != nil {
		return usageErr(err)
	}
	write := p.bool("write")
	// --from names the legacy source directory; the destination
	// is the --config file's directory (or the default config
	// directory). A relative --from value is working-directory
	// relative, like --config. An empty --from is a usage error.
	sourceDir := ""
	if p.strIsSet("from") {
		sourceDir = strings.TrimSpace(p.str("from"))
		if sourceDir == "" {
			return usageErr(&parserError{msg: "--from requires a non-empty directory"})
		}
		if abs, aerr := filepath.Abs(sourceDir); aerr == nil {
			sourceDir = abs
		}
	}
	// Only --write may create a missing explicit file, except
	// with --from: a missing destination file is the normal
	// pre-migration state for a new directory, so a --from
	// dry-run is not gated by RequirePresent either. A missing
	// non-explicit file is the normal pre-migration state and
	// passes the gate.
	loc, err := resolveConfig(g, env, write || sourceDir != "")
	if err != nil {
		return err
	}
	if sourceDir == "" {
		sourceDir = loc.ConfigDir
	}
	result, err := profile.MigrateFrom(sourceDir, loc.ConfigDir, write)
	if result != nil {
		if werr := writeJSON(env.stdout(), result); werr != nil {
			return werr
		}
	}
	return err
}

// ---------------------------------------------------------------------
// small helpers (kept in this file to avoid import cycles in tests)
// ---------------------------------------------------------------------

// redactMessage renders an error for profile-test output: the
// allowlist summary for a body-carrying error (loop-5 rule),
// SafeString text otherwise. It never carries a cookie value
// or server body bytes.
func redactMessage(err error) string {
	if err == nil {
		return ""
	}
	return logging.SummarizeErr(err)
}
