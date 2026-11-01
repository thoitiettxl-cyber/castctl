// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/thoitiettxl-cyber/castctl/internal/logging"
	"github.com/thoitiettxl-cyber/castctl/internal/pluginabi"
	"github.com/thoitiettxl-cyber/castctl/internal/pluginhost"
)

const pluginCheckHelpText = `usage: castctl plugin check <path> [--tag TAG] [--type TYPE]

Load one plugin binary through the real plugin loader and run a
single provider call against it. This is the on-device check
run inside Droidspaces with the normal linux/arm64 castctl
binary (see docs/plugins.md): it prints one line per
stage (dlopen, init, register, provider.call, shutdown), plus
any host.log lines the plugin emits (printed as plugin log lines).
Command-only plugins skip the provider.call stage (it is
printed as skipped, not failed). It loads no config, starts no
services, writes no config or cookies, and logs no secrets.
Exit 0 when every stage passes, exit 2 otherwise.
`

func init() {
	registerCommand(&commandSpec{
		name:     "plugin",
		help:     "check a plugin binary through the real loader",
		helpText: pluginCheckHelpText,
		handler:  cmdPlugin,
	})
	registerFlags("plugin", "plugin check <path> [--tag TAG] [--type TYPE]", nil)
}

func cmdPlugin(ctx context.Context, env *Env, g *globalOpts, args []string) error {
	if len(args) == 0 {
		fmt.Fprint(env.stderr(), pluginCheckHelpText)
		return errCode(2, nil)
	}
	switch args[0] {
	case "--help", "-h":
		fmt.Fprint(env.stdout(), pluginCheckHelpText)
		return errHelpShown
	case "check":
		return cmdPluginCheck(ctx, env, args[1:])
	default:
		fmt.Fprintf(env.stderr(), "castctl: argument subcommand: invalid choice: %q (choose from check)\n", args[0])
		return errCode(2, nil)
	}
}

func cmdPluginCheck(ctx context.Context, env *Env, args []string) error {
	ap := &argParser{defs: []flagDef{{name: "tag", kind: flagString}, {name: "type", kind: flagString}}, helpText: pluginCheckHelpText, prog: "plugin check"}
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
	if err := checkPositionals(p, []string{"path"}, "plugin check"); err != nil {
		return usageErr(err)
	}
	tag := p.str("tag")
	if tag == "" {
		tag = "check"
	}
	if !pluginhost.ValidatePluginID(tag) {
		return errCodef(2, "plugin: invalid --tag %q", tag)
	}
	typ := p.str("type")
	if typ == "" {
		typ = "check"
	}
	path := p.positionals[0]

	out := env.stdout()
	host := pluginhost.New(pluginhost.Options{
		Log: func(level, message string) {
			// Level and message are already sanitised by
			// the host (allowlisted level, control chars
			// stripped); cap the line so a chatty plugin
			// cannot flood check output.
			line := "plugin log [" + level + "]: " + message
			if len(line) > 4096 {
				line = truncateRunes(line, 4096) + "…"
			}
			fmt.Fprintln(out, line)
		},
	})
	report := host.ApplyConfig(ctx, []pluginhost.Desired{
		{Tag: tag, Type: typ, Path: path, Fragment: []byte(`{}`)},
	})
	if len(report.Skipped) != 0 {
		fmt.Fprintf(env.stderr(), "plugin check: FAIL %s: %s\n", tag, report.Skipped[0].Reason)
		host.Close()
		return errCode(2, nil)
	}
	loaded, ok := host.Loaded(tag)
	if !ok {
		fmt.Fprintf(env.stderr(), "plugin check: FAIL %s: loaded but not reported\n", tag)
		host.Close()
		return errCode(2, nil)
	}
	fmt.Fprintln(out, "dlopen: ok")
	fmt.Fprintln(out, "init: ok")
	var caps []string
	if loaded.Capabilities.Provider {
		caps = append(caps, "provider")
	}
	if loaded.Capabilities.CommandProvider {
		caps = append(caps, "command-provider")
	}
	fmt.Fprintf(out, "register: ok schema=%d name=%s version=%s capabilities=%s\n",
		loaded.SchemaVersion, checkField(loaded.Metadata.Name), checkField(loaded.Metadata.Version), strings.Join(caps, ","))
	if !loaded.Capabilities.Provider {
		// Command-only plugin: provider.call has no
		// dispatch path and must not FAIL the check.
		fmt.Fprintln(out, "provider.call: skipped (command-only plugin)")
		fmt.Fprintln(out, "shutdown: ok")
		host.Close()
		return nil
	}
	result, err := host.Call(ctx, tag, pluginabi.MethodProviderCall, []byte(`{"input":"ping"}`))
	host.Close()
	if err != nil {
		fmt.Fprintf(env.stderr(), "plugin check: FAIL %s: provider.call: %s\n", tag, shortPluginCheckError(err))
		return errCode(2, nil)
	}
	fmt.Fprintf(out, "provider.call: ok %s\n", compactJSON(result))
	fmt.Fprintln(out, "shutdown: ok")
	return nil
}

// redactClosers mirrors pluginhost.redactClosers: closing
// quotes appended after a cap cut so the redaction scanner
// sees a terminated value instead of writing the cut
// remainder verbatim. See internal/pluginhost/text.go.
const redactClosers = `""''\"\"\'\'`

// truncateRunes cuts s at the largest rune boundary at or
// below max bytes, in O(1) (backs up at most 3 bytes).
func truncateRunes(s string, max int) string {
	if max <= 0 {
		return ""
	}
	if len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && cut > max-4 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

// capBeforeRedact truncates s to max bytes at a rune
// boundary and, only when truncated, appends redactClosers.
// SafeString's cost is superlinear, so the cap must run
// BEFORE redaction.
func capBeforeRedact(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return truncateRunes(s, max) + redactClosers
}

// redactAndCap redacts s (SafeString) after capping it at
// max, then caps the redacted output again at max with the
// explicit marker.
func redactAndCap(s string, max int) string {
	out := logging.SafeString(capBeforeRedact(s, max))
	if len(out) > max {
		return truncateRunes(out, max) + "…"
	}
	return out
}

// checkField strips control characters from one metadata
// field for the register line and caps it: plugin-chosen
// text must never forge a check line. Metadata runs
// through the same SafeString path as envelope errors,
// after the cap (bounded cost: 200 bytes).
func checkField(s string) string {
	s = redactAndCap(s, 200)
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	return s
}

// shortPluginCheckError truncates a call error for the check
// output: no raw server bodies, no secret values, tag only.
// Plugin-chosen text is redacted (SafeString) and capped,
// cap before redact, with the "…" marker. Control
// characters are stripped first (safety N1): the FAIL
// line must stay one line.
func shortPluginCheckError(err error) string {
	return redactAndCap(stripCheckControls(err.Error()), 200)
}

// stripCheckControls maps newline/CR/tab to a space and
// drops other C0 controls and DEL, mirroring
// pluginhost.stripControlChars (same mapping, local copy:
// the check helpers must not import pluginhost internals).
func stripCheckControls(s string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case '\n', '\r', '\t':
			return ' '
		}
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
}

func compactJSON(raw []byte) string {
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return capCheckText(redactAndCap(strings.TrimSpace(string(raw)), 4096))
	}
	compact, err := json.Marshal(value)
	if err != nil {
		return capCheckText(redactAndCap(strings.TrimSpace(string(raw)), 4096))
	}
	return capCheckText(redactAndCap(string(compact), 4096))
}

// capCheckText caps rendered plugin output at the single
// plugin-text limit (4096, matching the host.log cap) with
// an explicit marker, at a rune boundary.
func capCheckText(s string) string {
	if len(s) > 4096 {
		return truncateRunes(s, 4096) + "…"
	}
	return s
}
