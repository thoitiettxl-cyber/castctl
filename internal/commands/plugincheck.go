// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/thoitiettxl-cyber/castctl/internal/logging"
	"github.com/thoitiettxl-cyber/castctl/internal/pluginabi"
	"github.com/thoitiettxl-cyber/castctl/internal/pluginhost"
)

const pluginCheckHelpText = `usage: castctl plugin check <path> [--tag TAG] [--type TYPE]

Load one plugin binary through the real plugin loader and run a
single provider call against it. This is the on-device check for
the KernelSU module (see docs/plugins.md): it prints one line per
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
				line = line[:4096] + "…"
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

// checkField strips control characters from one metadata
// field for the register line and caps it: plugin-chosen
// text must never forge a check line.
func checkField(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return s
}

// shortPluginCheckError truncates a call error for the check
// output: no raw server bodies, no secret values, tag only.
// Plugin-chosen text is redacted (SafeString) and capped.
func shortPluginCheckError(err error) string {
	text := logging.SafeString(err.Error())
	if len(text) > 200 {
		text = text[:200] + "..."
	}
	return text
}

func compactJSON(raw []byte) string {
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return capCheckText(logging.SafeString(strings.TrimSpace(string(raw))))
	}
	compact, err := json.Marshal(value)
	if err != nil {
		return capCheckText(logging.SafeString(strings.TrimSpace(string(raw))))
	}
	return capCheckText(logging.SafeString(string(compact)))
}

// capCheckText caps rendered plugin output at the single
// plugin-text limit (4096, matching the host.log cap) with
// an explicit marker.
func capCheckText(s string) string {
	if len(s) > 4096 {
		return s[:4096] + "…"
	}
	return s
}
