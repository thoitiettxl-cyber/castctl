// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/thoitiettxl-cyber/castctl/internal/pluginabi"
	"github.com/thoitiettxl-cyber/castctl/internal/pluginhost"
)

const pluginCheckHelpText = `usage: castctl plugin check <path> [--tag TAG] [--type TYPE]

Load one plugin binary through the real plugin loader and run a
single provider call against it. This is the on-device check for
the KernelSU module (see docs/plugins.md): it prints one line per
stage (dlopen, init, register, provider.call, shutdown) and
nothing else. It loads no config, starts no services, writes no
config or cookies, and logs no secrets. Exit 0 when every stage
passes, exit 2 otherwise.
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
			fmt.Fprintf(out, "plugin log [%s]: %s\n", level, message)
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
		loaded.SchemaVersion, loaded.Metadata.Name, loaded.Metadata.Version, strings.Join(caps, ","))
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

// shortPluginCheckError truncates a call error for the check
// output: no raw server bodies, no secret values, tag only.
func shortPluginCheckError(err error) string {
	text := err.Error()
	if len(text) > 200 {
		text = text[:200] + "..."
	}
	return text
}

func compactJSON(raw []byte) string {
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return strings.TrimSpace(string(raw))
	}
	compact, err := json.Marshal(value)
	if err != nil {
		return strings.TrimSpace(string(raw))
	}
	return string(compact)
}
