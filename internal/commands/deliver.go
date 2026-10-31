// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package commands

import (
	"context"
	"fmt"

	"github.com/thoitiettxl-cyber/castctl/internal/conn"
	"github.com/thoitiettxl-cyber/castctl/internal/deliver"
	"github.com/thoitiettxl-cyber/castctl/internal/gateway"
)

func init() {
	registerCommand(&commandSpec{
		name:     "auth",
		help:     "auth helpers",
		helpText: authHelpText,
		handler:  cmdAuth,
	})
	registerCommand(&commandSpec{
		name:     "session-start",
		help:     "start a new side chat",
		helpText: sessionStartHelpText,
		handler:  cmdSessionStart,
	})
	for kind, spec := range map[deliver.SessionOpKind]string{
		deliver.SessionOpRename:    "rename",
		deliver.SessionOpPin:       "pin",
		deliver.SessionOpUnpin:     "unpin",
		deliver.SessionOpArchive:   "archive",
		deliver.SessionOpUnarchive: "unarchive",
		deliver.SessionOpDelete:    "delete",
	} {
		kind := kind
		name := "session-" + spec
		registerCommand(&commandSpec{
			name:     name,
			help:     spec + " a session",
			helpText: sessionOpHelpText,
			handler: func(ctx context.Context, env *Env, g *globalOpts, args []string) error {
				return cmdSessionOp(ctx, env, g, args, kind, name)
			},
		})
	}
	registerCommand(&commandSpec{
		name:     "stop",
		help:     "stop Muse's current turn (like the app's Stop button)",
		helpText: stopHelpText,
		handler:  cmdStop,
	})
	registerCommand(&commandSpec{
		name:     "wake",
		help:     "request a VM wake",
		helpText: wakeHelpText,
		handler:  cmdWake,
	})
	registerFlags("auth", "auth <subcommand> [options]", nil)
	registerFlags("session-start", "session-start [--title TITLE]", []flagDef{
		{name: "title", kind: flagString},
	})
	registerFlags("stop", "stop [--thread ID]", []flagDef{
		{name: "thread", kind: flagString},
	})
	registerFlags("wake", "wake", nil)
}

// cmdAuth dispatches auth subcommands: list, export, import, login.
func cmdAuth(ctx context.Context, env *Env, g *globalOpts, args []string) error {
	if len(args) == 0 {
		fmt.Fprintln(env.stderr(), "castctl: the following arguments are required: subcommand")
		fmt.Fprint(env.stderr(), authHelpText)
		return errCode(2, nil)
	}
	switch args[0] {
	case "--help", "-h":
		fmt.Fprint(env.stdout(), authHelpText)
		return errHelpShown
	case "list":
		return cmdAuthList(ctx, env, g, args[1:])
	case "export":
		return cmdAuthExport(ctx, env, g, args[1:])
	case "import":
		return cmdAuthImport(ctx, env, g, args[1:])
	case "login":
		return cmdAuthLogin(ctx, env, g, args[1:])
	default:
		fmt.Fprintf(env.stderr(), "castctl: argument subcommand: invalid choice: %q (choose from list, export, import, login)\n", args[0])
		return errCode(2, nil)
	}
}

func cmdAuthList(ctx context.Context, env *Env, g *globalOpts, args []string) error {
	ap := &argParser{defs: []flagDef{{name: "json", kind: flagBool}}, helpText: authListHelpText, prog: "castctl auth list"}
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
	if err := checkPositionals(p, nil, "auth list"); err != nil {
		return usageErr(err)
	}
	loc, err := resolveConfig(g, env, false)
	if err != nil {
		return err
	}
	prof, err := resolveActive(loc, g, env)
	if err != nil {
		return err
	}
	list, err := deliver.ListProfiles(loc.ConfigDir, prof.Name)
	if err != nil {
		return err
	}
	if p.bool("json") {
		return writeJSON(env.stdout(), list)
	}
	fmt.Fprint(env.stdout(), deliver.FormatAuthList(list))
	return nil
}

func cmdAuthExport(ctx context.Context, env *Env, g *globalOpts, args []string) error {
	ap := &argParser{defs: nil, helpText: authExportHelpText, prog: "castctl auth export"}
	_, helpShown, err := ap.parse(args, env.stdout())
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
	// Guidance-only, exit 1, no writes, no browser. The error
	// carries the guidance; dispatch prints it verbatim.
	return deliver.AuthExport()
}

// sessionTitleFlag reads the --title flag for session-start.
func cmdSessionStart(ctx context.Context, env *Env, g *globalOpts, args []string) error {
	p, err := parseOrHelp(commandTable["session-start"], args, env)
	if err != nil {
		return err
	}
	if err := checkPositionals(p, nil, "session-start"); err != nil {
		return usageErr(err)
	}
	title := ""
	if p.strIsSet("title") {
		title = p.str("title")
	}
	return runNetwork(ctx, env, g, func(rt *Runtime) error {
		return rt.Muse.WithGateway(ctx, func(gw conn.Gateway) error {
			v, err := deliver.SessionStart(ctx, gw, title)
			if err != nil {
				return err
			}
			return writeJSON(env.stdout(), v)
		})
	})
}

func cmdSessionOp(ctx context.Context, env *Env, g *globalOpts, args []string, kind deliver.SessionOpKind, name string) error {
	spec := commandTable[name]
	p, err := parseOrHelp(spec, args, env)
	if err != nil {
		return err
	}
	names := []string{"id"}
	if kind == deliver.SessionOpRename {
		names = append(names, "title")
	}
	if err := checkPositionals(p, names, name); err != nil {
		return usageErr(err)
	}
	id := p.positionals[0]
	title := ""
	if kind == deliver.SessionOpRename {
		title = p.positionals[1]
	}
	return runNetwork(ctx, env, g, func(rt *Runtime) error {
		return rt.Muse.WithGateway(ctx, func(gw conn.Gateway) error {
			v, err := deliver.SessionOp(ctx, gw, kind, id, title)
			if err != nil {
				return err
			}
			return writeJSON(env.stdout(), v)
		})
	})
}

func cmdStop(ctx context.Context, env *Env, g *globalOpts, args []string) error {
	p, err := parseOrHelp(commandTable["stop"], args, env)
	if err != nil {
		return err
	}
	if err := checkPositionals(p, nil, "stop"); err != nil {
		return usageErr(err)
	}
	thread := ""
	if p.strIsSet("thread") {
		thread = p.str("thread")
	}
	return runNetwork(ctx, env, g, func(rt *Runtime) error {
		return rt.Muse.WithGateway(ctx, func(gw conn.Gateway) error {
			v, err := deliver.StopTurn(ctx, gw, thread)
			if err != nil {
				return err
			}
			return writeJSON(env.stdout(), v)
		})
	})
}

func cmdWake(ctx context.Context, env *Env, g *globalOpts, args []string) error {
	p, err := parseOrHelp(commandTable["wake"], args, env)
	if err != nil {
		return err
	}
	if err := checkPositionals(p, nil, "wake"); err != nil {
		return usageErr(err)
	}
	return runNetwork(ctx, env, g, func(rt *Runtime) error {
		cookies, err := rt.Cookies()
		if err != nil {
			return err
		}
		// Wake goes over plain HTTPS through the dialer, never
		// through the gateway/Noise connection. gateway.WakeVM
		// exists in the tree, so it is passed directly.
		result, err := deliver.Wake(ctx, deliver.WakeDeps{
			Client:  rt.HTTPClient(),
			Cookies: cookies,
			VMID:    rt.Profile.VMID,
			WakeVM:  gateway.WakeVM,
		})
		if err != nil {
			return err
		}
		return writeJSON(env.stdout(), result)
	})
}
