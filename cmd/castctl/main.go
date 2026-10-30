// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

// Command castctl is the Go port of muse-cli (Python 0.6.1).
//
// All command parsing, runtime wiring and output live in
// internal/commands; this package only wires the process
// environment (signal-aware context, stdio) and the exit code.
//
// Build tags: with_utls is required (uTLS+reality; the outbound package
// errors clearly without it). WireGuard endpoints additionally require
// with_gvisor: without it, sing-box's wireguard device stack is a stub
// returning tun.ErrGVisorNotIncluded (measured in PR1, transport/wireguard
// device_stack_stub.go, //go:build !with_gvisor) — the plan's "with_gvisor
// only for system:true" assumption does not hold for sing-box 1.14.4.
// Full product tag set: with_utls,with_quic,with_wireguard,with_gvisor.
package main

import (
	"context"
	"os"
	"os/signal"

	"github.com/thoitiettxl-cyber/castctl/internal/commands"
)

// Version mirrors src/muse_cli/__init__.py __version__ (0.6.1). The
// Python package is the version source of truth; PR5 packaging may
// generate this value instead of hard-coding it. The commands
// package owns the printed form "castctl <version>".
const Version = commands.Version

func main() {
	// SIGINT cancels in-flight network work; commands map a
	// cancelled context to exit 130, the shell convention.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	os.Exit(commands.Run(ctx, os.Args[1:], &commands.Env{}))
}
