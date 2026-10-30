// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

// Package deliver holds the deliver-side library commands ported
// from cli.py: offline profile listing, session operations, turn
// cancellation, VM wake, and the guidance-only form of cookie
// export. It is a library only: no flag parsing, no printing, no
// os.Exit. The commands layer owns CLI wiring, printing, and exit
// codes.
//
// Every function takes explicit dependencies (a Gateway, an
// *http.Client, a cookies string, a profile) and returns values
// plus classified errors. No function in this package dials,
// reads proxy environment variables, or uses a default HTTP
// client: all network traffic goes through the passed-in gateway
// or the passed-in client, which the caller derives from the
// profile outbound dialer.
//
// Deliberate portable subset — cookie export: AuthExport never
// extracts cookies. Real cookie extraction is carried, awaiting
// the login-research decision (native/relay/import); see
// authexport.go. This is a deliberate subset, not parity.
//
// Out of scope here (other PRs own them): send/wait, approvals,
// approve/deny/auto-approve, Telegram, and update.
package deliver
