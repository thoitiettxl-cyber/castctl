// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

// Package shared holds the pure shaping and parsing helpers ported
// from cli.py: history-event rows, downloadable-resource traversal,
// session/usage/invite/feed/goal/idea row shapes, and the token-count
// label parser. Every function here is pure: it takes decoded JSON
// values (map[string]any / []any as produced by conn.Gateway.CallJSON,
// numbers as json.Number or int64, never float64) and returns ordered
// structs for JSON output, never maps. No function in this package
// performs I/O, fetches anything, caches an id, or prints; command
// wiring (Phase 2) owns gateway calls and printing.
//
// Shaping is lenient, in the spirit of Python's dict .get() defaults
// and of describe_approval's "never crashes on garbage": a missing or
// wrong-typed field yields the zero value (a nil pointer for a
// nullable output field), and a wholly wrong-typed top-level value
// yields an empty result, instead of an error. Callers that need a
// hard failure on a malformed envelope must check the input shape
// themselves before calling these helpers.
//
// Time formatting takes an explicit *time.Location (nil means
// time.Local, the Python time.localtime behaviour). Tests pass a
// fixed zone so assertions never depend on the machine's TZ; the
// Asia/Ho_Chi_Minh equivalence of time.Local is a differential
// concern (plan risk R9), not something this package can prove.
//
// Approvals are deliberately out of scope here: decide_approval and
// every approval-decision helper belong to internal/wait (PR4 owns
// approvals). Nothing in this package decides, or pretends to decide,
// an approval.
//
// TODO(PR4/wait): if a future shared helper needs the approval
// description shape, port describe_approval from cli.py:1097-1169
// into internal/wait and import it from there; do not duplicate the
// shape here.
package shared
