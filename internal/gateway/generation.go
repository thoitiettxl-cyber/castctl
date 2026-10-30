// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package gateway

import (
	"sync/atomic"
)

// Generation-tagged demux (S6). Every record the reader delivers
// is tagged with the gateway's generation; consumers (next())
// drop frames from an older generation. A generation identifies
// one incarnation of the gateway connection: each Gateway gets a
// fresh generation at construction, and BumpGeneration moves it
// forward when the gateway is replaced or reset. The bump is
// driven from outside this package: internal/conn's Drop/Adopt/
// Live/Reset paths bump the gateway being replaced (through a
// type assertion to an interface with exactly this method set,
// BumpGeneration() with no arguments and no results), so a
// subscriber holding the old gateway's queues never sees a
// stale frame leak into a new turn. Within this package no
// production path bumps the generation — the gateway object is
// the incarnation — so filtering is a no-op in normal flows
// and can never drop a live record.

var gatewayGenerations atomic.Uint64

// Generation returns this gateway's current generation.
func (g *Gateway) Generation() uint64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.generation
}

func (g *Gateway) currentGeneration() uint64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.generation
}

// BumpGeneration moves the gateway to a new generation. Queued
// frames tagged with an older generation are dropped by next().
// Exported with EXACTLY this method set — no arguments, no
// results — because internal/conn matches it by a cross-package
// type assertion (generationBumper in internal/conn/gateway.go):
// an unexported method can never match across packages, so any
// other name or signature would silently leave conn's bump a
// no-op. Do not change the signature without updating conn's
// interface to match. Generation() is unchanged (read-only).
func (g *Gateway) BumpGeneration() {
	g.mu.Lock()
	g.generation = gatewayGenerations.Add(1)
	g.mu.Unlock()
}

// bumpGeneration is the unexported alias kept for existing
// callers inside this package (tests); it delegates to
// BumpGeneration so there is exactly one bump implementation.
func (g *Gateway) bumpGeneration() {
	g.BumpGeneration()
}
