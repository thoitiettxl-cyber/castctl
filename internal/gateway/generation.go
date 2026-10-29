package gateway

import (
	"sync/atomic"
)

// Generation-tagged demux (S6). Every record the reader delivers
// is tagged with the gateway's generation; consumers (next())
// drop frames from an older generation. A generation identifies
// one incarnation of the gateway connection: each Gateway gets a
// fresh generation at construction, and bumpGeneration moves it
// forward when the gateway is replaced or reset at the gateway
// level. No production code path in this package bumps the
// generation today — the gateway object is the incarnation — so
// filtering is a no-op in normal flows and can never drop a live
// record. The bump hook exists for the conn-side proposal
// recorded in doc.go: Muse.Drop/Adopt (and the Live replacement
// path) must bump the generation of the gateway being replaced,
// so a subscriber holding the old gateway's queues never sees a
// stale frame leak into a new turn. That bumping is a post-
// gateway follow-up, not code here: conn must not be touched in
// PR2.

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

// bumpGeneration moves the gateway to a new generation. Queued
// frames tagged with an older generation are dropped by next().
// Unexported: only the conn-side replacement paths (proposal,
// doc.go) and tests may call it.
func (g *Gateway) bumpGeneration() {
	g.mu.Lock()
	g.generation = gatewayGenerations.Add(1)
	g.mu.Unlock()
}
