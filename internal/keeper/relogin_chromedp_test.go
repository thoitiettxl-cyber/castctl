// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

//go:build with_chromedp

package keeper

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/chromedp/cdproto/target"
	"github.com/chromedp/chromedp"
	"github.com/chromedp/chromedp/remote"
)

// harvestTargetContext builds the target context harvest runs on:
// an allocator over the fake browser WebSocket URL plus a context
// already bound to the fake page target. It mirrors the seam the
// re-login driver already holds (tctx from browserContext) without
// going through Relogin/waitForCookies.
func harvestTargetContext(t *testing.T, f *fakeCDPServer) (context.Context, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	wsURL, err := DiscoverWebSocketURL(ctx, f.server.URL)
	if err != nil {
		t.Fatalf("DiscoverWebSocketURL: %v", err)
	}
	allocCtx, cancelAlloc := remote.NewAllocator(ctx, wsURL, remote.NoModifyURL)
	t.Cleanup(cancelAlloc)
	tctx, cancelTarget := chromedp.NewContext(allocCtx, chromedp.WithTargetID(target.ID("FAKE-TARGET-ID")), chromedp.WithDetachOnCancel())
	t.Cleanup(cancelTarget)
	return tctx, cancelTarget
}

// TestHarvest pins the K-LIVE-2 read order for the re-login
// harvest: target-level Network.getCookies first, as TWO
// sequential reads on the same target context — L1a scoped
// with ExportURLs, then L1b unscoped, but only when L1a did
// not yield hatch_sess (a scoped URL list replaces the
// page+subframes list, so L1b is what recovers a host-only
// cookie on the tab's own host) — then browser-level
// Storage, then browser-level Network with ExportURLs. An
// empty read is a failed read. A level's set is accepted
// only when it passes usableSession (the tick's
// validateExportedSet gate: usable filtered hatch_sess +
// no past filtered expiry); a non-empty set that fails
// the gate falls through to the next level, and the first
// such candidate is returned only when no level passes
// the gate. The fake encodes the
// Chrome 155 headless shape: the browser-level Storage read
// succeeds empty while the browser holds a live session.
// (empty, nil) holds ONLY when the final level succeeds
// empty; when the final level errors, harvest returns the
// joined error (four labelled components: l1a/l1b/l2/l3) instead — UNLESS an earlier level already
// yielded a non-empty candidate, which is returned instead.
// Wire assertions pin the read sequence: the first target
// Network.getCookies call must carry exactly ExportURLs, the
// second (when it runs) must be unscoped, every
// browser-level Network.getCookies call must carry exactly
// ExportURLs, and no target-session Storage.getCookies call
// may occur.
func TestHarvest(t *testing.T) {
	tests := []struct {
		name                 string
		storageFails         bool
		storageEmpty         bool
		targetNetworkEmpty   bool
		targetNetworkPartial bool
		networkFails         bool
		targetNetworkFails   bool
		browserNetworkFails  bool
		targetStorageFails   bool
		unscopedTabCookie    bool
		unscopedTabExpired   bool
		unscopedNetworkFails bool
		networkEmpty         bool
		wantLen              int
		wantErr              bool
		wantErrExact         string
		wantFirstValue       string
		wantFirstDomain      string
		wantCandidate        bool
		wantTargetNetwork    bool
		wantBrowserStorage   bool
		wantBrowserNetwork   bool
		wantTargetScoped     int
		wantTargetUnscoped   int
	}{
		{
			name:               "target level primary Chrome 155 shape",
			storageEmpty:       true,
			wantLen:            3,
			wantTargetNetwork:  true,
			wantBrowserStorage: false,
			wantBrowserNetwork: false,
			wantTargetScoped:   1,
			wantTargetUnscoped: 0,
		},
		{
			// Scoped L1a empty is a failed read; the
			// unscoped L1b read runs next, returns empty
			// (flag off), and the full set comes from
			// browser-level Storage.
			name:               "target empty falls through to browser Storage",
			targetNetworkEmpty: true,
			wantLen:            3,
			wantTargetNetwork:  true,
			wantBrowserStorage: true,
			wantBrowserNetwork: false,
			wantTargetScoped:   1,
			wantTargetUnscoped: 1,
		},
		{
			// All levels succeed empty: the final level
			// stands, so harvest returns (empty, nil).
			name:               "all levels empty returns empty nil",
			storageEmpty:       true,
			targetNetworkEmpty: true,
			networkEmpty:       true,
			wantLen:            0,
			wantTargetNetwork:  true,
			wantBrowserStorage: true,
			wantBrowserNetwork: true,
			wantTargetScoped:   1,
			wantTargetUnscoped: 1,
		},
		{
			// Partial target: a non-empty set without
			// hatch_sess must NOT be accepted; the full
			// set comes from browser-level Storage.
			name:                 "partial target without hatch_sess falls through to browser Storage",
			targetNetworkPartial: true,
			wantLen:              3,
			wantTargetNetwork:    true,
			wantBrowserStorage:   true,
			wantBrowserNetwork:   false,
			wantTargetScoped:     1,
			wantTargetUnscoped:   1,
		},
		{
			// Target Network error: fall through to
			// browser-level Storage, which returns the
			// full set; the browser Network level is
			// never reached.
			name:               "target Network error falls through to browser Storage",
			networkFails:       true,
			wantLen:            3,
			wantTargetNetwork:  true,
			wantBrowserStorage: true,
			wantBrowserNetwork: false,
			wantTargetScoped:   1,
			wantTargetUnscoped: 1,
		},
		{
			// Storage error falls through; the final
			// level succeeds empty, so (empty, nil).
			name:               "storage error falls through to empty final level returns empty nil",
			storageFails:       true,
			targetNetworkEmpty: true,
			networkEmpty:       true,
			wantLen:            0,
			wantTargetNetwork:  true,
			wantBrowserStorage: true,
			wantBrowserNetwork: true,
			wantTargetScoped:   1,
			wantTargetUnscoped: 1,
		},
		{
			// Every level errors: the joined error, not
			// (empty, nil), is returned, with all four
			// labelled components in order — a swap or
			// drop of any component must fail this case.
			name:                "all levels error returns joined error",
			storageFails:        true,
			targetNetworkFails:  true,
			browserNetworkFails: true,
			wantLen:             0,
			wantErr:             true,
			wantErrExact:        "cookie harvest failed: l1a: target synthetic failure: Network.getCookies unavailable (-32601); l1b: target synthetic failure: Network.getCookies unavailable (-32601); l2: storage synthetic failure: Storage.getCookies unavailable (-32601); l3: browser synthetic failure: Network.getCookies unavailable (-32601)",
			wantTargetNetwork:   true,
			wantBrowserStorage:  true,
			wantBrowserNetwork:  true,
			wantTargetScoped:    1,
			wantTargetUnscoped:  1,
		},
		{
			// L1b serves: the scoped read is empty, but
			// the unscoped read on the same target
			// context returns the tab-host cookie, whose
			// value and domain prove L1b served it; no
			// browser-level read runs.
			name:               "scoped empty unscoped tab-host cookie serves",
			targetNetworkEmpty: true,
			unscopedTabCookie:  true,
			wantLen:            3,
			wantFirstValue:     "FAKE-TABHOST-SESS",
			wantFirstDomain:    "www.muse.ai",
			wantTargetNetwork:  true,
			wantBrowserStorage: false,
			wantBrowserNetwork: false,
			wantTargetScoped:   1,
			wantTargetUnscoped: 1,
		},
		{
			// L1b serves over a candidate: the scoped
			// read yields a hatch_sess-less candidate,
			// the unscoped read yields hatch_sess, and
			// the unscoped set wins immediately.
			name:                 "scoped partial unscoped tab-host cookie serves over candidate",
			targetNetworkPartial: true,
			unscopedTabCookie:    true,
			wantLen:              3,
			wantFirstValue:       "FAKE-TABHOST-SESS",
			wantFirstDomain:      "www.muse.ai",
			wantTargetNetwork:    true,
			wantBrowserStorage:   false,
			wantBrowserNetwork:   false,
			wantTargetScoped:     1,
			wantTargetUnscoped:   1,
		},
		{
			// Target-only Network error: L1 errors, L2
			// succeeds empty, and the final level
			// succeeds empty, so (empty, nil) with all
			// levels attempted — the target error must
			// not poison the final level.
			name:               "target-only Network error with empty Storage and succeeding final level returns empty nil",
			targetNetworkFails: true,
			storageEmpty:       true,
			networkEmpty:       true,
			wantLen:            0,
			wantTargetNetwork:  true,
			wantBrowserStorage: true,
			wantBrowserNetwork: true,
			wantTargetScoped:   1,
			wantTargetUnscoped: 1,
		},
		{
			// L3-error-with-candidate: an earlier level
			// yielded a non-empty candidate and the
			// final level errors, so the candidate is
			// returned with a nil error, not the joined
			// error.
			name:                 "final level error after candidate returns candidate",
			targetNetworkPartial: true,
			storageEmpty:         true,
			browserNetworkFails:  true,
			wantLen:              2,
			wantCandidate:        true,
			wantTargetNetwork:    true,
			wantBrowserStorage:   true,
			wantBrowserNetwork:   true,
			wantTargetScoped:     1,
			wantTargetUnscoped:   1,
		},
		{
			// A target-only Storage error must not poison
			// the browser-level Storage read, which
			// serves the full set.
			name:               "target-only Storage error does not poison browser Storage",
			targetStorageFails: true,
			targetNetworkEmpty: true,
			wantLen:            3,
			wantTargetNetwork:  true,
			wantBrowserStorage: true,
			wantBrowserNetwork: false,
			wantTargetScoped:   1,
			wantTargetUnscoped: 1,
		},
		{
			// F1S fall-through: the unscoped L1b set holds a
			// tab-host hatch_sess, but expired, so it fails
			// usableSession; the harvest must fall through
			// to browser-level Storage and return its usable
			// set instead of being shadowed by L1b.
			name:               "expired tab-host cookie falls through to browser Storage",
			targetNetworkEmpty: true,
			unscopedTabExpired: true,
			wantLen:            3,
			wantFirstValue:     "FAKE-EXPORTED-SESS",
			wantFirstDomain:    ".muse.ai",
			wantTargetNetwork:  true,
			wantBrowserStorage: true,
			wantBrowserNetwork: false,
			wantTargetScoped:   1,
			wantTargetUnscoped: 1,
		},
		{
			// L1b provenance: L1a succeeds empty, only the
			// second target read errors, L2 succeeds empty,
			// and L3 errors with no candidate — the
			// joined error's l1b label must carry L1b's
			// own error, with l1a/l2 as the empty-read
			// sentinel.
			name:                 "second target read error is labelled l1b in joined error",
			targetNetworkEmpty:   true,
			unscopedNetworkFails: true,
			storageEmpty:         true,
			browserNetworkFails:  true,
			wantLen:              0,
			wantErr:              true,
			wantErrExact:         "cookie harvest failed: l1a: cdp read returned no cookies; l1b: target unscoped synthetic failure: Network.getCookies unavailable (-32601); l2: cdp read returned no cookies; l3: browser synthetic failure: Network.getCookies unavailable (-32601)",
			wantTargetNetwork:    true,
			wantBrowserStorage:   true,
			wantBrowserNetwork:   true,
			wantTargetScoped:     1,
			wantTargetUnscoped:   1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakeCDPServer(t, tt.storageFails)
			f.storageEmpty = tt.storageEmpty
			f.targetNetworkEmpty = tt.targetNetworkEmpty
			f.targetNetworkPartial = tt.targetNetworkPartial
			f.networkFails = tt.networkFails
			f.targetNetworkFails = tt.targetNetworkFails
			f.browserNetworkFails = tt.browserNetworkFails
			f.targetStorageFails = tt.targetStorageFails
			f.unscopedTabCookie = tt.unscopedTabCookie
			f.unscopedTabExpired = tt.unscopedTabExpired
			f.unscopedNetworkFails = tt.unscopedNetworkFails
			f.networkEmpty = tt.networkEmpty
			defer f.server.Close()

			tctx, _ := harvestTargetContext(t, f)
			cookies, err := (&chromedpReloginDriver{}).harvest(tctx)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("harvest error = nil; want joined error, cookies = %+v", cookies)
				}
				if tt.wantErrExact != "" {
					if err.Error() != tt.wantErrExact {
						t.Fatalf("harvest error = %q; want exact %q", err.Error(), tt.wantErrExact)
					}
				} else if !strings.Contains(err.Error(), "cookie harvest failed") {
					t.Fatalf("harvest error = %v; want joined cookie harvest error", err)
				}
				if len(cookies) != 0 {
					t.Fatalf("cookies = %+v; want empty on joined error", cookies)
				}
			} else {
				if err != nil {
					t.Fatalf("harvest: %v; want nil error", err)
				}
				if len(cookies) != tt.wantLen {
					t.Fatalf("cookies = %+v; want %d", cookies, tt.wantLen)
				}
				if tt.wantLen == 3 {
					wantFirstValue := tt.wantFirstValue
					if wantFirstValue == "" {
						wantFirstValue = "FAKE-EXPORTED-SESS"
					}
					wantFirstDomain := tt.wantFirstDomain
					if wantFirstDomain == "" {
						wantFirstDomain = ".muse.ai"
					}
					if cookies[0].Name != "hatch_sess" || cookies[0].Value != wantFirstValue || cookies[0].Domain != wantFirstDomain {
						t.Fatalf("cookie 0 = %+v; want hatch_sess %q on %q", cookies[0], wantFirstValue, wantFirstDomain)
					}
					names := map[string]bool{}
					for _, c := range cookies {
						names[c.Name] = true
					}
					if !names["hatch_sess"] || !names["hatch_gw"] || !names["sess"] {
						t.Fatalf("cookie names = %v; want hatch_sess, hatch_gw, sess", names)
					}
				}
				if tt.wantCandidate {
					names := map[string]bool{}
					for _, c := range cookies {
						names[c.Name] = true
					}
					if names["hatch_sess"] || !names["hatch_gw"] || !names["sess"] {
						t.Fatalf("candidate cookies = %+v; want the hatch_sess-less partial set", cookies)
					}
				}
			}

			msgs := f.messagesSeen()
			attached, targetNetwork, browserStorage, browserNetwork, targetStorage := false, false, false, false, false
			targetScoped, targetUnscoped := 0, 0
			firstTargetNetwork, firstTargetUnscoped, firstBrowserStorage, firstBrowserNetwork := -1, -1, -1, -1
			for i, msg := range msgs {
				switch msg.Method {
				case "Target.attachToTarget":
					attached = true
				case "Network.getCookies":
					var params struct {
						URLs []string `json:"urls"`
					}
					// No params field, or an empty urls
					// list, means the unscoped read: only
					// the second target read (L1b) may
					// send it. A scoped read must carry
					// exactly ExportURLs.
					if len(msg.Params) > 0 {
						if err := json.Unmarshal(msg.Params, &params); err != nil {
							t.Fatalf("Network.getCookies params undecodable: %v", err)
						}
					}
					if msg.SessionID != "" {
						targetNetwork = true
						if firstTargetNetwork == -1 {
							firstTargetNetwork = i
						}
						if slices.Equal(params.URLs, ExportURLs) {
							targetScoped++
						} else if len(params.URLs) == 0 {
							targetUnscoped++
							if firstTargetUnscoped == -1 {
								firstTargetUnscoped = i
							}
						} else {
							t.Fatalf("target Network.getCookies urls = %v; want %v or empty; methods = %v", params.URLs, ExportURLs, f.methodsSeen())
						}
					} else {
						browserNetwork = true
						if firstBrowserNetwork == -1 {
							firstBrowserNetwork = i
						}
						if !slices.Equal(params.URLs, ExportURLs) {
							t.Fatalf("browser Network.getCookies urls = %v; want %v; methods = %v", params.URLs, ExportURLs, f.methodsSeen())
						}
					}
				case "Storage.getCookies":
					if msg.SessionID != "" {
						targetStorage = true
					} else {
						browserStorage = true
						if firstBrowserStorage == -1 {
							firstBrowserStorage = i
						}
					}
				}
				forbidden := map[string]bool{
					"Page.navigate": true, "Input.dispatchMouseEvent": true,
					"Input.dispatchKeyEvent": true, "Input.insertText": true,
					"Target.createTarget": true, "Target.closeTarget": true,
					"Target.activateTarget": true,
				}
				if forbidden[msg.Method] {
					t.Fatalf("harvest sent forbidden %q", msg.Method)
				}
			}
			if targetStorage {
				t.Fatalf("target-session Storage.getCookies called; want none: %v", f.methodsSeen())
			}
			if !attached {
				t.Fatalf("methods = %v; want target attach", f.methodsSeen())
			}
			if targetNetwork != tt.wantTargetNetwork {
				t.Fatalf("target Network.getCookies = %v; want %v; methods = %v", targetNetwork, tt.wantTargetNetwork, f.methodsSeen())
			}
			if browserStorage != tt.wantBrowserStorage {
				t.Fatalf("browser Storage.getCookies = %v; want %v; methods = %v", browserStorage, tt.wantBrowserStorage, f.methodsSeen())
			}
			if browserNetwork != tt.wantBrowserNetwork {
				t.Fatalf("browser Network.getCookies = %v; want %v; methods = %v", browserNetwork, tt.wantBrowserNetwork, f.methodsSeen())
			}
			// Wire sequence: exactly one scoped target
			// read, then the unscoped target read only
			// when the scoped read did not yield
			// hatch_sess — the ordered scoped-then-
			// unscoped sequence pins L1b.
			if targetScoped != tt.wantTargetScoped {
				t.Fatalf("scoped target Network.getCookies calls = %d; want %d; methods = %v", targetScoped, tt.wantTargetScoped, f.methodsSeen())
			}
			if targetUnscoped != tt.wantTargetUnscoped {
				t.Fatalf("unscoped target Network.getCookies calls = %d; want %d; methods = %v", targetUnscoped, tt.wantTargetUnscoped, f.methodsSeen())
			}
			if tt.wantTargetUnscoped > 0 && firstTargetNetwork > firstTargetUnscoped {
				t.Fatalf("scoped target Network index %d after unscoped index %d; methods = %v", firstTargetNetwork, firstTargetUnscoped, f.methodsSeen())
			}
			// Wire order: the target-level reads run
			// before any browser-level read that runs
			// at all.
			if tt.wantTargetNetwork && tt.wantBrowserStorage && firstTargetNetwork > firstBrowserStorage {
				t.Fatalf("target Network index %d after browser Storage index %d; methods = %v", firstTargetNetwork, firstBrowserStorage, f.methodsSeen())
			}
			if tt.wantTargetNetwork && tt.wantBrowserStorage && firstTargetUnscoped > firstBrowserStorage {
				t.Fatalf("unscoped target Network index %d after browser Storage index %d; methods = %v", firstTargetUnscoped, firstBrowserStorage, f.methodsSeen())
			}
			if tt.wantBrowserStorage && tt.wantBrowserNetwork && firstBrowserStorage > firstBrowserNetwork {
				t.Fatalf("browser Storage index %d after browser Network index %d; methods = %v", firstBrowserStorage, firstBrowserNetwork, f.methodsSeen())
			}
			if tt.wantTargetNetwork && tt.wantBrowserNetwork && firstTargetNetwork > firstBrowserNetwork {
				t.Fatalf("target Network index %d after browser Network index %d; methods = %v", firstTargetNetwork, firstBrowserNetwork, f.methodsSeen())
			}
		})
	}
}
