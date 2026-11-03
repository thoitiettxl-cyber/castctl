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

// TestHarvest pins the Storage-first read order for the re-login
// harvest: browser-level Storage.getCookies first — the
// browser's authoritative store — then target-level
// Network.getCookies as TWO sequential reads on the same
// target context (L2 scoped with ExportURLs, then L3
// unscoped, which runs only when L2 did not yield a usable
// set; a scoped URL list replaces the page+subframes list,
// so L3 is what recovers a host-only cookie on the tab's
// own host), then browser-level Network with ExportURLs
// (L4). An empty read is a failed read. A level's set is
// accepted only when it passes usableSession (the tick's
// validateExportedSet gate: usable filtered hatch_sess +
// no past filtered expiry); a non-empty set that fails
// the gate falls through to the next level, and the first
// such candidate is returned only when no level passes
// the gate. The fake encodes the Chrome 155 headless
// shape: the browser-level Storage read succeeds empty
// while the browser holds a live session. (empty, nil)
// holds ONLY when the final level succeeds empty; when
// the final level errors, harvest returns the joined
// error (four labelled components: l1/l2/l3/l4) instead
// — UNLESS an earlier level already yielded a non-empty
// candidate, which is returned instead. Wire assertions
// pin the read sequence: Storage first, then the scoped
// target read, then the unscoped target read, then
// browser Network; the first target Network.getCookies
// call must carry exactly ExportURLs, the unscoped read
// must carry no urls, every browser-level
// Network.getCookies call must carry exactly ExportURLs,
// and no target-session Storage.getCookies call may occur.
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
		scopedTargetDistinct bool
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
			name:               "storage empty falls through to target scoped read",
			storageEmpty:       true,
			wantLen:            3,
			wantTargetNetwork:  true,
			wantBrowserStorage: true,
			wantBrowserNetwork: false,
			wantTargetScoped:   1,
			wantTargetUnscoped: 0,
		},
		{
			// Storage holds a usable set, so it returns
			// immediately and no target read runs at all: the
			// target-empty flag is inert under Storage-first,
			// and this case pins the short-circuit (no target
			// Network.getCookies call on the wire).
			name:               "usable Storage returns before any target read",
			wantLen:            3,
			wantTargetNetwork:  false,
			wantBrowserStorage: true,
			wantBrowserNetwork: false,
			wantTargetScoped:   0,
			wantTargetUnscoped: 0,
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
			// Storage is empty, so the scoped target read
			// runs and yields a non-empty set WITHOUT hatch_sess:
			// it must NOT be accepted; it becomes the candidate
			// and the final browser Network level serves the
			// full set.
			name:                 "partial target set falls through to final level",
			targetNetworkPartial: true,
			storageEmpty:         true,
			wantLen:              3,
			wantTargetNetwork:    true,
			wantBrowserStorage:   true,
			wantBrowserNetwork:   true,
			wantTargetScoped:     1,
			wantTargetUnscoped:   1,
		},
		{
			// Storage is empty, both target reads error
			// (target-only Network failure), and the final
			// browser Network level serves the full set; the
			// target error must not poison the final level.
			name:               "target Network errors fall through to browser Network level",
			storageEmpty:       true,
			targetNetworkFails: true,
			wantLen:            3,
			wantTargetNetwork:  true,
			wantBrowserStorage: true,
			wantBrowserNetwork: true,
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
			wantErrExact:        "cookie harvest failed: l1: storage synthetic failure: Storage.getCookies unavailable (-32601); l2: target synthetic failure: Network.getCookies unavailable (-32601); l3: target synthetic failure: Network.getCookies unavailable (-32601); l4: browser synthetic failure: Network.getCookies unavailable (-32601)",
			wantTargetNetwork:   true,
			wantBrowserStorage:  true,
			wantBrowserNetwork:  true,
			wantTargetScoped:    1,
			wantTargetUnscoped:  1,
		},
		{
			// L3 serves: Storage is empty and the scoped
			// read is empty, but the unscoped read on the same
			// target context returns the tab-host cookie, whose
			// value and domain prove L3 served it; no
			// browser-level Network read runs.
			name:               "Storage empty and scoped empty, unscoped tab-host cookie serves",
			targetNetworkEmpty: true,
			storageEmpty:       true,
			unscopedTabCookie:  true,
			wantLen:            3,
			wantFirstValue:     "FAKE-TABHOST-SESS",
			wantFirstDomain:    "www.muse.ai",
			wantTargetNetwork:  true,
			wantBrowserStorage: true,
			wantBrowserNetwork: false,
			wantTargetScoped:   1,
			wantTargetUnscoped: 1,
		},
		{
			// L3 serves over a candidate: Storage is empty,
			// the scoped read yields a hatch_sess-less
			// candidate, the unscoped read yields hatch_sess,
			// and the unscoped set wins immediately.
			name:                 "Storage empty, scoped partial candidate, unscoped tab-host cookie serves",
			targetNetworkPartial: true,
			storageEmpty:         true,
			unscopedTabCookie:    true,
			wantLen:              3,
			wantFirstValue:       "FAKE-TABHOST-SESS",
			wantFirstDomain:      "www.muse.ai",
			wantTargetNetwork:    true,
			wantBrowserStorage:   true,
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
			// Storage holds a usable set and returns first,
			// so no target read runs; the target-session
			// Storage error flag is inert for harvest (harvest
			// never issues a target Storage read), exactly as
			// before — this case pins the short-circuit.
			name:               "usable Storage returns before target reads; target Storage error inert",
			targetStorageFails: true,
			targetNetworkEmpty: true,
			wantLen:            3,
			wantTargetNetwork:  false,
			wantBrowserStorage: true,
			wantBrowserNetwork: false,
			wantTargetScoped:   0,
			wantTargetUnscoped: 0,
		},
		{
			// F1S fall-through, Storage-first form: Storage
			// is empty and the scoped read is empty, the
			// unscoped L3 set holds a tab-host hatch_sess,
			// but expired, so it fails usableSession; the
			// harvest must fall through to the final level
			// and return its usable set instead of being
			// shadowed by L3.
			name:               "expired tab-host cookie falls through to browser Network level",
			targetNetworkEmpty: true,
			storageEmpty:       true,
			unscopedTabExpired: true,
			wantLen:            3,
			wantFirstValue:     "FAKE-EXPORTED-SESS",
			wantFirstDomain:    ".muse.ai",
			wantTargetNetwork:  true,
			wantBrowserStorage: true,
			wantBrowserNetwork: true,
			wantTargetScoped:   1,
			wantTargetUnscoped: 1,
		},
		{
			// L3 provenance: Storage and the scoped read
			// succeed empty, only the third (unscoped) read
			// errors, L4 errors with no candidate — the
			// joined error's l3 label must carry L3's
			// own error, with l1/l2 as the empty-read
			// sentinel.
			name:                 "third read error is labelled l3 in joined error",
			targetNetworkEmpty:   true,
			unscopedNetworkFails: true,
			storageEmpty:         true,
			browserNetworkFails:  true,
			wantLen:              0,
			wantErr:              true,
			wantErrExact:         "cookie harvest failed: l1: cdp read returned no cookies; l2: cdp read returned no cookies; l3: target unscoped synthetic failure: Network.getCookies unavailable (-32601); l4: browser synthetic failure: Network.getCookies unavailable (-32601)",
			wantTargetNetwork:    true,
			wantBrowserStorage:   true,
			wantBrowserNetwork:   true,
			wantTargetScoped:     1,
			wantTargetUnscoped:   1,
		},
		{
			// P2 / Storage-first priority: the Storage set
			// and the scoped target set BOTH pass
			// usableSession with different hatch_sess
			// values on different hosts. Priority, not
			// a value comparison, decides: the Storage
			// set wins deterministically, and no target
			// read runs at all. A target-first order
			// must fail this case.
			name:                 "usable Storage wins over usable scoped target set with a different value",
			scopedTargetDistinct: true,
			wantLen:              3,
			wantFirstValue:       "FAKE-EXPORTED-SESS",
			wantFirstDomain:      ".muse.ai",
			wantTargetNetwork:    false,
			wantBrowserStorage:   true,
			wantBrowserNetwork:   false,
			wantTargetScoped:     0,
			wantTargetUnscoped:   0,
		},
		{
			// Chrome 155 empty Storage: the browser-level
			// Storage read succeeds empty (a failed
			// read), the scoped target read yields a
			// hatch_sess-less candidate, and the
			// unscoped target read serves the tab-host
			// set — the full fall-through chain, in
			// order Storage, scoped, unscoped.
			name:                 "Chrome 155 empty Storage falls through scoped and unscoped target reads",
			storageEmpty:         true,
			targetNetworkPartial: true,
			unscopedTabCookie:    true,
			wantLen:              3,
			wantFirstValue:       "FAKE-TABHOST-SESS",
			wantFirstDomain:      "www.muse.ai",
			wantTargetNetwork:    true,
			wantBrowserStorage:   true,
			wantBrowserNetwork:   false,
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
			f.scopedTargetDistinct = tt.scopedTargetDistinct
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
					// the third read (L3) may
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
			// Target attach is lazy in chromedp: it happens on
			// the first target-session call. A Storage-first
			// short-circuit legitimately never attaches, so
			// attach is required only when a target read ran.
			if !attached && tt.wantTargetNetwork {
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
			// unscoped sequence pins L3.
			if targetScoped != tt.wantTargetScoped {
				t.Fatalf("scoped target Network.getCookies calls = %d; want %d; methods = %v", targetScoped, tt.wantTargetScoped, f.methodsSeen())
			}
			if targetUnscoped != tt.wantTargetUnscoped {
				t.Fatalf("unscoped target Network.getCookies calls = %d; want %d; methods = %v", targetUnscoped, tt.wantTargetUnscoped, f.methodsSeen())
			}
			if tt.wantTargetUnscoped > 0 && firstTargetNetwork > firstTargetUnscoped {
				t.Fatalf("scoped target Network index %d after unscoped index %d; methods = %v", firstTargetNetwork, firstTargetUnscoped, f.methodsSeen())
			}
			// Wire order: Storage runs before any
			// target-level read, target reads run before
			// browser Network, and Storage runs before
			// browser Network.
			if tt.wantBrowserStorage && tt.wantTargetNetwork && firstBrowserStorage > firstTargetNetwork {
				t.Fatalf("browser Storage index %d after target Network index %d; methods = %v", firstBrowserStorage, firstTargetNetwork, f.methodsSeen())
			}
			if tt.wantBrowserStorage && tt.wantTargetUnscoped > 0 && firstBrowserStorage > firstTargetUnscoped {
				t.Fatalf("browser Storage index %d after unscoped target Network index %d; methods = %v", firstBrowserStorage, firstTargetUnscoped, f.methodsSeen())
			}
			if tt.wantBrowserStorage && tt.wantBrowserNetwork && firstBrowserStorage > firstBrowserNetwork {
				t.Fatalf("browser Storage index %d after browser Network index %d; methods = %v", firstBrowserStorage, firstBrowserNetwork, f.methodsSeen())
			}
			if tt.wantTargetNetwork && tt.wantBrowserNetwork && firstTargetNetwork > firstBrowserNetwork {
				t.Fatalf("target Network index %d after browser Network index %d; methods = %v", firstTargetNetwork, firstBrowserNetwork, f.methodsSeen())
			}
			if tt.wantTargetUnscoped > 0 && tt.wantBrowserNetwork && firstTargetUnscoped > firstBrowserNetwork {
				t.Fatalf("unscoped target Network index %d after browser Network index %d; methods = %v", firstTargetUnscoped, firstBrowserNetwork, f.methodsSeen())
			}
		})
	}
}
