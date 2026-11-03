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
// harvest: target-level Network.getCookies first (scoped with
// ExportURLs, an empty read is a failed read), then browser-level
// Storage, then browser-level Network with ExportURLs. A level's
// set is accepted only when it is non-empty AND contains
// hatch_sess; a non-empty set without hatch_sess falls through
// to the next level, and the first such candidate is returned
// only when no level yields hatch_sess. The fake encodes the
// Chrome 155 headless shape: the browser-level Storage read
// succeeds empty while the browser holds a live session.
// (empty, nil) holds ONLY when the final level succeeds empty;
// when the final level errors, harvest returns the joined
// error instead. Wire assertions pin the URL scoping: every
// Network.getCookies call must carry exactly ExportURLs, and
// no target-session Storage.getCookies call may occur.
func TestHarvest(t *testing.T) {
	tests := []struct {
		name                 string
		storageFails         bool
		storageEmpty         bool
		targetNetworkEmpty   bool
		targetNetworkPartial bool
		networkFails         bool
		networkEmpty         bool
		wantLen              int
		wantErr              bool
		wantTargetNetwork    bool
		wantBrowserStorage   bool
		wantBrowserNetwork   bool
	}{
		{
			name:               "target level primary Chrome 155 shape",
			storageEmpty:       true,
			wantLen:            3,
			wantTargetNetwork:  true,
			wantBrowserStorage: false,
			wantBrowserNetwork: false,
		},
		{
			name:               "target empty falls through to browser Storage",
			targetNetworkEmpty: true,
			wantLen:            3,
			wantTargetNetwork:  true,
			wantBrowserStorage: true,
			wantBrowserNetwork: false,
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
		},
		{
			// Every level errors: the joined error, not
			// (empty, nil), is returned.
			name:               "all levels error returns joined error",
			storageFails:       true,
			networkFails:       true,
			wantLen:            0,
			wantErr:            true,
			wantTargetNetwork:  true,
			wantBrowserStorage: true,
			wantBrowserNetwork: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakeCDPServer(t, tt.storageFails)
			f.storageEmpty = tt.storageEmpty
			f.targetNetworkEmpty = tt.targetNetworkEmpty
			f.targetNetworkPartial = tt.targetNetworkPartial
			f.networkFails = tt.networkFails
			f.networkEmpty = tt.networkEmpty
			defer f.server.Close()

			tctx, _ := harvestTargetContext(t, f)
			cookies, err := (&chromedpReloginDriver{}).harvest(tctx)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("harvest error = nil; want joined error, cookies = %+v", cookies)
				}
				if !strings.Contains(err.Error(), "cookie harvest failed") {
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
					if cookies[0].Name != "hatch_sess" || cookies[0].Value != "FAKE-EXPORTED-SESS" || cookies[0].Domain != ".muse.ai" {
						t.Fatalf("cookie 0 = %+v", cookies[0])
					}
					names := map[string]bool{}
					for _, c := range cookies {
						names[c.Name] = true
					}
					if !names["hatch_sess"] || !names["hatch_gw"] || !names["sess"] {
						t.Fatalf("cookie names = %v; want hatch_sess, hatch_gw, sess", names)
					}
				}
			}

			msgs := f.messagesSeen()
			attached, targetNetwork, browserStorage, browserNetwork, targetStorage := false, false, false, false, false
			firstTargetNetwork, firstBrowserStorage, firstBrowserNetwork := -1, -1, -1
			for i, msg := range msgs {
				switch msg.Method {
				case "Target.attachToTarget":
					attached = true
				case "Network.getCookies":
					var params struct {
						URLs []string `json:"urls"`
					}
					// No params field means no URL list: the
					// unscoped read, which must fail the
					// ExportURLs assertion below.
					if len(msg.Params) > 0 {
						if err := json.Unmarshal(msg.Params, &params); err != nil {
							t.Fatalf("Network.getCookies params undecodable: %v", err)
						}
					}
					if !slices.Equal(params.URLs, ExportURLs) {
						t.Fatalf("Network.getCookies urls = %v; want %v; methods = %v", params.URLs, ExportURLs, f.methodsSeen())
					}
					if msg.SessionID != "" {
						targetNetwork = true
						if firstTargetNetwork == -1 {
							firstTargetNetwork = i
						}
					} else {
						browserNetwork = true
						if firstBrowserNetwork == -1 {
							firstBrowserNetwork = i
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
			// Wire order: the target-level read runs before any
			// browser-level read that runs at all.
			if tt.wantTargetNetwork && tt.wantBrowserStorage && firstTargetNetwork > firstBrowserStorage {
				t.Fatalf("target Network index %d after browser Storage index %d; methods = %v", firstTargetNetwork, firstBrowserStorage, f.methodsSeen())
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
