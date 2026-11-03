// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

//go:build with_chromedp

package keeper

import (
	"context"
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
// harvest: target-level Network.getCookies first (an empty read
// is a failed read), then browser-level Storage, then
// browser-level Network. The fake encodes the Chrome 155 headless
// shape: the browser-level Storage read succeeds empty while the
// browser holds a live session.
func TestHarvest(t *testing.T) {
	tests := []struct {
		name               string
		storageEmpty       bool
		targetNetworkEmpty bool
		networkEmpty       bool
		wantLen            int
		wantTargetNetwork  bool
		wantBrowserStorage bool
		wantBrowserNetwork bool
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
			name:               "all levels empty returns empty nil",
			storageEmpty:       true,
			targetNetworkEmpty: true,
			networkEmpty:       true,
			wantLen:            0,
			wantTargetNetwork:  true,
			wantBrowserStorage: true,
			wantBrowserNetwork: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakeCDPServer(t, false)
			f.storageEmpty = tt.storageEmpty
			f.targetNetworkEmpty = tt.targetNetworkEmpty
			f.networkEmpty = tt.networkEmpty
			defer f.server.Close()

			tctx, _ := harvestTargetContext(t, f)
			cookies, err := (&chromedpReloginDriver{}).harvest(tctx)
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

			msgs := f.messagesSeen()
			attached, targetNetwork, browserStorage, browserNetwork := false, false, false, false
			firstTargetNetwork, firstBrowserStorage, firstBrowserNetwork := -1, -1, -1
			for i, msg := range msgs {
				switch msg.Method {
				case "Target.attachToTarget":
					attached = true
				case "Network.getCookies":
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
					if msg.SessionID == "" {
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
