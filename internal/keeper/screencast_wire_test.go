// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

//go:build with_chromedp

package keeper

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// Wire-recording tests (loop-2 Runtime correction): a fake
// CDP server records every method the attach and export paths
// actually send. The fake is SYNTHETIC (its own code, invented
// values); it proves what castctl/chromedp SEND, not what a
// real browser does (P1/CDP-skew gates stay box-side).
//
// Observed bootstrap set (chromedp v0.21.0, recorded
// 2026-10-31, also the list in screencast.go's header):
// Browser.getVersion, Target.attachToTarget, Runtime.enable,
// Runtime.evaluate("self"), Log.enable, Network.enable,
// Inspector.enable, Page.enable, DOM.enable, CSS.enable,
// Target.setDiscoverTargets, Target.setAutoAttach,
// Page.getFrameTree, DOM.getDocument, Page.enable,
// Page.startScreencast, Page.stopScreencast,
// Target.detachFromTarget. The test asserts the
// claim-relevant subset (superset-style: presence, never
// exact sequence or exact set) so incidental chromedp
// additions do not break it, while a missing Runtime enable
// fails loudly.

func TestAttachBootstrapRuntimeDiscipline(t *testing.T) {
	f := newFakeCDPServer(t, false)
	defer f.server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tr := NewFakeTransport(1)
	tr.CloseDone() // transport death ends the session at once.
	res := NewAttachRunner(f.server.URL).Run(ctx, tr)
	if res.Outcome != LoginFailed {
		t.Fatalf("outcome = %q; want failed (transport closed)", res.Outcome)
	}
	seen := map[string]bool{}
	var evalExpr string
	for _, m := range f.messagesSeen() {
		seen[m.Method] = true
		if m.Method == "Runtime.evaluate" {
			var params struct {
				Expression string `json:"expression"`
			}
			if err := json.Unmarshal(m.Params, &params); err == nil {
				evalExpr = params.Expression
			}
		}
	}
	required := []string{
		"Runtime.enable", "Runtime.evaluate",
		"Log.enable", "Network.enable", "Inspector.enable",
		"Page.enable", "DOM.enable", "CSS.enable",
		"Target.setDiscoverTargets", "Target.setAutoAttach",
	}
	for _, m := range required {
		if !seen[m] {
			t.Fatalf("attach bootstrap missing %q; methods = %v", m, f.methodsSeen())
		}
	}
	if evalExpr != "self" {
		t.Fatalf("Runtime.evaluate expression = %q; want the constant \"self\"", evalExpr)
	}
	// The attach path sends no cookie reads: export is a
	// separate browser-level step (see TestCDPExportPrimaryPath).
	for _, m := range f.methodsSeen() {
		if m == "Storage.getCookies" || m == "Network.getCookies" {
			t.Fatalf("attach path sent %q: %v", m, f.methodsSeen())
		}
	}
}

func TestDispatchKeyForwardsText(t *testing.T) {
	f := newFakeCDPServer(t, false)
	defer f.server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tr := NewFakeTransport(4)
	tr.SendInput(InputEvent{Kind: InputKey, KeyType: "char", Key: "a", Text: "a"})
	tr.SendInput(InputEvent{Kind: InputDone})
	res := NewAttachRunner(f.server.URL).Run(ctx, tr)
	if res.Outcome != DoneOutcome {
		t.Fatalf("outcome = %q; want done", res.Outcome)
	}
	var keyParams []json.RawMessage
	for _, m := range f.messagesSeen() {
		if m.Method == "Input.dispatchKeyEvent" {
			keyParams = append(keyParams, m.Params)
		}
	}
	if len(keyParams) == 0 {
		t.Fatalf("no Input.dispatchKeyEvent sent: %v", f.methodsSeen())
	}
	var params map[string]any
	if err := json.Unmarshal(keyParams[0], &params); err != nil {
		t.Fatalf("dispatchKeyEvent params unparseable: %v", err)
	}
	if params["text"] != "a" {
		t.Fatalf("dispatchKeyEvent params = %v; want text \"a\" (char events carry their character)", params)
	}
	if !strings.Contains(string(keyParams[0]), `"key":"a"`) {
		t.Fatalf("dispatchKeyEvent params = %s; want key \"a\"", keyParams[0])
	}
}
