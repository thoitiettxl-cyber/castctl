// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

//go:build cgo && (linux || darwin || freebsd) && !android

package pluginhost_test

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/thoitiettxl-cyber/castctl/internal/pluginabi"
	"github.com/thoitiettxl-cyber/castctl/internal/pluginhost"
	"github.com/thoitiettxl-cyber/castctl/internal/plugintest"
)

// TestRealLoaderCallVsCloseRace: a slow native call racing
// Host.Close must neither race (run under -race) nor crash
// (the original SIGSEGV at PC=0x0). Close waits for the
// in-flight call to drain.
func TestRealLoaderCallVsCloseRace(t *testing.T) {
	dir := t.TempDir()
	so := plugintest.BuildFakePlugin(t, dir, plugintest.FakePluginOptions{})
	var logs []string
	h := newRealHost(t, &logs)
	report := applyOne(t, h, so)
	if len(report.Skipped) != 0 {
		t.Fatalf("skipped = %+v", report.Skipped)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	var callErr error
	var callOut []byte
	go func() {
		defer wg.Done()
		callOut, callErr = h.Call(context.Background(), "echo", "fake.sleep", []byte(`{"ms":400}`))
	}()
	time.Sleep(50 * time.Millisecond)
	done := make(chan struct{})
	go func() {
		h.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not return after the slow call drained")
	}
	wg.Wait()
	if callErr != nil {
		t.Fatalf("slow call err = %v", callErr)
	}
	if !strings.Contains(string(callOut), `"slept":true`) {
		t.Fatalf("slow call out = %s", callOut)
	}
	// The plugin is detached now: further calls fail cleanly.
	if _, err := h.Call(context.Background(), "echo", pluginabi.MethodProviderCall, nil); err == nil {
		t.Fatal("call after Close: want error")
	}
	h.Close()
}

// TestRealLoaderTwoHostsShareImage: two Hosts loading the
// same tag+path share one shadow path (dlopen caches one
// image); different tags get different shadow paths and
// answer independently. This is the documented BQ2(A)
// sharing semantics: one image, multiple logical instances.
func TestRealLoaderTwoHostsShareImage(t *testing.T) {
	dir := t.TempDir()
	so := plugintest.BuildFakePlugin(t, dir, plugintest.FakePluginOptions{})
	same1, err := pluginhost.ShadowCopy(pluginhost.File{ID: "echo", Path: so})
	if err != nil {
		t.Fatal(err)
	}
	same2, err := pluginhost.ShadowCopy(pluginhost.File{ID: "echo", Path: so})
	if err != nil {
		t.Fatal(err)
	}
	if same1 != same2 {
		t.Fatalf("same tag+path shadow paths differ: %q vs %q", same1, same2)
	}
	other, err := pluginhost.ShadowCopy(pluginhost.File{ID: "other", Path: so})
	if err != nil {
		t.Fatal(err)
	}
	if other == same1 {
		t.Fatalf("different tag shares shadow path: %q", other)
	}
	var logsA, logsB []string
	ha := newRealHost(t, &logsA)
	defer ha.Close()
	hb := newRealHost(t, &logsB)
	defer hb.Close()
	if r := applyOne(t, ha, so); len(r.Skipped) != 0 {
		t.Fatalf("host A skipped = %+v", r.Skipped)
	}
	if r := applyOne(t, hb, so); len(r.Skipped) != 0 {
		t.Fatalf("host B skipped = %+v", r.Skipped)
	}
	for _, h := range []*pluginhost.Host{ha, hb} {
		out, err := h.Call(context.Background(), "echo", pluginabi.MethodProviderCall, []byte(`{"input":"ping"}`))
		if err != nil {
			t.Fatal(err)
		}
		var payload struct {
			Payload string `json:"payload"`
		}
		if err := json.Unmarshal(out, &payload); err != nil || payload.Payload != "echo:ping" {
			t.Fatalf("provider call = %s err=%v", out, err)
		}
	}
	// Closing one host does not detach the other's plugin.
	ha.Close()
	out, err := hb.Call(context.Background(), "echo", pluginabi.MethodProviderCall, []byte(`{"input":"still"}`))
	if err != nil {
		t.Fatalf("host B after host A close: %v", err)
	}
	if !strings.Contains(string(out), "echo:still") {
		t.Fatalf("host B out = %s", out)
	}
}
