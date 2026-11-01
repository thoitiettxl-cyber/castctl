// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package pluginhost_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/thoitiettxl-cyber/castctl/internal/pluginabi"
	"github.com/thoitiettxl-cyber/castctl/internal/pluginhost"
	"github.com/thoitiettxl-cyber/castctl/internal/plugintest"
)

// TestHostCallFailsFastWhenFused: after a panic fuse, Call
// fails without invoking the plugin again.
func TestHostCallFailsFastWhenFused(t *testing.T) {
	loader, clients := fakeSetup("/plugins/echo.so")
	var logs []string
	h := newFakeHost(t, loader, &logs)
	defer h.Close()
	h.ApplyConfig(context.Background(), []pluginhost.Desired{{Tag: "echo", Type: "echo", Path: "/plugins/echo.so"}})
	fake := clients["/plugins/echo.so"]
	fake.PanicMethods = map[string]any{pluginabi.MethodProviderCall: true}
	if _, err := h.Call(context.Background(), "echo", pluginabi.MethodProviderCall, nil); err == nil {
		t.Fatal("panicking call: want error")
	}
	before := fake.CallCount(pluginabi.MethodProviderCall)
	if _, err := h.Call(context.Background(), "echo", pluginabi.MethodProviderCall, nil); err == nil || !strings.Contains(err.Error(), "fused") {
		t.Fatalf("fused call err = %v, want fused error", err)
	}
	if got := fake.CallCount(pluginabi.MethodProviderCall); got != before {
		t.Fatalf("provider calls = %d after fuse (was %d): fused plugin must not be re-called", got, before)
	}
}

// TestHostFuseIsPerPath: rollback failure (reconfigure
// fails AND the rollback re-register fails) fuses the tag
// and deletes the loaded entry. A same-path ApplyConfig
// then skips WITHOUT re-opening the loader, Call fail-fasts
// without calling the plugin, and a different path loads
// and clears the fuse. A fused tag is never reported
// Loaded: Loaded means callable, and fused calls fail.
func TestHostFuseIsPerPath(t *testing.T) {
	loader, clients := fakeSetup("/plugins/echo.so", "/plugins/v2.so")
	var logs []string
	h := newFakeHost(t, loader, &logs)
	defer h.Close()
	ctx := context.Background()
	first := pluginhost.Desired{Tag: "echo", Type: "echo", Path: "/plugins/echo.so", Fragment: []byte(`{"n":1}`)}
	if report := h.ApplyConfig(ctx, []pluginhost.Desired{first}); len(report.Loaded) != 1 {
		t.Fatalf("initial load report = %+v", report)
	}
	fake := clients["/plugins/echo.so"]
	fake.OnCall = func(ctx context.Context, method string, request []byte) ([]byte, error) {
		switch method {
		case pluginabi.MethodPluginReconfigure:
			return nil, errors.New("reconfigure boom")
		case pluginabi.MethodPluginRegister:
			return nil, errors.New("rollback boom")
		default:
			return plugintest.ErrorResponse("unexpected", "unexpected call: "+method), nil
		}
	}
	// Same path, new fragment: reconfigure fails, rollback
	// register fails -> fused, loaded entry deleted.
	report := h.ApplyConfig(ctx, []pluginhost.Desired{{Tag: "echo", Type: "echo", Path: "/plugins/echo.so", Fragment: []byte(`{"n":2}`)}})
	if len(report.Skipped) != 1 || !strings.Contains(report.Skipped[0].Reason, "rollback failed") {
		t.Fatalf("rollback-failure report = %+v, want rollback-failed skip", report)
	}
	if len(report.Loaded) != 0 {
		t.Fatalf("fused tag reported Loaded: %+v", report)
	}
	if reason, fused := h.Fused("echo"); !fused || !strings.Contains(reason, "rollback") {
		t.Fatalf("fused=%v reason=%q, want fused with rollback reason", fused, reason)
	}
	if _, ok := h.Loaded("echo"); ok {
		t.Fatal("loaded entry must be deleted after rollback failure")
	}
	// Call fail-fasts without calling the plugin.
	callsBefore := fake.CallCount(pluginabi.MethodProviderCall)
	if _, err := h.Call(ctx, "echo", pluginabi.MethodProviderCall, nil); err == nil || !strings.Contains(err.Error(), "fused") {
		t.Fatalf("fused call err = %v, want fused error", err)
	}
	if got := fake.CallCount(pluginabi.MethodProviderCall); got != callsBefore {
		t.Fatalf("provider calls = %d (was %d): fused plugin must not be re-called", got, callsBefore)
	}
	// Same-path ApplyConfig skips WITHOUT re-opening.
	opensBefore := loader.OpenCount("/plugins/echo.so")
	report = h.ApplyConfig(ctx, []pluginhost.Desired{first})
	if len(report.Skipped) != 1 || !strings.Contains(report.Skipped[0].Reason, "fused") {
		t.Fatalf("same-path report = %+v, want fused skip", report)
	}
	if len(report.Loaded) != 0 {
		t.Fatalf("same-path fused tag reported Loaded: %+v", report)
	}
	if got := loader.OpenCount("/plugins/echo.so"); got != opensBefore {
		t.Fatalf("loader opens = %d (was %d): fused same-path load must not re-open", got, opensBefore)
	}
	// Different path loads and clears the fuse.
	fake.OnCall = nil
	report = h.ApplyConfig(ctx, []pluginhost.Desired{{Tag: "echo", Type: "echo", Path: "/plugins/v2.so", Fragment: []byte(`{"n":1}`)}})
	if len(report.Loaded) != 1 || len(report.Skipped) != 0 {
		t.Fatalf("replacement report = %+v", report)
	}
	if _, fused := h.Fused("echo"); fused {
		t.Fatal("fuse must clear after successful different-path load")
	}
	if _, err := h.Call(ctx, "echo", pluginabi.MethodProviderCall, []byte(`{"input":"ping"}`)); err != nil {
		t.Fatalf("call after replacement err = %v", err)
	}
}

// TestHostTagAndTypeValidation: invalid tag/type values are
// rejected at the Host layer.
func TestHostTagAndTypeValidation(t *testing.T) {
	loader, _ := fakeSetup("/plugins/echo.so")
	var logs []string
	h := newFakeHost(t, loader, &logs)
	defer h.Close()
	for _, d := range []pluginhost.Desired{
		{Tag: "../../evil", Type: "echo", Path: "/plugins/echo.so"},
		{Tag: "echo", Type: "../evil", Path: "/plugins/echo.so"},
		{Tag: "", Type: "echo", Path: "/plugins/echo.so"},
		{Tag: "echo", Type: "", Path: "/plugins/echo.so"},
		{Tag: "echo\nx", Type: "echo", Path: "/plugins/echo.so"},
	} {
		report := h.ApplyConfig(context.Background(), []pluginhost.Desired{d})
		if len(report.Skipped) != 1 || len(report.Loaded) != 0 {
			t.Fatalf("desired %+v: report = %+v, want skipped only", d, report)
		}
		if _, ok := h.Loaded(d.Tag); ok {
			t.Fatalf("tag %q loaded despite invalid tag/type", d.Tag)
		}
	}
}

// TestHostEmptyFragmentSentAsObject: a plugin registering
// with no fragment receives {} config_json, never null.
func TestHostEmptyFragmentSentAsObject(t *testing.T) {
	loader, clients := fakeSetup("/plugins/echo.so")
	var logs []string
	h := newFakeHost(t, loader, &logs)
	defer h.Close()
	h.ApplyConfig(context.Background(), []pluginhost.Desired{{Tag: "echo", Type: "echo", Path: "/plugins/echo.so"}})
	raw := clients["/plugins/echo.so"].LastRequest(pluginabi.MethodPluginRegister)
	var req pluginabi.RegisterRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		t.Fatal(err)
	}
	if string(req.ConfigJSON) != "{}" {
		t.Fatalf("config_json = %s, want {}", req.ConfigJSON)
	}
}

// TestHostEnvelopeErrorRedacted: a plugin error envelope
// carrying a secret-looking value never surfaces it in the
// returned error.
func TestHostEnvelopeErrorRedacted(t *testing.T) {
	loader, clients := fakeSetup("/plugins/echo.so")
	var logs []string
	h := newFakeHost(t, loader, &logs)
	defer h.Close()
	h.ApplyConfig(context.Background(), []pluginhost.Desired{{Tag: "echo", Type: "echo", Path: "/plugins/echo.so"}})
	fake := clients["/plugins/echo.so"]
	fake.OnCall = func(ctx context.Context, method string, request []byte) ([]byte, error) {
		if method == pluginabi.MethodPluginRegister {
			return plugintest.RegisterResponse(1, "fake", "0.1.0", "plugintest", pluginabi.Capabilities{Provider: true}), nil
		}
		return plugintest.ErrorResponse("boom", `failed with hatch_sess=SECRETVALUE and {"api_key":"abc123"}`), nil
	}
	// Re-register to install OnCall? OnCall applies to all
	// methods, so a fresh Call suffices.
	_, err := h.Call(context.Background(), "echo", pluginabi.MethodProviderCall, nil)
	if err == nil {
		t.Fatal("want envelope error")
	}
	if strings.Contains(err.Error(), "SECRETVALUE") || strings.Contains(err.Error(), "abc123") {
		t.Fatalf("error leaks plugin text: %q", err.Error())
	}
}

// TestHostCloseRevokesEgressCreds: an adopted proxy refuses
// dials after Host.Close.
func TestHostCloseRevokesEgressCreds(t *testing.T) {
	loader, _ := fakeSetup("/plugins/echo.so")
	var logs []string
	h := newFakeHost(t, loader, &logs)
	upstream := &recordingRoundTripper{body: "ok"}
	proxy, err := pluginhost.NewEgressProxy(upstream, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	h.AdoptEgress(proxy)
	addr := proxy.URL().Host
	h.Close()
	// Dial must be refused: the listener is closed.
	client := &http.Client{Timeout: 2 * time.Second}
	_, err = client.Get("http://" + addr + "/")
	if err == nil {
		t.Fatal("request after Host.Close succeeded, want refused")
	}
	// Second Close is idempotent.
	h.Close()
}

// TestHostCookieHostsAppliedFromRegistration: the host
// applies the plugin's declared cookie_hosts to the adopted
// proxy after registration.
func TestHostCookieHostsAppliedFromRegistration(t *testing.T) {
	loader, clients := fakeSetup("/plugins/echo.so")
	var logs []string
	h := newFakeHost(t, loader, &logs)
	defer h.Close()
	upstream := &recordingRoundTripper{body: "ok"}
	proxy, err := pluginhost.NewEgressProxy(upstream, nil, "injected-cookie-value")
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	fake := clients["/plugins/echo.so"]
	fake.OnCall = func(ctx context.Context, method string, request []byte) ([]byte, error) {
		if method == pluginabi.MethodPluginRegister || method == pluginabi.MethodPluginReconfigure {
			reg := pluginabi.Registration{
				SchemaVersion: 1,
				Metadata:      pluginabi.Metadata{Name: "fake", Version: "0.1.0", Author: "plugintest"},
				Capabilities:  pluginabi.Capabilities{Provider: true},
				CookieHosts:   []string{"declared.invalid"},
			}
			raw, _ := json.Marshal(reg)
			env, _ := json.Marshal(pluginabi.Envelope{OK: true, Result: raw})
			return env, nil
		}
		return plugintest.OKResponse(json.RawMessage(`{}`)), nil
	}
	report := h.ApplyConfig(context.Background(), []pluginhost.Desired{{
		Tag: "echo", Type: "echo", Path: "/plugins/echo.so", EgressProxy: proxy,
	}})
	if len(report.Skipped) != 0 {
		t.Fatalf("report = %+v", report)
	}
	// Declared host gets the cookie through the proxy.
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURLWithCreds(t, proxy, proxy.Username(), proxy.Password()))}}
	req, _ := http.NewRequest("GET", "http://declared.invalid/a", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if got := upstream.last.Header.Get("Cookie"); got != "injected-cookie-value" {
		t.Fatalf("declared host Cookie = %q, want injected value", got)
	}
}

// registerWithHosts returns an OnCall answering register /
// reconfigure with the given cookie_hosts declaration.
func registerWithHosts(hosts []string) func(context.Context, string, []byte) ([]byte, error) {
	return func(ctx context.Context, method string, request []byte) ([]byte, error) {
		if method == pluginabi.MethodPluginRegister || method == pluginabi.MethodPluginReconfigure {
			reg := pluginabi.Registration{
				SchemaVersion: 1,
				Metadata:      pluginabi.Metadata{Name: "fake", Version: "0.1.0", Author: "plugintest"},
				Capabilities:  pluginabi.Capabilities{Provider: true},
				CookieHosts:   hosts,
			}
			raw, _ := json.Marshal(reg)
			env, _ := json.Marshal(pluginabi.Envelope{OK: true, Result: raw})
			return env, nil
		}
		return plugintest.OKResponse(json.RawMessage(`{}`)), nil
	}
}

func dialViaProxy(t *testing.T, proxy *pluginhost.EgressProxy, upstream *recordingRoundTripper, target string) (*http.Response, error) {
	t.Helper()
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURLWithCreds(t, proxy, proxy.Username(), proxy.Password()))}, Timeout: 2 * time.Second}
	req, _ := http.NewRequest("GET", target, nil)
	return client.Do(req)
}

// TestHostSupersededEgressClosed: reconfiguring with a
// different egress proxy closes the old one (no loaded tag
// references it) and the old cookie scope stops applying.
// Narrowing scope on reconfigure must actually take effect
// for the old image's credentials too.
func TestHostSupersededEgressClosed(t *testing.T) {
	loader, clients := fakeSetup("/plugins/echo.so")
	var logs []string
	h := newFakeHost(t, loader, &logs)
	defer h.Close()
	ctx := context.Background()
	upstream := &recordingRoundTripper{body: "ok"}
	oldProxy, err := pluginhost.NewEgressProxy(upstream, nil, "injected-cookie-value")
	if err != nil {
		t.Fatal(err)
	}
	newProxy, err := pluginhost.NewEgressProxy(upstream, nil, "injected-cookie-value")
	if err != nil {
		t.Fatal(err)
	}
	defer newProxy.Close()
	fake := clients["/plugins/echo.so"]
	fake.OnCall = registerWithHosts([]string{"declared.invalid"})
	if report := h.ApplyConfig(ctx, []pluginhost.Desired{{Tag: "echo", Type: "echo", Path: "/plugins/echo.so", Fragment: []byte(`{"n":1}`), EgressProxy: oldProxy}}); len(report.Loaded) != 1 {
		t.Fatalf("load report = %+v", report)
	}
	// Reconfigure with a new proxy + narrowed scope.
	fake.OnCall = registerWithHosts([]string{"other.invalid"})
	if report := h.ApplyConfig(ctx, []pluginhost.Desired{{Tag: "echo", Type: "echo", Path: "/plugins/echo.so", Fragment: []byte(`{"n":2}`), EgressProxy: newProxy}}); len(report.Loaded) != 1 {
		t.Fatalf("reconfigure report = %+v", report)
	}
	// Old proxy refuses new connections.
	if resp, err := dialViaProxy(t, oldProxy, upstream, "http://declared.invalid/a"); err == nil {
		_, _ = io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		t.Fatal("dial via superseded proxy succeeded, want refused")
	}
	// New proxy serves with the NEW scope only.
	if resp, err := dialViaProxy(t, newProxy, upstream, "http://declared.invalid/a"); err != nil {
		t.Fatal(err)
	} else {
		_, _ = io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if got := upstream.last.Header.Get("Cookie"); got != "" {
			t.Fatalf("narrowed scope still injects for declared.invalid: %q", got)
		}
	}
	if resp, err := dialViaProxy(t, newProxy, upstream, "http://other.invalid/a"); err != nil {
		t.Fatal(err)
	} else {
		_, _ = io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if got := upstream.last.Header.Get("Cookie"); got != "injected-cookie-value" {
			t.Fatalf("new scope Cookie = %q, want injected value", got)
		}
	}
}

// TestHostDetachedEgressClosed: detaching a plugin closes
// its egress proxy when no loaded tag references it.
func TestHostDetachedEgressClosed(t *testing.T) {
	loader, clients := fakeSetup("/plugins/echo.so")
	var logs []string
	h := newFakeHost(t, loader, &logs)
	defer h.Close()
	upstream := &recordingRoundTripper{body: "ok"}
	proxy, err := pluginhost.NewEgressProxy(upstream, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	clients["/plugins/echo.so"].OnCall = registerWithHosts(nil)
	if report := h.ApplyConfig(context.Background(), []pluginhost.Desired{{Tag: "echo", Type: "echo", Path: "/plugins/echo.so", EgressProxy: proxy}}); len(report.Loaded) != 1 {
		t.Fatalf("load report = %+v", report)
	}
	h.ApplyConfig(context.Background(), nil)
	if resp, err := dialViaProxy(t, proxy, upstream, "http://example.invalid/a"); err == nil {
		_, _ = io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		t.Fatal("dial via detached proxy succeeded, want refused")
	}
}

// TestHostSharedEgressNotClosedEarly: two tags sharing one
// proxy pointer keep it alive until the LAST tag detaches.
func TestHostSharedEgressNotClosedEarly(t *testing.T) {
	loader, clients := fakeSetup("/plugins/echo.so", "/plugins/v2.so")
	var logs []string
	h := newFakeHost(t, loader, &logs)
	defer h.Close()
	upstream := &recordingRoundTripper{body: "ok"}
	proxy, err := pluginhost.NewEgressProxy(upstream, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	for _, c := range clients {
		c.OnCall = registerWithHosts(nil)
	}
	desired := []pluginhost.Desired{
		{Tag: "echo", Type: "echo", Path: "/plugins/echo.so", EgressProxy: proxy},
		{Tag: "v2", Type: "echo", Path: "/plugins/v2.so", EgressProxy: proxy},
	}
	if report := h.ApplyConfig(context.Background(), desired); len(report.Loaded) != 2 {
		t.Fatalf("load report = %+v", report)
	}
	h.ApplyConfig(context.Background(), desired[:1])
	if resp, err := dialViaProxy(t, proxy, upstream, "http://example.invalid/a"); err != nil {
		t.Fatalf("shared proxy refused after one detach: %v", err)
	} else {
		_, _ = io.ReadAll(resp.Body)
		_ = resp.Body.Close()
	}
	h.ApplyConfig(context.Background(), nil)
	if resp, err := dialViaProxy(t, proxy, upstream, "http://example.invalid/a"); err == nil {
		_, _ = io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		t.Fatal("shared proxy served after last detach, want refused")
	}
}

// TestHostNilEgressKeepsExisting: a later Desired with nil
// EgressProxy keeps the existing proxy (documented
// semantics) and applies the new cookie scope to it.
func TestHostNilEgressKeepsExisting(t *testing.T) {
	loader, clients := fakeSetup("/plugins/echo.so")
	var logs []string
	h := newFakeHost(t, loader, &logs)
	defer h.Close()
	upstream := &recordingRoundTripper{body: "ok"}
	proxy, err := pluginhost.NewEgressProxy(upstream, nil, "injected-cookie-value")
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	fake := clients["/plugins/echo.so"]
	fake.OnCall = registerWithHosts([]string{"declared.invalid"})
	ctx := context.Background()
	if report := h.ApplyConfig(ctx, []pluginhost.Desired{{Tag: "echo", Type: "echo", Path: "/plugins/echo.so", Fragment: []byte(`{"n":1}`), EgressProxy: proxy}}); len(report.Loaded) != 1 {
		t.Fatalf("load report = %+v", report)
	}
	fake.OnCall = registerWithHosts([]string{"other.invalid"})
	if report := h.ApplyConfig(ctx, []pluginhost.Desired{{Tag: "echo", Type: "echo", Path: "/plugins/echo.so", Fragment: []byte(`{"n":2}`)}}); len(report.Loaded) != 1 {
		t.Fatalf("reconfigure report = %+v", report)
	}
	if resp, err := dialViaProxy(t, proxy, upstream, "http://other.invalid/a"); err != nil {
		t.Fatalf("existing proxy refused after nil-egress reconfigure: %v", err)
	} else {
		_, _ = io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if got := upstream.last.Header.Get("Cookie"); got != "injected-cookie-value" {
			t.Fatalf("new scope Cookie = %q, want injected value", got)
		}
	}
}

// hammerLoadedVsReconfigure runs the red-team B-R1 shape:
// Call goroutines + same-path reconfigure goroutines +
// Loaded()/Fused() polling, concurrently. Under -race any
// unsynchronised read/write of registration fields (or of
// the egress pointer) is reported. Call errors are
// tolerated (a reconfigure may legitimately be in flight);
// a deadlock or race is not.
func hammerLoadedVsReconfigure(t *testing.T, h *pluginhost.Host, desired func(n int) []pluginhost.Desired) {
	t.Helper()
	ctx := context.Background()
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				_, _ = h.Call(ctx, "echo", pluginabi.MethodProviderCall, []byte(`{"input":"ping"}`))
			}
		}()
	}
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := 0; ; j++ {
				select {
				case <-stop:
					return
				default:
				}
				_ = h.ApplyConfig(ctx, desired(n*1000+j))
			}
		}(i)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			_, _ = h.Loaded("echo")
			_, _ = h.Fused("echo")
		}
	}()
	time.Sleep(2 * time.Second)
	close(stop)
	wg.Wait()
}

// TestHostLoadedVsReconfigureRace is the fake-loader half
// of the B-R1 hammer: registration fields written by
// applyRegistration must not race Loaded() reads.
func TestHostLoadedVsReconfigureRace(t *testing.T) {
	loader, _ := fakeSetup("/plugins/echo.so")
	var logs []string
	h := newFakeHost(t, loader, &logs)
	defer h.Close()
	if report := h.ApplyConfig(context.Background(), []pluginhost.Desired{{Tag: "echo", Type: "echo", Path: "/plugins/echo.so", Fragment: []byte(`{"v":0}`)}}); len(report.Loaded) != 1 {
		t.Fatalf("load report = %+v", report)
	}
	hammerLoadedVsReconfigure(t, h, func(n int) []pluginhost.Desired {
		return []pluginhost.Desired{{Tag: "echo", Type: "echo", Path: "/plugins/echo.so", Fragment: []byte(`{"v":` + strconv.Itoa(n) + `}`)}}
	})
}

// TestHostEnvelopeErrorControlStripped: a plugin-chosen
// envelope error code/message must not carry control
// characters into the Go error (safety N1): a forged
// newline in the message must not create a second output
// line on the plugin check FAIL line.
func TestHostEnvelopeErrorControlStripped(t *testing.T) {
	loader, clients := fakeSetup("/plugins/echo.so")
	var logs []string
	h := newFakeHost(t, loader, &logs)
	defer h.Close()
	clients["/plugins/echo.so"].OnCall = func(ctx context.Context, method string, request []byte) ([]byte, error) {
		switch method {
		case pluginabi.MethodPluginRegister, pluginabi.MethodPluginReconfigure:
			return plugintest.RegisterResponse(1, "fake", "0.1.0", "plugintest", pluginabi.Capabilities{Provider: true}), nil
		default:
			return plugintest.ErrorResponse("bad\ncode\x1b[31m", "line1\nFORGED-LINE\x1b[31m"), nil
		}
	}
	if report := h.ApplyConfig(context.Background(), []pluginhost.Desired{{Tag: "echo", Type: "echo", Path: "/plugins/echo.so"}}); len(report.Loaded) != 1 {
		t.Fatalf("load report = %+v", report)
	}
	_, err := h.Call(context.Background(), "echo", pluginabi.MethodProviderCall, nil)
	if err == nil {
		t.Fatal("want envelope error, got nil")
	}
	if strings.ContainsAny(err.Error(), "\n\r\x1b\x00") {
		t.Fatalf("envelope error kept controls: %q", err.Error())
	}
	if !strings.Contains(err.Error(), "FORGED-LINE") {
		t.Fatalf("envelope error lost content: %q", err.Error())
	}
}

// TestHostSharedEgressScopeLastWriterWins (safety N2):
// cookie scope lives on the PROXY, not per tag. Two tags
// sharing one proxy with differing cookie_hosts get the
// last registration's scope applied to both tags' traffic
// (last-writer-wins, per-proxy scope). Documented in
// docs/plugins.md; pinned here so the semantics cannot
// drift silently into per-tag scoping.
func TestHostSharedEgressScopeLastWriterWins(t *testing.T) {
	loader, clients := fakeSetup("/plugins/a.so", "/plugins/b.so")
	var logs []string
	h := newFakeHost(t, loader, &logs)
	defer h.Close()
	upstream := &recordingRoundTripper{body: "ok"}
	proxy, err := pluginhost.NewEgressProxy(upstream, nil, "injected-cookie-value")
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	clients["/plugins/a.so"].OnCall = registerWithHosts([]string{"a.invalid"})
	clients["/plugins/b.so"].OnCall = registerWithHosts([]string{"b.invalid"})
	ctx := context.Background()
	desired := []pluginhost.Desired{
		{Tag: "a", Type: "a", Path: "/plugins/a.so", EgressProxy: proxy},
		{Tag: "b", Type: "b", Path: "/plugins/b.so", EgressProxy: proxy},
	}
	if report := h.ApplyConfig(ctx, desired); len(report.Loaded) != 2 {
		t.Fatalf("load report = %+v", report)
	}
	// Last writer (b) wins: b.invalid gets the cookie,
	// a.invalid (registered first) no longer does.
	if resp, err := dialViaProxy(t, proxy, upstream, "http://b.invalid/x"); err != nil {
		t.Fatal(err)
	} else {
		_, _ = io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if got := upstream.last.Header.Get("Cookie"); got != "injected-cookie-value" {
			t.Fatalf("b.invalid Cookie = %q, want injected value", got)
		}
	}
	if resp, err := dialViaProxy(t, proxy, upstream, "http://a.invalid/x"); err != nil {
		t.Fatal(err)
	} else {
		_, _ = io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if got := upstream.last.Header.Get("Cookie"); got != "" {
			t.Fatalf("a.invalid Cookie = %q, want none (last-writer scope)", got)
		}
	}
}
