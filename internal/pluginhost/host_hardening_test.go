// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package pluginhost_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
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

// TestHostFuseIsPerPath: same-path reconfigure stays fused;
// a different path clears the fuse (already covered by
// TestHostPanicIsolationAndFuse for replacement; here the
// fused tag has NO loaded entry after rollback-failure
// deletion, and a same-path fresh load must still skip).
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
