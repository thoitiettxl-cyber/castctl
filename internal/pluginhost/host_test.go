// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package pluginhost_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/thoitiettxl-cyber/castctl/internal/pluginabi"
	"github.com/thoitiettxl-cyber/castctl/internal/pluginhost"
	"github.com/thoitiettxl-cyber/castctl/internal/plugintest"
)

func newFakeHost(t *testing.T, loader *plugintest.FakeLoader, logs *[]string) *pluginhost.Host {
	t.Helper()
	return pluginhost.New(pluginhost.Options{
		Loader: loader,
		Log: func(level, message string) {
			*logs = append(*logs, level+":"+message)
		},
	})
}

func fakeSetup(paths ...string) (*plugintest.FakeLoader, map[string]*plugintest.FakeClient) {
	loader := &plugintest.FakeLoader{Clients: map[string]*plugintest.FakeClient{}, OpenErr: map[string]error{}}
	clients := map[string]*plugintest.FakeClient{}
	for _, p := range paths {
		c := &plugintest.FakeClient{}
		loader.Clients[p] = c
		clients[p] = c
	}
	return loader, clients
}

func TestHostLoadAndCall(t *testing.T) {
	loader, clients := fakeSetup("/plugins/echo.so")
	var logs []string
	h := newFakeHost(t, loader, &logs)
	defer h.Close()
	report := h.ApplyConfig(context.Background(), []pluginhost.Desired{
		{Tag: "echo", Type: "echo", Path: "/plugins/echo.so", Fragment: []byte(`{"greeting":"hi"}`)},
	})
	if len(report.Skipped) != 0 {
		t.Fatalf("skipped = %+v", report.Skipped)
	}
	if len(report.Loaded) != 1 || report.Loaded[0] != "echo" {
		t.Fatalf("loaded = %v", report.Loaded)
	}
	loaded, ok := h.Loaded("echo")
	if !ok {
		t.Fatal("echo not loaded")
	}
	if loaded.Metadata.Name != "fake" || loaded.SchemaVersion != 1 || !loaded.Capabilities.Provider {
		t.Fatalf("loaded = %+v", loaded)
	}
	// The register request carries the fragment verbatim.
	req := clients["/plugins/echo.so"].LastRequest(pluginabi.MethodPluginRegister)
	var regReq pluginabi.RegisterRequest
	if err := json.Unmarshal(req, &regReq); err != nil {
		t.Fatal(err)
	}
	if string(regReq.ConfigJSON) != `{"greeting":"hi"}` {
		t.Fatalf("config_json = %s", regReq.ConfigJSON)
	}
	if regReq.SchemaVersion != 1 || regReq.Tag != "echo" || regReq.Type != "echo" {
		t.Fatalf("register request = %+v", regReq)
	}
	out, err := h.Call(context.Background(), "echo", pluginabi.MethodProviderCall, []byte(`{"input":"ping"}`))
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != `{"payload":"echo:ping"}` {
		t.Fatalf("provider call = %s", out)
	}
	if _, err := h.Call(context.Background(), "missing", pluginabi.MethodProviderCall, nil); err == nil || !strings.Contains(err.Error(), "not loaded") {
		t.Fatalf("missing plugin err = %v", err)
	}
}

func TestHostReconfigureSamePathAndRollback(t *testing.T) {
	loader, clients := fakeSetup("/plugins/echo.so")
	var logs []string
	h := newFakeHost(t, loader, &logs)
	defer h.Close()
	first := []pluginhost.Desired{{Tag: "echo", Type: "echo", Path: "/plugins/echo.so", Fragment: []byte(`{"v":1}`)}}
	h.ApplyConfig(context.Background(), first)
	fake := clients["/plugins/echo.so"]
	// Reconfigure with a new fragment.
	report := h.ApplyConfig(context.Background(), []pluginhost.Desired{{Tag: "echo", Type: "echo", Path: "/plugins/echo.so", Fragment: []byte(`{"v":2}`)}})
	if len(report.Skipped) != 0 {
		t.Fatalf("skipped = %+v", report.Skipped)
	}
	if got := fake.CallCount(pluginabi.MethodPluginReconfigure); got != 1 {
		t.Fatalf("reconfigure calls = %d, want 1", got)
	}
	if got := fake.CallCount(pluginabi.MethodPluginRegister); got != 1 {
		t.Fatalf("register calls = %d, want 1 (no re-register on same-path success)", got)
	}
	req := fake.LastRequest(pluginabi.MethodPluginReconfigure)
	var regReq pluginabi.RegisterRequest
	_ = json.Unmarshal(req, &regReq)
	if string(regReq.ConfigJSON) != `{"v":2}` {
		t.Fatalf("reconfigure fragment = %s", regReq.ConfigJSON)
	}
	// Now make reconfigure fail: rollback re-registers the old fragment.
	fake.OnCall = func(ctx context.Context, method string, request []byte) ([]byte, error) {
		if method == pluginabi.MethodPluginReconfigure {
			return plugintest.ErrorResponse("reconfigure_failed", "nope"), nil
		}
		if method == pluginabi.MethodPluginRegister {
			return plugintest.RegisterResponse(1, "fake", "0.1.0", "plugintest", pluginabi.Capabilities{Provider: true}), nil
		}
		return plugintest.OKResponse(json.RawMessage(`{}`)), nil
	}
	report = h.ApplyConfig(context.Background(), []pluginhost.Desired{{Tag: "echo", Type: "echo", Path: "/plugins/echo.so", Fragment: []byte(`{"v":3}`)}})
	if len(report.Skipped) != 1 || !strings.Contains(report.Skipped[0].Reason, "rolled back") {
		t.Fatalf("skipped = %+v, want rollback record", report.Skipped)
	}
	if _, ok := h.Loaded("echo"); !ok {
		t.Fatal("echo must stay loaded after rollback")
	}
	lastRegister := fake.LastRequest(pluginabi.MethodPluginRegister)
	_ = json.Unmarshal(lastRegister, &regReq)
	if string(regReq.ConfigJSON) != `{"v":2}` {
		t.Fatalf("rollback fragment = %s, want the previous (v2) fragment", regReq.ConfigJSON)
	}
}

func TestHostReplaceDifferentPathQuiesceAndRollback(t *testing.T) {
	loader, clients := fakeSetup("/plugins/v1.so", "/plugins/v2.so")
	var logs []string
	h := newFakeHost(t, loader, &logs)
	defer h.Close()
	h.ApplyConfig(context.Background(), []pluginhost.Desired{{Tag: "echo", Type: "echo", Path: "/plugins/v1.so", Fragment: []byte(`{}`)}})
	old := clients["/plugins/v1.so"]
	report := h.ApplyConfig(context.Background(), []pluginhost.Desired{{Tag: "echo", Type: "echo", Path: "/plugins/v2.so", Fragment: []byte(`{}`)}})
	if len(report.Skipped) != 0 {
		t.Fatalf("skipped = %+v", report.Skipped)
	}
	if got := old.CallCount(pluginabi.MethodPluginQuiesce); got != 1 {
		t.Fatalf("quiesce calls = %d, want 1", got)
	}
	if old.Shutdowns != 1 {
		t.Fatalf("old shutdowns = %d, want 1", old.Shutdowns)
	}
	if got := clients["/plugins/v2.so"].CallCount(pluginabi.MethodPluginRegister); got != 1 {
		t.Fatalf("new register calls = %d, want 1", got)
	}
	// Replacement failure: the new image fails to open, the old
	// image is re-registered and keeps running.
	loader.OpenErr["/plugins/v3.so"] = errors.New("dlopen failed")
	report = h.ApplyConfig(context.Background(), []pluginhost.Desired{{Tag: "echo", Type: "echo", Path: "/plugins/v3.so", Fragment: []byte(`{}`)}})
	if len(report.Skipped) != 1 || !strings.Contains(report.Skipped[0].Reason, "rolled back") {
		t.Fatalf("skipped = %+v, want rollback record", report.Skipped)
	}
	if _, ok := h.Loaded("echo"); !ok {
		t.Fatal("echo must stay loaded after failed replacement")
	}
	if got := clients["/plugins/v2.so"].CallCount(pluginabi.MethodPluginRegister); got != 2 {
		t.Fatalf("old register calls = %d, want 2 (initial + rollback)", got)
	}
}

func TestHostDetachUnselected(t *testing.T) {
	loader, clients := fakeSetup("/plugins/echo.so")
	var logs []string
	h := newFakeHost(t, loader, &logs)
	h.ApplyConfig(context.Background(), []pluginhost.Desired{{Tag: "echo", Type: "echo", Path: "/plugins/echo.so"}})
	h.ApplyConfig(context.Background(), nil)
	if _, ok := h.Loaded("echo"); ok {
		t.Fatal("echo must be detached")
	}
	if clients["/plugins/echo.so"].Shutdowns != 1 {
		t.Fatalf("shutdowns = %d, want 1", clients["/plugins/echo.so"].Shutdowns)
	}
	h.Close()
}

func TestHostBadPluginSkipped(t *testing.T) {
	loader, clients := fakeSetup("/plugins/bad.so")
	var logs []string
	h := newFakeHost(t, loader, &logs)
	defer h.Close()
	fake := clients["/plugins/bad.so"]
	fake.OnCall = func(ctx context.Context, method string, request []byte) ([]byte, error) {
		return plugintest.ErrorResponse("register_failed", "bad plugin"), nil
	}
	report := h.ApplyConfig(context.Background(), []pluginhost.Desired{{Tag: "bad", Type: "bad", Path: "/plugins/bad.so"}})
	if len(report.Skipped) != 1 {
		t.Fatalf("skipped = %+v, want 1", report.Skipped)
	}
	if _, ok := h.Loaded("bad"); ok {
		t.Fatal("bad plugin must not be loaded")
	}
	// Loader-level failure is also warn-and-skip.
	loader.OpenErr["/plugins/gone.so"] = errors.New("dlopen: file not found")
	report = h.ApplyConfig(context.Background(), []pluginhost.Desired{{Tag: "gone", Type: "gone", Path: "/plugins/gone.so"}})
	if len(report.Skipped) != 1 {
		t.Fatalf("skipped = %+v", report.Skipped)
	}
}

func TestHostVersionMismatch(t *testing.T) {
	cases := []struct {
		name   string
		schema uint32
		caps   pluginabi.Capabilities
		meta   pluginabi.Metadata
		wantOK bool
		want   string
	}{
		{"schema higher rejected", 2, pluginabi.Capabilities{Provider: true}, pluginabi.Metadata{Name: "x", Version: "1", Author: "a"}, false, "not supported"},
		{"schema missing becomes 1", 0, pluginabi.Capabilities{Provider: true}, pluginabi.Metadata{Name: "x", Version: "1", Author: "a"}, true, ""},
		{"no capabilities rejected", 1, pluginabi.Capabilities{}, pluginabi.Metadata{Name: "x", Version: "1", Author: "a"}, false, "at least one capability"},
		{"empty name rejected", 1, pluginabi.Capabilities{Provider: true}, pluginabi.Metadata{Name: "", Version: "1", Author: "a"}, false, "name is required"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			loader, clients := fakeSetup("/plugins/p.so")
			var logs []string
			h := newFakeHost(t, loader, &logs)
			defer h.Close()
			reg := pluginabi.Registration{SchemaVersion: tc.schema, Metadata: tc.meta, Capabilities: tc.caps}
			raw, _ := json.Marshal(reg)
			env, _ := json.Marshal(pluginabi.Envelope{OK: true, Result: raw})
			clients["/plugins/p.so"].OnCall = func(ctx context.Context, method string, request []byte) ([]byte, error) {
				if method == pluginabi.MethodPluginRegister {
					return env, nil
				}
				return plugintest.OKResponse(json.RawMessage(`{}`)), nil
			}
			report := h.ApplyConfig(context.Background(), []pluginhost.Desired{{Tag: "p", Type: "p", Path: "/plugins/p.so"}})
			loaded, ok := h.Loaded("p")
			if tc.wantOK {
				if !ok || len(report.Skipped) != 0 {
					t.Fatalf("loaded=%v skipped=%+v, want loaded", ok, report.Skipped)
				}
				if loaded.SchemaVersion != 1 {
					t.Fatalf("schema = %d, want 1", loaded.SchemaVersion)
				}
				return
			}
			if ok || len(report.Skipped) != 1 || !strings.Contains(report.Skipped[0].Reason, tc.want) {
				t.Fatalf("loaded=%v skipped=%+v, want skip containing %q", ok, report.Skipped, tc.want)
			}
		})
	}
}

func TestHostPanicIsolationAndFuse(t *testing.T) {
	loader, _ := fakeSetup("/plugins/echo.so", "/plugins/v2.so")
	var logs []string
	h := newFakeHost(t, loader, &logs)
	defer h.Close()
	h.ApplyConfig(context.Background(), []pluginhost.Desired{{Tag: "echo", Type: "echo", Path: "/plugins/echo.so"}})
	fake := loader.Clients["/plugins/echo.so"]
	fake.PanicMethods = map[string]any{pluginabi.MethodProviderCall: true}
	_, err := h.Call(context.Background(), "echo", pluginabi.MethodProviderCall, nil)
	if err == nil || !strings.Contains(err.Error(), "panic") {
		t.Fatalf("panic call err = %v, want panic error", err)
	}
	if reason, fused := h.Fused("echo"); !fused || !strings.Contains(reason, "panic") {
		t.Fatalf("fused=%v reason=%q, want fused with panic reason", fused, reason)
	}
	// Same-path ApplyConfig skips the fused plugin.
	report := h.ApplyConfig(context.Background(), []pluginhost.Desired{{Tag: "echo", Type: "echo", Path: "/plugins/echo.so"}})
	if len(report.Skipped) != 1 || !strings.Contains(report.Skipped[0].Reason, "fused") {
		t.Fatalf("skipped = %+v, want fused skip", report.Skipped)
	}
	// Replacement clears the fuse.
	fake.PanicMethods = nil
	report = h.ApplyConfig(context.Background(), []pluginhost.Desired{{Tag: "echo", Type: "echo", Path: "/plugins/v2.so"}})
	if len(report.Skipped) != 0 {
		t.Fatalf("skipped = %+v", report.Skipped)
	}
	if _, fused := h.Fused("echo"); fused {
		t.Fatal("fuse must clear after successful replacement")
	}
}

func TestHostTimeoutFusesAndReturns(t *testing.T) {
	loader, clients := fakeSetup("/plugins/echo.so")
	var logs []string
	h := newFakeHost(t, loader, &logs)
	defer h.Close()
	h.ApplyConfig(context.Background(), []pluginhost.Desired{{Tag: "echo", Type: "echo", Path: "/plugins/echo.so"}})
	clients["/plugins/echo.so"].BlockMethods = map[string]bool{pluginabi.MethodProviderCall: true}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := h.Call(ctx, "echo", pluginabi.MethodProviderCall, nil)
	elapsed := time.Since(start)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want DeadlineExceeded", err)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("call took %v, want prompt return on deadline", elapsed)
	}
	if _, fused := h.Fused("echo"); !fused {
		t.Fatal("hung plugin must be fused after timeout")
	}
}

func TestHostCallEnvelopeErrors(t *testing.T) {
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
		return plugintest.ErrorResponse("upstream_down", "upstream is down"), nil
	}
	_, err := h.Call(context.Background(), "echo", pluginabi.MethodProviderCall, nil)
	if err == nil || !strings.Contains(err.Error(), "upstream_down") || !strings.Contains(err.Error(), "upstream is down") {
		t.Fatalf("err = %v, want envelope code+message", err)
	}
	fake.OnCall = func(ctx context.Context, method string, request []byte) ([]byte, error) {
		if method == pluginabi.MethodPluginRegister {
			return plugintest.RegisterResponse(1, "fake", "0.1.0", "plugintest", pluginabi.Capabilities{Provider: true}), nil
		}
		return []byte(`not json`), nil
	}
	_, err = h.Call(context.Background(), "echo", pluginabi.MethodProviderCall, nil)
	if err == nil || !strings.Contains(err.Error(), "invalid envelope") {
		t.Fatalf("err = %v, want invalid envelope error", err)
	}
}

func TestHostRegisterRequestCarriesNoSecrets(t *testing.T) {
	loader, clients := fakeSetup("/plugins/echo.so")
	var logs []string
	h := newFakeHost(t, loader, &logs)
	defer h.Close()
	h.ApplyConfig(context.Background(), []pluginhost.Desired{
		{
			Tag: "echo", Type: "echo", Path: "/plugins/echo.so",
			Fragment: []byte(`{"note":"hello"}`),
			Identity: &pluginabi.Identity{OutboundTag: "direct", OutboundHash: "abc123"},
			Egress:   &pluginabi.Egress{ProxyURL: "http://127.0.0.1:0", Username: "u", Password: "ephemeral"},
		},
	})
	req := clients["/plugins/echo.so"].LastRequest(pluginabi.MethodPluginRegister)
	text := string(req)
	for _, forbidden := range []string{`"cookies"`, `"cookie_file"`, `"cookies_file"`, `"private_key"`, `"token"`, `"Cookie"`, `"WG"`, `"wireguard"`} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("register request contains forbidden key %s: %s", forbidden, text)
		}
	}
	if !strings.Contains(text, `"outbound_hash":"abc123"`) {
		t.Fatalf("register request missing stripped identity: %s", text)
	}
	if !strings.Contains(text, `"proxy_url":"http://127.0.0.1:0"`) {
		t.Fatalf("register request missing egress proxy: %s", text)
	}
}

func TestHostDuplicateDesiredTags(t *testing.T) {
	loader, _ := fakeSetup("/plugins/echo.so")
	var logs []string
	h := newFakeHost(t, loader, &logs)
	defer h.Close()
	report := h.ApplyConfig(context.Background(), []pluginhost.Desired{
		{Tag: "echo", Type: "echo", Path: "/plugins/echo.so"},
		{Tag: "echo", Type: "echo", Path: "/plugins/echo.so"},
	})
	if len(report.Skipped) != 1 || !strings.Contains(report.Skipped[0].Reason, "duplicate") {
		t.Fatalf("skipped = %+v", report.Skipped)
	}
	if len(report.Loaded) != 1 {
		t.Fatalf("loaded = %v", report.Loaded)
	}
}

func TestHostCommandProviderCommands(t *testing.T) {
	loader, clients := fakeSetup("/plugins/cmd.so")
	var logs []string
	h := newFakeHost(t, loader, &logs)
	defer h.Close()
	reg := pluginabi.Registration{
		SchemaVersion: 1,
		Metadata:      pluginabi.Metadata{Name: "cmd", Version: "1", Author: "a"},
		Capabilities:  pluginabi.Capabilities{CommandProvider: true},
		Commands:      []pluginabi.Command{{Name: "fake-cmd", Usage: "fake command"}},
	}
	raw, _ := json.Marshal(reg)
	env, _ := json.Marshal(pluginabi.Envelope{OK: true, Result: raw})
	clients["/plugins/cmd.so"].OnCall = func(ctx context.Context, method string, request []byte) ([]byte, error) {
		return env, nil
	}
	h.ApplyConfig(context.Background(), []pluginhost.Desired{{Tag: "cmd", Type: "cmd", Path: "/plugins/cmd.so"}})
	loaded, ok := h.Loaded("cmd")
	if !ok {
		t.Fatal("cmd not loaded")
	}
	if len(loaded.Commands) != 1 || loaded.Commands[0].Name != "fake-cmd" {
		t.Fatalf("commands = %+v", loaded.Commands)
	}
}
