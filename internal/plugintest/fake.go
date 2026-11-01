// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

// Package plugintest holds the plugin contract-test helpers:
// in-process fake clients/loaders implementing pluginhost's
// Client/Loader interfaces, envelope builders, and a builder
// that compiles the fake c-shared plugin fixture (testdata) for
// real-loader tests. The fakes never touch the filesystem, the
// network, or secrets; the fixture builder shells out to `go
// build` only under tests that opt into it.
package plugintest

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/thoitiettxl-cyber/castctl/internal/pluginabi"
	"github.com/thoitiettxl-cyber/castctl/internal/pluginhost"
)

// RegisterResponse builds the envelope bytes a plugin returns
// from plugin.register for the given registration fields.
func RegisterResponse(schema uint32, name, version, author string, caps pluginabi.Capabilities) []byte {
	reg := pluginabi.Registration{
		SchemaVersion: schema,
		Metadata:      pluginabi.Metadata{Name: name, Version: version, Author: author, GitHubRepository: "https://github.com/thoitiettxl-cyber/castctl"},
		Capabilities:  caps,
	}
	raw, _ := json.Marshal(reg)
	env, _ := json.Marshal(pluginabi.Envelope{OK: true, Result: raw})
	return env
}

// OKResponse builds an ok envelope carrying result.
func OKResponse(result json.RawMessage) []byte {
	env, _ := json.Marshal(pluginabi.Envelope{OK: true, Result: result})
	return env
}

// ErrorResponse builds a failed envelope with code/message.
func ErrorResponse(code, message string) []byte {
	env, _ := json.Marshal(pluginabi.NewErrorEnvelope(code, message))
	return env
}

// CallRecord is one recorded fake-client call.
type CallRecord struct {
	Method  string
	Request []byte
}

// FakeClient is an in-process pluginhost.Client for contract
// tests. Behaviour is driven by OnCall; when OnCall is nil the
// client answers register/reconfigure with a valid Provider
// registration, quiesce with ok, and provider.call by echoing
// the request's "input" field as {"payload":"echo:<input>"}.
type FakeClient struct {
	mu           sync.Mutex
	Calls        []CallRecord
	Shutdowns    int
	OnCall       func(ctx context.Context, method string, request []byte) ([]byte, error)
	PanicMethods map[string]any
	// BlockMethods lists methods whose Call waits for ctx
	// cancellation before returning (timeout tests).
	BlockMethods map[string]bool
}

var _ pluginhost.Client = (*FakeClient)(nil)

// Call records the call and dispatches to the configured
// behaviour.
func (f *FakeClient) Call(ctx context.Context, method string, request []byte) ([]byte, error) {
	f.mu.Lock()
	f.Calls = append(f.Calls, CallRecord{Method: method, Request: append([]byte(nil), request...)})
	onCall := f.OnCall
	panicMethods := f.PanicMethods
	block := f.BlockMethods[method]
	f.mu.Unlock()
	if _, ok := panicMethods[method]; ok {
		panic("fake plugin panic")
	}
	if block {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if onCall != nil {
		return onCall(ctx, method, request)
	}
	switch method {
	case pluginabi.MethodPluginRegister, pluginabi.MethodPluginReconfigure:
		return RegisterResponse(1, "fake", "0.1.0", "plugintest", pluginabi.Capabilities{Provider: true}), nil
	case pluginabi.MethodPluginQuiesce:
		return OKResponse(json.RawMessage(`{}`)), nil
	case pluginabi.MethodProviderCall:
		var req struct {
			Input string `json:"input"`
		}
		_ = json.Unmarshal(request, &req)
		return OKResponse(json.RawMessage(`{"payload":"echo:` + req.Input + `"}`)), nil
	default:
		return ErrorResponse("unknown_method", "unknown method: "+method), nil
	}
}

// Shutdown records a detach.
func (f *FakeClient) Shutdown() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Shutdowns++
}

// CallCount returns how many calls named method were recorded.
func (f *FakeClient) CallCount(method string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.Calls {
		if c.Method == method {
			n++
		}
	}
	return n
}

// LastRequest returns the most recent request for method, or
// nil.
func (f *FakeClient) LastRequest(method string) []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := len(f.Calls) - 1; i >= 0; i-- {
		if f.Calls[i].Method == method {
			return append([]byte(nil), f.Calls[i].Request...)
		}
	}
	return nil
}

// FakeLoader is a pluginhost.Loader serving FakeClients keyed by
// binary path. Open counts per path; an unregistered path is a
// load error.
type FakeLoader struct {
	mu       sync.Mutex
	Clients  map[string]*FakeClient
	OpenErr  map[string]error
	Opens    []string
	OpenFunc func(file pluginhost.File, host *pluginhost.Host) (pluginhost.Client, error)
}

var _ pluginhost.Loader = (*FakeLoader)(nil)

// Open returns the fake client for file.Path.
func (l *FakeLoader) Open(file pluginhost.File, host *pluginhost.Host) (pluginhost.Client, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.Opens = append(l.Opens, file.Path)
	if l.OpenFunc != nil {
		return l.OpenFunc(file, host)
	}
	if err, ok := l.OpenErr[file.Path]; ok && err != nil {
		return nil, err
	}
	c, ok := l.Clients[file.Path]
	if !ok {
		return nil, fmt.Errorf("no fake plugin for path %s", file.Path)
	}
	return c, nil
}

// OpenCount returns how many times path was opened.
func (l *FakeLoader) OpenCount(path string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, p := range l.Opens {
		if p == path {
			n++
		}
	}
	return n
}
