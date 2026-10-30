// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package deliver_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/thoitiettxl-cyber/castctl/internal/conn"
	"github.com/thoitiettxl-cyber/castctl/internal/deliver"
)

// fakeGateway records the method and options of each CallJSON and
// returns a canned reply. It is shared by the session and stop
// tests in this package.
type fakeGateway struct {
	calls  []fakeCall
	reply  any
	err    error
	called int
}

type fakeCall struct {
	method string
	opts   conn.RequestOptions
}

func (f *fakeGateway) CallJSON(_ context.Context, method string, opts conn.RequestOptions) (any, error) {
	f.calls = append(f.calls, fakeCall{method: method, opts: opts})
	f.called++
	if f.err != nil {
		return nil, f.err
	}
	return f.reply, nil
}

func bodyJSON(t *testing.T, opts conn.RequestOptions) string {
	t.Helper()
	raw, err := json.Marshal(opts.Body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	return string(raw)
}

func TestSessionStart(t *testing.T) {
	t.Run("without title", func(t *testing.T) {
		gw := &fakeGateway{reply: map[string]any{"session_id": "s1"}}
		got, err := deliver.SessionStart(context.Background(), gw, "")
		if err != nil {
			t.Fatalf("SessionStart: %v", err)
		}
		if len(gw.calls) != 1 || gw.calls[0].method != "session.start" {
			t.Fatalf("calls = %+v, want one session.start call", gw.calls)
		}
		want := `{"method":"/api/session/start","params":{"origin":"fresh","lifecycle":"persistent"}}`
		if gotBody := bodyJSON(t, gw.calls[0].opts); gotBody != want {
			t.Errorf("body = %s, want %s", gotBody, want)
		}
		if m, ok := got.(map[string]any); !ok || m["session_id"] != "s1" {
			t.Errorf("reply = %#v, want the server reply verbatim", got)
		}
	})
	t.Run("with title", func(t *testing.T) {
		gw := &fakeGateway{reply: map[string]any{"session_id": "s2"}}
		if _, err := deliver.SessionStart(context.Background(), gw, "My chat"); err != nil {
			t.Fatalf("SessionStart: %v", err)
		}
		want := `{"method":"/api/session/start","params":{"origin":"fresh","lifecycle":"persistent","title":"My chat"}}`
		if gotBody := bodyJSON(t, gw.calls[0].opts); gotBody != want {
			t.Errorf("body = %s, want %s", gotBody, want)
		}
	})
	t.Run("nil gateway", func(t *testing.T) {
		if _, err := deliver.SessionStart(context.Background(), nil, ""); err == nil {
			t.Error("SessionStart(nil gateway): got nil error")
		}
	})
}

func TestSessionOp(t *testing.T) {
	tests := []struct {
		name   string
		kind   deliver.SessionOpKind
		method string
		body   string
	}{
		{name: "rename", kind: deliver.SessionOpRename, method: "session.rename", body: `{"session_id":"s1","title":"New name"}`},
		{name: "pin", kind: deliver.SessionOpPin, method: "session.pin", body: `{"method":"/api/session/pin","session_id":"s1"}`},
		{name: "unpin", kind: deliver.SessionOpUnpin, method: "session.unpin", body: `{"method":"/api/session/unpin","session_id":"s1"}`},
		{name: "archive", kind: deliver.SessionOpArchive, method: "session.archive", body: `{"method":"/api/session/archive","session_id":"s1"}`},
		{name: "unarchive", kind: deliver.SessionOpUnarchive, method: "session.unarchive", body: `{"method":"/api/session/unarchive","session_id":"s1"}`},
		{name: "delete", kind: deliver.SessionOpDelete, method: "session.delete", body: `{"method":"/api/session/delete","session_id":"s1"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gw := &fakeGateway{reply: map[string]any{"ok": true}}
			got, err := deliver.SessionOp(context.Background(), gw, tt.kind, "s1", "New name")
			if err != nil {
				t.Fatalf("SessionOp: %v", err)
			}
			if len(gw.calls) != 1 || gw.calls[0].method != tt.method {
				t.Fatalf("calls = %+v, want one %s call", gw.calls, tt.method)
			}
			if gotBody := bodyJSON(t, gw.calls[0].opts); gotBody != tt.body {
				t.Errorf("body = %s, want %s", gotBody, tt.body)
			}
			if m, ok := got.(map[string]any); !ok || m["ok"] != true {
				t.Errorf("reply = %#v, want the server reply verbatim", got)
			}
		})
	}
	t.Run("unknown kind", func(t *testing.T) {
		gw := &fakeGateway{}
		if _, err := deliver.SessionOp(context.Background(), gw, "explode", "s1", ""); err == nil {
			t.Error("SessionOp(unknown kind): got nil error")
		}
		if gw.called != 0 {
			t.Errorf("unknown kind made %d gateway calls, want 0", gw.called)
		}
	})
	t.Run("nil gateway", func(t *testing.T) {
		if _, err := deliver.SessionOp(context.Background(), nil, deliver.SessionOpPin, "s1", ""); err == nil {
			t.Error("SessionOp(nil gateway): got nil error")
		}
	})
}
