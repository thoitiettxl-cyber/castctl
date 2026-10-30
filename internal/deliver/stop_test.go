// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package deliver_test

import (
	"context"
	"testing"

	"github.com/thoitiettxl-cyber/muse-cli/go/internal/deliver"
)

func TestStopTurn(t *testing.T) {
	t.Run("main chat", func(t *testing.T) {
		gw := &fakeGateway{reply: map[string]any{"cancelled": true}}
		got, err := deliver.StopTurn(context.Background(), gw, "")
		if err != nil {
			t.Fatalf("StopTurn: %v", err)
		}
		if len(gw.calls) != 1 || gw.calls[0].method != "chat.cancel" {
			t.Fatalf("calls = %+v, want one chat.cancel call", gw.calls)
		}
		if gotBody := bodyJSON(t, gw.calls[0].opts); gotBody != "{}" {
			t.Errorf("body = %s, want {}", gotBody)
		}
		if m, ok := got.(map[string]any); !ok || m["cancelled"] != true {
			t.Errorf("reply = %#v, want the server reply verbatim", got)
		}
	})
	t.Run("side chat", func(t *testing.T) {
		gw := &fakeGateway{reply: map[string]any{"cancelled": true}}
		if _, err := deliver.StopTurn(context.Background(), gw, "thread-1"); err != nil {
			t.Fatalf("StopTurn: %v", err)
		}
		want := `{"session_id":"thread-1"}`
		if gotBody := bodyJSON(t, gw.calls[0].opts); gotBody != want {
			t.Errorf("body = %s, want %s", gotBody, want)
		}
	})
	t.Run("nil gateway", func(t *testing.T) {
		if _, err := deliver.StopTurn(context.Background(), nil, ""); err == nil {
			t.Error("StopTurn(nil gateway): got nil error")
		}
	})
}
