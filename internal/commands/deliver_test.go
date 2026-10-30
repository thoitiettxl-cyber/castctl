// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package commands

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func TestAuthListAndExport(t *testing.T) {
	s := newFakeStack(t, nil, nil)

	// Text: the padded table names the profile.
	if code := s.run("auth", "list"); code != 0 {
		t.Fatalf("auth list: code=%d err=%q", code, s.errb.String())
	}
	if !strings.Contains(s.out.String(), "default") {
		t.Errorf("auth list text: %q", s.out.String())
	}
	// JSON: {active, profiles:[...]}.
	if code := s.run("auth", "list", "--json"); code != 0 {
		t.Fatalf("auth list --json: code=%d", code)
	}
	var list struct {
		Active   string `json:"active"`
		Profiles []struct {
			Name   string `json:"name"`
			Active bool   `json:"active"`
			Exists bool   `json:"exists"`
		} `json:"profiles"`
	}
	mustJSON(t, s.out.Bytes(), &list)
	if list.Active != "default" || len(list.Profiles) != 1 || !list.Profiles[0].Active || !list.Profiles[0].Exists {
		t.Errorf("auth list json=%+v", list)
	}
	// Export is guidance-only: exit 1, no writes, guidance text.
	if code := s.run("auth", "export"); code != 1 {
		t.Fatalf("auth export: code=%d, want 1", code)
	}
	if !strings.Contains(s.errb.String(), "cookie export") {
		t.Errorf("auth export guidance: %q", s.errb.String())
	}
}

func TestSessionStartOpStop(t *testing.T) {
	s := newFakeStack(t, routeHandler(map[string]string{
		"/session/start":  `{"session_id":"sess-1","title":"Hello"}`,
		"/session/rename": `{"ok":true}`,
		"/session/pin":    `{"ok":true}`,
		"/chat/cancel":    `{"ok":true}`,
	}), nil)
	if code := s.run("session-start", "--title", "Hello"); code != 0 {
		t.Fatalf("session-start: code=%d err=%q", code, s.errb.String())
	}
	if !strings.Contains(s.out.String(), "sess-1") {
		t.Errorf("session-start: %q", s.out.String())
	}
	if code := s.run("session-rename", "sess-1", "New title"); code != 0 {
		t.Fatalf("session-rename: code=%d err=%q", code, s.errb.String())
	}
	if code := s.run("session-pin", "sess-1"); code != 0 {
		t.Fatalf("session-pin: code=%d err=%q", code, s.errb.String())
	}
	// stop: no thread flag -> main cancel; with --thread -> side cancel.
	if code := s.run("stop"); code != 0 {
		t.Fatalf("stop: code=%d err=%q", code, s.errb.String())
	}
	if code := s.run("stop", "--thread", "t-9"); code != 0 {
		t.Fatalf("stop --thread: code=%d err=%q", code, s.errb.String())
	}
	// Verify the cancel bodies reached the server: main has no
	// session_id, side carries one.
	var cancelBodies []string
	for _, r := range s.server.Requests() {
		if strings.HasSuffix(r.Path, "/chat/cancel") {
			cancelBodies = append(cancelBodies, string(r.Body))
		}
	}
	if len(cancelBodies) != 2 || strings.Contains(cancelBodies[0], "session_id") || !strings.Contains(cancelBodies[1], "t-9") {
		t.Errorf("cancel bodies=%v", cancelBodies)
	}
}

func TestWake(t *testing.T) {
	wakeHTTP := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/hatch/vm/wake" {
			fmt.Fprint(w, `{"status":"waking"}`)
			return
		}
		http.NotFound(w, r)
	})
	s := newFakeStack(t, nil, wakeHTTP)
	if code := s.run("wake"); code != 0 {
		t.Fatalf("wake: code=%d err=%q", code, s.errb.String())
	}
	if !strings.Contains(s.out.String(), `"status": 200`) || !strings.Contains(s.out.String(), "waking") {
		t.Errorf("wake out: %q", s.out.String())
	}
	// Wake goes over HTTPS only: no gateway frames were exchanged.
	if len(s.server.Requests()) != 0 {
		t.Errorf("wake used the gateway: %+v", s.server.Requests())
	}
}
