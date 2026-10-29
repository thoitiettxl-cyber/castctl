// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package wait

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/thoitiettxl-cyber/muse-cli/go/internal/conn"
	"github.com/thoitiettxl-cyber/muse-cli/go/internal/gateway"
	"github.com/thoitiettxl-cyber/muse-cli/go/internal/gateway/gatewaytest"
	pb "github.com/thoitiettxl-cyber/muse-cli/go/internal/proto"
)

// TestGatewaySubscribeFeedsWaiter proves the Runner consumes a
// real (fake) gateway through SubscribeRaw: records captured in
// OnRecord feed the Waiter to a live done, with no parallel fake
// and no live work. Cookies are fake; all traffic is loopback.
func TestGatewaySubscribeFeedsWaiter(t *testing.T) {
	body := string(recordJSON(taskEv("running", "R", "R", 120, nil))) + "\n" +
		string(recordJSON(taskEv("completed", "R", "R", 180, nil))) + "\n"
	handler := gatewaytest.HandlerFunc(func(req *pb.ApplicationRequest, service pb.ServiceType) gatewaytest.Response {
		return gatewaytest.Response{Frames: []*pb.ServiceFrame{
			gatewaytest.ResponseFrame(0, 200, []byte(body), true),
		}}
	})
	server, err := gatewaytest.NewServer(handler)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	defer func() { _ = server.Close() }()
	auth := &gatewaytest.CannedAuth{VMID: "vm-test", AccessToken: "AT-FAKE", HatchToken: "HT-FAKE"}
	dialer := gatewaytest.NewFakeDialer(server, auth)
	cookiesFile := filepath.Join(t.TempDir(), "cookies.txt")
	if err := os.WriteFile(cookiesFile, []byte("hatch_sess=FAKE; datr=FAKE"), 0o600); err != nil {
		t.Fatalf("write cookies: %v", err)
	}
	connector := gateway.NewConnector(dialer, gateway.WithWebSocketSecure(false))
	gw, err := connector(context.Background(), conn.Config{CookiesFile: cookiesFile, VMID: "vm-test"})
	if err != nil {
		t.Fatalf("connector: %v", err)
	}
	dialed := false
	dial := func(ctx context.Context) (Subscriber, error) {
		dialed = true
		return gw, nil
	}
	hist := &queueHistory{resps: []historyResp{
		historyOK([]any{userEv(100)}),
		historyOK([]any{userEv(100), asst(150, "completed", "via gateway", nil)}),
	}}
	r, err := NewRunner(Config{Timeout: 60 * time.Second, Dial: dial, History: hist})
	if err != nil {
		t.Fatalf("NewRunner: %v", err)
	}
	res, err := r.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	_ = gw.Close()
	if !dialed {
		t.Error("Dial was never called")
	}
	if res.Kind != KindDone || res.ExitCode != 0 || res.FinalText != "via gateway" {
		t.Errorf("res = %+v", res)
	}
}

// TestEndedWithoutTerminalPredicate pins the real wait-level
// terminal predicate shape as a HELPER-LEVEL test only: it
// proves what counts as "terminal" over gathered records, not
// that the Runner uses EndedWithoutTerminal — the Runner never
// calls it (see SEAMS.md §6 G2). The predicate is stateful over
// the record order: a root-confirmed DONE/FAILED task.status
// counts only after a root-confirmed running was seen for the
// learned root (first root wins). A terminal before any running,
// a suspect string, and a foreign-root terminal do not count.
func TestEndedWithoutTerminalPredicate(t *testing.T) {
	terminal := func() func([]byte) bool {
		seenRunning := false
		var root string
		return func(rec []byte) bool {
			ev := decodeRecord(rec)
			if ev == nil {
				return false
			}
			info := TaskStatusInfo(ev, "")
			if info == nil || !info.HasStatus {
				return false
			}
			if info.Status == "running" && info.RootConfirmed {
				if !seenRunning {
					seenRunning = true
					root = info.RootAgentID
				}
				return false
			}
			if !seenRunning || !info.RootConfirmed || info.RootAgentID != root {
				return false
			}
			return IsDoneStatus(info.Status) || IsFailedStatus(info.Status)
		}
	}
	running := []byte(`{"event":"task.status","payload":{"status":"running","root_agent_id":"R","agent_id":"R"}}`)
	completed := []byte(`{"event":"task.status","payload":{"status":"completed","root_agent_id":"R","agent_id":"R"}}`)
	foreign := []byte(`{"event":"task.status","payload":{"status":"completed","root_agent_id":"R2","agent_id":"R2"}}`)
	suspect := []byte(`{"event":"task.status","payload":{"status":"idle","root_agent_id":"R","agent_id":"R"}}`)
	if !gateway.EndedWithoutTerminal([][]byte{running}, terminal()) {
		t.Error("running-only records must end without terminal")
	}
	if gateway.EndedWithoutTerminal([][]byte{running, completed}, terminal()) {
		t.Error("DONE after running must count as a terminal")
	}
	if !gateway.EndedWithoutTerminal([][]byte{completed}, terminal()) {
		t.Error("DONE before any running must not count as a terminal")
	}
	if !gateway.EndedWithoutTerminal([][]byte{running, suspect}, terminal()) {
		t.Error("suspect strings must not count as terminal")
	}
	if !gateway.EndedWithoutTerminal([][]byte{running, foreign}, terminal()) {
		t.Error("foreign-root DONE must not count as a terminal")
	}
	if !gateway.EndedWithoutTerminal([][]byte{running}, nil) {
		t.Error("nil predicate must report no terminal")
	}
}
