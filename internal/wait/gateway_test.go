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

// TestEndedWithoutTerminalPredicate proves the S3 predicate
// shape the Runner relies on: EndedWithoutTerminal over records
// gathered from a clean SubscribeRaw end, with the wait-level
// terminal predicate (root task.status DONE after running),
// not the S3 test's substring probe.
func TestEndedWithoutTerminalPredicate(t *testing.T) {
	terminal := func(rec []byte) bool {
		ev := parseRecord(rec)
		if ev == nil {
			return false
		}
		info := TaskStatusInfo(ev, "")
		return info != nil && info.HasStatus && (Done[info.Status] || Failed[info.Status])
	}
	plain := [][]byte{[]byte(`{"event":"task.status","payload":{"status":"running","root_agent_id":"R","agent_id":"R"}}`)}
	if !gateway.EndedWithoutTerminal(plain, terminal) {
		t.Error("running-only records must end without terminal")
	}
	withTerminal := append(append([][]byte{}, plain...),
		[]byte(`{"event":"task.status","payload":{"status":"completed","root_agent_id":"R","agent_id":"R"}}`))
	if gateway.EndedWithoutTerminal(withTerminal, terminal) {
		t.Error("records with a DONE task.status must have a terminal")
	}
	// A suspect string is not a terminal for this predicate.
	suspect := append(append([][]byte{}, plain...),
		[]byte(`{"event":"task.status","payload":{"status":"idle","root_agent_id":"R","agent_id":"R"}}`))
	if !gateway.EndedWithoutTerminal(suspect, terminal) {
		t.Error("suspect strings must not count as terminal")
	}
	if !gateway.EndedWithoutTerminal(plain, nil) {
		t.Error("nil predicate must report no terminal")
	}
}
