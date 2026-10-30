// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package commands

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/thoitiettxl-cyber/castctl/internal/conn"
	"github.com/thoitiettxl-cyber/castctl/internal/profile"
)

// deliverFakeGateway scripts chat.history + chat.stream for
// deliverSend: the first history call is the pre-send baseline
// read (baselineEvents, or baselineErr); later calls are ack
// polls (pollEvents). It embeds conn.Gateway so only the two
// methods deliverSend uses need bodies.
type deliverFakeGateway struct {
	conn.Gateway
	baselineErr    error
	baselineEvents []any
	pollEvents     []any
	historyCalls   int
	openStreams    int
}

func (f *deliverFakeGateway) CallJSON(ctx context.Context, method string, opts conn.RequestOptions) (any, error) {
	if method != "chat.history" {
		return nil, errors.New("unexpected method " + method)
	}
	f.historyCalls++
	if f.historyCalls == 1 {
		if f.baselineErr != nil {
			return nil, f.baselineErr
		}
		return map[string]any{"chat_events": f.baselineEvents}, nil
	}
	return map[string]any{"chat_events": f.pollEvents}, nil
}

func (f *deliverFakeGateway) OpenStream(ctx context.Context, method string, opts conn.OpenStreamOptions) (int64, error) {
	f.openStreams++
	return 7, nil
}

func userHistoryEvent(seq int64, text string) map[string]any {
	return map[string]any{
		"event_name": "message.user",
		"seq":        seq,
		"payload":    map[string]any{"display_text": text},
	}
}

// D13: a failed baseline read must fail the send BEFORE the
// message is sent. Falling back to baseline 0 lets the ack poll
// match an OLDER turn's identical text and returns its seq as
// this turn's boundary — the reply-reuse bug (a previous turn's
// replies delivered as this turn's).
func TestDeliverSendBaselineReadFailureFailsBeforeSend(t *testing.T) {
	gw := &deliverFakeGateway{
		baselineErr: &conn.GatewayError{Status: 502, Payload: "bad gateway"},
		pollEvents:  []any{userHistoryEvent(5, "hello")},
	}
	prof := &profile.Profile{NodeID: "node-1"}
	_, _, err := deliverSend(context.Background(), gw, prof, "hello", "", 5*time.Second)
	if err == nil {
		t.Fatal("baseline read failure must fail the send, got nil error")
	}
	var gwErr *conn.GatewayError
	if !errors.As(err, &gwErr) {
		t.Errorf("err = %v, want the GatewayError unwrapped", err)
	}
	if gw.openStreams != 0 {
		t.Errorf("openStreams = %d, want 0 (message must never be sent on a failed baseline read)", gw.openStreams)
	}
}

// D13 positive case: with a proved baseline, the ack is the
// just-sent message's own seq — the first user event above the
// baseline — never an older one.
func TestDeliverSendProvedBaselineAcksOwnMessage(t *testing.T) {
	gw := &deliverFakeGateway{
		baselineEvents: []any{userHistoryEvent(9, "earlier")},
		pollEvents:     []any{userHistoryEvent(9, "earlier"), userHistoryEvent(10, "hello")},
	}
	prof := &profile.Profile{NodeID: "node-1"}
	userSeq, streamID, err := deliverSend(context.Background(), gw, prof, "hello", "", 5*time.Second)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if userSeq == nil || *userSeq != 10 {
		t.Fatalf("userSeq = %v, want 10 (the just-sent message)", userSeq)
	}
	if streamID != 7 || gw.openStreams != 1 {
		t.Errorf("streamID = %d openStreams = %d, want 7/1", streamID, gw.openStreams)
	}
	if gw.historyCalls < 2 {
		t.Errorf("historyCalls = %d, want baseline + at least one poll", gw.historyCalls)
	}
}
