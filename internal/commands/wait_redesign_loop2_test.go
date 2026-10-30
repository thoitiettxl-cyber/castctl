// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package commands

// Loop-2 regression tests for the wait redesign (overnight item 3):
// the F10 two-window baseline for deliverSend (RT13a/b/c) and the
// safety D-1 note surfacing in printWaitTail. Written RED against
// the loop-1 head before the fix.

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/thoitiettxl-cyber/castctl/internal/conn"
	"github.com/thoitiettxl-cyber/castctl/internal/profile"
	"github.com/thoitiettxl-cyber/castctl/internal/wait"
)

// confirmingFakeGateway scripts chat.history by LIMIT, so the
// baseline reads and the ack polls can be told apart: limit=1 is
// the first baseline read, limit=20 the confirming read, any
// other limit an ack poll. It embeds conn.Gateway so only the
// two methods deliverSend uses need bodies.
type confirmingFakeGateway struct {
	conn.Gateway
	baselineErr    error
	baselineEvents []any
	confirmEvents  []any
	pollEvents     []any
	historyCalls   int
	limitsSeen     []int
	openStreams    int
}

func (f *confirmingFakeGateway) CallJSON(ctx context.Context, method string, opts conn.RequestOptions) (any, error) {
	if method != "chat.history" {
		return nil, errors.New("unexpected method " + method)
	}
	f.historyCalls++
	limit := 0
	if body, ok := opts.Body.(map[string]any); ok {
		limit, _ = body["limit"].(int)
	}
	f.limitsSeen = append(f.limitsSeen, limit)
	if limit == 1 {
		if f.baselineErr != nil {
			return nil, f.baselineErr
		}
		return map[string]any{"chat_events": f.baselineEvents}, nil
	}
	if limit == 20 {
		return map[string]any{"chat_events": f.confirmEvents}, nil
	}
	return map[string]any{"chat_events": f.pollEvents}, nil
}

func (f *confirmingFakeGateway) OpenStream(ctx context.Context, method string, opts conn.OpenStreamOptions) (int64, error) {
	f.openStreams++
	return 7, nil
}

// F10 / RT13a: a stale limit=1 baseline (one old event) must be
// corrected by the confirming wider read: the ack is the
// just-sent message's seq (9), never the older identical text
// (5) the narrow window missed.
func TestLoop2ConfirmingBaselineReadPreventsStaleAck(t *testing.T) {
	gw := &confirmingFakeGateway{
		baselineEvents: []any{userHistoryEvent(3, "hello")},
		confirmEvents:  []any{userHistoryEvent(3, "hello"), userHistoryEvent(5, "hello")},
		pollEvents:     []any{userHistoryEvent(5, "hello"), userHistoryEvent(9, "hello")},
	}
	prof := &profile.Profile{NodeID: "node-1"}
	userSeq, _, err := deliverSend(context.Background(), gw, prof, "hello", "", 5*time.Second)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if userSeq == nil || *userSeq != 9 {
		t.Fatalf("userSeq = %v, want 9 (the just-sent message; the stale ack 5 must not survive)", userSeq)
	}
}

// F10 / RT13b: a successful-but-empty limit=1 read must not
// settle the baseline at 0 when the confirming wider read sees
// an older identical message: the ack is the just-sent seq (9).
func TestLoop2EmptyFirstWindowConfirmedByWiderWindow(t *testing.T) {
	gw := &confirmingFakeGateway{
		baselineEvents: []any{},
		confirmEvents:  []any{userHistoryEvent(5, "hello")},
		pollEvents:     []any{userHistoryEvent(5, "hello"), userHistoryEvent(9, "hello")},
	}
	prof := &profile.Profile{NodeID: "node-1"}
	userSeq, _, err := deliverSend(context.Background(), gw, prof, "hello", "", 5*time.Second)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if userSeq == nil || *userSeq != 9 {
		t.Fatalf("userSeq = %v, want 9 (the confirming read must lift the baseline above the older message)", userSeq)
	}
}

// F10 / RT13c (deliverSend level): an empty sent text must
// never ack: the poll's user event is not this (empty) message.
func TestLoop2EmptySentTextNeverAcks(t *testing.T) {
	gw := &confirmingFakeGateway{
		baselineEvents: []any{userHistoryEvent(3, "earlier")},
		confirmEvents:  []any{userHistoryEvent(3, "earlier")},
		pollEvents:     []any{userHistoryEvent(5, "hello")},
	}
	prof := &profile.Profile{NodeID: "node-1"}
	userSeq, _, err := deliverSend(context.Background(), gw, prof, "", "", 5*time.Second)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if userSeq != nil {
		t.Fatalf("userSeq = %v, want nil (an empty needle must not ack)", userSeq)
	}
}

// D-1: printWaitTail must surface Result.Note in text mode and
// in the REPL tail (both call it). The note is a fixed template
// plus a count, never peer text, so the structural stderr rule
// is preserved.
func TestLoop2PrintWaitTailSurfacesNote(t *testing.T) {
	note := "history window exhausted at 1000 events; older replies may be missed; run `castctl wait` again"
	res := &wait.Result{Kind: wait.KindDone, Outcome: "done", Status: "completed", Note: note}
	for _, summary := range []bool{true, false} {
		var out, errb bytes.Buffer
		printWaitTail(&out, &errb, res, summary)
		if !strings.Contains(errb.String(), note) {
			t.Errorf("summary=%v: stderr = %q, want the result note surfaced", summary, errb.String())
		}
	}
	// No note: nothing extra is printed.
	res2 := &wait.Result{Kind: wait.KindDone, Outcome: "done", Status: "completed"}
	var out, errb bytes.Buffer
	printWaitTail(&out, &errb, res2, true)
	if strings.Contains(errb.String(), "note:") {
		t.Errorf("stderr = %q, want no note line without a note", errb.String())
	}
}

// D-1 (send JSON copy): the wait result's note must reach the
// send result, except that the timeout note keeps precedence.
func TestLoop2SendWaitJSONCarriesNote(t *testing.T) {
	res := &wait.Result{Kind: wait.KindDone, Outcome: "done", Status: "completed", Note: "history window exhausted at 1000 events; older replies may be missed; run `castctl wait` again", Replies: []wait.Reply{{Seq: 11, Text: "hi"}}}
	waitJSON := toWaitResultJSON(res, false)
	got := buildSendWaitJSON(sendBaseJSON{Sent: true, Delivered: true, Stream: 7}, waitJSON, res, 90, 10)
	if got.Note != res.Note {
		t.Errorf("send note = %q, want %q (the wait note must be copied)", got.Note, res.Note)
	}
	timeoutRes := &wait.Result{Kind: wait.KindTimeout, Outcome: "timeout", Status: "completed", Note: res.Note}
	timeoutJSON := toWaitResultJSON(timeoutRes, false)
	gotTimeout := buildSendWaitJSON(sendBaseJSON{Sent: true, Delivered: true, Stream: 7}, timeoutJSON, timeoutRes, 90, 10)
	wantTimeout := "turn not finished within 90s; run `castctl wait --after-seq 10`"
	if gotTimeout.Note != wantTimeout {
		t.Errorf("timeout send note = %q, want %q (the timeout note keeps precedence)", gotTimeout.Note, wantTimeout)
	}
}
