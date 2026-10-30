// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package wait

// Loop-3 regression tests for the wait redesign (overnight item 3).
// Each test pins the loop-2 red-team defect H1: a settle proof
// reply missing from a NON-EMPTY final read must be restored
// into it, deduped and within-turn filtered, with the restore
// note — never silently dropped.

import (
	"testing"
	"testing/synctest"
	"time"
)

// H1: settle proof window [user 10, subagent-shaped reply 11,
// root reply 12]; final read [user 10, subagent-shaped reply 11]
// only. The proven root reply 12 must be restored into the
// non-empty final read, with the restore note, and FinalText
// must be the root reply — not the subagent-shaped one the F2
// gate says must not count as proof on its own.
func TestLoop3ProofReplyRestoredIntoNonEmptyFinalRead(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sub := &fakeSubscriber{
			block: true,
			loopScript: [][]byte{
				recordJSON(taskEv("running", "R", "R", 120, nil)),
				recordJSON(taskEv("completed", "R", "R", 180, 2)),
			},
		}
		proof := historyOK([]any{
			userEv(10),
			asst(11, "completed", "subagent text", map[string]any{
				"agent_id": "S", "root_agent_id": "R",
			}),
			asst(12, "completed", "root reply", map[string]any{
				"agent_id": "R", "root_agent_id": "R",
			}),
		})
		hist := &queueHistory{resps: []historyResp{
			historyOK([]any{userEv(10)}),
			proof,
			historyOK([]any{
				userEv(10),
				asst(11, "completed", "subagent text", map[string]any{
					"agent_id": "S", "root_agent_id": "R",
				}),
			}),
		}}
		res := runRunner(t, Config{
			Timeout:      600 * time.Second,
			RecheckAfter: 20 * time.Second,
			CheckEvery:   60 * time.Second,
			Dial:         sub.dial,
			History:      hist,
		})
		if res.Kind != KindDone || res.ExitCode != 0 {
			t.Errorf("res = %+v, want KindDone/0", res)
		}
		if len(res.Replies) != 2 || res.Replies[0].Seq != 11 || res.Replies[1].Seq != 12 || res.FinalText != "root reply" {
			t.Errorf("res = %+v, want replies [11, 12] with FinalText the root reply", res)
		}
		wantNote := "final read missed the settle proof reply; reporting the proof reply"
		if res.Note != wantNote {
			t.Errorf("note = %q, want %q", res.Note, wantNote)
		}
	})
}

// H1 + note precedence (red-team nit 1): when the final read
// both drops the proof reply and holds a follow-up reply, the
// proof reply is restored, the follow-up reply is excluded,
// and the restore note wins over the exclusion note (the
// exclusion is visible in the reply list itself).
func TestLoop3RestoreWinsOverFollowUpExclusionNote(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sub := &fakeSubscriber{
			block: true,
			loopScript: [][]byte{
				recordJSON(taskEv("running", "R", "R", 120, nil)),
				recordJSON(taskEv("completed", "R", "R", 180, 2)),
			},
		}
		proof := historyOK([]any{
			userEv(10),
			asst(11, "completed", "subagent text", map[string]any{
				"agent_id": "S", "root_agent_id": "R",
			}),
			asst(12, "completed", "root reply", map[string]any{
				"agent_id": "R", "root_agent_id": "R",
			}),
		})
		hist := &queueHistory{resps: []historyResp{
			historyOK([]any{userEv(10)}),
			proof,
			historyOK([]any{
				userEv(10),
				asst(11, "completed", "subagent text", map[string]any{
					"agent_id": "S", "root_agent_id": "R",
				}),
				userEv(20),
				asst(21, "completed", "FOLLOWUP", nil),
			}),
		}}
		res := runRunner(t, Config{
			Timeout:      600 * time.Second,
			RecheckAfter: 20 * time.Second,
			CheckEvery:   60 * time.Second,
			Dial:         sub.dial,
			History:      hist,
		})
		if res.Kind != KindDone || res.ExitCode != 0 {
			t.Errorf("res = %+v, want KindDone/0", res)
		}
		if len(res.Replies) != 2 || res.Replies[0].Seq != 11 || res.Replies[1].Seq != 12 || res.FinalText != "root reply" {
			t.Errorf("res = %+v, want replies [11, 12] (follow-up 21 excluded)", res)
		}
		wantNote := "final read missed the settle proof reply; reporting the proof reply"
		if res.Note != wantNote {
			t.Errorf("note = %q, want %q (restore wins over exclusion)", res.Note, wantNote)
		}
	})
}
