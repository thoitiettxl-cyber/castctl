// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package commands

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/thoitiettxl-cyber/castctl/internal/approvals"
	"github.com/thoitiettxl-cyber/castctl/internal/wait"
)

// F1: in send results, question precedes needs_input_reason
// (Python _send_finish copies the optional keys in the order
// approvals, auto_approved, auto_approve_errors, widgets,
// question, needs_input_reason). The wait result keeps the
// opposite order (needs_input_reason, question).
func TestSendWaitJSONQuestionBeforeNeedsInputReason(t *testing.T) {
	v := sendWaitJSON{
		Outcome:          "needs_input",
		Status:           strPtrOrNil("waiting"),
		Question:         strPtrOrNil("Shall I?"),
		NeedsInputReason: strPtrOrNil("question"),
	}
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	qi := strings.Index(string(raw), `"question"`)
	ni := strings.Index(string(raw), `"needs_input_reason"`)
	if qi < 0 || ni < 0 || qi > ni {
		t.Errorf("send key order: question at %d, needs_input_reason at %d in %s", qi, ni, raw)
	}
}

// M1: an empty status marshals as JSON null (Python emits
// w.status, which is None when no status is known), never "".
func TestWaitResultJSONEmptyStatusIsNull(t *testing.T) {
	raw, err := json.Marshal(toWaitResultJSON(&wait.Result{
		Kind: wait.KindTimeout, Outcome: "timeout", Status: "", AfterSeq: 7,
	}, false))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"status":null`) {
		t.Errorf("empty status must marshal as null: %s", raw)
	}
	raw, err = json.Marshal(toWaitResultJSON(&wait.Result{
		Kind: wait.KindDone, Outcome: "done", Status: "completed", AfterSeq: 7,
	}, false))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"status":"completed"`) {
		t.Errorf("known status must marshal as a string: %s", raw)
	}
}

// M2: approved / auto_approve_errors rows collapse absent fields
// to null, like Python's describe_approval/.get() rows — never "".
func TestWaitResultJSONEmptyApprovedFieldsAreNull(t *testing.T) {
	res := &wait.Result{
		Kind:    wait.KindApproval,
		Outcome: "needs_approval",
		Status:  "waiting",
		AutoApproved: []approvals.ApprovedRecord{
			{ApprovalID: "", Title: "", Kind: "", Scope: "", Decision: ""},
		},
		AutoApproveErrors: []*approvals.ApproveError{
			{ApprovalID: "", Title: "", Kind: "", Scope: "", Decision: "", Err: errors.New("boom")},
		},
	}
	raw, err := json.Marshal(toWaitResultJSON(res, true))
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v (%s)", err, raw)
	}
	approved, _ := got["auto_approved"].([]any)
	if len(approved) != 1 {
		t.Fatalf("auto_approved = %v", got["auto_approved"])
	}
	row, _ := approved[0].(map[string]any)
	for _, k := range []string{"approval_id", "title", "kind", "scope", "decision"} {
		if _, ok := row[k]; !ok {
			t.Errorf("auto_approved row lacks %q: %v", k, row)
		} else if row[k] != nil {
			t.Errorf("auto_approved row %q = %v, want null", k, row[k])
		}
	}
	errs, _ := got["auto_approve_errors"].([]any)
	if len(errs) != 1 {
		t.Fatalf("auto_approve_errors = %v", got["auto_approve_errors"])
	}
	erow, _ := errs[0].(map[string]any)
	for _, k := range []string{"approval_id", "title", "kind", "scope", "decision"} {
		if _, ok := erow[k]; !ok {
			t.Errorf("auto_approve_errors row lacks %q: %v", k, erow)
		} else if erow[k] != nil {
			t.Errorf("auto_approve_errors row %q = %v, want null", k, erow[k])
		}
	}
	if erow["error"] != "boom" {
		t.Errorf("auto_approve_errors row error = %v, want boom", erow["error"])
	}
}
