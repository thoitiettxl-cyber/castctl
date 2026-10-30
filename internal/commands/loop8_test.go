// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package commands

// Loop-8 RED tests (structural close, Boss ruling 2026-10-30
// 12:21): the approveAll / logAutoApproved stderr lines must
// emit NO peer free text at all — title as a byte length only,
// option labels as a count only, ApprovalID only under a strict
// id gate, Decision/Kind/Scope only as fixed enum members.
// These tests FAIL on the loop-7 SafeString/cap renderings:
// title bytes, option values, and ungated ids reach stderr
// there. JSON stdout data output must stay byte-identical.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/thoitiettxl-cyber/castctl/internal/approvals"
	"github.com/thoitiettxl-cyber/castctl/internal/logging"
	"github.com/thoitiettxl-cyber/castctl/internal/wait"
)

const loop8Marker = "LOOP8MARKER7f3a91"

// TestLoop8LogAutoApprovedStructuralForms pins the exact
// structural line for a valid record and for every id / enum
// boundary. title_length is a BYTE count: "café ☕" is 9
// bytes (é 2, ☕ 3) and 6 runes — the literal 9 pins the unit.
func TestLoop8LogAutoApprovedStructuralForms(t *testing.T) {
	cases := []struct {
		name string
		rec  approvals.ApprovedRecord
		want string
	}{
		{
			name: "valid record, multi-byte title pins byte unit",
			rec:  approvals.ApprovedRecord{ApprovalID: "A1", Title: "café ☕", Kind: "shell", Scope: "example.com", Decision: "allow_once"},
			want: "auto-approved A1 (allow_once): title_length=9 [shell [omitted]]\n",
		},
		{
			name: "fragmented id omitted",
			rec:  approvals.ApprovedRecord{ApprovalID: "A1\ntoken=" + loop8Marker, Title: "", Kind: "browse", Scope: "x.com", Decision: "allow_always"},
			want: "auto-approved [omitted] (allow_always): title_length=0 [browse [omitted]]\n",
		},
		{
			name: "deny is not an emitted decision",
			rec:  approvals.ApprovedRecord{ApprovalID: "A1", Title: "t", Kind: "shell", Scope: "test", Decision: "deny"},
			want: "auto-approved A1 ([omitted]): title_length=1 [shell [omitted]]\n",
		},
		{
			name: "unknown kind omitted",
			rec:  approvals.ApprovedRecord{ApprovalID: "A1", Title: "t", Kind: "teleport", Scope: "test", Decision: "allow_once"},
			want: "auto-approved A1 (allow_once): title_length=1 [[omitted] [omitted]]\n",
		},
		{
			name: "empty id decision kind omitted, scope always omitted",
			rec:  approvals.ApprovedRecord{ApprovalID: "", Title: "", Kind: "", Scope: "", Decision: ""},
			want: "auto-approved [omitted] ([omitted]): title_length=0 [[omitted] [omitted]]\n",
		},
		{
			name: "64-char id emitted",
			rec:  approvals.ApprovedRecord{ApprovalID: strings.Repeat("a", 64), Title: "t", Kind: "network_access", Scope: "test", Decision: "allow_session"},
			want: fmt.Sprintf("auto-approved %s (allow_session): title_length=1 [network_access [omitted]]\n", strings.Repeat("a", 64)),
		},
		{
			name: "65-char id omitted",
			rec:  approvals.ApprovedRecord{ApprovalID: strings.Repeat("a", 65), Title: "t", Kind: "shell", Scope: "test", Decision: "allow_today"},
			want: "auto-approved [omitted] (allow_today): title_length=1 [shell [omitted]]\n",
		},
		{
			name: "slash id omitted",
			rec:  approvals.ApprovedRecord{ApprovalID: "A/B", Title: "t", Kind: "shell", Scope: "test", Decision: "allow_once"},
			want: "auto-approved [omitted] (allow_once): title_length=1 [shell [omitted]]\n",
		},
		{
			name: "space id omitted",
			rec:  approvals.ApprovedRecord{ApprovalID: "A B", Title: "t", Kind: "shell", Scope: "test", Decision: "allow_once"},
			want: "auto-approved [omitted] (allow_once): title_length=1 [shell [omitted]]\n",
		},
		{
			name: "non-ascii id omitted",
			rec:  approvals.ApprovedRecord{ApprovalID: "café", Title: "t", Kind: "shell", Scope: "test", Decision: "allow_once"},
			want: "auto-approved [omitted] (allow_once): title_length=1 [shell [omitted]]\n",
		},
		{
			name: "hyphen underscore id emitted",
			rec:  approvals.ApprovedRecord{ApprovalID: "appr-1_2", Title: "t", Kind: "shell", Scope: "test", Decision: "allow_once"},
			want: "auto-approved appr-1_2 (allow_once): title_length=1 [shell [omitted]]\n",
		},
		{
			name: "garbage decision omitted",
			rec:  approvals.ApprovedRecord{ApprovalID: "A1", Title: "t", Kind: "shell", Scope: "test", Decision: "allow_once; DROP TABLE"},
			want: "auto-approved A1 ([omitted]): title_length=1 [shell [omitted]]\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			logAutoApproved(&buf, &wait.Result{AutoApproved: []approvals.ApprovedRecord{tc.rec}})
			if buf.String() != tc.want {
				t.Errorf("logAutoApproved = %q, want %q", buf.String(), tc.want)
			}
			if strings.Contains(buf.String(), loop8Marker) {
				t.Errorf("logAutoApproved = %q, carries the marker", buf.String())
			}
		})
	}
}

// TestLoop8LogAutoApprovedTitleShapes drives every loop-7 F2
// label-fragmentation shape, the O1–O3 backlog shapes, and a
// bare marker title through logAutoApproved: no shape may
// leave any title byte on stderr. The line is exactly the
// structural form, with title_length the byte length of the
// (hostile) title.
func TestLoop8LogAutoApprovedTitleShapes(t *testing.T) {
	shapes := []struct {
		name string
		in   string
	}{
		{name: "newline-in-label", in: "tok\nen=" + loop8Marker},
		{name: "cr-in-label", in: "tok\r\nen=" + loop8Marker},
		{name: "nbsp-equals", in: "token\u00A0=" + loop8Marker},
		{name: "emspace-equals", in: "token\u2003=" + loop8Marker},
		{name: "vtab-equals", in: "token\v=" + loop8Marker},
		{name: "nbsp-colon", in: "token\u00A0:" + loop8Marker},
		{name: "emspace-colon", in: "token\u2003:" + loop8Marker},
		{name: "vtab-colon", in: "token\v:" + loop8Marker},
		{name: "json-newline-double", in: `{"token": "` + loop8Marker + "\nTAIL\"}"},
		{name: "json-newline-single", in: `{'token': '` + loop8Marker + "\nTAIL'}"},
		{name: "o1-json-colon-nbsp", in: "{\"token\"\u00A0: \"" + loop8Marker + "\"}"},
		{name: "o1-colon-nbsp-after", in: "{\"token\":\u00A0\"" + loop8Marker + "\"}"},
		{name: "o2-thin-space", in: "token\u2009=" + loop8Marker},
		{name: "o2-ideographic-space", in: "token\u3000=" + loop8Marker},
		{name: "o2-narrow-nbsp", in: "token\u202F=" + loop8Marker},
		{name: "o3-public-key-nbsp", in: "public_key\u00A0=" + loop8Marker},
		{name: "nul-in-label", in: "tok\x00en=" + loop8Marker},
		{name: "bare-marker", in: loop8Marker + " plain words"},
		{name: "crlf-title", in: "line1\r\n" + loop8Marker},
	}
	for _, tc := range shapes {
		t.Run(tc.name, func(t *testing.T) {
			rec := approvals.ApprovedRecord{ApprovalID: "A1", Title: tc.in, Kind: "shell", Scope: "test", Decision: "allow_once"}
			var buf bytes.Buffer
			logAutoApproved(&buf, &wait.Result{AutoApproved: []approvals.ApprovedRecord{rec}})
			want := fmt.Sprintf("auto-approved A1 (allow_once): title_length=%d [shell [omitted]]\n", len(tc.in))
			if buf.String() != want {
				t.Errorf("logAutoApproved(%q) = %q, want %q", tc.in, buf.String(), want)
			}
			if strings.Contains(buf.String(), loop8Marker) {
				t.Errorf("logAutoApproved(%q) = %q, carries the marker", tc.in, buf.String())
			}
			if strings.Count(buf.String(), "\n") != 1 {
				t.Errorf("logAutoApproved(%q) = %q, want exactly 1 line", tc.in, buf.String())
			}
		})
	}
}

// TestLoop8LogAutoApprovedSkipStructural drives a real skip
// through AutoApprover: the offered option kinds (one bare
// marker, no label for SafeString to strip) must reach stderr
// as option_count only, never as values. The producer error
// text itself is unchanged — SummarizeErr still carries the
// offers list, so the JSON data rendering is untouched.
func TestLoop8LogAutoApprovedSkipStructural(t *testing.T) {
	decide := func(ctx context.Context, a approvals.DescribedApproval, decision string) error { return nil }
	aa := approvals.NewAutoApprover(func(ctx context.Context) (approvals.Decider, func(), error) {
		return decide, func() {}, nil
	}, false)
	_, _, errs := aa.Approve(context.Background(), []approvals.DescribedApproval{
		{ApprovalID: strPtr("SK1"), Options: []string{"allow_once", loop8Marker}},
	})
	if len(errs) != 1 {
		t.Fatalf("Approve errs = %v, want 1 skip error", errs)
	}
	if got := logging.SummarizeErr(errs[0].Err); !strings.Contains(got, loop8Marker) {
		t.Fatalf("producer skip error %q lost the offers list: JSON data rendering would change", got)
	}
	var buf bytes.Buffer
	logAutoApproved(&buf, &wait.Result{AutoApproveErrors: errs})
	out := buf.String()
	if out == "" {
		t.Fatal("logAutoApproved output is empty: positive control failed")
	}
	if strings.Contains(out, loop8Marker) {
		t.Errorf("SKIPPED line = %q, carries the option value", out)
	}
	if strings.Contains(out, "offers [") {
		t.Errorf("SKIPPED line = %q, carries the offers list", out)
	}
	if !strings.Contains(out, "option_count=1") {
		t.Errorf("SKIPPED line = %q, want option_count=1", out)
	}
	if strings.Count(out, "\n") != 1 {
		t.Errorf("SKIPPED line = %q, want exactly 1 line", out)
	}
	if !strings.HasPrefix(out, "auto-approve SKIPPED SK1: ") {
		t.Errorf("SKIPPED line = %q, want the SK1 id emitted", out)
	}
}

// TestLoop8LogAutoApprovedFailedIDGating pins ApprovalID
// gating on the FAILED line; the underlying decide error is
// rendered by the settled SummarizeErr rule and is not
// re-litigated here.
func TestLoop8LogAutoApprovedFailedIDGating(t *testing.T) {
	fail := &approvals.ApproveError{
		ApprovalID: "C1\ntoken=" + loop8Marker,
		Decision:   "allow_once",
		Err:        errors.New("plain decision error"),
	}
	var buf bytes.Buffer
	logAutoApproved(&buf, &wait.Result{AutoApproveErrors: []*approvals.ApproveError{fail}})
	want := "auto-approve FAILED [omitted]: plain decision error\n"
	if buf.String() != want {
		t.Errorf("FAILED line = %q, want %q", buf.String(), want)
	}
}

// TestLoop8ApproveAllStructural drives the fake stack: the
// skipped line carries option_count only, the approved line
// carries title_length only, and stdout JSON still carries
// the full title and options byte-identical (data output).
func TestLoop8ApproveAllStructural(t *testing.T) {
	title := "tok\nen=" + loop8Marker + " café"
	// The title carries a raw newline: embed it JSON-escaped
	// (strconv.Quote), or the pending payload itself is
	// invalid JSON and the stack fails before approveAll.
	pending := `{"pending_approvals":[
		{"approval_id":"SKIP1",
		 "display":{"summary_title":"skipped title",
		 "permission_question":{"kind":"shell","scope":"test"}},
		 "decision_options":[{"kind":"allow_once"},{"kind":"` + loop8Marker + `"}]},
		{"approval_id":"OK1",
		 "display":{"summary_title":` + strconv.Quote(title) + `,
		 "permission_question":{"kind":"shell","scope":"test"}},
		 "decision_options":[{"kind":"allow_always"}]}
	]}`
	s := newFakeStack(t, routeHandler(map[string]string{"/approvals": pending}), nil)
	if code := s.run("approvals", "--approve-all"); code != 0 {
		t.Fatalf("approvals --approve-all: code=%d err=%q", code, s.errb.String())
	}
	stderr := s.errb.String()
	if stderr == "" {
		t.Fatal("stderr is empty: positive control failed")
	}
	if strings.Contains(stderr, loop8Marker) {
		t.Errorf("stderr %q carries the peer marker", stderr)
	}
	if strings.Contains(stderr, "café") {
		t.Errorf("stderr %q carries title bytes", stderr)
	}
	if !strings.Contains(stderr, "skipped SKIP1: no forever option option_count=2\n") {
		t.Errorf("stderr %q, want the structural skipped line", stderr)
	}
	// title_length=30: "tok"(3) + "\n"(1) + "en="(3) + marker(17)
	// + " "(1) + "café"(5 bytes).
	if !strings.Contains(stderr, "approved OK1 (allow_always): title_length=30 [shell [omitted]]\n") {
		t.Errorf("stderr %q, want the structural approved line with title_length=30", stderr)
	}
	stdout := s.out.String()
	if !strings.Contains(stdout, loop8Marker) || !strings.Contains(stdout, "café") {
		t.Errorf("stdout %q, want the raw data output untouched", stdout)
	}
}

func strPtr(s string) *string { return &s }
