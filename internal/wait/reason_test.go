// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package wait

import (
	"testing"
)

func TestWaitPhrasesCount(t *testing.T) {
	if len(WaitPhrases) != 34 {
		t.Fatalf("wait phrases = %d, want 34", len(WaitPhrases))
	}
	// Every phrase is exercised by NeedsInputReason below; here
	// pin the exact list order (order decides the named phrase).
	wantFirst := "chờ boss"
	wantLast := "your call"
	if WaitPhrases[0] != wantFirst || WaitPhrases[33] != wantLast {
		t.Errorf("first=%q last=%q", WaitPhrases[0], WaitPhrases[33])
	}
}

func TestNeedsInputReasonAllPhrases(t *testing.T) {
	for _, ph := range WaitPhrases {
		text := "Done. " + ph + " now"
		// Phrases ending in "?" already end the text with a
		// question; the phrase rule still wins over the tail
		// rule, and the returned reason names the phrase.
		got := NeedsInputReason(text)
		want := "waiting phrase: '" + ph + "'"
		if got != want {
			t.Errorf("phrase %q: got %q, want %q", ph, got, want)
		}
	}
}

func TestNeedsInputReasonExamples(t *testing.T) {
	tests := []struct {
		name string
		text string
		want string
	}{
		{"vietnamese phrase", "Xong. Boss có muốn tiếp tục?", "waiting phrase: 'boss có muốn'"},
		{"english phrase", "Done. Should I proceed?", "waiting phrase: 'should i'"},
		{"gate wins", "Gate Questions: pick one", "gate/policy question"},
		{"gate none", "Gate Questions: none", ""},
		{"gate none of these", "gate questions: none of these", ""},
		{"gate nonetheless", "gate questions: nonetheless", "gate/policy question"},
		{"gate empty", "gate questions: ", ""},
		{"gate policy variant", "policy-question = choose", "gate/policy question"},
		{"gate none equals", "policy-question = none", ""},
		{"gates no match", "gates: x", ""},
		{"safety check", "Stopped by a safety check.", "stopped by a safety check"},
		{"refuse to run", "I refuse to run that.", "stopped by a safety check"},
		{"refused to do", "I refused to do it.", "stopped by a safety check"},
		{"tripped safety", "The guard tripped the safety mechanism.", "stopped by a safety check"},
		{"vietnamese safety", "Đã kiểm tra an toàn xong", "stopped by a safety check"},
		{"vietnamese refuse", "Tôi từ chối chạy lệnh này", "stopped by a safety check"},
		{"plain question", "Hello world?", "ends with a question"},
		{"question not last line", "Hello world?\nDone.", ""},
		{"tail strip stars", "Done. **", ""},
		{"fullwidth question", "Bạn có khỏe không？", "ends with a question"},
		{"empty", "", ""},
		{"spaces", "   ", ""},
		{"widget marker only", "[[hatch_widget:q]]", ""},
		{"phrase substring", "Let me know if you need more", "waiting phrase: 'let me know if'"},
		{"gate beats phrase", "Gate Questions: should i?", "gate/policy question"},
		{"safety beats phrase", "safety check: should i continue?", "stopped by a safety check"},
		{"tail paren strip", "Really?)", "ends with a question"},
		{"tail quote strip", `Really?"`, "ends with a question"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NeedsInputReason(tt.text); got != tt.want {
				t.Errorf("NeedsInputReason(%q) = %q, want %q", tt.text, got, tt.want)
			}
		})
	}
}

func TestQuestionOf(t *testing.T) {
	tests := []struct {
		text string
		want string
	}{
		{"First. What now? Second. Really?", "What now? Really?"},
		{"No question here.", "No question here."},
		{"", ""},
		{"One? Two? Three? Four?", "Three? Four?"},
		{"Done! Really? Yes.", "Really?"},
		{"Câu hỏi？ Tiếp theo。", "Câu hỏi？ Tiếp theo。"},
	}
	for _, tt := range tests {
		if got := QuestionOf(tt.text); got != tt.want {
			t.Errorf("QuestionOf(%q) = %q, want %q", tt.text, got, tt.want)
		}
	}
}

func TestOutcomeAndExitCode(t *testing.T) {
	noReplies := []Reply(nil)
	plain := []Reply{{Text: "done"}}
	widget := []Reply{{Text: "pick", Widgets: []Widget{{ID: "w1"}}}}
	question := []Reply{{Text: "Should I continue?"}}
	tests := []struct {
		kind    Kind
		replies []Reply
		outcome string
		exit    int
	}{
		{KindDone, noReplies, "done", 0},
		{KindDone, plain, "done", 0},
		{KindDone, widget, "needs_input", 4},
		{KindDone, question, "needs_input", 4},
		{KindFailed, noReplies, "failed", 2},
		{KindFailed, plain, "failed", 2},
		{KindApproval, noReplies, "needs_approval", 4},
		{KindTimeout, noReplies, "timeout", 124},
		{Kind("bogus"), noReplies, "timeout", 124},
		// Only the last reply is inspected: a widget in an
		// earlier reply with a plain last reply is done.
		{KindDone, []Reply{widget[0], plain[0]}, "done", 0},
	}
	for _, tt := range tests {
		if got := OutcomeOf(tt.kind, tt.replies); got != tt.outcome {
			t.Errorf("OutcomeOf(%q) = %q, want %q", tt.kind, got, tt.outcome)
		}
		if got := ExitCode(tt.kind, tt.replies); got != tt.exit {
			t.Errorf("ExitCode(%q) = %d, want %d", tt.kind, got, tt.exit)
		}
	}
}
