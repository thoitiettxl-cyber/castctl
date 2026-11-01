// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package telegram

// Approval tests. Expected values are literals from the Python
// survey (wait.py describe_approval / offers_* /
// choose_auto_decision; tgbot.py approval_text / approval_row /
// cb registry), never recomputed from the Go code.

import (
	"reflect"
	"strings"
	"testing"
)

func TestDescribeApproval(t *testing.T) {
	t.Parallel()
	raw := map[string]any{
		"approval_id": "appr-1",
		"display": map[string]any{
			"summary_title": "Allow network",
			"permission_question": map[string]any{
				"text":  "{assistant} wants to fetch example.com",
				"kind":  "network",
				"scope": "example.com",
			},
			"short_explanation": "needed for the task",
			"detail_rows": []any{
				map[string]any{"label": "Host", "value": "example.com"},
			},
		},
		"payload":               map[string]any{"type": "egress"},
		"request_expires_at_ms": float64(1700000000000),
		"decision_options": []any{
			map[string]any{"kind": "allow_once"},
			map[string]any{"kind": "deny"},
			map[string]any{"label": "no kind here"},
			"not-a-dict",
		},
	}
	d := DescribeApproval(raw)
	if d.ID != "appr-1" || d.Title != "Allow network" || d.Question != "Muse wants to fetch example.com" ||
		d.Kind != "network" || d.Scope != "example.com" || d.Why != "needed for the task" {
		t.Errorf("DescribeApproval = %+v; want the mapped fields", d)
	}
	if d.ExpiresAtMS != 1700000000000 {
		t.Errorf("ExpiresAtMS = %d; want 1700000000000", d.ExpiresAtMS)
	}
	if len(d.Options) != 2 || d.Options[0] != "allow_once" || d.Options[1] != "deny" {
		t.Errorf("Options = %v; want [allow_once deny]", d.Options)
	}
	// display_name fallback; kind from payload; scope from Host row.
	raw2 := map[string]any{
		"approval_id": "appr-2",
		"display": map[string]any{
			"display_name": "Fallback title",
			"detail_rows":  []any{map[string]any{"label": "Host", "value": "host.example"}},
			"reason":       "why here",
		},
		"payload": map[string]any{"type": "fs"},
	}
	d2 := DescribeApproval(raw2)
	if d2.Title != "Fallback title" || d2.Kind != "fs" || d2.Scope != "host.example" || d2.Why != "why here" {
		t.Errorf("DescribeApproval(fallbacks) = %+v", d2)
	}
	if d2.Question != "" || d2.Options != nil {
		t.Errorf("DescribeApproval(fallbacks) question/options = %q/%v; want empty/nil", d2.Question, d2.Options)
	}
	// Non-dict degrades to empty fields instead of panicking.
	for _, bad := range []any{nil, "a string", 42, []any{}} {
		if got := DescribeApproval(bad); !reflect.DeepEqual(got, Approval{}) {
			t.Errorf("DescribeApproval(%v) = %+v; want zero Approval", bad, got)
		}
	}
	// Non-dict display/question/payload degrade to empty.
	d3 := DescribeApproval(map[string]any{"approval_id": "appr-3", "display": "nope", "payload": 7})
	if d3.ID != "appr-3" || d3.Title != "" {
		t.Errorf("DescribeApproval(malformed nests) = %+v", d3)
	}
}

func TestOffersAndChooseAutoDecision(t *testing.T) {
	t.Parallel()
	noOpts := Approval{ID: "a"}
	if !OffersForever(noOpts) || OffersOnce(noOpts) {
		t.Error("no options: want offers_forever=true, offers_once=false")
	}
	onceOnly := Approval{ID: "b", Options: []string{"allow_once"}}
	if OffersForever(onceOnly) || !OffersOnce(onceOnly) {
		t.Error("[allow_once]: want offers_forever=false, offers_once=true")
	}
	denyOnly := Approval{ID: "c", Options: []string{"deny"}}
	if OffersForever(denyOnly) || OffersOnce(denyOnly) {
		t.Error("[deny]: want both offers false")
	}
	forever := Approval{ID: "d", Options: []string{"allow_always", "deny"}}
	if !OffersForever(forever) || OffersOnce(forever) {
		t.Error("[allow_always, deny]: want offers_forever=true, offers_once=false")
	}
	cases := []struct {
		name    string
		d       Approval
		approve bool
		onceTgl bool
		want    string
		wantOK  bool
	}{
		{"off", noOpts, false, false, "", false},
		{"off-toggle-on", onceOnly, false, true, "", false},
		{"no-opts", noOpts, true, false, "allow_always", true},
		{"once-toggle-off", onceOnly, true, false, "", false},
		{"once-toggle-on", onceOnly, true, true, "allow_once", true},
		{"deny-only", denyOnly, true, true, "", false},
		{"forever-wins", Approval{ID: "e", Options: []string{"allow_always", "allow_once"}}, true, true, "allow_always", true},
	}
	for _, tc := range cases {
		got, ok := ChooseAutoDecision(tc.d, tc.approve, tc.onceTgl)
		if got != tc.want || ok != tc.wantOK {
			t.Errorf("%s: ChooseAutoDecision = (%q,%v); want (%q,%v)", tc.name, got, ok, tc.want, tc.wantOK)
		}
	}
}

func TestApprovalText(t *testing.T) {
	t.Parallel()
	got := ApprovalText(Approval{ID: "a", Title: "Allow network", Question: "Fetch?", Why: "because"})
	want := "🔐 <b>Allow network</b>\nFetch?\n<i>because</i>"
	if got != want {
		t.Errorf("ApprovalText = %q; want %q", got, want)
	}
	got = ApprovalText(Approval{ID: "a", Question: "Fetch?"})
	want = "🔐 <b>Approval</b>\nFetch?"
	if got != want {
		t.Errorf("ApprovalText(minimal) = %q; want %q", got, want)
	}
	got = ApprovalText(Approval{ID: "a", Title: "<b>x</b>", Question: "a & b"})
	if strings.Contains(got, "<b>x</b>") || !strings.Contains(got, "&lt;b&gt;x&lt;/b&gt;") || !strings.Contains(got, "a &amp; b") {
		t.Errorf("ApprovalText escapes title/question: %q", got)
	}
}

func TestCallbackRegistry(t *testing.T) {
	t.Parallel()
	reg := NewCallbackRegistry()
	entry := CallbackEntry{Action: "decide", ApprovalID: "appr-1", Decision: "allow_once"}
	data := reg.Register(entry)
	if !strings.HasPrefix(data, "c:") || len(data) > 64 {
		t.Errorf("callback data = %q; want c:-prefixed, <=64 bytes", data)
	}
	got, ok := reg.Lookup(data)
	if !ok || got != entry {
		t.Errorf("Lookup = %+v,%v; want %+v,true", got, ok, entry)
	}
	if _, ok := reg.Lookup("c:nosuchtoken"); ok {
		t.Error("Lookup(unknown) = true; want false")
	}
	if _, ok := reg.Lookup("plain-token"); ok {
		t.Error("Lookup(non-c: data) = true; want false")
	}
	// Distinct tokens per registration.
	data2 := reg.Register(entry)
	if data2 == data {
		t.Error("two registrations returned the same callback data")
	}
}

func TestCallbackRegistryEviction(t *testing.T) {
	t.Parallel()
	reg := NewCallbackRegistry()
	first := reg.Register(CallbackEntry{Action: "decide", ApprovalID: "first"})
	for i := 0; i < 3000; i++ {
		reg.Register(CallbackEntry{Action: "decide", ApprovalID: "filler"})
	}
	if _, ok := reg.Lookup(first); ok {
		t.Error("first entry survived 3000 further registrations; want FIFO eviction at cap 3000")
	}
}

// TestCallbackRegistryEvictionSkipsLiveDecide is the R8
// acceptance test: eviction must not kill a live decide
// button while expendable entries exist, and Consume is the
// single-flight guard (first tap wins, second finds nothing).
func TestCallbackRegistryEvictionSkipsLiveDecide(t *testing.T) {
	t.Parallel()
	reg := NewCallbackRegistry()
	live := reg.Register(CallbackEntry{Action: "decide", ApprovalID: "live"})
	firstNoop := reg.Register(CallbackEntry{Action: "noop"})
	for i := 0; i < 3000; i++ {
		reg.Register(CallbackEntry{Action: "noop"})
	}
	if _, ok := reg.Lookup(live); !ok {
		t.Error("live decide entry evicted by noop registrations; want decide entries skipped on eviction")
	}
	if _, ok := reg.Lookup(firstNoop); ok {
		t.Error("oldest noop survived past the cap; want eviction to take non-decide entries first")
	}
	if _, ok := reg.Consume(live); !ok {
		t.Error("Consume(live) = false; want the entry")
	}
	if _, ok := reg.Lookup(live); ok {
		t.Error("consumed entry still resolvable; want single-flight consumption")
	}
	if _, ok := reg.Consume(live); ok {
		t.Error("second Consume = true; want false")
	}
}

func TestApprovalMarkup(t *testing.T) {
	t.Parallel()
	reg := NewCallbackRegistry()
	// Forever offered: Always + Deny.
	mk := ApprovalMarkup(Approval{ID: "a", Options: []string{"allow_always", "deny"}}, ResumeTriple{}, reg)
	if len(mk.InlineKeyboard) != 1 || len(mk.InlineKeyboard[0]) != 2 {
		t.Fatalf("forever markup = %+v; want one row of 2 buttons", mk.InlineKeyboard)
	}
	labels := []string{mk.InlineKeyboard[0][0].Text, mk.InlineKeyboard[0][1].Text}
	if labels[0] != "✅ Always allow" || labels[1] != "❌ Deny" {
		t.Errorf("forever labels = %v", labels)
	}
	e, ok := reg.Lookup(mk.InlineKeyboard[0][0].CallbackData)
	if !ok || e.Decision != "allow_always" || e.ApprovalID != "a" {
		t.Errorf("Always button entry = %+v,%v", e, ok)
	}
	// Once only (no forever): Once + Deny.
	mk = ApprovalMarkup(Approval{ID: "b", Options: []string{"allow_once", "deny"}}, ResumeTriple{}, reg)
	if len(mk.InlineKeyboard[0]) != 2 || mk.InlineKeyboard[0][0].Text != "✅ Allow once" {
		t.Errorf("once markup = %+v", mk.InlineKeyboard)
	}
	// Deny only: a single Deny button.
	mk = ApprovalMarkup(Approval{ID: "c", Options: []string{"deny"}}, ResumeTriple{}, reg)
	if len(mk.InlineKeyboard[0]) != 1 || mk.InlineKeyboard[0][0].Text != "❌ Deny" {
		t.Errorf("deny-only markup = %+v", mk.InlineKeyboard)
	}
	// Resume triple is carried into the entry.
	after := int64(42)
	mk = ApprovalMarkup(Approval{ID: "d"}, ResumeTriple{SessionID: "s1", Title: "t", AfterSeq: &after}, reg)
	e, ok = reg.Lookup(mk.InlineKeyboard[0][0].CallbackData)
	if !ok || e.SessionID != "s1" || e.Title != "t" || e.AfterSeq == nil || *e.AfterSeq != 42 {
		t.Errorf("resume entry = %+v,%v", e, ok)
	}
}
