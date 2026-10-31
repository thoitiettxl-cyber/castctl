// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package telegram

// Approval description, auto-decision, rendering, and the opaque
// callback registry, mirrored from Python 0.6.1. Behaviour is
// paraphrased from the cited sources; short quoted identifiers
// appear only as citation evidence.

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"sync"

	"github.com/go-telegram/bot/models"
)

// Decision strings sent to Muse for one approval
// (src/muse_cli/wait.py:129-130).
const (
	// DecisionForever is Muse's "forever" / "Always allow" choice.
	DecisionForever = "allow_always"
	// DecisionOnce is Muse's "Allow once" choice.
	DecisionOnce = "allow_once"
	// DecisionDeny denies the approval.
	DecisionDeny = "deny"
)

// Approval is one normalised approval (src/muse_cli/wait.py:102-127,
// describe_approval). Options is nil when the approval lists no
// options (older servers), which offers_forever treats as
// offering forever.
type Approval struct {
	ID          string
	Title       string
	Question    string
	Kind        string
	Scope       string
	Why         string
	ExpiresAtMS int64
	Options     []string
}

func dictField(v any) map[string]any {
	m, _ := v.(map[string]any)
	if m == nil {
		return map[string]any{}
	}
	return m
}

func strField(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}

func intField(m map[string]any, key string) int64 {
	switch v := m[key].(type) {
	case json.Number:
		n, _ := v.Int64()
		return n
	case float64:
		return int64(v)
	case int64:
		return v
	case int:
		return int64(v)
	}
	return 0
}

// DescribeApproval normalises one raw approval into an Approval
// (src/muse_cli/wait.py:102-127). A non-dict approval, display,
// question, or payload degrades to empty fields instead of
// panicking: a malformed snapshot must not kill a wait. The
// "{assistant}" placeholder in the question is replaced with
// "Muse", as in Python.
func DescribeApproval(a any) Approval {
	m, ok := a.(map[string]any)
	if !ok {
		return Approval{}
	}
	display := dictField(m["display"])
	question := dictField(display["permission_question"])
	payload := dictField(m["payload"])
	rows := map[string]string{}
	if arr, ok := display["detail_rows"].([]any); ok {
		for _, r := range arr {
			if rm, ok := r.(map[string]any); ok {
				if label := strField(rm, "label"); label != "" {
					rows[label] = strField(rm, "value")
				}
			}
		}
	}
	title := strField(display, "summary_title")
	if title == "" {
		title = strField(display, "display_name")
	}
	questionText := strField(question, "text")
	questionText = strings.ReplaceAll(questionText, "{assistant}", "Muse")
	kind := strField(question, "kind")
	if kind == "" {
		kind = strField(payload, "type")
	}
	scope := strField(question, "scope")
	if scope == "" {
		scope = rows["Host"]
	}
	why := strField(display, "short_explanation")
	if why == "" {
		why = strField(display, "reason")
	}
	if why == "" {
		why = strField(m, "reason")
	}
	var options []string
	if arr, ok := m["decision_options"].([]any); ok {
		for _, o := range arr {
			if om, ok := o.(map[string]any); ok {
				if kind := strField(om, "kind"); kind != "" {
					options = append(options, kind)
				}
			}
		}
		if len(options) == 0 {
			options = nil
		}
	}
	return Approval{
		ID:          strField(m, "approval_id"),
		Title:       title,
		Question:    questionText,
		Kind:        kind,
		Scope:       scope,
		Why:         why,
		ExpiresAtMS: intField(m, "request_expires_at_ms"),
		Options:     options,
	}
}

// OffersForever reports whether the approval can be decided with
// Muse's forever choice. Approvals that list no options (older
// servers) are assumed to accept it
// (src/muse_cli/wait.py:133-136, offers_forever).
func OffersForever(d Approval) bool {
	if len(d.Options) == 0 {
		return true
	}
	for _, o := range d.Options {
		if o == DecisionForever {
			return true
		}
	}
	return false
}

// OffersOnce reports whether allow_once is explicitly listed
// (src/muse_cli/wait.py:140-143, offers_once).
func OffersOnce(d Approval) bool {
	for _, o := range d.Options {
		if o == DecisionOnce {
			return true
		}
	}
	return false
}

// ChooseAutoDecision is the decision an auto-approver may send, or
// ("", false) to leave the approval for a human
// (src/muse_cli/wait.py:146-164, choose_auto_decision):
// allow_always wins when offered; otherwise allow_once, and only
// when the caller explicitly enabled the fallback and
// auto-approve is on. It never picks options[0], never
// allow_session/allow_today, and never restricts by kind.
func ChooseAutoDecision(d Approval, autoApprove, allowOnce bool) (string, bool) {
	if !autoApprove {
		return "", false
	}
	if OffersForever(d) {
		return DecisionForever, true
	}
	if allowOnce && OffersOnce(d) {
		return DecisionOnce, true
	}
	return "", false
}

// ApprovalText renders the approval message
// (src/muse_cli/tgbot.py:1703-1707, approval_text): title,
// question, optional italic why.
func ApprovalText(d Approval) string {
	title := d.Title
	if title == "" {
		title = "Approval"
	}
	t := "🔐 <b>" + EscapeText(title) + "</b>\n" + EscapeText(d.Question)
	if d.Why != "" {
		t += "\n<i>" + EscapeText(d.Why) + "</i>"
	}
	return t
}

// ResumeTriple is the resume information embedded in a callback
// registry entry (src/muse_cli/tgbot.py:938-946, cb): the
// session/title/after_seq a decide button resumes. A nil AfterSeq
// means "no resume" (the on_pending default (None, None, None)).
type ResumeTriple struct {
	SessionID string
	Title     string
	AfterSeq  *int64
}

// CallbackEntry is one registered button action. The callback
// data string carries NO approval data: it is an opaque "c:"
// token, and the arguments live in process memory only
// (src/muse_cli/tgbot.py:938-946).
type CallbackEntry struct {
	Action     string
	ApprovalID string
	Decision   string
	SessionID  string
	Title      string
	AfterSeq   *int64
}

// CallbackRegistry is the in-memory callback store, capped at
// 3000 entries, oldest evicted first
// (src/muse_cli/tgbot.py:938-946). Entries are lost on restart,
// exactly as in Python: after a restart (or eviction) a button
// is unknown and the user gets the "expired" answer.
type CallbackRegistry struct {
	mu      sync.Mutex
	entries map[string]CallbackEntry
	order   []string
}

// CallbackRegistryCap is the registry cap
// (src/muse_cli/tgbot.py:938-946).
const CallbackRegistryCap = 3000

// NewCallbackRegistry returns an empty registry.
func NewCallbackRegistry() *CallbackRegistry {
	return &CallbackRegistry{entries: make(map[string]CallbackEntry)}
}

// Register stores an entry and returns its opaque callback data
// ("c:" + token, <= 64 bytes). The token is random
// (src/muse_cli/tgbot.py:938-946 uses secrets.token_urlsafe(6);
// 6 random bytes base64url-encode to 8 characters here).
func (r *CallbackRegistry) Register(entry CallbackEntry) string {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failure is unrecoverable for a token that
		// must be unguessable; panic rather than register a
		// predictable entry. Callers run under the bot's
		// per-update recover, and registration happens only
		// when building a message, never inside a handler.
		panic(err)
	}
	token := base64.RawURLEncoding.EncodeToString(b[:])
	data := "c:" + token
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries[data] = entry
	r.order = append(r.order, data)
	for len(r.entries) > CallbackRegistryCap {
		oldest := r.order[0]
		r.order = r.order[1:]
		delete(r.entries, oldest)
	}
	return data
}

// Lookup resolves callback data to its entry. Data not starting
// with "c:" or naming no entry resolves to false (the "expired"
// button path).
func (r *CallbackRegistry) Lookup(data string) (CallbackEntry, bool) {
	if len(data) < 3 || data[:2] != "c:" {
		return CallbackEntry{}, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.entries[data]
	return e, ok
}

// ApprovalMarkup builds the approval keyboard
// (src/muse_cli/tgbot.py:1709-1723, approval_row /
// approval_markup): "Always allow" when forever is offered,
// otherwise "Allow once" when once is offered, always "Deny".
// Button labels are truncated to 64 characters.
func ApprovalMarkup(d Approval, resume ResumeTriple, reg *CallbackRegistry) models.InlineKeyboardMarkup {
	row := []models.InlineKeyboardButton{}
	mk := func(label, decision string) models.InlineKeyboardButton {
		return models.InlineKeyboardButton{
			Text: ButtonText(label),
			CallbackData: reg.Register(CallbackEntry{
				Action:     "decide",
				ApprovalID: d.ID,
				Decision:   decision,
				SessionID:  resume.SessionID,
				Title:      resume.Title,
				AfterSeq:   resume.AfterSeq,
			}),
		}
	}
	if OffersForever(d) {
		row = append(row, mk("✅ Always allow", DecisionForever))
	} else if OffersOnce(d) {
		row = append(row, mk("✅ Allow once", DecisionOnce))
	}
	row = append(row, mk("❌ Deny", DecisionDeny))
	return models.InlineKeyboardMarkup{InlineKeyboard: [][]models.InlineKeyboardButton{row}}
}

// ApproveAllMarkup builds the "Always allow all" button
// (src/muse_cli/tgbot.py:1996-2007, cmd_approvals): one button
// whose entry carries the approve_all action.
func ApproveAllMarkup(reg *CallbackRegistry) models.InlineKeyboardMarkup {
	btn := models.InlineKeyboardButton{
		Text:         ButtonText("✅ Always allow all"),
		CallbackData: reg.Register(CallbackEntry{Action: "approve_all"}),
	}
	return models.InlineKeyboardMarkup{InlineKeyboard: [][]models.InlineKeyboardButton{{btn}}}
}
