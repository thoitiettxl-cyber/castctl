// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package keeper

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"
)

// The versioned login-form contract (Boss decision G4).
//
// The contract is built ONLY from automated, read-only
// observation of the live login page: the page is loaded
// headless through the S2 profile-routed inbound, and the
// redacted DOM structure, selectors, and flow steps are
// recorded — no credential entry, no submit, ever. The
// recorded contract is encoded here as a versioned fixture
// (login-contract.v1.json, embedded below); the driver
// matches the live page against it BEFORE entering anything,
// and stops with a *ReloginBlocker on any mismatch.
//
// A contract with Observed=false is NOT established: the
// driver must refuse to run (ErrContractNotEstablished,
// mapped to the blocked notice). If the read-only observation
// cannot establish the contract, the fixture stays
// unobserved and F6 is honestly unmet — the contract is
// never invented from reasoning or from a guessed form.

//go:embed testdata/login-contract.v1.json
var loginContractJSON []byte

// ErrContractNotEstablished is returned when no observed
// login-form contract exists for this build: the driver
// must not guess a form.
var ErrContractNotEstablished = fmt.Errorf("login-form contract not established: no read-only observation recorded")

// LoginContractStep is one recorded flow step: fill a field
// or activate a control. Selector is a CSS selector recorded
// from the observed page; Field names the credential slot
// ("username" or "password") for fill steps, "" otherwise.
// No values are recorded: selectors and structure only.
type LoginContractStep struct {
	Action   string `json:"action"` // "fill" or "click"
	Selector string `json:"selector"`
	Field    string `json:"field,omitempty"`
}

// LoginBlockerSignal is one recorded blocker signal: a CSS
// selector whose presence means the page is blocked, or a
// page-text keyword (lowercase substring) with the same
// meaning. Kind is the closed NoticeKind for the alert.
type LoginBlockerSignal struct {
	Selector string     `json:"selector,omitempty"`
	Keyword  string     `json:"keyword,omitempty"`
	Kind     NoticeKind `json:"kind"`
}

// LoginContract is the recorded login-form contract for one
// provider login page.
type LoginContract struct {
	Version  int                  `json:"version"`
	Observed bool                 `json:"observed"`
	LoginURL string               `json:"login_url"`
	Steps    []LoginContractStep  `json:"steps"`
	Blockers []LoginBlockerSignal `json:"blockers"`
	Notes    string               `json:"notes,omitempty"`
}

// DefaultLoginContract returns the embedded recorded
// contract. Callers must check Observed before using it.
func DefaultLoginContract() (LoginContract, error) {
	var c LoginContract
	if err := json.Unmarshal(loginContractJSON, &c); err != nil {
		return LoginContract{}, fmt.Errorf("embedded login contract is corrupt: %w", err)
	}
	return c, nil
}

// PageSnapshot is the redacted, driver-supplied view of the
// live login page the contract is matched against: which
// recorded selectors are present, and the page's visible text
// (lowercased by the driver) for keyword signals. It carries
// no values, no HTML, and no screenshot bytes.
type PageSnapshot struct {
	PresentSelectors map[string]bool
	VisibleText      string
}

// snapshotResult is the driver's boolean-only snapshot: which
// contract selectors are present, and which blocker kinds
// hit (by selector or keyword — the value names the signal
// class only, never page text). The evaluation script
// returns nothing else. It lives here (not in the
// chromedp-tagged driver file) so the decision equivalence
// with MatchContract is testable without a browser.
type snapshotResult struct {
	Present map[string]bool   `json:"present"`
	Hits    map[string]string `json:"hits"`
}

// snapshotDecision maps a boolean snapshot onto the contract
// through the SAME decision as MatchContract (see
// matchDecision below): blocker signals first, then
// step-selector presence. The two paths must agree on every
// input; TestSnapshotDecisionMatchesContract pins it.
func snapshotDecision(c LoginContract, res snapshotResult) error {
	var blockedKind NoticeKind
	blockedDetail := ""
	for _, sig := range c.Blockers {
		if detail, ok := res.Hits[string(sig.Kind)]; ok {
			blockedKind, blockedDetail = sig.Kind, "blocker_"+detail
			break
		}
	}
	// No special case for an empty-kind signal: MatchContract
	// records its hit as blockedKind "" too, so matchDecision
	// falls through to the step checks. An empty kind in the
	// contract is a malformed entry; both paths treat it the
	// same (a hit does not block by itself).
	return matchDecision(c, blockedKind, blockedDetail, res.Present)
}

// isBlockerSignal reports whether a blocker was produced by a
// recorded blocker signal (selector or keyword hit), as opposed
// to a contract mismatch: mismatch means "the form is not the
// recorded one (yet)", a signal means "the page is blocked".
// Wait loops stop immediately on a signal but poll to the
// deadline on a mismatch (a slow page still loading must not
// look like a changed form). The Detail values are the fixed
// enums produced by MatchContract and by the driver's boolean
// snapshot; any other Detail is not a signal.
func isBlockerSignal(b *ReloginBlocker) bool {
	if b == nil {
		return false
	}
	switch b.Detail {
	case "blocker_signal", "blocker_selector", "blocker_keyword":
		return true
	default:
		return false
	}
}

// matchDecision is the ONE blocker/mismatch decision shared by
// MatchContract (Go-side snapshot: page text in hand) and the
// driver's boolean snapshot (kinds only, no page text crosses
// from the page). blockedKind is "" when no blocker signal
// hit; blockedDetail names the signal class that hit.
// present maps contract selectors to presence. Both callers
// must agree: a test pins their equivalence (see
// TestSnapshotDecisionMatchesContract).
func matchDecision(c LoginContract, blockedKind NoticeKind, blockedDetail string, present map[string]bool) error {
	if !c.Observed {
		return ErrContractNotEstablished
	}
	if blockedKind != "" {
		kind := blockedKind
		if !ValidNoticeKind(kind) {
			kind = NoticeBlocked
		}
		return &ReloginBlocker{Kind: kind, Detail: blockedDetail}
	}
	for _, step := range c.Steps {
		if step.Selector == "" {
			return &ReloginBlocker{Kind: NoticeBlocked, Detail: "contract_step_no_selector"}
		}
		if !present[step.Selector] {
			return &ReloginBlocker{Kind: NoticeBlocked, Detail: "contract_mismatch"}
		}
	}
	return nil
}

// MatchContract checks a page snapshot against the contract.
// Blocker signals are checked FIRST (a blocked page may also
// lack the form): a hit returns a *ReloginBlocker with the
// signal's kind. Then every contract step selector must be
// present: a missing selector returns a *ReloginBlocker of
// kind NoticeBlocked (contract mismatch — the page changed).
// A contract that is not Observed refuses outright with
// ErrContractNotEstablished. The returned blocker Detail is a
// fixed enum string naming the signal class only, never page
// text or a value.
func MatchContract(c LoginContract, snap PageSnapshot) error {
	var blockedKind NoticeKind
	blockedDetail := ""
	for _, sig := range c.Blockers {
		if sig.Selector != "" && snap.PresentSelectors[sig.Selector] {
			blockedKind, blockedDetail = sig.Kind, "blocker_selector"
			break
		}
		if sig.Keyword != "" && strings.Contains(strings.ToLower(snap.VisibleText), strings.ToLower(sig.Keyword)) {
			blockedKind, blockedDetail = sig.Kind, "blocker_keyword"
			break
		}
	}
	return matchDecision(c, blockedKind, blockedDetail, snap.PresentSelectors)
}
