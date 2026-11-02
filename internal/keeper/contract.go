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
	if !c.Observed {
		return ErrContractNotEstablished
	}
	for _, sig := range c.Blockers {
		if sig.Selector != "" && snap.PresentSelectors[sig.Selector] {
			kind := sig.Kind
			if !ValidNoticeKind(kind) {
				kind = NoticeBlocked
			}
			return &ReloginBlocker{Kind: kind, Detail: "blocker_selector"}
		}
		if sig.Keyword != "" && strings.Contains(strings.ToLower(snap.VisibleText), strings.ToLower(sig.Keyword)) {
			kind := sig.Kind
			if !ValidNoticeKind(kind) {
				kind = NoticeBlocked
			}
			return &ReloginBlocker{Kind: kind, Detail: "blocker_keyword"}
		}
	}
	for _, step := range c.Steps {
		if step.Selector == "" {
			return &ReloginBlocker{Kind: NoticeBlocked, Detail: "contract_step_no_selector"}
		}
		if !snap.PresentSelectors[step.Selector] {
			return &ReloginBlocker{Kind: NoticeBlocked, Detail: "contract_mismatch"}
		}
	}
	return nil
}
