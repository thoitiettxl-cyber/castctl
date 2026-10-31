// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package telegram

// Approval claims and pending-approval notifications, mirroring
// Python's in-memory approval state machine
// (src/muse_cli/tgbot.py:1505-1701, approve_forever / _await_claim
// / _record_claim / _fail_claim / on_pending). All state is
// process-memory only and lost on restart, exactly as in
// Python (decided_approvals, claimed, _inflight_claims, notified,
// warned_no_forever, auto_log are plain attributes / module state
// in 0.6.1; the bot's state file persists only the toggles and the
// offset, not the claims).
//
// Decision semantics (surveyed, not invented): allow_once is a
// decision string for ONE approval id gated by the persistent
// auto_allow_once toggle; it is NOT a consumed one-shot grant
// (src/muse_cli/tgbot.py:557-568, 663-664, 2009-2052). The manual
// Allow-once button ignores the toggle (tgbot.py:1703-1723).
// Per-id consumption lives only in the in-memory decided set and
// is lost on restart: after a restart an already-decided approval
// may be decided again if it is still pending.

import (
	"context"
	"sync"
	"time"
)

// AutoLogEntry records one auto-decision, newest last, capped at
// 51 entries: Python keeps at most 51 (append then [-50:]+[entry]
// semantics, src/muse_cli/tgbot.py:1594-1597).
type AutoLogEntry struct {
	Time       time.Time
	ApprovalID string
	Title      string
	Decision   string
	Kind       string
	Scope      string
}

type inflightClaim struct {
	done       chan struct{}
	closeOnce  sync.Once
	decision   *string
	failed     bool
	superseded bool
}

func newInflightClaim() *inflightClaim {
	return &inflightClaim{done: make(chan struct{})}
}

func (c *inflightClaim) settle() {
	c.closeOnce.Do(func() { close(c.done) })
}

// claim constants mirror the Python claim protocol
// (src/muse_cli/tgbot.py:63, 618, 1505-1530).
const (
	claimChainMax    = 3
	claimWaitDefault = 15 * time.Second
)

// ApproveForever auto-decides every approval that offers a
// forever option, skipping empty ids, already-decided ids, and
// ids with an in-flight claim owned elsewhere (those are
// awaited, then decided on takeover). It returns the ids it
// decided (src/muse_cli/tgbot.py:1505-1580, approve_forever).
// A failed decide releases the claim so a retry can decide it
// (src/muse_cli/tgbot.py:1568-1572, _fail_claim). No claim is
// created for an id that does not offer forever; that is
// recorded once as a warning (warned_no_forever,
// tgbot.py:1648-1656) and the id is skipped on later calls
// until restart.
func (b *Bot) ApproveForever(ctx context.Context, items []Approval) []string {
	type work struct {
		a     Approval
		claim *inflightClaim
	}
	var done []string
	var waited []work
	var todo []work

	b.claimsMu.Lock()
	for _, a := range items {
		if a.ID == "" {
			continue
		}
		if _, decided := b.decided[a.ID]; decided {
			done = append(done, a.ID)
			continue
		}
		if claim, inflight := b.inflight[a.ID]; inflight {
			waited = append(waited, work{a: a, claim: claim})
			continue
		}
		if b.claimed[a.ID] {
			continue
		}
		claim := newInflightClaim()
		b.inflight[a.ID] = claim
		b.claimed[a.ID] = true
		todo = append(todo, work{a: a, claim: claim})
	}
	b.claimsMu.Unlock()

	for _, w := range waited {
		isDone, takeover := b.awaitClaim(w.a, w.claim)
		if isDone {
			done = append(done, w.a.ID)
		} else {
			todo = append(todo, work{a: w.a, claim: takeover})
		}
	}

	for _, w := range todo {
		decision, ok := ChooseAutoDecision(w.a, b.AutoApprove, b.AutoAllowOnce)
		if !ok {
			b.claimsMu.Lock()
			warned := b.warned[w.a.ID]
			b.warned[w.a.ID] = true
			b.claimsMu.Unlock()
			b.failClaim(w.a.ID, w.claim)
			if !warned {
				b.logger.Warn("telegram approval offers no forever option; skipping auto-decision",
					"approval_id", w.a.ID, "kind", w.a.Kind, "scope", w.a.Scope, "title", w.a.Title)
			}
			continue
		}
		if err := b.decider.Decide(ctx, w.a.ID, decision); err != nil {
			b.logger.Warn("telegram auto-decide failed; claim released",
				"approval_id", w.a.ID, "err", b.summarize(err.Error()))
			b.failClaim(w.a.ID, w.claim)
			continue
		}
		if b.recordClaim(w.a, decision, w.claim) {
			done = append(done, w.a.ID)
		}
	}
	return done
}

// awaitClaim waits for another owner's in-flight claim to
// settle, following up to claimChainMax - 1 takeover hops
// (src/muse_cli/tgbot.py:1532-1567, _await_claim). It reports
// (done, nil) when the claim settled with a decision, and
// (false, takeover) when this caller owns the claim now.
func (b *Bot) awaitClaim(a Approval, claim *inflightClaim) (bool, *inflightClaim) {
	current := claim
	hops := 0
	for {
		timer := time.NewTimer(b.claimWait)
		settled := false
		select {
		case <-current.done:
			settled = true
		case <-timer.C:
		}
		timer.Stop()

		b.claimsMu.Lock()
		if current.decision != nil {
			b.claimsMu.Unlock()
			return true, nil
		}
		next := b.inflight[a.ID]
		if next != nil && next != current {
			hops++
			if hops < claimChainMax {
				current = next
				b.claimsMu.Unlock()
				continue
			}
			next.superseded = true
			current.superseded = true
		}
		if !settled {
			current.superseded = true
		}
		if b.inflight[a.ID] == current {
			delete(b.inflight, a.ID)
		}
		b.claimed[a.ID] = true
		takeover := newInflightClaim()
		b.inflight[a.ID] = takeover
		b.claimsMu.Unlock()
		return false, takeover
	}
}

// recordClaim records a decision and settles the claim
// (src/muse_cli/tgbot.py:1582-1597, _record_claim). It returns
// false when the claim was superseded: the decision still
// happened, but the superseding owner records it, so this
// caller must not report the id as decided-by-it.
func (b *Bot) recordClaim(a Approval, decision string, claim *inflightClaim) bool {
	b.claimsMu.Lock()
	defer b.claimsMu.Unlock()
	if claim.superseded {
		claim.failed = true
		claim.settle()
		return false
	}
	b.decided[a.ID] = decision
	claim.decision = &decision
	b.autoLog = append(b.autoLog, AutoLogEntry{
		Time:       time.Now(),
		ApprovalID: a.ID,
		Title:      a.Title,
		Decision:   decision,
		Kind:       a.Kind,
		Scope:      a.Scope,
	})
	if len(b.autoLog) > 51 {
		b.autoLog = b.autoLog[len(b.autoLog)-51:]
	}
	if b.inflight[a.ID] == claim {
		delete(b.inflight, a.ID)
	}
	claim.settle()
	return true
}

// failClaim releases a claim after a failed decide
// (src/muse_cli/tgbot.py:1599-1605, _fail_claim), so a retry
// can take it over.
func (b *Bot) failClaim(id string, claim *inflightClaim) bool {
	b.claimsMu.Lock()
	defer b.claimsMu.Unlock()
	if claim.superseded {
		claim.failed = true
		claim.settle()
		return false
	}
	claim.failed = true
	if b.inflight[id] == claim {
		delete(b.inflight, id)
	}
	delete(b.claimed, id)
	claim.settle()
	return true
}

// AutoLog returns a copy of the auto-decision log.
func (b *Bot) AutoLog() []AutoLogEntry {
	b.claimsMu.Lock()
	defer b.claimsMu.Unlock()
	out := make([]AutoLogEntry, len(b.autoLog))
	copy(out, b.autoLog)
	return out
}

// NotifyPending auto-decides newly pending approvals, notifies
// the chat once per decided approval, then sends undecidable
// approvals as buttons — unless a turn is running, in which
// case it returns early and never notifies later for those ids
// (src/muse_cli/tgbot.py:1630-1701, on_pending). The early
// return is deliberate: a pending approval that arrives during
// a turn stays un-notified until the next on_pending call with
// a fresh pending list; the bot keeps no reminder queue.
func (b *Bot) NotifyPending(ctx context.Context, chatID int64, items []Approval) error {
	remaining := items
	if b.AutoApprove {
		var fresh []Approval
		b.claimsMu.Lock()
		for _, d := range items {
			if _, decided := b.decided[d.ID]; !decided {
				fresh = append(fresh, d)
			}
		}
		b.claimsMu.Unlock()
		decidedIDs := b.ApproveForever(ctx, fresh)
		decidedSet := make(map[string]bool, len(decidedIDs))
		for _, id := range decidedIDs {
			decidedSet[id] = true
		}
		if b.anyActiveTurn() {
			return nil
		}
		b.claimsMu.Lock()
		decisions := make(map[string]string, len(b.decided))
		for id, dec := range b.decided {
			decisions[id] = dec
		}
		var toNotify []Approval
		for _, d := range fresh {
			if decidedSet[d.ID] && !b.notified[d.ID] {
				b.notified[d.ID] = true
				toNotify = append(toNotify, d)
			}
		}
		b.claimsMu.Unlock()
		for _, d := range toNotify {
			label := "always"
			if dec, ok := decisions[d.ID]; ok && dec != DecisionForever {
				label = "once"
			}
			title := d.Title
			if title == "" {
				title = d.ID
			}
			if _, err := b.Send(ctx, chatID, "✅ Auto-approved ("+label+"): "+EscapeText(title), SendOptions{Silent: true}); err != nil {
				b.logger.Warn("telegram auto-approval notify failed", "err", b.summarize(err.Error()))
			}
		}
		var undecidable []Approval
		for _, d := range items {
			if _, decided := b.decided[d.ID]; decided {
				continue
			}
			if _, ok := ChooseAutoDecision(d, true, b.AutoAllowOnce); ok {
				continue
			}
			undecidable = append(undecidable, d)
		}
		remaining = undecidable
		if len(remaining) == 0 {
			return nil
		}
	}
	if b.anyActiveTurn() {
		return nil
	}
	for _, d := range remaining {
		b.claimsMu.Lock()
		if b.notified[d.ID] {
			b.claimsMu.Unlock()
			continue
		}
		b.notified[d.ID] = true
		b.claimsMu.Unlock()
		markup := b.ApprovalMarkup(d, ResumeTriple{})
		if _, err := b.Send(ctx, chatID, ApprovalText(d), SendOptions{Markup: markup}); err != nil {
			b.logger.Warn("telegram pending approval notify failed", "err", b.summarize(err.Error()))
		}
	}
	return nil
}
