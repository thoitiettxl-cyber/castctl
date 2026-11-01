// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package commands

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	"github.com/go-telegram/bot/models"

	"github.com/thoitiettxl-cyber/castctl/internal/approvals"
	"github.com/thoitiettxl-cyber/castctl/internal/conn"
	"github.com/thoitiettxl-cyber/castctl/internal/deliver"
	"github.com/thoitiettxl-cyber/castctl/internal/logging"
	"github.com/thoitiettxl-cyber/castctl/internal/profile"
	"github.com/thoitiettxl-cyber/castctl/internal/telegram"
	"github.com/thoitiettxl-cyber/castctl/internal/wait"
)

// The Telegram turn runner: one Muse turn per Telegram chat,
// following Python 0.6.1's run_turn / _follow / finish_turn
// (src/muse_cli/tgbot.py:1131-1203, 1283-1301, 1303-1490,
// surveyed, reimplemented) over castctl's own send/wait seams
// (deliverSend + executeWait), never a sleep+history poll loop.
//
// One turn, in order: resolve the chat's session mapping from
// the state file; send the streaming bubble; deliver the text
// on a leased gateway connection held until the turn ends
// (closing it early can drop the chat.stream request); follow
// with the wait Runner, streaming live deltas into the bubble
// through the OnEvent seam; deliver the final reply from the
// wait Result (history re-read, never the streamed preview);
// advance the watermark, capped at the last seq delivered.
//
// Differences from Python, all deliberate:
//   - No history-poll fallback for side chats that deliver no
//     live deltas (Python _tick_turn / set_partial_from_history):
//     without deltas the bubble keeps its initial text until
//     final delivery, which is still correct. The fallback is
//     NOT DONE in PR-A (see the PR body).
//   - No live-media freeze/send (delta.presentation is ignored
//     by the preview): media is PR-B work.
//   - The turn timeout is Python's TURN_TIMEOUT (6h); /stop is
//     the escape hatch, and process cancellation ends the wait.
//   - User-facing turn errors use fixed templates by error
//     class, never error text: raw server bodies never reach a
//     chat message (the tree's structural output rule).
//   - A fresh reply is delivered every turn: deliverSend's
//     two-window baseline ack (loop-2 F10) means the previous
//     turn's replies can never resurface as this turn's (the
//     Python reply-reuse bug is not reproduced).
//
// Lifetime: the heartbeat is owned by the bot process (started
// once in cmdTelegramRun), not per turn: concurrent turns on
// one Muse share it, and no turn can stop another's heartbeat
// (executeWait's externalHeartbeat). The send lease is per
// turn. Turns run in their own goroutine (startTurn): the
// dispatcher's per-chat worker calls the handler synchronously,
// so a synchronous turn would block the worker and /stop could
// never run while a turn is active. At most one turn runs per
// chat; a second message while one is active gets the busy
// reply instead of queueing a second turn behind it.

// telegramTurnTimeout bounds one follow, as in Python
// (TURN_TIMEOUT = 6h, tgbot.py:1131).
const telegramTurnTimeout = 6 * time.Hour

// telegramTurnDeps are the turn runner's dependencies. Toggles
// returns the CURRENT effective auto-approve pair (telegram
// block overlaid with runtime state toggles) on every call, so
// a /autoapprove change applies to the next turn without a
// restart. TurnTimeout 0 means telegramTurnTimeout; AckTimeout
// 0 means 30s (the deliverSend ack wait).
type telegramTurnDeps struct {
	env         *Env
	bot         *telegram.Bot
	rt          *Runtime
	prof        *profile.Profile
	store       *telegram.StateStore
	logger      *slog.Logger
	toggles     func() (autoApprove, allowOnce bool)
	turnTimeout time.Duration
	ackTimeout  time.Duration
}

// telegramTurnRunner runs turns and tracks the active turn per
// chat for /stop. It is safe for concurrent use across chats;
// the dispatcher already serialises within one chat.
type telegramTurnRunner struct {
	deps telegramTurnDeps

	stopsMu sync.Mutex
	stops   map[int64]*telegramStopEntry

	// active tracks chats with a turn goroutine running
	// (startTurn's guard). It is separate from stops: the stop
	// entry exists only inside runTextTurn, while active spans
	// the whole goroutine lifetime.
	activeMu sync.Mutex
	active   map[int64]struct{}

	// live tracks each running turn's streaming preview, for
	// the /status "Now:" line. It is separate from active: a
	// resume-follow also registers its preview here.
	liveMu sync.Mutex
	live   map[int64]*streamPreview

	// resumed records, per chat, the AfterSeq of the last
	// resume-follow that reached its wait: a stale resume
	// triple (an approval button tapped after its turn
	// already resumed) must not re-fire from the same seq.
	// Process-memory only, like the claim state.
	resumeMu sync.Mutex
	resumed  map[int64]int64
}

type telegramStopEntry struct {
	cancel  context.CancelFunc
	stopped atomic.Bool
}

func newTelegramTurnRunner(deps telegramTurnDeps) *telegramTurnRunner {
	if deps.turnTimeout <= 0 {
		deps.turnTimeout = telegramTurnTimeout
	}
	if deps.ackTimeout <= 0 {
		deps.ackTimeout = 30 * time.Second
	}
	return &telegramTurnRunner{deps: deps, stops: map[int64]*telegramStopEntry{}, active: map[int64]struct{}{}, live: map[int64]*streamPreview{}, resumed: map[int64]int64{}}
}

// clearActive releases a chat's active-turn slot.
func (r *telegramTurnRunner) clearActive(chatID int64) {
	r.activeMu.Lock()
	delete(r.active, chatID)
	r.activeMu.Unlock()
}

// recoverTurnPanic logs a panic from a turn goroutine instead of
// crashing the process: turn goroutines run outside the
// dispatcher's per-update recover, so a panic here (for example
// a callback-registry Register failure while building buttons)
// must be contained. The defers in runTextTurn/runResume still
// run during the unwind, so turn bookkeeping is released.
func (r *telegramTurnRunner) recoverTurnPanic(chatID int64) {
	if rec := recover(); rec != nil {
		r.deps.logger.Error("telegram turn goroutine panicked", "chat_id", chatID, "panic", fmt.Sprint(rec))
	}
}

// liveTurn returns the running turn's preview for a chat, if any.
func (r *telegramTurnRunner) liveTurn(chatID int64) (*streamPreview, bool) {
	r.liveMu.Lock()
	defer r.liveMu.Unlock()
	p, ok := r.live[chatID]
	return p, ok
}

func (r *telegramTurnRunner) registerLive(chatID int64, p *streamPreview) {
	r.liveMu.Lock()
	r.live[chatID] = p
	r.liveMu.Unlock()
}

func (r *telegramTurnRunner) unregisterLive(chatID int64, p *streamPreview) {
	r.liveMu.Lock()
	if r.live[chatID] == p {
		delete(r.live, chatID)
	}
	r.liveMu.Unlock()
}

// startTurn launches a text turn in its own goroutine and
// returns immediately, so the dispatcher's per-chat worker
// stays free for /stop while the turn runs. At most one turn
// runs per chat: a second message while one is active gets the
// busy reply. The turn inherits the handler ctx: process
// shutdown cancels it, and the process does not wait for
// in-flight turns before exiting (documented in the PR body).
func (r *telegramTurnRunner) startTurn(ctx context.Context, chatID int64, text string) {
	r.activeMu.Lock()
	if _, busy := r.active[chatID]; busy {
		r.activeMu.Unlock()
		_, _ = r.deps.bot.Send(ctx, chatID, "⏳ Muse is already working in this chat. Use /stop to interrupt it.", telegram.SendOptions{Mode: telegram.HTMLModePlain})
		return
	}
	r.active[chatID] = struct{}{}
	r.activeMu.Unlock()
	go func() {
		defer r.clearActive(chatID)
		defer r.recoverTurnPanic(chatID)
		if err := r.runTextTurn(ctx, chatID, text); err != nil {
			r.deps.logger.Error("telegram turn failed", "err", logging.SummarizeErr(err))
		}
	}()
}

// resumeSlotWait bounds how long a scheduled resume waits for
// the chat's active-turn slot: the usual holder is the deciding
// turn itself, still in teardown (watermark save) when its
// buttons were just shown, so a tap in that window must wait
// out the teardown rather than drop the follow. A genuinely
// busy chat (a new turn started) never frees the slot in time,
// and the stale-triple guard drops the resume then.
const resumeSlotWait = 5 * time.Second

// startResume schedules a resume-follow in its own goroutine
// under the same one-turn-per-chat guard as startTurn, so the
// dispatcher's per-chat worker stays free for /stop while the
// follow runs (a synchronous follow would block the worker for
// up to the 6h turn timeout, and /stop sent mid-follow would
// queue behind the very turn it must interrupt). The slot is
// waited for briefly inside the goroutine: the deciding turn
// usually still holds it while its final edit's watermark save
// completes, and dropping the follow in that window would
// strand the decision (the buttons are cleared after a
// decide). The decide→resume ordering is preserved — the
// decision already happened in cbDecide before this is called.
// A stale triple is dropped: if a turn is already active for
// the chat when the slot frees, or a follow already ran from
// this AfterSeq, the resume does not re-fire.
func (r *telegramTurnRunner) startResume(ctx context.Context, info telegram.ResumeInfo) error {
	chatID := info.ChatID
	go func() {
		acquired := false
		defer func() {
			if acquired {
				r.clearActive(chatID)
			}
		}()
		defer r.recoverTurnPanic(chatID)
		deadline := time.Now().Add(resumeSlotWait)
		for {
			r.activeMu.Lock()
			_, busy := r.active[chatID]
			if !busy {
				r.active[chatID] = struct{}{}
				acquired = true
				r.activeMu.Unlock()
				break
			}
			r.activeMu.Unlock()
			if ctx.Err() != nil || time.Now().After(deadline) {
				return
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(10 * time.Millisecond):
			}
		}
		if r.deps.bot.HasActiveTurn(chatID) {
			return
		}
		r.resumeMu.Lock()
		last, seen := r.resumed[chatID]
		r.resumeMu.Unlock()
		if seen && info.AfterSeq <= last {
			return
		}
		if err := r.runResume(ctx, info); err != nil {
			r.deps.logger.Error("telegram resume failed", "err", logging.SummarizeErr(err))
		}
	}()
	return nil
}

// registerStop records a turn's cancel func; unregisterStop
// removes it only when it is still the recorded entry.
func (r *telegramTurnRunner) registerStop(chatID int64, cancel context.CancelFunc) *telegramStopEntry {
	entry := &telegramStopEntry{cancel: cancel}
	r.stopsMu.Lock()
	r.stops[chatID] = entry
	r.stopsMu.Unlock()
	return entry
}

func (r *telegramTurnRunner) unregisterStop(chatID int64, entry *telegramStopEntry) {
	r.stopsMu.Lock()
	if r.stops[chatID] == entry {
		delete(r.stops, chatID)
	}
	r.stopsMu.Unlock()
}

// stopTurn cancels the chat's active turn (if any) and asks the
// server to cancel it (chat.cancel for the chat's current
// session). It reports whether the server said anything was
// running. Queued updates are NOT dropped in PR-A: the
// dispatcher has no per-chat drop API (NOT DONE, see PR body).
func (r *telegramTurnRunner) stopTurn(ctx context.Context, chatID int64) (bool, error) {
	r.stopsMu.Lock()
	entry := r.stops[chatID]
	r.stopsMu.Unlock()
	if entry != nil {
		entry.stopped.Store(true)
		entry.cancel()
	}
	scope := ""
	if mapping, ok := r.deps.store.Chat(chatID); ok {
		scope = mapping.SessionID
	}
	var cancelled bool
	err := r.deps.rt.Muse.WithGateway(ctx, func(gw conn.Gateway) error {
		res, err := deliver.StopTurn(ctx, gw, scope)
		if err != nil {
			return err
		}
		if m, ok := res.(map[string]any); ok {
			cancelled, _ = m["cancelled"].(bool)
		}
		return nil
	})
	if err != nil {
		return false, err
	}
	return cancelled, nil
}

// runTextTurn runs one turn for a plain message (or a
// question-button value, which Python sends as ordinary user
// text). A fresh reply is delivered per turn; errors are
// rendered into the bubble and nil is returned (a failed turn
// must not stop the poll loop: the bot logs handler errors).
func (r *telegramTurnRunner) runTextTurn(ctx context.Context, chatID int64, text string) error {
	mapping, _ := r.deps.store.Chat(chatID)
	scope, title := mapping.SessionID, mapping.Title
	if title == "" {
		title = "main chat"
	}
	turnCtx, cancel := context.WithCancel(ctx)
	entry := r.registerStop(chatID, cancel)
	defer r.unregisterStop(chatID, entry)
	defer cancel()

	r.deps.bot.BeginTurn(chatID)
	defer r.deps.bot.EndTurn(chatID)

	preview := newStreamPreview(time.Now())
	r.registerLive(chatID, preview)
	defer r.unregisterLive(chatID, preview)
	bubbleID, err := r.deps.bot.Send(turnCtx, chatID, "⏳ Sending to Muse…", telegram.SendOptions{Mode: telegram.HTMLModePlain})
	if err != nil {
		// Bubble failure aborts the turn, as in Python: without
		// a bubble there is nowhere to stream to.
		return err
	}
	editor := newBubbleEditor(r.deps.bot, turnCtx, chatID, bubbleID, preview)
	go editor.loop()
	defer editor.finish()

	gw, err := r.deps.rt.Muse.Connect(turnCtx, nil)
	if err != nil {
		editor.editFinal(turnErrorText(err, false))
		return nil
	}
	defer func() { _ = gw.Close() }()
	userSeq, _, err := deliverSend(turnCtx, gw, r.deps.prof, text, scope, r.deps.ackTimeout)
	if err != nil {
		editor.editFinal(turnErrorText(err, entry.stopped.Load()))
		return nil
	}
	if userSeq == nil {
		editor.editFinal("⚠️ Muse did not confirm delivery within 30 s. Check /history before sending again.")
		return nil
	}
	aa, ao := r.deps.toggles()
	res, _, err := executeWait(turnCtx, r.deps.env, r.deps.rt, r.deps.prof, waitRunArgs{
		thread:            scope,
		afterSeq:          userSeq,
		timeout:           r.deps.turnTimeout,
		requireRunning:    true,
		togglesResolved:   &resolvedBotToggles{approve: aa, allowOnce: ao},
		onEvent:           func(ev wait.Event) { preview.feed(ev); editor.signal() },
		externalHeartbeat: true,
	})
	if err != nil {
		editor.editFinal(turnErrorText(err, entry.stopped.Load()))
		return nil
	}
	// The final reply owns the bubble from here: stop streaming
	// edits before delivering, so no streaming edit can land
	// after the final edit (Python Turn.finish).
	editor.finish()
	stopped := entry.stopped.Load()
	if err := r.deliverFinal(turnCtx, chatID, bubbleID, scope, title, *userSeq, res, stopped); err != nil {
		return err
	}
	// Advance the watermark only after delivery succeeded,
	// capped at the last seq this turn delivered.
	if top := deliveredTopSeq(*userSeq, res); top > 0 {
		if err := r.deps.store.SetWatermark(telegram.WatermarkKey(scope), top); err != nil {
			r.deps.logger.Warn("telegram watermark save failed", "err", logging.SummarizeErr(err))
		}
	}
	return nil
}

// runResume follows a turn after a manual approval decision,
// with no new delivery (Python resume_turn, tgbot.py:1205-1222):
// the bubble says Muse is continuing, and the wait follows from
// after_seq. It runs on the goroutine startResume schedules, under
// the active-turn guard; it must never be called synchronously on
// the dispatcher's per-chat worker. The chat comes from
// info.ChatID (set by cbDecide from the update).
func (r *telegramTurnRunner) runResume(ctx context.Context, info telegram.ResumeInfo) error {
	chatID := info.ChatID
	scope, title := info.SessionID, info.Title
	if title == "" {
		title = "main chat"
	}
	turnCtx, cancel := context.WithCancel(ctx)
	entry := r.registerStop(chatID, cancel)
	defer r.unregisterStop(chatID, entry)
	defer cancel()

	r.deps.bot.BeginTurn(chatID)
	defer r.deps.bot.EndTurn(chatID)

	preview := newStreamPreview(time.Now())
	r.registerLive(chatID, preview)
	defer r.unregisterLive(chatID, preview)
	bubbleID, err := r.deps.bot.Send(turnCtx, chatID, "⏳ Muse is continuing…", telegram.SendOptions{Mode: telegram.HTMLModePlain})
	if err != nil {
		return err
	}
	editor := newBubbleEditor(r.deps.bot, turnCtx, chatID, bubbleID, preview)
	go editor.loop()
	defer editor.finish()

	afterSeq := info.AfterSeq
	aa, ao := r.deps.toggles()
	res, _, err := executeWait(turnCtx, r.deps.env, r.deps.rt, r.deps.prof, waitRunArgs{
		thread:            scope,
		afterSeq:          &afterSeq,
		timeout:           r.deps.turnTimeout,
		requireRunning:    false,
		togglesResolved:   &resolvedBotToggles{approve: aa, allowOnce: ao},
		onEvent:           func(ev wait.Event) { preview.feed(ev); editor.signal() },
		externalHeartbeat: true,
	})
	if err != nil {
		editor.editFinal(turnErrorText(err, entry.stopped.Load()))
		return nil
	}
	// The follow reached its wait: record the seq so a stale
	// re-tap of another button from the same turn cannot
	// re-fire this follow. A failed follow records nothing,
	// so it stays retryable.
	r.resumeMu.Lock()
	r.resumed[chatID] = afterSeq
	r.resumeMu.Unlock()
	editor.finish()
	if err := r.deliverFinal(turnCtx, chatID, bubbleID, scope, title, afterSeq, res, entry.stopped.Load()); err != nil {
		return err
	}
	if top := deliveredTopSeq(afterSeq, res); top > 0 {
		if err := r.deps.store.SetWatermark(telegram.WatermarkKey(scope), top); err != nil {
			r.deps.logger.Warn("telegram watermark save failed", "err", logging.SummarizeErr(err))
		}
	}
	return nil
}

// deliveredTopSeq is the watermark cap for a turn: the greatest
// seq this turn delivered (its own user message, or a later
// reply), so a later turn's events already in the history window
// are never skipped.
func deliveredTopSeq(userSeq int64, res *wait.Result) int64 {
	top := userSeq
	for _, reply := range res.Replies {
		if reply.Seq > top {
			top = reply.Seq
		}
	}
	return top
}

// turnErrorText renders a turn failure for the bubble using
// fixed templates by error class only: no error text, and
// therefore no server body, ever reaches a chat message.
func turnErrorText(err error, stopped bool) string {
	var authErr *conn.AuthError
	if errors.As(err, &authErr) {
		return "🔑 muse.ai login expired. Re-export cookies with `castctl auth export` and restart the bot."
	}
	if stopped || errors.Is(err, context.Canceled) {
		return "⏹ Stopped."
	}
	return "⚠️ Could not reach Muse (gateway error). Try again."
}

// bubbleEditor owns the streaming edits of one bubble: at most
// one edit per second, only when the preview changed and the
// rendered text differs, under one lock so the final edit can
// never be overwritten by a streaming edit (Python
// Turn.maybe_edit / finish, tgbot.py:498-518). Only the loop
// goroutine performs edits: the Runner's goroutine signals
// through a non-blocking channel send and never touches the
// network, so a slow or 429-throttled edit cannot stall record
// consumption (the OnEvent seam contract in runner.go).
type bubbleEditor struct {
	bot     *telegram.Bot
	ctx     context.Context
	chatID  int64
	msgID   int
	preview *streamPreview

	mu       sync.Mutex
	finished bool
	shown    string
	lastEdit time.Time
	done     chan struct{}
	loopDone chan struct{}
	signalCh chan struct{}
	stopOnce sync.Once
}

func newBubbleEditor(bot *telegram.Bot, ctx context.Context, chatID int64, msgID int, preview *streamPreview) *bubbleEditor {
	return &bubbleEditor{bot: bot, ctx: ctx, chatID: chatID, msgID: msgID, preview: preview, done: make(chan struct{}), loopDone: make(chan struct{}), signalCh: make(chan struct{}, 1)}
}

// signal wakes the editor loop after a feed. It runs on the
// Runner's goroutine via OnEvent: a non-blocking channel send
// only, never I/O, never a lock. Coalescing is intended: one
// pending signal is enough, the loop re-checks the preview
// on every wake and every tick.
func (e *bubbleEditor) signal() {
	select {
	case e.signalCh <- struct{}{}:
	default:
	}
}

// loop forces an edit attempt every second so the elapsed timer
// keeps moving even between events (Python's _tick_turn cadence,
// without its history poll), and on every signal. It is the
// only goroutine that calls maybeEdit.
func (e *bubbleEditor) loop() {
	defer close(e.loopDone)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-e.done:
			return
		case <-e.signalCh:
			e.maybeEdit()
		case <-ticker.C:
			e.maybeEdit()
		}
	}
}

func (e *bubbleEditor) maybeEdit() {
	e.mu.Lock()
	if e.finished {
		e.mu.Unlock()
		return
	}
	now := time.Now()
	if !e.lastEdit.IsZero() && now.Sub(e.lastEdit) < time.Second {
		e.mu.Unlock()
		return
	}
	text, dirty := e.preview.renderAndClear(now)
	if !dirty || text == e.shown {
		e.mu.Unlock()
		return
	}
	e.lastEdit = now
	e.shown = text
	e.mu.Unlock()
	// EditPlain swallows every error: a failed streaming edit
	// never fails a turn. It runs without the lock: the loop
	// is the only editor, and finish() joins the loop before
	// the final edit, so no streaming edit can land after it.
	_ = e.bot.EditPlain(e.ctx, e.chatID, e.msgID, text)
}

// finish stops streaming edits and joins the loop goroutine,
// so any in-flight edit completes before the final edit; it
// then lands one last partial edit when deltas arrived after
// the last streaming edit, so streamed text is not lost when
// the final edit follows immediately after.
func (e *bubbleEditor) finish() {
	e.stopOnce.Do(func() { close(e.done) })
	<-e.loopDone
	e.mu.Lock()
	e.finished = true
	shown := e.shown
	e.mu.Unlock()
	text, dirty := e.preview.renderAndClear(time.Now())
	if !dirty || text == shown {
		return
	}
	e.mu.Lock()
	e.shown = text
	e.mu.Unlock()
	_ = e.bot.EditPlain(e.ctx, e.chatID, e.msgID, text)
}

// editFinal replaces the bubble with text (Markdown-converted,
// plain fallback on parse errors, as in Python's edit). It runs
// on a detached context with its own timeout, NOT the turn ctx:
// the error paths call it after the turn ctx was cancelled
// (/stop, shutdown), and an edit on a dead ctx could never land
// — the "⏹ Stopped." confirmation included. When the edit
// fails the text goes out as a fresh message instead; the turn
// still ends successfully.
func (e *bubbleEditor) editFinal(text string) {
	e.finish()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := e.bot.Edit(ctx, e.chatID, e.msgID, text, nil, telegram.HTMLModeMarkdown); err != nil {
		_, _ = e.bot.Send(ctx, e.chatID, text, telegram.SendOptions{Mode: telegram.HTMLModeMarkdown})
	}
}

// deliverFinal delivers a finished turn into the bubble (first
// piece) and follow-up messages (the rest), with outcome notes
// and buttons. The text comes from the wait Result only: the
// streamed preview is never used as reply text. A document
// attachment for very long replies (Python needs_document) is
// NOT DONE in PR-A: long replies split into messages instead,
// with no attachment claim.
func (r *telegramTurnRunner) deliverFinal(ctx context.Context, chatID int64, bubbleID int, scope, title string, userSeq int64, res *wait.Result, stopped bool) error {
	finalText := res.FinalText
	if finalText == "" {
		finalText = joinReplyTexts(res.Replies)
	}
	notes := outcomeNotes(res, stopped)
	var text string
	switch {
	case finalText != "" && notes != "":
		text = finalText + "\n\n" + notes
	case finalText != "":
		text = finalText
	case notes != "":
		text = notes
	case res.Outcome == "done" || res.Outcome == "needs_input":
		text = "(no reply text)"
	default:
		text = "(done)"
	}
	markup := r.finalMarkup(res, scope, title, userSeq)
	pieces := telegram.SplitText(text)
	for i, piece := range pieces {
		last := i == len(pieces)-1
		var pieceMarkup models.ReplyMarkup
		if last {
			pieceMarkup = markup
		}
		if i == 0 {
			if err := r.deps.bot.Edit(ctx, chatID, bubbleID, piece, pieceMarkup, telegram.HTMLModeMarkdown); err != nil {
				if _, err := r.deps.bot.Send(ctx, chatID, piece, telegram.SendOptions{Markup: pieceMarkup, Mode: telegram.HTMLModeMarkdown}); err != nil {
					return err
				}
			}
			continue
		}
		if _, err := r.deps.bot.Send(ctx, chatID, piece, telegram.SendOptions{Markup: pieceMarkup, Mode: telegram.HTMLModeMarkdown}); err != nil {
			return err
		}
	}
	return nil
}

func joinReplyTexts(replies []wait.Reply) string {
	var texts []string
	for _, reply := range replies {
		if strings.TrimSpace(reply.Text) != "" {
			texts = append(texts, reply.Text)
		}
	}
	return strings.Join(texts, "\n\n")
}

// outcomeNotes appends the outcome notes in Python's order
// (tgbot.py:1303-1373, finish_turn): auto-approval notes, the
// needs_input question line, one approval line per pending
// approval, the failed/timeout line, and auto-approve errors.
// Approval ids render in full in chat text (as in Python and in
// the decide-button confirmations); error text never does: only
// the class/length summary.
func outcomeNotes(res *wait.Result, stopped bool) string {
	var notes []string
	for _, rec := range res.AutoApproved {
		label := "always"
		if rec.Decision == approvals.Once {
			label = "once"
		}
		note := "✅ auto-approved (" + label + "): " + rec.Title
		if rec.Kind != "" || rec.Scope != "" {
			note += " [" + rec.Kind + " " + strings.TrimSpace(rec.Scope) + "]"
		}
		notes = append(notes, note)
	}
	switch res.Outcome {
	case "needs_input":
		notes = append(notes, "❓ Muse is asking…")
	case "needs_approval":
		for _, a := range res.Approvals {
			notes = append(notes, "🔐 Approval: "+derefApprovalField(a.Title)+": "+derefApprovalField(a.Question))
		}
	case "failed":
		if stopped {
			notes = append(notes, "⏹ Stopped.")
		} else if res.Status != "" {
			notes = append(notes, "⚠️ Muse's turn ended: "+res.Status)
		} else {
			notes = append(notes, "⚠️ Muse's turn ended.")
		}
	case "timeout":
		notes = append(notes, "⌛ Still running after 6h…")
	}
	for _, e := range res.AutoApproveErrors {
		if e == nil {
			continue
		}
		notes = append(notes, "⚠️ could not auto-approve "+e.ApprovalID+": "+logging.SummarizeErr(e.Err))
	}
	return strings.Join(notes, "\n")
}

func derefApprovalField(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// finalMarkup builds the turn-end buttons: question-option
// buttons for needs_input, one approval row per pending approval
// for needs_approval. Nil for every other outcome.
func (r *telegramTurnRunner) finalMarkup(res *wait.Result, scope, title string, userSeq int64) models.ReplyMarkup {
	switch res.Outcome {
	case "needs_input":
		if len(res.Replies) == 0 {
			return nil
		}
		options := questionOptions(res.Replies[len(res.Replies)-1])
		if len(options) == 0 {
			return nil
		}
		var rows [][]models.InlineKeyboardButton
		for _, opt := range options {
			rows = append(rows, []models.InlineKeyboardButton{{
				Text:         telegram.ButtonText(opt.label),
				CallbackData: r.deps.bot.Registry().Register(telegram.CallbackEntry{Action: "answer", Answer: opt.value}),
			}})
		}
		return models.InlineKeyboardMarkup{InlineKeyboard: rows}
	case "needs_approval":
		if len(res.Approvals) == 0 {
			return nil
		}
		var rows [][]models.InlineKeyboardButton
		for _, a := range res.Approvals {
			approval := approvalsToTelegram(a)
			markup := r.deps.bot.ApprovalMarkup(approval, telegram.ResumeTriple{SessionID: scope, Title: title, AfterSeq: &userSeq})
			rows = append(rows, markup.InlineKeyboard...)
		}
		return models.InlineKeyboardMarkup{InlineKeyboard: rows}
	default:
		return nil
	}
}

// approvalsToTelegram converts a wait-core description to the
// Telegram approval shape (the two DescribeApproval functions
// normalise the same server fields; the Telegram shape uses
// plain values).
func approvalsToTelegram(a approvals.DescribedApproval) telegram.Approval {
	var expires int64
	if a.ExpiresAtMS != nil {
		expires = int64(*a.ExpiresAtMS)
	}
	return telegram.Approval{
		ID:          derefApprovalField(a.ApprovalID),
		Title:       derefApprovalField(a.Title),
		Question:    derefApprovalField(a.Question),
		Kind:        derefApprovalField(a.Kind),
		Scope:       derefApprovalField(a.Scope),
		Why:         derefApprovalField(a.Why),
		ExpiresAtMS: expires,
		Options:     a.Options,
	}
}

// questionOption is one button: the label shown and the value
// sent to Muse as a new turn when tapped.
type questionOption struct {
	label string
	value string
}

// questionOptions derives the question buttons for a
// needs_input reply (tgbot.py:200-220, question_options), in
// priority order: (1) the first widget with non-empty options
// across ALL widgets in the last reply, at most 10; (2) a
// numbered/bulleted list (2-8 items) parsed from the reply
// tail; (3) the generic Yes/No/Go-ahead set.
func questionOptions(last wait.Reply) []questionOption {
	for _, w := range last.Widgets {
		if opts := widgetOptions(w); len(opts) > 0 {
			return opts
		}
	}
	if opts := listOptions(last.Text); len(opts) > 0 {
		return opts
	}
	return []questionOption{
		{label: "👍 Yes", value: "Yes"},
		{label: "👎 No", value: "No"},
		{label: "▶️ Go ahead", value: "Go ahead"},
	}
}

// widgetOptions reads one widget's options: a list of strings,
// dicts, or other scalars. Dicts use the Python key orders
// (label: label/text/title/value; value: value/label/text/
// title); other scalars stringify as Python str(o) does; nil
// and composites carry no label and are skipped. Options with
// an empty label are filtered before the 10-cap, as in
// Python. At most 10 options.
func widgetOptions(w wait.Widget) []questionOption {
	list, ok := w.Options.([]any)
	if !ok {
		return nil
	}
	var opts []questionOption
	for _, raw := range list {
		if len(opts) >= 10 {
			break
		}
		label := optionLabel(raw)
		if label == "" {
			continue
		}
		opts = append(opts, questionOption{label: label, value: optionValue(raw)})
	}
	return opts
}

// optionLabel mirrors Python option_label: a dict's first
// non-empty label/text/title/value, a plain string itself, or
// the string form of another scalar (number, bool). Nil and
// composite values have no label.
func optionLabel(o any) string {
	switch v := o.(type) {
	case string:
		return v
	case map[string]any:
		return firstWidgetString(v, "label", "text", "title", "value")
	case nil:
		return ""
	default:
		if s, ok := optionScalarString(v); ok {
			return s
		}
		return ""
	}
}

// optionValue mirrors Python option_value: a dict's first
// non-empty value/label/text/title, a plain string itself, or
// the string form of another scalar.
func optionValue(o any) string {
	switch v := o.(type) {
	case string:
		return v
	case map[string]any:
		return firstWidgetString(v, "value", "label", "text", "title")
	case nil:
		return ""
	default:
		if s, ok := optionScalarString(v); ok {
			return s
		}
		return ""
	}
}

// optionScalarString stringifies a JSON scalar as Python str()
// would for option purposes. Slices, maps, and other shapes
// are not scalars here.
func optionScalarString(v any) (string, bool) {
	switch v.(type) {
	case float64, float32, int, int64, int32, uint64, bool:
		return fmt.Sprint(v), true
	default:
		return "", false
	}
}

func firstWidgetString(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if s, ok := m[k].(string); ok && s != "" {
			return s
		}
	}
	return ""
}

// listOptions parses a trailing list block from reply text,
// faithfully to tgbot.py:200-220: the last 12 non-blank lines,
// scanned forward; an option line appends, a non-option line
// after options resets the block unless it ends with "?"
// (a closing question line is tolerated mid-block); 2-8
// items or the generic fallback. More than 8 items is not a
// list at all: the fallback applies, the first 8 are not
// kept.
func listOptions(text string) []questionOption {
	var tail []string
	for _, ln := range strings.Split(text, "\n") {
		if strings.TrimSpace(ln) != "" {
			tail = append(tail, ln)
		}
	}
	if len(tail) > 12 {
		tail = tail[len(tail)-12:]
	}
	var found []string
	for _, ln := range tail {
		if item, ok := parseListItem(ln); ok {
			found = append(found, item)
		} else if len(found) > 0 && !strings.HasSuffix(strings.TrimSpace(ln), "?") {
			found = nil
		}
	}
	if len(found) < 2 || len(found) > 8 {
		return nil
	}
	opts := make([]questionOption, 0, len(found))
	for _, f := range found {
		opts = append(opts, questionOption{label: f, value: f})
	}
	return opts
}

// parseListItem extracts a list item's text per Python _OPT_RE
// (tgbot.py:198): optional leading whitespace, then a marker —
// 1-2 digits or one A-H letter, optionally "(" -prefixed,
// followed by "." or ")"; or a -, •, * bullet — then REQUIRED
// whitespace, then 1-80 runes. Markup chars [*_`] are stripped
// from the item, which is then re-trimmed.
func parseListItem(line string) (string, bool) {
	runes := []rune(line)
	i := 0
	for i < len(runes) && unicode.IsSpace(runes[i]) {
		i++
	}
	if i >= len(runes) {
		return "", false
	}
	rest := runes[i:]
	// Bullet alternative: no paren, no terminator.
	if rest[0] == '-' || rest[0] == '•' || rest[0] == '*' {
		return parseListItemRest(rest[1:])
	}
	j := 0
	if rest[0] == '(' {
		j = 1
	}
	start := j
	if j < len(rest) && rest[j] >= '0' && rest[j] <= '9' {
		for j < len(rest) && j-start < 2 && rest[j] >= '0' && rest[j] <= '9' {
			j++
		}
	} else if j < len(rest) && ((rest[j] >= 'A' && rest[j] <= 'H') || (rest[j] >= 'a' && rest[j] <= 'h')) {
		j++
	} else {
		return "", false
	}
	if j >= len(rest) || (rest[j] != '.' && rest[j] != ')') {
		return "", false
	}
	return parseListItemRest(rest[j+1:])
}

// parseListItemRest validates the item text after a marker:
// required whitespace, then 1-80 runes after stripping
// [*_`] and trimming.
func parseListItemRest(after []rune) (string, bool) {
	if len(after) == 0 || !unicode.IsSpace(after[0]) {
		return "", false
	}
	k := 0
	for k < len(after) && unicode.IsSpace(after[k]) {
		k++
	}
	item := strings.TrimSpace(string(after[k:]))
	item = strings.Map(func(r rune) rune {
		if r == '*' || r == '_' || r == '`' {
			return -1
		}
		return r
	}, item)
	item = strings.TrimSpace(item)
	if n := len([]rune(item)); n < 1 || n > 80 {
		return "", false
	}
	return item, true
}
