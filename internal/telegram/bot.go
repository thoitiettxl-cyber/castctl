// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package telegram

// The Telegram bot: polling via go-telegram/bot, an allowlist
// middleware, per-chat serial dispatch, update_id dedupe, and the
// send/edit surface mirrored from Python 0.6.1. Every mirrored
// behaviour cites its Python file:line; deliberate deviations are
// marked [DEVIATION] in the doc comments.
//
// Library construction (pinned commit f53bfe55; see the libpin
// report): WithHTTPClient with a writer-built client whose
// Transport.Proxy is explicitly nil (the library default client's
// nil Transport silently inherits the stdlib env proxy),
// WithNotAsyncHandlers + WithWorkers(1) for serial dispatch,
// WithAllowedUpdates restricted to message + callback_query,
// a custom errors handler (the default logs errors verbatim,
// including raw payloads; the default handler is registered
// but unreachable behind the match-all handler), and GetMe at
// construction (no SkipGetMe:
// Python's Bot.run calls getMe at startup,
// src/muse_cli/tgbot.py:2465). The per-chat serialising dispatcher
// and the update_id dedupe store are writer code: the library
// provides neither. There is no recover in the library, so the
// recover middleware and the dispatcher worker recover are
// writer code too.
//
// [DEVIATION] Dedupe: Python 0.6.1 has NO duplicate-update handling
// (src/muse_cli/tgbot.py:2435-2462, absence inspected); a
// redelivered update would be handled twice. This bot drops
// redelivered update_ids (in-memory seen set). The dedupe state
// is lost on restart, like every other in-memory registry here;
// the persisted offset (state.go) bounds redelivery to what the
// server replays below the confirmed offset.
// Offset persistence: Python saves offset = update_id + 1 to
// telegram-state.json BEFORE handling each update
// (tgbot.py:2454-2457). This build persists the maximum handled
// update_id itself (the library adds 1 when resuming) through
// the OnOffset hook, marked at enqueue before handling, in the
// state file (state.go). A crash mid-handle loses that update
// instead of redelivering it, exactly as in Python.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/go-telegram/bot"
	"github.com/go-telegram/bot/models"
)

// PollTimeout is the long-poll duration passed to WithHTTPClient:
// Python polls getUpdates with timeout=25
// (src/muse_cli/tgbot.py:2438-2439); the library sends
// pollTimeout - 1s as the timeout parameter, so 26s here sends
// exactly 25s.
const PollTimeout = 26 * time.Second

// ClientTimeout bounds the bot's HTTP client: Python uses a 40s
// HTTP timeout for getUpdates (src/muse_cli/tgapi.py:84-86,
// _http_timeout=40 in poll_once via call defaults). It must
// exceed PollTimeout or the client aborts every long poll early.
const ClientTimeout = 40 * time.Second

// botTokenShape mirrors Python's token check
// (src/muse_cli/tgapi.py:49-52).
var botTokenShape = regexp.MustCompile(`^[0-9]+:[A-Za-z0-9_-]{20,}$`)

// HTMLMode selects the Send/Edit body mode (Python's html
// parameter: True / "md" / False, src/muse_cli/tgbot.py:703).
type HTMLMode int

const (
	// HTMLModeHTML means the text is already HTML (Python html=True).
	HTMLModeHTML HTMLMode = iota
	// HTMLModePlain means plain text, never parsed as HTML (Python html=False).
	HTMLModePlain
	// HTMLModeMarkdown means Markdown converted by MDToHTML (Python html="md").
	HTMLModeMarkdown
)

// SendOptions mirrors Bot.send's parameters
// (src/muse_cli/tgbot.py:703-712).
type SendOptions struct {
	// Markup is attached only to the last piece of a split send.
	Markup models.ReplyMarkup
	// Mode selects HTML / plain / Markdown handling.
	Mode HTMLMode
	// ReplyTo, when non-zero, is passed to every piece.
	ReplyTo int
	// Silent sends without a notification.
	Silent bool
}

// MessageContext is one plain message delivered to the message
// handler.
type MessageContext struct {
	ChatID    int64
	UserID    int64
	Text      string
	MessageID int
}

// MessageHandlerFunc handles a plain allowlisted message. It runs
// on the chat's dispatcher worker; an error is logged, never
// propagated (a failed turn must not stop the poll loop).
type MessageHandlerFunc func(ctx context.Context, mc MessageContext) error

// Decider decides one approval: the Go side of
// cli.decide_approval (src/muse_cli/cli.py:1097-1100: gateway
// egress.approval.decide with {"decision": decision}). Item 4
// wires no gateway decider; the production command supplies a
// fail-closed decider and the gateway wiring is step-5 work.
type Decider interface {
	Decide(ctx context.Context, approvalID, decision string) error
}

// DeciderFunc adapts a function to Decider.
type DeciderFunc func(ctx context.Context, approvalID, decision string) error

// Decide implements Decider.
func (f DeciderFunc) Decide(ctx context.Context, approvalID, decision string) error {
	return f(ctx, approvalID, decision)
}

// PendingFunc lists pending approvals for approve-all
// (src/muse_cli/tgbot.py:1739-1747 re-reads pending approvals
// from the server via cli._pending).
type PendingFunc func(ctx context.Context) ([]Approval, error)

// ResumeInfo is the resume triple carried by a decide button
// (src/muse_cli/tgbot.py:1725-1737). ChatID is the chat the
// decision came from: the resume closure needs it to send the
// follow bubble, and the button entry carries no chat.
type ResumeInfo struct {
	ChatID    int64
	SessionID string
	Title     string
	AfterSeq  int64
}

// ResumeFunc resumes a turn after a manual approval decision
// (src/muse_cli/tgbot.py:1205-1223, resume_turn). It is called
// only when the button carries a resume triple and no turn is
// active for the chat.
type ResumeFunc func(ctx context.Context, info ResumeInfo) error

// Settings configures a Bot. Token, AllowedUserIDs, and HTTPClient
// are required; everything else has the documented default.
type Settings struct {
	// Token is the bot token (shape-checked, never logged).
	Token string
	// AllowedUserIDs is the sender-id allowlist (required,
	// non-empty; Python tgbot.py:643-648, 989-1000).
	AllowedUserIDs []int64
	// AutoApprove / AutoAllowOnce are the toggles the approval
	// surface reads (from the telegram config block).
	AutoApprove   bool
	AutoAllowOnce bool
	// ServerURL overrides the Bot API base URL. Empty means the
	// library default (https://api.telegram.org). Tests pass
	// the fake server's URL via WithServerURL.
	ServerURL string
	// HTTPClient is the profile-outbound-dialling client
	// (Runtime.HTTPClient / Dialer.HTTPClient in production).
	// It must not consult env proxies: BoundClient rejects a
	// nil Transport and a Transport with a non-nil Proxy.
	HTTPClient *http.Client
	// Logger receives bot log lines (summarised errors only).
	// Nil means discard.
	Logger *slog.Logger
	// Decider decides approvals. Nil means a fail-closed decider
	// that always errors (no gateway wiring in item 4).
	Decider Decider
	// Pending lists approvals for approve-all. Nil means empty.
	Pending PendingFunc
	// Resume resumes turns after decisions. Nil means no resume.
	Resume ResumeFunc
	// CallbackFunc handles registry actions the bot core does not
	// know: question answers, chat-picker paging/open, delete
	// confirms, and other step-5 button surfaces. It returns
	// (handled=true) when it acted (its error, if any, becomes
	// the chat warning, as for decide/approve-all); (handled=false)
	// falls back to the unknown-action log. Nil means no extra
	// actions exist: unknown actions are only logged, exactly as
	// before the hook existed.
	CallbackFunc func(ctx context.Context, chatID int64, messageID int, entry CallbackEntry) (bool, error)
	// MessageHandler handles plain messages. Nil means messages
	// are dropped after the allowlist (no turn wiring in item 4).
	MessageHandler MessageHandlerFunc
	// ClaimWait bounds the in-flight claim wait
	// (claim_wait_seconds = 15, src/muse_cli/tgbot.py:618).
	// Zero means 15s.
	ClaimWait time.Duration
	// Sleep sleeps between 429 retries. Nil means time.Sleep.
	// Tests inject a recorder.
	Sleep func(time.Duration)
	// InitialOffset is the last handled update_id from a previous
	// run in this process (WithInitialOffset: the library adds
	// 1). Zero means start from the beginning.
	InitialOffset int64
	// OnOffset is called with each new maximum update_id, marked
	// before the update is handled (the offset-before-handle
	// order). The production command persists it to the state
	// file. It runs on the poll goroutine under the dispatcher
	// lock: it must be fast, must not block, and must not call
	// back into the Bot. Nil means offsets are tracked in
	// memory only (MaxHandledID).
	OnOffset func(offset int64)
}

// Bot is a polling Telegram bot bound to one profile's outbound
// via its injected HTTP client.
type Bot struct {
	api      *bot.Bot
	token    string
	allowed  map[int64]bool
	logger   *slog.Logger
	registry *CallbackRegistry
	dispatch *dispatcher

	decider      Decider
	pending      PendingFunc
	resume       ResumeFunc
	handler      MessageHandlerFunc
	callbackFunc func(ctx context.Context, chatID int64, messageID int, entry CallbackEntry) (bool, error)
	sleep        func(time.Duration)

	// AutoApprove / AutoAllowOnce are the toggles the approval
	// surface reads (from the telegram config block).
	AutoApprove   bool
	AutoAllowOnce bool

	claimWait time.Duration

	turnsMu sync.Mutex
	turns   map[int64]bool

	claimsMu sync.Mutex
	decided  map[string]string
	// decidedOrder is the insertion order of decided, for
	// oldest-first eviction at decidedCap.
	decidedOrder []string
	// decideInflight marks approval ids with a Decide RPC
	// in flight under decideOnce: a second caller for the
	// same id waits on the channel, then re-checks decided.
	// Guarded by claimsMu; channels are closed, never sent.
	decideInflight map[string]chan struct{}
	claimed        map[string]bool
	inflight       map[string]*inflightClaim
	notified       map[string]bool
	warned         map[string]bool
	autoLog        []AutoLogEntry

	startMu sync.Mutex
	started bool
}

// BoundClient wraps a profile-outbound client for the Telegram
// library: the same Transport (the outbound dial path), an
// explicit Timeout exceeding pollTimeout, no cookie jar, a
// no-follow redirect policy (a redirect is refused as an
// error; the token-bearing path is never sent to a second
// server), and fail-closed rejection of any client that could
// consult env proxies or bypass the outbound: nil Transport
// (the stdlib default transport, env-proxy inheriting),
// a non-nil Proxy, any non-*http.Transport RoundTripper
// (delegating/wrapping transports are rejected outright —
// there is no test-double carve-out), and an *http.Transport
// with no custom dial path at all (nil DialContext and nil
// DialTLSContext: the default direct-dial shape).
//
// Residual, stated honestly: construction-time checks cannot
// prove that an explicitly supplied dial function dials
// through the outbound — a hostile caller that supplies
// explicit direct-dial functions passes this binder. The
// guarantee rests on the production construction path
// (Dialer.HTTPClient, whose transport carries the outbound
// dial functions) plus rejection of the default and wrapped
// shapes above; BoundClient never accepts a transport it
// cannot inspect.
func BoundClient(base *http.Client, pollTimeout time.Duration) (*http.Client, error) {
	if base == nil {
		return nil, errors.New("telegram: HTTP client is required (profile outbound client)")
	}
	if base.Transport == nil {
		return nil, errors.New("telegram: HTTP client has no Transport: refusing the stdlib default transport (env proxy)")
	}
	tr, ok := base.Transport.(*http.Transport)
	if !ok {
		return nil, errors.New("telegram: HTTP client Transport is not an *http.Transport: refusing a delegating/wrapping RoundTripper")
	}
	if tr.Proxy != nil {
		return nil, errors.New("telegram: HTTP client Transport consults proxy environment variables: refusing")
	}
	if tr.DialContext == nil && tr.DialTLSContext == nil {
		return nil, errors.New("telegram: HTTP client Transport has no custom dial path: refusing the default direct-dial transport")
	}
	timeout := base.Timeout
	if timeout == 0 {
		timeout = ClientTimeout
	}
	if timeout <= pollTimeout {
		return nil, fmt.Errorf("telegram: HTTP client timeout %v must exceed the poll timeout %v", timeout, pollTimeout)
	}
	return &http.Client{
		Transport:     tr,
		CheckRedirect: noFollowRedirect,
		Timeout:       timeout,
	}, nil
}

// noFollowRedirect refuses every redirect: the library
// surfaces the refusal as an error through the scrubbed
// error path, and no second server is ever requested.
func noFollowRedirect(_ *http.Request, _ []*http.Request) error {
	return errors.New("telegram: HTTP redirects are not followed")
}

// New constructs a Bot. It performs GetMe (no SkipGetMe) through
// the injected client, so construction fails fast on a rejected
// token, before any polling. No token value appears in any error
// returned here.
func New(s Settings) (*Bot, error) {
	token := strings.TrimSpace(s.Token)
	if !botTokenShape.MatchString(token) {
		return nil, errors.New("telegram: token does not look like a bot token (expected digits, a colon, then 20 or more token characters)")
	}
	if len(s.AllowedUserIDs) == 0 {
		return nil, errors.New("telegram: allowed user ids must not be empty: the bot refuses to start without an allowlist")
	}
	client, err := BoundClient(s.HTTPClient, PollTimeout)
	if err != nil {
		return nil, err
	}
	logger := s.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	decider := s.Decider
	if decider == nil {
		decider = DeciderFunc(func(context.Context, string, string) error {
			return errors.New("telegram: approval decisions are not wired (no decider)")
		})
	}
	pending := s.Pending
	if pending == nil {
		pending = func(context.Context) ([]Approval, error) { return nil, nil }
	}
	sleep := s.Sleep
	if sleep == nil {
		sleep = time.Sleep
	}
	claimWait := s.ClaimWait
	if claimWait <= 0 {
		claimWait = 15 * time.Second
	}
	b := &Bot{
		token:         token,
		allowed:       make(map[int64]bool, len(s.AllowedUserIDs)),
		logger:        logger,
		registry:      NewCallbackRegistry(),
		decider:       decider,
		pending:       pending,
		resume:        s.Resume,
		handler:       s.MessageHandler,
		callbackFunc:  s.CallbackFunc,
		sleep:         sleep,
		claimWait:     claimWait,
		AutoApprove:   s.AutoApprove,
		AutoAllowOnce: s.AutoAllowOnce,
		turns:          make(map[int64]bool),
		decided:        make(map[string]string),
		decideInflight: make(map[string]chan struct{}),
		claimed:       make(map[string]bool),
		inflight:      make(map[string]*inflightClaim),
		notified:      make(map[string]bool),
		warned:        make(map[string]bool),
	}
	for _, id := range s.AllowedUserIDs {
		b.allowed[id] = true
	}
	b.dispatch = newDispatcher(b.processUpdate, b.logPanic)
	b.dispatch.onOffset = s.OnOffset
	// Surface dropped updates: a queue-full or
	// shutdown-abandoned update's offset is already
	// persisted (offset-before-handle), so it is never
	// replayed — this warn log is the only observability
	// for the loss.
	b.dispatch.onDropped = func(total int64) {
		b.logger.Warn("telegram dispatcher dropped update(s)", "dropped_total", total)
	}
	// Seed the in-memory maximum from the persisted offset so
	// MaxHandledID never regresses across a restart and a
	// replayed id at or below the offset reports nothing new.
	// The server-side skip itself is the library's
	// WithInitialOffset above.
	b.dispatch.maxSeen_.Store(s.InitialOffset)
	opts := []bot.Option{
		bot.WithHTTPClient(PollTimeout, client),
		bot.WithNotAsyncHandlers(),
		bot.WithWorkers(1),
		bot.WithAllowedUpdates(bot.AllowedUpdates{models.AllowedUpdateMessage, models.AllowedUpdateCallbackQuery}),
		bot.WithMiddlewares(b.recoverMiddleware, b.allowlistMiddleware),
		bot.WithDefaultHandler(b.defaultHandler),
		bot.WithErrorsHandler(b.errorsHandler),
		bot.WithInitialOffset(s.InitialOffset),
	}
	if s.ServerURL != "" {
		opts = append(opts, bot.WithServerURL(s.ServerURL))
	}
	api, err := bot.New(token, opts...)
	if err != nil {
		return nil, b.scrubErr(fmt.Errorf("telegram: bot construction failed: %w", err))
	}
	b.api = api
	api.RegisterHandlerMatchFunc(func(*models.Update) bool { return true }, b.libraryHandler)
	return b, nil
}

// Registry returns the bot's callback registry (for building
// approval keyboards). Entries are process-memory only.
func (b *Bot) Registry() *CallbackRegistry { return b.registry }

// ApprovalMarkup builds an approval keyboard registered in this
// bot's registry.
func (b *Bot) ApprovalMarkup(d Approval, resume ResumeTriple) models.InlineKeyboardMarkup {
	return ApprovalMarkup(d, resume, b.registry)
}

// ApproveAllMarkup builds the "Always allow all" keyboard.
func (b *Bot) ApproveAllMarkup() models.InlineKeyboardMarkup {
	return ApproveAllMarkup(b.registry)
}

// MaxHandledID returns the largest update_id seen (marked at
// enqueue, before handling — the offset-before-handle order of
// src/muse_cli/tgbot.py:2454-2457).
func (b *Bot) MaxHandledID() int64 { return b.dispatch.maxSeen() }

// Start polls until ctx is done, then drains the dispatcher and
// returns ctx.Err(). SIGINT cancellation therefore surfaces as
// context.Canceled (exit 130 via the command layer), matching
// the process-wide signal contract.
func (b *Bot) Start(ctx context.Context) error {
	b.startMu.Lock()
	if b.started {
		b.startMu.Unlock()
		return errors.New("telegram: bot already started")
	}
	b.started = true
	b.startMu.Unlock()
	defer b.dispatch.shutdown()
	b.api.Start(ctx)
	return ctx.Err()
}

// BeginTurn / EndTurn / HasActiveTurn track per-chat active turns
// (src/muse_cli/tgbot.py:1070-1072, active_turn). Item 4 has no
// turn runner; the production handler marks turns around the
// step-5 turn wiring. Until then no turn is ever active, so
// decide-button resumes always fire.
func (b *Bot) BeginTurn(chatID int64) {
	b.turnsMu.Lock()
	b.turns[chatID] = true
	b.turnsMu.Unlock()
}

// EndTurn clears a chat's active turn.
func (b *Bot) EndTurn(chatID int64) {
	b.turnsMu.Lock()
	delete(b.turns, chatID)
	b.turnsMu.Unlock()
}

// HasActiveTurn reports whether the chat has an active turn.
func (b *Bot) HasActiveTurn(chatID int64) bool {
	b.turnsMu.Lock()
	defer b.turnsMu.Unlock()
	return b.turns[chatID]
}

func (b *Bot) anyActiveTurn() bool {
	b.turnsMu.Lock()
	defer b.turnsMu.Unlock()
	return len(b.turns) > 0
}

func (b *Bot) libraryHandler(ctx context.Context, _ *bot.Bot, upd *models.Update) {
	b.dispatch.enqueue(ctx, upd)
}

func (b *Bot) processUpdate(ctx context.Context, upd *models.Update) {
	switch {
	case upd.CallbackQuery != nil:
		b.onCallback(ctx, upd)
	case upd.Message != nil:
		b.onMessage(ctx, upd)
	default:
		b.logger.Debug("telegram unmatched update", "update_id", upd.ID, "kind", updateKind(upd))
	}
}

func updateKind(upd *models.Update) string {
	switch {
	case upd.Message != nil:
		return "message"
	case upd.CallbackQuery != nil:
		return "callback_query"
	case upd.EditedMessage != nil:
		return "edited_message"
	case upd.ChannelPost != nil:
		return "channel_post"
	default:
		return "other"
	}
}

// senderID extracts the sender's user id for the update kind
// actually dispatched, or 0 when the update carries none
// (src/muse_cli/tgbot.py:989-1000 takes from.id from the
// message or callback_query, or None). The callback sender is
// checked FIRST: processUpdate dispatches CallbackQuery
// before Message, so the allowlist gate must derive the
// sender from the callback when one is present — a combined
// update (message + callback_query, a shape only a
// hostile/compromised response can emit) is gated on the
// callback sender, never on the message sender. Only
// message, callback_query, and edited_message carry a sender
// here; every other kind returns 0 and is dropped by the
// allowlist gate.
func senderID(upd *models.Update) int64 {
	if upd.CallbackQuery != nil {
		return upd.CallbackQuery.From.ID
	}
	if upd.Message != nil && upd.Message.From != nil {
		return upd.Message.From.ID
	}
	if upd.EditedMessage != nil && upd.EditedMessage.From != nil {
		return upd.EditedMessage.From.ID
	}
	return 0
}

// callbackChat returns the chat id and message id of a
// callback query's message, whether it is a regular Message
// or an InaccessibleMessage (date:0, e.g. a group/old or
// deleted message whose buttons are still pressed). It
// reports false when the callback carries no message at all
// (inline messages): the caller then falls back to the
// sender id as the chat, with no message to clear, as in
// Python (tgbot.py:1042-1049: chat_id from message.chat or
// uid, mid from message.message_id).
func callbackChat(cq *models.CallbackQuery) (chatID int64, mid int, ok bool) {
	if cq.Message.Message != nil {
		return cq.Message.Message.Chat.ID, cq.Message.Message.ID, true
	}
	if cq.Message.InaccessibleMessage != nil {
		return cq.Message.InaccessibleMessage.Chat.ID, cq.Message.InaccessibleMessage.MessageID, true
	}
	return 0, 0, false
}

// chatKey is the dispatcher's per-chat serialisation key: the
// message chat, else the callback message chat (regular or
// inaccessible), else the sender.
func chatKey(upd *models.Update) int64 {
	if upd.CallbackQuery != nil {
		if chatID, _, ok := callbackChat(upd.CallbackQuery); ok {
			return chatID
		}
		return senderID(upd)
	}
	if upd.Message != nil {
		return upd.Message.Chat.ID
	}
	return senderID(upd)
}

// allowlistMiddleware is the single update gate
// (src/muse_cli/tgbot.py:989-1000, handle_update): the sender's
// user id only, never chat id or chat type; a missing or
// non-allowlisted sender is dropped silently (no reply, no
// state change), with only an id-only log line.
func (b *Bot) allowlistMiddleware(next bot.HandlerFunc) bot.HandlerFunc {
	return func(ctx context.Context, api *bot.Bot, upd *models.Update) {
		uid := senderID(upd)
		if uid == 0 || !b.allowed[uid] {
			b.logger.Debug("telegram ignored update (not allowed)", "update_id", upd.ID, "user_id", uid)
			return
		}
		next(ctx, api, upd)
	}
}

// recoverMiddleware is the outermost middleware: a handler panic
// must not kill the process (the library has no recover). It
// wraps the library handler only, whose work is enqueueing
// the update: it does NOT protect deferred handler execution
// (the dispatcher recovers per item; that recover is the
// effective one for handler panics). The panic value is
// logged summarised and token-scrubbed, never verbatim.
func (b *Bot) recoverMiddleware(next bot.HandlerFunc) bot.HandlerFunc {
	return func(ctx context.Context, api *bot.Bot, upd *models.Update) {
		defer func() {
			if r := recover(); r != nil {
				b.logPanic(r)
			}
		}()
		next(ctx, api, upd)
	}
}

func (b *Bot) logPanic(r any) {
	b.logger.Error("telegram update panic", "err", b.summarize(fmt.Sprint(r)))
}

// defaultHandler replaces the library default (which logs the
// full update with %+v). It logs ids and kinds only, never
// message content. It is registered as a fallback but is
// unreachable while the match-all handler is registered (the
// match-all handler wins); it is kept only as defence if the
// match-all registration is ever removed, and must not be
// claimed as an active layer.
func (b *Bot) defaultHandler(_ context.Context, _ *bot.Bot, upd *models.Update) {
	b.logger.Debug("telegram unmatched update", "update_id", upd.ID, "kind", updateKind(upd))
}

// errorsHandler replaces the library default (which logs errors
// verbatim, including raw payloads on decode failure). Every
// error renders through summarize as a class/length summary
// only: no verbatim error text — and therefore no server body,
// description, or raw update bytes — reaches a log line at any
// level, whatever the error's shape or size.
func (b *Bot) errorsHandler(err error) {
	b.logger.Error("telegram poll error", "err", b.summarize(err.Error()))
}

// summarize renders an error for a log line as a class/length
// summary only, never verbatim error text. The class label is
// chosen from a small safe vocabulary (library error classes
// and the response/update decode classes) detected in a
// bounded prefix; an unrecognised shape renders with the
// generic class. Detection only selects the label: the bound
// does not depend on it, so an undetected shape is still
// fragment-free. No fragment of the input is ever emitted:
// summarize returns only fixed-vocabulary labels and the
// input's rune count, and carries no method field of any
// kind (no method, op, or api_method field exists in any
// summary output).
// The token is scrubbed out of the examined prefix first
// (a hostile server body may echo it), but no scrub of the
// full text is needed: nothing verbatim is emitted.
//
// Bounded work: summarize inspects only the first 256 runes
// for the class label (one ReplaceAll over that prefix,
// preserving scrub-before-detection order for the examined
// text) plus one allocation-free rune-count pass over the
// whole input for message_length. The count pass is linear
// in the input length, so a multi-megabyte input costs more
// than a short one — one linear pass, not a whole-input
// scrub, SafeString, or rune-slice conversion — and the
// emitted output is always a short fixed-shape summary.
// Classification is untouched: 429 and parse-error
// classification run on the raw error in
// retryCall/isParseError before scrubbing, and summarize is
// log-only. Callers must never log an error by unwrapping
// and printing: the scrubbed error type carries no raw chain
// (see scrubErr), and %+v/%#v of a scrubbed error contain no
// token.
func (b *Bot) summarize(msg string) string {
	length := utf8.RuneCountInString(msg)
	prefix := b.scrub(firstRunes(msg, summarizePrefixRunes))
	class := summarizeClass(prefix)
	switch class {
	case "response decode failure":
		return fmt.Sprintf("telegram poll error: response decode failure message_length=%d", length)
	case "update decode failure":
		return fmt.Sprintf("telegram poll error: update decode failure message_length=%d", length)
	case "":
		return fmt.Sprintf("telegram error: message_length=%d", length)
	default:
		return fmt.Sprintf("telegram error: %s message_length=%d", class, length)
	}
}

// summarizePrefixRunes bounds how much of an error text
// summarize ever inspects for its class label.
const summarizePrefixRunes = 256

// firstRunes returns the first n runes of s without converting
// or scanning the rest: it stops at the nth rune boundary.
func firstRunes(s string, n int) string {
	count := 0
	for i := range s {
		if count == n {
			return s[:i]
		}
		count++
	}
	return s
}

// summarizeClass selects the summary class label from a
// bounded, token-scrubbed prefix of the error text. It returns
// "" for an unrecognised shape. The labels are a fixed
// safe vocabulary: no part of the input text is ever returned.
// Class selection is by substring search in the prefix, so a
// hostile fragment can mis-select the label (e.g. a 400
// description embedding a decode-body phrase renders with
// the response-decode class); the label is fixed-vocabulary
// either way, so no fragment is emitted.
func summarizeClass(prefix string) string {
	if isResponseBodyError(prefix) {
		return "response decode failure"
	}
	if strings.Contains(prefix, "decode update") {
		return "update decode failure"
	}
	for _, sentinel := range []string{
		"too many requests", "bad request", "forbidden",
		"unauthorized", "not found", "conflict",
	} {
		if strings.Contains(prefix, sentinel) {
			return sentinel
		}
	}
	return ""
}

// isResponseBodyError reports whether the examined prefix is
// one of the library's body-carrying errors: its message embeds
// the raw response body, so it must never reach a log line
// verbatim (the logging-PR rule: raw server bodies are never
// emitted anywhere, at any level). In summarize it only
// selects the class label; the bound applies to every shape
// whether or not this matches.
func isResponseBodyError(msg string) bool {
	return strings.Contains(msg, "decode response body") ||
		strings.Contains(msg, "read response body") ||
		strings.Contains(msg, "decode response result")
}

// scrub removes every occurrence of the token from s. The token
// itself is never logged; replacement is the only use.
func (b *Bot) scrub(s string) string {
	if b.token == "" {
		return s
	}
	return strings.ReplaceAll(s, b.token, "***")
}

// scrubErr returns a copy of err with the token scrubbed out
// of the error text AND out of every typed string field that
// can carry server text. The raw chain is NOT preserved:
// returning the original error (or wrapping it) would leave
// the token reachable through errors.As / Unwrap even when
// Error() itself is scrubbed. Instead the copy preserves
// only what step-5 needs: errors.As to *TooManyRequestsError
// (RetryAfter) and *MigrateError (MigrateToChatID), with
// their Message fields scrubbed, and errors.Is to the
// library sentinel classes (bad request / forbidden /
// unauthorized / not found / conflict / too many requests),
// via Unwrap() []error over scrubbed copies and sentinels
// only. No other errors.As target is preserved — in
// particular, errors.As to *url.Error and other transport
// types and errors.Is to context.Canceled and
// context.DeadlineExceeded do not survive scrubbing. A caller
// needing another typed view of a server error must add it
// here, with its string fields scrubbed, rather than
// unwrapping the raw error.
//
// Invariant (never unwrap-and-print): a scrubbed error's
// Error(), %+v, and %#v forms contain no token, and no
// layer reachable from it carries the token; the scrubbed
// copy holds no reference to the original error.
func (b *Bot) scrubErr(err error) error {
	if err == nil {
		return nil
	}
	text := b.scrub(err.Error())
	var unwraps []error
	var tmr *bot.TooManyRequestsError
	if errors.As(err, &tmr) {
		unwraps = append(unwraps, &bot.TooManyRequestsError{
			Message:    b.scrub(tmr.Message),
			RetryAfter: tmr.RetryAfter,
		})
	}
	var mig *bot.MigrateError
	if errors.As(err, &mig) {
		unwraps = append(unwraps, &bot.MigrateError{
			Message:         b.scrub(mig.Message),
			MigrateToChatID: mig.MigrateToChatID,
		})
	}
	for _, sentinel := range []error{
		bot.ErrorBadRequest, bot.ErrorForbidden, bot.ErrorUnauthorized,
		bot.ErrorNotFound, bot.ErrorConflict, bot.ErrorTooManyRequests,
	} {
		if errors.Is(err, sentinel) {
			unwraps = append(unwraps, sentinel)
		}
	}
	return &scrubbedError{text: text, unwraps: unwraps}
}

type scrubbedError struct {
	text    string
	unwraps []error
}

func (e *scrubbedError) Error() string { return e.text }
func (e *scrubbedError) Unwrap() []error {
	return e.unwraps
}

// onMessage delivers a plain message to the message handler.
// Non-text messages are ignored (src/muse_cli/tgbot.py:1013-1027
// falls through when there is no text and no media; media upload
// is not in item 4). A handler error is logged, never propagated.
func (b *Bot) onMessage(ctx context.Context, upd *models.Update) {
	msg := upd.Message
	if msg.Text == "" || b.handler == nil {
		return
	}
	err := b.handler(ctx, MessageContext{
		ChatID:    msg.Chat.ID,
		UserID:    senderID(upd),
		Text:      msg.Text,
		MessageID: msg.ID,
	})
	if err != nil {
		b.logger.Error("telegram message handler error", "err", b.summarize(err.Error()), "update_id", upd.ID)
	}
}

// onCallback answers the callback query first, then dispatches
// the registry entry (src/muse_cli/tgbot.py:1042-1067,
// on_callback / _run_callback). The answer is sent before the
// entry check is acted on, and its own failure is only
// debug-logged. A handler error becomes a warning message in
// the chat.
func (b *Bot) onCallback(ctx context.Context, upd *models.Update) {
	cq := upd.CallbackQuery
	chatID, mid, ok := callbackChat(cq)
	if !ok {
		// No message (inline message): fall back to the
		// sender id as the chat, with no markup to clear.
		chatID = senderID(upd)
		mid = 0
	}
	entry, ok := b.registry.Lookup(cq.Data)
	answerText := ""
	if !ok {
		answerText = "This button expired; run the command again."
	} else if entry.Action == "decide" || entry.Action == "approve_all" {
		// Decide buttons are single-flight: the first tap
		// consumes the entry, so a double-tap, redelivery,
		// or second user's tap takes the "expired" answer
		// instead of issuing a second non-idempotent
		// Decide RPC. Lookup above only peeked (the action
		// decides whether consumption applies); Consume is
		// the atomic arbiter when two taps race.
		entry, ok = b.registry.Consume(cq.Data)
		if !ok {
			answerText = "This button expired; run the command again."
		}
	}
	if err := b.answer(ctx, cq.ID, answerText); err != nil {
		b.logger.Debug("telegram answerCallbackQuery failed", "err", b.summarize(err.Error()))
	}
	if !ok {
		return
	}
	var err error
	switch entry.Action {
	case "decide":
		err = b.cbDecide(ctx, chatID, mid, entry)
	case "approve_all":
		err = b.cbApproveAll(ctx, chatID, entry)
	case "profile":
		// Owner-only in Python (tgbot.py:1055-1056); no profile
		// action is ever registered in item 4. Defensive drop.
		return
	default:
		if b.callbackFunc == nil {
			b.logger.Debug("telegram unknown callback action", "update_id", upd.ID)
			return
		}
		handled, herr := b.callbackFunc(ctx, chatID, mid, entry)
		if !handled {
			b.logger.Debug("telegram unknown callback action", "update_id", upd.ID)
			return
		}
		err = herr
	}
	if err != nil {
		warning := "⚠️ " + EscapeText(truncateRunes(b.summarize(err.Error()), 600))
		if _, werr := b.Send(ctx, chatID, warning, SendOptions{}); werr != nil {
			b.logger.Debug("telegram callback warning failed", "err", b.summarize(werr.Error()))
		}
	}
}

// decidedCap bounds the in-memory decided set: one entry per
// decided approval id, lost on restart (matching Python's
// in-memory semantics). Eviction is oldest-first; an evicted
// id may be decided again if a stale button for it is tapped
// later — the documented cost of the bound, unreachable at
// human-paced volumes. The cap is an internal constant (no
// config retrofit in this loop; flagged for a Boss decision
// under the config.json-only standing rule).
const decidedCap = 1024

// setDecidedLocked records a decision in the claim protocol's
// decided set, first decision wins. The caller holds claimsMu.
func (b *Bot) setDecidedLocked(approvalID, decision string) {
	if _, ok := b.decided[approvalID]; ok {
		return
	}
	b.decided[approvalID] = decision
	b.decidedOrder = append(b.decidedOrder, approvalID)
	for len(b.decidedOrder) > decidedCap {
		oldest := b.decidedOrder[0]
		b.decidedOrder = b.decidedOrder[1:]
		delete(b.decided, oldest)
	}
}

// RecordDecided records a decision made outside decideOnce
// (the turn auto-approve path, which decides through the
// gateway directly) in the same decided set decideOnce
// consults, so a later manual tap for the same id does not
// re-issue the RPC. It never issues an RPC itself. Ordering
// limit, stated honestly: a tap racing an in-flight auto RPC
// can still double-issue, because the record lands only
// after the auto RPC returns; the concurrent window is
// disclosed in the PR body residuals.
func (b *Bot) RecordDecided(approvalID, decision string) {
	b.claimsMu.Lock()
	defer b.claimsMu.Unlock()
	b.setDecidedLocked(approvalID, decision)
}

// decideOnce issues at most one Decide RPC per approval id
// for the bot's lifetime (in-memory). The check, the RPC, and
// the record are atomic per id: a second caller for the SAME
// id waits for the in-flight call to settle and then
// re-checks, while callers for DIFFERENT ids proceed
// concurrently — claimsMu is never held across the RPC, so
// one slow gateway call cannot head-of-line-block another
// chat's decide. The record lands in the claim protocol's
// decided set, so the monitor paths see manual decisions
// too. A failed RPC records nothing, so a retry stays
// possible. Registry consumption in onCallback is the first
// line for the same button; this is the second, for distinct
// buttons over one approval.
func (b *Bot) decideOnce(ctx context.Context, approvalID, decision string) (bool, error) {
	var waitCh chan struct{}
	for {
		b.claimsMu.Lock()
		if _, ok := b.decided[approvalID]; ok {
			b.claimsMu.Unlock()
			return false, nil
		}
		if ch, ok := b.decideInflight[approvalID]; ok {
			b.claimsMu.Unlock()
			select {
			case <-ch:
				continue
			case <-ctx.Done():
				return false, ctx.Err()
			}
		}
		waitCh = make(chan struct{})
		b.decideInflight[approvalID] = waitCh
		b.claimsMu.Unlock()
		break
	}
	err := b.decider.Decide(ctx, approvalID, decision)
	b.claimsMu.Lock()
	delete(b.decideInflight, approvalID)
	if err == nil {
		b.setDecidedLocked(approvalID, decision)
	}
	close(waitCh)
	b.claimsMu.Unlock()
	if err != nil {
		return false, err
	}
	return true, nil
}

// cbDecide decides one approval, confirms, clears the buttons,
// and resumes when the button carries a resume triple (src/
// muse_cli/tgbot.py:1725-1737, cb_decide). When the approval
// was already decided (a distinct button for the same id, or
// a monitor path decided first), it clears the buttons and
// returns without a second RPC, confirm, or resume: the first
// decision already confirmed and scheduled the follow.
func (b *Bot) cbDecide(ctx context.Context, chatID int64, mid int, entry CallbackEntry) error {
	decided, err := b.decideOnce(ctx, entry.ApprovalID, entry.Decision)
	if err != nil {
		return b.scrubErr(err)
	}
	if !decided {
		// Already decided elsewhere (a distinct button for
		// the same id, or a monitor path decided first):
		// clear the buttons and return without a second
		// confirm or resume.
		if mid != 0 {
			// Failure swallowed, as in Python (try/except pass).
			_ = b.clearMarkup(ctx, chatID, mid)
		}
		return nil
	}
	label := "❌ Denied"
	switch entry.Decision {
	case DecisionForever:
		label = "✅ Always allowed"
	case DecisionOnce:
		label = "✅ Allowed once"
	}
	if _, err := b.Send(ctx, chatID, label+": <code>"+EscapeText(entry.ApprovalID)+"</code>", SendOptions{Silent: true}); err != nil {
		return err
	}
	// The confirm is sent before the buttons are cleared:
	// observing the markup clear implies the confirm
	// already landed (the test sync assumption).
	if mid != 0 {
		// Failure swallowed, as in Python (try/except pass).
		_ = b.clearMarkup(ctx, chatID, mid)
	}
	if entry.AfterSeq != nil && b.resume != nil {
		// The resume is scheduled, not run here: startResume
		// guards the active-turn slot and drops stale
		// triples, so no HasActiveTurn pre-check is needed
		// (a tap during the deciding turn's teardown must
		// wait the slot out, not drop the follow).
		if err := b.resume(ctx, ResumeInfo{ChatID: chatID, SessionID: entry.SessionID, Title: entry.Title, AfterSeq: *entry.AfterSeq}); err != nil {
			return b.scrubErr(err)
		}
	}
	return nil
}

// cbApproveAll decides every forever-offering pending approval
// with allow_always, reports the titles, and enqueues no resume
// (src/muse_cli/tgbot.py:1739-1747, cb_approve_all). It has no
// allow-once fallback.
func (b *Bot) cbApproveAll(ctx context.Context, chatID int64, _ CallbackEntry) error {
	pend, err := b.pending(ctx)
	if err != nil {
		return b.scrubErr(err)
	}
	var done []string
	for _, d := range pend {
		if !OffersForever(d) {
			continue
		}
		// Single-flight, as in cbDecide: an approval already
		// decided (manual tap, or a monitor path) is skipped
		// without a second RPC and without a second report
		// line — it was already confirmed where decided.
		decided, err := b.decideOnce(ctx, d.ID, DecisionForever)
		if err != nil {
			return b.scrubErr(err)
		}
		if !decided {
			continue
		}
		title := d.Title
		if title == "" {
			title = d.ID
		}
		done = append(done, title)
	}
	joined := strings.Join(done, ", ")
	if joined == "" {
		joined = "nothing pending"
	} else {
		joined = EscapeText(joined)
	}
	_, err = b.Send(ctx, chatID, "✅ Always allowed: "+joined, SendOptions{})
	return err
}

func truncateRunes(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n])
	}
	return s
}

func runeLen(s string) int { return len([]rune(s)) }

func truncateToRunes(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n])
	}
	return s
}

// retryCall runs one Bot API call with Python's 429 retry rule
// (src/muse_cli/tgapi.py:116-130, TelegramAPI.call): retry only
// HTTP 429 with retry_after present and <= 60, at most 2 retries,
// sleeping retry_after + 0.5s between attempts.
func (b *Bot) retryCall(call func() error) error {
	for attempt := 0; ; attempt++ {
		err := call()
		if err == nil {
			return nil
		}
		var tmr *bot.TooManyRequestsError
		if errors.As(err, &tmr) && tmr.RetryAfter > 0 && tmr.RetryAfter <= 60 && attempt < 2 {
			b.sleep(time.Duration(tmr.RetryAfter)*time.Second + 500*time.Millisecond)
			continue
		}
		return err
	}
}

func isParseError(err error) bool {
	if !errors.Is(err, bot.ErrorBadRequest) {
		return false
	}
	lower := strings.ToLower(err.Error())
	return strings.Contains(lower, "can't parse") ||
		strings.Contains(lower, "parse entities") ||
		strings.Contains(lower, "unsupported start tag")
}

func isNotModified(err error) bool {
	return strings.Contains(strings.ToLower(err.Error()), "message is not modified")
}

// Send sends text, splitting when long, with the HTML-then-plain
// fallback (src/muse_cli/tgbot.py:703-727, send / _send_one). It
// returns the last message id sent. The inline keyboard is
// attached only to the last piece; reply_to is passed to every
// piece; previews are always disabled; disable_notification is
// set only when silent.
func (b *Bot) Send(ctx context.Context, chatID int64, text string, opts SendOptions) (int, error) {
	var pieces []string
	if runeLen(text) > ChunkSize {
		pieces = SplitText(text)
	} else {
		pieces = []string{text}
	}
	mid := 0
	for i, piece := range pieces {
		last := i == len(pieces)-1
		var markup models.ReplyMarkup
		if last {
			markup = opts.Markup
		}
		var err error
		mid, err = b.sendOne(ctx, chatID, piece, markup, opts.Mode, opts.ReplyTo, opts.Silent)
		if err != nil {
			return 0, err
		}
	}
	return mid, nil
}

// SendMD sends Markdown-converted text (src/muse_cli/tgbot.py:729-730,
// send_md: send(..., html="md")).
func (b *Bot) SendMD(ctx context.Context, chatID int64, text string, opts SendOptions) (int, error) {
	opts.Mode = HTMLModeMarkdown
	return b.Send(ctx, chatID, text, opts)
}

func (b *Bot) sendOne(ctx context.Context, chatID int64, text string, markup models.ReplyMarkup, mode HTMLMode, replyTo int, silent bool) (int, error) {
	if mode != HTMLModePlain {
		body := text
		if mode == HTMLModeMarkdown {
			body = MDToHTML(text)
		}
		if runeLen(body) <= TextLimit {
			msg, err := b.sendMessageCall(ctx, chatID, body, models.ParseModeHTML, markup, replyTo, silent)
			if err == nil {
				return messageIDOf(msg), nil
			}
			if !isParseError(err) {
				return 0, b.scrubErr(err)
			}
			if mode == HTMLModeHTML {
				text = StripTags(text)
			}
			// Fall through to the plain attempt.
		} else if mode == HTMLModeHTML {
			// An HTML body over 4096 skips the HTML attempt
			// entirely (src/muse_cli/tgbot.py:717-727).
			text = StripTags(text)
		}
	}
	msg, err := b.sendMessageCall(ctx, chatID, truncateToRunes(text, TextLimit), "", markup, replyTo, silent)
	if err != nil {
		return 0, b.scrubErr(err)
	}
	return messageIDOf(msg), nil
}

func messageIDOf(msg *models.Message) int {
	if msg == nil {
		return 0
	}
	return msg.ID
}

func (b *Bot) sendMessageCall(ctx context.Context, chatID int64, text string, parseMode models.ParseMode, markup models.ReplyMarkup, replyTo int, silent bool) (*models.Message, error) {
	disabled := true
	params := &bot.SendMessageParams{
		ChatID:              chatID,
		Text:                text,
		ParseMode:           parseMode,
		LinkPreviewOptions:  &models.LinkPreviewOptions{IsDisabled: &disabled},
		DisableNotification: silent,
		ReplyMarkup:         markup,
	}
	if replyTo != 0 {
		params.ReplyParameters = &models.ReplyParameters{MessageID: replyTo}
	}
	var msg *models.Message
	err := b.retryCall(func() error {
		var err error
		msg, err = b.api.SendMessage(ctx, params)
		return err
	})
	if err != nil {
		return nil, err
	}
	if msg == nil {
		return nil, errors.New("telegram: sendMessage returned no message")
	}
	return msg, nil
}

// Edit edits a message with the HTML-then-plain fallback,
// swallowing "message is not modified"
// (src/muse_cli/tgbot.py:732-752, edit). A nil *Message with a
// nil error (the API answered JSON true, e.g. inline messages)
// is success, as the library documents.
func (b *Bot) Edit(ctx context.Context, chatID int64, msgID int, text string, markup models.ReplyMarkup, mode HTMLMode) error {
	if mode != HTMLModePlain {
		body := text
		if mode == HTMLModeMarkdown {
			body = MDToHTML(text)
		}
		if runeLen(body) <= TextLimit {
			err := b.editTextCall(ctx, chatID, msgID, body, models.ParseModeHTML, markup)
			if err == nil {
				return nil
			}
			if isNotModified(err) {
				return nil
			}
			if !isParseError(err) {
				return b.scrubErr(err)
			}
			if mode == HTMLModeHTML {
				text = StripTags(text)
			}
		} else if mode == HTMLModeHTML {
			text = StripTags(text)
		}
	}
	err := b.editTextCall(ctx, chatID, msgID, truncateToRunes(text, TextLimit), "", markup)
	if err != nil {
		if isNotModified(err) {
			return nil
		}
		return b.scrubErr(err)
	}
	return nil
}

func (b *Bot) editTextCall(ctx context.Context, chatID int64, msgID int, text string, parseMode models.ParseMode, markup models.ReplyMarkup) error {
	disabled := true
	params := &bot.EditMessageTextParams{
		ChatID:             chatID,
		MessageID:          msgID,
		Text:               text,
		ParseMode:          parseMode,
		LinkPreviewOptions: &models.LinkPreviewOptions{IsDisabled: &disabled},
		ReplyMarkup:        markup,
	}
	return b.retryCall(func() error {
		_, err := b.api.EditMessageText(ctx, params)
		return err
	})
}

// EditPlain edits with plain text, swallowing ALL errors: the
// streaming-edit path, where a failed edit never fails a turn
// (src/muse_cli/tgbot.py:754-758, edit_plain).
//
// [DEVIATION] Python's edit_plain catches only
// (TelegramError, ConnectionError); other exceptions
// propagate. This Go version swallows every error: scrubbed
// errors (see scrubErr) deliberately drop the transport-type
// distinctions that would let EditPlain tell a connection
// error from any other failure, so narrowing the catch to
// the Python pair is not expressible here without
// unwrapping raw errors. The deviation is documented in
// code, docs, and the PR draft; narrowing it is step-5 work
// only if the scrubbed-error contract grows a connection
// class.
func (b *Bot) EditPlain(ctx context.Context, chatID int64, msgID int, text string) error {
	if err := b.Edit(ctx, chatID, msgID, text, nil, HTMLModePlain); err != nil {
		b.logger.Debug("telegram stream edit failed", "err", b.summarize(err.Error()))
		return nil
	}
	return nil
}

// Answer answers a callback query (src/muse_cli/tgbot.py:1042-1053:
// answerCallbackQuery with the expired text when the entry is
// unknown, no text otherwise). Its own failure is the caller's
// to log; onCallback debug-logs it.
func (b *Bot) answer(ctx context.Context, callbackQueryID, text string) error {
	err := b.retryCall(func() error {
		_, err := b.api.AnswerCallbackQuery(ctx, &bot.AnswerCallbackQueryParams{
			CallbackQueryID: callbackQueryID,
			Text:            text,
		})
		return err
	})
	return b.scrubErr(err)
}

// Delete deletes a message (the /login cookie-message deletion
// pattern, src/muse_cli/tgbot.py:2251-2279).
func (b *Bot) Delete(ctx context.Context, chatID int64, msgID int) error {
	err := b.retryCall(func() error {
		_, err := b.api.DeleteMessage(ctx, &bot.DeleteMessageParams{ChatID: chatID, MessageID: msgID})
		return err
	})
	return b.scrubErr(err)
}

// ClearMarkup clears a message's inline keyboard. It is the
// exported form of clearMarkup for step-5 callback actions
// (question answers), which run outside the bot core.
func (b *Bot) ClearMarkup(ctx context.Context, chatID int64, msgID int) error {
	return b.clearMarkup(ctx, chatID, msgID)
}

// clearMarkup clears a message's inline keyboard with an empty
// editMessageReplyMarkup (src/muse_cli/tgbot.py:1725-1737:
// failure swallowed by the caller).
func (b *Bot) clearMarkup(ctx context.Context, chatID int64, msgID int) error {
	err := b.retryCall(func() error {
		_, err := b.api.EditMessageReplyMarkup(ctx, &bot.EditMessageReplyMarkupParams{
			ChatID:      chatID,
			MessageID:   msgID,
			ReplyMarkup: models.InlineKeyboardMarkup{InlineKeyboard: [][]models.InlineKeyboardButton{}},
		})
		return err
	})
	return b.scrubErr(err)
}
