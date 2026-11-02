// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package webui

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
)

// Chats/sessions over the profile's gateway connection, exposed
// read + send through /api/v1. The shapes reuse the CLI's:
// sessions.list rows (internal/shared.SessionRows), chat.history
// events (internal/shared.FmtEvent), deliverSend + executeWait
// for send. This package never imports internal/commands: the
// command layer injects the five seams below, each building and
// closing its own Runtime per call (the CLI runNetwork pattern,
// settled by the writer's lifecycle probe: a held Runtime would
// go stale whenever the UI itself saves the config it was built
// from, and per-turn heartbeat ownership stays with
// executeWait). A send job therefore pays one runtime build;
// reads pay one each. No Runtime is held across requests.
//
// Send is async by design: a turn can run past the 30 s API
// timeout, so POST creates a job and GET polls it. One send
// runs at a time per profile: a second POST while one is in
// flight gets a fixed 409. Jobs live in memory only, bounded
// and TTL'd, and are never logged — job results hold chat
// text, which is sensitive display, never persisted to disk,
// never put in browser storage by the frontend, and never
// echoed in an error message.
//
// Send uses the profile's existing auto_approve/auto_allow_once
// toggles as-is (the injected seam resolves them exactly as
// the CLI does). There is no approvals UI: a turn stopped on a
// pending approval ends the job with outcome "needs_approval"
// (or "needs_input" for a question/widget), and the operator
// decides in the CLI or Telegram. An approval-blocked turn
// never stalls the job: the job ends when executeWait returns,
// bounded by the job timeout below. A job whose turn never
// ends within the budget ends with outcome "timeout".
//
// Chat bodies are never redacted with SafeString on read: the
// authenticated operator reads their own chats verbatim, as
// the CLI prints them. The control is structural instead: no
// chat text is ever logged (this package never logs), no chat
// text enters an error envelope (errors carry fixed messages
// or SafeString'd summaries of transport errors only), and job
// state is memory-only.

// ChatSession is one sessions.list row, as the CLI's `threads`
// shapes it. SessionID is nil when the server sent no id.
type ChatSession struct {
	SessionID *string `json:"session_id"`
	Title     *string `json:"title"`
	Thread    *bool   `json:"thread"`
	Pinned    *bool   `json:"pinned"`
	Archived  *bool   `json:"archived"`
	Updated   string  `json:"updated"`
}

// ChatEvent is one chat.history event, as the CLI's `history`
// shapes it (FmtEvent): text only, no payload, no resources.
// Resource download is a CLI concern and is not exposed here.
type ChatEvent struct {
	Seq       *int64  `json:"seq"`
	Role      *string `json:"role"`
	MessageID *string `json:"message_id"`
	Text      string  `json:"text"`
}

// ChatReply is one assistant reply in a finished send job.
type ChatReply struct {
	Seq       int64   `json:"seq"`
	Text      string  `json:"text"`
	MessageID *string `json:"message_id"`
}

// ChatSendResult is a finished send job's turn result: the
// wait outcome vocabulary (done, needs_input, needs_approval,
// failed, timeout, undelivered), the final text, and the
// replies. Approvals are counted, never described: there is
// no approvals UI, and approval titles/questions are peer
// text with no display purpose here.
type ChatSendResult struct {
	Outcome          string      `json:"outcome"`
	Status           *string     `json:"status,omitempty"`
	AfterSeq         int64       `json:"after_seq"`
	FinalText        *string     `json:"final_text,omitempty"`
	Replies          []ChatReply `json:"replies"`
	Note             string      `json:"note,omitempty"`
	ApprovalsCount   int         `json:"approvals_count,omitempty"`
	NeedsInputReason *string     `json:"needs_input_reason,omitempty"`
	Question         *string     `json:"question,omitempty"`
}

// ChatDeps are the injected chat seams. Each builds and closes
// its own Runtime per call (see the package note above) and
// returns transport errors only: implementations must never
// return chat text inside an error.
type ChatDeps struct {
	// ListSessions returns the profile's sessions.list rows.
	ListSessions func(ctx context.Context, profileName string, includeArchived bool) ([]ChatSession, error)
	// GetHistory returns one session's chat.history events,
	// newest-first as the gateway returns them, capped at
	// limit events.
	GetHistory func(ctx context.Context, profileName, sessionID string, limit int) ([]ChatEvent, error)
	// StartSession starts a new side chat and returns the
	// server-assigned session id.
	StartSession func(ctx context.Context, profileName, title string) (string, error)
	// SessionOp runs one session operation: rename, pin,
	// unpin, archive, unarchive, or delete. Title is used
	// only for rename.
	SessionOp func(ctx context.Context, profileName, sessionID, op, title string) error
	// SendChat sends text and waits for the turn, bounded by
	// the job timeout. It resolves the profile's
	// auto_approve/auto_allow_once toggles as-is.
	SendChat func(ctx context.Context, profileName, sessionID, text string) (*ChatSendResult, error)
}

// chatJobTimeout bounds one send job end to end: the 30 s
// delivery-ack budget plus the 90 s default wait budget, with
// margin for the runtime build. A job that exceeds it is
// cancelled and ends failed with a fixed message; the turn
// itself may continue server-side, exactly as a CLI send whose
// wait timed out leaves the turn running.
const chatJobTimeout = 150 * time.Second

// chatJobTTL bounds how long a finished job stays pollable.
// chatJobMax is the job-store cap: the oldest finished jobs
// are evicted past it.
const chatJobTTL = time.Hour
const chatJobMax = 32

// chatJobStatus is a job's lifecycle state.
type chatJobStatus string

const (
	chatJobRunning chatJobStatus = "running"
	chatJobDone    chatJobStatus = "done"
	chatJobFailed  chatJobStatus = "failed"
)

// chatJob is one async send. Result is set only on done;
// Err is a fixed message only, never chat text.
type chatJob struct {
	ID        string
	Profile   string
	SessionID string
	Status    chatJobStatus
	CreatedAt time.Time
	UpdatedAt time.Time
	Result    *ChatSendResult
	Err       string
}

// chatJobView is the poll shape: the job plus its result when
// finished. Chat text appears only in Result, only to the
// authenticated caller that created the job.
type chatJobView struct {
	ID        string          `json:"id"`
	Profile   string          `json:"profile"`
	SessionID string          `json:"session_id"`
	Status    chatJobStatus   `json:"status"`
	CreatedAt time.Time       `json:"created_at"`
	UpdatedAt time.Time       `json:"updated_at"`
	Result    *ChatSendResult `json:"result,omitempty"`
	Error     string          `json:"error,omitempty"`
}

func (j *chatJob) view() chatJobView {
	v := chatJobView{
		ID: j.ID, Profile: j.Profile, SessionID: j.SessionID,
		Status: j.Status, CreatedAt: j.CreatedAt, UpdatedAt: j.UpdatedAt,
	}
	if j.Status == chatJobDone {
		v.Result = j.Result
	}
	if j.Status == chatJobFailed {
		v.Error = j.Err
	}
	return v
}

// chatJobStore is the bounded in-memory job store. All methods
// are safe for concurrent use. Jobs are never persisted and
// never logged.
type chatJobStore struct {
	mu   sync.Mutex
	jobs map[string]*chatJob
	// order is creation order (oldest first), for eviction.
	order []string
	now   func() time.Time
}

func newChatJobStore() *chatJobStore {
	return &chatJobStore{jobs: map[string]*chatJob{}}
}

func (s *chatJobStore) clock() time.Time {
	if s.now != nil {
		return s.now()
	}
	return nowUTC()
}

// errChatBusy is the fixed 409 when a send is already in flight
// for the profile.
var errChatBusy = &apiError{status: http.StatusConflict, typ: "send_in_flight", msg: "a send is already in flight for this profile"}

// create registers a new running job, or reports busy when one
// is already running for the profile. Expired jobs are pruned
// and the oldest finished jobs evicted past the cap, under the
// same lock, so the store cannot grow without bound.
func (s *chatJobStore) create(profileName, sessionID string) (*chatJob, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked()
	for _, j := range s.jobs {
		if j.Profile == profileName && j.Status == chatJobRunning {
			return nil, errChatBusy
		}
	}
	id, err := newChatJobID()
	if err != nil {
		return nil, errInternal()
	}
	now := s.clock()
	job := &chatJob{ID: id, Profile: profileName, SessionID: sessionID, Status: chatJobRunning, CreatedAt: now, UpdatedAt: now}
	if s.jobs == nil {
		s.jobs = map[string]*chatJob{}
	}
	s.jobs[id] = job
	s.order = append(s.order, id)
	for len(s.jobs) > chatJobMax {
		s.evictOldestFinishedLocked()
	}
	return job, nil
}

// get returns a job by id, pruning expired jobs first. A pruned
// job reads as not found: the TTL is part of the contract.
func (s *chatJobStore) get(id string) *chatJob {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked()
	return s.jobs[id]
}

// finish records a job's terminal result. A job finished by a
// stale worker (pruned while running) is dropped, never
// resurrected.
func (s *chatJobStore) finish(id string, result *ChatSendResult, errMsg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	j, ok := s.jobs[id]
	if !ok || j.Status != chatJobRunning {
		return
	}
	j.UpdatedAt = s.clock()
	if errMsg != "" {
		j.Status = chatJobFailed
		j.Err = errMsg
		return
	}
	j.Status = chatJobDone
	j.Result = result
}

// pruneLocked drops jobs older than the TTL. The caller holds
// the mutex.
func (s *chatJobStore) pruneLocked() {
	now := s.clock()
	kept := s.order[:0]
	for _, id := range s.order {
		j, ok := s.jobs[id]
		if !ok {
			continue
		}
		if now.Sub(j.CreatedAt) > chatJobTTL {
			delete(s.jobs, id)
			continue
		}
		kept = append(kept, id)
	}
	s.order = kept
}

// evictOldestFinishedLocked drops the oldest finished job. The
// caller holds the mutex and the store is over the cap. A
// running job is never evicted: the cap yields to in-flight
// work, and the next create prunes again.
func (s *chatJobStore) evictOldestFinishedLocked() {
	for i, id := range s.order {
		if j, ok := s.jobs[id]; ok && j.Status != chatJobRunning {
			delete(s.jobs, id)
			s.order = append(s.order[:i], s.order[i+1:]...)
			return
		}
	}
}

// newChatJobID mints a 128-bit random job id (hex). A randomness
// failure is an internal error: ids must be unguessable, since
// a job id grants read access to that job's chat text to any
// authenticated caller.
func newChatJobID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// --- handlers ---------------------------------------------------

// chatDeps returns the server's injected chat seams, or an
// unavailable error when the command layer wired none (tests
// and builds without a runtime seam).
func (s *Server) chatDeps() (*ChatDeps, error) {
	if s.deps.Chats == nil {
		return nil, &apiError{status: http.StatusNotImplemented, typ: "unavailable", msg: "chats are unavailable in this build"}
	}
	return s.deps.Chats, nil
}

// requireChatProfile validates that name is a profile key in
// the stored config. Unknown profiles 404 with a fixed message;
// the name is never echoed beyond the fixed profile-not-found
// wording used elsewhere in this package.
func (s *Server) requireChatProfile(name string) error {
	load, err := s.loadConfig()
	if err != nil {
		return err
	}
	cfg, err := s.parseLoaded(load)
	if err != nil {
		return err
	}
	if _, ok := cfg.Profiles[name]; !ok {
		return errNotFound("profile not found")
	}
	return nil
}

// chatSessionID maps a path session segment to the gateway
// session id: the literal "main" is the main chat (the CLI's
// empty --thread), anything else passes through verbatim.
func chatSessionID(segment string) string {
	if segment == "main" {
		return ""
	}
	return segment
}

func (s *Server) handleListChats(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "profile")
	if err := s.requireChatProfile(name); err != nil {
		writeAPIError(w, err)
		return
	}
	deps, err := s.chatDeps()
	if err != nil {
		writeAPIError(w, err)
		return
	}
	includeArchived := r.URL.Query().Get("include_archived") == "1" || strings.EqualFold(r.URL.Query().Get("include_archived"), "true")
	sessions, err := deps.ListSessions(r.Context(), name, includeArchived)
	if err != nil {
		writeAPIError(w, errUpstream(err))
		return
	}
	if sessions == nil {
		sessions = []ChatSession{}
	}
	writeEnvelope(w, http.StatusOK, sessions)
}

type startChatBody struct {
	Title *string `json:"title"`
}

func (s *Server) handleStartChat(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "profile")
	if err := s.requireChatProfile(name); err != nil {
		writeAPIError(w, err)
		return
	}
	var body startChatBody
	if err := decodeBody(w, r, 64<<10, &body); err != nil {
		writeAPIError(w, err)
		return
	}
	title := ""
	if body.Title != nil {
		title = *body.Title
	}
	deps, err := s.chatDeps()
	if err != nil {
		writeAPIError(w, err)
		return
	}
	id, err := deps.StartSession(r.Context(), name, title)
	if err != nil {
		writeAPIError(w, errUpstream(err))
		return
	}
	writeEnvelope(w, http.StatusCreated, map[string]any{"session_id": id})
}

func (s *Server) handleGetChatHistory(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "profile")
	if err := s.requireChatProfile(name); err != nil {
		writeAPIError(w, err)
		return
	}
	limit := 50
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > 200 {
			writeAPIError(w, errValidation("limit must be an integer from 1 to 200"))
			return
		}
		limit = n
	}
	deps, err := s.chatDeps()
	if err != nil {
		writeAPIError(w, err)
		return
	}
	events, err := deps.GetHistory(r.Context(), name, chatSessionID(chi.URLParam(r, "session")), limit)
	if err != nil {
		writeAPIError(w, errUpstream(err))
		return
	}
	if events == nil {
		events = []ChatEvent{}
	}
	writeEnvelope(w, http.StatusOK, events)
}

type sendChatBody struct {
	Text string `json:"text"`
}

func (s *Server) handleSendChat(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "profile")
	sessionID := chatSessionID(chi.URLParam(r, "session"))
	if err := s.requireChatProfile(name); err != nil {
		writeAPIError(w, err)
		return
	}
	var body sendChatBody
	if err := decodeBody(w, r, 64<<10, &body); err != nil {
		writeAPIError(w, err)
		return
	}
	if strings.TrimSpace(body.Text) == "" {
		writeAPIError(w, errValidation("text must not be empty"))
		return
	}
	deps, err := s.chatDeps()
	if err != nil {
		writeAPIError(w, err)
		return
	}
	job, err := s.jobs().create(name, sessionID)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	// The job runs detached from the request context: the
	// apiTimeout middleware cancels the request context after
	// 30 s, but a turn legitimately runs longer. The job's
	// own timeout bounds it instead.
	jobCtx, cancel := context.WithTimeout(context.Background(), chatJobTimeout)
	go func() {
		defer cancel()
		result, err := deps.SendChat(jobCtx, name, sessionID, body.Text)
		if err != nil {
			// The job context has no parent: an error here
			// means the job budget expired, whatever the
			// seam returned alongside it.
			if jobCtx.Err() != nil {
				s.jobs().finish(job.ID, nil, "send timed out")
				return
			}
			s.jobs().finish(job.ID, nil, "upstream error")
			return
		}
		s.jobs().finish(job.ID, result, "")
	}()
	writeEnvelope(w, http.StatusAccepted, job.view())
}

func (s *Server) handleGetChatJob(w http.ResponseWriter, r *http.Request) {
	job := s.jobs().get(chi.URLParam(r, "job"))
	if job == nil {
		writeAPIError(w, errNotFound("job not found"))
		return
	}
	writeEnvelope(w, http.StatusOK, job.view())
}

type chatSessionOpBody struct {
	Op    string  `json:"op"`
	Title *string `json:"title"`
}

var validChatSessionOps = map[string]bool{
	"rename": true, "pin": true, "unpin": true,
	"archive": true, "unarchive": true, "delete": true,
}

func (s *Server) handleChatSessionOp(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "profile")
	sessionID := chatSessionID(chi.URLParam(r, "session"))
	if err := s.requireChatProfile(name); err != nil {
		writeAPIError(w, err)
		return
	}
	var body chatSessionOpBody
	if err := decodeBody(w, r, 64<<10, &body); err != nil {
		writeAPIError(w, err)
		return
	}
	if !validChatSessionOps[body.Op] {
		writeAPIError(w, errValidation("op must be one of rename, pin, unpin, archive, unarchive, delete"))
		return
	}
	title := ""
	if body.Title != nil {
		title = *body.Title
	}
	if body.Op == "rename" && strings.TrimSpace(title) == "" {
		writeAPIError(w, errValidation("title must not be empty for rename"))
		return
	}
	deps, err := s.chatDeps()
	if err != nil {
		writeAPIError(w, err)
		return
	}
	if err := deps.SessionOp(r.Context(), name, sessionID, body.Op, title); err != nil {
		writeAPIError(w, errUpstream(err))
		return
	}
	writeEnvelope(w, http.StatusOK, map[string]any{"ok": true})
}

// errUpstream maps a chat-seam error to a fixed 502: the failure
// class only, with no error text at all. Seam errors come from
// the gateway transport, whose messages could in principle
// carry server-supplied text; chat bodies must never reach an
// error envelope, so nothing from the error is surfaced. The
// operator re-runs the read in the CLI for the detail.
func errUpstream(err error) error {
	return &apiError{status: http.StatusBadGateway, typ: "upstream_error", msg: "upstream error"}
}

// jobs returns the server's job store, creating it lazily so
// servers built in tests without one still serve the jobs
// routes (with the unavailable seam error for creation).
func (s *Server) jobs() *chatJobStore {
	s.jobsMu.Lock()
	defer s.jobsMu.Unlock()
	if s.jobStore == nil {
		s.jobStore = newChatJobStore()
	}
	return s.jobStore
}
