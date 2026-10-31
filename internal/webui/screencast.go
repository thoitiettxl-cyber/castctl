// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package webui

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/websocket"

	"github.com/thoitiettxl-cyber/castctl/internal/keeper"
	"github.com/thoitiettxl-cyber/castctl/internal/profile"
)

// Screencast relay: the web UI front-end for keeper.LoginSession,
// over the frozen keeper.Transport boundary. This package sends
// no CDP calls of its own and imports no chromedp package: the
// runner (attach to the user's Chrome) lives in internal/keeper
// behind the with_chromedp tag, reached through the injected
// ScreencastStarter. Without the tag, the starter seam is nil
// and the page and the API say unavailable.
//
// Honesty note (item-1 lesson, repeated here because this file
// is where a reader would look for it): chromedp's target-attach
// bootstrap enables Runtime, DOM, CSS, Log, Inspector, and Page
// internally and evaluates the constant "self". castctl's own
// code sends no Runtime/JS calls and the export path sends only
// Storage.getCookies, but the bootstrap's method set is wider.
// Nothing in this package claims otherwise.
//
// Session auth: POST /screencast/{profile}/start (Bearer) mints
// a single-use opaque session token (crypto/rand, 5-minute
// TTL, in-memory only, never logged). The WebSocket validates
// that token from its query string — a browser WebSocket cannot
// set an Authorization header, and a Bearer token must never be
// put in a query string. At most one live session per profile.

const (
	screencastSessionTTL = 5 * time.Minute
	maxScreencastInput   = 64
)

// sessionRegistry mints, consumes, and tracks screencast
// sessions. A token is consumed on first WebSocket connect; an
// expired or unknown token is a 401 before upgrade.
type sessionRegistry struct {
	mu        sync.Mutex
	sessions  map[string]*screencastSession
	byProfile map[string]string
}

type screencastSession struct {
	token     string
	profile   string
	expiresAt time.Time
	live      bool
	consumed  bool
}

func newSessionRegistry() *sessionRegistry {
	return &sessionRegistry{
		sessions:  map[string]*screencastSession{},
		byProfile: map[string]string{},
	}
}

func (r *sessionRegistry) mint(profileName string) (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	token := hex.EncodeToString(raw[:])
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	// Prune expired unconsumed tokens (bounded map; the live
	// check below is what enforces one session per profile).
	for tok, sess := range r.sessions {
		if !sess.live && now.After(sess.expiresAt) {
			delete(r.sessions, tok)
		}
	}
	if existing, ok := r.byProfile[profileName]; ok {
		if sess, ok := r.sessions[existing]; ok && sess.live {
			return "", errScreencastBusy
		}
	}
	r.sessions[token] = &screencastSession{token: token, profile: profileName, expiresAt: now.Add(screencastSessionTTL)}
	return token, nil
}

var errScreencastBusy = errors.New("a screencast session is already live for this profile")

// consume validates and single-use consumes a token, marking
// its session live. It returns the profile name.
func (r *sessionRegistry) consume(token string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	sess, ok := r.sessions[token]
	if !ok {
		return "", errSessionUnknown
	}
	if sess.consumed {
		// Single-use: a replayed token is unknown, even
		// while its session is live (the busy branch below
		// is for a DIFFERENT token for the same profile).
		return "", errSessionUnknown
	}
	if time.Now().After(sess.expiresAt) {
		// Expired: drop it so a later mint is not blocked
		// by a stale byProfile entry (none exists for an
		// unconsumed token, but be explicit).
		delete(r.sessions, token)
		return "", errSessionUnknown
	}
	sess.consumed = true
	// Kept in the map while live: mint()'s busy check reads
	// it through byProfile. release() removes both entries.
	if existing, ok := r.byProfile[sess.profile]; ok {
		if other, ok := r.sessions[existing]; ok && other.live {
			return "", errScreencastBusy
		}
	}
	sess.live = true
	r.byProfile[sess.profile] = token
	return sess.profile, nil
}

var errSessionUnknown = errors.New("unknown or expired screencast session")

func (r *sessionRegistry) release(profileName string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if token, ok := r.byProfile[profileName]; ok {
		delete(r.byProfile, profileName)
		delete(r.sessions, token)
	}
}

// screencastAvailability resolves availability for a profile:
// the injected seam (chromedp build + keeper entry) when present,
// unavailable otherwise.
func (s *Server) screencastAvailability(ctx context.Context, profileName string) (bool, string, error) {
	if s.deps.ScreencastAvailable == nil {
		return false, "screencast unavailable in this build (rebuild with -tags with_chromedp)", nil
	}
	return s.deps.ScreencastAvailable(ctx, profileName)
}

func (s *Server) handleScreencastStatus(w http.ResponseWriter, r *http.Request) {
	profileName := r.URL.Query().Get("profile")
	if profileName == "" {
		load, err := s.loadConfig()
		if err != nil {
			writeAPIError(w, err)
			return
		}
		if load.state.Found {
			if cfg, perr := profile.ParseSingleConfig(load.raw, s.deps.ConfigDir); perr == nil {
				profileName = cfg.DefaultProfile
			}
		}
	}
	available, reason, err := s.screencastAvailability(r.Context(), profileName)
	if err != nil {
		writeAPIError(w, errValidation(safeMessage(err)))
		return
	}
	writeEnvelope(w, http.StatusOK, map[string]any{
		"available": available,
		"reason":    reason,
		"profile":   profileName,
	})
}

func (s *Server) handleScreencastStart(w http.ResponseWriter, r *http.Request) {
	profileName := chi.URLParam(r, "profile")
	available, reason, err := s.screencastAvailability(r.Context(), profileName)
	if err != nil {
		writeAPIError(w, errValidation(safeMessage(err)))
		return
	}
	if !available {
		writeError(w, http.StatusServiceUnavailable, "screencast_unavailable", reason)
		return
	}
	if s.deps.ScreencastStarter == nil {
		writeError(w, http.StatusServiceUnavailable, "screencast_unavailable", "screencast unavailable in this build (rebuild with -tags with_chromedp)")
		return
	}
	token, err := s.sessions.mint(profileName)
	if err != nil {
		if errors.Is(err, errScreencastBusy) {
			writeError(w, http.StatusConflict, "screencast_busy", "a screencast session is already live for this profile")
			return
		}
		writeAPIError(w, errInternal())
		return
	}
	writeEnvelope(w, http.StatusOK, map[string]any{
		"session_id": token,
		"ws_url":     "/api/v1/screencast/ws?session=" + token,
	})
}

var wsUpgrader = websocket.Upgrader{
	// Loopback-only server, Bearer/session-token authed: the
	// browser origin is the server itself. Cross-origin WebSocket
	// hijack protection is not the control here; the session
	// token is. Still, reject non-loopback Origin hosts when an
	// Origin header is present, so a foreign page cannot drive
	// a session it did not mint.
	CheckOrigin: func(r *http.Request) bool {
		origin := r.Header.Get("Origin")
		if origin == "" {
			return true
		}
		// Origin host must be loopback or the request host
		// itself (same-origin page served by this server).
		if host := originHost(origin); host != "" {
			return isLoopbackHost(host) || host == r.Host
		}
		return false
	},
	ReadBufferSize:  64 << 10,
	WriteBufferSize: 64 << 10,
}

func originHost(origin string) string {
	rest := origin
	if i := strings.Index(rest, "://"); i >= 0 {
		rest = rest[i+3:]
	}
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		rest = rest[:i]
	}
	return rest
}

func isLoopbackHost(host string) bool {
	if i := strings.LastIndex(host, ":"); i >= 0 {
		host = host[:i]
	}
	host = strings.Trim(host, "[]")
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

func (s *Server) handleScreencastWS(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("session")
	if token == "" {
		writeError(w, http.StatusUnauthorized, "unauthorized", "invalid or missing token")
		return
	}
	profileName, err := s.sessions.consume(token)
	if err != nil {
		if errors.Is(err, errScreencastBusy) {
			writeError(w, http.StatusConflict, "screencast_busy", "a screencast session is already live for this profile")
			return
		}
		writeError(w, http.StatusUnauthorized, "unauthorized", "invalid or missing token")
		return
	}
	defer s.sessions.release(profileName)
	if s.deps.ScreencastStarter == nil {
		writeError(w, http.StatusServiceUnavailable, "screencast_unavailable", "screencast unavailable in this build (rebuild with -tags with_chromedp)")
		return
	}
	conn, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()
	transport := newWSTransport(conn)
	defer transport.close()
	ctx, cancel := context.WithTimeout(r.Context(), keeper.DefaultLoginTimeout)
	defer cancel()
	result, starterErr := s.deps.ScreencastStarter(ctx, profileName, token, transport)
	if starterErr != nil {
		// An infrastructure failure starting the session is
		// a failed outcome, not a crash: the outcome enum
		// names it, and no error text leaves this handler.
		result = keeper.LoginResult{Outcome: keeper.LoginFailed, Err: starterErr}
	}
	// Terminal report: outcome enum only, plus value-free
	// metadata (saved names, earliest expiry). No error text:
	// infrastructure errors are fixed strings at the CLI
	// boundary; here the outcome names the result.
	report := map[string]any{
		"type":          "result",
		"outcome":       string(result.Outcome),
		"cookies_saved": result.CookiesSaved,
		"saved_names":   result.SavedNames,
	}
	if result.EarliestExpiry != nil {
		report["earliest_expiry"] = result.EarliestExpiry.Format(time.RFC3339)
	}
	_ = transport.sendJSON(report)
}

// --- WebSocket transport --------------------------------------

// wsTransport implements keeper.Transport over one WebSocket:
// frames out as base64 JPEG data URLs' payloads, phases out as
// phase notices, inputs in as validated InputEvents. Frames are
// latest-only (size-1 slot, stale frames dropped, never block
// the screencast loop). No logging calls in frame/input paths:
// frames and keystrokes are sensitive.
type wsTransport struct {
	conn *websocket.Conn

	writeMu sync.Mutex

	frameMu  sync.Mutex
	frame    *keeper.Frame
	frameSig chan struct{}

	inputs chan keeper.InputEvent
	done   chan struct{}
	once   sync.Once
}

func newWSTransport(conn *websocket.Conn) *wsTransport {
	t := &wsTransport{
		conn:     conn,
		frameSig: make(chan struct{}, 1),
		inputs:   make(chan keeper.InputEvent, maxScreencastInput),
		done:     make(chan struct{}),
	}
	go t.pumpFrames()
	go t.pumpInputs()
	return t
}

func (t *wsTransport) SendFrame(ctx context.Context, frame keeper.Frame) error {
	t.frameMu.Lock()
	cp := frame
	t.frame = &cp
	t.frameMu.Unlock()
	select {
	case t.frameSig <- struct{}{}:
	default:
	}
	return nil
}

func (t *wsTransport) SendPhase(ctx context.Context, phase keeper.SessionPhase, detail string) error {
	return t.sendJSON(map[string]any{
		"type":   "phase",
		"phase":  string(phase),
		"detail": detail,
	})
}

func (t *wsTransport) Inputs() <-chan keeper.InputEvent { return t.inputs }

func (t *wsTransport) Done() <-chan struct{} { return t.done }

func (t *wsTransport) close() {
	t.once.Do(func() { close(t.done) })
}

func (t *wsTransport) sendJSON(v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	_ = t.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	return t.conn.WriteMessage(websocket.TextMessage, data)
}

// pumpFrames forwards the latest frame whenever one arrives.
// A slow consumer drops stale frames: only the newest slot
// content is ever sent.
func (t *wsTransport) pumpFrames() {
	for {
		select {
		case <-t.done:
			return
		case <-t.frameSig:
		}
		t.frameMu.Lock()
		frame := t.frame
		t.frame = nil
		t.frameMu.Unlock()
		if frame == nil {
			continue
		}
		_ = t.sendJSON(map[string]any{
			"type":   "frame",
			"data":   base64.StdEncoding.EncodeToString(frame.Data),
			"width":  frame.Width,
			"height": frame.Height,
		})
	}
}

// wsInputMessage is the client's input message shape. Unknown
// fields are ignored; kind and type vocabularies are allowlisted
// before any event reaches the runner.
type wsInputMessage struct {
	Kind       string  `json:"kind"`
	MouseType  string  `json:"mouse_type"`
	Button     string  `json:"button"`
	X          float64 `json:"x"`
	Y          float64 `json:"y"`
	ClickCount int     `json:"click_count"`
	DeltaX     float64 `json:"delta_x"`
	DeltaY     float64 `json:"delta_y"`
	KeyType    string  `json:"key_type"`
	Key        string  `json:"key"`
	Text       string  `json:"text"`
	Modifiers  int     `json:"modifiers"`
}

var (
	allowedMouseTypes = map[string]bool{
		"mousePressed": true, "mouseReleased": true, "mouseMoved": true, "mouseWheel": true,
	}
	allowedKeyTypes = map[string]bool{
		"keyDown": true, "keyUp": true, "rawKeyDown": true, "char": true,
	}
	allowedButtons = map[string]bool{
		"left": true, "middle": true, "right": true, "back": true, "forward": true, "none": true, "": true,
	}
)

// pumpInputs reads client messages, validates them against the
// InputEvent allowlists, and forwards them. Anything invalid is
// dropped silently: a malformed message must never reach the
// runner or fail the session. Read errors close Done.
func (t *wsTransport) pumpInputs() {
	defer t.close()
	for {
		_, data, err := t.conn.ReadMessage()
		if err != nil {
			return
		}
		var msg wsInputMessage
		if err := json.Unmarshal(data, &msg); err != nil {
			continue
		}
		ev, ok := validateWSInput(msg)
		if !ok {
			continue
		}
		select {
		case t.inputs <- ev:
		case <-t.done:
			return
		default:
			// Input buffer full: drop the oldest input
			// rather than block the reader.
			select {
			case <-t.inputs:
			default:
			}
			select {
			case t.inputs <- ev:
			case <-t.done:
				return
			default:
			}
		}
	}
}

func validateWSInput(msg wsInputMessage) (keeper.InputEvent, bool) {
	switch keeper.InputKind(msg.Kind) {
	case keeper.InputMouse:
		if !allowedMouseTypes[msg.MouseType] || !allowedButtons[msg.Button] {
			return keeper.InputEvent{}, false
		}
		if msg.ClickCount < 0 || msg.ClickCount > 3 {
			return keeper.InputEvent{}, false
		}
		if msg.Modifiers < 0 || msg.Modifiers > 15 {
			return keeper.InputEvent{}, false
		}
		return keeper.InputEvent{
			Kind: keeper.InputMouse, MouseType: msg.MouseType, Button: msg.Button,
			X: msg.X, Y: msg.Y, ClickCount: msg.ClickCount,
			DeltaX: msg.DeltaX, DeltaY: msg.DeltaY, Modifiers: msg.Modifiers,
		}, true
	case keeper.InputKey:
		if !allowedKeyTypes[msg.KeyType] {
			return keeper.InputEvent{}, false
		}
		if len(msg.Key) > 64 {
			return keeper.InputEvent{}, false
		}
		if msg.Modifiers < 0 || msg.Modifiers > 15 {
			return keeper.InputEvent{}, false
		}
		return keeper.InputEvent{
			Kind: keeper.InputKey, KeyType: msg.KeyType, Key: msg.Key,
			Text: msg.Text, Modifiers: msg.Modifiers,
		}, true
	case keeper.InputText:
		if len(msg.Text) == 0 || len(msg.Text) > 1024 {
			return keeper.InputEvent{}, false
		}
		return keeper.InputEvent{Kind: keeper.InputText, Text: msg.Text}, true
	case keeper.InputDone:
		return keeper.InputEvent{Kind: keeper.InputDone}, true
	case keeper.InputCancel:
		return keeper.InputEvent{Kind: keeper.InputCancel}, true
	default:
		return keeper.InputEvent{}, false
	}
}
