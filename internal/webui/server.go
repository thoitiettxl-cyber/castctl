// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

// Package webui is the castctl web UI HTTP server: a go-chi/chi
// router serving the committed single-file frontend (webui/dist)
// and the /api/v1 management API against the single config.json.
//
// Invariants (Boss-final scope, phase 2 item 2):
//
//   - Loopback only: the server binds a loopback address validated
//     by the `webui` config block (see internal/profile/webui.go).
//     There is no non-loopback listen in this build.
//   - Token auth: every /api/v1 route and every screencast endpoint
//     requires a Bearer token. The token itself is never logged,
//     returned, or echoed; comparison is bcrypt
//     CompareHashAndPassword against the stored hash (the config
//     file's `webui.token`, hashed on serve start / on save).
//     The static frontend shell is served WITHOUT auth:
//     it contains no secrets, and the login page needs the shell
//     to enter the token.
//   - Secrets write-only: GET endpoints return redacted views
//     (sentinel "<redacted>" at secret positions, per
//     webui/SECRETS-CONTRACT.md); PUT/POST set or replace secrets
//     without ever returning them. Cookie writes go through the
//     existing locked writer path (injected by the command layer),
//     never a new ad-hoc writer.
//   - Single config: all config mutations validate the FULL
//     config (parse + tag cross-references) before any write,
//     then write through the base guarded path (flock + hash
//     check, atomic temp+rename, mode 0600). No second lock
//     scheme, no separate config files.
//   - Log gate: the live-log endpoint reads the configured log
//     FILE only when logging is on and output is a file; with no
//     log block (or stderr output) it reports disabled. No log
//     ring is invented, and no raw server/peer response body is
//     ever emitted: only status, error class, length,
//     content-type, and allowlisted keys, with SafeString at the
//     API boundary.
//   - Screencast: the relay embeds internal/keeper only, through
//     the frozen Transport boundary. Without the with_chromedp
//     build tag the page and the API say unavailable. chromedp
//     must not appear in this package's untagged dependency
//     closure: this package imports keeper, never chromedp.
//     Honesty note (item-1 lesson): chromedp's attach bootstrap
//     enables Runtime/DOM/etc. internally; nothing in this
//     package, its docs, or its API responses claims otherwise.
//
// The server never logs: it has no logger and writes nothing to
// stderr. Error responses carry fixed messages or SafeString'd
// path-only config errors, never secret values or raw bodies.
package webui

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/thoitiettxl-cyber/castctl/internal/keeper"
	"github.com/thoitiettxl-cyber/castctl/internal/profile"
)

// ScreencastStarter runs one screencast login session for a
// profile over the given transport, returning the session's
// terminal report. It is injected by the command layer, which
// owns runtime construction (profile outbound checker, attach
// runner, LoginSession). A nil starter means screencast is
// unavailable in this build.
type ScreencastStarter func(ctx context.Context, profileName, sessionID string, transport keeper.Transport) (keeper.LoginResult, error)

// ScreencastAvailability reports whether a screencast session can
// start for a profile. Injected by the command layer: available
// only when the build carries chromedp AND a keeper entry names
// the profile. A nil seam means unavailable.
type ScreencastAvailability func(ctx context.Context, profileName string) (available bool, reason string, err error)

// Deps wires one Server. ConfigDir is the directory holding
// config.json. TokenHash is the stored bcrypt hash of the
// `webui` block token at startup (the command layer hashes a
// plaintext token on serve start and fails closed when no token
// is configured); HasToken must be true. The live comparator
// starts at TokenHash and is refreshed by refreshTokenHash
// after every successful guarded save that persists a token,
// so a rotation through the API takes effect without restart.
// DistFS serves the frontend shell;
// BundleSHA256 is the SHA-256 of the embedded dist/index.html.
// UIDir, when set, is an on-disk frontend directory served
// instead of DistFS (see uidir.go); BundleSHA256 is then the
// hash of the on-disk index.html, supplied by the command
// layer, and the embedded hash is used only in fallback mode.
type Deps struct {
	ConfigDir    string
	Version      string
	ListenAddr   string
	TokenHash    string
	HasToken     bool
	DistFS       fs.FS
	BundleSHA256 string
	UIDir        string
	// CookiesFiles, when set, is the list of profile cookies
	// file paths (as resolved at parse time, absolute). With
	// UIDir set, checkUIDir rejects a root containing any of
	// them, so the cookies-exposure rule lives in New() itself
	// and runs whenever CookiesFiles is supplied; the sole
	// production caller supplies the profile list, so the
	// rule is enforced on the production path. Empty
	// means no cookies-exposure check (tests and callers
	// without profiles).
	CookiesFiles []string

	// ImportCookies validates and writes cookies for a profile
	// through the existing locked writer path, returning whether
	// a .bak backup was made. Nil means cookie import is
	// unavailable (the handler reports it explicitly).
	ImportCookies func(ctx context.Context, profileName, content string) (backup bool, err error)
	// RestoreCookies restores a profile's .bak cookies file
	// through the locked writer path. Nil means unavailable.
	RestoreCookies func(ctx context.Context, profileName string) (restored bool, err error)
	// ScreencastAvailable and ScreencastStarter wire the keeper
	// screencast relay; nil means unavailable.
	ScreencastAvailable ScreencastAvailability
	ScreencastStarter   ScreencastStarter
}

// Server is one web UI HTTP server: chi router + session
// registry for screencast sessions. tokenHash is the live
// comparator for Bearer auth, guarded by tokenMu: it starts
// at Deps.TokenHash and is replaced by refreshTokenHash
// after a successful guarded save, so a save goroutine never
// races a request goroutine on the hash.
type Server struct {
	deps      Deps
	handler   http.Handler
	sessions  *sessionRegistry
	tokenMu   sync.RWMutex
	tokenHash string
}

// New builds a Server. It fails closed when no token is
// configured or the frontend filesystem is missing: the server
// never starts unauthenticated and never serves a partial shell.
// With UIDir set, the on-disk root must additionally be a
// directory holding a regular index.html and must not overlap
// the config directory (B-1: the static shell is
// unauthenticated, so an overlapping root would serve secrets);
// a present-but-broken root fails here, never by falling back
// to the embedded frontend.
func New(deps Deps) (*Server, error) {
	if deps.ConfigDir == "" {
		return nil, errors.New("webui: config directory is required")
	}
	if !deps.HasToken || deps.TokenHash == "" {
		return nil, errors.New("webui: no token configured")
	}
	if deps.DistFS == nil {
		return nil, errors.New("webui: frontend filesystem is required")
	}
	if _, err := fs.Stat(deps.DistFS, "index.html"); err != nil {
		return nil, fmt.Errorf("webui: frontend shell: %w", err)
	}
	if deps.UIDir != "" {
		if err := checkUIDir(deps.ConfigDir, deps.UIDir, deps.CookiesFiles); err != nil {
			return nil, err
		}
	}
	s := &Server{deps: deps, sessions: newSessionRegistry(), tokenHash: deps.TokenHash}
	s.handler = s.routes()
	return s, nil
}

// UIDirError is a fail-closed ui_dir configuration error
// from checkUIDir: missing, not a directory, no regular
// non-symlink index.html, overlapping the config directory,
// or containing a cookies file. It is a distinct type so
// callers can map it to exit 2 (configuration) rather than
// exit 1 (operational startup failure).
type UIDirError struct{ msg string }

func (e *UIDirError) Error() string { return e.msg }

// checkUIDir validates an on-disk frontend root at startup:
// a directory, holding a regular non-symlink index.html,
// resolved against the config directory, not overlapping it
// in either direction (equal, inside, or ancestor —
// symlink-resolved), and containing none of the cookies files
// when any are supplied. The index.html check uses Lstat: a
// symlink to a regular file must fail here, or the shell path
// would serve the link target unauthenticated. Error messages
// name the rule only, never the path.
func checkUIDir(configDir, uiDir string, cookiesFiles []string) error {
	root := resolveAgainst(configDir, uiDir)
	st, err := os.Stat(root)
	if err != nil || !st.IsDir() {
		return &UIDirError{"webui: ui_dir is not a readable directory"}
	}
	base := resolvePathBestEffort(configDir)
	if pathWithin(root, base) || pathWithin(base, root) {
		return &UIDirError{"webui: ui_dir must not overlap the config directory"}
	}
	for _, cookiesFile := range cookiesFiles {
		if cookiesFile == "" {
			continue
		}
		if pathWithin(resolvePathBestEffort(cookiesFile), root) {
			return &UIDirError{"webui: ui_dir must not contain a cookies file"}
		}
	}
	index, err := os.Lstat(filepath.Join(root, "index.html"))
	if err != nil || index.Mode()&os.ModeSymlink != 0 || !index.Mode().IsRegular() {
		return &UIDirError{"webui: ui_dir has no readable index.html"}
	}
	return nil
}

// Handler returns the server's HTTP handler (chi router with
// auth on /api/v1 only; the static shell is unauthenticated).
func (s *Server) Handler() http.Handler { return s.handler }

func (s *Server) routes() http.Handler {
	r := chi.NewRouter()
	r.Use(recoverer)
	r.MethodNotAllowed(methodNotAllowed)
	r.NotFound(s.serveStatic)
	api := chi.NewRouter()
	api.Use(s.requireAuth)
	api.Use(s.apiTimeout)
	api.Get("/status", s.handleStatus)
	api.Get("/profiles", s.handleListProfiles)
	api.Post("/profiles", s.handleCreateProfile)
	api.Get("/profiles/{name}", s.handleGetProfile)
	api.Patch("/profiles/{name}", s.handlePatchProfile)
	api.Delete("/profiles/{name}", s.handleDeleteProfile)
	api.Post("/profiles/{name}/rename", s.handleRenameProfile)
	api.Post("/profiles/{name}/set-default", s.handleSetDefaultProfile)
	api.Post("/profiles/{name}/test", handleUnavailableProfileTest)
	api.Get("/profiles/{name}/login/status", s.handleLoginStatus)
	api.Post("/profiles/{name}/login/import", s.handleLoginImport)
	api.Post("/profiles/{name}/login/restore", s.handleLoginRestore)
	api.Get("/outbounds", s.handleListOutbounds)
	api.Post("/outbounds", s.handleCreateOutbound)
	api.Post("/outbounds/validate", s.handleValidateOutbound)
	api.Get("/outbounds/{tag}", s.handleGetOutbound)
	api.Patch("/outbounds/{tag}", s.handlePatchOutbound)
	api.Delete("/outbounds/{tag}", s.handleDeleteOutbound)
	api.Post("/outbounds/{tag}/test", handleUnavailableOutboundTest)
	api.Get("/endpoints", s.handleListEndpoints)
	api.Post("/endpoints", s.handleCreateEndpoint)
	api.Post("/endpoints/import", s.handleImportEndpoint)
	api.Get("/endpoints/{tag}", s.handleGetEndpoint)
	api.Patch("/endpoints/{tag}", s.handlePatchEndpoint)
	api.Delete("/endpoints/{tag}", s.handleDeleteEndpoint)
	api.Get("/config", s.handleGetConfig)
	api.Put("/config", s.handlePutConfig)
	api.Post("/config/validate", s.handleValidateConfig)
	api.Get("/dns", s.handleGetDNS)
	api.Put("/dns", s.handlePutDNS)
	api.Get("/settings/telegram", s.handleGetTelegram)
	api.Put("/settings/telegram", s.handlePutTelegram)
	api.Get("/logs", s.handleGetLogs)
	api.Delete("/logs", handleLogsDeleteRefused)
	api.Get("/keeper", s.handleGetKeeper)
	api.Get("/screencast/status", s.handleScreencastStatus)
	api.Post("/screencast/{profile}/start", s.handleScreencastStart)
	api.Get("/screencast/ws", s.handleScreencastWS)
	r.Mount("/api/v1", api)
	// Everything else is the SPA shell (hash routing): the shell
	// itself carries no secrets and needs no token. With UIDir
	// set, static files under the on-disk root are served here
	// (GET only, contained, no listing); anything else falls
	// back to the shell.
	r.Get("/*", s.serveStatic)
	return r
}

// requireAuth is the Bearer-token gate for /api/v1. The presented
// token is hashed and compared in constant time against the
// configured token hash. Every failure — missing, malformed, or
// wrong — gets the same fixed 401 with no information leak: no
// hint whether a token is configured, no path/value echo.
//
// The screencast WebSocket (/screencast/ws) is the one exception:
// a browser WebSocket cannot set an Authorization header, so it
// authenticates with the single-use session token minted by
// POST /screencast/{profile}/start (checked before upgrade in
// the WS handler). A Bearer token must NEVER be put in a query
// string: query tokens leak to logs and history.
func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/screencast/ws") {
			next.ServeHTTP(w, r)
			return
		}
		if !s.authorized(r) {
			writeError(w, http.StatusUnauthorized, "unauthorized", "invalid or missing token")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) authorized(r *http.Request) bool {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return false
	}
	const prefix = "Bearer "
	if !strings.HasPrefix(auth, prefix) {
		return false
	}
	presented := strings.TrimPrefix(auth, prefix)
	if presented == "" || strings.ContainsAny(presented, " \t\r\n") {
		return false
	}
	// The stored hash is compared with bcrypt only: no plaintext
	// fallback, and any comparison error (malformed hash, empty
	// hash) rejects with the same generic 401 as a wrong token.
	// The hash is the live comparator, refreshed on save (see
	// refreshTokenHash), not the startup snapshot.
	s.tokenMu.RLock()
	hash := s.tokenHash
	s.tokenMu.RUnlock()
	return profile.CompareWebUIToken(hash, presented)
}

// refreshTokenHash refreshes the live comparator from the
// persisted document after a successful guarded save, so a
// token rotated through the API takes effect on the running
// server immediately, with no restart. It runs only after
// Save succeeds: a failed save leaves the live comparator
// untouched. A sentinel keep-on-save re-adopts the unchanged
// stored hash (a no-op). A save whose document carries no
// webui token clears the comparator — but only when the
// stored document carried one (hadToken): the token is gone,
// so every authenticated request fails closed with 401 until
// a token is restored out-of-band (file edit + restart,
// since a token-less server accepts no Bearer token with
// which to save a new one through the API). When the stored
// document never carried a token, the comparator came from
// the startup Deps, not the file, and the save leaves it
// untouched.
func (s *Server) refreshTokenHash(parsed *profile.SingleConfig, hadToken bool) {
	var hash string
	if parsed != nil && parsed.WebUI != nil {
		hash = parsed.WebUI.Token
	}
	if hash == "" && !hadToken {
		return
	}
	s.tokenMu.Lock()
	s.tokenHash = hash
	s.tokenMu.Unlock()
}

// apiHandlerTimeout is the context timeout applied to non-WS
// API handlers (loop-2 F4). Overridable in tests; the
// production default is 30s.
var apiHandlerTimeout = 30 * time.Second

// apiTimeout bounds a handler by a context timeout, replying
// 503 with a fixed timeout envelope when the handler does not
// finish in time. The screencast WebSocket is excluded: it is
// a long-lived session, and a context timeout would kill it.
// No other API handler is long-lived: every config read/write
// and keeper status read completes immediately.
//
// The handler runs against a buffered writer so a timeout can
// still reply cleanly; a handler that finishes after the
// timeout has its output discarded. A panic in the handler
// goroutine is re-panicked on the request goroutine so the
// outer recoverer keeps converting it to a fixed 500.
func (s *Server) apiTimeout(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/screencast/ws") {
			next.ServeHTTP(w, r)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), apiHandlerTimeout)
		defer cancel()
		buf := &timeoutBuffer{header: make(http.Header)}
		done := make(chan struct{})
		var panicked any
		go func() {
			defer func() {
				if p := recover(); p != nil {
					panicked = p
				}
				close(done)
			}()
			next.ServeHTTP(buf, r.WithContext(ctx))
		}()
		select {
		case <-done:
			if panicked != nil {
				panic(panicked)
			}
			buf.writeTo(w)
		case <-ctx.Done():
			writeError(w, http.StatusServiceUnavailable, "timeout", "request timed out")
		}
	})
}

// timeoutBuffer is a mutex-guarded ResponseWriter buffer: the
// handler goroutine may keep writing after the middleware has
// replied, so the buffer must stay safe to write after the
// read-out. writeTo runs only after the handler goroutine has
// finished (the done channel closes in its defer), so the
// header map is never read concurrently with a handler write.
type timeoutBuffer struct {
	mu          sync.Mutex
	header      http.Header
	status      int
	wroteHeader bool
	body        []byte
}

func (b *timeoutBuffer) Header() http.Header { return b.header }

func (b *timeoutBuffer) WriteHeader(status int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.wroteHeader {
		b.status = status
		b.wroteHeader = true
	}
}

func (b *timeoutBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.wroteHeader {
		b.status = http.StatusOK
		b.wroteHeader = true
	}
	b.body = append(b.body, p...)
	return len(p), nil
}

func (b *timeoutBuffer) writeTo(w http.ResponseWriter) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for k, vs := range b.header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	status := b.status
	if !b.wroteHeader {
		status = http.StatusOK
	}
	w.WriteHeader(status)
	_, _ = w.Write(b.body)
}

// recoverer converts a handler panic into a fixed 500 envelope
// with no stack and no value text: a panic on an API path must
// never leak a secret-bearing stack trace.
func recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if recover() != nil {
				writeError(w, http.StatusInternalServerError, "internal_error", "internal error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func methodNotAllowed(w http.ResponseWriter, r *http.Request) {
	writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
}

// serveShell serves the embedded single-file frontend. It is
// deliberately unauthenticated: the shell contains no secrets,
// and the login page needs it to enter the token. Every path
// that matches no API route falls back to the shell (hash
// routing) — including unknown /api/v1 paths, which return
// the 200 shell rather than a 404: the mount falls through to
// the root NotFound handler. Unauthenticated unknown /api/v1
// paths still 401 (requireAuth runs before the fallthrough);
// only known API routes return API envelopes. The shell itself
// carries no secrets.
func (s *Server) serveShell(w http.ResponseWriter, r *http.Request) {
	data, err := fs.ReadFile(s.deps.DistFS, "index.html")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "internal error")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(data)
}

// apiError is a handler error carrying an HTTP status, a stable
// envelope type, and a fixed or path-only message. Messages must
// never contain secret values or raw response bodies; callers
// pass internal error text through safeMessage first.
type apiError struct {
	status int
	typ    string
	msg    string
}

func (e *apiError) Error() string { return e.msg }

func errValidation(msg string) *apiError {
	return &apiError{status: http.StatusBadRequest, typ: "validation_failed", msg: msg}
}

func errNotFound(msg string) *apiError {
	return &apiError{status: http.StatusNotFound, typ: "not_found", msg: msg}
}

func errConfigChanged() *apiError {
	return &apiError{status: http.StatusConflict, typ: "config_changed", msg: "the config file changed on disk since it was loaded"}
}

func errInternal() *apiError {
	return &apiError{status: http.StatusInternalServerError, typ: "internal_error", msg: "internal error"}
}

// writeEnvelope writes a success envelope {data: ...}.
func writeEnvelope(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"data": data})
}

// writeError writes an error envelope {error: {type, message}}.
// A nil *apiError is a fixed internal error.
func writeError(w http.ResponseWriter, status int, typ, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"type": typ, "message": msg}})
}

func writeAPIError(w http.ResponseWriter, err error) {
	var ae *apiError
	if errors.As(err, &ae) {
		writeError(w, ae.status, ae.typ, ae.msg)
		return
	}
	writeError(w, http.StatusInternalServerError, "internal_error", "internal error")
}

// decodeBody decodes a JSON request body with a size cap into dst.
// Unknown fields are rejected: a typo'd field must fail loudly
// rather than silently do nothing. The returned error is always a
// fixed validation message — request bytes are never echoed.
func decodeBody(w http.ResponseWriter, r *http.Request, maxBytes int64, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
	dec := json.NewDecoder(r.Body)
	dec.UseNumber()
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return errValidation("invalid JSON in request body")
	}
	var extra any
	if err := dec.Decode(&extra); err != nil && !errors.Is(err, io.EOF) {
		return errValidation("invalid JSON in request body")
	}
	return nil
}

// bodyJSON decodes a request body into a generic JSON value with a
// size cap, preserving numbers via UseNumber. The returned error
// is always a fixed validation message.
func bodyJSON(w http.ResponseWriter, r *http.Request, maxBytes int64) (any, error) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
	dec := json.NewDecoder(r.Body)
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, errValidation("invalid JSON in request body")
	}
	var extra any
	if err := dec.Decode(&extra); err != nil && !errors.Is(err, io.EOF) {
		return nil, errValidation("invalid JSON in request body")
	}
	return v, nil
}

// nowUTC is overridable in tests for timestamp fields.
var nowUTC = func() time.Time { return time.Now().UTC() }
