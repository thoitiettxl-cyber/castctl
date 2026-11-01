// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package webui

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// On-disk frontend directory (`webui.ui_dir` in config.json).
//
// When Deps.UIDir is set, the unauthenticated static shell is
// served from that directory instead of the embedded frontend:
// the directory holds public static files (HTML/JS/CSS/assets)
// and carries no secrets, so it needs no token — exactly like
// the embedded shell. The /api/v1 routes keep their Bearer gate
// and keep precedence: an API path that falls through to the
// static handler never reads a disk file.
//
// Containment is re-run per request with the symlink-aware
// helpers from contain.go (resolveAgainst / pathWithin): no
// verdict is cached across renames, symlinks that leave the
// root are refused, directories never list, and only regular
// files are served. The root-vs-config overlap rule is also
// re-checked per request: a root repointed at the config tree
// after startup is refused instead of followed. A missing file
// under a valid root falls back to the on-disk shell (SPA hash
// routing, F1). A present-but-broken root (missing, not a
// directory, no regular index.html) is rejected at startup by
// New() and by the command layer; it never silently falls back
// to the embedded frontend.
//
// The shell file itself (index.html) is never served through
// a symlink: any symlinked index.html is refused at startup
// (exit 2) and per request (fixed 404), even when its target
// stays inside the root — the shell path must only ever serve
// the regular file startup validated. ui_dir content is
// trusted same-origin code (the frontend keeps the token in
// sessionStorage): serve only content from a trusted source.
//
// Residual (documented honestly, same candour as the shell
// side): between the per-request containment resolution and
// the open, a swapped symlink can redirect the read, and a
// swapped-in FIFO could block one request goroutine
// (check-then-open TOCTOU). The open is followed by an fstat
// re-check, so a steady-state non-regular file is never
// served; the shell path additionally requires the opened
// file to be the same file the Lstat saw (os.SameFile), so a
// symlink swapped in between the Lstat and the open is
// refused instead of served. The window is one open call;
// nothing here claims it closed.

// uiDirMIME is the closed extension allowlist for on-disk
// frontend files. Anything unlisted is served as
// application/octet-stream. mime.TypeByExtension is never
// used: the host MIME database is untrusted input at a
// security boundary, and must not decide a served
// Content-Type.
var uiDirMIME = map[string]string{
	".html":  "text/html; charset=utf-8",
	".js":    "text/javascript; charset=utf-8",
	".mjs":   "text/javascript; charset=utf-8",
	".css":   "text/css; charset=utf-8",
	".json":  "application/json",
	".map":   "application/json",
	".txt":   "text/plain; charset=utf-8",
	".png":   "image/png",
	".jpg":   "image/jpeg",
	".jpeg":  "image/jpeg",
	".gif":   "image/gif",
	".svg":   "image/svg+xml",
	".webp":  "image/webp",
	".avif":  "image/avif",
	".ico":   "image/x-icon",
	".woff":  "font/woff",
	".woff2": "font/woff2",
	".ttf":   "font/ttf",
	".otf":   "font/otf",
	".wasm":  "application/wasm",
}

func uiDirContentType(name string) string {
	if ct, ok := uiDirMIME[strings.ToLower(filepath.Ext(name))]; ok {
		return ct
	}
	return "application/octet-stream"
}

// serveStatic serves the unauthenticated frontend shell: the
// embedded build, or static files from Deps.UIDir when set.
func (s *Server) serveStatic(w http.ResponseWriter, r *http.Request) {
	if s.deps.UIDir == "" {
		s.serveShell(w, r)
		return
	}
	s.serveUIDir(w, r)
}

// uidirRootOverlapsConfig reports whether the per-request
// resolved root overlaps the config directory in either
// direction. Re-checked on every request so a root repointed
// at the config tree after startup (symlink retargeted, root
// swapped) is refused instead of followed.
func (s *Server) uidirRootOverlapsConfig(root string) bool {
	base := resolvePathBestEffort(s.deps.ConfigDir)
	return pathWithin(root, base) || pathWithin(base, root)
}

// serveUIDir serves one request from the on-disk frontend
// root. Only GET requests read disk files: the router already
// answers other methods on static paths with 405, and any
// method reaching here through the /api/v1 fallthrough gets
// the shell, never a file.
func (s *Server) serveUIDir(w http.ResponseWriter, r *http.Request) {
	root := resolveAgainst(s.deps.ConfigDir, s.deps.UIDir)
	if s.uidirRootOverlapsConfig(root) {
		// The root overlaps the config tree (swapped after
		// startup): serve nothing, fixed 404, never a file.
		writeError(w, http.StatusNotFound, "not_found", "not found")
		return
	}
	// /api/v1 precedence: an API path that fell through to
	// the static handler (authenticated, unknown route) never
	// reads a disk file, even one that exists under the root.
	if r.URL.Path == "/api/v1" || strings.HasPrefix(r.URL.Path, "/api/v1/") {
		s.serveUIDirShell(w, r, root)
		return
	}
	if r.Method != http.MethodGet {
		s.serveUIDirShell(w, r, root)
		return
	}
	rel := strings.TrimPrefix(r.URL.Path, "/")
	// Dotfiles are never served (defence in depth: a stray
	// .env or .git file landing in the served tree must not
	// become readable). "." and ".." components are left to
	// resolveAgainst, which pops them against the resolved
	// prefix.
	for _, comp := range strings.Split(rel, "/") {
		if comp != "." && comp != ".." && strings.HasPrefix(comp, ".") {
			writeError(w, http.StatusNotFound, "not_found", "not found")
			return
		}
	}
	resolved := resolveAgainst(root, rel)
	if !pathWithin(resolved, root) {
		// Traversal out of the root: fixed 404, never a file,
		// never a path echo.
		writeError(w, http.StatusNotFound, "not_found", "not found")
		return
	}
	st, err := os.Stat(resolved)
	if err != nil {
		// Missing file under a valid root: SPA fallback.
		s.serveUIDirShell(w, r, root)
		return
	}
	if st.IsDir() {
		// Directories never list: SPA fallback.
		s.serveUIDirShell(w, r, root)
		return
	}
	if !st.Mode().IsRegular() {
		// FIFO, socket, device: fixed 404, never opened (an
		// open could block on a FIFO).
		writeError(w, http.StatusNotFound, "not_found", "not found")
		return
	}
	f, err := os.Open(resolved)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "internal error")
		return
	}
	defer func() { _ = f.Close() }()
	// Open-then-verify: the type is re-checked on the open
	// file, so a non-regular file swapped in between Stat and
	// Open is refused instead of served.
	fst, err := f.Stat()
	if err != nil || !fst.Mode().IsRegular() {
		writeError(w, http.StatusNotFound, "not_found", "not found")
		return
	}
	w.Header().Set("Content-Type", uiDirContentType(resolved))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Length", strconv.FormatInt(fst.Size(), 10))
	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, f)
}

// serveUIDirShell serves the on-disk shell (the root's
// index.html) for SPA fallback paths. It mirrors serveShell's
// headers. A root whose index.html vanished mid-run is a fixed
// 500: the server was validated at startup, and a broken root
// must not silently downgrade to the embedded frontend. A
// symlinked index.html is a fixed 404, never the link target:
// the shell path only serves the regular file startup
// validated, and a symlink swapped in after startup must not
// redirect the shell read to a secret.
func (s *Server) serveUIDirShell(w http.ResponseWriter, r *http.Request, root string) {
	if s.uidirRootOverlapsConfig(root) {
		writeError(w, http.StatusNotFound, "not_found", "not found")
		return
	}
	index := filepath.Join(root, "index.html")
	lst, err := os.Lstat(index)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "internal error")
		return
	}
	if lst.Mode()&os.ModeSymlink != 0 {
		writeError(w, http.StatusNotFound, "not_found", "not found")
		return
	}
	if !lst.Mode().IsRegular() {
		writeError(w, http.StatusInternalServerError, "internal_error", "internal error")
		return
	}
	f, err := os.Open(index)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "internal error")
		return
	}
	defer func() { _ = f.Close() }()
	// Open-then-verify: the opened file must be regular and
	// the same file the Lstat saw, so a symlink swapped in
	// between the Lstat and the open is refused instead of
	// served.
	fst, err := f.Stat()
	if err != nil || !fst.Mode().IsRegular() || !os.SameFile(lst, fst) {
		writeError(w, http.StatusNotFound, "not_found", "not found")
		return
	}
	data, err := io.ReadAll(f)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "internal error")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(data)
}
