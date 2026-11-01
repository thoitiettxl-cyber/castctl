// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package webui

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"testing/fstest"
)

// On-disk frontend (webui.ui_dir) serving: containment,
// symlink handling, MIME allowlist, methods, auth precedence,
// startup fail-closed, and the save-time B-1 guard. Fixture
// values are FAKE markers only.

const uiDirShellMarker = "<html>MARKER-UIDIR-SHELL</html>"

func writeUIDir(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for rel, content := range files {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if _, ok := files["index.html"]; !ok {
		if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte(uiDirShellMarker), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func newUIDirDeps(t *testing.T, configDir, uiDir string) Deps {
	t.Helper()
	return Deps{
		ConfigDir:    configDir,
		Version:      "0.6.1-test",
		ListenAddr:   "127.0.0.1:8317",
		TokenHash:    testTokenHash(t),
		HasToken:     true,
		DistFS:       fstest.MapFS{"index.html": {Data: []byte("<html>castctl shell</html>")}},
		BundleSHA256: "test-bundle-hash",
		UIDir:        uiDir,
	}
}

func TestUIDirFallbackByteIdentical(t *testing.T) {
	// Absent ui_dir: the embedded shell, byte-identical, for
	// every path (hash routing).
	ts := newTestServer(t, fixtureConfig, nil)
	for _, path := range []string{"/", "/anything", "/deep/route"} {
		rec := ts.do(t, "GET", path, "", false)
		if rec.Code != http.StatusOK || rec.Body.String() != "<html>castctl shell</html>" {
			t.Fatalf("GET %s: %d %q, want the embedded shell", path, rec.Code, rec.Body.String())
		}
		if rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Fatalf("GET %s: shell headers = %v", path, rec.Header())
		}
	}
}

func TestUIDirServesRootAndAssets(t *testing.T) {
	uiDir := writeUIDir(t, map[string]string{
		"index.html":     uiDirShellMarker,
		"app.js":         "MARKER-JS",
		"style.css":      "MARKER-CSS",
		"data.json":      `{"k":"MARKER-JSON"}`,
		"pic.png":        "MARKER-PNG-BYTES",
		"weird.zzzunk":   "MARKER-UNKNOWN",
		"UPPER.HTML":     "MARKER-UPPER",
		"assets/app.mjs": "MARKER-MJS",
	})
	ts := newTestServer(t, fixtureConfig, func(d *Deps) { d.UIDir = uiDir })
	cases := []struct {
		path, body, ctype string
	}{
		{"/", uiDirShellMarker, "text/html; charset=utf-8"},
		{"/app.js", "MARKER-JS", "text/javascript; charset=utf-8"},
		{"/style.css", "MARKER-CSS", "text/css; charset=utf-8"},
		{"/data.json", `{"k":"MARKER-JSON"}`, "application/json"},
		{"/pic.png", "MARKER-PNG-BYTES", "image/png"},
		{"/weird.zzzunk", "MARKER-UNKNOWN", "application/octet-stream"},
		{"/UPPER.HTML", "MARKER-UPPER", "text/html; charset=utf-8"},
		{"/assets/app.mjs", "MARKER-MJS", "text/javascript; charset=utf-8"},
	}
	for _, tc := range cases {
		rec := ts.do(t, "GET", tc.path, "", false)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s: %d, want 200: %s", tc.path, rec.Code, rec.Body.String())
		}
		if rec.Body.String() != tc.body {
			t.Fatalf("GET %s: body = %q, want %q", tc.path, rec.Body.String(), tc.body)
		}
		if got := rec.Header().Get("Content-Type"); got != tc.ctype {
			t.Fatalf("GET %s: Content-Type = %q, want %q", tc.path, got, tc.ctype)
		}
		if rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Fatalf("GET %s: headers = %v", tc.path, rec.Header())
		}
		if tc.path != "/" {
			// The "/" shell fallback mirrors serveShell: no
			// Content-Length is set (chunked by the server).
			if rec.Header().Get("Content-Length") != strconv.Itoa(len(tc.body)) {
				t.Fatalf("GET %s: Content-Length = %q, want %d", tc.path, rec.Header().Get("Content-Length"), len(tc.body))
			}
		}
	}
	// Missing files under a valid root fall back to the shell.
	for _, path := range []string{"/missing", "/deep/route", "/nope.html"} {
		rec := ts.do(t, "GET", path, "", false)
		if rec.Code != http.StatusOK || rec.Body.String() != uiDirShellMarker {
			t.Fatalf("GET %s: %d %q, want the on-disk shell fallback", path, rec.Code, rec.Body.String())
		}
	}
}

func TestUIDirTraversalBlocked(t *testing.T) {
	// The ui root is a subdirectory; a secret sits next to it.
	// No traversal spelling may return it.
	parent := t.TempDir()
	uiDir := filepath.Join(parent, "ui")
	if err := os.MkdirAll(uiDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(uiDir, "index.html"), []byte(uiDirShellMarker), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(parent, "config.json"), []byte("MARKER-PARENT-SECRET"), 0o600); err != nil {
		t.Fatal(err)
	}
	ts := newTestServer(t, fixtureConfig, func(d *Deps) { d.UIDir = uiDir })
	for _, path := range []string{
		"/../config.json",
		"/%2e%2e/config.json",
		"/..%2fconfig.json",
		"/%2e%2e%2fconfig.json",
		"/assets/../../config.json",
		"/....//config.json",
	} {
		rec := ts.do(t, "GET", path, "", false)
		if strings.Contains(rec.Body.String(), "MARKER-PARENT-SECRET") {
			t.Fatalf("GET %s: parent secret leaked: %d %q", path, rec.Code, rec.Body.String())
		}
		if strings.Contains(rec.Body.String(), "FAKE-SECRET") {
			t.Fatalf("GET %s: config marker leaked: %d %q", path, rec.Code, rec.Body.String())
		}
		if rec.Code != http.StatusOK && rec.Code != http.StatusNotFound {
			t.Fatalf("GET %s: %d, want 200 (fallback) or 404", path, rec.Code)
		}
	}
}

func TestUIDirSymlinks(t *testing.T) {
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("MARKER-OUTSIDE-SECRET"), 0o600); err != nil {
		t.Fatal(err)
	}
	uiDir := writeUIDir(t, map[string]string{
		"real.txt": "MARKER-REAL",
	})
	// Symlink escaping the root: 404, never the target.
	if err := os.Symlink(filepath.Join(outside, "secret.txt"), filepath.Join(uiDir, "escape.txt")); err != nil {
		t.Fatal(err)
	}
	// Symlink staying inside the root: served.
	if err := os.Symlink("real.txt", filepath.Join(uiDir, "link.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(uiDir, "real.txt"), filepath.Join(uiDir, "abslink.txt")); err != nil {
		t.Fatal(err)
	}
	// Symlinked directory escaping the root: 404.
	if err := os.Symlink(outside, filepath.Join(uiDir, "escdir")); err != nil {
		t.Fatal(err)
	}
	ts := newTestServer(t, fixtureConfig, func(d *Deps) { d.UIDir = uiDir })
	for _, path := range []string{"/escape.txt", "/escdir/secret.txt"} {
		rec := ts.do(t, "GET", path, "", false)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("GET %s: %d, want 404", path, rec.Code)
		}
		if strings.Contains(rec.Body.String(), "MARKER-OUTSIDE-SECRET") {
			t.Fatalf("GET %s: outside secret leaked", path)
		}
	}
	for _, tc := range []struct{ path, body string }{
		{"/link.txt", "MARKER-REAL"},
		{"/abslink.txt", "MARKER-REAL"},
	} {
		rec := ts.do(t, "GET", tc.path, "", false)
		if rec.Code != http.StatusOK || rec.Body.String() != tc.body {
			t.Fatalf("GET %s: %d %q, want %q", tc.path, rec.Code, rec.Body.String(), tc.body)
		}
	}
	// The root itself may be a symlink: it resolves and serves.
	real := writeUIDir(t, map[string]string{"index.html": uiDirShellMarker, "a.txt": "MARKER-VIA-LINK"})
	linkRoot := filepath.Join(t.TempDir(), "linkroot")
	if err := os.Symlink(real, linkRoot); err != nil {
		t.Fatal(err)
	}
	ts2 := newTestServer(t, fixtureConfig, func(d *Deps) { d.UIDir = linkRoot })
	rec := ts2.do(t, "GET", "/a.txt", "", false)
	if rec.Code != http.StatusOK || rec.Body.String() != "MARKER-VIA-LINK" {
		t.Fatalf("symlinked root: %d %q", rec.Code, rec.Body.String())
	}
}

func TestUIDirDirectoryDotfileAndFIFO(t *testing.T) {
	uiDir := writeUIDir(t, map[string]string{
		"assets/inner.txt": "MARKER-INNER",
		".env":             "MARKER-DOTENV",
	})
	if err := os.MkdirAll(filepath.Join(uiDir, "assets"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(uiDir, "pipe"), 0o600); err != nil {
		t.Fatal(err)
	}
	ts := newTestServer(t, fixtureConfig, func(d *Deps) { d.UIDir = uiDir })
	// Directories never list: SPA fallback, no listing.
	for _, path := range []string{"/assets/", "/assets"} {
		rec := ts.do(t, "GET", path, "", false)
		if rec.Code != http.StatusOK || rec.Body.String() != uiDirShellMarker {
			t.Fatalf("GET %s: %d %q, want the shell fallback", path, rec.Code, rec.Body.String())
		}
		if strings.Contains(rec.Body.String(), "MARKER-INNER") {
			t.Fatalf("GET %s: directory listing leaked content", path)
		}
	}
	// Dotfiles are never served.
	for _, path := range []string{"/.env", "/assets/.hidden"} {
		rec := ts.do(t, "GET", path, "", false)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("GET %s: %d, want 404", path, rec.Code)
		}
		if strings.Contains(rec.Body.String(), "MARKER-DOTENV") {
			t.Fatalf("GET %s: dotfile leaked", path)
		}
	}
	// A FIFO is never opened (this must return promptly, not
	// block on the FIFO).
	rec := ts.do(t, "GET", "/pipe", "", false)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("GET /pipe: %d, want 404", rec.Code)
	}
}

func TestUIDirMethodsPinned(t *testing.T) {
	// GET-only for static paths, in both modes: the router
	// answers every other method with 405 (HEAD included —
	// chi does not map HEAD to GET).
	for _, withUIDir := range []bool{false, true} {
		var ts *testServer
		if withUIDir {
			uiDir := writeUIDir(t, map[string]string{"a.txt": "MARKER-A"})
			ts = newTestServer(t, fixtureConfig, func(d *Deps) { d.UIDir = uiDir })
		} else {
			ts = newTestServer(t, fixtureConfig, nil)
		}
		for _, method := range []string{"HEAD", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"} {
			rec := ts.do(t, method, "/", "", false)
			if rec.Code != http.StatusMethodNotAllowed {
				t.Fatalf("ui_dir=%v %s /: %d, want 405", withUIDir, method, rec.Code)
			}
			if !strings.Contains(rec.Body.String(), "method_not_allowed") {
				t.Fatalf("ui_dir=%v %s /: body = %q", withUIDir, method, rec.Body.String())
			}
		}
	}
}

func TestUIDirAuthUnchanged(t *testing.T) {
	uiDir := writeUIDir(t, map[string]string{
		"api/v1/nope": "MARKER-API-FILE",
	})
	for _, withUIDir := range []bool{false, true} {
		var ts *testServer
		if withUIDir {
			ts = newTestServer(t, fixtureConfig, func(d *Deps) { d.UIDir = uiDir })
		} else {
			ts = newTestServer(t, fixtureConfig, nil)
		}
		// No token: 401 on every API route, both modes.
		for _, path := range []string{"/api/v1/status", "/api/v1/profiles", "/api/v1/nope"} {
			rec := ts.do(t, "GET", path, "", false)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("ui_dir=%v GET %s without token: %d, want 401", withUIDir, path, rec.Code)
			}
		}
		// Right token: API works.
		rec := ts.do(t, "GET", "/api/v1/status", "", true)
		if rec.Code != http.StatusOK {
			t.Fatalf("ui_dir=%v authed status: %d", withUIDir, rec.Code)
		}
		// Authenticated unknown API path: shell fallback, never
		// a disk file — even one planted under api/v1/.
		rec = ts.do(t, "GET", "/api/v1/nope", "", true)
		if strings.Contains(rec.Body.String(), "MARKER-API-FILE") {
			t.Fatalf("ui_dir=%v: disk file served for an API path", withUIDir)
		}
	}
}

func TestNewUIDirFailsClosed(t *testing.T) {
	configDir := t.TempDir()
	outside := t.TempDir()
	// A config marker file: overlap cases must never serve it.
	if err := os.WriteFile(filepath.Join(configDir, "config.json"), []byte("MARKER-CONFIG"), 0o600); err != nil {
		t.Fatal(err)
	}
	valid := writeUIDir(t, map[string]string{"index.html": uiDirShellMarker})
	noIndex := writeUIDir(t, map[string]string{})
	_ = os.Remove(filepath.Join(noIndex, "index.html"))
	fileNotDir := filepath.Join(outside, "afile")
	if err := os.WriteFile(fileNotDir, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	dirIndex := writeUIDir(t, map[string]string{})
	_ = os.Remove(filepath.Join(dirIndex, "index.html"))
	if err := os.MkdirAll(filepath.Join(dirIndex, "index.html"), 0o755); err != nil {
		t.Fatal(err)
	}
	linkToConfig := filepath.Join(outside, "MARKER-UIDIR-LINK")
	if err := os.Symlink(configDir, linkToConfig); err != nil {
		t.Fatal(err)
	}
	// A symlinked index.html is refused at startup even when
	// its target is a regular file: outside the root (a secret)
	// and inside the root (a sibling file) alike.
	secretOutside := filepath.Join(outside, "MARKER-UIDIR-SECRET")
	if err := os.WriteFile(secretOutside, []byte("MARKER-OUTSIDE-SECRET"), 0o600); err != nil {
		t.Fatal(err)
	}
	linkIndexOutside := writeUIDir(t, map[string]string{"real.html": "MARKER-REAL"})
	_ = os.Remove(filepath.Join(linkIndexOutside, "index.html"))
	if err := os.Symlink(secretOutside, filepath.Join(linkIndexOutside, "index.html")); err != nil {
		t.Fatal(err)
	}
	linkIndexInside := writeUIDir(t, map[string]string{"real.html": "MARKER-REAL"})
	_ = os.Remove(filepath.Join(linkIndexInside, "index.html"))
	if err := os.Symlink("real.html", filepath.Join(linkIndexInside, "index.html")); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		uiDir string
	}{
		{"missing", filepath.Join(outside, "MARKER-UIDIR-MISSING")},
		{"file not dir", fileNotDir},
		{"no index.html", noIndex},
		{"index.html is dir", dirIndex},
		{"equal to config dir", configDir},
		{"inside config dir", filepath.Join(configDir, "ui")},
		{"ancestor of config dir", filepath.Dir(configDir)},
		{"symlink to config dir", linkToConfig},
		{"index.html symlink to outside secret", linkIndexOutside},
		{"index.html symlink inside root", linkIndexInside},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(newUIDirDeps(t, configDir, tc.uiDir))
			if err == nil {
				t.Fatalf("New with ui_dir %q succeeded, want failure", tc.uiDir)
			}
			if strings.Contains(err.Error(), "MARKER-UIDIR") {
				t.Fatalf("New error echoes the path: %v", err)
			}
		})
	}
	if _, err := New(newUIDirDeps(t, configDir, valid)); err != nil {
		t.Fatalf("New with a valid ui_dir failed: %v", err)
	}
	// Relative ui_dir resolves against the config dir — and is
	// then rejected by the same overlap rule.
	if _, err := New(newUIDirDeps(t, configDir, "ui")); err == nil {
		t.Fatal("New with relative inside ui_dir succeeded, want failure")
	}
}

func TestUIDirStatusHashPassthrough(t *testing.T) {
	uiDir := writeUIDir(t, map[string]string{"index.html": uiDirShellMarker})
	ts := newTestServer(t, fixtureConfig, func(d *Deps) {
		d.UIDir = uiDir
		d.BundleSHA256 = "MARKER-ONDISK-HASH"
	})
	rec := ts.do(t, "GET", "/api/v1/status", "", true)
	if rec.Code != http.StatusOK {
		t.Fatalf("status: %d: %s", rec.Code, rec.Body.String())
	}
	if decodeEnvelope(t, rec)["data"].(map[string]any)["bundle_sha256"] != "MARKER-ONDISK-HASH" {
		t.Fatalf("bundle_sha256 = %s", rec.Body.String())
	}
}

func TestUIDirNotRedactedInConfigView(t *testing.T) {
	// ui_dir is NOT a secret: the redacted config view shows
	// it verbatim, while the token stays redacted.
	uiDir := writeUIDir(t, map[string]string{"index.html": uiDirShellMarker})
	config := strings.Replace(fixtureConfig, `"dns":`, `"webui":{"listen":"127.0.0.1:8317","token":"MARKER-WEBUI-TOKEN","ui_dir":`+quoteUIDirJSON(uiDir)+`}, "dns":`, 1)
	ts := newTestServer(t, config, func(d *Deps) { d.UIDir = uiDir })
	rec := ts.do(t, "GET", "/api/v1/config", "", true)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET config: %d: %s", rec.Code, rec.Body.String())
	}
	content, _ := decodeEnvelope(t, rec)["data"].(map[string]any)["content"].(string)
	if !strings.Contains(content, uiDir) {
		t.Fatalf("ui_dir missing from redacted view:\n%s", content)
	}
	if strings.Contains(content, "MARKER-WEBUI-TOKEN") {
		t.Fatalf("token leaked into redacted view:\n%s", content)
	}
}

func quoteUIDirJSON(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// --- save-time B-1 guard -------------------------------------

func putConfigWithUIDir(t *testing.T, ts *testServer, uiDir string) (int, string) {
	t.Helper()
	rec := ts.do(t, http.MethodGet, "/api/v1/config", "", true)
	data := decodeEnvelope(t, rec)["data"].(map[string]any)
	content, _ := data["content"].(string)
	baseSHA, _ := data["sha256"].(string)
	doc := map[string]any{}
	if err := json.Unmarshal([]byte(content), &doc); err != nil {
		t.Fatal(err)
	}
	webuiBlock, _ := doc["webui"].(map[string]any)
	if webuiBlock == nil {
		webuiBlock = map[string]any{}
		doc["webui"] = webuiBlock
	}
	webuiBlock["ui_dir"] = uiDir
	body, _ := json.Marshal(doc)
	rec = ts.do(t, http.MethodPut, "/api/v1/config", postJSONBody(t, map[string]any{
		"base_sha256": baseSHA,
		"content":     string(body),
	}), true)
	return rec.Code, rec.Body.String()
}

func TestPutConfigRejectsOverlappingUIDir(t *testing.T) {
	ts := newTestServer(t, fixtureConfig, nil)
	before, err := os.ReadFile(filepath.Join(ts.dir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	// Symlink to the config dir: canonical overlap.
	outside := t.TempDir()
	link := filepath.Join(outside, "MARKER-UIDIR-LINK")
	if err := os.Symlink(ts.dir, link); err != nil {
		t.Fatal(err)
	}
	for name, uiDir := range map[string]string{
		"equal":      ts.dir,
		"inside":     filepath.Join(ts.dir, "ui"),
		"ancestor":   filepath.Dir(ts.dir),
		"symlink":    link,
		"dotdot":     filepath.Join(ts.dir, "sub", ".."),
		"relative":   "ui",
		"dot":        ".",
		"dotdot-rel": "..",
	} {
		t.Run(name, func(t *testing.T) {
			code, body := putConfigWithUIDir(t, ts, uiDir)
			if code != http.StatusBadRequest {
				t.Fatalf("PUT ui_dir %q: %d, want 400: %s", uiDir, code, body)
			}
			if strings.Contains(body, "MARKER-UIDIR") || strings.Contains(body, ts.dir) {
				t.Fatalf("rejection echoes the value: %s", body)
			}
			after, err := os.ReadFile(filepath.Join(ts.dir, "config.json"))
			if err != nil {
				t.Fatal(err)
			}
			if string(after) != string(before) {
				t.Fatalf("config file changed:\n%s", after)
			}
		})
	}
}

func TestPutConfigRejectsUIDirContainingCookies(t *testing.T) {
	// Cookies live outside the config dir (CLI-created
	// absolute path); a ui_dir over their directory is
	// rejected even though it does not overlap the config dir.
	outside := t.TempDir()
	cookiesFile := filepath.Join(outside, "cookies.txt")
	if err := os.WriteFile(cookiesFile, []byte("ORIGINAL-CONTENT"), 0o600); err != nil {
		t.Fatal(err)
	}
	ts := newTestServer(t, importConfigWithCookiesFile(cookiesFile), nil)
	before, err := os.ReadFile(filepath.Join(ts.dir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	code, body := putConfigWithUIDir(t, ts, outside)
	if code != http.StatusBadRequest {
		t.Fatalf("PUT ui_dir over cookies dir: %d, want 400: %s", code, body)
	}
	if strings.Contains(body, outside) {
		t.Fatalf("rejection echoes the value: %s", body)
	}
	after, err := os.ReadFile(filepath.Join(ts.dir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatalf("config file changed:\n%s", after)
	}
	content, err := os.ReadFile(cookiesFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "ORIGINAL-CONTENT" {
		t.Fatalf("cookies file changed: %q", content)
	}
}

func TestPutConfigAcceptsValidUIDirChange(t *testing.T) {
	// A ui_dir outside the config dir, not containing a
	// cookies file, saves; an unchanged ui_dir does not block
	// an unrelated edit.
	outside := t.TempDir()
	ts := newTestServer(t, fixtureConfig, nil)
	code, body := putConfigWithUIDir(t, ts, outside)
	if code != http.StatusOK {
		t.Fatalf("PUT valid ui_dir: %d, want 200: %s", code, body)
	}
	raw, _ := os.ReadFile(filepath.Join(ts.dir, "config.json"))
	if !strings.Contains(string(raw), outside) {
		t.Fatalf("ui_dir did not land:\n%s", raw)
	}
	// Unrelated edit with the ui_dir unchanged: still saves.
	rec := ts.do(t, http.MethodGet, "/api/v1/config", "", true)
	data := decodeEnvelope(t, rec)["data"].(map[string]any)
	content, _ := data["content"].(string)
	baseSHA, _ := data["sha256"].(string)
	edited := strings.Replace(content, `"fingerprint": "chrome"`, `"fingerprint": "firefox"`, 1)
	if edited == content {
		t.Fatal("fixture edit did not apply")
	}
	body2, _ := json.Marshal(map[string]any{"content": edited, "base_sha256": baseSHA})
	rec = ts.do(t, http.MethodPut, "/api/v1/config", string(body2), true)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT unrelated edit with ui_dir set: %d: %s", rec.Code, rec.Body.String())
	}
	// Changing to a second valid outside dir also saves.
	other := t.TempDir()
	code, body = putConfigWithUIDir(t, ts, other)
	if code != http.StatusOK {
		t.Fatalf("PUT changed ui_dir: %d, want 200: %s", code, body)
	}
}

// --- fix loop 1: symlinked index.html + root-swap regressions ---

func TestNewUIDirRejectsCookiesFileInsideRoot(t *testing.T) {
	// The cookies-exposure rule lives in New() via
	// Deps.CookiesFiles: a root containing a cookies file fails
	// closed even when a direct Server construction bypasses
	// the command layer.
	configDir := t.TempDir()
	uiDir := writeUIDir(t, map[string]string{"index.html": uiDirShellMarker})
	cookiesFile := filepath.Join(uiDir, "cookies.txt")
	if err := os.WriteFile(cookiesFile, []byte("MARKER-COOKIE"), 0o600); err != nil {
		t.Fatal(err)
	}
	deps := newUIDirDeps(t, configDir, uiDir)
	deps.CookiesFiles = []string{cookiesFile}
	if _, err := New(deps); err == nil {
		t.Fatal("New with a cookies file inside ui_dir succeeded, want failure")
	}
	// A cookies file outside the root does not block startup.
	other := t.TempDir()
	cookiesOutside := filepath.Join(other, "cookies.txt")
	if err := os.WriteFile(cookiesOutside, []byte("MARKER-COOKIE"), 0o600); err != nil {
		t.Fatal(err)
	}
	deps.CookiesFiles = []string{cookiesOutside}
	if _, err := New(deps); err != nil {
		t.Fatalf("New with a cookies file outside ui_dir failed: %v", err)
	}
}

func swapIndexToSymlink(t *testing.T, uiDir, target string) {
	t.Helper()
	index := filepath.Join(uiDir, "index.html")
	if err := os.Remove(index); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, index); err != nil {
		t.Fatal(err)
	}
}

func TestUIDirSymlinkedIndexSwappedMidRun(t *testing.T) {
	// A server started with a regular index.html must never
	// serve the target of a symlink swapped in afterwards —
	// per request, fixed 404, on every fallback path.
	outside := t.TempDir()
	secret := filepath.Join(outside, "secret.txt")
	if err := os.WriteFile(secret, []byte("MARKER-SWAPPED-SECRET"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Run("symlink to outside secret", func(t *testing.T) {
		uiDir := writeUIDir(t, map[string]string{
			"index.html": uiDirShellMarker,
			"app.js":     "MARKER-JS",
		})
		ts := newTestServer(t, fixtureConfig, func(d *Deps) { d.UIDir = uiDir })
		rec := ts.do(t, "GET", "/", "", false)
		if rec.Code != http.StatusOK || rec.Body.String() != uiDirShellMarker {
			t.Fatalf("before swap: %d %q, want the shell", rec.Code, rec.Body.String())
		}
		swapIndexToSymlink(t, uiDir, secret)
		for _, path := range []string{"/", "/missing", "/deep/route"} {
			rec := ts.do(t, "GET", path, "", false)
			if rec.Code != http.StatusNotFound {
				t.Fatalf("GET %s after swap: %d, want 404", path, rec.Code)
			}
			if strings.Contains(rec.Body.String(), "MARKER-SWAPPED-SECRET") {
				t.Fatalf("GET %s after swap: secret leaked", path)
			}
		}
		// Regular assets keep serving: only the shell
		// path is refused.
		rec = ts.do(t, "GET", "/app.js", "", false)
		if rec.Code != http.StatusOK || rec.Body.String() != "MARKER-JS" {
			t.Fatalf("GET /app.js after swap: %d %q, want the asset", rec.Code, rec.Body.String())
		}
	})
	t.Run("symlink inside root", func(t *testing.T) {
		uiDir := writeUIDir(t, map[string]string{
			"index.html": uiDirShellMarker,
			"real.html":  "MARKER-REAL-SHELL",
		})
		ts := newTestServer(t, fixtureConfig, func(d *Deps) { d.UIDir = uiDir })
		swapIndexToSymlink(t, uiDir, "real.html")
		rec := ts.do(t, "GET", "/", "", false)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("GET / after inside-root swap: %d, want 404", rec.Code)
		}
		if strings.Contains(rec.Body.String(), "MARKER-REAL-SHELL") {
			t.Fatal("inside-root symlinked shell served")
		}
	})
}

func TestUIDirSymlinkToDotfileRefused(t *testing.T) {
	// F-RT2-1: the asset path checked dotfiles only on the
	// request path, so a symlink resolving to a dotfile
	// inside the root served the dotfile (GET /index.html
	// and GET /x.js both 200 with the marker, while GET /
	// and GET /.secret were 404). The resolved
	// root-relative path is re-checked, and the opened file
	// must be the file the Lstat saw.
	t.Run("symlinked index requested as asset", func(t *testing.T) {
		uiDir := writeUIDir(t, map[string]string{
			"index.html": uiDirShellMarker,
			".secret":    "DOTFILE-MARKER-RT2",
		})
		ts := newTestServer(t, fixtureConfig, func(d *Deps) { d.UIDir = uiDir })
		// The startup check refuses a symlinked index.html,
		// so the swap happens after startup, as in the
		// demonstrated exploit.
		swapIndexToSymlink(t, uiDir, ".secret")
		for _, path := range []string{"/index.html", "/"} {
			rec := ts.do(t, "GET", path, "", false)
			if rec.Code != http.StatusNotFound {
				t.Fatalf("GET %s: %d, want 404", path, rec.Code)
			}
			if strings.Contains(rec.Body.String(), "DOTFILE-MARKER-RT2") {
				t.Fatalf("GET %s: dotfile marker leaked", path)
			}
		}
	})
	t.Run("symlink to dotfile under another name", func(t *testing.T) {
		uiDir := writeUIDir(t, map[string]string{
			"index.html": uiDirShellMarker,
			"app.js":     "MARKER-JS",
			".secret":    "DOTFILE-MARKER-RT2",
		})
		if err := os.Symlink(".secret", filepath.Join(uiDir, "x.js")); err != nil {
			t.Fatal(err)
		}
		ts := newTestServer(t, fixtureConfig, func(d *Deps) { d.UIDir = uiDir })
		for _, path := range []string{"/x.js", "/.secret"} {
			rec := ts.do(t, "GET", path, "", false)
			if rec.Code != http.StatusNotFound {
				t.Fatalf("GET %s: %d, want 404", path, rec.Code)
			}
			if strings.Contains(rec.Body.String(), "DOTFILE-MARKER-RT2") {
				t.Fatalf("GET %s: dotfile marker leaked", path)
			}
		}
		// A regular asset in the same root still serves.
		rec := ts.do(t, "GET", "/app.js", "", false)
		if rec.Code != http.StatusOK || rec.Body.String() != "MARKER-JS" {
			t.Fatalf("GET /app.js: %d %q, want the asset", rec.Code, rec.Body.String())
		}
	})
	t.Run("symlink to dotfile in a subdirectory", func(t *testing.T) {
		uiDir := writeUIDir(t, map[string]string{
			"index.html":  uiDirShellMarker,
			"sub/.secret": "DOTFILE-MARKER-RT2",
			"sub/ok.txt":  "MARKER-OK",
		})
		if err := os.Symlink("sub/.secret", filepath.Join(uiDir, "s.js")); err != nil {
			t.Fatal(err)
		}
		ts := newTestServer(t, fixtureConfig, func(d *Deps) { d.UIDir = uiDir })
		rec := ts.do(t, "GET", "/s.js", "", false)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("GET /s.js: %d, want 404", rec.Code)
		}
		if strings.Contains(rec.Body.String(), "DOTFILE-MARKER-RT2") {
			t.Fatal("GET /s.js: dotfile marker leaked")
		}
		rec = ts.do(t, "GET", "/sub/ok.txt", "", false)
		if rec.Code != http.StatusOK || rec.Body.String() != "MARKER-OK" {
			t.Fatalf("GET /sub/ok.txt: %d %q, want the asset", rec.Code, rec.Body.String())
		}
	})
}

func TestUIDirRootSwapRefused(t *testing.T) {
	// The ui root is reached through a symlink. Repointing
	// that symlink at the config directory after startup must
	// refuse every request (fixed 404), never serve config
	// content through the re-resolved root.
	realDir := writeUIDir(t, map[string]string{
		"index.html": uiDirShellMarker,
		"a.txt":      "MARKER-VIA-LINK",
	})
	linkRoot := filepath.Join(t.TempDir(), "linkroot")
	if err := os.Symlink(realDir, linkRoot); err != nil {
		t.Fatal(err)
	}
	ts := newTestServer(t, fixtureConfig, func(d *Deps) { d.UIDir = linkRoot })
	rec := ts.do(t, "GET", "/a.txt", "", false)
	if rec.Code != http.StatusOK || rec.Body.String() != "MARKER-VIA-LINK" {
		t.Fatalf("before swap: %d %q, want the asset", rec.Code, rec.Body.String())
	}
	if err := os.Remove(linkRoot); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(ts.dir, linkRoot); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/", "/a.txt", "/config.json", "/profiles/muse01/cookies.txt"} {
		rec := ts.do(t, "GET", path, "", false)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("GET %s after root swap: %d, want 404", path, rec.Code)
		}
		if strings.Contains(rec.Body.String(), "FAKE-SECRET") || strings.Contains(rec.Body.String(), "MARKER-VIA-LINK") {
			t.Fatalf("GET %s after root swap: content leaked: %q", path, rec.Body.String())
		}
	}
}

func TestPutConfigRejectsSymlinkedIndexUIDir(t *testing.T) {
	// PUT chain for the demonstrated F1 exploit: an
	// authenticated user sets ui_dir to a directory whose
	// index.html is a symlink to a secret outside the root.
	// The PUT must fail (400), the config file must not
	// change, and a server built with that ui_dir must fail
	// closed at startup.
	outside := t.TempDir()
	secret := filepath.Join(outside, "secret.txt")
	if err := os.WriteFile(secret, []byte("MARKER-PUT-SECRET"), 0o600); err != nil {
		t.Fatal(err)
	}
	evil := filepath.Join(outside, "evilui")
	if err := os.MkdirAll(evil, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, filepath.Join(evil, "index.html")); err != nil {
		t.Fatal(err)
	}
	ts := newTestServer(t, fixtureConfig, nil)
	before, err := os.ReadFile(filepath.Join(ts.dir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	code, body := putConfigWithUIDir(t, ts, evil)
	if code != http.StatusBadRequest {
		t.Fatalf("PUT symlinked-index ui_dir: %d, want 400: %s", code, body)
	}
	after, err := os.ReadFile(filepath.Join(ts.dir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatalf("config file changed:\n%s", after)
	}
	if _, err := New(newUIDirDeps(t, ts.dir, evil)); err == nil {
		t.Fatal("New with a symlinked index.html succeeded, want failure")
	}
}
