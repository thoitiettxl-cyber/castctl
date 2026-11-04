// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package commands

// PR-F owner commands: /profile (display-only), /update
// (check-only), /login (cookie-awaiting), /raw (route-checked
// gateway call), behind the owner gate. No live network, no
// real token, no real cookies: cookie fixtures use MARKER
// strings, and every login test asserts the markers appear in
// no send, no document, no edit, and no captured log line.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"strings"
	"sync"
	"testing"

	"github.com/thoitiettxl-cyber/castctl/internal/gateway"
	"github.com/thoitiettxl-cyber/castctl/internal/update"
)

// ownerOnlySentence and loginNoHatchSessSentence are the
// production constants (telegram_owner.go), asserted
// byte-identical to upstream in the gate/login tests.

// Marker cookie fixtures: recognisable, never real cookies.
const (
	loginMarkerSession = "MARKERSESSIONAAA111"
	loginMarkerOther   = "MARKEROTHERBBB222"
	loginMarkerText    = "hatch_sess=" + loginMarkerSession + "; other=" + loginMarkerOther
)

func telegramTestConfigWithOwner(owner int64, allowlist []int64) string {
	ids := make([]string, len(allowlist))
	for i, id := range allowlist {
		ids[i] = fmt.Sprint(id)
	}
	return `{"default_profile":"default","profiles":{"default":{},"muse01":{}},"telegram":{"profile":"muse01","token":"` + telegramTestToken + `","allowed_user_ids":[` + strings.Join(ids, ",") + `],"owner_id":` + fmt.Sprint(owner) + `}}`
}

func telegramTestConfigTwoUsers() string {
	return `{"default_profile":"default","profiles":{"default":{},"muse01":{}},"telegram":{"profile":"muse01","token":"` + telegramTestToken + `","allowed_user_ids":[111,222],"owner_id":111}}`
}

// telegramDocumentUpdate builds one getUpdates batch carrying a
// document message (no text) with the given message id.
func telegramDocumentUpdate(updateID, userID, messageID int64, fileID, fileName, mime string, size int64) string {
	return fmt.Sprintf(`{"ok":true,"result":[{"update_id":%d,"message":{"message_id":%d,"date":1700000000,"chat":{"id":500,"type":"private"},"from":{"id":%d,"is_bot":false,"first_name":"Tester"},"document":{"file_id":%q,"file_unique_id":"unique-%s","file_name":%q,"mime_type":%q,"file_size":%d}}}]}`,
		updateID, messageID, userID, fileID, fileID, fileName, mime, size)
}

// telegramPhotoUpdate builds one getUpdates batch carrying a
// photo message (no text, no caption) with the given message id.
func telegramPhotoUpdate(updateID, userID, messageID int64) string {
	return fmt.Sprintf(`{"ok":true,"result":[{"update_id":%d,"message":{"message_id":%d,"date":1700000000,"chat":{"id":500,"type":"private"},"from":{"id":%d,"is_bot":false,"first_name":"Tester"},"photo":[{"file_id":"photofid","file_unique_id":"unique-photo","file_size":5,"width":100,"height":100}]}}]}`,
		updateID, messageID, userID)
}

// captureLogger returns a slog logger writing to a
// mutex-guarded buffer (lockedBuffer lives in keeper_test.go).
func captureLogger() (*slog.Logger, *lockedBuffer) {
	lb := &lockedBuffer{}
	return slog.New(slog.NewTextHandler(lb, nil)), lb
}

func assertNoMarker(t *testing.T, what string, texts []string, logs string) {
	t.Helper()
	for _, marker := range []string{loginMarkerSession, loginMarkerOther} {
		for _, text := range texts {
			if strings.Contains(text, marker) {
				t.Errorf("%s carries the cookie marker %q: %q", what, marker, text)
			}
		}
		if strings.Contains(logs, marker) {
			t.Errorf("%s logs carry the cookie marker %q: %q", what, marker, logs)
		}
	}
}

func allSendsAndEdits(h *telegramBotHarness) []string {
	out := append([]string(nil), sendsOf(h)...)
	out = append(out, h.fake.editTexts()...)
	for _, d := range h.fake.documentsSeen() {
		out = append(out, d.Caption, d.Filename)
	}
	return out
}

func stopBot(t *testing.T, cancel context.CancelFunc, codeCh chan int) {
	t.Helper()
	cancel()
	if code := <-codeCh; code != 130 {
		t.Errorf("run code = %d; want 130", code)
	}
}

// TestTelegramOwnerGateNoOwner: with no owner_id configured,
// all four owner commands answer the fixed owner-only
// sentence, with zero gateway traffic.
func TestTelegramOwnerGateNoOwner(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	h, cancel, codeCh := runTelegramBot(t, gw, []string{
		telegramUpdate(1, 111, "/profile"),
		telegramUpdate(2, 111, "/update"),
		telegramUpdate(3, 111, "/login"),
		telegramUpdate(4, 111, "/raw sessions.list"),
	})
	defer cancel()
	waitFor(t, "4 owner-only replies", func() bool { return len(sendsOf(h)) >= 4 })
	stopBot(t, cancel, codeCh)
	sends := sendsOf(h)
	if len(sends) != 4 {
		t.Fatalf("sends = %d, want 4: %q", len(sends), sends)
	}
	for i, s := range sends {
		if s != ownerOnlySentence {
			t.Errorf("sends[%d] = %q; want %q", i, s, ownerOnlySentence)
		}
	}
	hist, streams, subs, _ := gw.counts()
	if hist != 0 || streams != 0 || subs != 0 {
		t.Errorf("gateway counts history=%d streams=%d subscribes=%d; want 0 (gate fires before any call)", hist, streams, subs)
	}
	if len(gw.rawCallsSeen()) != 0 {
		t.Errorf("raw calls = %d; want 0", len(gw.rawCallsSeen()))
	}
}

// TestTelegramOwnerGateWrongUID: owner set, a different
// allowlisted uid gets the same fixed sentence.
func TestTelegramOwnerGateWrongUID(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	h, cancel, codeCh := runTelegramBotWithConfig(t, gw, []string{
		telegramUpdate(1, 222, "/profile"),
		telegramUpdate(2, 222, "/update"),
		telegramUpdate(3, 222, "/login"),
		telegramUpdate(4, 222, "/raw sessions.list"),
	}, telegramTestConfigTwoUsers(), nil)
	defer cancel()
	waitFor(t, "4 owner-only replies", func() bool { return len(sendsOf(h)) >= 4 })
	stopBot(t, cancel, codeCh)
	sends := sendsOf(h)
	if len(sends) != 4 {
		t.Fatalf("sends = %d, want 4: %q", len(sends), sends)
	}
	for i, s := range sends {
		if s != ownerOnlySentence {
			t.Errorf("sends[%d] = %q; want %q", i, s, ownerOnlySentence)
		}
	}
	if len(gw.rawCallsSeen()) != 0 {
		t.Errorf("raw calls = %d; want 0", len(gw.rawCallsSeen()))
	}
}

// TestTelegramOwnerGateOwnerRuns: the owner uid passes the
// gate on all four commands (update covered by the DryRun
// test; here profile/raw/login must proceed past the gate).
func TestTelegramOwnerOutsideAllowlist(t *testing.T) {
	t.Parallel()
	// D2: the owner need not be listed in allowed_user_ids —
	// cmdTelegramRun merges the owner into the effective
	// allowlist. Without the merge the update is dropped
	// silently before dispatch and this test times out.
	gw := newTelegramTurnFakeGateway()
	h, cancel, codeCh := runTelegramBotWithConfig(t, gw, []string{
		telegramUpdate(1, 333, "/profile"),
	}, telegramTestConfigWithOwner(333, []int64{111}), nil)
	defer cancel()
	waitFor(t, "owner-outside-allowlist profile reply", func() bool { return len(sendsOf(h)) >= 1 })
	stopBot(t, cancel, codeCh)
	sends := sendsOf(h)
	if len(sends) != 1 {
		t.Fatalf("sends = %d, want 1: %q", len(sends), sends)
	}
	if sends[0] == ownerOnlySentence {
		t.Errorf("owner outside the allowlist got the refusal sentence: %q", sends[0])
	}
	if !strings.Contains(sends[0], "Serving profile") {
		t.Errorf("/profile send = %q; want the display reply", sends[0])
	}
}

func TestTelegramOwnerGateOwnerRuns(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	gw.rawScript = []byte(`{"sessions":[]}`)
	h, cancel, codeCh := runTelegramBotWithConfig(t, gw, []string{
		telegramUpdate(1, 111, "/profile"),
		telegramUpdate(2, 111, "/raw sessions.list"),
		telegramUpdate(3, 111, "/login"),
	}, telegramTestConfigWithOwner(111, []int64{111}), nil)
	defer cancel()
	waitFor(t, "3 owner replies", func() bool { return len(sendsOf(h)) >= 3 })
	stopBot(t, cancel, codeCh)
	sends := sendsOf(h)
	if len(sends) != 3 {
		t.Fatalf("sends = %d, want 3: %q", len(sends), sends)
	}
	for _, s := range sends {
		if s == ownerOnlySentence {
			t.Errorf("owner got the refusal sentence: %q", s)
		}
	}
	if !strings.Contains(sends[0], "Serving profile") {
		t.Errorf("/profile send = %q; want the display reply", sends[0])
	}
	if len(gw.rawCallsSeen()) != 1 || gw.rawCallsSeen()[0].Method != "sessions.list" {
		t.Errorf("raw calls = %+v; want one sessions.list call", gw.rawCallsSeen())
	}
	if !strings.Contains(sends[2], "Send the muse.ai cookies now") {
		t.Errorf("/login send = %q; want the instruction reply", sends[2])
	}
}

// TestTelegramProfileDisplay: name + configured VM id +
// cookies presence, no absolute path, no cookie bytes, zero
// gateway calls.
func TestTelegramProfileDisplay(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	h, cancel, codeCh := runTelegramBotWithConfig(t, gw, []string{
		telegramUpdate(1, 111, "/profile"),
	}, telegramTestConfigWithOwner(111, []int64{111}), nil)
	defer cancel()
	waitFor(t, "profile reply", func() bool { return len(sendsOf(h)) >= 1 })
	stopBot(t, cancel, codeCh)
	sends := sendsOf(h)
	if len(sends) != 1 {
		t.Fatalf("sends = %d, want 1: %q", len(sends), sends)
	}
	reply := sends[0]
	if !strings.Contains(reply, "<b>muse01</b>") {
		t.Errorf("profile reply names no profile: %q", reply)
	}
	if !strings.Contains(reply, "<code>vm-test</code>") {
		t.Errorf("profile reply carries no VM id: %q", reply)
	}
	if !strings.Contains(reply, "Cookies: missing") {
		t.Errorf("profile reply = %q; want Cookies: missing (no cookies file for muse01 in the harness)", reply)
	}
	if strings.Contains(reply, h.homeDir) {
		t.Errorf("profile reply contains the absolute home path: %q", reply)
	}
	if strings.Contains(reply, "cookies.txt") && strings.Contains(reply, "/") {
		t.Errorf("profile reply looks path-bearing: %q", reply)
	}
	if !strings.Contains(reply, "not available from chat") {
		t.Errorf("profile reply states no switch: %q", reply)
	}
	if strings.Contains(reply, "castctl --profile") {
		t.Errorf("profile reply carries the bare --profile hint: %q", reply)
	}
	hist, streams, subs, _ := gw.counts()
	if hist != 0 || streams != 0 || subs != 0 {
		t.Errorf("gateway counts history=%d streams=%d subscribes=%d; want 0 (display-only, no gateway call)", hist, streams, subs)
	}
}

// TestTelegramProfileDisplayCookiesPresent: a non-empty
// cookies file reports present (seeded via the batch gate,
// before the /profile batch is served).
func TestTelegramProfileDisplayCookiesPresent(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	var homeDir string
	seed := func(f *cmdFakeTelegram) bool {
		if homeDir == "" {
			return false
		}
		dir := filepath.Join(homeDir, "profiles", "muse01")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return false
		}
		if err := os.WriteFile(filepath.Join(dir, "cookies.txt"), []byte("hatch_sess=seed;"), 0o600); err != nil {
			return false
		}
		return true
	}
	h, cancel, codeCh := runTelegramBotWithConfig(t, gw, []string{
		telegramUpdate(1, 111, "/profile"),
	}, telegramTestConfigWithOwner(111, []int64{111}), []func(*cmdFakeTelegram) bool{seed})
	homeDir = h.homeDir
	defer cancel()
	waitFor(t, "profile reply", func() bool { return len(sendsOf(h)) >= 1 })
	stopBot(t, cancel, codeCh)
	sends := sendsOf(h)
	if len(sends) != 1 {
		t.Fatalf("sends = %d, want 1: %q", len(sends), sends)
	}
	if !strings.Contains(sends[0], "Cookies: present") {
		t.Errorf("profile reply = %q; want Cookies: present", sends[0])
	}
}

// TestTelegramUpdateDryRunReport: DryRun observed at the fake
// release server; the reply carries current + target + the
// manual command; the fake executable is untouched. No
// t.Parallel: setUpdateStamp mutates the package version vars
// (repo precedent, update_test.go).
func TestTelegramUpdateDryRunReport(t *testing.T) {
	setUpdateStamp(t, "0.6.3", "abc1234", "2026-01-02T00:00:00Z")
	exeDir := t.TempDir()
	exePath := filepath.Join(exeDir, "castctl")
	exeBytes := buildCLIFakeBinary(t)
	if err := os.WriteFile(exePath, exeBytes, 0o755); err != nil {
		t.Fatal(err)
	}
	before := sha256.Sum256(exeBytes)
	tarBytes := buildCLITar(t, exeBytes)
	srv := newCLIReleaseServer(t, "v0.6.4", tarBytes)
	deps := cliDeps(t, srv, exePath)
	gw := newTelegramTurnFakeGateway()
	h, cancel, codeCh := runTelegramBotWithConfigDeps(t, gw, []string{
		telegramUpdate(1, 111, "/update"),
	}, telegramTestConfigWithOwner(111, []int64{111}), nil, deps, nil)
	defer cancel()
	waitFor(t, "update report", func() bool { return len(sendsOf(h)) >= 1 })
	stopBot(t, cancel, codeCh)
	sends := sendsOf(h)
	if len(sends) != 1 {
		t.Fatalf("sends = %d, want 1: %q", len(sends), sends)
	}
	reply := sends[0]
	if !strings.Contains(reply, "dry-run: would update 0.6.3 -&gt; 0.6.4") && !strings.Contains(reply, "dry-run: would update 0.6.3 -> 0.6.4") {
		t.Errorf("update reply carries no dry-run current->target line: %q", reply)
	}
	if !strings.Contains(reply, "castctl update") {
		t.Errorf("update reply names no manual command: %q", reply)
	}
	if !strings.Contains(reply, "not restarted") && !strings.Contains(reply, "nothing was changed") {
		t.Errorf("update reply states no check-only notice: %q", reply)
	}
	after, err := os.ReadFile(exePath)
	if err != nil {
		t.Fatal(err)
	}
	if sha256.Sum256(after) != before {
		t.Error("fake executable changed: the bot must never replace the binary")
	}
	if srv.total() == 0 {
		t.Error("release server saw no requests: DryRun never ran")
	}
}

// TestTelegramUpdateErrorGeneric: an unreachable release
// server yields the fixed generic sentence (no error text,
// no URL). No t.Parallel (stamp mutation).
func TestTelegramUpdateErrorGeneric(t *testing.T) {
	setUpdateStamp(t, "0.6.3", "abc1234", "2026-01-02T00:00:00Z")
	var hits int
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits++
		mu.Unlock()
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	exePath := filepath.Join(t.TempDir(), "castctl")
	if err := os.WriteFile(exePath, buildCLIFakeBinary(t), 0o755); err != nil {
		t.Fatal(err)
	}
	deps := &update.Deps{
		HTTPClient: srv.Client(),
		Executable: exePath,
		BuildInfo: &debug.BuildInfo{Settings: []debug.BuildSetting{
			{Key: "CGO_ENABLED", Value: "1"},
		}},
		APIBase:    srv.URL,
		GitHubBase: srv.URL,
	}
	gw := newTelegramTurnFakeGateway()
	h, cancel, codeCh := runTelegramBotWithConfigDeps(t, gw, []string{
		telegramUpdate(1, 111, "/update"),
	}, telegramTestConfigWithOwner(111, []int64{111}), nil, deps, nil)
	defer cancel()
	waitFor(t, "update error reply", func() bool { return len(sendsOf(h)) >= 1 })
	stopBot(t, cancel, codeCh)
	sends := sendsOf(h)
	if len(sends) != 1 {
		t.Fatalf("sends = %d, want 1: %q", len(sends), sends)
	}
	if !strings.Contains(sends[0], "Could not check for updates") {
		t.Errorf("update error reply = %q; want the fixed generic sentence", sends[0])
	}
	if strings.Contains(sends[0], srv.URL) || strings.Contains(sends[0], "404") {
		t.Errorf("update error reply leaks fetch detail: %q", sends[0])
	}
	mu.Lock()
	defer mu.Unlock()
	if hits == 0 {
		t.Error("release server saw no requests: the failure was not a fetch failure")
	}
}

// TestTelegramRawUsage: empty method answers the upstream
// usage sentence byte-identically (literal entities).
func TestTelegramRawUsage(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	h, cancel, codeCh := runTelegramBotWithConfig(t, gw, []string{
		telegramUpdate(1, 111, "/raw"),
	}, telegramTestConfigWithOwner(111, []int64{111}), nil)
	defer cancel()
	waitFor(t, "raw usage reply", func() bool { return len(sendsOf(h)) >= 1 })
	stopBot(t, cancel, codeCh)
	sends := sendsOf(h)
	want := "Usage: /raw &lt;method&gt; [json body]; path params go in <code>{\"_params\": {...}}</code>"
	if len(sends) != 1 || sends[0] != want {
		t.Fatalf("sends = %q; want exactly [%q]", sends, want)
	}
	if len(gw.rawCallsSeen()) != 0 {
		t.Errorf("raw calls = %d; want 0", len(gw.rawCallsSeen()))
	}
}

// TestTelegramRawUnknownMethod: unknown method answers with
// the route-table count, before any gateway call.
func TestTelegramRawUnknownMethod(t *testing.T) {
	t.Parallel()
	table, err := gateway.DefaultRoutes()
	if err != nil {
		t.Fatal(err)
	}
	gw := newTelegramTurnFakeGateway()
	h, cancel, codeCh := runTelegramBotWithConfig(t, gw, []string{
		telegramUpdate(1, 111, "/raw bogus.method"),
		// Route check precedes JSON parse: an unknown
		// method with a malformed body still gets the
		// unknown-method sentence, never "invalid JSON".
		telegramUpdate(2, 111, "/raw bogus.method {bad json"),
	}, telegramTestConfigWithOwner(111, []int64{111}), nil)
	defer cancel()
	waitFor(t, "raw unknown replies", func() bool { return len(sendsOf(h)) >= 2 })
	stopBot(t, cancel, codeCh)
	sends := sendsOf(h)
	want := fmt.Sprintf("Unknown method <code>bogus.method</code> (%d known).", table.Total())
	if len(sends) != 2 || sends[0] != want || sends[1] != want {
		t.Fatalf("sends = %q; want exactly [%q %q]", sends, want, want)
	}
	if len(gw.rawCallsSeen()) != 0 {
		t.Errorf("raw calls = %d; want 0 (route check precedes the call)", len(gw.rawCallsSeen()))
	}
}

// TestTelegramRawInvalidJSON: bad JSON answers the invalid
// sentence carrying only the decoder error, never the body.
func TestTelegramRawInvalidJSON(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	h, cancel, codeCh := runTelegramBotWithConfig(t, gw, []string{
		telegramUpdate(1, 111, `/raw sessions.list {"x": MARKERBODYSECRET}`),
	}, telegramTestConfigWithOwner(111, []int64{111}), nil)
	defer cancel()
	waitFor(t, "raw invalid reply", func() bool { return len(sendsOf(h)) >= 1 })
	stopBot(t, cancel, codeCh)
	sends := sendsOf(h)
	if len(sends) != 1 {
		t.Fatalf("sends = %d, want 1: %q", len(sends), sends)
	}
	if !strings.HasPrefix(sends[0], "⚠️ invalid JSON: ") {
		t.Errorf("raw invalid reply = %q; want the invalid-JSON sentence", sends[0])
	}
	if strings.Contains(sends[0], "MARKERBODYSECRET") {
		t.Errorf("raw invalid reply echoes the request body: %q", sends[0])
	}
	if len(gw.rawCallsSeen()) != 0 {
		t.Errorf("raw calls = %d; want 0", len(gw.rawCallsSeen()))
	}
}

// TestTelegramRawParamsSplit: a dict _params is popped into
// path params; the body reaching the gateway has no _params.
func TestTelegramRawParamsSplit(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	gw.rawScript = []byte(`{"ok":true}`)
	h, cancel, codeCh := runTelegramBotWithConfig(t, gw, []string{
		telegramUpdate(1, 111, `/raw chat.mark_seen {"_params":{"thread_id":"th-1"},"limit":5}`),
	}, telegramTestConfigWithOwner(111, []int64{111}), nil)
	defer cancel()
	waitFor(t, "raw reply", func() bool { return len(sendsOf(h)) >= 1 })
	stopBot(t, cancel, codeCh)
	calls := gw.rawCallsSeen()
	if len(calls) != 1 {
		t.Fatalf("raw calls = %d, want 1: %+v", len(calls), calls)
	}
	if calls[0].Method != "chat.mark_seen" {
		t.Errorf("raw method = %q; want chat.mark_seen", calls[0].Method)
	}
	if calls[0].PathParams["thread_id"] != "th-1" || len(calls[0].PathParams) != 1 {
		t.Errorf("raw path params = %+v; want {thread_id:th-1}", calls[0].PathParams)
	}
	body, ok := calls[0].Body.(map[string]any)
	if !ok {
		t.Fatalf("raw body = %#v; want a JSON object", calls[0].Body)
	}
	if _, has := body["_params"]; has {
		t.Errorf("raw body still carries _params: %+v", body)
	}
	if body["limit"] != json.Number("5") {
		t.Errorf("raw body = %+v; want limit preserved", body)
	}
}

// TestTelegramRawParamsNonString: a non-string _params value
// is a fixed input error, with no gateway call and no echo.
func TestTelegramRawParamsNonString(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	h, cancel, codeCh := runTelegramBotWithConfig(t, gw, []string{
		telegramUpdate(1, 111, `/raw chat.mark_seen {"_params":{"thread_id":7}}`),
	}, telegramTestConfigWithOwner(111, []int64{111}), nil)
	defer cancel()
	waitFor(t, "raw params reply", func() bool { return len(sendsOf(h)) >= 1 })
	stopBot(t, cancel, codeCh)
	sends := sendsOf(h)
	if len(sends) != 1 || sends[0] != "⚠️ _params values must be strings" {
		t.Fatalf("sends = %q; want the fixed _params sentence", sends)
	}
	if len(gw.rawCallsSeen()) != 0 {
		t.Errorf("raw calls = %d; want 0", len(gw.rawCallsSeen()))
	}
}

// TestTelegramRawLongResultDocument: a >3800-rune result
// arrives as one document named <method>.json with a
// rune-count caption.
func TestTelegramRawLongResultDocument(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	payload, _ := json.Marshal(map[string]any{"data": strings.Repeat("x", 4000)})
	gw.rawScript = payload
	h, cancel, codeCh := runTelegramBotWithConfig(t, gw, []string{
		telegramUpdate(1, 111, "/raw sessions.list"),
	}, telegramTestConfigWithOwner(111, []int64{111}), nil)
	defer cancel()
	waitFor(t, "raw document", func() bool { return len(h.fake.documentsSeen()) >= 1 })
	stopBot(t, cancel, codeCh)
	docs := h.fake.documentsSeen()
	if len(docs) != 1 {
		t.Fatalf("documents = %d, want 1: %+v", len(docs), docs)
	}
	if docs[0].Filename != "sessions.list.json" {
		t.Errorf("document filename = %q; want sessions.list.json", docs[0].Filename)
	}
	m := regexp.MustCompile(`^sessions\.list\.json \((\d+) chars\)$`).FindStringSubmatch(docs[0].Caption)
	if m == nil {
		t.Fatalf("document caption = %q; want \"sessions.list.json (N chars)\"", docs[0].Caption)
	}
	var n int
	fmt.Sscanf(m[1], "%d", &n)
	if n <= 3800 {
		t.Errorf("caption count = %d; want > 3800", n)
	}
	if docs[0].Size <= 3800 {
		t.Errorf("document size = %d; want > 3800 bytes", docs[0].Size)
	}
}

// TestTelegramRawGatewayError: a gateway failure returns
// upward to dispatch's generic sentence (no handler reply).
func TestTelegramRawGatewayError(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	gw.rawErr = errors.New("gateway down")
	h, cancel, codeCh := runTelegramBotWithConfig(t, gw, []string{
		telegramUpdate(1, 111, "/raw sessions.list"),
	}, telegramTestConfigWithOwner(111, []int64{111}), nil)
	defer cancel()
	waitFor(t, "raw error reply", func() bool { return len(sendsOf(h)) >= 1 })
	stopBot(t, cancel, codeCh)
	sends := sendsOf(h)
	if len(sends) != 1 || sends[0] != "⚠️ Could not run /raw (gateway error)." {
		t.Fatalf("sends = %q; want dispatch's generic sentence", sends)
	}
}

// loginCookiesPath returns the muse01 cookies path in the
// harness home dir.
func loginCookiesPath(home string) string {
	return filepath.Join(home, "profiles", "muse01", "cookies.txt")
}

// homeBox is a mutex-guarded home-dir holder: batch gates
// run on the fake server's goroutine while the test goroutine
// learns the harness home dir after runTelegramBot returns.
type homeBox struct {
	mu  sync.Mutex
	dir string
}

func (b *homeBox) set(dir string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.dir = dir
}

func (b *homeBox) get() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.dir
}

// loginGate seeds the fake download fields (and, when
// oldContent != nil, the previous cookies file) the first
// time the gated batch is polled.
func loginGate(home *homeBox, fileBytes []byte, size int64, oldContent *[]byte) func(*cmdFakeTelegram) bool {
	return func(f *cmdFakeTelegram) bool {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.getFileSizeSet = true
		f.getFileSize = size
		f.getFilePath = "documents/cookies.txt"
		f.fileBytes = fileBytes
		if oldContent != nil {
			if dir := home.get(); dir != "" {
				profDir := filepath.Join(dir, "profiles", "muse01")
				_ = os.MkdirAll(profDir, 0o700)
				_ = os.WriteFile(filepath.Join(profDir, "cookies.txt"), *oldContent, 0o600)
			}
		}
		return true
	}
}

// TestTelegramLoginDocumentCookies: a document cookie file is
// downloaded, the user message deleted, the old file kept as
// .bak, the new file written mode 0600, and the success
// sentence sent — with no marker in any send or log.
func TestTelegramLoginDocumentCookies(t *testing.T) {
	t.Parallel()
	logger, logs := captureLogger()
	gw := newTelegramTurnFakeGateway()
	gw.subScripts = []turnSubScript{{replyText: "ok"}}
	home := &homeBox{}
	old := []byte("hatch_sess=OLDCOOKIEMARKER;")
	h, cancel, codeCh := runTelegramBotWithConfigDeps(t, gw, []string{
		telegramUpdate(1, 111, "/login"),
		telegramDocumentUpdate(2, 111, 7, "docfid", "cookies.txt", "text/plain", int64(len(loginMarkerText))),
	}, telegramTestConfigWithOwner(111, []int64{111}),
		[]func(*cmdFakeTelegram) bool{nil, loginGate(home, []byte(loginMarkerText), int64(len(loginMarkerText)), &old)}, nil, logger)
	home.set(h.homeDir)
	defer cancel()
	waitFor(t, "login success reply", func() bool {
		for _, s := range sendsOf(h) {
			if strings.Contains(s, "Cookies saved and working") {
				return true
			}
		}
		return false
	})
	// Let the delete land before stopping.
	waitFor(t, "delete recorded", func() bool { return len(h.fake.deletesSeen()) >= 1 })
	stopBot(t, cancel, codeCh)
	sends := sendsOf(h)
	found := false
	for _, s := range sends {
		if strings.Contains(s, "✅ Cookies saved and working (VM <code>vm-test</code>).") {
			found = true
		}
	}
	if !found {
		t.Fatalf("sends = %q; want the success sentence with vm-test", sends)
	}
	deletes := h.fake.deletesSeen()
	if len(deletes) != 1 || deletes[0].ChatID != 500 || deletes[0].MessageID != 7 {
		t.Errorf("deletes = %+v; want one delete of message 7 in chat 500", deletes)
	}
	cookiesPath := loginCookiesPath(home.get())
	data, err := os.ReadFile(cookiesPath)
	if err != nil {
		t.Fatalf("cookies file unreadable: %v", err)
	}
	if string(data) != loginMarkerText+"\n" {
		t.Errorf("cookies file = %q; want the stripped text + newline", data)
	}
	if st, err := os.Stat(cookiesPath); err != nil || st.Mode().Perm() != 0o600 {
		t.Errorf("cookies file mode = %v, err = %v; want 0600", st, err)
	}
	bak, err := os.ReadFile(cookiesPath + ".bak")
	if err != nil {
		t.Fatalf("cookies .bak unreadable: %v", err)
	}
	if string(bak) != string(old) {
		t.Errorf(".bak = %q; want the previous file bytes", bak)
	}
	assertNoMarker(t, "login document", allSendsAndEdits(h), logs.String())
	if strings.Contains(logs.String(), home.get()) {
		t.Errorf("logs carry the home path: %q", logs.String())
	}
}

// TestTelegramLoginTextCookies: a one-line text message is
// accepted the same way as a document.
func TestTelegramLoginTextCookies(t *testing.T) {
	t.Parallel()
	logger, logs := captureLogger()
	gw := newTelegramTurnFakeGateway()
	gw.subScripts = []turnSubScript{{replyText: "ok"}}
	h, cancel, codeCh := runTelegramBotWithConfigDeps(t, gw, []string{
		telegramUpdate(1, 111, "/login"),
		telegramUpdate(2, 111, loginMarkerText),
	}, telegramTestConfigWithOwner(111, []int64{111}), nil, nil, logger)
	defer cancel()
	waitFor(t, "login success reply", func() bool {
		for _, s := range sendsOf(h) {
			if strings.Contains(s, "Cookies saved and working") {
				return true
			}
		}
		return false
	})
	waitFor(t, "delete recorded", func() bool { return len(h.fake.deletesSeen()) >= 1 })
	stopBot(t, cancel, codeCh)
	sends := sendsOf(h)
	found := false
	for _, s := range sends {
		if strings.Contains(s, "✅ Cookies saved and working (VM <code>vm-test</code>).") {
			found = true
		}
	}
	if !found {
		t.Fatalf("sends = %q; want the success sentence", sends)
	}
	deletes := h.fake.deletesSeen()
	if len(deletes) != 1 || deletes[0].MessageID != 1 {
		t.Errorf("deletes = %+v; want one delete of the text message (id 1)", deletes)
	}
	data, err := os.ReadFile(loginCookiesPath(h.homeDir))
	if err != nil {
		t.Fatalf("cookies file unreadable: %v", err)
	}
	if string(data) != loginMarkerText+"\n" {
		t.Errorf("cookies file = %q; want the stripped text + newline", data)
	}
	assertNoMarker(t, "login text", allSendsAndEdits(h), logs.String())
}

// TestTelegramLoginNoHatchSess: no hatch_sess → the exact
// upstream sentence, nothing written, message still
// deleted, awaiting cleared (the next cookie text starts a
// turn instead).
func TestTelegramLoginNoHatchSess(t *testing.T) {
	t.Parallel()
	logger, logs := captureLogger()
	gw := newTelegramTurnFakeGateway()
	gw.subScripts = []turnSubScript{{replyText: "turn reply"}}
	h, cancel, codeCh := runTelegramBotWithConfigDeps(t, gw, []string{
		telegramUpdate(1, 111, "/login"),
		telegramUpdate(2, 111, "other=MARKEROTHERBBB222"),
		telegramUpdate(3, 111, loginMarkerText),
	}, telegramTestConfigWithOwner(111, []int64{111}), nil, nil, logger)
	defer cancel()
	waitFor(t, "no-hatch_sess reply", func() bool {
		for _, s := range sendsOf(h) {
			if s == loginNoHatchSessSentence {
				return true
			}
		}
		return false
	})
	// The third message must start a turn (awaiting cleared),
	// not repeat the login flow.
	waitFor(t, "turn after cleared awaiting", func() bool {
		_, _, subs, _ := gw.counts()
		return subs >= 1
	})
	stopBot(t, cancel, codeCh)
	sends := sendsOf(h)
	count := 0
	for _, s := range sends {
		if s == loginNoHatchSessSentence {
			count++
		}
	}
	if count != 1 {
		t.Errorf("no-hatch_sess sentence appears %d times; want 1: %q", count, sends)
	}
	cookiesPath := loginCookiesPath(h.homeDir)
	if _, err := os.Stat(cookiesPath); !os.IsNotExist(err) {
		t.Errorf("cookies file exists after a no-hatch_sess message (err=%v); nothing must be written", err)
	}
	if _, err := os.Stat(cookiesPath + ".bak"); !os.IsNotExist(err) {
		t.Errorf(".bak exists after a no-hatch_sess message (err=%v)", err)
	}
	deletes := h.fake.deletesSeen()
	if len(deletes) != 1 || deletes[0].MessageID != 1 {
		t.Errorf("deletes = %+v; want one delete of the no-hatch_sess message", deletes)
	}
	assertNoMarker(t, "login no-hatch_sess", allSendsAndEdits(h), logs.String())
}

// TestTelegramLoginTooLargeDeclared: a declared >1MB size
// refuses BEFORE any download, deletes the message, and
// writes nothing.
func TestTelegramLoginTooLargeDeclared(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	home := &homeBox{}
	h, cancel, codeCh := runTelegramBotWithConfig(t, gw, []string{
		telegramUpdate(1, 111, "/login"),
		telegramDocumentUpdate(2, 111, 7, "docfid", "cookies.txt", "text/plain", (1<<20)+1),
	}, telegramTestConfigWithOwner(111, []int64{111}),
		[]func(*cmdFakeTelegram) bool{nil, loginGate(home, []byte("x"), (1<<20)+1, nil)})
	home.set(h.homeDir)
	defer cancel()
	waitFor(t, "too-big reply", func() bool {
		for _, s := range sendsOf(h) {
			if strings.Contains(s, "too big") {
				return true
			}
		}
		return false
	})
	stopBot(t, cancel, codeCh)
	sends := sendsOf(h)
	found := false
	for _, s := range sends {
		if s == "⚠️ That cookies file is too big (1 MiB limit)." {
			found = true
		}
	}
	if !found {
		t.Fatalf("sends = %q; want the fixed too-big sentence", sends)
	}
	if len(h.fake.filePathsSeen()) != 0 {
		t.Errorf("file downloads = %d; want 0 (declared size refuses first)", len(h.fake.filePathsSeen()))
	}
	deletes := h.fake.deletesSeen()
	if len(deletes) != 1 || deletes[0].MessageID != 7 {
		t.Errorf("deletes = %+v; want one delete of the oversize message", deletes)
	}
	if _, err := os.Stat(loginCookiesPath(home.get())); !os.IsNotExist(err) {
		t.Errorf("cookies file exists after an oversize message (err=%v)", err)
	}
}

// TestTelegramLoginTooLargeBody: a small declaration with a
// >1MB body refuses AFTER the download, deletes, writes nothing.
func TestTelegramLoginTooLargeBody(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	home := &homeBox{}
	big := bytes.Repeat([]byte("x"), (1<<20)+1)
	h, cancel, codeCh := runTelegramBotWithConfig(t, gw, []string{
		telegramUpdate(1, 111, "/login"),
		telegramDocumentUpdate(2, 111, 7, "docfid", "cookies.txt", "text/plain", 5),
	}, telegramTestConfigWithOwner(111, []int64{111}),
		[]func(*cmdFakeTelegram) bool{nil, loginGate(home, big, 5, nil)})
	home.set(h.homeDir)
	defer cancel()
	waitFor(t, "too-big reply", func() bool {
		for _, s := range sendsOf(h) {
			if strings.Contains(s, "too big") {
				return true
			}
		}
		return false
	})
	stopBot(t, cancel, codeCh)
	found := false
	for _, s := range sendsOf(h) {
		if s == "⚠️ That cookies file is too big (1 MiB limit)." {
			found = true
		}
	}
	if !found {
		t.Fatalf("sends = %q; want the fixed too-big sentence", sendsOf(h))
	}
	if len(h.fake.filePathsSeen()) != 1 {
		t.Errorf("file downloads = %d; want 1 (the body gate runs after download)", len(h.fake.filePathsSeen()))
	}
	deletes := h.fake.deletesSeen()
	if len(deletes) != 1 || deletes[0].MessageID != 7 {
		t.Errorf("deletes = %+v; want one delete", deletes)
	}
	if _, err := os.Stat(loginCookiesPath(home.get())); !os.IsNotExist(err) {
		t.Errorf("cookies file exists after an oversize body (err=%v)", err)
	}
}

// TestTelegramLoginNonOwner: a non-owner /login refuses and
// sets no awaiting state — a following document goes to the
// inbox, is not deleted, and triggers no login sentence.
func TestTelegramLoginNonOwner(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	gw.subScripts = []turnSubScript{{replyText: "ok"}}
	home := &homeBox{}
	h, cancel, codeCh := runTelegramBotWithConfig(t, gw, []string{
		telegramUpdate(1, 222, "/login"),
		telegramDocumentUpdate(2, 222, 7, "docfid", "cookies.txt", "text/plain", int64(len(loginMarkerText))),
	}, telegramTestConfigTwoUsers(),
		[]func(*cmdFakeTelegram) bool{nil, loginGate(home, []byte(loginMarkerText), int64(len(loginMarkerText)), nil)})
	home.set(h.homeDir)
	defer cancel()
	waitFor(t, "inbox save", func() bool { return len(sendsOf(h)) >= 2 })
	// Settle: the inbox turn's subscribe must have run.
	waitFor(t, "inbox turn subscribed", func() bool {
		_, _, subs, _ := gw.counts()
		return subs >= 1
	})
	stopBot(t, cancel, codeCh)
	sends := sendsOf(h)
	if len(sends) < 1 || sends[0] != ownerOnlySentence {
		t.Fatalf("sends = %q; want the owner-only refusal first", sends)
	}
	for _, s := range sends {
		if strings.Contains(s, "Cookies saved") || strings.Contains(s, "hatch_sess") {
			t.Errorf("non-owner document triggered the login flow: %q", s)
		}
	}
	if len(h.fake.deletesSeen()) != 0 {
		t.Errorf("deletes = %+v; want 0 (no login flow, no deletion)", h.fake.deletesSeen())
	}
	if _, err := os.Stat(loginCookiesPath(home.get())); !os.IsNotExist(err) {
		t.Errorf("cookies file exists after a non-owner document (err=%v)", err)
	}
	// The document reached the inbox (fs.write recorded).
	gw.mu.Lock()
	wrote := len(gw.fsWritten) > 0
	gw.mu.Unlock()
	if !wrote {
		t.Error("no fs.write recorded: the non-owner document never reached the inbox")
	}
}

// TestTelegramLoginAwaitingIgnoresCommandsAndPhotos: /help
// runs and a photo goes to the inbox while awaiting; the
// state survives both, and the cookie text then completes
// the login.
func TestTelegramLoginAwaitingIgnoresCommandsAndPhotos(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	gw.subScripts = []turnSubScript{{replyText: "ok"}}
	var home string
	photoGate := func(f *cmdFakeTelegram) bool {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.getFileSizeSet = true
		f.getFileSize = 5
		f.getFilePath = "photos/file_1.jpg"
		f.fileBytes = []byte("JPEG!")
		return true
	}
	h, cancel, codeCh := runTelegramBotWithConfig(t, gw, []string{
		telegramUpdate(1, 111, "/login"),
		telegramUpdate(2, 111, "/help"),
		telegramPhotoUpdate(3, 111, 5),
		telegramUpdate(4, 111, loginMarkerText),
	}, telegramTestConfigWithOwner(111, []int64{111}),
		[]func(*cmdFakeTelegram) bool{nil, nil, photoGate, nil})
	home = h.homeDir
	defer cancel()
	waitFor(t, "login success after help+photo", func() bool {
		for _, s := range sendsOf(h) {
			if strings.Contains(s, "Cookies saved and working") {
				return true
			}
		}
		return false
	})
	stopBot(t, cancel, codeCh)
	sends := sendsOf(h)
	helped := false
	for _, s := range sends {
		if s == telegramBotHelpText {
			helped = true
		}
	}
	if !helped {
		t.Errorf("sends = %q; want /help answered while awaiting", sends)
	}
	gw.mu.Lock()
	wroteInbox := false
	for path := range gw.fsWritten {
		if strings.HasPrefix(path, "telegram-inbox/") && strings.Contains(path, "photo-5.jpg") {
			wroteInbox = true
		}
	}
	gw.mu.Unlock()
	if !wroteInbox {
		t.Errorf("fsWritten = %+v; want the photo saved to telegram-inbox/", gw.fsWritten)
	}
	data, err := os.ReadFile(loginCookiesPath(home))
	if err != nil {
		t.Fatalf("cookies file unreadable after help+photo: %v", err)
	}
	if string(data) != loginMarkerText+"\n" {
		t.Errorf("cookies file = %q; want the cookie text", data)
	}
	// Only the cookie text message was deleted (id 1 in
	// telegramUpdate shape); the photo was not.
	for _, d := range h.fake.deletesSeen() {
		if d.MessageID == 5 {
			t.Errorf("photo message was deleted: %+v", h.fake.deletesSeen())
		}
	}
}

// TestTelegramLoginWrongUIDCookieIgnored: awaiting set by
// the owner is not consumed by another allowlisted user's
// cookie text; that text starts a turn, and the owner's own
// later text completes the login.
func TestTelegramLoginWrongUIDCookieIgnored(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	gw.subScripts = []turnSubScript{{replyText: "turn reply"}}
	h, cancel, codeCh := runTelegramBotWithConfig(t, gw, []string{
		telegramUpdate(1, 111, "/login"),
		telegramUpdate(2, 222, loginMarkerText),
		telegramUpdate(3, 111, loginMarkerText),
	}, telegramTestConfigTwoUsers(), nil)
	defer cancel()
	waitFor(t, "owner login success", func() bool {
		for _, s := range sendsOf(h) {
			if strings.Contains(s, "Cookies saved and working") {
				return true
			}
		}
		return false
	})
	stopBot(t, cancel, codeCh)
	// Exactly one delete: the owner's completing message.
	// The other user's text started a turn (subscribe ran).
	deletes := h.fake.deletesSeen()
	if len(deletes) != 1 {
		t.Errorf("deletes = %+v; want exactly the owner's message deleted", deletes)
	}
	_, _, subs, _ := gw.counts()
	if subs < 1 {
		t.Error("no turn subscribe: the other user's text should have started a turn")
	}
	data, err := os.ReadFile(loginCookiesPath(h.homeDir))
	if err != nil {
		t.Fatalf("cookies file unreadable: %v", err)
	}
	if string(data) != loginMarkerText+"\n" {
		t.Errorf("cookies file = %q; want the owner's cookie text", data)
	}
}

// TestTelegramLoginInstructionNoPath: the /login instruction
// names the profile's cookies.txt without any absolute path.
func TestTelegramLoginInstructionNoPath(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	h, cancel, codeCh := runTelegramBotWithConfig(t, gw, []string{
		telegramUpdate(1, 111, "/login"),
	}, telegramTestConfigWithOwner(111, []int64{111}), nil)
	defer cancel()
	waitFor(t, "login instruction", func() bool { return len(sendsOf(h)) >= 1 })
	stopBot(t, cancel, codeCh)
	sends := sendsOf(h)
	if len(sends) != 1 {
		t.Fatalf("sends = %d, want 1: %q", len(sends), sends)
	}
	if !strings.Contains(sends[0], "cookies.txt") {
		t.Errorf("instruction names no cookies file: %q", sends[0])
	}
	if strings.Contains(sends[0], h.homeDir) || strings.Contains(sends[0], "/profiles/") {
		t.Errorf("instruction contains a filesystem path: %q", sends[0])
	}
	if !strings.Contains(sends[0], "delete your message") {
		t.Errorf("instruction keeps no delete notice: %q", sends[0])
	}
	if !strings.Contains(sends[0], ".bak") {
		t.Errorf("instruction keeps no .bak sentence: %q", sends[0])
	}
}

// TestTelegramRawShortResultPre: a short JSON result arrives
// as one <pre> send (replyLong pre branch), not a document.
func TestTelegramRawShortResultPre(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	gw.rawScript = []byte(`{"sessions":[]}`)
	h, cancel, codeCh := runTelegramBotWithConfig(t, gw, []string{
		telegramUpdate(1, 111, "/raw sessions.list"),
	}, telegramTestConfigWithOwner(111, []int64{111}), nil)
	defer cancel()
	waitFor(t, "raw pre reply", func() bool { return len(sendsOf(h)) >= 1 })
	stopBot(t, cancel, codeCh)
	sends := sendsOf(h)
	if len(sends) != 1 {
		t.Fatalf("sends = %d, want 1: %q", len(sends), sends)
	}
	if !strings.HasPrefix(sends[0], "<pre>") || !strings.Contains(sends[0], "sessions") {
		t.Errorf("raw short reply = %q; want one <pre> send", sends[0])
	}
	if len(h.fake.documentsSeen()) != 0 {
		t.Errorf("documents = %d; want 0 for a short result", len(h.fake.documentsSeen()))
	}
}
