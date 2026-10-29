// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/thoitiettxl-cyber/muse-cli/go/internal/commands"
	"github.com/thoitiettxl-cyber/muse-cli/go/internal/conn"
	"github.com/thoitiettxl-cyber/muse-cli/go/internal/gateway"
	"github.com/thoitiettxl-cyber/muse-cli/go/internal/gateway/gatewaytest"
)

// runChat runs the chat command against a fake gateway with a
// scripted prompt. lines are the prompt answers in order; exhaustion
// returns io.EOF.
func runChat(t *testing.T, home string, handler *scriptedHandler, lines []string) (int, string, string) {
	t.Helper()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("MUSE_CLI_CONFIG", "")
	t.Setenv("MUSE_CLI_PROFILE", "")
	server, err := gatewaytest.NewServer(handler)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	defer func() { _ = server.Close() }()
	auth := &gatewaytest.CannedAuth{VMID: "vm-test", AccessToken: "AT-FAKE", HatchToken: "HT-FAKE"}
	dialer := gatewaytest.NewFakeDialer(server, auth)
	var out, errb bytes.Buffer
	next := 0
	env := &commands.Env{
		Stdout: &out,
		Stderr: &errb,
		Stdin:  strings.NewReader(""),
		Prompt: func(prompt string) (string, error) {
			if next >= len(lines) {
				return "", io.EOF
			}
			line := lines[next]
			next++
			return line, nil
		},
		NewConnector: func(d gateway.OutboundDialer, opts ...gateway.ConnectorOption) conn.Connector {
			_ = d
			_ = opts
			return gateway.NewConnector(dialer, gateway.WithWebSocketSecure(false))
		},
	}
	code := commands.Run(context.Background(), []string{"chat"}, env)
	return code, out.String(), errb.String()
}

func chatStateFile(home string) string {
	return filepath.Join(home, ".config", "muse-cli", "chat.json")
}

func TestChatHelpAndExit(t *testing.T) {
	home := fakeHome(t, defaultSingleConfig)
	h := &scriptedHandler{history: []string{historyBody()}}
	code, out, _ := runChat(t, home, h, []string{"/help", "/exit"})
	if code != 0 {
		t.Fatalf("chat: code=%d out=%q", code, out)
	}
	for _, want := range []string{"/chats", "/open N", "/main", "/new [title]", "/history [N]", "/login", "/exit", "Muse chat, in: main chat"} {
		if !strings.Contains(out, want) {
			t.Errorf("chat output lacks %q:\n%s", want, out)
		}
	}
	if !strings.Contains(out, "Bye.") {
		t.Errorf("chat output lacks Bye:\n%s", out)
	}
	if _, err := os.Stat(chatStateFile(home)); !os.IsNotExist(err) {
		t.Errorf("help/exit must not create a state file")
	}
}

func TestChatSendPrintsReply(t *testing.T) {
	home := fakeHome(t, defaultSingleConfig)
	h := &scriptedHandler{
		history: []string{
			historyBody(),
			historyBody(userEv(100, "old")),
			historyBody(userEv(100, "old")),
			historyBody(userEv(100, "old"), userEv(110, "hello")),
			historyBody(userEv(100, "old"), userEv(110, "hello")),
			historyBody(userEv(100, "old"), userEv(110, "hello"), asstEv(150, "hi there")),
		},
		subscribe: [][]byte{append(taskRecord("running"), taskRecord("completed")...)},
	}
	code, out, errb := runChat(t, home, h, []string{"hello", "/exit"})
	if code != 0 {
		t.Fatalf("chat send: code=%d out=%q err=%q", code, out, errb)
	}
	if !strings.Contains(out, "Muse is thinking...") {
		t.Errorf("output lacks thinking line:\n%s", out)
	}
	if !strings.Contains(out, "Muse: hi there") {
		t.Errorf("output lacks reply:\n%s", out)
	}
	if _, err := os.Stat(chatStateFile(home)); !os.IsNotExist(err) {
		t.Errorf("a plain send must not create a state file")
	}
}

func TestChatNewOpenMain(t *testing.T) {
	home := fakeHome(t, defaultSingleConfig)
	h := &scriptedHandler{
		history: []string{historyBody(
			userEv(100, "first"),
			asstEv(110, "answer"),
			userEv(120, "second"),
		)},
		sessions: `{"sessions":[
			{"session_id":"s-1","title":"First","updated_at_ms":1700000000000,"is_thread":true},
			{"session_id":"s-2","title":"Second","updated_at_ms":1700000060000,"is_thread":true},
			{"session_id":"s-3","title":"Old","updated_at_ms":1700000120000,"is_thread":true,"archived":true}
		]}`,
		start: `{"session_id":"s-new"}`,
	}
	code, out, errb := runChat(t, home, h, []string{"/new My Title", "/chats", "/open 2", "/main", "/exit"})
	if code != 0 {
		t.Fatalf("chat nav: code=%d out=%q err=%q", code, out, errb)
	}
	if !strings.Contains(out, "Now in: My Title") {
		t.Errorf("output lacks new-chat switch:\n%s", out)
	}
	if !strings.Contains(out, "1. First") || !strings.Contains(out, "2. Second") {
		t.Errorf("output lacks chat list:\n%s", out)
	}
	if strings.Contains(out, "Old") {
		t.Errorf("archived chats must be hidden:\n%s", out)
	}
	if !strings.Contains(out, "Type /open and a number to switch.") {
		t.Errorf("output lacks open hint:\n%s", out)
	}
	if !strings.Contains(out, "Now in: Second") || !strings.Contains(out, "Now in: main chat") {
		t.Errorf("output lacks switches:\n%s", out)
	}
	raw, err := os.ReadFile(chatStateFile(home))
	if err != nil {
		t.Fatalf("state file: %v", err)
	}
	var st map[string]any
	if err := json.Unmarshal(raw, &st); err != nil {
		t.Fatalf("state JSON: %v (%s)", err, raw)
	}
	if st["session_id"] != nil || st["title"] != "main chat" {
		t.Errorf("final state = %v, want main chat", st)
	}
}

func TestChatOpenWithoutListingListsFirst(t *testing.T) {
	home := fakeHome(t, defaultSingleConfig)
	h := &scriptedHandler{
		history:  []string{historyBody()},
		sessions: `{"sessions":[{"session_id":"s-1","title":"First","updated_at_ms":1700000000000,"is_thread":true}]}`,
	}
	code, out, _ := runChat(t, home, h, []string{"/open 1", "/exit"})
	if code != 0 {
		t.Fatalf("chat: code=%d out=%q", code, out)
	}
	if !strings.Contains(out, "1. First") {
		t.Errorf("/open with no listing must list chats:\n%s", out)
	}
	if strings.Contains(out, "Now in:") {
		t.Errorf("/open with no listing must not switch:\n%s", out)
	}
}

func TestChatHistoryAndUnknown(t *testing.T) {
	home := fakeHome(t, defaultSingleConfig)
	h := &scriptedHandler{
		history: []string{historyBody(
			userEv(100, "q1"),
			asstEv(110, "a1"),
			userEv(120, "q2"),
			asstEv(130, "a2"),
		)},
	}
	code, out, _ := runChat(t, home, h, []string{"/history 2", "/bogus", "/exit"})
	if code != 0 {
		t.Fatalf("chat: code=%d out=%q", code, out)
	}
	if !strings.Contains(out, "You: q2") || !strings.Contains(out, "Muse: a2") {
		t.Errorf("/history 2 must show the last 2:\n%s", out)
	}
	if strings.Contains(out, "You: q1") {
		t.Errorf("/history 2 must not show older messages:\n%s", out)
	}
	if !strings.Contains(out, "Unknown command. Type /help.") {
		t.Errorf("output lacks unknown-command line:\n%s", out)
	}
}

// A non-numeric /history argument defaults to 10, like Python's
// int(arg) if arg.isdigit() else 10: the whole short history shows.
func TestChatHistoryNonDigitDefaultsTo10(t *testing.T) {
	home := fakeHome(t, defaultSingleConfig)
	h := &scriptedHandler{
		history: []string{historyBody(
			userEv(100, "q1"),
			asstEv(110, "a1"),
			userEv(120, "q2"),
			asstEv(130, "a2"),
		)},
	}
	code, out, _ := runChat(t, home, h, []string{"/history xyz", "/exit"})
	if code != 0 {
		t.Fatalf("chat: code=%d out=%q", code, out)
	}
	if !strings.Contains(out, "You: q1") || !strings.Contains(out, "Muse: a2") {
		t.Errorf("/history xyz must show all messages:\n%s", out)
	}
}

func TestChatEOFExitsCleanly(t *testing.T) {
	home := fakeHome(t, defaultSingleConfig)
	h := &scriptedHandler{history: []string{historyBody()}}
	code, out, _ := runChat(t, home, h, nil)
	if code != 0 {
		t.Fatalf("chat EOF: code=%d out=%q", code, out)
	}
	if !strings.Contains(out, "Bye.") {
		t.Errorf("output lacks Bye:\n%s", out)
	}
}

func TestChatLoginPrintsGuidance(t *testing.T) {
	home := fakeHome(t, defaultSingleConfig)
	h := &scriptedHandler{history: []string{historyBody()}}
	code, out, _ := runChat(t, home, h, []string{"/login", "/exit"})
	if code != 0 {
		t.Fatalf("chat /login: code=%d out=%q", code, out)
	}
	if !strings.Contains(out, "muse.ai") && !strings.Contains(out, "Muse") {
		t.Errorf("/login must print the agent-browser guidance:\n%s", out)
	}
	if strings.Contains(out, "Signed in.") {
		t.Errorf("/login must not claim a sign-in when no cookies were saved:\n%s", out)
	}
}

// R1 (REPL path): with no cookies file, the REPL's eager connect
// fails as an auth failure and exits 2 with the sign-in guidance
// instead of dropping into a prompt that cannot work.
func TestChatNoCookiesExits2(t *testing.T) {
	home := t.TempDir()
	base := filepath.Join(home, ".config", "muse-cli")
	if err := os.MkdirAll(base, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "config.json"), []byte(defaultSingleConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	h := &scriptedHandler{history: []string{historyBody()}}
	code, out, _ := runChat(t, home, h, []string{"/exit"})
	if code != 2 {
		t.Fatalf("chat with no cookies: code=%d, want 2 (out=%q)", code, out)
	}
	if !strings.Contains(out, "Can't sign in") {
		t.Errorf("output lacks the sign-in guidance:\n%s", out)
	}
}
