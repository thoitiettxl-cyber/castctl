// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package commands

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/thoitiettxl-cyber/castctl/internal/conn"
	"github.com/thoitiettxl-cyber/castctl/internal/deliver"
	"github.com/thoitiettxl-cyber/castctl/internal/logging"
	"github.com/thoitiettxl-cyber/castctl/internal/profile"
	"github.com/thoitiettxl-cyber/castctl/internal/shared"
)

// The chat REPL, ported from chat.py per CHAT-REPL-DESIGN.md: the
// turn is followed with the wait/send seams (deliverSend + Runner),
// never a sleep+history poll loop. The prompt loop, state file,
// listing/switch/history display and /login guidance follow chat.py;
// the send path is the Runner's (boundary, watchdog, settle, lag
// window), so a REPL turn ends exactly like `wait` does.
//
// Differences from chat.py, all deliberate (see the design doc):
//   - The wait uses wait.Runner with a 300 s timeout (chat.py's
//     WAIT), not the 300 s + 10 s-quiet-extension poll loop.
//   - Replies print once, from the final Result, not incrementally.
//   - /login prints the guidance-only auth-export text (the Go port
//     never extracts browser cookies); no reconnect follows it.
//   - Prompt reading uses one persistent reader over env stdin when
//     no PromptFunc is injected (the default prompt seam builds a
//     fresh bufio.Reader per call, which can drop piped input).

const (
	chatWaitTimeout = 300 * time.Second
	chatHelpText    = `Commands:
  /chats          list your conversations
  /open N         switch to conversation number N from /chats
  /main           switch to your main chat
  /new [title]    start a new conversation
  /history [N]    read the last N messages here (default 10)
  /login          save your muse.ai login from Chrome again (same as ` + "`castctl auth export`" + `)
  /exit           quit (Ctrl+C works too)`
)

func init() {
	registerCommand(&commandSpec{name: "chat", help: "interactive chat (the default with no command)", helpText: chatHelpUsageText, handler: cmdChat})
	registerFlags("chat", "chat", nil)
}

// chatState is chat.json: the last conversation used.
type chatState struct {
	SessionID *string `json:"session_id"`
	Title     string  `json:"title"`
}

func loadChatState(path string) chatState {
	data, err := os.ReadFile(path)
	if err != nil {
		return chatState{Title: "main chat"}
	}
	var st chatState
	if err := json.Unmarshal(data, &st); err != nil {
		return chatState{Title: "main chat"}
	}
	if st.Title == "" {
		st.Title = "main chat"
	}
	return st
}

func saveChatState(path string, st chatState) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o600)
}

// chatSession is one REPL session: the runtime, the profile, the
// persisted state, and the last /chats listing.
type chatSession struct {
	env     *Env
	rt      *Runtime
	prof    *profile.Profile
	state   chatState
	listing []map[string]any
	reader  *bufio.Reader
}

func (s *chatSession) scope() string {
	if s.state.SessionID != nil {
		return *s.state.SessionID
	}
	return ""
}

func (s *chatSession) statePath() string {
	return s.prof.ChatFile
}

// messages returns (who, text) pairs for message.user /
// message.assistant events with text, oldest first, mirroring
// chat.py's messages().
func (s *chatSession) messages(ctx context.Context, limit int) ([][2]string, error) {
	v, err := s.rt.Muse.Call(ctx, "chat.history", conn.RequestOptions{Body: historyScopeBody(s.scope(), limit)})
	if err != nil {
		return nil, err
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("gateway: chat.history result is not an object: %T", v)
	}
	events, _ := m["chat_events"].([]any)
	// History may arrive newest-first; sort by seq ascending, as
	// Python's events() does.
	sort.SliceStable(events, func(i, j int) bool {
		return eventSeq(events[i]) < eventSeq(events[j])
	})
	var out [][2]string
	for _, raw := range events {
		ev, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		row := shared.FmtEvent(ev)
		name, _ := ev["event_name"].(string)
		if row.Text == "" || (name != "message.user" && name != "message.assistant") {
			continue
		}
		who := "Muse"
		if name == "message.user" {
			who = "You"
		}
		out = append(out, [2]string{who, row.Text})
	}
	return out, nil
}

func historyScopeBody(thread string, limit int) map[string]any {
	body := map[string]any{"limit": limit}
	if thread != "" {
		body["session_id"] = thread
	}
	return body
}

func (s *chatSession) showHistory(ctx context.Context, n int) error {
	msgs, err := s.messages(ctx, n*3)
	if err != nil {
		return err
	}
	if n < len(msgs) {
		msgs = msgs[len(msgs)-n:]
	}
	if len(msgs) == 0 {
		fmt.Fprintln(s.env.stdout(), "No messages here yet.")
		return nil
	}
	for _, m := range msgs {
		fmt.Fprintf(s.env.stdout(), "\n%s: %s\n", m[0], m[1])
	}
	return nil
}

func (s *chatSession) listChats(ctx context.Context) error {
	v, err := s.rt.Muse.Call(ctx, "sessions.list", conn.RequestOptions{})
	if err != nil {
		return err
	}
	m, ok := v.(map[string]any)
	if !ok {
		return fmt.Errorf("gateway: sessions.list result is not an object: %T", v)
	}
	sessions, _ := m["sessions"].([]any)
	s.listing = nil
	for _, raw := range sessions {
		sess, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if archived, _ := sess["archived"].(bool); archived {
			continue
		}
		s.listing = append(s.listing, sess)
	}
	for i, sess := range s.listing {
		title, _ := sess["title"].(string)
		if title == "" {
			title = "untitled"
		}
		main := ""
		if isThread, _ := sess["is_thread"].(bool); !isThread {
			main = " (main chat)"
		}
		var updatedMs int64
		switch t := sess["updated_at_ms"].(type) {
		case int64:
			updatedMs = t
		case json.Number:
			updatedMs, _ = t.Int64()
		case float64:
			updatedMs = int64(t)
		}
		when := time.UnixMilli(updatedMs).Local().Format("2006-01-02 15:04")
		fmt.Fprintf(s.env.stdout(), "%d. %s%s, updated %s\n", i+1, title, main, when)
	}
	fmt.Fprintln(s.env.stdout(), "Type /open and a number to switch.")
	return nil
}

func (s *chatSession) switchTo(ctx context.Context, sessionID *string, title string) error {
	s.state = chatState{SessionID: sessionID, Title: title}
	if err := saveChatState(s.statePath(), s.state); err != nil {
		return err
	}
	fmt.Fprintf(s.env.stdout(), "Now in: %s\n", title)
	return s.showHistory(ctx, 3)
}

func (s *chatSession) openChat(ctx context.Context, arg string) error {
	if len(s.listing) == 0 {
		return s.listChats(ctx)
	}
	n, err := parseChatNumber(arg)
	if err != nil {
		fmt.Fprintln(s.env.stdout(), "Type /open and a number from /chats.")
		return nil
	}
	if n < 1 || n > len(s.listing) {
		fmt.Fprintln(s.env.stdout(), "No conversation with that number. Type /chats to see them.")
		return nil
	}
	sess := s.listing[n-1]
	var id *string
	if sid, _ := sess["session_id"].(string); sid != "" {
		id = &sid
	}
	title, _ := sess["title"].(string)
	if title == "" {
		title = "untitled"
	}
	return s.switchTo(ctx, id, title)
}

func parseChatNumber(arg string) (int, error) {
	return strconv.Atoi(strings.TrimSpace(arg))
}

func (s *chatSession) newChat(ctx context.Context, title string) error {
	gw, err := s.rt.Muse.Connect(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = gw.Close() }()
	res, err := deliver.SessionStart(ctx, gw, title)
	if err != nil {
		return err
	}
	var sessionID *string
	displayTitle := title
	if displayTitle == "" {
		displayTitle = "new conversation"
	}
	if m, ok := res.(map[string]any); ok {
		if sid, _ := m["session_id"].(string); sid != "" {
			sessionID = &sid
		} else if sid, _ := m["id"].(string); sid != "" {
			sessionID = &sid
		}
	}
	return s.switchTo(ctx, sessionID, displayTitle)
}

// sendOne sends one line and displays the turn's replies. The ack
// failure path prints the send note and returns to the prompt
// without waiting; a timeout prints chat.py's no-reply line.
func (s *chatSession) sendOne(ctx context.Context, text string) error {
	gw, err := s.rt.Muse.Connect(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = gw.Close() }()
	userSeq, _, err := deliverSend(ctx, gw, s.prof, text, s.scope(), 30*time.Second)
	if err != nil {
		return err
	}
	if userSeq == nil {
		fmt.Fprintln(s.env.stdout(), "no delivery ack within 30s; check `castctl history`")
		return nil
	}
	fmt.Fprintln(s.env.stdout(), "Muse is thinking...")
	res, _, err := executeWait(ctx, s.env, s.rt, s.prof, waitRunArgs{
		thread: s.scope(), afterSeq: userSeq, timeout: chatWaitTimeout,
		requireRunning: true,
	})
	if err != nil {
		return err
	}
	for _, r := range res.Replies {
		fmt.Fprintf(s.env.stdout(), "\nMuse: %s\n", r.Text)
	}
	printWaitTail(s.env.stdout(), s.env.stderr(), res, false)
	if res.Outcome == "timeout" {
		fmt.Fprintln(s.env.stdout(), "(No reply within 300 seconds. Type /history later to check.)")
	}
	return nil
}

// handle runs one slash command. Unknown slash commands print the
// help hint and the REPL continues.
func (s *chatSession) handle(ctx context.Context, line string) error {
	cmd, arg, _ := strings.Cut(line, " ")
	arg = strings.TrimSpace(arg)
	switch cmd {
	case "/help", "/?":
		fmt.Fprintln(s.env.stdout(), chatHelpText)
	case "/chats":
		return s.listChats(ctx)
	case "/open":
		return s.openChat(ctx, arg)
	case "/main":
		return s.switchTo(ctx, nil, "main chat")
	case "/new":
		return s.newChat(ctx, arg)
	case "/history":
		n := 10
		if isDigits(arg) {
			fmt.Sscanf(arg, "%d", &n)
		}
		return s.showHistory(ctx, n)
	case "/login":
		// Guidance-only: the Go port never extracts browser
		// cookies, so no sign-in follows and no reconnect runs.
		if err := deliver.AuthExport(); err != nil {
			var export *deliver.ExportError
			if errors.As(err, &export) {
				fmt.Fprintln(s.env.stdout(), export.Guidance)
				return nil
			}
			return err
		}
		// NOTE: unreachable today — deliver.AuthExport always
		// returns *ExportError, so the branch above always
		// returns first. If a real cookie export ever lands,
		// this branch must reconnect like Python
		// (chat.py:176-179) before printing: claiming a
		// sign-in with no live connection would lie.
		fmt.Fprintln(s.env.stdout(), "Signed in.")
	default:
		fmt.Fprintln(s.env.stdout(), "Unknown command. Type /help.")
	}
	return nil
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// readLine reads one prompt line: through the injected PromptFunc
// when set, else from the persistent stdin reader (one reader for
// the whole session, so piped input is never dropped by a fresh
// buffer per line).
func (s *chatSession) readLine() (string, error) {
	if s.env.Prompt != nil {
		return s.env.Prompt("\nYou: ")
	}
	fmt.Fprint(s.env.stdout(), "\nYou: ")
	if s.reader == nil {
		s.reader = bufio.NewReader(s.env.stdin())
	}
	line, err := s.reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), err
}

func cmdChat(ctx context.Context, env *Env, g *globalOpts, args []string) error {
	p, err := parseOrHelp(commandTable["chat"], args, env)
	if err != nil {
		return err
	}
	if err := checkPositionals(p, nil, "chat"); err != nil {
		return usageErr(err)
	}
	return runWaitNetwork(ctx, env, g, func(rt *Runtime, prof *profile.Profile) error {
		sess := &chatSession{env: env, rt: rt, prof: prof}
		sess.state = loadChatState(prof.ChatFile)
		// Connect eagerly, like Chat.__init__: an auth failure at
		// startup prints the sign-in guidance path and exits 2
		// instead of dropping into a prompt that cannot work.
		gw, err := rt.Muse.Connect(ctx, nil)
		if err != nil {
			// The connector returns *conn.AuthError for auth
			// failures (including a missing/unreadable
			// cookies file); the classifyConnError taxonomy
			// is the auth check, as at dispatch. Only auth
			// failures print the sign-in guidance; other
			// connect errors surface typed.
			if _, ok := classifyConnError(err).(*typedAuthError); ok {
				fmt.Fprintf(env.stdout(), "Can't sign in to muse.ai: %s\n", logging.SummarizeErr(err))
				if exportErr := deliver.AuthExport(); exportErr != nil {
					var export *deliver.ExportError
					if errors.As(exportErr, &export) {
						fmt.Fprintln(env.stdout(), export.Guidance)
					}
				}
			}
			return err
		}
		_ = gw.Close()
		fmt.Fprintf(env.stdout(), "Muse chat, in: %s. Type /help for commands, /exit to quit.\n", sess.state.Title)
		if err := sess.showHistory(ctx, 3); err != nil {
			return err
		}
		for {
			line, err := sess.readLine()
			if err != nil {
				if errors.Is(err, io.EOF) {
					break
				}
				return err
			}
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			if lower := strings.ToLower(line); lower == "/exit" || lower == "/quit" || lower == "exit" || lower == "quit" {
				break
			}
			if ctx.Err() != nil {
				break
			}
			var runErr error
			if strings.HasPrefix(line, "/") {
				runErr = sess.handle(ctx, line)
			} else {
				runErr = sess.sendOne(ctx, line)
			}
			if runErr != nil {
				// Same auth taxonomy as the eager-connect check
				// above: an expired login returns to the prompt
				// with the sign-in hint instead of exiting.
				if _, ok := classifyConnError(runErr).(*typedAuthError); ok {
					fmt.Fprintln(env.stdout(), "Your login expired. Type /login to sign in again.")
					continue
				}
				fmt.Fprintf(env.stdout(), "Connection problem (%s). Reconnected; please try again.\n", logging.SummarizeErr(runErr))
				rt.Muse.Close()
			}
		}
		fmt.Fprintln(env.stdout(), "\nBye.")
		return nil
	})
}
