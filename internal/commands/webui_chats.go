// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package commands

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/thoitiettxl-cyber/castctl/internal/conn"
	"github.com/thoitiettxl-cyber/castctl/internal/deliver"
	"github.com/thoitiettxl-cyber/castctl/internal/profile"
	"github.com/thoitiettxl-cyber/castctl/internal/shared"
	"github.com/thoitiettxl-cyber/castctl/internal/wait"
	"github.com/thoitiettxl-cyber/castctl/internal/webui"
)

// Web UI chats seams: the command layer owns runtime construction
// (per call, build + close — the CLI runNetwork pattern), and the
// webui package owns HTTP, jobs, and envelopes. internal/webui
// never imports this package.
//
// Each seam builds its own Runtime for the NAMED profile (not
// the active profile: the UI addresses profiles by name, and
// --profile is ignored by `webui serve`). Reads never write:
// ensureNodeID runs only on the send path, where deliverSend
// transmits the node_id; list/history/start/op leave the config
// file untouched. Errors are classified like runNetwork's, and
// the webui layer surfaces only a fixed 502 for them, so no
// gateway text — and no chat text — ever reaches an error
// envelope.

// webuiChatAckTimeout is deliverSend's delivery-ack budget, the CLI
// send default. webuiChatWaitTimeout is the turn-wait budget, the
// CLI send --wait default. The job budget in the webui package
// (150 s) covers both plus the runtime build.
const webuiChatAckTimeout = 30 * time.Second
const webuiChatWaitTimeout = 90 * time.Second

// webuiChatRuntime resolves the named profile, builds one
// Runtime, runs fn, and closes the Runtime. Gateway/auth
// failures from fn are classified into the typed auth
// taxonomy, as in runNetwork.
func webuiChatRuntime(ctx context.Context, env *Env, loc *profile.ConfigLocation, profileName string, fn func(*Runtime, *profile.Profile) error) error {
	prof, err := profile.LoadProfile(loc.ConfigDir, profileName, env.lookupEnv)
	if err != nil {
		return err
	}
	rt, err := env.buildRuntime(ctx, loc, prof)
	if err != nil {
		return err
	}
	defer func() { _ = rt.Close() }()
	if err := fn(rt, prof); err != nil {
		return classifyConnError(err)
	}
	return nil
}

// webuiChatDeps builds the injected chat seams for one `webui
// serve` process. The seams close over loc/env, which the
// server already owns for its cookie/screencast seams.
func webuiChatDeps(loc *profile.ConfigLocation, env *Env) *webui.ChatDeps {
	return &webui.ChatDeps{
		ListSessions: func(ctx context.Context, profileName string, includeArchived bool) ([]webui.ChatSession, error) {
			var out []webui.ChatSession
			err := webuiChatRuntime(ctx, env, loc, profileName, func(rt *Runtime, _ *profile.Profile) error {
				d, err := callMap(ctx, rt, "sessions.list", conn.RequestOptions{})
				if err != nil {
					return err
				}
				rows := shared.SessionRows(d, includeArchived, time.Local)
				out = make([]webui.ChatSession, 0, len(rows))
				for _, row := range rows {
					out = append(out, webui.ChatSession{
						SessionID: row.SessionID, Title: row.Title,
						Thread: row.Thread, Pinned: row.Pinned,
						Archived: row.Archived, Updated: row.Updated,
					})
				}
				return nil
			})
			return out, err
		},
		GetHistory: func(ctx context.Context, profileName, sessionID string, limit int) ([]webui.ChatEvent, error) {
			var out []webui.ChatEvent
			err := webuiChatRuntime(ctx, env, loc, profileName, func(rt *Runtime, _ *profile.Profile) error {
				_, events, err := historyResult(ctx, rt, sessionID, int64(limit))
				if err != nil {
					return err
				}
				rows := filterEvents(events)
				out = make([]webui.ChatEvent, 0, len(rows))
				for _, row := range rows {
					out = append(out, webui.ChatEvent{
						Seq: row.Seq, Role: row.Role,
						MessageID: row.MessageID, Text: row.Text,
					})
				}
				return nil
			})
			return out, err
		},
		StartSession: func(ctx context.Context, profileName, title string) (string, error) {
			var sessionID string
			err := webuiChatRuntime(ctx, env, loc, profileName, func(rt *Runtime, _ *profile.Profile) error {
				return rt.Muse.WithGateway(ctx, func(gw conn.Gateway) error {
					res, err := deliver.SessionStart(ctx, gw, title)
					if err != nil {
						return err
					}
					// The reply is server-defined: accept the
					// session_id key the CLI chat session
					// accepts, with its `id` fallback. Any
					// other shape is an upstream error, with
					// no part of the reply surfaced.
					if m, ok := res.(map[string]any); ok {
						if sid, _ := m["session_id"].(string); sid != "" {
							sessionID = sid
							return nil
						}
						if sid, _ := m["id"].(string); sid != "" {
							sessionID = sid
							return nil
						}
					}
					return errors.New("session.start reply has no session id")
				})
			})
			return sessionID, err
		},
		SessionOp: func(ctx context.Context, profileName, sessionID, op, title string) error {
			return webuiChatRuntime(ctx, env, loc, profileName, func(rt *Runtime, _ *profile.Profile) error {
				return rt.Muse.WithGateway(ctx, func(gw conn.Gateway) error {
					_, err := deliver.SessionOp(ctx, gw, deliver.SessionOpKind(op), sessionID, title)
					return err
				})
			})
		},
		SendChat: func(ctx context.Context, profileName, sessionID, text string) (*webui.ChatSendResult, error) {
			var result *webui.ChatSendResult
			err := webuiChatRuntime(ctx, env, loc, profileName, func(rt *Runtime, prof *profile.Profile) error {
				// The node_id is transmitted verbatim on
				// chat.stream, so it is ensured here — and
				// only here — exactly as runWaitNetwork does
				// for the CLI send path.
				if err := ensureNodeID(loc, prof, env.lookupEnv); err != nil {
					return err
				}
				// The sending connection stays open until
				// the wait is done, so the chat.stream
				// request is never torn down mid-turn (the
				// cmdSend shape).
				gw, err := rt.Muse.Connect(ctx, nil)
				if err != nil {
					return err
				}
				defer func() { _ = gw.Close() }()
				userSeq, _, err := deliverSend(ctx, gw, prof, text, sessionID, webuiChatAckTimeout)
				if err != nil {
					return err
				}
				if userSeq == nil {
					result = &webui.ChatSendResult{
						Outcome: "undelivered",
						Note:    "no delivery ack within 30s; check history before sending again",
						Replies: []webui.ChatReply{},
					}
					return nil
				}
				// No explicit toggles: executeWait resolves
				// the profile's auto_approve/auto_allow_once
				// as-is, the CLI default for a turn.
				res, _, err := executeWait(ctx, env, rt, prof, waitRunArgs{
					thread:         sessionID,
					afterSeq:       userSeq,
					timeout:        webuiChatWaitTimeout,
					requireRunning: true,
				})
				if err != nil {
					return err
				}
				result = toChatSendResult(res)
				return nil
			})
			return result, err
		},
	}
}

// toChatSendResult maps a wait.Result onto the job result
// shape, mirroring toWaitResultJSON's field rules: final text
// only when replies exist, the timeout note keeping precedence
// over the wait note (reworded for the UI: there is no CLI
// re-run hint to give), approval counts only, and the
// needs_input reason/question only for that outcome.
func toChatSendResult(res *wait.Result) *webui.ChatSendResult {
	out := &webui.ChatSendResult{
		Outcome:  res.Outcome,
		Status:   strPtrOrNil(res.Status),
		AfterSeq: res.AfterSeq,
		Replies:  []webui.ChatReply{},
	}
	for _, r := range res.Replies {
		out.Replies = append(out.Replies, webui.ChatReply{
			Seq: r.Seq, Text: r.Text, MessageID: strPtrOrNil(r.MessageID),
		})
	}
	if len(res.Replies) > 0 {
		text := res.FinalText
		out.FinalText = &text
	}
	if res.Outcome == "timeout" {
		out.Note = fmt.Sprintf("turn not finished within %ds; the turn may still complete — re-read history for later replies", int(webuiChatWaitTimeout.Seconds()))
	} else {
		out.Note = res.Note
	}
	if len(res.Approvals) > 0 {
		out.ApprovalsCount = len(res.Approvals)
	}
	if res.Outcome == "needs_input" {
		reason := res.NeedsInputReason
		out.NeedsInputReason = &reason
		question := res.Question
		out.Question = &question
	}
	return out
}
