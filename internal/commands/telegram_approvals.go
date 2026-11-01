// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package commands

import (
	"context"
	"log/slog"
	"strings"

	"github.com/thoitiettxl-cyber/castctl/internal/approvals"
	"github.com/thoitiettxl-cyber/castctl/internal/conn"
	"github.com/thoitiettxl-cyber/castctl/internal/logging"
	"github.com/thoitiettxl-cyber/castctl/internal/profile"
	"github.com/thoitiettxl-cyber/castctl/internal/telegram"
)

// Approval wiring: the telegram.Decider <-> approvals.Decider
// adapter, the pending-approvals read, and the /approvals +
// /autoapprove command handlers.
//
// One decide RPC shape is shared by every decide path: the
// gatewayDecider adapter (manual button decisions), the
// waitApprover closure (auto-approve inside a turn), and the
// CLI approve/deny commands (decideApproval, untouched here
// except through the shared shape). callDecide is never
// retried by any caller: decide is not idempotent, and the
// server-side idempotency the claim protocol requires is
// unproven [NEEDS-MEASUREMENT] (see claims.go and the PR body).
// Every decision failure leaves the approval undecided: the
// adapter returns the error unwrapped-typed (auth errors stay
// *conn.AuthError), cbDecide surfaces it as a warning, and no
// fallback decision is ever issued.

// callDecide issues one egress.approval.decide call on an
// already-leased gateway. It performs no retry and no claim:
// claim discipline lives in the caller (AutoApprover's
// decided set per turn; ApproveForever's claim chain on the
// monitor path, which has no caller in PR-A).
func callDecide(ctx context.Context, gw conn.Gateway, approvalID, decision string) error {
	_, err := gw.CallJSON(ctx, "egress.approval.decide", conn.RequestOptions{
		PathParams: map[string]string{"approval_id": approvalID},
		Body:       map[string]any{"decision": decision},
	})
	return err
}

// gatewayDecider adapts telegram.Decider to the gateway decide
// path: one fresh lease per decision, one call, no retry.
type gatewayDecider struct {
	muse *conn.Muse
}

func (d gatewayDecider) Decide(ctx context.Context, approvalID, decision string) error {
	return d.muse.WithGateway(ctx, func(gw conn.Gateway) error {
		return callDecide(ctx, gw, approvalID, decision)
	})
}

// telegramPendingApprovals reads the pending list fresh from
// the server (egress.approvals, pending_approvals falling back
// to pending, the same helper the CLI approvals command uses)
// and maps each entry through approvals.DescribeApproval. A
// listing never decides, even with auto-approve on.
func telegramPendingApprovals(ctx context.Context, rt *Runtime) ([]telegram.Approval, error) {
	_, pend, err := pendingApprovals(ctx, rt)
	if err != nil {
		return nil, err
	}
	out := make([]telegram.Approval, 0, len(pend))
	for _, raw := range pend {
		out = append(out, approvalsToTelegram(approvals.DescribeApproval(raw)))
	}
	return out, nil
}

// telegramCmdHandler is the shared state for the step-5
// command handlers. A3 adds /approvals + /autoapprove; A4 adds
// the remaining commands and the dispatcher that calls them.
// Toggles returns the CURRENT effective pair (block over
// runtime state), re-read per command.
type telegramCmdHandler struct {
	env     *Env
	bot     *telegram.Bot
	rt      *Runtime
	prof    *profile.Profile
	store   *telegram.StateStore
	runner  *telegramTurnRunner
	toggles func() (autoApprove, allowOnce bool)
	logger  *slog.Logger
}

// approvals lists pending approvals fresh from the server, one
// message per approval with decide buttons (no resume triple:
// listing buttons decide without resuming), plus the
// approve-all message when more than one is pending
// (src/muse_cli/tgbot.py:1994-2007, cmd_approvals). A gateway
// failure gets the fixed reply below, never error text.
func (h *telegramCmdHandler) approvals(ctx context.Context, chatID int64) error {
	pend, err := telegramPendingApprovals(ctx, h.rt)
	if err != nil {
		h.logger.Warn("telegram approvals list failed", "err", logging.SummarizeErr(err))
		_, err := h.bot.Send(ctx, chatID, "⚠️ Could not list approvals (gateway error).", telegram.SendOptions{Mode: telegram.HTMLModePlain})
		return err
	}
	approveOn, _ := h.toggles()
	if len(pend) == 0 {
		text := "No pending approvals. Auto-approve is off."
		if approveOn {
			text = "No pending approvals. Auto-approve is on (always)."
		}
		_, err := h.bot.Send(ctx, chatID, text, telegram.SendOptions{Mode: telegram.HTMLModePlain})
		return err
	}
	for _, d := range pend {
		if _, err := h.bot.Send(ctx, chatID, telegram.ApprovalText(d), telegram.SendOptions{Markup: h.bot.ApprovalMarkup(d, telegram.ResumeTriple{})}); err != nil {
			return err
		}
	}
	if len(pend) > 1 {
		_, err := h.bot.Send(ctx, chatID, "Or decide them all:", telegram.SendOptions{Markup: h.bot.ApproveAllMarkup()})
		return err
	}
	return nil
}

// autoApprove implements /autoapprove on|off|status and
// /autoapprove once on|off|status (src/muse_cli/tgbot.py:2009-
// 2052, cmd_autoapprove), with one deliberate asymmetry: the
// toggles persist ONLY to the runtime state file. Python also
// wrote the CLI config and reloaded the Muse client; castctl
// never rewrites config.json from the bot, and the effective
// toggles are re-read per turn, so no reload is needed.
// Toggling one toggle never changes the other: the set writes
// both values with the untouched one carried over from the
// current effective state.
func (h *telegramCmdHandler) autoApprove(ctx context.Context, chatID int64, arg string) error {
	a := strings.ToLower(strings.TrimSpace(arg))
	parts := strings.Fields(a)
	if len(parts) > 0 && parts[0] == "once" {
		if len(parts) > 2 {
			return h.sendText(ctx, chatID, "Usage: /autoapprove once on|off|status")
		}
		if len(parts) == 1 || parts[1] == "status" {
			// Report only.
		} else if parts[1] == "on" || parts[1] == "off" {
			approveOn, _ := h.toggles()
			if err := h.store.SetToggles(approveOn, parts[1] == "on"); err != nil {
				h.logger.Warn("telegram auto-approve toggle save failed", "err", logging.SummarizeErr(err))
			}
		} else {
			return h.sendText(ctx, chatID, "Usage: /autoapprove once on|off|status")
		}
		_, allowOnce := h.toggles()
		fallback := "are left for a human (exit 4 / needs_approval)."
		if allowOnce {
			fallback = "are decided with allow_once when auto-approve is on."
		}
		approveOn, _ := h.toggles()
		return h.sendText(ctx, chatID, "Auto-allow-once is <b>"+onOff(allowOnce)+"</b>: approvals with no forever option "+fallback+" Auto-approve is <b>"+onOff(approveOn)+"</b>.")
	}
	if a == "on" || a == "always" || a == "off" {
		_, allowOnce := h.toggles()
		if err := h.store.SetToggles(a != "off", allowOnce); err != nil {
			h.logger.Warn("telegram auto-approve toggle save failed", "err", logging.SummarizeErr(err))
		}
	} else if a != "" && a != "status" {
		return h.sendText(ctx, chatID, "Usage: /autoapprove on|off|status")
	}
	approveOn, allowOnce := h.toggles()
	if approveOn {
		text := "✅ Auto-approve is <b>on</b>: every approval gets Muse's forever choice (allow_always), so Muse never blocks."
		if allowOnce {
			text += " Approvals with no forever option fall back to allow_once."
		}
		return h.sendText(ctx, chatID, text)
	}
	return h.sendText(ctx, chatID, "Auto-approve is <b>off</b>: approvals come here with buttons.")
}

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

// sendText sends one HTML-mode message (the command reports
// carry <b> markup, pre-escaped where they interpolate state;
// no user or server text is interpolated).
func (h *telegramCmdHandler) sendText(ctx context.Context, chatID int64, text string) error {
	_, err := h.bot.Send(ctx, chatID, text, telegram.SendOptions{})
	return err
}
