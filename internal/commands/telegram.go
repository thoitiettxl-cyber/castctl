// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package commands

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/thoitiettxl-cyber/castctl/internal/profile"
	"github.com/thoitiettxl-cyber/castctl/internal/telegram"
)

// The telegram command wires the optional top-level `telegram`
// config block (docs/config.md) to the polling bot in
// internal/telegram. It wires exactly two subcommands:
//
//   - `telegram run`: poll the Bot API through the LINKED
//     profile's outbound until interrupted. Allowed users
//     talk to Muse with plain messages (streamed, edited
//     replies through the send/wait path), approvals are
//     decided through the gateway decide path, and the core
//     slash commands (/help, /status, /chats, /main, /new,
//     /history, /unread, /approvals, /autoapprove, /watch,
//     session ops, /stop) are wired; media, /files, /fs,
//     /feed, /goals, /goal, /ideas, /usage, /wake, /profile,
//     /update, /login, /raw, watch forwarding, and
//     `telegram setup` / `install-service` are roadmap
//     step 5b, not this build.
//   - `telegram status`: offline report of the block (configured
//     flag, linked profile tag, allowlist count, toggles,
//     token-shape validity). No network, no GetMe, no token
//     value anywhere in the output.
//
// An absent block is exit 2 for both subcommands (fail-closed:
// the bot refuses to start without a block, and status has
// nothing to report). A malformed block is exit 2 from config
// validation, before any token use. An explicit --profile or
// CASTCTL_PROFILE naming a different profile than the block's
// is exit 2 naming both tags: the bot always serves the linked
// profile, never the active one.

const telegramHelpText = `usage: castctl telegram <subcommand> [options]

Telegram bot that operates your Muse, polling through the profile
linked by the "telegram" block in config.json.

subcommands:
  run       poll the Bot API until interrupted (Ctrl-C).
  status    show the telegram block configuration (offline).

"run" serves the profile named by the block's "profile" field,
never the active profile: --profile or CASTCTL_PROFILE naming a
different profile is an error. Allowed users talk to Muse with
plain messages; /help in the chat lists the bot commands.
`

const telegramRunHelpText = `usage: castctl telegram run

Poll the Telegram Bot API through the linked profile's outbound
until interrupted. Requires a "telegram" block in config.json
with a token and a non-empty allowed_user_ids allowlist.
`

const telegramStatusHelpText = `usage: castctl telegram status

Show the "telegram" block configuration as JSON (offline: no
network, no GetMe). The token value is never printed; only its
shape validity is reported.
`

var telegramSubcommands = []string{"run", "status"}

func init() {
	registerCommand(&commandSpec{
		name:     "telegram",
		help:     "Telegram bot that operates your Muse (run, status)",
		helpText: telegramHelpText,
		handler:  cmdTelegram,
	})
	registerFlags("telegram", "telegram <subcommand> [options]", nil)
}

// cmdTelegram dispatches telegram subcommands, following the
// cmdFS pattern: --help after the command prints command help,
// an unknown subcommand is exit 2.
func cmdTelegram(ctx context.Context, env *Env, g *globalOpts, args []string) error {
	if len(args) == 0 {
		fmt.Fprintln(env.stderr(), "castctl: the following arguments are required: subcommand")
		fmt.Fprint(env.stderr(), telegramHelpText)
		return errCode(2, nil)
	}
	if args[0] == "--help" || args[0] == "-h" {
		fmt.Fprint(env.stdout(), telegramHelpText)
		return errHelpShown
	}
	sub := args[0]
	rest := args[1:]
	switch sub {
	case "run":
		return cmdTelegramRun(ctx, env, g, rest)
	case "status":
		return cmdTelegramStatus(ctx, env, g, rest)
	default:
		fmt.Fprintf(env.stderr(), "castctl: argument subcommand: invalid choice: %q (choose from %s)\n", sub, strings.Join(telegramSubcommands, ", "))
		return errCode(2, nil)
	}
}

func cmdTelegramRun(ctx context.Context, env *Env, g *globalOpts, args []string) error {
	if len(args) > 0 && (args[0] == "--help" || args[0] == "-h") {
		fmt.Fprint(env.stdout(), telegramRunHelpText)
		return errHelpShown
	}
	if len(args) > 0 {
		fmt.Fprintf(env.stderr(), "castctl: telegram run takes no arguments (got %q)\n", args[0])
		return errCode(2, nil)
	}
	tg, loc, err := resolveTelegramBlock(g, env)
	if err != nil {
		return err
	}
	prof, err := profile.LoadProfile(loc.ConfigDir, tg.Profile, env.lookupEnv)
	if err != nil {
		return err
	}
	// ensureNodeID before the runtime is built: deliverSend
	// transmits prof.NodeID verbatim, so the runtime must be
	// built with the identity the send path uses.
	if err := ensureNodeID(loc, prof, env.lookupEnv); err != nil {
		return err
	}
	// Persistent runtime state lives beside the profile's other
	// files (telegram-state.json in the profile directory), never
	// inside the token-bearing config.json. A read failure other
	// than "missing" fails startup: running without a
	// persistable offset would silently re-handle updates after
	// a restart. A corrupt file loads fresh (and is reported
	// once below) instead of failing.
	stateStore, stateCorrupt, err := telegram.LoadStateStore(prof.Dir)
	if err != nil {
		return err
	}
	rt, err := env.buildRuntime(ctx, loc, prof)
	if err != nil {
		return err
	}
	defer func() { _ = rt.Close() }()
	if rt.Muse == nil {
		// Production buildRuntime always sets Muse; a nil
		// Muse here is a wiring error, and the turn runner
		// would nil-panic on first use. Fail fast, before
		// polling starts.
		return errors.New("telegram: runtime has no Muse connection")
	}

	// The bot logger comes from the runtime's logging factory
	// (the sing-box-mirroring log block: level filter +
	// SafeString redaction), tagged "telegram". env.Logger, when
	// set, is an explicit override (tests); on the production
	// path it is nil and the factory logger applies.
	logger := env.Logger
	if logger == nil {
		logger = rt.Logger("telegram")
	}
	if stateCorrupt {
		logger.Warn("telegram state file corrupt; starting with fresh state", "path", telegram.StatePath(prof.Dir))
	}
	// The heartbeat lives for the bot process, not per turn:
	// concurrent turns on one Muse share it, and no turn's
	// stop may end the heartbeat mid-turn for another chat.
	// executeWait therefore runs with externalHeartbeat.
	rt.Muse.StartHeartbeat(0)
	defer rt.Muse.StopHeartbeat()

	// Effective toggles are resolved per turn: the telegram
	// block values are the initial values, and the runtime
	// state file wins after the first /autoapprove toggle
	// (gate D4). No CLI flag, env var, or profile-entry value
	// feeds a bot turn.
	effectiveToggles := func() (bool, bool) {
		aa, ao, _ := stateStore.Toggles()
		approve, allowOnce := tg.AutoApprove, tg.AutoAllowOnce
		if aa != nil {
			approve = *aa
		}
		if ao != nil {
			allowOnce = *ao
		}
		return approve, allowOnce
	}
	var bot *telegram.Bot
	var runner *telegramTurnRunner
	var handler *telegramCmdHandler
	bot, err = telegram.New(telegram.Settings{
		Token:          tg.Token,
		AllowedUserIDs: tg.AllowedUserIDs,
		AutoApprove:    tg.AutoApprove,
		AutoAllowOnce:  tg.AutoAllowOnce,
		HTTPClient:     rt.HTTPClient(),
		Logger:         logger,
		InitialOffset:  stateStore.Offset(),
		OnOffset: func(offset int64) {
			// Offset-before-handle: the save runs before the
			// update is handled. A save failure is logged
			// only — failing the poll loop over state would
			// lose every later update too.
			if err := stateStore.NoteOffset(offset); err != nil {
				logger.Warn("telegram state save failed", "err", err.Error())
			}
		},
		Decider: gatewayDecider{muse: rt.Muse},
		Pending: func(ctx context.Context) ([]telegram.Approval, error) {
			return telegramPendingApprovals(ctx, rt)
		},
		Resume: func(ctx context.Context, info telegram.ResumeInfo) error {
			return runner.runResume(ctx, info)
		},
		// Command dispatch (A4) routes "/" messages to the
		// command table and everything else to a turn. The
		// handler is assigned after New returns; it cannot
		// run before Start, so the nil window never observes
		// a message.
		MessageHandler: func(ctx context.Context, mc telegram.MessageContext) error {
			return handler.dispatch(ctx, mc)
		},
		CallbackFunc: func(ctx context.Context, chatID int64, messageID int, entry telegram.CallbackEntry) (bool, error) {
			return handler.handleCallback(ctx, chatID, messageID, entry)
		},
	})
	if err != nil {
		return err
	}
	runner = newTelegramTurnRunner(telegramTurnDeps{
		env:     env,
		bot:     bot,
		rt:      rt,
		prof:    prof,
		store:   stateStore,
		logger:  logger,
		toggles: effectiveToggles,
	})
	handler = &telegramCmdHandler{
		env:     env,
		bot:     bot,
		rt:      rt,
		prof:    prof,
		store:   stateStore,
		runner:  runner,
		toggles: effectiveToggles,
		logger:  logger,
	}
	fmt.Fprintf(env.stdout(), "telegram: polling for profile %q (%d allowed users); Ctrl-C to stop\n", tg.Profile, len(tg.AllowedUserIDs))
	return bot.Start(ctx)
}

// telegramStatus is the offline JSON report of the block.
type telegramStatus struct {
	Configured    bool   `json:"configured"`
	Profile       string `json:"profile"`
	AllowedUsers  int    `json:"allowed_user_ids"`
	AutoApprove   bool   `json:"auto_approve"`
	AutoAllowOnce bool   `json:"auto_allow_once"`
	TokenValid    bool   `json:"token_valid"`
}

func cmdTelegramStatus(ctx context.Context, env *Env, g *globalOpts, args []string) error {
	if len(args) > 0 && (args[0] == "--help" || args[0] == "-h") {
		fmt.Fprint(env.stdout(), telegramStatusHelpText)
		return errHelpShown
	}
	if len(args) > 0 {
		fmt.Fprintf(env.stderr(), "castctl: telegram status takes no arguments (got %q)\n", args[0])
		return errCode(2, nil)
	}
	tg, _, err := resolveTelegramBlock(g, env)
	if err != nil {
		return err
	}
	st := telegramStatus{
		Configured:    true,
		Profile:       tg.Profile,
		AllowedUsers:  len(tg.AllowedUserIDs),
		AutoApprove:   tg.AutoApprove,
		AutoAllowOnce: tg.AutoAllowOnce,
		TokenValid:    true, // resolveTelegramBlock already shape-checked it
	}
	out, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	fmt.Fprintln(env.stdout(), string(out))
	return nil
}

// resolveTelegramBlock loads the single config, resolves the
// telegram block (nil when absent: exit 2, nothing to run or
// report), and refuses an explicitly named profile that differs
// from the block's linked profile. It never uses the token: it
// only parses and validates the block.
func resolveTelegramBlock(g *globalOpts, env *Env) (*profile.TelegramConfig, *profile.ConfigLocation, error) {
	loc, err := resolveConfig(g, env, false)
	if err != nil {
		return nil, nil, err
	}
	single, found, err := profile.LoadSingleConfig(loc.ConfigDir)
	if err != nil {
		return nil, nil, err
	}
	if !found {
		return nil, nil, errCodef(2, "telegram: no config.json found; add a \"telegram\" block to configure the bot")
	}
	tg, err := profile.ResolveTelegram(single)
	if err != nil {
		return nil, nil, err
	}
	if tg == nil {
		return nil, nil, errCodef(2, "telegram: no \"telegram\" block in config.json; the bot is off")
	}
	if g.profileSet && g.profileFlag != tg.Profile {
		return nil, nil, errCodef(2, "telegram: --profile %q does not match the telegram block's profile %q", g.profileFlag, tg.Profile)
	}
	if v, ok := env.lookupEnv(profile.ProfileEnv); ok && strings.TrimSpace(v) != "" && strings.TrimSpace(v) != tg.Profile {
		return nil, nil, errCodef(2, "telegram: %s %q does not match the telegram block's profile %q", profile.ProfileEnv, strings.TrimSpace(v), tg.Profile)
	}
	return tg, loc, nil
}
