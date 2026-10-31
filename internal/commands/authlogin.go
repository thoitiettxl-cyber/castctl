// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package commands

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/thoitiettxl-cyber/castctl/internal/keeper"
	"github.com/thoitiettxl-cyber/castctl/internal/profile"
)

// `castctl auth login`: screencast login, EXPERIMENTAL and OFF
// by default. The human completes the login in a Chrome window
// (the attached browser when one is configured, otherwise a
// castctl-launched Chrome — which fails closed at this base,
// see keeper launch). The session only watches, exports, and
// saves on Done. Never auto-solves captcha/2FA.
//
//   - Without --experimental-login (or CASTCTL_EXPERIMENTAL_LOGIN=1):
//     exit 2 pointing at the flag and at `auth import`.
//   - Without the with_chromedp build tag: exit 2, "not in
//     this build".
//   - Exit 0 for saved / cancelled / timed-out outcomes (the
//     JSON result on stdout says which). Infrastructure
//     failures return errors through the normal contract.
//
// Input is stdin lines: "done" when the login is complete,
// "cancel" to abandon. Frames are dropped: the user watches
// their own Chrome window, not a relay (the relay is item 2).

const authLoginHelpText = `usage: castctl auth login [--profile NAME] [--timeout 15m] [--browser-path PATH] [--experimental-login]

Log in to Muse through a screencast session (EXPERIMENTAL).

The human completes the login in a Chrome window. Type "done"
on stdin when logged in, or "cancel" to abandon. Cookies are
exported from the browser and saved only on "done", after the
session is validated against the cheap chain.

  --profile NAME        profile to log in (default: active profile)
  --timeout DURATION    session timeout, 60s-60min (default 15m)
  --browser-path PATH   Chrome/Chromium binary for the launch fallback
  --experimental-login  enable this experimental command

Also enabled by CASTCTL_EXPERIMENTAL_LOGIN=1. Without it, use
"castctl auth import" instead (paste a cookies.txt export).
`

// experimentalLoginEnabled reports whether the screencast
// login gate is open: the flag, or the env var set to "1".
func experimentalLoginEnabled(env *Env, flagSet bool) bool {
	if flagSet {
		return true
	}
	if v, ok := env.lookupEnv("CASTCTL_EXPERIMENTAL_LOGIN"); ok && v == "1" {
		return true
	}
	return false
}

func cmdAuthLogin(ctx context.Context, env *Env, g *globalOpts, args []string) error {
	ap := &argParser{
		defs: []flagDef{
			{name: "profile", kind: flagString},
			{name: "timeout", kind: flagString},
			{name: "browser-path", kind: flagString},
			{name: "experimental-login", kind: flagBool},
		},
		helpText: authLoginHelpText,
		prog:     "castctl auth login",
	}
	p, helpShown, err := ap.parse(args, env.stdout())
	if err != nil {
		if pe, ok := err.(*parserError); ok {
			fmt.Fprintf(env.stderr(), "castctl: %s\n", pe.msg)
			return errCode(2, pe)
		}
		return err
	}
	if helpShown {
		return errHelpShown
	}
	if err := checkPositionals(p, nil, "auth login"); err != nil {
		return usageErr(err)
	}
	if !experimentalLoginEnabled(env, p.bool("experimental-login")) {
		return errCodef(2, "auth login is experimental: pass --experimental-login (or set CASTCTL_EXPERIMENTAL_LOGIN=1), or use \"castctl auth import\" instead")
	}
	if !keeper.CDPAvailable() {
		return errCodef(2, "auth login is not available in this build: rebuild with -tags with_chromedp")
	}
	// Profile: the subcommand flag wins over global resolution.
	var prof *profile.Profile
	loc, err := resolveConfig(g, env, false)
	if err != nil {
		return err
	}
	if p.strIsSet("profile") {
		prof, err = profile.LoadProfile(loc.ConfigDir, p.str("profile"), env.lookupEnv)
		if err != nil {
			return err
		}
	} else {
		prof, err = resolveActive(loc, g, env)
		if err != nil {
			return err
		}
	}
	timeout := keeper.DefaultLoginTimeout
	if p.strIsSet("timeout") {
		d, err := time.ParseDuration(p.str("timeout"))
		if err != nil {
			return errCodef(2, "auth login: invalid --timeout %q: %v", p.str("timeout"), err)
		}
		timeout = d
	}
	if timeout < keeper.MinLoginTimeout || timeout > keeper.MaxLoginTimeout {
		return errCodef(2, "auth login: --timeout %v out of range [%v, %v]", timeout, keeper.MinLoginTimeout, keeper.MaxLoginTimeout)
	}
	// Runner: attach first (the keeper entry's browser URL),
	// launch fallback only when no attachable browser exists.
	// A configured-but-unreachable browser is an error, never
	// a silent fallback to a launched browser.
	single, found, err := profile.LoadSingleConfig(loc.ConfigDir)
	if err != nil {
		return err
	}
	var runner keeper.ScreencastRunner
	if found {
		if kcfg, err := profile.ResolveKeeper(single); err == nil && kcfg != nil {
			if entry := kcfg.KeeperEntryForProfile(prof.Name); entry != nil && entry.Browser != "" {
				runner = keeper.NewAttachRunner(entry.Browser)
			}
		} else if err != nil {
			return err
		}
	}
	if runner == nil {
		runner = keeper.NewLaunchRunner(loc.ConfigDir, prof, p.str("browser-path"), nil)
	}
	rt, err := env.buildRuntime(ctx, loc, prof)
	if err != nil {
		return err
	}
	defer rt.Close()
	transport := newStdinTransport(env.stdin(), env.stderr())
	session := &keeper.LoginSession{
		BaseDir:      loc.ConfigDir,
		Profile:      prof,
		Timeout:      timeout,
		Transport:    transport,
		Checker:      &keeper.GatewayChecker{Client: rt.HTTPClient()},
		Runner:       runner,
		PollInterval: keeper.LoginPollInterval,
	}
	result := session.Run(ctx)
	out := struct {
		Outcome          string   `json:"outcome"`
		CookiesSaved     bool     `json:"cookies_saved"`
		SavedCookieNames []string `json:"saved_cookie_names,omitempty"`
		EarliestExpiry   *string  `json:"earliest_expiry,omitempty"`
		DurationMS       int64    `json:"duration_ms"`
		FramesDropped    int64    `json:"frames_dropped"`
	}{
		Outcome:       string(result.Outcome),
		CookiesSaved:  result.CookiesSaved,
		DurationMS:    result.Duration.Milliseconds(),
		FramesDropped: transport.droppedFrames(),
	}
	if result.CookiesSaved {
		out.SavedCookieNames = result.SavedNames
		if result.EarliestExpiry != nil {
			s := result.EarliestExpiry.Format(time.RFC3339)
			out.EarliestExpiry = &s
		}
	}
	if err := writeJSON(env.stdout(), out); err != nil {
		return err
	}
	if result.Outcome == keeper.LoginFailed && result.Err != nil {
		return result.Err
	}
	if result.Outcome == keeper.LoginFailed {
		return errCode(1, errors.New("auth login failed"))
	}
	return nil
}

// stdinTransport is the local-only Transport for `auth login`:
// frames are dropped (the user watches their own Chrome),
// phases go to stderr, and stdin lines drive Done/Cancel.
// EOF on stdin is transport death: the session ends.
type stdinTransport struct {
	inputs  chan keeper.InputEvent
	done    chan struct{}
	stderr  io.Writer
	dropped int64
	once    sync.Once
}

func newStdinTransport(stdin io.Reader, stderr io.Writer) *stdinTransport {
	t := &stdinTransport{
		inputs: make(chan keeper.InputEvent, 4),
		done:   make(chan struct{}),
		stderr: stderr,
	}
	go func() {
		defer close(t.done)
		sc := bufio.NewScanner(stdin)
		sc.Buffer(make([]byte, 0, 1024), 1024)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			switch strings.ToLower(line) {
			case "done":
				t.inputs <- keeper.InputEvent{Kind: keeper.InputDone}
			case "cancel":
				t.inputs <- keeper.InputEvent{Kind: keeper.InputCancel}
			default:
				fmt.Fprintf(stderr, "castctl: auth login: ignoring input %q (type \"done\" or \"cancel\")\n", line)
			}
		}
	}()
	return t
}

func (t *stdinTransport) SendFrame(_ context.Context, _ keeper.Frame) error {
	// The user watches their own Chrome window; the frame
	// bytes are never stored, logged, or forwarded. Count
	// only.
	atomic.AddInt64(&t.dropped, 1)
	return nil
}

func (t *stdinTransport) SendPhase(_ context.Context, phase keeper.SessionPhase, detail string) error {
	// Phases are the only user-visible progress channel for a
	// local session. The phase is a fixed label; detail is a
	// fixed label too, never data, and is not printed.
	fmt.Fprintf(t.stderr, "castctl: auth login: %s\n", phase)
	return nil
}

func (t *stdinTransport) Inputs() <-chan keeper.InputEvent { return t.inputs }
func (t *stdinTransport) Done() <-chan struct{}            { return t.done }

func (t *stdinTransport) droppedFrames() int64 {
	return atomic.LoadInt64(&t.dropped)
}
