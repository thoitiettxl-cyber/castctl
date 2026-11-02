// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package commands

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/thoitiettxl-cyber/castctl/internal/conn"
	"github.com/thoitiettxl-cyber/castctl/internal/gateway"
	"github.com/thoitiettxl-cyber/castctl/internal/keeper"
	"github.com/thoitiettxl-cyber/castctl/internal/profile"
)

// The keeper command: `keeper run|check|status`.
//
//   - `run`: foreground, one goroutine per entry, ticker per
//     interval with ±20% jitter. SIGINT ends it (exit 130 via
//     the main contract). A second `run` for the same entry
//     refuses via the single-flight owner file.
//   - `check`: one tick now, per entry or selected by --tag /
//     --profile. Exit 0 healthy, 2 config, 3
//     auth-expired-or-export-failed, 4 timeout.
//   - `status`: reads state files only, no network. Exit 0
//     even when an entry is logged out or stopped.
//
// Output discipline: stdout carries one summary line per tick
// (run) or JSON (check/status), with counts, names, outcomes,
// and expiry dates only — never cookie values, tokens, or
// error bodies. The keeper core has no logger dependency (it
// must stay embeddable by the web UI), so the slog pipeline
// is not used here; the state file is the durable channel and
// stdout is the foreground channel. When logging is configured
// for the process, the keeper emits nothing extra through it.

const keeperHelpText = `usage: castctl keeper <subcommand> [options]

Session keeper: watch profile cookies for expiry (cheap chain
only: GET /api/session -> POST /api/auth/check), re-export them
from the attached browser when they die, and report. Requires a
"keeper" block in config.json (see docs/config.md).

subcommands:
  run       tick every entry in the foreground until interrupted
  check     run one tick now (exit 0/2/3/4, see below)
  status    show per-entry state from state files only (no network)

selection (run/check/status):
  --tag TAG          only the entry with this tag
  --profile NAME     only the entry for this profile

Default cadence is 24h per entry (the "interval" key; the
adaptive rule shortens it once a cookie expiry is observed).

check exit codes:
  0  healthy (or skipped: login in progress / lock held)
  1  hard failure: lock (other than held), state-directory, or state-save failure (outcome "error", never skipped)
  2  config error (no keeper block, dangling refs, bad selection)
  3  entry stopped (auth expired) or export failed
  4  tick timeout

run prints one summary line per tick to stdout. check prints
one JSON object per entry. status prints a JSON array.
`

const keeperRunHelpText = `usage: castctl keeper run [--tag TAG | --profile NAME]

Tick every selected keeper entry in the foreground until
interrupted (Ctrl-C, exit 130) or every entry stops. A second
"keeper run" for the same entry refuses while the first is
alive (single-flight owner file).
`

const keeperCheckHelpText = `usage: castctl keeper check [--tag TAG | --profile NAME]

Run one tick now for each selected entry and print one JSON
object per entry: tag, profile, outcome, stopped, cookies
seen, whether the cookies file was written, and the next
check time. Exit codes: 0 healthy, 1 hard failure
(lock other than held, state-directory, or state-save
failure; outcome "error", never "skipped"), 2 config, 3 entry
stopped (auth expired) or export failed, 4 timeout (90s per
entry).
A transient error surfaces through the normal error
contract instead (GatewayError 3, timeout 4, other 1).
`

const keeperStatusHelpText = `usage: castctl keeper status [--tag TAG | --profile NAME]

Show per-entry state from the state files only: no network, no
browser contact. Exit 0 even when an entry is logged out or
stopped. Prints a JSON array.
`

func init() {
	registerCommand(&commandSpec{
		name:     "keeper",
		help:     "watch profile cookies for expiry, re-export from the browser",
		helpText: keeperHelpText,
		handler:  cmdKeeper,
	})
	registerFlags("keeper", "keeper <subcommand> [options]", nil)
}

func cmdKeeper(ctx context.Context, env *Env, g *globalOpts, args []string) error {
	if len(args) == 0 {
		fmt.Fprintln(env.stderr(), "castctl: the following arguments are required: subcommand")
		fmt.Fprint(env.stderr(), keeperHelpText)
		return errCode(2, nil)
	}
	switch args[0] {
	case "--help", "-h":
		fmt.Fprint(env.stdout(), keeperHelpText)
		return errHelpShown
	case "run":
		return cmdKeeperRun(ctx, env, g, args[1:])
	case "check":
		return cmdKeeperCheck(ctx, env, g, args[1:])
	case "status":
		return cmdKeeperStatus(ctx, env, g, args[1:])
	default:
		fmt.Fprintf(env.stderr(), "castctl: argument subcommand: invalid choice: %q (choose from run, check, status)\n", args[0])
		return errCode(2, nil)
	}
}

// keeperSelection is the --tag/--profile selector. Both set is
// an error; neither means all entries.
type keeperSelection struct {
	tag     string
	profile string
	set     bool
}

func parseKeeperSelection(args []string, prog, helpText string, env *Env) (keeperSelection, error) {
	ap := &argParser{defs: []flagDef{{name: "tag", kind: flagString}, {name: "profile", kind: flagString}}, helpText: helpText, prog: prog}
	p, helpShown, err := ap.parse(args, env.stdout())
	if err != nil {
		if pe, ok := err.(*parserError); ok {
			fmt.Fprintf(env.stderr(), "castctl: %s\n", pe.msg)
			return keeperSelection{}, errCode(2, pe)
		}
		return keeperSelection{}, err
	}
	if helpShown {
		return keeperSelection{}, errHelpShown
	}
	if err := checkPositionals(p, nil, prog); err != nil {
		return keeperSelection{}, usageErr(err)
	}
	sel := keeperSelection{}
	if p.strIsSet("tag") {
		sel.tag = p.str("tag")
		sel.set = true
	}
	if p.strIsSet("profile") {
		sel.profile = p.str("profile")
		sel.set = true
	}
	if sel.tag != "" && sel.profile != "" {
		return keeperSelection{}, errCodef(2, "keeper: --tag and --profile are mutually exclusive")
	}
	return sel, nil
}

// startEmbeddedKeeper starts the keeper loop inside a
// long-running process (telegram run), sharing its shutdown
// context. It returns a release function the caller defers:
// releasing the single-flight claims and closing the keeper
// runtimes. When no keeper block exists it returns a no-op
// release and starts nothing. A config load failure here
// never fails the host process: the host's own config load
// would already have failed first on a broken file, and a
// keeper that cannot start must not take the bot down with
// it — the failure is logged, once, and the bot runs
// without an embedded keeper.
//
// Single-flight: an entry already owned by a standalone
// `keeper run` is skipped (logged once), never stolen: the
// owner file refuses a second runner for the same entry,
// whichever process started first.
func startEmbeddedKeeper(ctx context.Context, env *Env, g *globalOpts, logger interface {
	Info(string, ...any)
	Warn(string, ...any)
}) func() {
	noop := func() {}
	loc, err := resolveConfig(g, env, false)
	if err != nil {
		logger.Warn("keeper: embedded keeper not started (config location)", "err", err.Error())
		return noop
	}
	single, found, err := profile.LoadSingleConfig(loc.ConfigDir)
	if err != nil || !found {
		if err != nil {
			logger.Warn("keeper: embedded keeper not started (config load)", "err", err.Error())
		}
		return noop
	}
	kcfg, err := profile.ResolveKeeper(single)
	if err != nil {
		logger.Warn("keeper: embedded keeper not started (keeper block)", "err", err.Error())
		return noop
	}
	if kcfg == nil || len(kcfg.Entries) == 0 {
		return noop
	}
	var releases []func()
	var entries []*profile.KeeperEntry
	for _, e := range kcfg.Entries {
		paths, err := profile.ProfilePaths(loc.ConfigDir, e.Profile)
		if err != nil {
			logger.Warn("keeper: embedded keeper skipped entry (paths)", "tag", e.Tag, "err", err.Error())
			continue
		}
		release, err := keeper.AcquireSingleFlight(paths.Dir, e.Tag, keeper.RealClock)
		if err != nil {
			logger.Warn("keeper: embedded keeper skipped entry (already running)", "tag", e.Tag, "err", err.Error())
			continue
		}
		releases = append(releases, release)
		entries = append(entries, e)
	}
	if len(entries) == 0 {
		for _, r := range releases {
			r()
		}
		return noop
	}
	rts := &keeperRuntimes{env: env, g: g, loc: loc, single: single, ctx: ctx}
	onTick := func(entry *profile.KeeperEntry, res keeper.TickResult) {
		logger.Info("keeper tick",
			"tag", keeper.SanitizeDisplay(entry.Tag),
			"profile", keeper.SanitizeDisplay(entry.Profile),
			"outcome", res.Outcome,
			"cookies_seen", res.CookiesSeen,
			"wrote_cookies", res.WroteCookies,
			"next_delay", res.NextDelay.String())
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		keeper.Run(ctx, entries, single.Profiles, loc.ConfigDir, rts.factory, onTick)
	}()
	return func() {
		<-done
		for _, r := range releases {
			r()
		}
		rts.closeAll()
	}
}
// keeperConfig loads the config location, the single config,
// and the keeper block. A missing block is exit 2: the keeper
// is off, and run/check/status have nothing to do.
func keeperConfig(g *globalOpts, env *Env) (*profile.ConfigLocation, *profile.SingleConfig, *profile.KeeperConfig, error) {
	loc, err := resolveConfig(g, env, false)
	if err != nil {
		return nil, nil, nil, err
	}
	single, found, err := profile.LoadSingleConfig(loc.ConfigDir)
	if err != nil {
		return nil, nil, nil, err
	}
	if !found {
		return nil, nil, nil, errCodef(2, "keeper: no config.json found; add a \"keeper\" block to configure the keeper")
	}
	kcfg, err := profile.ResolveKeeper(single)
	if err != nil {
		return nil, nil, nil, err
	}
	if kcfg == nil {
		return nil, nil, nil, errCodef(2, "keeper: no \"keeper\" block in config.json; the keeper is off")
	}
	return loc, single, kcfg, nil
}

func (s keeperSelection) apply(entries []*profile.KeeperEntry) ([]*profile.KeeperEntry, error) {
	if !s.set {
		return entries, nil
	}
	var out []*profile.KeeperEntry
	for _, e := range entries {
		if s.tag != "" && e.Tag == s.tag {
			out = append(out, e)
		}
		if s.profile != "" && e.Profile == s.profile {
			out = append(out, e)
		}
	}
	if len(out) == 0 {
		return nil, errCodef(2, "keeper: no entry matches the selection")
	}
	return out, nil
}

// keeperRuntimes caches one Runtime per profile name for the
// command's lifetime. Runtimes are closed by the caller.
type keeperRuntimes struct {
	env     *Env
	g       *globalOpts
	loc     *profile.ConfigLocation
	single  *profile.SingleConfig
	ctx     context.Context
	runtime map[string]*Runtime
}

func (k *keeperRuntimes) forProfile(name string) (*Runtime, error) {
	if rt, ok := k.runtime[name]; ok {
		return rt, nil
	}
	prof, ok := k.single.Profiles[name]
	if !ok {
		return nil, errCodef(2, "keeper: profile %q does not exist", name)
	}
	rt, err := k.env.buildRuntime(k.ctx, k.loc, prof)
	if err != nil {
		return nil, err
	}
	if k.runtime == nil {
		k.runtime = map[string]*Runtime{}
	}
	k.runtime[name] = rt
	return rt, nil
}

func (k *keeperRuntimes) closeAll() {
	for _, rt := range k.runtime {
		_ = rt.Close()
	}
}

// keeperFactory builds one entry's TickDeps: a per-profile
// runtime (the entry profile's outbound), the cheap-chain
// checker through it, the CDP exporter for the entry's
// browser URL (only when the entry configures a browser: a
// browser-less entry is keep-alive-only and must never
// attempt an export), the gateway probe + wake leg, the
// headless re-login driver when the entry references
// credentials, and the Telegram notifier when referenced.
func (k *keeperRuntimes) factory(entry *profile.KeeperEntry, prof *profile.Profile) (keeper.TickDeps, error) {
	rt, err := k.forProfile(prof.Name)
	if err != nil {
		return keeper.TickDeps{}, err
	}
	deps := keeper.TickDeps{
		Clock:   keeper.RealClock,
		Entry:   entry,
		BaseDir: k.loc.ConfigDir,
		Profile: prof,
		Checker: &keeper.GatewayChecker{Client: rt.HTTPClient()},
	}
	if entry.Browser != "" {
		deps.Exporter = keeper.NewCDPExporter(entry.Browser)
	}
	k.wireWake(entry, prof, rt, &deps)
	k.wireRelogin(entry, prof, rt, &deps)
	if entry.Notify == "telegram" {
		n, err := k.notifier()
		if err != nil {
			// A broken notifier never fails the tick: it
			// degrades to a notifier that always errors,
			// leaving the warn marker pending.
			deps.Notifier = errorNotifier{err: err}
		} else {
			deps.Notifier = n
		}
	}
	return deps, nil
}

// wireWake installs the gateway probe and the wake leg: the
// probe is the full connector path (auth chain + WebSocket
// + Noise handshake, gateway closed immediately, no chat),
// and Wake re-fetches the session/token from the cookies
// file and issues one WakeVM request. A connector-config
// failure leaves both nil: the tick then never wakes, and
// the cheap chain alone decides (the same failure would
// break chat too, so nothing is silently lost).
func (k *keeperRuntimes) wireWake(entry *profile.KeeperEntry, prof *profile.Profile, rt *Runtime, deps *keeper.TickDeps) {
	if !entry.EffectiveWakeOnGatewayFailure() {
		return
	}
	cfg, err := connectorConfig(prof, k.single)
	if err != nil {
		return
	}
	if rt.Dialer == nil {
		// No outbound dialer (test/fake runtime): the
		// gateway probe cannot run, so the wake leg
		// stays unwired rather than dialing on a nil
		// dialer. The cheap chain alone decides.
		return
	}
	connector := k.env.newConnector(rt.Dialer)
	client := rt.HTTPClient()
	deps.GatewayProbe = func(ctx context.Context) error {
		gw, err := conn.BoundedConnect(ctx, connector, cfg, conn.ConnectTimeout)
		if err != nil {
			return err
		}
		return gw.Close()
	}
	deps.Wake = func(ctx context.Context) error {
		cookies, err := rt.Cookies()
		if err != nil {
			return err
		}
		info, err := gateway.FetchSessionInfo(ctx, client, cookies)
		if err != nil {
			return err
		}
		token, err := gateway.FetchAccessToken(ctx, client, cookies)
		if err != nil {
			return err
		}
		vmID := prof.VMID
		if vmID == "" {
			vmID = info.VMID
		}
		if vmID == "" {
			// FetchSessionInfo already classifies a
			// missing vm_id as a GatewayError; reaching
			// here with an empty id means the profile
			// and the session disagree — treat it as
			// the same transient class, never auth.
			return &conn.GatewayError{Status: -1, Payload: "wake: no vm_id available"}
		}
		_, _, err = gateway.WakeVM(ctx, client, cookies, token, vmID)
		return err
	}
}

// wireRelogin installs the headless re-login driver and the
// narrow credential provider when the entry references a
// credentials tag. The provider RE-READS config.json from
// disk on every invocation (i.e. on every re-login attempt):
// a credential removed or rotated by file edit is
// authoritative on the next re-login attempt of a running
// keeper, with no restart. The driver wiring itself (which
// entries get a driver) is fixed at factory-build time from
// the once-loaded config; only the credential VALUES are
// re-read. The provider reads through CredentialForProfile —
// the only read path for credential values — and is only
// invoked when a re-login is actually attempted. The driver
// is built with the recorded contract (unobserved contracts
// refuse at runtime) and the S2 inbound builder for the
// launch fallback. A missing or unresolvable credentials
// block leaves the driver unset: the tick stops and alerts
// instead of guessing.
func (k *keeperRuntimes) wireRelogin(entry *profile.KeeperEntry, prof *profile.Profile, rt *Runtime, deps *keeper.TickDeps) {
	if entry.Credentials == "" {
		return
	}
	creds, err := profile.ResolveCredentials(k.single)
	if err != nil || creds == nil {
		return
	}
	configDir := k.loc.ConfigDir
	profileName := prof.Name
	snapshot := creds
	deps.CredentialProvider = func() (profile.LoginCredential, bool) {
		// Re-read from disk per attempt: the factory-time
		// snapshot is only the fallback when the config
		// file cannot be re-read because there is no
		// config dir (never in production: factory
		// callers always set loc). A re-read failure —
		// deleted file, broken JSON — is fail-closed:
		// no credential, so the tick stops with
		// blocked instead of re-logging in on stale
		// values.
		if configDir == "" {
			return snapshot.CredentialForProfile(profileName)
		}
		fresh, found, err := profile.LoadSingleConfig(configDir)
		if err != nil || !found {
			return profile.LoginCredential{}, false
		}
		freshCreds, err := profile.ResolveCredentials(fresh)
		if err != nil || freshCreds == nil {
			return profile.LoginCredential{}, false
		}
		return freshCreds.CredentialForProfile(profileName)
	}
	contract, err := keeper.DefaultLoginContract()
	if err != nil {
		return
	}
	deps.Relogin = keeper.NewReloginDriver(keeper.ReloginOptions{
		BrowserURL:  entry.Browser,
		BaseDir:     k.loc.ConfigDir,
		Inbound:     newProfileInboundBuilder(rt, entry),
		Profile:     prof,
		Contract:    contract,
		MaxAttempts: entry.EffectiveReloginAttempts(),
		Entry:       entry,
	})
}

// notifier builds the Telegram notifier for the single
// telegram block: fixed-content notices via sendMessage
// through the LINKED profile's outbound.
//
// TARGETING (live-test gate, [NEEDS-MEASUREMENT]): the
// telegram block has no chat registry, so the notice goes to
// the FIRST allowed_user_ids entry, on the assumption that a
// user id is a valid chat id for a 1:1 bot chat. Delivery to
// that id is UNVERIFIED offline: the fake Bot API tests prove
// the request shape, not delivery. If delivery fails in the
// live test, the fix is a chat registry (item 2 scope), not a
// silent change here.
func (k *keeperRuntimes) notifier() (keeper.Notifier, error) {
	tg, err := profile.ResolveTelegram(k.single)
	if err != nil {
		return nil, err
	}
	if tg == nil {
		return nil, errors.New("keeper: entry notifies \"telegram\" but no \"telegram\" block exists")
	}
	if len(tg.AllowedUserIDs) == 0 {
		return nil, errors.New("keeper: telegram block has an empty allowed_user_ids allowlist")
	}
	rt, err := k.forProfile(tg.Profile)
	if err != nil {
		return nil, err
	}
	return &telegramNotifier{
		client: rt.HTTPClient(),
		token:  tg.Token,
		chatID: tg.AllowedUserIDs[0],
	}, nil
}

type errorNotifier struct{ err error }

func (n errorNotifier) Notify(_ context.Context, _ keeper.NoticeKind, _ string) error {
	return n.err
}

// telegramNotifier sends fixed-content notices with a raw
// sendMessage POST. The token travels in the request path
// only; it is never logged, and failures carry a fixed
// message plus the HTTP status, never a body.
type telegramNotifier struct {
	client *http.Client
	token  string
	chatID int64
}

func (n *telegramNotifier) Notify(ctx context.Context, kind keeper.NoticeKind, profileName string) error {
	// Bounded: a notice must never hang the runner on a dead
	// Telegram endpoint (loop-2 red-team N9). 30s covers a
	// normal send with retries inside the client; the tick
	// already finished, so this bound only caps the wait.
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	form := url.Values{}
	form.Set("chat_id", strconv.FormatInt(n.chatID, 10))
	form.Set("text", keeper.NoticeText(kind, profileName))
	endpoint := "https://api.telegram.org/bot" + n.token + "/sendMessage"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return errors.New("telegram notice send failed")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := n.client.Do(req)
	if err != nil {
		return errors.New("telegram notice send failed")
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return errors.New("telegram notice send failed")
	}
	var decoded struct {
		OK bool `json:"ok"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil || !decoded.OK {
		return fmt.Errorf("telegram notice send failed: status %d", resp.StatusCode)
	}
	return nil
}

func cmdKeeperRun(ctx context.Context, env *Env, g *globalOpts, args []string) error {
	sel, err := parseKeeperSelection(args, "castctl keeper run", keeperRunHelpText, env)
	if err != nil {
		return err
	}
	loc, single, kcfg, err := keeperConfig(g, env)
	if err != nil {
		return err
	}
	entries, err := sel.apply(kcfg.Entries)
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		fmt.Fprintln(env.stdout(), "keeper: no entries configured")
		return nil
	}
	profiles := single.Profiles
	// Single-flight per entry, acquired before ticking.
	var releases []func()
	for _, e := range entries {
		paths, err := profile.ProfilePaths(loc.ConfigDir, e.Profile)
		if err != nil {
			return err
		}
		release, err := keeper.AcquireSingleFlight(paths.Dir, e.Tag, keeper.RealClock)
		if err != nil {
			for _, r := range releases {
				r()
			}
			// A live owner is a usage conflict, exit 2.
			return errCode(2, err)
		}
		releases = append(releases, release)
	}
	defer func() {
		for _, r := range releases {
			r()
		}
	}()
	rts := &keeperRuntimes{env: env, g: g, loc: loc, single: single, ctx: ctx}
	defer rts.closeAll()
	// Ticks for different entries run concurrently; serialise
	// the summary lines so they never interleave, whatever
	// writer backs stdout.
	var outMu sync.Mutex
	onTick := func(entry *profile.KeeperEntry, res keeper.TickResult) {
		outMu.Lock()
		defer outMu.Unlock()
		corrupt := ""
		if res.StateCorrupt {
			corrupt = " state_corrupt=true"
		}
		fmt.Fprintf(env.stdout(), "keeper: %s (%s): %s cookies_seen=%d wrote=%v next_delay=%s%s\n",
			keeper.SanitizeDisplay(entry.Tag), keeper.SanitizeDisplay(entry.Profile), res.Outcome, res.CookiesSeen, res.WroteCookies, res.NextDelay, corrupt)
	}
	results := keeper.Run(ctx, entries, profiles, loc.ConfigDir, rts.factory, onTick)
	if ctx.Err() != nil {
		// Interrupted: the main contract maps this to 130.
		return ctx.Err()
	}
	// A factory failure is not a tick: the entry never ran,
	// and Run records it with Ticks==0 and Last.Err set. It
	// must not exit 0 silently (loop-2 red-team F5): name
	// the entry and exit 2.
	for _, res := range results {
		if res.Ticks == 0 && res.Last.Err != nil {
			fmt.Fprintf(env.stdout(), "keeper: %s: failed (factory error, entry never ticked)\n",
				keeper.SanitizeDisplay(res.Tag))
			return errCode(2, res.Last.Err)
		}
	}
	return nil
}

type keeperCheckResult struct {
	Tag          string     `json:"tag"`
	Profile      string     `json:"profile"`
	Outcome      string     `json:"outcome"`
	Stopped      bool       `json:"stopped"`
	CookiesSeen  int        `json:"cookies_seen"`
	WroteCookies bool       `json:"wrote_cookies"`
	NextCheckAt  *time.Time `json:"next_check_at,omitempty"`
	// StateCorrupt reports a corrupt/unknown-version state
	// file observed by this tick (fresh state substituted,
	// re-observed from the cookies file).
	StateCorrupt bool `json:"state_corrupt,omitempty"`
}

// keeperCheckTimeout bounds one entry's tick: past it, the
// command exits 4 (timeout), never hangs on a dead browser
// or a wedged chain. A var, not a const, so tests can
// shorten it; the production default is 90s, and a test
// that overrides it must restore it and must not run in
// parallel with other keeper check tests.
var keeperCheckTimeout = 90 * time.Second

func cmdKeeperCheck(ctx context.Context, env *Env, g *globalOpts, args []string) error {
	sel, err := parseKeeperSelection(args, "castctl keeper check", keeperCheckHelpText, env)
	if err != nil {
		return err
	}
	loc, single, kcfg, err := keeperConfig(g, env)
	if err != nil {
		return err
	}
	entries, err := sel.apply(kcfg.Entries)
	if err != nil {
		return err
	}
	rts := &keeperRuntimes{env: env, g: g, loc: loc, single: single, ctx: ctx}
	defer rts.closeAll()
	worst := 0
	var firstSurfacedErr error
	for _, entry := range entries {
		prof := single.Profiles[entry.Profile]
		deps, err := rts.factory(entry, prof)
		if err != nil {
			return err
		}
		tickCtx, cancel := context.WithTimeout(ctx, keeperCheckTimeout)
		res := keeper.Tick(tickCtx, deps)
		timedOut := tickCtx.Err() == context.DeadlineExceeded
		cancel()
		// An interrupted parent context ends the command:
		// never swallow it as a per-entry outcome, and never
		// continue to further entries (loop-2 technical N4).
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if res.Stopped {
			keeper.NotifyStopped(ctx, deps, deps.Notifier)
		}
		nextAt := nextCheckAt(loc.ConfigDir, entry)
		out := keeperCheckResult{
			Tag: entry.Tag, Profile: entry.Profile, Outcome: res.Outcome,
			Stopped: res.Stopped, CookiesSeen: res.CookiesSeen,
			WroteCookies: res.WroteCookies, NextCheckAt: nextAt,
			StateCorrupt: res.StateCorrupt,
		}
		if err := writeJSON(env.stdout(), out); err != nil {
			return err
		}
		// A hard failure (OutcomeError) is remembered even
		// when the entry also stopped: the typed error must
		// surface after the loop (exit 1) instead of being
		// swallowed into the stopped exit 3.
		if res.Outcome == keeper.OutcomeError && res.Err != nil && firstSurfacedErr == nil {
			firstSurfacedErr = res.Err
		}
		switch {
		case timedOut:
			worst = 4
		case res.Stopped || res.Outcome == keeper.OutcomeExportFailed:
			if worst < 3 {
				worst = 3
			}
		case res.Outcome == keeper.OutcomeTransientError:
			// Transient: remember the first typed error
			// and CONTINUE with the remaining entries so
			// the output is complete (loop-2 red-team
			// N20). The error surfaces after the loop
			// through the normal contract (GatewayError
			// 3, timeout 4, other 1) instead of
			// inventing a new code.
			if res.Err != nil && firstSurfacedErr == nil {
				firstSurfacedErr = res.Err
			} else if worst < 1 {
				worst = 1
			}
		case res.Outcome == keeper.OutcomeError:
			// Hard failure (K-LIVE-1/B1/B2): loud,
			// never skipped. Same shape as the transient
			// path — print every entry, then return the
			// first typed error (a plain error, so the
			// normal contract exits 1 with its message).
			if res.Err != nil && firstSurfacedErr == nil {
				firstSurfacedErr = res.Err
			} else if worst < 1 {
				worst = 1
			}
		}
	}
	// Interrupt first (already returned above), then the
	// remembered transient/state-dir error, then the worst outcome.
	if firstSurfacedErr != nil {
		return firstSurfacedErr
	}
	switch worst {
	case 4:
		return errCode(4, errors.New("keeper check timed out"))
	case 3:
		return errCode(3, errors.New("keeper check: entry stopped (auth expired) or export failed"))
	case 1:
		return errCode(1, errors.New("keeper check: transient error"))
	default:
		return nil
	}
}

// nextCheckAt reads the state's next_check_at for the check
// output. A missing/corrupt state is not a check failure:
// the field is omitted.
func nextCheckAt(baseDir string, entry *profile.KeeperEntry) *time.Time {
	paths, err := profile.ProfilePaths(baseDir, entry.Profile)
	if err != nil {
		return nil
	}
	st, err := keeper.LoadState(paths.Dir)
	if err != nil {
		return nil
	}
	return st.NextCheckAt
}

func cmdKeeperStatus(ctx context.Context, env *Env, g *globalOpts, args []string) error {
	sel, err := parseKeeperSelection(args, "castctl keeper status", keeperStatusHelpText, env)
	if err != nil {
		return err
	}
	loc, _, kcfg, err := keeperConfig(g, env)
	if err != nil {
		return err
	}
	entries, err := sel.apply(kcfg.Entries)
	if err != nil {
		return err
	}
	statuses := make([]keeper.Status, 0, len(entries))
	for _, entry := range entries {
		st, err := keeper.ReadStatus(loc.ConfigDir, entry)
		if err != nil {
			return err
		}
		statuses = append(statuses, st)
	}
	// Exit 0 even when entries are logged out or stopped:
	// status reports state, it does not judge it.
	return writeJSON(env.stdout(), statuses)
}
