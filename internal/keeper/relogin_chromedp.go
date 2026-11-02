// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

//go:build with_chromedp

package keeper

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/chromedp/cdproto/storage"
	"github.com/chromedp/chromedp"
	"github.com/chromedp/chromedp/remote"

	"github.com/thoitiettxl-cyber/castctl/internal/profile"
)

// Headless re-login driver (with_chromedp only).
//
// BOUNDARY. This driver is the ONE place in castctl that
// evaluates JavaScript in a browser, and it does so under a
// strict rule: the evaluated script is a FIXED string that
// takes the contract's selectors/keywords as data and
// returns ONLY booleans (which selectors are present) and
// fixed signal-class strings (which blocker kind hit, and
// whether by selector or keyword). No page text, HTML,
// attribute value, screenshot, or cookie value ever crosses
// from the page into Go through evaluation; cookies are
// harvested only through the browser-level Storage.getCookies
// call, the same read the CDP exporter uses. The driver never
// exfiltrates, never screenshots, never enables the screencast
// relay, and never touches a target it did not create.
//
// FLOW. Attach to the already-running Chrome first (the
// entry's browser URL); only when no attachable browser
// exists, launch headless through the S2 profile-routed
// inbound (the proxy URL from InboundBuilder is the browser's
// ONLY egress). Match the page against the recorded contract
// BEFORE entering anything; on any mismatch or blocker
// signal, stop with a *ReloginBlocker and enter nothing.
// Fill and submit exactly the recorded steps — clearing each
// field before typing, and re-matching the page before the
// submit click so a blocker appearing mid-fill stops before
// anything is submitted — then poll for the harvested
// session cookies. Transient failures retry up to MaxAttempts
// with a fresh tab each time; a blocker returns immediately
// and is never retried. A failed launch or attempt removes
// the browser profile dir the launch created (a pre-existing
// dir is never removed: it may belong to the screencast
// login path); a successful harvest keeps the dir, which
// persists by design (see docs/security.md).

// ReloginAvailable reports whether this build has a headless
// re-login driver. Chromedp build: yes.
func ReloginAvailable() bool { return true }

// NewReloginDriver builds the headless re-login driver.
func NewReloginDriver(opts ReloginOptions) ReloginDriver {
	return &chromedpReloginDriver{opts: opts}
}

type chromedpReloginDriver struct {
	opts ReloginOptions
}

// snapshotScript is the FIXED evaluation script. It receives
// the selector list and blocker signals as JSON data (never
// interpolated page content) and returns booleans only.
func snapshotScript(selectors []string, blockers []LoginBlockerSignal) (string, error) {
	selJSON, err := json.Marshal(selectors)
	if err != nil {
		return "", err
	}
	type blockerArg struct {
		Selector string `json:"selector"`
		Keyword  string `json:"keyword"`
		Kind     string `json:"kind"`
	}
	args := make([]blockerArg, 0, len(blockers))
	for _, b := range blockers {
		args = append(args, blockerArg{Selector: b.Selector, Keyword: b.Keyword, Kind: string(b.Kind)})
	}
	blkJSON, err := json.Marshal(args)
	if err != nil {
		return "", err
	}
	script := `(function(selectors, blockers){
		var present = {};
		for (var i = 0; i < selectors.length; i++) {
			try { present[selectors[i]] = !!document.querySelector(selectors[i]); }
			catch (e) { present[selectors[i]] = false; }
		}
		var text = "";
		try { text = (document.body ? document.body.innerText : "") || ""; } catch (e) {}
		var lower = text.toLowerCase();
		var hits = {};
		for (var j = 0; j < blockers.length; j++) {
			var b = blockers[j];
			// Selector first, then keyword, first hit per
			// kind wins — the same order MatchContract
			// applies Go-side. The value names the signal
			// class only, never page text.
			if (b.selector) { try { if (document.querySelector(b.selector)) { if (!hits[b.kind]) { hits[b.kind] = "selector"; } } } catch (e) {} }
			if (b.keyword && lower.indexOf(b.keyword.toLowerCase()) !== -1) { if (!hits[b.kind]) { hits[b.kind] = "keyword"; } }
		}
		return {present: present, hits: hits};
	})(` + string(selJSON) + `, ` + string(blkJSON) + `)`
	return script, nil
}

// snapshot evaluates the fixed boolean script on the target
// and maps the result onto the contract through
// snapshotDecision (the same decision MatchContract makes).
// It returns a *ReloginBlocker for a hit/mismatch, or nil
// when the page matches.
func snapshotMatch(ctx context.Context, contract LoginContract) error {
	selectors := make([]string, 0, len(contract.Steps))
	for _, step := range contract.Steps {
		selectors = append(selectors, step.Selector)
	}
	script, err := snapshotScript(selectors, contract.Blockers)
	if err != nil {
		return err
	}
	res, err := chromedp.Run(ctx, chromedp.Evaluate[snapshotResult](script))
	if err != nil {
		return err
	}
	return snapshotDecision(contract, res)
}

// browserContext acquires a chromedp target context:
// attach-first when a browser URL is configured, headless
// launch through the S2 inbound otherwise. The returned
// cancel tears down the target AND the browser it owns (for
// a launched browser) or just the target (for attach: the
// user's browser is never killed). An attach failure falls
// back to launch; a launch failure is returned.
//
// removeDir removes the browser profile dir when the launch
// created it AND the caller reports failure (the caller
// invokes it only on a failed attempt/observation, after
// cancel). It is a no-op for the attach path and when the
// dir pre-existed the launch: a pre-existing dir may belong
// to the screencast login path and must never be deleted
// from here. A successful attempt never calls it: the dir
// persists by design.
func (d *chromedpReloginDriver) browserContext(ctx context.Context) (context.Context, context.CancelFunc, func(), error) {
	if d.opts.BrowserURL != "" {
		if tctx, cancel, err := attachTargetContext(ctx, d.opts.BrowserURL, d.opts.Entry.EffectiveReloginAttachTimeout()); err == nil {
			return tctx, cancel, func() {}, nil
		} else {
			attachErr := err
			if d.opts.Inbound == nil {
				return nil, nil, nil, attachErr
			}
			// Attach failed: fall through to launch.
			_ = attachErr
		}
	}
	return launchHeadlessContext(ctx, d.opts)
}

// attachTargetContext attaches to a running browser and
// returns a fresh target context in it. dialTimeout bounds
// the WebSocket dial; it comes from the entry's
// relogin_attach_timeout (documented default when the entry
// is absent).
func attachTargetContext(ctx context.Context, browserURL string, dialTimeout time.Duration) (context.Context, context.CancelFunc, error) {
	wsURL, err := DiscoverWebSocketURL(ctx, browserURL)
	if err != nil {
		return nil, nil, err
	}
	allocCtx, cancelAlloc := remote.NewAllocator(ctx, wsURL, remote.NoModifyURL, remote.WithDialTimeout(dialTimeout))
	tctx, cancelTarget := chromedp.NewContext(allocCtx)
	cancel := func() {
		cancelTarget()
		cancelAlloc()
	}
	// Prove the attach works before the caller navigates:
	// a dead debug port must fall back to launch, not fail
	// the attempt mid-form.
	if _, err := chromedp.Run(tctx, chromedp.Navigate("about:blank")); err != nil {
		cancel()
		return nil, nil, err
	}
	return tctx, cancel, nil
}

// launchHeadlessContext launches a headless Chrome whose
// ONLY egress is the S2 profile-routed inbound, and returns
// a target context in it. The browser is killed when cancel
// runs; the per-profile user-data dir persists (see
// browserContext's removeDir for the failure-cleanup rule).
func launchHeadlessContext(ctx context.Context, opts ReloginOptions) (context.Context, context.CancelFunc, func(), error) {
	if opts.Inbound == nil {
		return nil, nil, nil, ErrLaunchUnavailable
	}
	if opts.Profile == nil {
		return nil, nil, nil, errors.New("re-login: no profile")
	}
	// Fail fast on a missing Chrome binary, BEFORE creating
	// the profile dir or starting the proxy: chromedp's
	// context cancel waits for the allocator to reap the
	// browser process, and a process that never started is
	// never reaped — a launch against a missing binary
	// would wedge the attempt past context cancellation
	// (observed: 130s+ hang on a 60s context). Only an
	// explicitly configured path is checked here; an empty
	// path falls through to chromedp's own search, and the
	// bounded cancel below guards that case.
	browserPath := resolveBrowserPath("")
	if browserPath != "" {
		if _, err := os.Stat(browserPath); err != nil {
			return nil, nil, nil, fmt.Errorf("re-login: chrome binary not found at %s", browserPath)
		}
	}
	proxyURL, cleanup, err := opts.Inbound.BuildInbound(ctx, opts.Profile)
	if err != nil {
		return nil, nil, nil, err
	}
	dir, err := browserProfileDir(opts.BaseDir, opts.Profile)
	if err != nil {
		cleanup()
		return nil, nil, nil, err
	}
	// Only a dir this launch creates is ever removed on
	// failure (see browserContext): record pre-existence
	// before creating it. A pre-existing dir may hold the
	// screencast login's Chrome state.
	_, statErr := os.Lstat(dir)
	created := os.IsNotExist(statErr)
	removeDir := func() {
		if !created {
			return
		}
		// Best effort, with one settle retry: Chrome child
		// processes can outlive the browser and recreate
		// (part of) the dir after RemoveAll — the
		// recreated skeleton holds lock/empty files, not
		// the cookie store (the browser process is dead),
		// but the removal must still be attempted again
		// after a short settle. The settle is one driver
		// poll interval (the entry's
		// relogin_poll_interval, documented default when
		// the entry is absent), not a second hardcoded
		// bound. If the dir is already gone, the second
		// check costs nothing and no sleep happens.
		_ = os.RemoveAll(dir)
		if _, err := os.Lstat(dir); os.IsNotExist(err) {
			return
		}
		time.Sleep(opts.Entry.EffectiveReloginPollInterval())
		_ = os.RemoveAll(dir)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		cleanup()
		removeDir()
		return nil, nil, nil, err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		cleanup()
		removeDir()
		return nil, nil, nil, err
	}
	allocOpts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Headless,
		// The debug-port flag selects the WebSocket
		// transport: chromedp v0.21 defaults to the pipe
		// transport, which has no port to discover.
		remote.WebSocket,
		chromedp.Flag("enable-automation", false),
		chromedp.Flag("disable-blink-features", "AutomationControlled"),
		chromedp.Flag("remote-debugging-port", "0"),
		chromedp.UserDataDir(dir),
		chromedp.ProxyServer(proxyURL),
	)
	if path := resolveBrowserPath(""); path != "" {
		allocOpts = append(allocOpts, chromedp.ExecPath(path))
	}
	allocCtx, cancelAlloc := chromedp.NewExecAllocator(ctx, allocOpts...)
	tctx, cancelTarget := chromedp.NewContext(allocCtx)
	cancel := func() {
		// Bounded: chromedp's target cancel waits for the
		// allocator to reap the browser process, which never
		// happens when the process failed to start (or died
		// before allocating) — an unbounded wait wedges the
		// tick past context cancellation. The bound is the
		// entry's relogin_cancel_timeout (documented
		// default when the entry is absent). Note the
		// ordering precisely: if cancelTarget() itself
		// wedges, cancelAlloc() never runs, and the
		// process kill in that case comes from the outer
		// attempt-context cancellation watched by the
		// allocator — the bound limits only the wait, it
		// does not itself kill anything. A wedged cancel
		// leaks one goroutine per failed launch; a failed
		// launch already stops the entry, so this cannot
		// accumulate in normal operation.
		done := make(chan struct{})
		go func() {
			cancelTarget()
			cancelAlloc()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(opts.Entry.EffectiveReloginCancelTimeout()):
		}
		cleanup()
	}
	return tctx, cancel, removeDir, nil
}

// Relogin runs one headless re-login incident: up to
// MaxAttempts whole-sequence attempts, one tab per attempt,
// blockers never retried.
func (d *chromedpReloginDriver) Relogin(ctx context.Context, cred profile.LoginCredential) ([]ExportedCookie, error) {
	contract := d.opts.Contract
	if !contract.Observed {
		return nil, ErrContractNotEstablished
	}
	// The driver's copy is cleared on return (best effort:
	// copies already handed to chromedp/CDP cannot be
	// scrubbed from here — see LoginCredential.Clear).
	defer cred.Clear()
	if len(contract.Steps) == 0 || contract.LoginURL == "" {
		return nil, &ReloginBlocker{Kind: NoticeBlocked, Detail: "contract_empty"}
	}
	attempts := d.opts.MaxAttempts
	if attempts < 1 {
		attempts = 1
	}
	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		cookies, berr, terr := d.attempt(ctx, contract, cred)
		if berr != nil {
			return nil, berr
		}
		if terr == nil {
			return cookies, nil
		}
		lastErr = terr
	}
	if lastErr == nil {
		lastErr = errors.New("re-login: attempts exhausted without cookies")
	}
	return nil, lastErr
}

// attempt runs one whole login sequence in a fresh tab:
// navigate, match, fill, submit, harvest. It returns either
// cookies, a blocker, or a transient error — never more
// than one of them. A failed attempt removes the browser
// profile dir the launch created (after the browser is
// killed); a successful harvest keeps it.
func (d *chromedpReloginDriver) attempt(ctx context.Context, contract LoginContract, cred profile.LoginCredential) ([]ExportedCookie, *ReloginBlocker, error) {
	// This attempt's copy is cleared on return; the
	// caller's copy is cleared by Relogin.
	defer cred.Clear()
	tctx, cancel, removeDir, err := d.browserContext(ctx)
	if err != nil {
		return nil, nil, err
	}
	// fail tears the browser down, removes a
	// launch-created profile dir, and returns the failure.
	fail := func(blocker *ReloginBlocker, terr error) ([]ExportedCookie, *ReloginBlocker, error) {
		cancel()
		removeDir()
		return nil, blocker, terr
	}
	defer cancel()
	if _, err := chromedp.Run(tctx, chromedp.Navigate(contract.LoginURL)); err != nil {
		return fail(nil, err)
	}
	// Wait for the form (or a blocker) to appear, polling
	// the boolean snapshot. A page that never matches the
	// contract is a mismatch blocker, not a retry: the
	// form genuinely is not the recorded one. The wait and
	// poll cadence come from the entry (documented
	// defaults when the entry is absent).
	if berr := d.waitForMatch(tctx, contract, d.opts.Entry.EffectiveReloginMatchTimeout(), d.opts.Entry.EffectiveReloginPollInterval()); berr != nil {
		var blocker *ReloginBlocker
		if errors.As(berr, &blocker) {
			return fail(blocker, nil)
		}
		return fail(nil, berr)
	}
	// Enter exactly the recorded steps, in order. No other
	// input is ever dispatched. Before a click step, the
	// page is re-matched: a blocker appearing mid-fill
	// (captcha/checkpoint after the first field) stops
	// before the submit click, and a page that changed
	// mid-fill is never clicked into. Each fill clears the
	// field first: a prefilled/autofilled value must not be
	// appended to. The typed value is dropped after each
	// step.
	for _, step := range contract.Steps {
		if step.Action == "click" {
			if berr := snapshotMatch(tctx, contract); berr != nil {
				var blocker *ReloginBlocker
				if errors.As(berr, &blocker) {
					return fail(blocker, nil)
				}
				return fail(nil, berr)
			}
		}
		var actErr error
		switch step.Action {
		case "fill":
			var value string
			switch step.Field {
			case "username":
				value = cred.Username
			case "password":
				value = cred.Password
			default:
				return fail(&ReloginBlocker{Kind: NoticeBlocked, Detail: "contract_unknown_field"}, nil)
			}
			actErr = chromedp.Do(tctx, chromedp.Clear(step.Selector), chromedp.SendKeys(step.Selector, value))
			value = ""
		case "click":
			_, actErr = chromedp.Run(tctx, chromedp.Click(step.Selector))
		default:
			return fail(&ReloginBlocker{Kind: NoticeBlocked, Detail: "contract_unknown_action"}, nil)
		}
		if actErr != nil {
			return fail(nil, actErr)
		}
	}
	// After submit: poll for blockers, then for the
	// harvested session. A blocker here (captcha after
	// submit, checkpoint) stops immediately. A failed
	// harvest removes the launch-created profile dir, like
	// any other failed attempt.
	cookies, blocker, terr := d.waitForCookies(tctx, contract, d.opts.Entry.EffectiveReloginCookieTimeout(), d.opts.Entry.EffectiveReloginPollInterval())
	if blocker != nil || terr != nil {
		return fail(blocker, terr)
	}
	return cookies, nil, nil
}

// waitForMatch polls the boolean snapshot until the page
// matches the contract, a blocker signal appears, or the
// deadline passes (mismatch blocker). Only a named blocker
// signal stops immediately: a contract_mismatch on an early
// poll means "the form is not there YET" (slow/async render)
// as much as "the form is not the recorded one", so it polls
// to the deadline like any other transient state. A snapshot
// evaluation failure is transient for the same reason: the
// page may still be loading.
func (d *chromedpReloginDriver) waitForMatch(ctx context.Context, contract LoginContract, timeout, poll time.Duration) error {
	deadline := time.Now().Add(timeout)
	var lastErr error
	var lastMismatch *ReloginBlocker
	for {
		if err := snapshotMatch(ctx, contract); err == nil {
			return nil
		} else {
			var blocker *ReloginBlocker
			if errors.As(err, &blocker) {
				if isBlockerSignal(blocker) {
					return blocker
				}
				lastMismatch = blocker
			} else {
				lastErr = err
			}
		}
		if time.Now().After(deadline) {
			if lastErr != nil {
				return lastErr
			}
			if lastMismatch != nil {
				return lastMismatch
			}
			return &ReloginBlocker{Kind: NoticeBlocked, Detail: "contract_mismatch"}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(poll):
		}
	}
}

// waitForCookies polls the browser-level cookie read until
// a hatch_sess cookie is harvested, a blocker appears, or
// the deadline passes (transient: the login may have
// failed server-side, which a retry can still recover).
func (d *chromedpReloginDriver) waitForCookies(ctx context.Context, contract LoginContract, timeout, poll time.Duration) ([]ExportedCookie, *ReloginBlocker, error) {
	deadline := time.Now().Add(timeout)
	for {
		// Blockers first: a captcha/2FA page after submit
		// must stop the attempt, not spin until timeout.
		if err := snapshotMatch(ctx, contract); err != nil {
			var blocker *ReloginBlocker
			if errors.As(err, &blocker) {
				// A contract_mismatch AFTER submit is
				// not a blocker: the page navigated
				// away from the form (likely a
				// successful login). Only a named
				// blocker signal stops here; a mismatch
				// falls through to the cookie check.
				// (Same distinction as waitForMatch.)
				if isBlockerSignal(blocker) {
					return nil, blocker, nil
				}
			}
		}
		cookies, err := d.harvest(ctx)
		if err == nil && hasHatchSess(cookies) {
			return cookies, nil, nil
		}
		if time.Now().After(deadline) {
			return nil, nil, errors.New("re-login: no session cookie harvested after submit")
		}
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		case <-time.After(poll):
		}
	}
}

// harvest reads all browser cookies through the
// browser-level Storage.getCookies call.
func (d *chromedpReloginDriver) harvest(ctx context.Context) ([]ExportedCookie, error) {
	res, err := chromedp.CallBrowser(ctx, storage.GetCookies, storage.GetCookiesParams{})
	if err != nil {
		return nil, err
	}
	return fromNetworkCookies(res.Cookies), nil
}

// hasHatchSess reports whether the harvest holds a
// non-empty hatch_sess cookie.
func hasHatchSess(cookies []ExportedCookie) bool {
	for _, c := range cookies {
		if c.Name == "hatch_sess" && c.Value != "" {
			return true
		}
	}
	return false
}

// ObserveLoginPage loads the login page headless and
// returns its redacted form-control inventory. It attaches
// to a running browser only when the caller supplies a
// browser URL; the `auth observe-login` command never does,
// so observation through the command always launches
// (launch-only in practice). No credential is entered,
// nothing is submitted, and the tab is closed on return.
// The inventory script returns structure only: tag, type,
// name, id, classes, aria-label presence — never values,
// text, or hrefs. The returned URL is the final URL with
// query, fragment, and userinfo stripped. A failed
// observation removes the browser profile dir the launch
// created; a successful one keeps it (see browserContext).
// The settle wait, poll cadence, and inventory cap come
// from the entry (documented defaults when absent).
func ObserveLoginPage(ctx context.Context, opts ObserveOptions) (LoginPageObservation, error) {
	if opts.LoginURL == "" {
		return LoginPageObservation{}, errors.New("observe: no login URL")
	}
	if opts.Profile == nil {
		return LoginPageObservation{}, errors.New("observe: no profile")
	}
	driver := &chromedpReloginDriver{opts: ReloginOptions{BrowserURL: opts.BrowserURL, BaseDir: opts.BaseDir, Inbound: opts.Inbound, Profile: opts.Profile, Entry: opts.Entry}}
	tctx, cancel, removeDir, err := driver.browserContext(ctx)
	if err != nil {
		return LoginPageObservation{}, err
	}
	defer cancel()
	fail := func(err error) (LoginPageObservation, error) {
		cancel()
		removeDir()
		return LoginPageObservation{}, err
	}
	if _, err := chromedp.Run(tctx, chromedp.Navigate(opts.LoginURL)); err != nil {
		return fail(err)
	}
	// Let the page settle: poll until at least one form
	// control exists or the entry's settle timeout passes
	// (a page with no form at all still returns its —
	// empty — inventory).
	deadline := time.Now().Add(opts.Entry.EffectiveObserveSettleTimeout())
	poll := opts.Entry.EffectiveReloginPollInterval()
	var obs LoginPageObservation
	for {
		res, err := chromedp.Run(tctx, chromedp.Evaluate[LoginPageObservation](inventoryScript(opts.Entry.EffectiveObserveInventoryCap())))
		if err == nil {
			obs = res
			if len(obs.Elements) > 0 || time.Now().After(deadline) {
				obs.URL = StripObservationURL(obs.URL)
				return obs, nil
			}
		} else if time.Now().After(deadline) {
			return fail(err)
		}
		select {
		case <-ctx.Done():
			return fail(ctx.Err())
		case <-time.After(poll):
		}
	}
}

// inventoryScript is the FIXED evaluation script, with the
// entry's inventory cap interpolated as a decimal: the cap
// is an int validated at parse time, so formatting it with
// %d cannot inject script. The script returns structure
// only, capped at that many elements.
func inventoryScript(cap int) string {
	return `(function(){
	var out = [];
	var els = document.querySelectorAll("input, button, select, textarea, form");
	for (var i = 0; i < els.length && out.length < ` + strconv.Itoa(cap) + `; i++) {
		var el = els[i];
		var cls = (el.getAttribute("class") || "").split(/\s+/).filter(function(s){ return s !== ""; });
		out.push({tag: el.tagName.toLowerCase(), type: el.getAttribute("type") || "", name: el.getAttribute("name") || "", id: el.getAttribute("id") || "", classes: cls, has_aria_label: !!el.getAttribute("aria-label")});
	}
	return {url: location.href, elements: out};
})()`
}
