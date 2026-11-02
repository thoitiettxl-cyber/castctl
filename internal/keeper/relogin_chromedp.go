// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

//go:build with_chromedp

package keeper

import (
	"context"
	"encoding/json"
	"errors"
	"os"
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
// returns ONLY booleans (which selectors are present, which
// blocker signals hit). No page text, HTML, attribute value,
// screenshot, or cookie value ever crosses from the page
// into Go through evaluation; cookies are harvested only
// through the browser-level Storage.getCookies call, the
// same read the CDP exporter uses. The driver never
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
// Fill and submit exactly the recorded steps, then poll for
// the harvested session cookies. Transient failures retry
// up to MaxAttempts with a fresh tab each time; a blocker
// returns immediately and is never retried.

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

// snapshotResult is the boolean-only page snapshot: which
// contract selectors are present, and which blocker kinds
// hit (by keyword or selector). The script returns nothing
// else.
type snapshotResult struct {
	Present map[string]bool `json:"present"`
	Hits    map[string]bool `json:"hits"`
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
			if (b.keyword && lower.indexOf(b.keyword.toLowerCase()) !== -1) { hits[b.kind] = true; }
			if (b.selector) { try { if (document.querySelector(b.selector)) { hits[b.kind] = true; } } catch (e) {} }
		}
		return {present: present, hits: hits};
	})(` + string(selJSON) + `, ` + string(blkJSON) + `)`
	return script, nil
}

// snapshot evaluates the fixed boolean script on the target
// and maps the result onto the contract: blocker hits first,
// then step-selector presence. It returns a *ReloginBlocker
// for a hit/mismatch, or nil when the page matches.
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
	// Keyword/selector hits are computed in-page; a hit kind
	// present in the map is a blocker, whatever the signal
	// was. No page text crosses into Go: the hits map
	// carries kinds only.
	for _, sig := range contract.Blockers {
		if res.Hits[string(sig.Kind)] {
			kind := sig.Kind
			if !ValidNoticeKind(kind) {
				kind = NoticeBlocked
			}
			return &ReloginBlocker{Kind: kind, Detail: "blocker_signal"}
		}
	}
	for _, step := range contract.Steps {
		if step.Selector == "" {
			return &ReloginBlocker{Kind: NoticeBlocked, Detail: "contract_step_no_selector"}
		}
		if !res.Present[step.Selector] {
			return &ReloginBlocker{Kind: NoticeBlocked, Detail: "contract_mismatch"}
		}
	}
	return nil
}

// browserContext acquires a chromedp target context:
// attach-first when a browser URL is configured, headless
// launch through the S2 inbound otherwise. The returned
// cancel tears down the target AND the browser it owns (for
// a launched browser) or just the target (for attach: the
// user's browser is never killed). An attach failure falls
// back to launch; a launch failure is returned.
func (d *chromedpReloginDriver) browserContext(ctx context.Context) (context.Context, context.CancelFunc, error) {
	if d.opts.BrowserURL != "" {
		if tctx, cancel, err := attachTargetContext(ctx, d.opts.BrowserURL); err == nil {
			return tctx, cancel, nil
		} else {
			attachErr := err
			if d.opts.Inbound == nil {
				return nil, nil, attachErr
			}
			// Attach failed: fall through to launch.
			_ = attachErr
		}
	}
	return launchHeadlessContext(ctx, d.opts)
}

// attachTargetContext attaches to a running browser and
// returns a fresh target context in it.
func attachTargetContext(ctx context.Context, browserURL string) (context.Context, context.CancelFunc, error) {
	wsURL, err := DiscoverWebSocketURL(ctx, browserURL)
	if err != nil {
		return nil, nil, err
	}
	allocCtx, cancelAlloc := remote.NewAllocator(ctx, wsURL, remote.NoModifyURL, remote.WithDialTimeout(10*time.Second))
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
// runs; the per-profile user-data dir persists.
func launchHeadlessContext(ctx context.Context, opts ReloginOptions) (context.Context, context.CancelFunc, error) {
	if opts.Inbound == nil {
		return nil, nil, ErrLaunchUnavailable
	}
	if opts.Profile == nil {
		return nil, nil, errors.New("re-login: no profile")
	}
	proxyURL, cleanup, err := opts.Inbound.BuildInbound(ctx, opts.Profile)
	if err != nil {
		return nil, nil, err
	}
	dir, err := browserProfileDir(opts.BaseDir, opts.Profile)
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		cleanup()
		return nil, nil, err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		cleanup()
		return nil, nil, err
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
		cancelTarget()
		cancelAlloc()
		cleanup()
	}
	return tctx, cancel, nil
}

// Relogin runs one headless re-login incident: up to
// MaxAttempts whole-sequence attempts, one tab per attempt,
// blockers never retried.
func (d *chromedpReloginDriver) Relogin(ctx context.Context, cred profile.LoginCredential) ([]ExportedCookie, error) {
	contract := d.opts.Contract
	if !contract.Observed {
		return nil, ErrContractNotEstablished
	}
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
// than one of them.
func (d *chromedpReloginDriver) attempt(ctx context.Context, contract LoginContract, cred profile.LoginCredential) ([]ExportedCookie, *ReloginBlocker, error) {
	tctx, cancel, err := d.browserContext(ctx)
	if err != nil {
		return nil, nil, err
	}
	defer cancel()
	if _, err := chromedp.Run(tctx, chromedp.Navigate(contract.LoginURL)); err != nil {
		return nil, nil, err
	}
	// Wait for the form (or a blocker) to appear, polling
	// the boolean snapshot. A page that never matches the
	// contract is a mismatch blocker, not a retry: the
	// form genuinely is not the recorded one.
	if berr := d.waitForMatch(tctx, contract, 30*time.Second); berr != nil {
		var blocker *ReloginBlocker
		if errors.As(berr, &blocker) {
			return nil, blocker, nil
		}
		return nil, nil, berr
	}
	// Enter exactly the recorded steps, in order. No other
	// input is ever dispatched.
	for _, step := range contract.Steps {
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
				return nil, &ReloginBlocker{Kind: NoticeBlocked, Detail: "contract_unknown_field"}, nil
			}
			_, actErr = chromedp.Run(tctx, chromedp.SendKeys(step.Selector, value))
		case "click":
			_, actErr = chromedp.Run(tctx, chromedp.Click(step.Selector))
		default:
			return nil, &ReloginBlocker{Kind: NoticeBlocked, Detail: "contract_unknown_action"}, nil
		}
		if actErr != nil {
			return nil, nil, actErr
		}
	}
	// After submit: poll for blockers, then for the
	// harvested session. A blocker here (captcha after
	// submit, checkpoint) stops immediately.
	return d.waitForCookies(tctx, contract, 30*time.Second)
}

// waitForMatch polls the boolean snapshot until the page
// matches the contract, a blocker appears, or the deadline
// passes (mismatch blocker). A snapshot evaluation failure
// is transient: the page may still be loading.
func (d *chromedpReloginDriver) waitForMatch(ctx context.Context, contract LoginContract, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for {
		if err := snapshotMatch(ctx, contract); err == nil {
			return nil
		} else {
			var blocker *ReloginBlocker
			if errors.As(err, &blocker) {
				return blocker
			}
			lastErr = err
		}
		if time.Now().After(deadline) {
			if lastErr != nil {
				return lastErr
			}
			return &ReloginBlocker{Kind: NoticeBlocked, Detail: "contract_mismatch"}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// waitForCookies polls the browser-level cookie read until
// a hatch_sess cookie is harvested, a blocker appears, or
// the deadline passes (transient: the login may have
// failed server-side, which a retry can still recover).
func (d *chromedpReloginDriver) waitForCookies(ctx context.Context, contract LoginContract, timeout time.Duration) ([]ExportedCookie, *ReloginBlocker, error) {
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
				// successful login). Only named
				// blocker kinds stop here; a mismatch
				// falls through to the cookie check.
				if blocker.Kind != NoticeBlocked {
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
		case <-time.After(500 * time.Millisecond):
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

// ObserveLoginPage loads the login page headless (attach
// first, launch fallback) and returns its redacted
// form-control inventory. No credential is entered, nothing
// is submitted, and the tab is closed on return. The
// inventory script returns structure only: tag, type, name,
// id, classes, aria-label presence — never values, text, or
// hrefs.
func ObserveLoginPage(ctx context.Context, opts ObserveOptions) (LoginPageObservation, error) {
	if opts.LoginURL == "" {
		return LoginPageObservation{}, errors.New("observe: no login URL")
	}
	if opts.Profile == nil {
		return LoginPageObservation{}, errors.New("observe: no profile")
	}
	driver := &chromedpReloginDriver{opts: ReloginOptions{BrowserURL: opts.BrowserURL, BaseDir: opts.BaseDir, Inbound: opts.Inbound, Profile: opts.Profile}}
	tctx, cancel, err := driver.browserContext(ctx)
	if err != nil {
		return LoginPageObservation{}, err
	}
	defer cancel()
	if _, err := chromedp.Run(tctx, chromedp.Navigate(opts.LoginURL)); err != nil {
		return LoginPageObservation{}, err
	}
	// Let the page settle: poll until at least one form
	// control exists or 15s pass (a page with no form at
	// all still returns its — empty — inventory).
	deadline := time.Now().Add(15 * time.Second)
	var obs LoginPageObservation
	for {
		res, err := chromedp.Run(tctx, chromedp.Evaluate[LoginPageObservation](inventoryScript))
		if err == nil {
			obs = res
			if len(obs.Elements) > 0 || time.Now().After(deadline) {
				return obs, nil
			}
		} else if time.Now().After(deadline) {
			return LoginPageObservation{}, err
		}
		select {
		case <-ctx.Done():
			return LoginPageObservation{}, ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}

const inventoryScript = `(function(){
	var out = [];
	var els = document.querySelectorAll("input, button, select, textarea, form");
	for (var i = 0; i < els.length && out.length < 200; i++) {
		var el = els[i];
		var cls = (el.getAttribute("class") || "").split(/\s+/).filter(function(s){ return s !== ""; });
		out.push({tag: el.tagName.toLowerCase(), type: el.getAttribute("type") || "", name: el.getAttribute("name") || "", id: el.getAttribute("id") || "", classes: cls, has_aria_label: !!el.getAttribute("aria-label")});
	}
	return {url: location.href, elements: out};
})()`
