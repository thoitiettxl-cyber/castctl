// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

//go:build with_chromedp

package keeper

import (
	"context"
	"os"
	"path/filepath"

	"github.com/chromedp/cdproto/browser"
	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"

	"github.com/thoitiettxl-cyber/castctl/internal/profile"
)

// Launch fallback (with_chromedp only): a castctl-owned Chrome
// for screencast login when no attachable browser exists.
//
// FAIL-CLOSED VERDICT (verified at base 6d3baac): the
// minimal-router plumbing the design's S2 gate requires does
// not exist in this tree — internal/outbound/router_stub.go
// returns errNoRouter and no mixed-inbound construction
// exists in production code. A castctl-launched browser
// therefore CANNOT be routed through the profile outbound
// today, and launching one with direct egress would violate
// the per-profile routing invariant. So the launch path
// refuses BEFORE spawning anything unless an InboundBuilder
// is supplied (none exists at this base; the command layer
// passes nil). The code below (flag list, persistent dir,
// detection order) exists behind that check so the S2 work
// plugs in without restructuring; live launch correctness
// remains an S2 gate and is NOT claimed here.

type launchRunner struct {
	baseDir     string
	prof        *profile.Profile
	browserPath string
	inbound     InboundBuilder
}

// NewLaunchRunner returns a ScreencastRunner that launches a
// castctl-owned Chrome. browserPath is the explicit --browser-path
// value ("" means the detection order in resolveBrowserPath).
// A nil inbound fails every Run closed before spawning.
func NewLaunchRunner(baseDir string, prof *profile.Profile, browserPath string, inbound InboundBuilder) ScreencastRunner {
	return launchRunner{baseDir: baseDir, prof: prof, browserPath: browserPath, inbound: inbound}
}

// ChromiumPathEnv is the environment override for the browser
// executable, after --browser-path, before PATH search.
const ChromiumPathEnv = "CASTCTL_CHROMIUM_PATH"

// resolveBrowserPath implements the detection order:
// --browser-path > CASTCTL_CHROMIUM_PATH > chromedp's PATH
// search ("" lets chromedp find it). No download, no install.
func resolveBrowserPath(flagPath string) string {
	if flagPath != "" {
		return flagPath
	}
	if env := os.Getenv(ChromiumPathEnv); env != "" {
		return env
	}
	return ""
}

// browserProfileDir is the persistent per-profile user-data
// dir (0700, never auto-deleted): the launched browser's
// state survives across logins, like a real profile. For the
// default profile it sits in the base dir; named profiles
// under profiles/<name>/.
func browserProfileDir(baseDir string, prof *profile.Profile) (string, error) {
	paths, err := profile.ProfilePaths(baseDir, prof.Name)
	if err != nil {
		return "", err
	}
	return filepath.Join(paths.Dir, "chromium-profile"), nil
}

func (r launchRunner) Run(ctx context.Context, transport Transport) RunnerResult {
	// Fail closed BEFORE spawning: no inbound, no browser.
	if r.inbound == nil {
		return RunnerResult{Outcome: LoginFailed, Err: ErrLaunchUnavailable}
	}
	proxyURL, cleanup, err := r.inbound.BuildInbound(ctx, r.prof)
	if err != nil {
		return RunnerResult{Outcome: LoginFailed, Err: err}
	}
	defer cleanup()
	dir, err := browserProfileDir(r.baseDir, r.prof)
	if err != nil {
		return RunnerResult{Outcome: LoginFailed, Err: err}
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return RunnerResult{Outcome: LoginFailed, Err: err}
	}
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.VisibleWindow,
		// Undo the automation markers: a login browser must
		// look like a browser, not a bot.
		chromedp.Flag("enable-automation", false),
		chromedp.Flag("disable-blink-features", "AutomationControlled"),
		// Ephemeral debug port: chromedp discovers it from
		// the DevToolsActivePort file in the user-data dir.
		chromedp.Flag("remote-debugging-port", "0"),
		chromedp.UserDataDir(dir),
		// The ONLY egress: the profile-routed inbound.
		chromedp.ProxyServer(proxyURL),
	)
	if path := resolveBrowserPath(r.browserPath); path != "" {
		opts = append(opts, chromedp.ExecPath(path))
	}
	allocCtx, cancelAlloc := chromedp.NewExecAllocator(ctx, opts...)
	defer cancelAlloc()
	// The launch runner owns its browser: cancelling the
	// allocator kills the process it started (cleanup order:
	// kill everything started, leave the per-profile dir).
	tctx, cancelTarget := chromedp.NewContext(allocCtx)
	defer cancelTarget()
	version, err := browserVersionFromContext(tctx)
	if err != nil {
		return RunnerResult{Outcome: LoginFailed, Err: err}
	}
	// Own browser, own tab: navigating to the login page is
	// the point of the launch model (never done on attach).
	if _, err := chromedp.Call(tctx, page.Navigate, page.NavigateParams{URL: "https://muse.ai/"}); err != nil {
		return RunnerResult{Outcome: LoginFailed, Version: version, Err: err}
	}
	return serveScreencast(tctx, transport, version)
}

// browserVersionFromContext reads Browser.getVersion on an
// already-allocated context (launch model: the allocator
// context is the browser).
func browserVersionFromContext(tctx context.Context) (BrowserVersion, error) {
	res, err := chromedp.CallBrowser(tctx, browser.GetVersion, cdp.Empty{})
	if err != nil {
		return BrowserVersion{}, err
	}
	return BrowserVersion{Product: res.Product, UserAgent: res.UserAgent}, nil
}
