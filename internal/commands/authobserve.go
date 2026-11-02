// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package commands

import (
	"context"
	"fmt"
	"time"

	"github.com/thoitiettxl-cyber/castctl/internal/keeper"
	"github.com/thoitiettxl-cyber/castctl/internal/profile"
)

// `castctl auth observe-login`: read-only observation of the
// provider login page. It loads the page headless through the
// profile's outbound (S2 inbound plumbing, AGENTS.md rule 2),
// records ONLY the redacted form-control inventory — element
// tag, type, name, id, classes, aria-label presence — and
// prints it as JSON. It never enters or submits a credential,
// never clicks anything, and writes nothing to the profile
// (the throwaway browser dir is removed with the launch).
//
// The output is the evidence for the versioned login contract
// (keeper LoginContract): a human records the selectors/steps
// from it into the contract fixture, redacted. The command
// itself never writes a contract file.
//
// Exit 2 when the build has no headless driver, when no
// runtime/inbound can be built (fail closed), or when the
// page cannot be loaded.

const authObserveLoginHelpText = `usage: castctl auth observe-login [--profile NAME] [--login-url URL]

Observe the provider login page read-only (headless) and print
its redacted form-control inventory as JSON: element tag, type,
name, id, classes, and aria-label presence only. No values, no
page text, no links, no screenshots. Nothing is entered or
submitted; nothing is written to the profile.

  --profile NAME    profile whose outbound routes the page load
                    (default: active profile)
  --login-url URL   page to observe (default: https://auth.muse.ai/login)
`

func cmdAuthObserveLogin(ctx context.Context, env *Env, g *globalOpts, args []string) error {
	ap := &argParser{
		defs: []flagDef{
			{name: "profile", kind: flagString},
			{name: "login-url", kind: flagString},
		},
		helpText: authObserveLoginHelpText,
		prog:     "castctl auth observe-login",
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
	if err := checkPositionals(p, nil, "auth observe-login"); err != nil {
		return usageErr(err)
	}
	if !keeper.ReloginAvailable() {
		return errCodef(2, "auth observe-login is not available in this build: rebuild with -tags with_chromedp")
	}
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
	loginURL := "https://auth.muse.ai/login"
	if p.strIsSet("login-url") {
		loginURL = p.str("login-url")
	}
	rt, err := env.buildRuntime(ctx, loc, prof)
	if err != nil {
		return err
	}
	defer rt.Close()
	inbound := newProfileInboundBuilder(rt)
	if inbound == nil {
		return errCodef(2, "auth observe-login: no outbound for profile %q: refusing to load the page outside the profile's outbound", prof.Name)
	}
	obsCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	obs, err := keeper.ObserveLoginPage(obsCtx, keeper.ObserveOptions{
		BaseDir:  loc.ConfigDir,
		Inbound:  inbound,
		Profile:  prof,
		LoginURL: loginURL,
	})
	if err != nil {
		return err
	}
	out := struct {
		Profile  string                   `json:"profile"`
		LoginURL string                   `json:"login_url"`
		Elements []keeper.ObservedElement `json:"elements"`
		URL      string                   `json:"url"`
	}{Profile: prof.Name, LoginURL: loginURL, Elements: obs.Elements, URL: obs.URL}
	return writeJSON(env.stdout(), out)
}
