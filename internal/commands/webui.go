// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package commands

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/thoitiettxl-cyber/castctl/internal/keeper"
	"github.com/thoitiettxl-cyber/castctl/internal/profile"
	"github.com/thoitiettxl-cyber/castctl/internal/webui"
	webuiassets "github.com/thoitiettxl-cyber/castctl/webui"
)

// `castctl webui serve`: the web UI server (phase 2 item 2).
//
// The server is loopback-only and token-authed, configured by
// the optional top-level `webui` block in config.json (see
// docs/config.md). An absent block fails closed (exit 2): the
// server never starts without explicit configuration. The
// effective token is CASTCTL_WEBUI_KEY when set, else the
// block's `token`; with neither set the command fails closed
// and never starts unauthenticated. The token is never printed,
// logged, or echoed: the startup line names the listen address
// only. `--profile` is ignored by this command (the server
// serves the whole single file); `--config` selects the config
// location as usual.
//
// Exit codes: 2 usage/config (absent block, non-loopback
// listen, missing token, bad flags), 1 server runtime failure,
// 130 on interrupt (via the cancelled-context contract).

const webuiHelpText = `usage: castctl webui <subcommand> [options]

Web UI server: serve the castctl web UI (frontend + /api/v1)
on loopback only, with token auth. Requires a "webui" block in
config.json (see docs/config.md); absent means no web UI.

subcommands:
  serve     serve the web UI in the foreground until interrupted

Run "castctl webui serve --help" for serve options.
`

const webuiServeHelpText = `usage: castctl webui serve [--listen ADDR] [--port N]

Serve the web UI in the foreground until interrupted (Ctrl-C,
exit 130). Listens on 127.0.0.1 only, with token auth.

The "webui" block in config.json configures the listen address
(default 127.0.0.1:8317) and the token. The effective token is
CASTCTL_WEBUI_KEY when set, else the block's "token". With
neither set, the server does not start. The token is never
printed or logged.

  --listen ADDR   override the block's listen address
                  (loopback only; a warning names the address)
  --port N        override the port, keeping the block's host
                  (or 127.0.0.1 when the block has no listen key)

--listen and --port together are an error. --profile is ignored:
the server serves the whole single file.
`

func init() {
	registerCommand(&commandSpec{
		name:     "webui",
		help:     "serve the castctl web UI on loopback only, with token auth",
		helpText: webuiHelpText,
		handler:  cmdWebUI,
	})
	registerFlags("webui", "webui <subcommand> [options]", nil)
}

func cmdWebUI(ctx context.Context, env *Env, g *globalOpts, args []string) error {
	if len(args) == 0 {
		fmt.Fprintln(env.stderr(), "castctl: the following arguments are required: subcommand")
		fmt.Fprint(env.stderr(), webuiHelpText)
		return errCode(2, nil)
	}
	if args[0] == "--help" || args[0] == "-h" {
		fmt.Fprint(env.stdout(), webuiHelpText)
		return errHelpShown
	}
	switch args[0] {
	case "serve":
		return cmdWebUIServe(ctx, env, g, args[1:])
	default:
		fmt.Fprintf(env.stderr(), "castctl: argument subcommand: invalid choice: %q (choose from serve)\n", args[0])
		fmt.Fprint(env.stderr(), webuiHelpText)
		return errCode(2, nil)
	}
}

func cmdWebUIServe(ctx context.Context, env *Env, g *globalOpts, args []string) error {
	ap := &argParser{
		defs: []flagDef{
			{name: "listen", kind: flagString},
			{name: "port", kind: flagString},
		},
		helpText: webuiServeHelpText,
		prog:     "castctl webui serve",
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
	if err := checkPositionals(p, nil, "webui serve"); err != nil {
		return usageErr(err)
	}
	if p.strIsSet("listen") && p.strIsSet("port") {
		return errCodef(2, "webui serve: --listen and --port together are an error")
	}

	loc, err := resolveConfig(g, env, false)
	if err != nil {
		return err
	}
	single, found, err := profile.LoadSingleConfig(loc.ConfigDir)
	if err != nil {
		return err
	}
	if !found {
		return errCodef(2, "webui serve: no config file: run \"castctl config migrate\" or create a config with a \"webui\" block first")
	}
	webuiCfg, err := profile.ResolveWebUI(single)
	if err != nil {
		return err
	}
	if webuiCfg == nil {
		return errCodef(2, "webui serve: no \"webui\" block in config.json: add one (see docs/config.md) or use the CLI")
	}

	listen, err := resolveWebUIListen(webuiCfg, p)
	if err != nil {
		return err
	}
	if p.strIsSet("listen") {
		// One warning naming the ADDRESS only (never the
		// token), per the prior --listen + warning design.
		fmt.Fprintf(env.stderr(), "castctl: webui: --listen overrides the \"webui\" block: listening on %s\n", listen)
	}

	token := ""
	if v, ok := env.lookupEnv("CASTCTL_WEBUI_KEY"); ok && strings.TrimSpace(v) != "" {
		// A whitespace-only env value counts as unset: it
		// could never authenticate (the token is compared
		// exactly), so treating it as set would strand the
		// operator with an unusable server. The token
		// itself is used verbatim, never trimmed.
		token = v
	} else {
		token = webuiCfg.Token
	}
	if token == "" {
		return errCodef(2, "webui serve: no token: set CASTCTL_WEBUI_KEY or a \"token\" in the \"webui\" block")
	}
	tokenHash := sha256.Sum256([]byte(token))

	// Resolve the on-disk frontend root, if configured. A
	// present-but-broken ui_dir fails closed (exit 2) here,
	// before the server starts; only an absent key falls back
	// to the embedded frontend. The cookies-exposure rule is
	// enforced inside webui.New via Deps.CookiesFiles, so it
	// cannot be skipped by a future direct Server
	// construction.
	uiDir, err := resolveWebUIUIDir(webuiCfg, loc.ConfigDir)
	if err != nil {
		return err
	}
	var cookiesFiles []string
	for _, p := range single.Profiles {
		if p != nil && p.CookiesFile != "" {
			cookiesFiles = append(cookiesFiles, p.CookiesFile)
		}
	}
	bundleHash := webuiassets.BundleSHA256()
	if uiDir != "" {
		// The status bundle hash is the on-disk shell's hash
		// while ui_dir is active; the embedded hash is used
		// only in fallback mode.
		data, err := os.ReadFile(filepath.Join(uiDir, "index.html"))
		if err != nil {
			return errCodef(2, "webui serve: ui_dir has no readable index.html")
		}
		sum := sha256.Sum256(data)
		bundleHash = hex.EncodeToString(sum[:])
	}

	srv, err := webui.New(webui.Deps{
		ConfigDir:           loc.ConfigDir,
		Version:             versionString(),
		ListenAddr:          listen,
		TokenHash:           tokenHash,
		HasToken:            true,
		DistFS:              webuiassets.FS(),
		BundleSHA256:        bundleHash,
		UIDir:               uiDir,
		CookiesFiles:        cookiesFiles,
		ImportCookies:       webuiImportCookies(loc, env),
		RestoreCookies:      webuiRestoreCookies(loc, env),
		ScreencastAvailable: webuiScreencastAvailable(loc),
		ScreencastStarter:   webuiScreencastStarter(loc, env),
	})
	if err != nil {
		var uidErr *webui.UIDirError
		if errors.As(err, &uidErr) {
			return errCodef(2, "webui serve: %v", uidErr)
		}
		return errCodef(1, "webui serve: %v", err)
	}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return errCodef(1, "webui serve: listen %s: %v", listen, err)
	}
	fmt.Fprintf(env.stderr(), "castctl: web UI listening on %s (loopback only, token auth)\n", listen)
	httpSrv := &http.Server{
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- httpSrv.Serve(ln)
	}()
	select {
	case err := <-serveErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return errCodef(1, "webui serve: %v", err)
		}
		return nil
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutdownCtx)
		// Interrupted: the main contract maps the cancelled
		// context to exit 130.
		return ctx.Err()
	}
}

// resolveWebUIUIDir resolves a configured ui_dir against
// configDir and validates it on disk. It returns "" when no
// ui_dir is configured (embedded fallback). A present-but-broken
// value — missing, not a directory, no regular index.html, a
// symlinked index.html, or overlapping the config directory —
// fails closed (exit 2) with a fixed rule-only message: the
// value is never echoed, and a broken directory must never
// silently fall back to the embedded frontend (that would hide
// a misconfiguration behind a stale UI). The root is
// canonicalised (EvalSymlinks) so a symlink into the config
// tree is caught here, before serving.
func resolveWebUIUIDir(cfg *profile.WebUIConfig, configDir string) (string, error) {
	if cfg == nil || strings.TrimSpace(cfg.UIDir) == "" {
		return "", nil
	}
	resolved := strings.TrimSpace(cfg.UIDir)
	if !filepath.IsAbs(resolved) {
		resolved = filepath.Join(configDir, resolved)
	}
	resolved = filepath.Clean(resolved)
	canonical, err := filepath.EvalSymlinks(resolved)
	if err != nil {
		return "", errCodef(2, "webui serve: ui_dir is not a readable directory")
	}
	resolved = canonical
	st, err := os.Stat(resolved)
	if err != nil || !st.IsDir() {
		return "", errCodef(2, "webui serve: ui_dir is not a readable directory")
	}
	canonicalConfig, err := filepath.EvalSymlinks(configDir)
	if err != nil {
		canonicalConfig = filepath.Clean(configDir)
	}
	if profile.DirOverlaps(canonicalConfig, resolved) {
		return "", errCodef(2, "webui serve: ui_dir must not overlap the config directory")
	}
	index, err := os.Lstat(filepath.Join(resolved, "index.html"))
	if err != nil || index.Mode()&os.ModeSymlink != 0 || !index.Mode().IsRegular() {
		return "", errCodef(2, "webui serve: ui_dir has no readable index.html")
	}
	return resolved, nil
}

// resolveWebUIListen computes the effective listen address:
// the block's listen (or the default), with --listen replacing
// it wholesale or --port replacing only the port. Every result
// is re-validated loopback-only: an override can never widen
// the bind.
func resolveWebUIListen(cfg *profile.WebUIConfig, p *parsed) (string, error) {
	base := profile.EffectiveListen(cfg)
	if p.strIsSet("listen") {
		addr := strings.TrimSpace(p.str("listen"))
		if err := profile.ValidateWebUIListen(addr); err != nil {
			return "", errCodef(2, "webui serve: invalid --listen: %v", err)
		}
		return addr, nil
	}
	if p.strIsSet("port") {
		portStr := strings.TrimSpace(p.str("port"))
		port, err := strconv.Atoi(portStr)
		if err != nil || port < 1 || port > 65535 {
			return "", errCodef(2, "webui serve: invalid --port %q (expected 1-65535)", portStr)
		}
		host, _, err := net.SplitHostPort(base)
		if err != nil {
			return "", errCodef(2, "webui serve: invalid listen address in config")
		}
		addr := net.JoinHostPort(host, strconv.Itoa(port))
		if err := profile.ValidateWebUIListen(addr); err != nil {
			return "", errCodef(2, "webui serve: invalid --port: %v", err)
		}
		return addr, nil
	}
	return base, nil
}

// webuiImportCookies is the cookie-import seam: the exact
// `auth import` boundary (normalise + validate + locked write
// + keeper reset), with the content supplied by the API
// instead of stdin. Cookie values stay in-process: only fixed
// validation messages leave this function.
func webuiImportCookies(loc *profile.ConfigLocation, env *Env) func(ctx context.Context, profileName, content string) (bool, error) {
	return func(ctx context.Context, profileName, content string) (bool, error) {
		stored, err := normaliseImportInput([]byte(content))
		if err != nil {
			return false, err
		}
		if err := validateImportInput(stored); err != nil {
			return false, err
		}
		single, found, err := profile.LoadSingleConfig(loc.ConfigDir)
		if err != nil {
			return false, err
		}
		if !found || single.Profiles[profileName] == nil {
			return false, fmt.Errorf("profile %q does not exist", profileName)
		}
		prof, err := profile.LoadProfile(loc.ConfigDir, profileName, env.lookupEnv)
		if err != nil {
			return false, err
		}
		backup, err := profile.WriteCookiesFileLocked(loc.ConfigDir, prof.Name, prof.CookiesFile, []byte(stored+"\n"), keeper.DefaultLockTimeout)
		if err != nil {
			return false, fmt.Errorf("write cookies file: %v", err)
		}
		if err := keeper.ResetAfterLogin(loc.ConfigDir, prof, keeper.RealClock); err != nil {
			return false, fmt.Errorf("cookies written but keeper state reset failed: %v", err)
		}
		return backup, nil
	}
}

// webuiRestoreCookies restores a profile's .bak cookies file
// through the locked writer path (the current file is backed
// up first, so the restore is reversible). A missing .bak is
// webui.ErrNoBackup, mapped to 404 by the handler.
func webuiRestoreCookies(loc *profile.ConfigLocation, env *Env) func(ctx context.Context, profileName string) (bool, error) {
	return func(ctx context.Context, profileName string) (bool, error) {
		single, found, err := profile.LoadSingleConfig(loc.ConfigDir)
		if err != nil {
			return false, err
		}
		if !found || single.Profiles[profileName] == nil {
			return false, fmt.Errorf("profile %q does not exist", profileName)
		}
		prof, err := profile.LoadProfile(loc.ConfigDir, profileName, env.lookupEnv)
		if err != nil {
			return false, err
		}
		bakPath := prof.CookiesFile + ".bak"
		// Stat only for existence: the bytes are read by the
		// writer path itself and never leave the process
		// except into the cookies file.
		if _, err := os.Stat(bakPath); err != nil {
			if os.IsNotExist(err) {
				return false, webui.ErrNoBackup
			}
			return false, err
		}
		data, err := os.ReadFile(bakPath)
		if err != nil {
			return false, err
		}
		if _, err := profile.WriteCookiesFileLocked(loc.ConfigDir, prof.Name, prof.CookiesFile, data, keeper.DefaultLockTimeout); err != nil {
			return false, fmt.Errorf("write cookies file: %v", err)
		}
		if err := keeper.ResetAfterLogin(loc.ConfigDir, prof, keeper.RealClock); err != nil {
			return false, fmt.Errorf("cookies written but keeper state reset failed: %v", err)
		}
		return true, nil
	}
}

// webuiScreencastAvailable reports whether a screencast session
// can start: chromedp in the build AND a keeper entry naming
// the profile with a browser URL. Attach-only: the web UI never
// launches its own browser.
func webuiScreencastAvailable(loc *profile.ConfigLocation) webui.ScreencastAvailability {
	return func(ctx context.Context, profileName string) (bool, string, error) {
		if !keeper.CDPAvailable() {
			return false, "screencast unavailable in this build (rebuild with -tags with_chromedp)", nil
		}
		single, found, err := profile.LoadSingleConfig(loc.ConfigDir)
		if err != nil {
			return false, "", err
		}
		if !found {
			return false, "no config file", nil
		}
		kcfg, err := profile.ResolveKeeper(single)
		if err != nil {
			return false, "", err
		}
		if kcfg == nil {
			return false, fmt.Sprintf("no keeper entry for profile %q: add a \"keeper\" entry with a browser URL (see docs/config.md)", profileName), nil
		}
		if entry := kcfg.KeeperEntryForProfile(profileName); entry != nil && entry.Browser != "" {
			return true, "", nil
		}
		return false, fmt.Sprintf("no keeper entry for profile %q: add a \"keeper\" entry with a browser URL (see docs/config.md)", profileName), nil
	}
}

// webuiScreencastStarter runs one LoginSession over the relay
// transport, attach-only, with the checker built from the
// profile runtime (the same wiring as `auth login`). The
// session ID is left empty so LoginSession generates its own:
// the single-use WebSocket token must never land in the audit
// file. No launch fallback: without an attachable browser the
// session fails loudly instead of launching a browser the
// operator did not ask for.
func webuiScreencastStarter(loc *profile.ConfigLocation, env *Env) webui.ScreencastStarter {
	return func(ctx context.Context, profileName, sessionID string, transport keeper.Transport) (keeper.LoginResult, error) {
		prof, err := profile.LoadProfile(loc.ConfigDir, profileName, env.lookupEnv)
		if err != nil {
			return keeper.LoginResult{Outcome: keeper.LoginFailed}, err
		}
		single, found, err := profile.LoadSingleConfig(loc.ConfigDir)
		if err != nil {
			return keeper.LoginResult{Outcome: keeper.LoginFailed}, err
		}
		var runner keeper.ScreencastRunner
		if found {
			if kcfg, kerr := profile.ResolveKeeper(single); kerr == nil && kcfg != nil {
				if entry := kcfg.KeeperEntryForProfile(prof.Name); entry != nil && entry.Browser != "" {
					runner = keeper.NewAttachRunner(entry.Browser)
				}
			} else if kerr != nil {
				return keeper.LoginResult{Outcome: keeper.LoginFailed}, kerr
			}
		}
		if runner == nil {
			return keeper.LoginResult{Outcome: keeper.LoginFailed}, fmt.Errorf("no keeper entry for profile %q: add a \"keeper\" entry with a browser URL (see docs/config.md)", profileName)
		}
		rt, err := env.buildRuntime(ctx, loc, prof)
		if err != nil {
			return keeper.LoginResult{Outcome: keeper.LoginFailed}, err
		}
		defer func() { _ = rt.Close() }()
		session := &keeper.LoginSession{
			BaseDir:      loc.ConfigDir,
			Profile:      prof,
			Timeout:      keeper.DefaultLoginTimeout,
			Transport:    transport,
			Checker:      &keeper.GatewayChecker{Client: rt.HTTPClient()},
			Runner:       runner,
			PollInterval: keeper.LoginPollInterval,
		}
		return session.Run(ctx), nil
	}
}
