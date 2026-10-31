// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package commands

import (
	"context"
	"errors"

	"github.com/thoitiettxl-cyber/castctl/internal/update"
)

// updateHelpText is the `castctl update --help` text. It states the
// verification contract up front: checksums verified before any
// replace, and no signature verification (releases carry no
// signatures; the checksums prove match-to-published-bytes only).
const updateHelpText = `usage: castctl update [--dry-run] [--version TAG] [--allow-downgrade] [--allow-prerelease]

Self-update castctl from the latest stable GitHub release.

The release asset matching this platform and build flavour is
downloaded, its sha256 is verified against the release
checksums.txt BEFORE any replace, the extracted binary is
validated (ELF/arch sanity and a --version run), and only then
the running binary is replaced atomically (same-directory rename,
permission bits preserved, fsync of file and directory). On any
failure the old binary is left intact and partial downloads are
deleted. There is no signature verification: GitHub releases
carry no signatures, so the checksums prove only that the bytes
match what the release published, over HTTPS.

The running build must be stamped (release -X flags): unstamped
dev builds refuse with "cannot determine running version" in
every mode. The build flavour (glibc vs no-plugin) is read from
the build info CGO_ENABLED setting; an unknown flavour refuses.
Linux only: no release assets exist for other platforms.

  --dry-run          Report what would be downloaded, verified
                     and replaced, without writing anything.
  --version TAG      Update to a specific release tag (with or
                     without a leading v). Must name a stable
                     release unless --allow-prerelease is given.
  --allow-downgrade  Allow installing an older version than the
                     running one. Refused by default.
  --allow-prerelease
                     Allow a pre-release target. Refused by
                     default.

Exit codes: 0 success, already-latest no-op, or dry-run report;
2 usage and policy refusals decided without fetching bytes;
1 operational failures (network, checksums, validation, replace).
`

func init() {
	boolFlag := func(name string) flagDef { return flagDef{name: name, kind: flagBool} }
	strFlag := func(name string) flagDef { return flagDef{name: name, kind: flagString} }
	registerCommand(&commandSpec{name: "update", help: "self-update from the latest stable GitHub release", helpText: updateHelpText, handler: cmdUpdate})
	registerFlags("update", "update [--dry-run] [--version TAG] [--allow-downgrade] [--allow-prerelease]",
		[]flagDef{boolFlag("dry-run"), strFlag("version"), boolFlag("allow-downgrade"), boolFlag("allow-prerelease")})
}

func cmdUpdate(ctx context.Context, env *Env, g *globalOpts, args []string) error {
	p, err := parseOrHelp(commandTable["update"], args, env)
	if err != nil {
		return err
	}
	if err := checkPositionals(p, nil, "update"); err != nil {
		return usageErr(err)
	}
	// No config load, no profile, no outbound: release downloads
	// are public URLs, not profile traffic (see internal/update).
	opts := update.Options{
		CurrentVersion:  Version,
		Commit:          Commit,
		BuildDate:       BuildDate,
		DryRun:          p.bool("dry-run"),
		AllowDowngrade:  p.bool("allow-downgrade"),
		AllowPrerelease: p.bool("allow-prerelease"),
		Stdout:          env.stdout(),
	}
	if p.strIsSet("version") {
		opts.TargetVersion = p.str("version")
	}
	if env.UpdateDeps != nil {
		opts.Deps = *env.UpdateDeps
	}
	_, err = update.Run(ctx, opts)
	if err != nil {
		var ue *update.Error
		if errors.As(err, &ue) {
			return errCode(ue.Code(), ue)
		}
		return err
	}
	return nil
}
