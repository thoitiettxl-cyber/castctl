// Command muse-cli is the Go port of muse-cli (Python 0.6.1).
//
// PR1 scope: --version / --help and a read-only config load for the
// active profile. There are no other commands yet (profile commands and
// the gateway arrive in PR2/PR3). This command never writes files, never
// reads cookies, and never touches the network; it only resolves and
// loads the active profile's settings and prints the non-secret subset.
//
// Build tags: with_utls is required (uTLS+reality; the outbound package
// errors clearly without it). WireGuard endpoints additionally require
// with_gvisor: without it, sing-box's wireguard device stack is a stub
// returning tun.ErrGVisorNotIncluded (measured in PR1, transport/wireguard
// device_stack_stub.go, //go:build !with_gvisor) — the plan's "with_gvisor
// only for system:true" assumption does not hold for sing-box 1.14.4.
// Full product tag set: with_utls,with_quic,with_wireguard,with_gvisor.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/thoitiettxl-cyber/muse-cli/go/internal/profile"
)

// Version mirrors src/muse_cli/__init__.py __version__ (0.6.1). The
// Python package is the version source of truth; PR5 packaging may
// generate this value instead of hard-coding it.
const Version = "0.6.1"

const usage = `Usage: muse-cli [--profile NAME] [--version] [--help]

Options:
  --profile NAME   profile to load (overrides MUSE_CLI_PROFILE)
  --version        print version and exit
  --help           print this help and exit

With no option, muse-cli loads the active profile's config (read-only)
and prints its non-secret settings as JSON. No other commands exist yet.
`

// summary is the non-secret subset of a resolved profile. vm_id,
// node_id, and subscription_action_id are deliberately never printed.
type summary struct {
	Profile       string `json:"profile"`
	Source        string `json:"source"`
	ConfigFound   bool   `json:"config_found"`
	CookiesFile   string `json:"cookies_file"`
	AutoApprove   string `json:"auto_approve"`
	AutoAllowOnce bool   `json:"auto_allow_once"`
	OutboundKind  string `json:"outbound_kind"`
	OutboundTag   string `json:"outbound_tag,omitempty"`
	OutboundType  string `json:"outbound_type,omitempty"`
}

func main() {
	os.Exit(run(os.Args[1:], os.LookupEnv, os.Stdout, os.Stderr, ""))
}

// run parses args with a hand-rolled parser (no Cobra, no stdlib flag:
// argparse accepts only --long and -h, rejects single-dash long flags
// and --version=true, and exits 2 on unknown arguments; the stdlib flag
// package accepts all three) and returns the exit code.
// home, when non-empty, overrides os.UserHomeDir (tests); empty means
// resolve the real home directory.
func run(args []string, getenv func(string) (string, bool), stdout, stderr io.Writer, home string) int {
	var showVersion, showHelp bool
	var profileFlag string
	var profileSet bool
	seenDashDash := false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if seenDashDash || !strings.HasPrefix(arg, "-") || arg == "-" {
			fmt.Fprintf(stderr, "muse-cli: unexpected argument %q\n", arg)
			fmt.Fprint(stderr, usage)
			return 2
		}
		if arg == "--" {
			seenDashDash = true
			continue
		}
		switch {
		case arg == "-h" || arg == "--help":
			showHelp = true
		case arg == "--version":
			showVersion = true
		case arg == "--profile":
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
				fmt.Fprint(stderr, "muse-cli: argument --profile: expected one argument\n")
				fmt.Fprint(stderr, usage)
				return 2
			}
			i++
			profileFlag, profileSet = args[i], true
		case strings.HasPrefix(arg, "--profile="):
			profileFlag, profileSet = strings.TrimPrefix(arg, "--profile="), true
		default:
			fmt.Fprintf(stderr, "muse-cli: unrecognized argument %q\n", arg)
			fmt.Fprint(stderr, usage)
			return 2
		}
	}
	if showHelp {
		fmt.Fprint(stdout, usage)
		return 0
	}
	if showVersion {
		fmt.Fprintf(stdout, "muse-cli %s\n", Version)
		return 0
	}
	if home == "" {
		var err error
		home, err = os.UserHomeDir()
		if err != nil {
			fmt.Fprintf(stderr, "muse-cli: %v\n", err)
			return 1
		}
	}
	var flagName *string
	if profileSet {
		flagName = &profileFlag
	}
	prof, err := profile.ResolveActiveProfile(profile.BaseDir(home), flagName, getenv)
	if err != nil {
		fmt.Fprintf(stderr, "muse-cli: %v\n", err)
		return profile.ExitCode(err)
	}
	out := summary{
		Profile:       prof.Name,
		Source:        string(prof.Source),
		ConfigFound:   prof.ConfigFound,
		CookiesFile:   prof.CookiesFile,
		AutoApprove:   prof.AutoApprove,
		AutoAllowOnce: prof.AutoAllowOnce,
		OutboundKind:  string(prof.Outbound.Kind),
		OutboundTag:   prof.Outbound.Tag,
		OutboundType:  prof.Outbound.Type,
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		fmt.Fprintf(stderr, "muse-cli: %v\n", err)
		return 1
	}
	return 0
}
