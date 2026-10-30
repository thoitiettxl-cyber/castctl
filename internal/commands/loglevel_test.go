// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package commands

// Tests for the global --log-level flag.
//
// What each test observes: scanGlobal parsing results, Run exit
// codes/stderr for invalid levels, and the threading of the parsed
// override into the Env the runtime builder reads. What the red run
// catches: scanGlobal rejecting --log-level as "unrecognized
// argument" (it knows only --profile/--config/--version/--help
// today), and the override never reaching defaultBuildRuntime
// (globalOpts is not passed there today).

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/thoitiettxl-cyber/castctl/internal/profile"
)

func scanEnv() *Env {
	return &Env{Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}}
}

func TestScanGlobalLogLevel(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		args     []string
		wantSet  bool
		wantLvl  string
		wantCode int
		wantDone bool
		wantErr  string
	}{
		{"separate value", []string{"--log-level", "trace", "profile", "list"}, true, "trace", 0, false, ""},
		{"equals value", []string{"--log-level=debug", "profile", "list"}, true, "debug", 0, false, ""},
		{"warning alias", []string{"--log-level", "warning", "profile", "list"}, true, "warning", 0, false, ""},
		{"unambiguous prefix", []string{"--log-l", "info", "profile", "list"}, true, "info", 0, false, ""},
		{"prefix equals", []string{"--log-le=warn", "profile", "list"}, true, "warn", 0, false, ""},
		{"after profile flag", []string{"--profile", "default", "--log-level", "error", "profile", "list"}, true, "error", 0, false, ""},
		{"invalid level", []string{"--log-level", "verbose", "profile", "list"}, false, "", 2, true, "argument --log-level"},
		{"invalid uppercase", []string{"--log-level", "TRACE", "profile", "list"}, false, "", 2, true, "argument --log-level"},
		{"missing value", []string{"--log-level"}, false, "", 2, true, "expected one argument"},
		{"missing value before command", []string{"--log-level", "profile", "list"}, false, "", 2, true, "argument --log-level"},
		{"empty value", []string{"--log-level=", "profile", "list"}, false, "", 2, true, "argument --log-level"},
		{"value looks like flag", []string{"--log-level", "--profile", "profile", "list"}, false, "", 2, true, "expected one argument"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := scanEnv()
			g, cmdName, cmdArgs, code, done := scanGlobal(tc.args, env)
			if done != tc.wantDone || code != tc.wantCode {
				t.Fatalf("scanGlobal(%v) done=%v code=%d, want done=%v code=%d (stderr %q)", tc.args, done, code, tc.wantDone, tc.wantCode, env.Stderr)
			}
			if tc.wantDone {
				if tc.wantErr != "" && !strings.Contains(env.Stderr.(*bytes.Buffer).String(), tc.wantErr) {
					t.Errorf("stderr %q, want it to contain %q", env.Stderr, tc.wantErr)
				}
				return
			}
			if g.logLevelSet != tc.wantSet || g.logLevelFlag != tc.wantLvl {
				t.Errorf("globalOpts logLevel=%q set=%v, want %q set=%v", g.logLevelFlag, g.logLevelSet, tc.wantLvl, tc.wantSet)
			}
			if cmdName != "profile" || len(cmdArgs) == 0 || cmdArgs[0] != "list" {
				t.Errorf("scanGlobal(%v) cmd=%q args=%v, want profile/list", tc.args, cmdName, cmdArgs)
			}
		})
	}
}

// TestScanGlobalLogLevelAfterCommand: a global flag after the
// command name is NOT consumed by scanGlobal (existing global-flag
// semantics, same as --profile/--config); it stays in the command
// args for the per-command parser to reject.
func TestScanGlobalLogLevelAfterCommand(t *testing.T) {
	t.Parallel()
	env := scanEnv()
	_, cmdName, cmdArgs, _, done := scanGlobal([]string{"profile", "list", "--log-level", "trace"}, env)
	if done {
		t.Fatal("scanGlobal consumed the command")
	}
	if cmdName != "profile" || len(cmdArgs) != 3 || cmdArgs[1] != "--log-level" {
		t.Errorf("cmd=%q args=%v, want the flag left in command args", cmdName, cmdArgs)
	}
}

// TestRunInvalidLogLevel: invalid level exits 2, names the flag,
// and never echoes the supplied value (the value could be a secret
// a user pasted by mistake; the error must not repeat it).
func TestRunInvalidLogLevel(t *testing.T) {
	t.Parallel()
	_, configFile := testHome(t, "")
	env := &Env{Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}, Getenv: mapGetenv(map[string]string{"CASTCTL_CONFIG": configFile})}
	code := Run(context.Background(), []string{"--config", configFile, "--log-level", "LOGFIX-HT-2c6e88", "profile", "list"}, env)
	if code != 2 {
		t.Errorf("Run code = %d, want 2", code)
	}
	stderr := env.Stderr.(*bytes.Buffer).String()
	if !strings.Contains(stderr, "argument --log-level") {
		t.Errorf("stderr %q, want it to name --log-level", stderr)
	}
	if strings.Contains(stderr, "LOGFIX-HT-2c6e88") {
		t.Errorf("stderr echoes the supplied level value: %q", stderr)
	}
	if strings.Contains(stderr, "castctl: panic:") || strings.Contains(stderr, "goroutine ") {
		t.Errorf("stderr looks like a panic/stack dump: %q", stderr)
	}
}

// TestRunLogLevelThreading: the parsed override reaches the Env
// that defaultBuildRuntime reads, via runInner. The fake runtime
// builder captures the Env fields and returns a sentinel error so
// no real runtime is built.
func TestRunLogLevelThreading(t *testing.T) {
	t.Parallel()
	_, configFile := testHome(t, "")
	var gotLevel string
	var gotSet bool
	env := &Env{
		Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{},
		Getenv: mapGetenv(map[string]string{"CASTCTL_CONFIG": configFile}),
		BuildRuntime: func(ctx context.Context, loc *profile.ConfigLocation, prof *profile.Profile, e *Env) (*Runtime, error) {
			gotLevel, gotSet = e.LogLevelOverride, e.LogLevelSet
			return nil, errors.New("capture-probe")
		},
	}
	Run(context.Background(), []string{"--config", configFile, "--log-level", "trace", "status"}, env)
	if !gotSet || gotLevel != "trace" {
		t.Errorf("BuildRuntime saw LogLevelOverride=%q set=%v, want trace/set", gotLevel, gotSet)
	}

	// No flag: unset, so the config block / default governs.
	gotLevel, gotSet = "", false
	env.BuildRuntime = func(ctx context.Context, loc *profile.ConfigLocation, prof *profile.Profile, e *Env) (*Runtime, error) {
		gotLevel, gotSet = e.LogLevelOverride, e.LogLevelSet
		return nil, errors.New("capture-probe")
	}
	Run(context.Background(), []string{"--config", configFile, "status"}, env)
	if gotSet || gotLevel != "" {
		t.Errorf("BuildRuntime saw LogLevelOverride=%q set=%v without a flag, want unset", gotLevel, gotSet)
	}
}

// TestGlobalHelpMentionsLogLevel pins the help text update: the
// flag, its spellings, and its precedence must be documented where
// --profile/--config are.
func TestGlobalHelpMentionsLogLevel(t *testing.T) {
	t.Parallel()
	if !strings.Contains(globalHelpText, "--log-level") {
		t.Error("globalHelpText does not mention --log-level")
	}
	if !strings.Contains(globalHelpText, "warn") {
		t.Error("globalHelpText does not document the default level")
	}
}
