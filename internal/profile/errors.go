// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

// Package profile implements profile resolution, the single-file
// config.json format, legacy layout reading, config migration, cookie
// parsing, auto-approve precedence, and secret redaction for muse-cli.
//
// Load is read-only: unlike the Python load_config (cli.py:151-188), Load
// never generates or writes a node_id. Node_id generation happens only in
// Migrate with write=true (and, in a later phase, profile-add). This is a
// deliberate difference required by the sing-box delta: Load must have no
// file side effects.
//
// All functions that touch the filesystem take the config base directory
// (usually ~/.config/muse-cli) as a parameter; library code never calls
// os.UserHomeDir. Callers resolve the home directory and pass it in via
// BaseDir. No network access happens in this package.
package profile

import (
	"errors"
	"fmt"
)

// Error is a typed error carrying an exit code so cmd can map errors
// without string matching. Code 2 covers ValueError-class and
// AuthError-class errors per the plan's main() mapping (AuthError→2,
// GatewayError→3, ValueError→2, TimeoutError→4); this package only
// produces code 2 (plus 0 for nil via ExitCode).
type Error struct {
	Code    int
	Kind    string
	Message string
	Cause   error
}

func (e *Error) Error() string { return e.Message }

// Unwrap exposes the sentinel cause (ErrInvalidProfile, ErrConfigParse,
// ErrAuth, or ErrRefuseOverwrite) for errors.Is.
func (e *Error) Unwrap() error { return e.Cause }

// ExitCode returns the process exit code for this error.
func (e *Error) ExitCode() int { return e.Code }

var (
	// ErrInvalidProfile is the sentinel for invalid profile names.
	ErrInvalidProfile = &Error{Code: 2, Kind: "invalid_profile", Message: "profile: invalid profile name"}
	// ErrConfigParse is the sentinel for config parse/validation errors.
	ErrConfigParse = &Error{Code: 2, Kind: "config_parse", Message: "profile: config parse error"}
	// ErrAuth is the sentinel for cookie/auth errors.
	ErrAuth = &Error{Code: 2, Kind: "auth", Message: "profile: auth error"}
	// ErrRefuseOverwrite is the sentinel for migrate refusing to overwrite
	// a different existing single config file.
	ErrRefuseOverwrite = &Error{Code: 2, Kind: "refuse_overwrite", Message: "profile: refuse to overwrite existing single config"}
)

// ExitCode maps an error to a process exit code: 0 for nil, the typed
// code for *Error (including wrapped ones), 1 for anything else.
func ExitCode(err error) int {
	if err == nil {
		return 0
	}
	var coded interface{ ExitCode() int }
	if errors.As(err, &coded) {
		return coded.ExitCode()
	}
	return 1
}

func newConfigError(msg string) *Error {
	return &Error{Code: 2, Kind: "config_parse", Message: "profile: " + msg, Cause: ErrConfigParse}
}

func newConfigErrorf(format string, args ...any) *Error {
	return newConfigError(fmt.Sprintf(format, args...))
}

func newInvalidProfileError(name string) *Error {
	// Truncate long names in the message; the name is user input, not a secret,
	// but an unbounded env value must not bloat logs.
	shown := name
	if len([]rune(shown)) > 64 {
		shown = string([]rune(shown)[:64]) + "…"
	}
	return &Error{
		Code:    2,
		Kind:    "invalid_profile",
		Message: fmt.Sprintf("profile: invalid profile name %q: use 1-64 letters, digits, '.', '-' or '_' (not starting or ending with '.')", shown),
		Cause:   ErrInvalidProfile,
	}
}

func newAuthError(msg string) *Error {
	return &Error{Code: 2, Kind: "auth", Message: "profile: " + msg, Cause: ErrAuth}
}

func newRefuseError(msg string) *Error {
	return &Error{Code: 2, Kind: "refuse_overwrite", Message: "profile: " + msg, Cause: ErrRefuseOverwrite}
}
