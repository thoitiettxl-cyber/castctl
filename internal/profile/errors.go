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
// (usually the UserConfigDir-derived home) as a parameter; library
// code never calls os.UserHomeDir, except ResolveConfigLocation's
// HOME fallback (os.UserHomeDir) when HOME is absent from the getenv
// it was given. Callers resolve the home directory and pass it in via
// BaseDir. No network access happens in this package.
//
// Concurrent writes: see guard.go. Guarded writes serialise through an
// in-process mutex plus an flock on config.json.lock, and the checked
// paths (ConfigState.Save, UpdateSingleConfig) additionally refuse
// with ErrConcurrentChange when the file's sha256 changed since the
// load. SaveSingleConfig takes the lock but does NOT hash-check: it is
// the write path for Migrate and for callers with no prior read.
//
// Config location (Requirement A, portable per the PLATFORMS
// clarification): ResolveConfigLocation (configlocation.go)
// resolves the config file once per invocation: explicit FILE path
// (--config flag value, else MUSE_CLI_CONFIG) > the
// os.UserConfigDir()-derived home (Join(userConfigDir, "muse-cli")).
// A relative XDG_CONFIG_HOME (Unix) is caught, warned about, and
// falls back to the computed $HOME-based default; any other
// user-config-dir error with no usable home is a clear error, never
// a silent fallback. The resolved file's directory becomes
// CONFIG_DIR for the whole invocation; every derived path comes
// from it. Symlinks are not resolved for display paths; relative
// explicit paths are CWD-relative with no tilde expansion. Phase 2
// must call ConfigLocation.RequirePresent for every command except
// `config migrate --write`, which alone may create a missing
// explicit file.
//
// Per-key path resolution (config file keys; survey of Python 0.6.1
// cli.py:32-260 and the PR1 profile code, 2026-10-29):
//
//   - cookies_file (single-file profile entry and legacy flat
//     config): a relative value resolves under the config file's
//     directory (the resolved CONFIG_DIR); an absolute value is
//     honoured as-is. The named-profile coercion (a named profile
//     cannot borrow another profile's login when the value points
//     inside the config dir) applies within the resolved dir.
//     Python 0.6.1 did NOT resolve this key (the value was kept
//     as-is, so a relative value meant CWD-relative at open
//     time); the Go delta rule (resolve under the config dir)
//     predates Requirement A and is unchanged — only the base
//     moved from the default home to the resolved dir.
//   - vm_id, node_id, subscription_action_id, auto_approve,
//     auto_allow_once, default_profile, fingerprint, tls_engine:
//     not paths; no resolution is performed.
//   - outbound / outbounds / endpoints / dns: opaque sing-box
//     option objects, parsed by sing-box's own registry and
//     stored as raw JSON. Path-like fields inside them (tls
//     certificate_path, client_certificate_path, key_path; ssh
//     private_key_path; openvpn/openconnect certificate, key,
//     crl and static-key paths; tailscale config_path; any other
//     *_path) are passed through VERBATIM. This package never
//     rewrites them, so a relative value resolves the way
//     sing-box resolves it (process working directory), NOT
//     relative to the config file's directory. Rewriting them
//     would need a hand-written copy of the sing-box schema,
//     which the delta forbids. Users with a custom --config
//     location must use absolute paths inside outbound objects.
//   - Derived filesystem paths (all from the resolved CONFIG_DIR):
//     config.json, config.json.lock, profiles/<name>/config.json
//     (legacy), profiles/<name>/cookies.txt (default),
//     profiles/<name>/chat.json, and — for consumers in other
//     packages — the active profile's telegram.json and
//     telegram-state.json (via Profile.Dir) and update.json
//     (config-global: under CONFIG_DIR, never per-profile, and
//     never pinned to the default home once a custom location
//     is resolved; no derivation for update.json exists in this
//     package yet).
//
// Fingerprint/tls_engine recording: see fingerprint.go. The values
// are stored, data-validated, and displayed only; they have no
// effect on traffic in PR3 (fingerprint-engine evaluation pending).
package profile

import (
	"errors"
	"fmt"
	"path/filepath"
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
	// ErrConcurrentChange is the sentinel for a guarded write refused
	// because config.json changed since it was loaded (see guard.go).
	// The caller retries the whole command.
	ErrConcurrentChange = &Error{Code: 2, Kind: "concurrent_change", Message: "profile: config changed concurrently"}
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

func newConcurrentChangeError(baseDir string) *Error {
	return &Error{
		Code:    2,
		Kind:    "concurrent_change",
		Message: fmt.Sprintf("profile: config changed concurrently, retry: %s", filepath.Join(baseDir, "config.json")),
		Cause:   ErrConcurrentChange,
	}
}
