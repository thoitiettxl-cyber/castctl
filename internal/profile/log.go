// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package profile

// The top-level `log` config block and its resolution.
//
// Schema (exactly four keys; unknown keys are rejected, like every
// other strict section in this file):
//
//	{"disabled": bool, "level": string, "output": string, "timestamp": bool}
//
// Semantics follow sing-box's log option
// (github.com/sagernet/sing-box v1.14.4, option/options.go:69-75,
// log/log.go:22-71) except where Boss decided otherwise — each
// deviation is marked below and in docs/config.md:
//
//   - Default level is "warn" (Boss). Sing-box's empty level means
//     trace (log/log.go:67-69); castctl sets warn explicitly and
//     never passes an empty level to the factory.
//   - "warning" is accepted as an alias for "warn", as sing-box's
//     ParseLevel does (log/level.go:40-58); ResolveLogSettings
//     normalises it to "warn". No other spelling is accepted;
//     levels are case-sensitive, exactly as ParseLevel requires.
//   - Output accepts "" (stderr), "stderr", and file paths ONLY.
//     "stdout" is rejected: Boss named file path or stderr only.
//     Sing-box additionally accepts "stdout" (log/log.go:40-41);
//     that shape is a deliberate deviation, documented in
//     docs/config.md.
//   - DisableColor is a sing-box programmatic-only field
//     (json:"-", option/options.go:75); it is NOT a config key and
//     is rejected as unknown. Console colour follows sing-box's
//     default (colours on for console, plain for files).
//
// Resolution is pure (ResolveProfileDNS is the pattern): it reads
// only its inputs, never the filesystem, never mutates. Precedence
// is CLI > config block > default warn. An absent block is NOT
// written back on save: parse keeps Log nil, and the render branch
// emits nothing, so defaults stay runtime-only (the same
// presence-flag precedent as fingerprint/tls_engine).

import "strings"

// LogConfig is one parsed `log` block. A nil *LogConfig on
// SingleConfig means the block was absent from the file.
type LogConfig struct {
	Disabled  bool
	Level     string
	Output    string
	Timestamp bool
}

// logLevels are the accepted level spellings, including sing-box's
// "warning" alias. ParseLevel in sing-box is the authority for the
// set (log/level.go:40-58); this list mirrors it.
var logLevels = map[string]bool{
	"trace": true, "debug": true, "info": true, "warn": true,
	"warning": true, "error": true, "fatal": true, "panic": true,
}

// validLogLevel reports whether s is an accepted level spelling
// (case-sensitive; "" is not accepted in a config block —
// resolution supplies the default instead).
func validLogLevel(s string) bool { return logLevels[s] }

// ValidLogLevel reports whether s is an accepted --log-level /
// config log level spelling, including sing-box's "warning" alias
// for "warn". Case-sensitive, exactly as sing-box ParseLevel
// requires (log/level.go:40-58).
func ValidLogLevel(s string) bool { return validLogLevel(s) }

// parseLogBlock parses one decoded `log` value into a LogConfig.
// Wrong shapes, wrong types, unknown keys, unknown levels, and
// "stdout" output are all config errors (exit 2).
func parseLogBlock(v any) (*LogConfig, error) {
	obj, ok := v.(*orderedObject)
	if !ok {
		return nil, newConfigError(`"log" must be an object`)
	}
	cfg := &LogConfig{}
	for _, k := range obj.keys {
		val := obj.values[k]
		switch k {
		case "disabled":
			b, ok := val.(bool)
			if !ok {
				return nil, newConfigError(`"log.disabled" must be a boolean`)
			}
			cfg.Disabled = b
		case "level":
			s, ok := val.(string)
			if !ok {
				return nil, newConfigError(`"log.level" must be a string`)
			}
			if s == "" || !validLogLevel(s) {
				return nil, newConfigErrorf("unknown log level %q", s)
			}
			cfg.Level = s
		case "output":
			s, ok := val.(string)
			if !ok {
				return nil, newConfigError(`"log.output" must be a string`)
			}
			if s == "stdout" {
				return nil, newConfigError(`"log.output" must be a file path or "stderr"; "stdout" is not accepted`)
			}
			cfg.Output = s
		case "timestamp":
			b, ok := val.(bool)
			if !ok {
				return nil, newConfigError(`"log.timestamp" must be a boolean`)
			}
			cfg.Timestamp = b
		default:
			return nil, newConfigErrorf("unknown log config key %q", k)
		}
	}
	return cfg, nil
}

// ResolveLogSettings returns the effective log settings for one
// invocation: CLI override > config block > defaults (level warn,
// output stderr, timestamp false, disabled false). cliLevel is
// honoured only when cliSet is true; a set-but-empty CLI level is
// an error (an empty level must never mean "no filtering"). A
// "warning" level (CLI or config) normalises to "warn". The
// returned Output is canonicalised: "" becomes "stderr".
func ResolveLogSettings(single *SingleConfig, cliLevel string, cliSet bool) (LogConfig, error) {
	out := LogConfig{Level: "warn", Output: "stderr"}
	if single != nil && single.Log != nil {
		out = *single.Log
		if out.Level == "" {
			out.Level = "warn"
		}
		if out.Output == "" {
			out.Output = "stderr"
		}
	}
	if cliSet {
		if cliLevel == "" || !validLogLevel(cliLevel) {
			return LogConfig{}, newConfigError("invalid --log-level value")
		}
		out.Level = cliLevel
	}
	if out.Level == "warning" {
		out.Level = "warn"
	}
	if !validLogLevel(out.Level) {
		return LogConfig{}, newConfigErrorf("unknown log level %q", out.Level)
	}
	if out.Output == "stdout" {
		return LogConfig{}, newConfigError(`"log.output" must be a file path or "stderr"; "stdout" is not accepted`)
	}
	if strings.TrimSpace(out.Output) == "" {
		out.Output = "stderr"
	}
	return out, nil
}
