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
// Defaults are IDENTICAL to sing-box's (github.com/sagernet/
// sing-box v1.14.4, verified from module source; no default is
// imposed by castctl) WHEN A LOG BLOCK IS PRESENT:
//
//   - Level: empty means trace (log/log.go:67-69: an empty
//     level SetLevels LevelTrace; a set level goes through
//     ParseLevel). "warning" is accepted as an alias for
//     "warn", as ParseLevel does (log/level.go:40-58);
//     ResolveLogSettings normalises it to "warn". No other
//     spelling is accepted; levels are case-sensitive,
//     exactly as ParseLevel requires.
//   - Output: "" means stderr (log/log.go:32-36: the default
//     writer, else os.Stderr); "stderr" means stderr
//     (:38-39); "stdout" means stdout (:40-41); any other
//     string is a file path, opened for append at Start
//     (:42-45, log/observable.go:79). There is no hardcoded
//     default log path: the user sets output freely, or
//     leaves it empty for stderr.
//   - Timestamp: false (log/log.go:46-52): file output carries
//     no timestamp, console output carries a relative
//     elapsed-seconds prefix; true adds the full timestamp
//     in both cases (log/format.go:96-125).
//   - Disabled: false. Disabled:true returns the NOP factory
//     before level parsing or file creation (log/log.go:
//     25-27), so a disabled block with a bogus level still
//     constructs and emits nothing.
//   - DisableColor is a sing-box programmatic-only field
//     (json:"-", option/options.go:75); it is NOT a config key and
//     is rejected as unknown. Console colour follows sing-box's
//     default (colours on for console, plain for files).
//
// CASTCTL GATE (Boss decision 2026-10-30, superseding the
// loop-2 last-line narrowing): when the config has NO log
// block AND no --log-level flag was given, logging is OFF
// (Disabled true) — stderr carries only the typed JSON error,
// as before the log block existed. This gate sits ON TOP of
// sing-box defaults: sing-box alone would log at trace. A
// present block — INCLUDING an empty {} block — follows
// sing-box defaults exactly, and --log-level with no block
// turns logging ON at that level (output stderr). Presence
// is the nil/non-nil Log pointer; parse preserves it.
//
// Resolution is pure (ResolveProfileDNS is the pattern): it reads
// only its inputs, never the filesystem, never mutates. Precedence
// is CLI > config block > sing-box default. An absent block is NOT
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
				// The supplied value is never echoed: it
				// could be a secret pasted by mistake (the
				// same rule as the --log-level CLI path).
				return nil, newConfigError("unknown log level (expected trace, debug, info, warn, warning, error, fatal, or panic)")
			}
			cfg.Level = s
		case "output":
			s, ok := val.(string)
			if !ok {
				return nil, newConfigError(`"log.output" must be a string`)
			}
			// "stdout" is accepted, exactly as sing-box
			// parses it (log/log.go:40-41); "" means stderr,
			// any other string is a file path.
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
// invocation. The castctl gate (see the file header) comes
// first: an ABSENT log block with no CLI flag means logging
// OFF (Disabled true), regardless of sing-box's trace default.
// A PRESENT block (including an empty {} block) follows
// sing-box defaults (level trace, output "" = stderr,
// timestamp false, disabled false). Precedence is CLI >
// config block > sing-box default. cliLevel is honoured only
// when cliSet is true; a set-but-empty CLI level is an error
// (an empty level must never mean "no filtering"). A CLI flag
// turns logging ON when no block exists, but never clears a
// present block's disabled:true. A "warning" level (CLI or
// config) normalises to "warn". An unset Output stays "": the
// factory treats "" as stderr, exactly as sing-box does. No
// resolved value is ever echoed in an error: an invalid level
// reports the fixed expected list only, exactly like the
// --log-level CLI path.
func ResolveLogSettings(single *SingleConfig, cliLevel string, cliSet bool) (LogConfig, error) {
	blockPresent := single != nil && single.Log != nil
	out := LogConfig{Disabled: !blockPresent, Level: "trace"}
	if blockPresent {
		out = *single.Log
		if out.Level == "" {
			out.Level = "trace"
		}
	}
	if cliSet {
		if cliLevel == "" || !validLogLevel(cliLevel) {
			return LogConfig{}, newConfigError("invalid --log-level value")
		}
		out.Level = cliLevel
		if !blockPresent {
			out.Disabled = false
		}
	}
	if out.Level == "warning" {
		out.Level = "warn"
	}
	if !validLogLevel(out.Level) {
		return LogConfig{}, newConfigError("unknown log level (expected trace, debug, info, warn, warning, error, fatal, or panic)")
	}
	if strings.TrimSpace(out.Output) == "" {
		out.Output = ""
	}
	return out, nil
}
