// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package profile

// Tests for the top-level `log` config block and its resolution.
//
// What each test observes: ParseSingleConfig / ResolveLogSettings /
// buildSingleFileOrdered / cloneSingleConfig behaviour for a `log`
// block. What the red run catches: the block rejected as an unknown
// top-level key (config.go singleTopLevelKeys has no "log" entry),
// the off-gate missed (an absent block with no --log-level flag
// must mean logging OFF, not sing-box's trace default), the
// absent-vs-present-empty distinction lost (an empty {} block
// turns logging ON at sing-box defaults), CLI precedence
// inverted, and config migrate silently dropping the block
// (clone/render field-by-field carriers).

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func logJSON(t *testing.T, logBlock string) *SingleConfig {
	t.Helper()
	data := `{"profiles":{"default":{}},"log":` + logBlock + `}`
	cfg, err := ParseSingleConfig([]byte(data), "/base")
	if err != nil {
		t.Fatalf("ParseSingleConfig(%s) = %v", data, err)
	}
	return cfg
}

func TestParseLogBlockValid(t *testing.T) {
	t.Parallel()
	cfg := logJSON(t, `{"disabled":false,"level":"debug","output":"stderr","timestamp":true}`)
	if cfg.Log == nil {
		t.Fatal("Log is nil; want parsed block")
	}
	if cfg.Log.Disabled || cfg.Log.Level != "debug" || cfg.Log.Output != "stderr" || !cfg.Log.Timestamp {
		t.Errorf("Log = %+v; want {false debug stderr true}", *cfg.Log)
	}
	// Every accepted level spelling parses, including the sing-box
	// "warning" alias for warn.
	for _, level := range []string{"trace", "debug", "info", "warn", "warning", "error", "fatal", "panic"} {
		cfg := logJSON(t, `{"level":`+quoteStr(level)+`}`)
		if cfg.Log == nil || cfg.Log.Level != level {
			t.Errorf("level %q: Log = %+v; want level preserved", level, cfg.Log)
		}
	}
	// Partial blocks parse; absent fields are zero values, resolved
	// later by ResolveLogSettings (parse must not invent defaults
	// into the file representation).
	cfg = logJSON(t, `{"level":"info"}`)
	if cfg.Log.Level != "info" || cfg.Log.Disabled || cfg.Log.Output != "" || cfg.Log.Timestamp {
		t.Errorf("partial Log = %+v; want only level set", *cfg.Log)
	}
	// Empty output means stderr (sing-box "" semantics, castctl
	// spelling: "" and "stderr" both mean stderr).
	cfg = logJSON(t, `{"output":""}`)
	if cfg.Log.Output != "" {
		t.Errorf("output = %q; want empty (stderr)", cfg.Log.Output)
	}
	// A file path is carried verbatim.
	cfg = logJSON(t, `{"output":"/tmp/castctl.log"}`)
	if cfg.Log.Output != "/tmp/castctl.log" {
		t.Errorf("output = %q; want verbatim path", cfg.Log.Output)
	}
	// "stdout" is accepted, exactly as sing-box parses it
	// (log/log.go:40-41); it names the real stdout, not a file.
	cfg = logJSON(t, `{"output":"stdout"}`)
	if cfg.Log.Output != "stdout" {
		t.Errorf("output = %q; want stdout accepted", cfg.Log.Output)
	}
}

func quoteStr(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func TestParseLogBlockInvalid(t *testing.T) {
	t.Parallel()
	bad := []string{
		`{"profiles":{"default":{}},"log":"debug"}`,             // not an object
		`{"profiles":{"default":{}},"log":{"level":"verbose"}}`, // unknown level
		`{"profiles":{"default":{}},"log":{"level":"TRACE"}}`,   // case-sensitive: uppercase rejected
		`{"profiles":{"default":{}},"log":{"level":""}}`,        // empty level rejected in config
		`{"profiles":{"default":{}},"log":{"level":3}}`,         // wrong type
		`{"profiles":{"default":{}},"log":{"disabled":"yes"}}`,  // wrong type
		`{"profiles":{"default":{}},"log":{"timestamp":1}}`,     // wrong type
		`{"profiles":{"default":{}},"log":{"output":42}}`,       // wrong type
		// NOTE: "STDERR" is NOT special: sing-box matches "stderr"
		// exactly and treats any other string as a file path, so
		// "STDERR" names a file. "stdout" is accepted (see
		// TestParseLogBlockValid), not rejected.
		`{"profiles":{"default":{}},"log":{"rotation":true}}`,      // unknown key inside log
		`{"profiles":{"default":{}},"log":{"disable_color":true}}`, // DisableColor is not a config key
		`{"profiles":{"default":{}},"log":{"disabled":false,"bogus":1}}`,
	}
	for _, data := range bad {
		cfg, err := ParseSingleConfig([]byte(data), "/base")
		if err == nil {
			t.Errorf("ParseSingleConfig(%s) = %+v, want error (exit 2)", data, cfg)
			continue
		}
		if ExitCode(err) != 2 {
			t.Errorf("ParseSingleConfig(%s) exit code = %d, want 2", data, ExitCode(err))
		}
	}
}

func TestParseLogBlockAbsent(t *testing.T) {
	t.Parallel()
	cfg, err := ParseSingleConfig([]byte(`{"profiles":{"default":{}}}`), "/base")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Log != nil {
		t.Errorf("Log = %+v; want nil for an absent block (defaults live in resolution, never written back)", *cfg.Log)
	}
}

func TestResolveLogSettings(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		cfg     *SingleConfig
		cli     string
		cliSet  bool
		want    LogConfig
		wantErr bool
	}{
		{"absent block", nil, "", false, LogConfig{Disabled: true, Level: "trace", Output: "", Timestamp: false}, false},
		{"absent block, nil single", nilSingle(), "", false, LogConfig{Disabled: true, Level: "trace", Output: "", Timestamp: false}, false},
		{"empty block present turns logging on", configWithLog(LogConfig{}), "", false, LogConfig{Disabled: false, Level: "trace", Output: "", Timestamp: false}, false},
		{"explicit disabled:false block", configWithLog(LogConfig{Disabled: false}), "", false, LogConfig{Disabled: false, Level: "trace", Output: "", Timestamp: false}, false},
		{"config level", configWithLog(LogConfig{Level: "debug", Output: "stderr"}), "", false, LogConfig{Level: "debug", Output: "stderr"}, false},
		{"warning alias normalises", configWithLog(LogConfig{Level: "warning"}), "", false, LogConfig{Level: "warn", Output: ""}, false},
		{"CLI beats config upward", configWithLog(LogConfig{Level: "error"}), "trace", true, LogConfig{Level: "trace", Output: ""}, false},
		{"CLI beats config downward", configWithLog(LogConfig{Level: "debug"}), "warn", true, LogConfig{Level: "warn", Output: ""}, false},
		{"CLI only", nil, "info", true, LogConfig{Level: "info", Output: ""}, false},
		{"config disabled kept", configWithLog(LogConfig{Disabled: true, Level: "trace"}), "", false, LogConfig{Disabled: true, Level: "trace", Output: ""}, false},
		{"CLI does not clear disabled", configWithLog(LogConfig{Disabled: true, Level: "trace"}), "debug", true, LogConfig{Disabled: true, Level: "debug", Output: ""}, false},
		{"config file output kept", configWithLog(LogConfig{Level: "info", Output: "/tmp/x.log", Timestamp: true}), "", false, LogConfig{Level: "info", Output: "/tmp/x.log", Timestamp: true}, false},
		{"stdout in config accepted at resolve", configWithLog(LogConfig{Level: "debug", Output: "stdout"}), "", false, LogConfig{Level: "debug", Output: "stdout"}, false},
		{"invalid CLI level", configWithLog(LogConfig{Level: "debug"}), "verbose", true, LogConfig{}, true},
		{"empty CLI level", nil, "", true, LogConfig{}, true},
		{"invalid config level", configWithLog(LogConfig{Level: "bogus"}), "", false, LogConfig{}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ResolveLogSettings(tc.cfg, tc.cli, tc.cliSet)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ResolveLogSettings = %+v, want error", got)
				}
				if ExitCode(err) != 2 {
					t.Errorf("error exit code = %d, want 2", ExitCode(err))
				}
				return
			}
			if err != nil {
				t.Fatalf("ResolveLogSettings = %v, want %+v", err, tc.want)
			}
			if got != tc.want {
				t.Errorf("ResolveLogSettings = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func nilSingle() *SingleConfig { return nil }

func configWithLog(l LogConfig) *SingleConfig {
	return &SingleConfig{Profiles: map[string]*Profile{}, Log: &l}
}

// TestLogBlockEmptyObjectPresent: an empty {} log block is
// PRESENT, distinct from an absent block. Parse keeps it
// non-nil, and resolution turns logging ON at sing-box
// defaults — the absent-vs-present-empty distinction the
// off-gate depends on.
func TestLogBlockEmptyObjectPresent(t *testing.T) {
	t.Parallel()
	cfg := logJSON(t, `{}`)
	if cfg.Log == nil {
		t.Fatal("Log is nil for an empty {} block; want non-nil (presence matters)")
	}
	if *cfg.Log != (LogConfig{}) {
		t.Errorf("Log = %+v; want the zero block", *cfg.Log)
	}
	resolved, err := ResolveLogSettings(cfg, "", false)
	if err != nil {
		t.Fatal(err)
	}
	if resolved.Disabled {
		t.Errorf("ResolveLogSettings(empty block) = %+v, want logging ON (Disabled false)", resolved)
	}
	if resolved.Level != "trace" {
		t.Errorf("ResolveLogSettings(empty block) level = %q, want trace (sing-box default)", resolved.Level)
	}
	// Absent block, same call shape: logging OFF.
	absent := logJSONAbsent(t)
	resolved, err = ResolveLogSettings(absent, "", false)
	if err != nil {
		t.Fatal(err)
	}
	if !resolved.Disabled {
		t.Errorf("ResolveLogSettings(absent block) = %+v, want logging OFF (Disabled true)", resolved)
	}
}

func logJSONAbsent(t *testing.T) *SingleConfig {
	t.Helper()
	cfg, err := ParseSingleConfig([]byte(`{"profiles":{"default":{}}}`), "/base")
	if err != nil {
		t.Fatalf("ParseSingleConfig(absent log) = %v", err)
	}
	if cfg.Log != nil {
		t.Fatalf("Log = %+v for an absent block; want nil", *cfg.Log)
	}
	return cfg
}

// TestLogBlockSaveRoundTrip: a config WITH a log block keeps it
// byte-faithfully through save/load; a config WITHOUT one gains
// none (absence is preserved, defaults are never written back).
func TestLogBlockSaveRoundTrip(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfg := logJSON(t, `{"disabled":true,"level":"trace","output":"castctl.log","timestamp":true}`)
	if err := SaveSingleConfig(dir, cfg); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if err := json.Unmarshal(data, &root); err != nil {
		t.Fatal(err)
	}
	logBlock, ok := root["log"].(map[string]any)
	if !ok {
		t.Fatalf("saved config has no log block: %s", data)
	}
	if logBlock["disabled"] != true || logBlock["level"] != "trace" || logBlock["output"] != "castctl.log" || logBlock["timestamp"] != true {
		t.Errorf("saved log block = %v; want the authored values", logBlock)
	}
	loaded, err := ParseSingleConfig(data, dir)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Log == nil || *loaded.Log != *cfg.Log {
		t.Errorf("reloaded Log = %+v, want %+v", loaded.Log, cfg.Log)
	}

	// Absent stays absent.
	dir2 := t.TempDir()
	plain, err := ParseSingleConfig([]byte(`{"profiles":{"default":{}}}`), "/base")
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveSingleConfig(dir2, plain); err != nil {
		t.Fatal(err)
	}
	data2, err := os.ReadFile(filepath.Join(dir2, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data2), `"log"`) {
		t.Errorf("saved config without a log block gained one: %s", data2)
	}
}

// TestCloneSingleConfigCarriesLog: config migrate clones through
// cloneSingleConfig; a log block must survive the clone AND the
// re-render, or migrate silently drops it.
func TestCloneSingleConfigCarriesLog(t *testing.T) {
	t.Parallel()
	cfg := logJSON(t, `{"disabled":false,"level":"debug","output":"stderr","timestamp":true}`)
	cloned := cloneSingleConfig(cfg)
	if cloned == nil || cloned.Log == nil || *cloned.Log != *cfg.Log {
		t.Fatalf("clone Log = %+v, want %+v", cloned.Log, cfg.Log)
	}
	// Mutating the clone must not mutate the original.
	cloned.Log.Level = "error"
	if cfg.Log.Level != "debug" {
		t.Errorf("clone shares Log with original: original level = %q", cfg.Log.Level)
	}
	root, err := buildSingleFileOrdered(cloneSingleConfig(cfg))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := encodeOrderedJSON(root)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"log"`) || !strings.Contains(string(raw), `"debug"`) {
		t.Errorf("rendered clone has no log block: %s", raw)
	}
	// A clone of a log-less config renders no log block.
	plain, err := ParseSingleConfig([]byte(`{"profiles":{"default":{}}}`), "/base")
	if err != nil {
		t.Fatal(err)
	}
	root2, err := buildSingleFileOrdered(cloneSingleConfig(plain))
	if err != nil {
		t.Fatal(err)
	}
	raw2, err := encodeOrderedJSON(root2)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw2), `"log"`) {
		t.Errorf("rendered log-less clone gained a log block: %s", raw2)
	}
}

// TestParseLogBlockRealConfigShape: the exact shape from a real
// sing-box config — level "warning", an absolute output path,
// timestamp true — must parse and resolve. The output path here
// is a SCRATCH path under t.TempDir only: never a live config
// path, never the real path from that config.
func TestParseLogBlockRealConfigShape(t *testing.T) {
	t.Parallel()
	outPath := filepath.Join(t.TempDir(), "sing-box.log")
	raw := `{"profiles":{"default":{}},"log":{"level":"warning","output":` + quoteStr(outPath) + `,"timestamp":true}}`
	cfg, err := ParseSingleConfig([]byte(raw), "/base")
	if err != nil {
		t.Fatalf("ParseSingleConfig(real shape) = %v", err)
	}
	if cfg.Log == nil || cfg.Log.Level != "warning" || cfg.Log.Output != outPath || !cfg.Log.Timestamp {
		t.Fatalf("Log = %+v; want {warning %s true}", cfg.Log, outPath)
	}
	resolved, err := ResolveLogSettings(cfg, "", false)
	if err != nil {
		t.Fatalf("ResolveLogSettings(real shape) = %v", err)
	}
	if resolved.Level != "warn" || resolved.Output != outPath || !resolved.Timestamp {
		t.Errorf("resolved = %+v; want {warn %s true}", resolved, outPath)
	}
}

// TestLogBlockInvalidLevelEchoesNothing: an invalid level value
// must never appear in the error, on either the config path or
// the resolve path — the value could be a secret pasted by
// mistake. The fixture value actually enters the parse/resolve
// (it is the level under test), and the error text is scanned
// for it verbatim.
func TestLogBlockInvalidLevelEchoesNothing(t *testing.T) {
	t.Parallel()
	fixture := "LOGFIX-LEVEL-9d2e41"
	data := `{"profiles":{"default":{}},"log":{"level":` + quoteStr(fixture) + `}}`
	_, err := ParseSingleConfig([]byte(data), "/base")
	if err == nil {
		t.Fatal("ParseSingleConfig(invalid level) = nil, want error")
	}
	if ExitCode(err) != 2 {
		t.Errorf("exit code = %d, want 2", ExitCode(err))
	}
	if strings.Contains(err.Error(), fixture) {
		t.Errorf("config-path error echoes the invalid level: %q", err.Error())
	}
	if !strings.Contains(err.Error(), "trace") {
		t.Errorf("config-path error %q, want the fixed expected-level list", err.Error())
	}

	_, err = ResolveLogSettings(configWithLog(LogConfig{Level: fixture}), "", false)
	if err == nil {
		t.Fatal("ResolveLogSettings(invalid level) = nil, want error")
	}
	if strings.Contains(err.Error(), fixture) {
		t.Errorf("resolve-path error echoes the invalid level: %q", err.Error())
	}
}
