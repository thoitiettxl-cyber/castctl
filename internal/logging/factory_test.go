// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package logging

// Factory tests: one resolved level governs every emission, the
// sing-box formatter semantics (timestamp truth table, colours,
// file handling) are replicated through the writer-injection seam,
// and disabled/file-mode behaviour is pinned.
//
// What each test observes: bytes written to a buffer (console) or
// a temp file (file output) by the production factory, plus file
// modes via os.Stat. What the red run catches: a factory built but
// never started (entries buffered, buffer empty), a level passed
// as sing-box's empty-means-trace (debug/trace leaking at warn),
// the file opened 0644 by the sing-box path (Start opening the
// path itself instead of castctl owning creation), and timestamp
// flags copied wrong (file lines timestamped when they must not
// be, console lines bare when sing-box shows the elapsed prefix).

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	singlog "github.com/sagernet/sing-box/log"
)

var ansiRe = regexp.MustCompile("\x1b\\[[0-9;]*m")

func stripANSI(s string) string { return ansiRe.ReplaceAllString(s, "") }

func emitAll(h *Handle, tag string) {
	logger := h.Logger(tag)
	logger.Trace("level-probe-trace")
	logger.Debug("level-probe-debug")
	logger.Info("level-probe-info")
	logger.Warn("level-probe-warn")
	logger.Error("level-probe-error")
	// Fatal/Panic are not emitted here: the real factory's Fatal
	// calls os.Exit(1) and Panic panics (sing-box log/observable.go
	// output semantics). Panic is covered separately with recover.
}

func assertContains(t *testing.T, buf, sub string) {
	t.Helper()
	if !strings.Contains(buf, sub) {
		t.Errorf("output %q, want it to contain %q", buf, sub)
	}
}

func assertNotContains(t *testing.T, buf, sub string) {
	t.Helper()
	if strings.Contains(buf, sub) {
		t.Errorf("output %q, want it NOT to contain %q", buf, sub)
	}
}

func TestFactoryLevelFiltering(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		level string
		want  []string
		drop  []string
	}{
		{"warn", "warn", []string{"level-probe-warn", "level-probe-error"}, []string{"level-probe-debug", "level-probe-trace", "level-probe-info"}},
		{"trace", "trace", []string{"level-probe-trace", "level-probe-debug", "level-probe-info", "level-probe-warn", "level-probe-error"}, nil},
		{"error", "error", []string{"level-probe-error"}, []string{"level-probe-warn", "level-probe-info", "level-probe-debug"}},
		{"info", "info", []string{"level-probe-info", "level-probe-warn", "level-probe-error"}, []string{"level-probe-debug", "level-probe-trace"}},
		{"default empty means warn", "", []string{"level-probe-warn", "level-probe-error"}, []string{"level-probe-debug", "level-probe-trace"}},
		{"warning alias", "warning", []string{"level-probe-warn", "level-probe-error"}, []string{"level-probe-debug", "level-probe-trace"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			h, err := NewFactory(context.Background(), Settings{Level: tc.level}, &buf)
			if err != nil {
				t.Fatal(err)
			}
			defer h.Close()
			emitAll(h, "castctl")
			got := stripANSI(buf.String())
			for _, w := range tc.want {
				assertContains(t, got, w)
			}
			for _, d := range tc.drop {
				assertNotContains(t, got, d)
			}
		})
	}
}

func TestFactoryInvalidLevel(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	if _, err := NewFactory(context.Background(), Settings{Level: "verbose"}, &buf); err == nil {
		t.Error("NewFactory(level=verbose) = nil, want error")
	}
	if _, err := NewFactory(context.Background(), Settings{Level: "TRACE"}, &buf); err == nil {
		t.Error("NewFactory(level=TRACE) = nil, want error (case-sensitive)")
	}
	// Disabled short-circuits level parsing, mirroring sing-box
	// log.New (log/log.go:25-27): a disabled factory with a bogus
	// level constructs successfully and emits nothing. (Config
	// parsing is stricter and rejects the bogus level first.)
	h, err := NewFactory(context.Background(), Settings{Disabled: true, Level: "bogus"}, &buf)
	if err != nil {
		t.Fatalf("disabled NewFactory = %v, want success", err)
	}
	defer h.Close()
	emitAll(h, "castctl")
	if buf.Len() != 0 {
		t.Errorf("disabled factory emitted %q, want empty", buf.String())
	}
}

func TestFactoryPanicLevel(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	h, err := NewFactory(context.Background(), Settings{Level: "panic"}, &buf)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	// Error is suppressed at panic level.
	h.Logger("castctl").Error("level-probe-error")
	if buf.Len() != 0 {
		t.Errorf("panic-level factory emitted %q, want empty", buf.String())
	}
	// Panic panics with the formatted line (sing-box semantics);
	// the panic value must carry the marker.
	func() {
		defer func() {
			r := recover()
			if r == nil {
				t.Error("Panic did not panic")
				return
			}
			if !strings.Contains(fmt.Sprint(r), "level-probe-panic") {
				t.Errorf("panic value %q, want it to contain the marker", fmt.Sprint(r))
			}
		}()
		h.Logger("castctl").Panic("level-probe-panic")
	}()
}

func TestFactoryTimestampFormats(t *testing.T) {
	t.Parallel()
	fullTS := regexp.MustCompile(`^[+-]\d{4} \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} (TRACE|DEBUG|INFO|WARN|ERROR) `)
	relTS := regexp.MustCompile(`^(TRACE|DEBUG|INFO|WARN|ERROR)\[\d{4,}\] `)
	plain := regexp.MustCompile(`^(TRACE|DEBUG|INFO|WARN|ERROR) `)

	// Console, timestamp true: full timestamp prefix.
	var buf bytes.Buffer
	h, err := NewFactory(context.Background(), Settings{Level: "info", Timestamp: true}, &buf)
	if err != nil {
		t.Fatal(err)
	}
	h.Logger("castctl").Info("timestamp-probe")
	h.Close()
	lines := strings.Split(strings.TrimRight(stripANSI(buf.String()), "\n"), "\n")
	if len(lines) != 1 || !fullTS.MatchString(lines[0]) {
		t.Errorf("console timestamp=true line %q, want full-timestamp prefix", buf.String())
	}

	// Console, timestamp false: relative elapsed-seconds prefix
	// (sing-box semantics: false does NOT mean bare on console).
	buf.Reset()
	h, err = NewFactory(context.Background(), Settings{Level: "info", Timestamp: false}, &buf)
	if err != nil {
		t.Fatal(err)
	}
	h.Logger("castctl").Info("timestamp-probe")
	h.Close()
	lines = strings.Split(strings.TrimRight(stripANSI(buf.String()), "\n"), "\n")
	if len(lines) != 1 || !relTS.MatchString(lines[0]) {
		t.Errorf("console timestamp=false line %q, want relative [SSSS] prefix", buf.String())
	}

	// File, timestamp false: NO timestamp at all.
	path := filepath.Join(t.TempDir(), "castctl.log")
	h, err = NewFactory(context.Background(), Settings{Level: "info", Output: path, Timestamp: false}, &buf)
	if err != nil {
		t.Fatal(err)
	}
	h.Logger("castctl").Info("timestamp-probe")
	h.Close()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines = strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) != 1 || !plain.MatchString(lines[0]) {
		t.Errorf("file timestamp=false line %q, want bare level prefix", data)
	}

	// File, timestamp true: full timestamp prefix.
	path2 := filepath.Join(t.TempDir(), "castctl2.log")
	h, err = NewFactory(context.Background(), Settings{Level: "info", Output: path2, Timestamp: true}, &buf)
	if err != nil {
		t.Fatal(err)
	}
	h.Logger("castctl").Info("timestamp-probe")
	h.Close()
	data, err = os.ReadFile(path2)
	if err != nil {
		t.Fatal(err)
	}
	lines = strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) != 1 || !fullTS.MatchString(lines[0]) {
		t.Errorf("file timestamp=true line %q, want full-timestamp prefix", data)
	}
}

func TestFactoryDisabled(t *testing.T) {
	t.Parallel()
	// Stderr path: nothing emitted, at trace level (suppression
	// cannot be explained by level filtering).
	var buf bytes.Buffer
	h, err := NewFactory(context.Background(), Settings{Disabled: true, Level: "trace"}, &buf)
	if err != nil {
		t.Fatal(err)
	}
	emitAll(h, "castctl")
	h.Close()
	if buf.Len() != 0 {
		t.Errorf("disabled factory emitted %q, want empty", buf.String())
	}
	// File path: no file is created at all.
	path := filepath.Join(t.TempDir(), "castctl.log")
	h, err = NewFactory(context.Background(), Settings{Disabled: true, Level: "trace", Output: path}, &buf)
	if err != nil {
		t.Fatal(err)
	}
	emitAll(h, "castctl")
	h.Close()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("disabled factory created log file (stat err %v), want no file", err)
	}
}

func TestFactoryFileMode(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	// Created file: mode 0600, non-empty (mode alone on an empty
	// file proves nothing about capture).
	path := filepath.Join(t.TempDir(), "castctl.log")
	h, err := NewFactory(context.Background(), Settings{Level: "info", Output: path}, &buf)
	if err != nil {
		t.Fatal(err)
	}
	h.Logger("castctl").Info("file-mode-probe")
	h.Close()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() {
		t.Errorf("log path is not a regular file: %v", info.Mode())
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("created log file mode = %o, want 0600", info.Mode().Perm())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "file-mode-probe") {
		t.Errorf("log file %q, want it to contain the probe line", data)
	}

	// Pre-existing looser file: narrowed to 0600, content
	// appended (never truncated), mode never widened.
	path2 := filepath.Join(t.TempDir(), "existing.log")
	if err := os.WriteFile(path2, []byte("prior line\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	h, err = NewFactory(context.Background(), Settings{Level: "info", Output: path2}, &buf)
	if err != nil {
		t.Fatal(err)
	}
	h.Logger("castctl").Info("append-probe")
	h.Close()
	info, err = os.Stat(path2)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("pre-existing log file mode = %o, want narrowed to 0600", info.Mode().Perm())
	}
	data, err = os.ReadFile(path2)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "prior line\n") || !strings.Contains(string(data), "append-probe") {
		t.Errorf("log file %q, want prior content preserved plus appended probe", data)
	}

	// Bad path (missing parent): fail-closed error, no fallback.
	bad := filepath.Join(t.TempDir(), "no-such-dir", "castctl.log")
	if _, err := NewFactory(context.Background(), Settings{Level: "info", Output: bad}, &buf); err == nil {
		t.Error("NewFactory with a missing-parent log path = nil, want error")
	}
}

func TestFactoryOutputSpelling(t *testing.T) {
	t.Parallel()
	// "" and "stderr" both mean the supplied stderr writer.
	for _, out := range []string{"", "stderr"} {
		var buf bytes.Buffer
		h, err := NewFactory(context.Background(), Settings{Level: "info", Output: out}, &buf)
		if err != nil {
			t.Fatal(err)
		}
		h.Logger("castctl").Info("stderr-probe")
		h.Close()
		if !strings.Contains(buf.String(), "stderr-probe") {
			t.Errorf("output %q: buffer %q, want the probe line", out, buf.String())
		}
	}
	// A nil stderr writer falls back to the real os.Stderr (no
	// panic, no crash); nothing is asserted about its bytes.
	h, err := NewFactory(context.Background(), Settings{Level: "info"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	h.Close()
}

func TestFactoryLevelAccessor(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	h, err := NewFactory(context.Background(), Settings{Level: "warning"}, &buf)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	if h.Level() != singlog.LevelWarn {
		t.Errorf("Level() = %v, want LevelWarn for \"warning\"", h.Level())
	}
}

func TestEmitRedacts(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	h, err := NewFactory(context.Background(), Settings{Level: "trace"}, &buf)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	Emit(h.Logger("castctl"), context.Background(), singlog.LevelDebug,
		"event=ws_handshake status_token=error url=wss://gateway.example.invalid/v1/noise?vm_id="+fixVMID+"&auth_token="+fixHatchToken)
	got := buf.String()
	for _, v := range []string{fixVMID, fixHatchToken} {
		if strings.Contains(got, v) {
			t.Errorf("emitted output contains fixture value %q: %q", v, got)
		}
	}
	if !strings.Contains(got, "event=ws_handshake") {
		t.Errorf("emitted output %q, want the event marker", got)
	}
	if !strings.Contains(got, "auth_token=[redacted]") {
		t.Errorf("emitted output %q, want the redacted label to survive", got)
	}
}

func TestSlogBridgeFilteringAndRedaction(t *testing.T) {
	t.Parallel()
	// At warn: slog Debug suppressed, Warn visible, through the
	// ONE resolved level.
	var buf bytes.Buffer
	h, err := NewFactory(context.Background(), Settings{Level: "warn"}, &buf)
	if err != nil {
		t.Fatal(err)
	}
	sl := NewSlogLogger(h.Factory, "castctl")
	sl.Debug("slog-debug-probe")
	sl.Info("slog-info-probe")
	sl.Warn("slog-warn-probe", "seconds", 3)
	h.Close()
	got := stripANSI(buf.String())
	assertNotContains(t, got, "slog-debug-probe")
	assertNotContains(t, got, "slog-info-probe")
	assertContains(t, got, "slog-warn-probe")

	// At trace: slog Debug visible, and a fixture-bearing error
	// attr is stripped (vm_id case included) with the marker
	// surviving.
	buf.Reset()
	h, err = NewFactory(context.Background(), Settings{Level: "trace"}, &buf)
	if err != nil {
		t.Fatal(err)
	}
	sl = NewSlogLogger(h.Factory, "castctl")
	sl.Debug("slog-debug-probe")
	sl.Warn("gateway down", "err", errors.New("dial wss://gateway.example.invalid/v1/noise?vm_id="+fixVMID+"&auth_token="+fixHatchToken))
	sl.Info("retrying", "what", "fs.read", "err", errors.New("down: hatch_sess="+fixCookieVal))
	h.Close()
	got = stripANSI(buf.String())
	assertContains(t, got, "slog-debug-probe")
	for _, v := range []string{fixVMID, fixHatchToken, fixCookieVal} {
		if strings.Contains(got, v) {
			t.Errorf("slog output contains fixture value %q: %q", v, got)
		}
	}
	if !strings.Contains(got, "[redacted]") {
		t.Errorf("slog output %q, want a [redacted] marker (positive control)", got)
	}

	// slog levels map onto sing-box levels: a slog Error is
	// visible at error, suppressed at... (error is the threshold;
	// assert visibility, the warn case above covers suppression
	// of below-threshold lines).
	buf.Reset()
	h, err = NewFactory(context.Background(), Settings{Level: "error"}, &buf)
	if err != nil {
		t.Fatal(err)
	}
	sl = NewSlogLogger(h.Factory, "castctl")
	sl.Error("slog-error-probe", "err", errors.New("boom"))
	sl.Warn("slog-warn-probe")
	h.Close()
	got = stripANSI(buf.String())
	assertContains(t, got, "slog-error-probe")
	assertNotContains(t, got, "slog-warn-probe")
}
