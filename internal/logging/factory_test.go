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
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
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
		{"default empty means trace", "", []string{"level-probe-trace", "level-probe-debug", "level-probe-info", "level-probe-warn", "level-probe-error"}, nil},
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

	// Pre-existing file: appended (never truncated) WITHOUT any
	// chmod — castctl never changes the mode of a file it did
	// not create. The mode recorded before opening must be the
	// mode observed after, whatever it was.
	path2 := filepath.Join(t.TempDir(), "existing.log")
	if err := os.WriteFile(path2, []byte("prior line\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path2)
	if err != nil {
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
	if info.Mode().Perm() != before.Mode().Perm() {
		t.Errorf("pre-existing log file mode = %o, want unchanged %o (never chmod a foreign file)", info.Mode().Perm(), before.Mode().Perm())
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

// TestFactoryConcurrentWrites: sing-box emits from parallel
// goroutines with no writer lock of its own, so the factory must
// serialise writes itself. Concurrent Emit calls into a plain
// buffer must produce whole lines only (no interleaving), and
// must not trip the race detector. Red run: two goroutines
// writing to the shared buffer race in bytes.Buffer.
func TestFactoryConcurrentWrites(t *testing.T) {
	var buf bytes.Buffer
	handle, err := NewFactory(context.Background(), Settings{Level: "trace", Output: "stderr"}, &buf)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = handle.Close() }()
	logger := handle.Logger("conc")
	const goroutines, perGoroutine = 8, 25
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				Emit(logger, context.Background(), singlog.LevelInfo, "event=conc g="+strconv.Itoa(g)+" i="+strconv.Itoa(i))
			}
		}(g)
	}
	wg.Wait()
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != goroutines*perGoroutine {
		t.Fatalf("got %d lines, want %d:\n%s", len(lines), goroutines*perGoroutine, buf.String())
	}
	for _, line := range lines {
		if strings.Count(line, "event=conc") != 1 {
			t.Errorf("interleaved line: %q", line)
		}
	}
}

// TestFactoryRefusedPaths: the minimal A7 guard — refuse, BEFORE
// opening, when the resolved output equals a refused path (the
// config file or a cookies file), including through a symlinked
// alias. The protected files must be byte- and mode-identical
// afterwards. Symlinks to ordinary targets and non-regular files
// are NOT refused (Boss correction #2): they open and receive
// lines. All paths are scratch fixtures under t.TempDir.
func TestFactoryRefusedPaths(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	cookiePath := filepath.Join(dir, "cookies.txt")
	origConfig := "FIXTURE-CONFIG\n"
	origCookie := "FIXTURE-COOKIE\n"
	if err := os.WriteFile(configPath, []byte(origConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cookiePath, []byte(origCookie), 0o600); err != nil {
		t.Fatal(err)
	}
	refused := []string{configPath, cookiePath}

	// Direct equality: refused before open.
	for _, out := range []string{configPath, cookiePath} {
		if _, err := NewFactory(context.Background(), Settings{Level: "trace", Output: out, Refused: refused}, &buf); err == nil {
			t.Errorf("NewFactory(Output=%q, refused) = nil, want error", out)
		}
	}
	for _, p := range []string{configPath, cookiePath} {
		data, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		want := origConfig
		if p == cookiePath {
			want = origCookie
		}
		if string(data) != want {
			t.Errorf("protected file %s = %q, want untouched %q", p, data, want)
		}
		if info, err := os.Stat(p); err != nil || info.Mode().Perm() != 0o600 {
			t.Errorf("protected file %s mode = %v, want 0600 untouched", p, info)
		}
	}

	// Symlinked alias of the config file: still refused (the
	// guard compares resolved/canonical paths).
	alias := filepath.Join(dir, "alias.json")
	if err := os.Symlink(configPath, alias); err != nil {
		t.Fatal(err)
	}
	if _, err := NewFactory(context.Background(), Settings{Level: "trace", Output: alias, Refused: refused}, &buf); err == nil {
		t.Error("NewFactory(Output=symlink-to-config) = nil, want error")
	}
	data, _ := os.ReadFile(configPath)
	if string(data) != origConfig {
		t.Errorf("config via alias = %q, want untouched", data)
	}

	// Symlink to an ORDINARY target: NOT refused; the line
	// lands in the target through the link.
	target := filepath.Join(dir, "ordinary.log")
	if err := os.WriteFile(target, []byte("prior\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.log")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	h, err := NewFactory(context.Background(), Settings{Level: "info", Output: link, Refused: refused}, &buf)
	if err != nil {
		t.Fatalf("NewFactory(Output=symlink-to-ordinary) = %v, want success", err)
	}
	h.Logger("castctl").Info("symlink-target-probe")
	h.Close()
	data, _ = os.ReadFile(target)
	if !strings.Contains(string(data), "symlink-target-probe") {
		t.Errorf("symlink target %q, want the probe line", data)
	}

	// Non-regular file: NOT refused on that basis. /dev/null is
	// the portable character device; skip where it does not
	// exist (Windows).
	if _, err := os.Stat("/dev/null"); err == nil {
		h, err := NewFactory(context.Background(), Settings{Level: "info", Output: "/dev/null", Refused: refused}, &buf)
		if err != nil {
			t.Errorf("NewFactory(Output=/dev/null) = %v, want success (non-regular is not refused)", err)
		} else {
			h.Logger("castctl").Info("devnull-probe")
			h.Close()
		}
	}
}

// TestFactorySinkRedactsSingBoxLines: a line emitted through the
// sing-box logger WITHOUT going through logging.Emit — exactly
// how sing-box's own WG/DNS/TLS emissions reach the factory —
// must still be redacted, because the writer itself (safeWriter)
// applies SafeString. The fixture URL actually enters the call;
// the capture is scanned for every fixture value, on both the
// stderr buffer and a file destination.
func TestFactorySinkRedactsSingBoxLines(t *testing.T) {
	t.Parallel()
	line := "wireguard: setup failed: wss://gateway.example.invalid/v1/noise?vm_id=" + fixVMID + "&auth_token=" + fixHatchToken + " private_key=" + fixWGPriv + " public_key=" + fixWGPub
	scan := func(t *testing.T, got, where string) {
		t.Helper()
		if got == "" {
			t.Fatalf("%s capture empty: positive control failed", where)
		}
		for _, v := range []string{fixVMID, fixHatchToken, fixWGPriv, fixWGPub} {
			if strings.Contains(got, v) {
				t.Errorf("%s capture contains fixture value %q: %q", where, v, got)
			}
		}
		if !strings.Contains(got, "[redacted]") {
			t.Errorf("%s capture %q, want a [redacted] marker (positive control)", where, got)
		}
		// WG public key: at most the 8-char prefix may survive.
		if !strings.Contains(got, "public_key="+fixWGPub[:8]) {
			t.Errorf("%s capture %q, want the 8-char public-key prefix", where, got)
		}
	}

	var buf bytes.Buffer
	h, err := NewFactory(context.Background(), Settings{Level: "trace"}, &buf)
	if err != nil {
		t.Fatal(err)
	}
	h.Logger("wireguard").DebugContext(context.Background(), line)
	h.Close()
	scan(t, stripANSI(buf.String()), "stderr")

	path := filepath.Join(t.TempDir(), "sink.log")
	h, err = NewFactory(context.Background(), Settings{Level: "trace", Output: path}, &buf)
	if err != nil {
		t.Fatal(err)
	}
	h.Logger("wireguard").DebugContext(context.Background(), line)
	h.Close()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	scan(t, string(data), "file")
}

// TestFactoryOutputStdout: "stdout" names the real stdout
// (sing-box log/log.go:40-41). The factory must write the line
// to the process stdout — captured here by swapping os.Stdout
// for a pipe for the duration of the emission.
func TestFactoryOutputStdout(t *testing.T) {
	t.Parallel()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	defer func() { os.Stdout = old }()
	var buf bytes.Buffer
	h, err := NewFactory(context.Background(), Settings{Level: "info", Output: "stdout"}, &buf)
	if err != nil {
		t.Fatalf("NewFactory(Output=stdout) = %v", err)
	}
	h.Logger("castctl").Info("stdout-probe")
	h.Close()
	_ = w.Close()
	os.Stdout = old
	data, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "stdout-probe") {
		t.Errorf("stdout capture %q, want the probe line", data)
	}
}

// TestFactoryRefusedPathsByIdentity: the A7 guard compares FILE
// IDENTITY (dev/ino), not resolved path strings. A hardlink to a
// refused file shares its inode while its path differs, and a
// symlink to a not-yet-existing refused target resolves (through
// the parent directory) to the refused location while EvalSymlinks
// on either side fails. Both bypasses must be refused BEFORE any
// line is written, leaving the protected files byte- and
// mode-identical. All paths are scratch fixtures under t.TempDir;
// the refused cookies path in the absent-target case does not
// exist before the call and must not be created by it.
func TestFactoryRefusedPathsByIdentity(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	cookiePath := filepath.Join(dir, "cookies.txt")
	origConfig := "FIXTURE-CONFIG\n"
	origCookie := "FIXTURE-COOKIE\n"
	if err := os.WriteFile(configPath, []byte(origConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cookiePath, []byte(origCookie), 0o600); err != nil {
		t.Fatal(err)
	}
	refused := []string{configPath, cookiePath}

	assertProtected := func() {
		t.Helper()
		for p, want := range map[string]string{configPath: origConfig, cookiePath: origCookie} {
			data, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			if string(data) != want {
				t.Errorf("protected file %s = %q, want untouched %q", p, data, want)
			}
			info, err := os.Stat(p)
			if err != nil || info.Mode().Perm() != 0o600 {
				t.Errorf("protected file %s mode = %v, want 0600 untouched", p, info)
			}
		}
	}
	// refusedOutput asserts NewFactory errors for out, and that
	// emitting through a factory (if one were returned) could not
	// have happened: the error alone is the guard.
	refusedOutput := func(name, out string) {
		t.Helper()
		var buf bytes.Buffer
		if _, err := NewFactory(context.Background(), Settings{Level: "trace", Output: out, Refused: refused}, &buf); err == nil {
			t.Errorf("NewFactory(Output=%s %q) = nil, want error", name, out)
			return
		}
		assertProtected()
	}

	// Direct equality (already covered by TestFactoryRefusedPaths;
	// repeated here so this test alone covers all five shapes).
	refusedOutput("direct-config", configPath)

	// Hardlink to the config file: same inode, different path.
	hardConfig := filepath.Join(dir, "hard-config.json")
	if err := os.Link(configPath, hardConfig); err != nil {
		t.Fatal(err)
	}
	refusedOutput("hardlink-config", hardConfig)
	// Hardlink to the cookies file.
	hardCookie := filepath.Join(dir, "hard-cookies.txt")
	if err := os.Link(cookiePath, hardCookie); err != nil {
		t.Fatal(err)
	}
	refusedOutput("hardlink-cookies", hardCookie)

	// Symlink to an ABSENT cookies target: the refused path does
	// not exist yet; the link must still be refused, and the
	// target must not be created.
	absentTarget := filepath.Join(dir, "cookies-absent.txt")
	absentLink := filepath.Join(dir, "absent-link.txt")
	if err := os.Symlink(absentTarget, absentLink); err != nil {
		t.Fatal(err)
	}
	refusedAbsent := []string{configPath, absentTarget}
	var buf bytes.Buffer
	if _, err := NewFactory(context.Background(), Settings{Level: "trace", Output: absentLink, Refused: refusedAbsent}, &buf); err == nil {
		t.Error("NewFactory(Output=symlink-to-absent-cookies-target) = nil, want error")
	}
	if _, err := os.Lstat(absentTarget); err == nil {
		t.Errorf("absent refused target %s was created by the refused open", absentTarget)
	}
	assertProtected()

	// Symlink to the EXISTING config file (path-string guard
	// already catches this; identity must catch it too).
	alias := filepath.Join(dir, "alias2.json")
	if err := os.Symlink(configPath, alias); err != nil {
		t.Fatal(err)
	}
	refusedOutput("symlink-existing-config", alias)
}
