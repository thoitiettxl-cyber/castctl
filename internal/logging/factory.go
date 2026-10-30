// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package logging

import (
	"context"
	"io"
	"log/slog"
	"os"
	"sync"
	"time"

	singlog "github.com/sagernet/sing-box/log"
)

// Settings is the resolved log configuration for one invocation:
// the output of profile.ResolveLogSettings, translated into this
// package's own type so logging never imports the config parser.
// Level is one of trace/debug/info/warn/error/fatal/panic (or
// "warning", normalised by the caller); "" means the default warn.
// Output is "stderr" or a file path.
type Settings struct {
	Disabled  bool
	Level     string
	Output    string
	Timestamp bool
}

// singBoxTimestampFormat is the hard-coded layout sing-box's log
// factory uses (log/log.go:51). It is a literal here, not a
// package constant upstream, so it is repeated verbatim.
const singBoxTimestampFormat = "-0700 2006-01-02 15:04:05"

// Handle owns one sing-box log factory and, for file output, the
// log file handle. Close releases both; it is idempotent.
type Handle struct {
	Factory singlog.Factory
	level   singlog.Level
	file    *os.File

	mu     sync.Mutex
	closed bool
}

// NewFactory builds the single log factory for one invocation from
// resolved settings.
//
// Construction uses sing-box's own log factory
// (github.com/sagernet/sing-box/log, v1.14.4) so sing-box
// inbound/outbound/DNS logs appear at the configured level. Two
// deviations from calling log.New directly are deliberate and
// documented:
//
//   - File creation is owned by castctl, not by the factory's
//     Start(): sing-box opens a path output itself at Start() with
//     mode 0644 (log/observable.go:79). Castctl must create the
//     file 0600 (and narrow a pre-existing looser file), so the
//     factory is built with log.NewDefaultFactory
//     (log/observable.go:45-52) taking the already-opened *os.File
//     as its writer and an empty file path — Start() then opens
//     nothing. The formatter flags replicate log.New's exactly
//     (log/log.go:46-52): DisableColors for files, DisableTimestamp
//     only for files when timestamp is false, FullTimestamp from
//     the setting, the same TimestampFormat literal, and a
//     non-zero BaseTime (time.Now() at construction) anchoring the
//     relative console prefix.
//   - Console output is likewise built through NewDefaultFactory
//     with the caller's writer (Env stderr in production, a buffer
//     in tests). log.New's "stderr" branch writes to the real
//     os.Stderr unconditionally (log/log.go:38-39), which would
//     bypass hermetic capture and mix logs into command output
//     streams the caller owns. The writer is the only difference;
//     level, timestamp, and colour semantics are sing-box's.
//
// Disabled mirrors sing-box (log/log.go:25-27): the NOP factory is
// returned before any level parsing or file creation, so a
// disabled factory with a bogus level still constructs and emits
// nothing. (Config parsing is stricter and rejects bogus levels
// before this point; the short-circuit matters only for
// programmatic construction.)
//
// A bad file path (missing parent) is a fail-closed error: no
// fallback to stderr, matching sing-box Box behaviour where a
// Start() file error fails startup (box.go:539-545).
func NewFactory(ctx context.Context, s Settings, stderr io.Writer) (*Handle, error) {
	if s.Disabled {
		factory := singlog.NewNOPFactory()
		_ = factory.Start()
		return &Handle{Factory: factory, level: singlog.LevelTrace}, nil
	}
	levelName := s.Level
	if levelName == "" {
		levelName = "warn"
	}
	level, err := singlog.ParseLevel(levelName)
	if err != nil {
		return nil, err
	}
	var writer io.Writer
	var file *os.File
	isFile := false
	switch s.Output {
	case "", "stderr":
		writer = stderr
		if writer == nil {
			writer = os.Stderr
		}
	default:
		isFile = true
		f, err := openLogFile(s.Output)
		if err != nil {
			return nil, err
		}
		file = f
		writer = f
	}
	formatter := singlog.Formatter{
		BaseTime:         time.Now(),
		DisableColors:    isFile,
		DisableTimestamp: !s.Timestamp && isFile,
		FullTimestamp:    s.Timestamp,
		TimestampFormat:  singBoxTimestampFormat,
	}
	factory := singlog.NewDefaultFactory(ctx, formatter, writer, "", nil, false)
	factory.SetLevel(level)
	if err := factory.Start(); err != nil {
		if file != nil {
			_ = file.Close()
		}
		return nil, err
	}
	return &Handle{Factory: factory, level: level, file: file}, nil
}

// openLogFile opens path for append/create/write-only with mode
// 0600, then narrows a pre-existing looser file to 0600. It never
// truncates, never creates parent directories (sing-box creates
// none either), and never widens a stricter mode: only group/other
// permission bits trigger narrowing.
func openLogFile(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	if info.Mode().Perm()&0o077 != 0 {
		if err := f.Chmod(0o600); err != nil {
			_ = f.Close()
			return nil, err
		}
	}
	return f, nil
}

// Close closes the factory and, for file output, the log file.
// Idempotent: a second call is a no-op.
func (h *Handle) Close() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return nil
	}
	h.closed = true
	err := h.Factory.Close()
	if h.file != nil {
		if cerr := h.file.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}
	return err
}

// Level returns the factory's configured level.
func (h *Handle) Level() singlog.Level { return h.level }

// Logger returns a tagged logger from the factory.
func (h *Handle) Logger(tag string) singlog.ContextLogger {
	return h.Factory.NewLogger(tag)
}

// SlogLogger returns a *slog.Logger writing through the factory at
// the factory's level, for the slog world (conn.Muse, bootstrap).
// Its handler redacts every value through the SafeString boundary
// and filters by the ONE resolved level; see slog.go.
func (h *Handle) SlogLogger(tag string) *slog.Logger {
	return NewSlogLogger(h.Factory, tag)
}

// Emit logs one pre-composed castctl event line at level through
// logger, after the SafeString boundary. Callers compose only
// safe fields (tags, enums, protocol strings, parsed status
// tokens, counts); Emit is defence in depth, not a licence to
// pass URLs, headers, or options objects.
func Emit(logger singlog.ContextLogger, ctx context.Context, level singlog.Level, msg string) {
	msg = SafeString(msg)
	switch level {
	case singlog.LevelTrace:
		logger.TraceContext(ctx, msg)
	case singlog.LevelDebug:
		logger.DebugContext(ctx, msg)
	case singlog.LevelInfo:
		logger.InfoContext(ctx, msg)
	case singlog.LevelWarn:
		logger.WarnContext(ctx, msg)
	case singlog.LevelError:
		logger.ErrorContext(ctx, msg)
	case singlog.LevelFatal:
		logger.FatalContext(ctx, msg)
	case singlog.LevelPanic:
		logger.PanicContext(ctx, msg)
	default:
		logger.DebugContext(ctx, msg)
	}
}
