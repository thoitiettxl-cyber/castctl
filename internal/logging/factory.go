// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package logging

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	singlog "github.com/sagernet/sing-box/log"
)

// Settings is the resolved log configuration for one invocation:
// the output of profile.ResolveLogSettings, translated into this
// package's own type so logging never imports the config parser.
// Level is one of trace/debug/info/warn/error/fatal/panic (or
// "warning", normalised by the caller); "" means sing-box's
// default, trace (log/log.go:67-69). Output follows sing-box
// exactly (log/log.go:32-45): "" or "stderr" means the supplied
// stderr writer, "stdout" means the real stdout, any other
// string is a file path. Refused lists absolute paths the
// factory must never open as a log file (the config file and
// cookies files, supplied by the runtime); see openLogFile.
type Settings struct {
	Disabled  bool
	Level     string
	Output    string
	Timestamp bool
	Refused   []string
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
//     file 0600, so the factory is built with
//     log.NewDefaultFactory (log/observable.go:45-52) taking
//     the already-opened *os.File as its writer and an empty
//     file path — Start() then opens nothing. A pre-existing
//     file that passes the openLogFile guard is appended to
//     WITHOUT any chmod: castctl never changes the mode of a
//     file it did not create. The formatter flags replicate
//     log.New's exactly
//     (log/log.go:46-52): DisableColors for files, DisableTimestamp
//     only for files when timestamp is false, FullTimestamp from
//     the setting, the same TimestampFormat literal, and a
//     non-zero BaseTime (time.Now() at construction) anchoring the
//     relative console prefix.
//
//   - Console output is likewise built through NewDefaultFactory
//     with the caller's writer (Env stderr in production, a buffer
//     in tests). log.New's "stderr" branch writes to the real
//     os.Stderr unconditionally (log/log.go:38-39), which would
//     bypass hermetic capture and mix logs into command output
//     streams the caller owns. The writer is the only difference;
//     level, timestamp, and colour semantics are sing-box's.
//
//   - Redaction at the sink: every formatted line passes
//     SafeString in the writer itself (safeWriter, below), so
//     sing-box's own emissions — which reach the writer
//     directly, never through logging.Emit — cannot bypass
//     the redaction boundary. Castctl's own lines are
//     redacted twice (at Emit and here); SafeString is
//     idempotent, so that is harmless. The sink sees one
//     Write per formatted line (sing-box log/observable.go
//     writes one formatted []byte per entry), which is what
//     makes per-chunk redaction complete here.
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
		// Sing-box default: an empty level means trace
		// (log/log.go:67-69), not warn, not info.
		levelName = "trace"
	}
	level, err := singlog.ParseLevel(levelName)
	if err != nil {
		// Never echo the supplied level: sing-box's
		// ParseLevel error embeds it verbatim ("unknown log
		// level: <value>", log/level.go:57), and a pasted
		// secret must never surface through it. The
		// production paths validate first, so this fires
		// only for programmatic construction — the fixed
		// message is the whole contract.
		return nil, errors.New("logging: unknown log level (expected trace, debug, info, warn, warning, error, fatal, or panic)")
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
	case "stdout":
		writer = os.Stdout
	default:
		isFile = true
		f, err := openLogFile(s.Output, s.Refused)
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
	// Sing-box's factory writes to its writer from concurrent
	// goroutines with no lock of its own (observable.go:155
	// calls writer.Write directly): the writer must be safe for
	// concurrent use. os.Stderr and *os.File are; an arbitrary
	// caller writer (a test buffer) is not — serialise every
	// write here so one formatted line is never interleaved
	// with another, whatever the caller passes.
	factory := singlog.NewDefaultFactory(ctx, formatter, &lockedWriter{w: &safeWriter{w: writer}}, "", nil, false)
	factory.SetLevel(level)
	if err := factory.Start(); err != nil {
		if file != nil {
			_ = file.Close()
		}
		return nil, err
	}
	return &Handle{Factory: factory, level: level, file: file}, nil
}

// lockedWriter serialises concurrent writes to an underlying
// writer. One Write call is one formatted log line; the mutex
// keeps lines whole when sing-box emits from parallel goroutines.
type lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

// safeWriter is the redaction sink: every chunk (one formatted
// log line, per the sing-box writer contract) passes SafeString
// before reaching the underlying writer, so no line — castctl's
// or sing-box's — can carry a labelled secret to the log
// destination. It reports the original length on success: the
// caller (sing-box) discards write results, and a redacted line
// is shorter than its input without being a short write.
type safeWriter struct {
	w io.Writer
}

func (s *safeWriter) Write(p []byte) (int, error) {
	redacted := SafeString(string(p))
	if _, err := io.WriteString(s.w, redacted); err != nil {
		return 0, err
	}
	return len(p), nil
}

// openLogFile opens path for append/create/write-only with mode
// 0600 on creation (sing-box opens its path output with
// O_APPEND|O_CREATE|O_WRONLY, log/observable.go:79; castctl
// differs only in the 0600 creation mode). It never truncates
// and never creates parent directories (sing-box creates none
// either). A pre-existing file is appended to WITHOUT any
// chmod: castctl never changes the mode of a file it did not
// create.
//
// The ONLY guard is the minimal A7 check: refuse, before
// opening, when the output file's IDENTITY equals a refused
// file's identity (castctl's own config file or a cookies
// file). Identity is the resolved path AND the file's
// dev/ino: a hardlink to a refused file shares its inode
// while its path differs, and a symlink to a not-yet-existing
// refused target resolves (through its parent directory) to
// the refused location. After opening, the identity is
// RE-CHECKED against freshly collected refused identities
// via fstat, and the open is refused (file closed, no line
// written) if the opened file is a refused file — this closes
// the check-then-open swap window as far as an identity check
// can. There are NO other path restrictions: symlinks to
// other targets and non-regular files are NOT refused (Boss
// correction #2).
func openLogFile(path string, refused []string) (*os.File, error) {
	outID, ok := collectFileIdentity(path)
	if !ok {
		return nil, errors.New("logging: cannot resolve log output path")
	}
	refusedIDs := collectRefusedIdentities(refused)
	for _, id := range refusedIDs {
		if identitiesEqual(outID, id) {
			return nil, errRefusedLogOutput
		}
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	// Re-check after open: a swap between the check above and
	// the open that redirected the path at a refused file is
	// caught here, before any line is written. Refused
	// identities are collected fresh (a refused file created
	// or replaced in the window is seen as it now is), and
	// the opened file's own fstat identity is compared too.
	if fi, statErr := f.Stat(); statErr == nil {
		freshRefused := collectRefusedIdentities(refused)
		outID2, ok2 := collectFileIdentity(path)
		for _, id := range freshRefused {
			if id.info != nil && os.SameFile(fi, id.info) {
				_ = f.Close()
				return nil, errRefusedLogOutput
			}
			if ok2 && identitiesEqual(outID2, id) {
				_ = f.Close()
				return nil, errRefusedLogOutput
			}
		}
	} else {
		_ = f.Close()
		return nil, statErr
	}
	return f, nil
}

// errRefusedLogOutput is the fixed refusal error: it names no
// path, so a refused output never echoes a config/cookies path.
var errRefusedLogOutput = errors.New("logging: refusing to open a protected file as the log output")

// fileIdentity is one path's identity for the A7 guard: its
// symlink-resolved location plus, when the file exists, its
// os.FileInfo (dev/ino comparison via os.SameFile).
type fileIdentity struct {
	resolved string
	info     os.FileInfo
}

// collectFileIdentity resolves path and stats the resolved
// location. It reports false only when the path cannot be
// resolved at all (a symlink cycle); an absent file resolves
// fine (info is nil) via its parent directory.
func collectFileIdentity(path string) (fileIdentity, bool) {
	resolved, err := resolveLogPath(path)
	if err != nil {
		return fileIdentity{}, false
	}
	id := fileIdentity{resolved: resolved}
	if fi, err := os.Stat(resolved); err == nil {
		id.info = fi
	}
	return id, true
}

// collectRefusedIdentities resolves every non-empty refused
// path; an unresolvable entry is skipped (it cannot be proven
// identical, and the output path's own resolution failure
// already fails closed above).
func collectRefusedIdentities(refused []string) []fileIdentity {
	var out []fileIdentity
	for _, r := range refused {
		if r == "" {
			continue
		}
		if id, ok := collectFileIdentity(r); ok {
			out = append(out, id)
		}
	}
	return out
}

// identitiesEqual reports whether two identities denote the
// same file: the same resolved location (covers an absent
// target, which has no inode yet), or the same existing file
// by dev/ino (covers hardlinks, whose paths differ).
func identitiesEqual(a, b fileIdentity) bool {
	if a.resolved != "" && a.resolved == b.resolved {
		return true
	}
	return a.info != nil && b.info != nil && os.SameFile(a.info, b.info)
}

// resolveLogPath returns the canonical form of path for
// identity comparison: symlinks are resolved component by
// component, including a final symlink whose target does not
// exist yet — the longest existing prefix is resolved and
// the remainder appended, so a symlink to an absent target
// resolves to the target's location instead of to the link's
// own path. A symlink cycle is an error (fail closed).
func resolveLogPath(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	return resolveIdentity(abs, 0)
}

func resolveIdentity(cur string, depth int) (string, error) {
	if depth > 40 {
		return "", errors.New("logging: too many symlinks resolving log path")
	}
	fi, err := os.Lstat(cur)
	if err != nil {
		// Absent: resolve the parent, then append the base
		// name. The parent chain terminates at the root,
		// which always exists.
		parent := filepath.Dir(cur)
		if parent == cur {
			return cur, nil
		}
		resolvedParent, err := resolveIdentity(parent, depth+1)
		if err != nil {
			return "", err
		}
		return filepath.Join(resolvedParent, filepath.Base(cur)), nil
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		target, err := os.Readlink(cur)
		if err != nil {
			return cur, nil
		}
		if !filepath.IsAbs(target) {
			target = filepath.Join(filepath.Dir(cur), target)
		}
		return resolveIdentity(filepath.Clean(target), depth+1)
	}
	// Exists and is not itself a symlink: EvalSymlinks
	// resolves any symlinked ancestors.
	if resolved, err := filepath.EvalSymlinks(cur); err == nil {
		return resolved, nil
	}
	return cur, nil
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
// pass URLs, headers, or options objects. A caller composing
// error text into a line at ANY level including trace must use
// SummarizeErr for the error (status + class + length only for
// a body-carrying error): Emit cannot tell body bytes from prose
// in a pre-composed string, and SafeString alone strips only
// labelled secrets, not arbitrary body text.
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
