// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package webui

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/thoitiettxl-cyber/castctl/internal/logging"
	"github.com/thoitiettxl-cyber/castctl/internal/profile"
)

// Live logs: tail of the configured log FILE, gated exactly like
// the log pipeline (docs/config.md). No log block, a disabled
// block, or stderr/stdout output means the page reports
// disabled: no ring is invented and no logging is started to
// serve the page. Every returned line passes logging.SafeString
// at the API boundary (the second boundary after emission), so
// a marker secret in a fixture body can never reach a response.
// No raw server/peer response body is ever emitted: the file
// itself holds only the allowlisted summaries the pipeline
// emits, and this endpoint adds no body extraction of its own.
//
// The cursor is a decimal byte offset into the file. A request
// without a cursor returns the tail (last `limit` lines);
// a request with a cursor returns lines appended after it.
// The frontend polls without a cursor (replace) and loads more
// with the returned cursor (append).

const (
	maxLogReadBytes = 256 << 10
	maxLogLimit     = 500
	defaultLogLimit = 100
)

// logGate resolves the live-log gate for the current config. It
// returns the log file path, or disabled=true with a fixed
// reason. The identity guard refuses a log output that IS the
// config file or any cookies file (the factory's A7 rule,
// re-checked here because this endpoint opens the file itself).
func (s *Server) logGate() (path string, disabled bool, reason string, err error) {
	load, err := s.loadConfig()
	if err != nil {
		return "", false, "", err
	}
	cfg, err := s.parseLoaded(load)
	if err != nil {
		return "", false, "", err
	}
	settings, err := profile.ResolveLogSettings(cfg, "", false)
	if err != nil {
		return "", false, "", err
	}
	if settings.Disabled {
		return "", true, "logging_disabled", nil
	}
	switch settings.Output {
	case "", "stderr", "stdout":
		return "", true, "log_output_not_file", nil
	}
	resolved := settings.Output
	if !filepath.IsAbs(resolved) {
		// sing-box opens a relative output against the process
		// working directory; the server resolves the same way.
		wd, werr := os.Getwd()
		if werr != nil {
			return "", false, "", errInternal()
		}
		resolved = filepath.Join(wd, resolved)
	}
	resolved = filepath.Clean(resolved)
	// A7 identity guard: never open the config file or a cookies
	// file as if it were a log.
	refused := []string{filepath.Join(s.deps.ConfigDir, "config.json")}
	for _, name := range cfg.ProfileNames() {
		if p := cfg.Profiles[name]; p != nil && p.CookiesFile != "" {
			refused = append(refused, p.CookiesFile)
		}
	}
	for _, other := range refused {
		if sameFile(resolved, other) {
			return "", true, "log_output_refused", nil
		}
	}
	return resolved, false, "", nil
}

// sameFile reports whether two paths name the same file: by
// device/inode when both exist, else by resolved lexical path.
// A stat failure on either side is "not the same file" only
// when the lexical paths also differ.
func sameFile(a, b string) bool {
	ai, aerr := os.Stat(a)
	bi, berr := os.Stat(b)
	if aerr == nil && berr == nil {
		return os.SameFile(ai, bi)
	}
	ra, err := filepath.EvalSymlinks(a)
	if err != nil {
		ra = filepath.Clean(a)
	}
	rb, err := filepath.EvalSymlinks(b)
	if err != nil {
		rb = filepath.Clean(b)
	}
	return ra == rb
}

var (
	// Full-timestamp form: "+0700 2026-10-31 13:00:00 INFO msg"
	// (singBoxTimestampFormat "-0700 2006-01-02 15:04:05").
	reLogFullTS = regexp.MustCompile(`^([+-]\d{4} \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (TRACE|DEBUG|INFO|WARN|WARNING|ERROR|FATAL|PANIC) (.*)$`)
	// No-timestamp form: "INFO msg" (files with timestamp:false).
	reLogBare = regexp.MustCompile(`^(TRACE|DEBUG|INFO|WARN|WARNING|ERROR|FATAL|PANIC) (.*)$`)
	// Relative-seconds form: "INFO[0001] msg" (console shape).
	reLogRelative = regexp.MustCompile(`^(TRACE|DEBUG|INFO|WARN|WARNING|ERROR|FATAL|PANIC)\[\d+\] (.*)$`)
	// Tag prefix inside the message: "tag: rest".
	reLogTag = regexp.MustCompile(`^([A-Za-z0-9_.\-]+): (.*)$`)
	// ANSI colour escapes (never expected in file output, which
	// disables colours, but stripped defensively before parsing).
	reANSI = regexp.MustCompile("\x1b\\[[0-9;]*m")
)

// logEntry is the frozen LogEntry shape.
type logEntry struct {
	TS      string `json:"ts"`
	Level   string `json:"level"`
	Kind    string `json:"kind"`
	Message string `json:"message"`
}

// parseLogLine parses one log file line best-effort. Unparseable
// lines keep level/kind empty and carry the SafeString'd line
// as the message: nothing is dropped silently, and nothing
// unredacted reaches the response.
func parseLogLine(line string) logEntry {
	line = reANSI.ReplaceAllString(line, "")
	line = strings.TrimSuffix(line, "\r")
	ts, level, rest := "", "", line
	if m := reLogFullTS.FindStringSubmatch(line); m != nil {
		ts, level, rest = m[1], normalizeLevel(m[2]), m[3]
	} else if m := reLogRelative.FindStringSubmatch(line); m != nil {
		level, rest = normalizeLevel(m[1]), m[2]
	} else if m := reLogBare.FindStringSubmatch(line); m != nil {
		level, rest = normalizeLevel(m[1]), m[2]
	}
	kind := ""
	if m := reLogTag.FindStringSubmatch(rest); m != nil && level != "" {
		kind, rest = m[1], m[2]
	}
	return logEntry{
		TS:      logging.SafeString(ts),
		Level:   logging.SafeString(level),
		Kind:    logging.SafeString(kind),
		Message: logging.SafeString(rest),
	}
}

func normalizeLevel(level string) string {
	if level == "WARNING" {
		return "warn"
	}
	return strings.ToLower(level)
}

func (s *Server) handleGetLogs(w http.ResponseWriter, r *http.Request) {
	path, disabled, reason, err := s.logGate()
	if err != nil {
		writeAPIError(w, err)
		return
	}
	if disabled {
		writeEnvelope(w, http.StatusOK, map[string]any{
			"disabled":    true,
			"reason":      reason,
			"entries":     []logEntry{},
			"next_cursor": nil,
			"more":        false,
		})
		return
	}
	limit := defaultLogLimit
	if q := r.URL.Query().Get("limit"); q != "" {
		if n, err := strconv.Atoi(q); err == nil && n >= 1 && n <= maxLogLimit {
			limit = n
		}
	}
	levelFilter := r.URL.Query().Get("level")
	if levelFilter == "all" {
		levelFilter = ""
	}
	levelFilter = normalizeLevel(strings.ToUpper(levelFilter))
	if levelFilter == "warning" {
		levelFilter = "warn"
	}

	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			// The file is created on first write: no entries
			// yet is an empty page, not an error.
			writeEnvelope(w, http.StatusOK, map[string]any{
				"disabled":    false,
				"entries":     []logEntry{},
				"next_cursor": "0",
				"more":        false,
			})
			return
		}
		writeAPIError(w, errInternal())
		return
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		writeAPIError(w, errInternal())
		return
	}
	size := info.Size()

	var data []byte
	var startOffset int64
	cursor := r.URL.Query().Get("cursor")
	if cursor != "" {
		offset, err := strconv.ParseInt(cursor, 10, 64)
		if err != nil || offset < 0 {
			writeAPIError(w, errValidation("invalid cursor"))
			return
		}
		if offset >= size {
			// No new bytes: return the requested cursor
			// unchanged so the next poll resumes at the same
			// line boundary (a cursor is always a boundary;
			// see the boundary logic below).
			writeEnvelope(w, http.StatusOK, map[string]any{
				"disabled":    false,
				"entries":     []logEntry{},
				"next_cursor": strconv.FormatInt(offset, 10),
				"more":        false,
			})
			return
		}
		startOffset = offset
		// A cursor read is bounded by the byte cap and the line
		// limit; it never re-reads the tail.
		n := size - offset
		if n > maxLogReadBytes {
			n = maxLogReadBytes
		}
		data = make([]byte, n)
		if _, err := f.ReadAt(data, offset); err != nil && err != io.EOF {
			writeAPIError(w, errInternal())
			return
		}
	} else {
		startOffset = 0
		if size > maxLogReadBytes {
			startOffset = size - maxLogReadBytes
		}
		data = make([]byte, size-startOffset)
		if _, err := f.ReadAt(data, startOffset); err != nil && err != io.EOF {
			writeAPIError(w, errInternal())
			return
		}
	}

	// Line-boundary discipline: a cursor is always the offset
	// just after a newline. Drop a leading partial line when the
	// window starts mid-line, and drop a trailing partial line
	// (it is delivered whole on the poll after its newline
	// lands). endCursor is the boundary the next poll resumes
	// from.
	endCursor := size
	text := string(data)
	if startOffset > 0 && len(text) > 0 {
		one := make([]byte, 1)
		if _, err := f.ReadAt(one, startOffset-1); err == nil && one[0] != '\n' {
			if i := strings.IndexByte(text, '\n'); i >= 0 {
				text = text[i+1:]
			} else {
				text = ""
			}
		}
	}
	if len(text) > 0 && !strings.HasSuffix(text, "\n") {
		if i := strings.LastIndexByte(text, '\n'); i >= 0 {
			endCursor = startOffset + int64(len(data)) - int64(len(text)) + int64(i) + 1
			text = text[:i+1]
		} else {
			endCursor = startOffset
			text = ""
		}
	}
	var lines []string
	if text != "" {
		lines = strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	}
	// Tail reads keep the LAST limit lines; cursor reads keep
	// the FIRST limit lines (oldest-first append order).
	if cursor == "" && len(lines) > limit {
		lines = lines[len(lines)-limit:]
	} else if cursor != "" && len(lines) > limit {
		lines = lines[:limit]
	}
	entries := make([]logEntry, 0, len(lines))
	for _, line := range lines {
		if line == "" {
			continue
		}
		entry := parseLogLine(line)
		if levelFilter != "" && entry.Level != levelFilter {
			continue
		}
		entries = append(entries, entry)
	}
	writeEnvelope(w, http.StatusOK, map[string]any{
		"disabled":    false,
		"entries":     entries,
		"next_cursor": strconv.FormatInt(endCursor, 10),
		"more":        false,
	})
}

// handleLogsDeleteRefused refuses DELETE /logs: truncating a
// live log file from the web UI would destroy the only record
// of the server's own emissions. The frozen logsApi.clear
// client has no call site; the refusal is explicit, not silent.
func handleLogsDeleteRefused(w http.ResponseWriter, r *http.Request) {
	writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "logs cannot be cleared from the web UI")
}
