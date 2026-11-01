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
// at the API boundary, which strips only the pipeline's
// redacted vocabulary (values already replaced by the
// "<redacted>" marker at emission); it cannot strip a bare
// secret value sitting in the file. Cookie material stays out
// because the identity guard below refuses cookie-adjacent
// outputs, not because SafeString would catch it.
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
// reason. The identity guard refuses a log output that resolves
// to the config file, any cookies file, any cookies `.bak`
// sibling, any legacy-layout cookies file or its `.bak`
// (including a legacy config's own cookies_file override and
// its .bak, and legacy profiles reached through a symlinked
// profiles/<name> directory; a legacy config that cannot be
// read, or a profiles/ enumeration that fails, fails the
// gate closed), or any file under the config dir's
// profiles/ subtree (the factory's A7 rule, re-checked here
// because this endpoint opens the file itself). Paths are
// re-resolved per request with symlink evaluation, so a
// symlink or ".." reaching a refused file is refused even
// before the file exists; no verdict is cached across
// renames.
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
	// sing-box opens a relative output against the process
	// working directory; the server resolves the same way,
	// component by component so a symlink followed by ".."
	// cannot hide the real target.
	base := s.deps.ConfigDir
	if !filepath.IsAbs(settings.Output) {
		wd, werr := os.Getwd()
		if werr != nil {
			return "", false, "", errInternal()
		}
		base = wd
	}
	resolved := resolveAgainst(base, settings.Output)
	// A7 identity guard: never open the config file, a cookies
	// file, a cookies backup, or anything under profiles/ as
	// if it were a log.
	refused := []string{filepath.Join(s.deps.ConfigDir, "config.json")}
	for _, name := range cfg.ProfileNames() {
		if p := cfg.Profiles[name]; p != nil && p.CookiesFile != "" {
			refused = append(refused, p.CookiesFile, p.CookiesFile+".bak")
		}
	}
	legacyNames, enumErr := s.legacyProfileNames(cfg)
	if enumErr != nil {
		// The refused set cannot be enumerated: fail the
		// whole gate closed rather than serve a file that
		// might be a legacy cookies file.
		return "", true, "log_output_refused", nil
	}
	for _, name := range legacyNames {
		paths, perr := profile.ProfilePaths(s.deps.ConfigDir, name)
		if perr != nil {
			// The listed entry's refused set cannot be
			// computed (e.g. the name fails validation,
			// so no valid paths exist for it): fail the
			// whole gate closed rather than serve a file
			// that might be that entry's cookies file.
			// Every listed name carries a config.json
			// (see legacyProfileNames), so this cannot
			// trigger for an entry without one — an
			// invalid-name directory without a config.json
			// is still skipped at enumeration, not
			// refused here.
			return "", true, "log_output_refused", nil
		}
		refused = append(refused, paths.Cookies, paths.Cookies+".bak")
		// A legacy config's own cookies_file override
		// names a cookies file the default path does
		// not: refuse its raw forms too (R10). An
		// unreadable config fails the whole gate
		// closed — see legacyCookiesFileRefusals.
		forms, corrupt := legacyCookiesFileRefusals(s.deps.ConfigDir, paths)
		if corrupt {
			return "", true, "log_output_refused", nil
		}
		refused = append(refused, forms...)
	}
	profilesDir := resolvePathBestEffort(filepath.Join(s.deps.ConfigDir, "profiles"))
	if pathWithin(resolved, profilesDir) {
		return "", true, "log_output_refused", nil
	}
	// Raw configured values: the parser coerces some
	// cookies_file values to the profile's own path (an
	// in-dir value that is not the profile's own), but the
	// configured path is still the operator's cookies
	// location, and its .bak must be refused too. Both the
	// lexical form (so symlink aliases compare equal via
	// the best-effort check below) and the resolved form
	// are refused.
	if rawDoc, derr := decodeGeneric(load.raw); derr == nil {
		for _, v := range profileCookiesFiles(rawDoc) {
			lexical := v
			if !filepath.IsAbs(lexical) {
				lexical = filepath.Join(s.deps.ConfigDir, lexical)
			}
			lexical = filepath.Clean(lexical)
			resolvedRaw := resolveAgainst(s.deps.ConfigDir, v)
			refused = append(refused, lexical, lexical+".bak", resolvedRaw, resolvedRaw+".bak")
		}
	}
	resolvedReal := resolvePathBestEffort(resolved)
	for _, other := range refused {
		if sameFile(resolved, other) || resolvedReal == resolvePathBestEffort(other) {
			return "", true, "log_output_refused", nil
		}
	}
	return resolved, false, "", nil
}

// legacyCookiesFileRefusals returns the refusal forms for a
// legacy profile's OWN cookies_file override, read from
// profiles/<name>/config.json. The migrate-only parser and
// resolveCookiesFile are unexported, and the guard needs only
// the RAW value: the parser-resolved form of an override is
// always the profile's default cookies path (an in-dir value
// coerces there, and the default path sits under profiles/,
// refused by the subtree rule) or an outside absolute path
// (which the raw forms below name directly). The raw value is
// the spelling a log.output can name, so its lexical and
// resolved forms, plus their .bak siblings, are refused —
// the same treatment the single-file raw values in logGate
// get. The file is decoded with the same generic decode used
// for the single-file document; no new parser is introduced.
// corrupt is true when the file cannot be stat'ed as a regular
// file or read, cannot be decoded as a JSON object, or carries
// a cookies_file that is present but not a string (null counts
// as absent, as in the parser). The caller then refuses the
// whole gate: the refused set cannot be enumerated for that
// profile, so no file may be served as its log.
func legacyCookiesFileRefusals(configDir string, paths profile.Paths) (forms []string, corrupt bool) {
	st, err := os.Stat(paths.Config)
	if err != nil || !st.Mode().IsRegular() {
		return nil, true
	}
	data, err := os.ReadFile(paths.Config)
	if err != nil {
		return nil, true
	}
	doc, err := decodeGeneric(data)
	if err != nil {
		return nil, true
	}
	obj, ok := doc.(map[string]any)
	if !ok {
		return nil, true
	}
	v, ok := obj["cookies_file"]
	if !ok || v == nil {
		return nil, false
	}
	s, ok := v.(string)
	if !ok {
		return nil, true
	}
	if strings.TrimSpace(s) == "" {
		return nil, false
	}
	lexical := s
	if !filepath.IsAbs(lexical) {
		lexical = filepath.Join(configDir, lexical)
	}
	lexical = filepath.Clean(lexical)
	resolvedRaw := resolveAgainst(configDir, s)
	return []string{lexical, lexical + ".bak", resolvedRaw, resolvedRaw + ".bak"}, false
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
		n, err := strconv.Atoi(q)
		if err != nil || n < 1 || n > maxLogLimit {
			writeAPIError(w, errValidation("invalid limit"))
			return
		}
		limit = n
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
	// lands). windowStart/windowEnd are the file offsets of the
	// kept text.
	windowStart := startOffset
	windowEnd := size
	text := string(data)
	if startOffset > 0 && len(text) > 0 {
		one := make([]byte, 1)
		if _, err := f.ReadAt(one, startOffset-1); err == nil && one[0] != '\n' {
			if i := strings.IndexByte(text, '\n'); i >= 0 {
				windowStart += int64(i) + 1
				text = text[i+1:]
			} else {
				text = ""
			}
		}
	}
	if len(text) > 0 && !strings.HasSuffix(text, "\n") {
		if i := strings.LastIndexByte(text, '\n'); i >= 0 {
			windowEnd = windowStart + int64(i) + 1
			text = text[:i+1]
		} else {
			windowEnd = windowStart
			text = ""
		}
	}
	// Split into lines with their end offsets, so the cursor
	// advances only past delivered lines.
	type logLine struct {
		text string
		end  int64
	}
	var lines []logLine
	if text != "" {
		off := windowStart
		for _, raw := range strings.Split(strings.TrimSuffix(text, "\n"), "\n") {
			off += int64(len(raw)) + 1
			lines = append(lines, logLine{text: raw, end: off})
		}
	}
	// Filter BEFORE truncating: the level filter must not
	// discard entries the window never delivered.
	var filtered []logLine
	for _, ln := range lines {
		entry := parseLogLine(ln.text)
		if levelFilter != "" && entry.Level != levelFilter {
			continue
		}
		filtered = append(filtered, ln)
	}
	// Tail reads keep the LAST limit lines; cursor reads keep
	// the FIRST limit lines (oldest-first append order). more
	// is true only when undelivered filtered lines remain in
	// this window, or bytes remain past the window end; the
	// cursor is the end offset of the last delivered line, or
	// the window end when nothing remains undelivered.
	var delivered []logLine
	more := false
	nextCursor := windowEnd
	if cursor == "" && len(filtered) > limit {
		delivered = filtered[len(filtered)-limit:]
	} else if cursor != "" && len(filtered) > limit {
		delivered = filtered[:limit]
		more = true
		nextCursor = delivered[len(delivered)-1].end
	} else {
		delivered = filtered
	}
	if !more && windowEnd < size {
		more = true
		nextCursor = windowEnd
	}
	entries := make([]logEntry, 0, len(delivered))
	for _, ln := range delivered {
		if ln.text == "" {
			continue
		}
		entries = append(entries, parseLogLine(ln.text))
	}
	writeEnvelope(w, http.StatusOK, map[string]any{
		"disabled":    false,
		"entries":     entries,
		"next_cursor": strconv.FormatInt(nextCursor, 10),
		"more":        more,
	})
}

// handleLogsDeleteRefused refuses DELETE /logs: truncating a
// live log file from the web UI would destroy the only record
// of the server's own emissions. The frozen logsApi.clear
// client has no call site; the refusal is explicit, not silent.
func handleLogsDeleteRefused(w http.ResponseWriter, r *http.Request) {
	writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "logs cannot be cleared from the web UI")
}
