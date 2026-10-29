// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package commands

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/thoitiettxl-cyber/muse-cli/go/internal/gateway"
	"github.com/thoitiettxl-cyber/muse-cli/go/internal/profile"
)

// authImportResult is the success output of `auth import`: value-free
// JSON naming the profile and the file written. It never carries
// cookie names, values, or input substrings.
type authImportResult struct {
	OK          bool   `json:"ok"`
	Profile     string `json:"profile"`
	CookiesFile string `json:"cookies_file"`
	Backup      bool   `json:"backup"`
}

// cmdAuthImport implements `muse-cli auth import`: read cookies from
// stdin, validate them, and replace the active profile's cookies
// file. It is offline: it uses only resolveConfig/resolveActive and
// never the network runtime path, so no runtime, DNS, or connection
// machinery starts. Stdin is read fully before any filesystem access
// (config resolution is read-only; the only write is the cookies
// file). Every failure of this command exits 2: usage and stdin
// errors via errCode, config/profile errors as returned by the
// profile package (exit 2 via classifyError), and write errors via
// errCode. ParseCookies failures are converted to a fixed message
// rather than surfaced as typed-auth JSON: import validation is not
// a failure of an existing login.
//
// The command cannot panic on hostile input: every helper below is
// total over arbitrary byte strings (the only panics possible would
// come from a nil Env, which Run already guards). This tree has no
// CLI-boundary recover yet (PR4 owns it, R2 decision); until this
// branch merges after PR4 or rebases onto it, the recover is a
// merge-order dependency, not a property of this command.
func cmdAuthImport(_ context.Context, env *Env, g *globalOpts, args []string) error {
	ap := &argParser{defs: nil, helpText: authImportHelpText, prog: "muse-cli auth import"}
	p, helpShown, err := ap.parse(args, env.stdout())
	if err != nil {
		if pe, ok := err.(*parserError); ok {
			fmt.Fprintf(env.stderr(), "muse-cli: %s\n", pe.msg)
			return errCode(2, pe)
		}
		return err
	}
	if helpShown {
		return errHelpShown
	}
	if err := checkPositionals(p, nil, "auth import"); err != nil {
		return usageErr(err)
	}
	data, err := io.ReadAll(env.stdin())
	if err != nil {
		return errCode(2, fmt.Errorf("read stdin: %w", err))
	}
	stored, err := normaliseImportInput(data)
	if err != nil {
		return errCode(2, err)
	}
	if err := validateImportInput(stored); err != nil {
		return err
	}
	loc, err := resolveConfig(g, env, false)
	if err != nil {
		return err
	}
	prof, err := resolveActive(loc, g, env)
	if err != nil {
		return err
	}
	backup, err := profile.WriteCookiesFile(loc.ConfigDir, prof.Name, prof.CookiesFile, []byte(stored+"\n"))
	if err != nil {
		return errCodef(2, "write cookies file: %v", err)
	}
	return writeJSON(env.stdout(), authImportResult{
		OK:          true,
		Profile:     prof.Name,
		CookiesFile: prof.CookiesFile,
		Backup:      backup,
	})
}

// normaliseImportInput applies the import-boundary normalisation
// (D2): stdin must be valid UTF-8, CRLF and CR-only line endings
// become \n, and leading/trailing whitespace is stripped. The
// shared ParseCookies/LoadCookies parser is NOT modified: the
// CRLF/CR gap in its jar branch stays carried, and this boundary
// normalisation is what closes it for import. A BOM is not stripped
// here: BOM behaviour is exactly ParseCookies behaviour (a
// BOM-prefixed JSON object fails; a BOM-prefixed one-line paste
// parses with the BOM kept). The result is stored verbatim apart
// from this normalisation plus the single trailing newline added by
// the caller (D1).
func normaliseImportInput(raw []byte) (string, error) {
	if !utf8.Valid(raw) {
		return "", errors.New("stdin is not valid UTF-8")
	}
	s := strings.ReplaceAll(string(raw), "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	return strings.TrimSpace(s), nil
}

// validateImportInput checks the normalised input against the three
// accepted forms (via ParseCookies semantics, unmodified) and the
// hatch_sess rule (D4): a parsed pair with the exact name
// hatch_sess and a non-empty value, in whichever form the input
// parsed as — for JSON input the value must be a non-empty string
// (D4-CLARIFICATION, see jsonHasHatchPair). It returns an
// errCode(2) error with a fixed message that never echoes input
// bytes.
func validateImportInput(normalised string) error {
	if normalised == "" {
		return errCode(2, errors.New("no cookies on stdin"))
	}
	if _, err := gateway.ParseCookies(normalised, "<stdin>"); err != nil {
		return errCode(2, errors.New("could not parse cookies input"))
	}
	if !importHasHatchSess(normalised) {
		return errCode(2, errors.New("no hatch_sess cookie in input"))
	}
	return nil
}

// importHasHatchSess mirrors the ParseCookies dispatch order to
// find a parsed hatch_sess pair: JSON object first (only when the
// JSON decode succeeds and yields an object), then the one-line
// form (only when the hatch_sess=/datr= trigger is present), then
// the Netscape jar. Checking the rendered header string would be
// wrong: a hatch_sess mention inside another cookie's value would
// false-pass, and a value containing ";" would split mid-value.
// Each branch therefore inspects its own parsed pairs. Comment
// lines are excluded from consideration entirely: neither the
// qualifying-line scan nor the fallback may count a hatch_sess
// mention in a `#` line.
func importHasHatchSess(raw string) bool {
	if strings.HasPrefix(raw, "{") {
		if decided, ok := importJSONHasHatchSess(raw); decided {
			return ok
		}
	}
	if strings.Contains(raw, "hatch_sess=") || strings.Contains(raw, "datr=") {
		for _, line := range strings.Split(raw, "\n") {
			line = strings.TrimSpace(line)
			if line != "" && !isImportCommentLine(line) && !isJarRowLine(line) && strings.Contains(line, "=") && strings.Contains(line, ";") {
				return lineHasHatchPair(line)
			}
		}
		// No qualifying line: parse strict pairs from the
		// flattened non-comment, non-jar lines only. A `#`
		// mention must not produce a pair, and a jar row's
		// value column must not be scanned as a pair: jar rows
		// are evaluated only by the jar branch (column 6), and
		// splitting the flattened text on ";" only (never on
		// whitespace) means a jar value such as hatch_sess=FAKE
		// stays inside a segment whose name is not hatch_sess.
		var kept []string
		for _, line := range strings.Split(raw, "\n") {
			line = strings.TrimSpace(line)
			if line != "" && !isImportCommentLine(line) && !isJarRowLine(line) {
				kept = append(kept, line)
			}
		}
		return fallbackHasHatchPair(strings.Join(kept, " "))
	}
	for _, line := range strings.Split(raw, "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		cols := strings.Split(line, "\t")
		if len(cols) >= 7 && cols[5] == "hatch_sess" && strings.TrimSpace(cols[6]) != "" {
			return true
		}
	}
	return false
}

// importJSONHasHatchSess checks the JSON branch. It reports
// decided=false when the input is not a JSON object, so the caller
// falls through to the line forms exactly as ParseCookies does
// (invalid JSON and trailing data both fall through). A "cookies"
// value that is an object scopes the check to that object;
// otherwise all top-level entries are checked (ParseCookies joins
// them all in that case).
func importJSONHasHatchSess(raw string) (decided bool, ok bool) {
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return false, false
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return false, false
	}
	obj, isObj := v.(map[string]any)
	if !isObj {
		return false, false
	}
	if cookies, present := obj["cookies"]; present {
		if inner, isObj := cookies.(map[string]any); isObj {
			return true, jsonHasHatchPair(inner)
		}
	}
	return true, jsonHasHatchPair(obj)
}

// jsonHasHatchPair reports whether m holds hatch_sess with a
// non-empty STRING value (D4-CLARIFICATION): only a non-blank
// string counts. Numbers, booleans, arrays, objects, and null do
// NOT count, even though ParseCookies would render them as
// non-empty literals — the import check is deliberately stricter
// than the shared loader, so junk JSON cannot clobber working
// cookies. Duplicate keys collapse last-wins in the decoded map,
// matching ParseCookies.
func jsonHasHatchPair(m map[string]any) bool {
	v, ok := m["hatch_sess"]
	if !ok {
		return false
	}
	s, isStr := v.(string)
	return isStr && strings.TrimSpace(s) != ""
}

// isImportCommentLine reports whether line is a comment line: a
// `#` first after surrounding whitespace (and an optional BOM at
// the start of the input, which TrimSpace does not strip). Comment
// lines are excluded from the hatch check entirely.
func isImportCommentLine(line string) bool {
	line = strings.TrimSpace(line)
	line = strings.TrimPrefix(line, "\ufeff")
	return strings.HasPrefix(line, "#")
}

// isJarRowLine reports whether line is shaped like a Netscape jar
// row: at least seven tab-separated columns, the same threshold
// the jar branch uses. Jar rows are evaluated only by that branch
// (column 6); they must never be pair-scanned as one-line input,
// even when a value column contains ";" or "hatch_sess=".
func isJarRowLine(line string) bool {
	return len(strings.Split(line, "\t")) >= 7
}

// fallbackHasHatchPair checks the flattened no-qualifying-line
// text for a hatch_sess pair, strictly: split on ";", split each
// segment on its first "=", trim the name, and require the exact
// name hatch_sess with a non-blank value. Whitespace is not a pair
// separator here: a flattened jar row must not yield a pair from
// its value column. A leading BOM is stripped for the check only,
// matching lineHasHatchPair.
func fallbackHasHatchPair(s string) bool {
	s = strings.TrimPrefix(s, "\ufeff")
	for _, seg := range strings.Split(s, ";") {
		name, value, found := strings.Cut(seg, "=")
		if !found {
			continue
		}
		if strings.TrimSpace(name) == "hatch_sess" && strings.TrimSpace(value) != "" {
			return true
		}
	}
	return false
}

// lineHasHatchPair checks one one-line-form string for a
// hatch_sess pair: segments are split on ";" and whitespace (the
// fallback form is whitespace-joined), each pair splits on its
// first "=", and the name must be exactly hatch_sess with a
// non-blank value. A leading BOM is not part of the cookie name:
// it is stripped for the check only, matching ParseCookies, which
// returns a BOM-prefixed one-line paste as a valid header line;
// stored bytes keep the BOM verbatim.
func lineHasHatchPair(s string) bool {
	s = strings.TrimPrefix(s, "\ufeff")
	for _, seg := range strings.FieldsFunc(s, func(r rune) bool { return r == ';' || r == ' ' || r == '\t' || r == '\n' }) {
		name, value, found := strings.Cut(seg, "=")
		if !found {
			continue
		}
		if name == "hatch_sess" && strings.TrimSpace(value) != "" {
			return true
		}
	}
	return false
}
