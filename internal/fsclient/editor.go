// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package fsclient

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// ApplyReplace replaces occurrences of old with new in text,
// ported from fs.py (apply_replace). When old is absent it is an
// error naming the missing text, Python-style. count selects how
// many occurrences to replace: a negative count replaces all
// (Python's count=None), zero replaces none (but still errors when
// old is absent, as Python's `if old not in text` check runs
// first), and a positive count replaces at most that many, from
// the left.
func ApplyReplace(text, old, new string, count int) (string, error) {
	if !strings.Contains(text, old) {
		return "", fmt.Errorf("--replace: text not found: %s", pythonRepr(old))
	}
	n := count
	if n < 0 {
		n = -1
	}
	return strings.Replace(text, old, new, n), nil
}

// EditInEditor opens data in the user's editor and returns the
// file's contents afterwards, ported from fs.py (edit_in_editor).
// The editor is VISUAL, else EDITOR, else "vi"; an empty VISUAL
// falls through to EDITOR, as Python's `or` chain does. The data
// is written to a temporary file (with suffix appended to its
// name, e.g. ".md"), the editor runs with the terminal attached,
// and the temporary file is removed afterwards even when reading
// it back fails.
//
// The one intentional difference from Python (plan risk R6): the
// editor command is split shlex-style by SplitEditorCommand and
// executed directly, with the temporary file appended as the last
// argument. Python runs `editor + " " + shlex.quote(file)` through
// a shell. The editor's argv, the file it edits, and the ignored
// exit status are the same; no shell interprets the command. An
// editor that cannot be started (or exits non-zero) is ignored
// exactly as Python ignores subprocess.call's return value: the
// file is read back either way.
func EditInEditor(ctx context.Context, data []byte, suffix string) ([]byte, error) {
	editor := os.Getenv("VISUAL")
	if editor == "" {
		editor = os.Getenv("EDITOR")
	}
	if editor == "" {
		editor = "vi"
	}
	argv, err := SplitEditorCommand(editor)
	if err != nil {
		return nil, fmt.Errorf("fsclient: split editor command: %w", err)
	}
	if len(argv) == 0 {
		return nil, fmt.Errorf("fsclient: empty editor command")
	}
	tmp, err := os.CreateTemp("", "muse-cli-edit-*"+suffix)
	if err != nil {
		return nil, fmt.Errorf("fsclient: create temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return nil, fmt.Errorf("fsclient: write temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return nil, fmt.Errorf("fsclient: close temp file: %w", err)
	}
	cmd := exec.CommandContext(ctx, argv[0], append(argv[1:], tmpName)...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	// The editor's exit status is ignored, as in Python: a
	// non-zero exit (or a missing editor binary) still yields
	// whatever the file holds afterwards.
	_ = cmd.Run()
	after, err := os.ReadFile(tmpName)
	if err != nil {
		return nil, fmt.Errorf("fsclient: read temp file: %w", err)
	}
	return after, nil
}

// SplitEditorCommand splits an editor command line the way POSIX
// shlex.split does: whitespace separates words, single quotes
// protect everything inside them, double quotes protect everything
// except the backslash escapes for $, `, ", \ and newline, and a
// backslash outside quotes escapes the next character. An empty
// quoted string yields an empty word; an unbalanced quote is an
// error, as shlex.split raises ValueError for one. This is the
// splitting the direct-exec editor path needs for commands like
// `code --wait` or `"my editor" --flag` (plan risk R6).
func SplitEditorCommand(command string) ([]string, error) {
	var words []string
	var cur strings.Builder
	tokenStarted := false

	const (
		normal = iota
		inSingle
		inDouble
	)
	state := normal
	runes := []rune(command)
	flush := func() {
		if tokenStarted {
			words = append(words, cur.String())
			cur.Reset()
			tokenStarted = false
		}
	}

	for i := 0; i < len(runes); i++ {
		r := runes[i]
		switch state {
		case normal:
			switch {
			case r == ' ' || r == '\t' || r == '\n' || r == '\r':
				flush()
			case r == '\\':
				tokenStarted = true
				if i+1 < len(runes) {
					i++
					// A backslash-newline is a line
					// continuation: both vanish.
					if runes[i] != '\n' {
						cur.WriteRune(runes[i])
					}
				} else {
					// A trailing backslash has no escaped
					// character: shlex raises ValueError.
					return nil, fmt.Errorf("no escaped character")
				}
			case r == '\'':
				tokenStarted = true
				state = inSingle
			case r == '"':
				tokenStarted = true
				state = inDouble
			default:
				tokenStarted = true
				cur.WriteRune(r)
			}
		case inSingle:
			// Inside single quotes every character is
			// literal, including backslashes.
			if r == '\'' {
				state = normal
			} else {
				cur.WriteRune(r)
			}
		case inDouble:
			switch r {
			case '"':
				state = normal
			case '\\':
				if i+1 < len(runes) {
					next := runes[i+1]
					switch next {
					case '$', '`', '"', '\\', '\n':
						i++
						if next != '\n' {
							cur.WriteRune(next)
						}
					default:
						cur.WriteRune('\\')
					}
				} else {
					cur.WriteRune('\\')
				}
			default:
				cur.WriteRune(r)
			}
		}
	}
	if state != normal {
		return nil, fmt.Errorf("no closing quotation")
	}
	flush()
	return words, nil
}

// FmtSize renders a byte count, ported from fs.py (fmt_size): B
// with no decimal, K/M/G with one decimal ("1023B", "1.0K",
// "2.5M"). A nil size renders "-", as Python's `if n is None:
// return "-"` does. Sizes are compared against 1024 at each step
// exactly as Python's loop does, so 1048575 renders "1024.0K",
// not "1.0M".
func FmtSize(n *int64) string {
	if n == nil {
		return "-"
	}
	f := float64(*n)
	for _, u := range []string{"B", "K", "M", "G"} {
		if f < 1024 || u == "G" {
			if u == "B" {
				return fmt.Sprintf("%.0f%s", f, u)
			}
			return fmt.Sprintf("%.1f%s", f, u)
		}
		f /= 1024
	}
	return ""
}
