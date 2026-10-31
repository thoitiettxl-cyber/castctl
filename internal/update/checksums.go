// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package update

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"unicode/utf8"
)

// Checksums file parsing.
//
// The release workflow generates checksums.txt with GNU sha256sum over
// the four archives, sorted by filename (release.yaml checksums job).
// The exact separator bytes were never measured live (the file body
// was never downloaded in research), so this parser accepts every
// standard sha256sum output shape: two-space text mode, the ` *`
// binary-mode marker, and single-space/tab separators. It matches by
// EXACT filename only, never by substring, and rejects
// self-contradictory files.
//
// Pinned rules (failure-report §1):
//   - uppercase hex is accepted only because it decodes to the same
//     bytes (hex.DecodeString is case-insensitive; comparison is over
//     decoded bytes, never over hex strings);
//   - identical duplicate lines are idempotent; conflicting or
//     malformed duplicates refuse the whole file;
//   - CRLF, a missing trailing newline, and blank lines are tolerated;
//   - a leading UTF-8 BOM is stripped from the first line;
//   - NUL bytes, invalid UTF-8, escaped (`\`-prefixed) lines, and any
//     malformed line refuse the whole file;
//   - extra entries for other files are ignored; only the exact asset
//     filename is ever looked up.

// maxChecksumsBytes bounds the checksums file: the real file is four
// lines (~416 bytes). Anything larger is not a checksums file.
const maxChecksumsBytes = 64 * 1024

// ParseChecksums parses sha256sum-format data into filename -> digest
// bytes. The returned digests are always 32 bytes.
func ParseChecksums(data []byte) (map[string][]byte, error) {
	if len(data) > maxChecksumsBytes {
		return nil, errors.New("update: checksums file too large")
	}
	if bytes.IndexByte(data, 0) >= 0 {
		return nil, errors.New("update: checksums file contains NUL bytes")
	}
	if !utf8.Valid(data) {
		return nil, errors.New("update: checksums file is not valid UTF-8")
	}
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	out := map[string][]byte{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSuffix(line, "\r")
		if strings.Trim(line, " \t") == "" {
			continue // blank line
		}
		name, digest, err := parseChecksumsLine(line)
		if err != nil {
			return nil, err
		}
		if prev, ok := out[name]; ok {
			if !bytes.Equal(prev, digest) {
				return nil, errors.New("update: checksums file has conflicting entries")
			}
			continue // identical duplicate: idempotent
		}
		out[name] = digest
	}
	if len(out) == 0 {
		return nil, errors.New("update: checksums file has no entries")
	}
	return out, nil
}

func parseChecksumsLine(line string) (string, []byte, error) {
	// First field: exactly 64 hex characters, then whitespace.
	i := 0
	for i < len(line) && line[i] != ' ' && line[i] != '\t' {
		i++
	}
	hashStr := line[:i]
	if len(hashStr) != 64 || i >= len(line) {
		return "", nil, errors.New("update: malformed checksums line")
	}
	digest, err := hex.DecodeString(hashStr)
	if err != nil {
		return "", nil, errors.New("update: malformed checksums line")
	}
	// Skip the separator run, then one optional '*' binary marker.
	j := i
	for j < len(line) && (line[j] == ' ' || line[j] == '\t') {
		j++
	}
	if j < len(line) && line[j] == '*' {
		j++
	}
	name := line[j:]
	if name == "" {
		return "", nil, errors.New("update: malformed checksums line")
	}
	for k := 0; k < len(name); k++ {
		if name[k] < 0x20 || name[k] == 0x7f {
			return "", nil, errors.New("update: malformed checksums line")
		}
	}
	return name, digest, nil
}
