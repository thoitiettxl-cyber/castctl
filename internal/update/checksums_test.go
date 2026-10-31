// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package update

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

// Slice 1 RED: checksums.txt parsing (failure-report §1, A-01..A-17).
// ParseChecksums does not exist yet: this test must fail to compile.

const (
	testAssetName = "castctl_0.6.4_linux_amd64.tar.gz"
	testAssetHex  = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

func testChecksumsBody(t *testing.T, lines ...string) []byte {
	t.Helper()
	return []byte(strings.Join(lines, "\n") + "\n")
}

func lookupDigest(t *testing.T, m map[string][]byte, name string) []byte {
	t.Helper()
	d, ok := m[name]
	if !ok {
		t.Fatalf("lookup %q: not found in %v", name, m)
	}
	return d
}

func TestParseChecksumsShapes(t *testing.T) {
	// Two-space, asterisk-marker, single-space, and tab separators
	// (A-11, A-12) all parse to the same digest bytes.
	shapes := []string{
		testAssetHex + "  " + testAssetName,
		testAssetHex + " *" + testAssetName,
		testAssetHex + " " + testAssetName,
		testAssetHex + "\t" + testAssetName,
	}
	want, err := hex.DecodeString(testAssetHex)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range shapes {
		m, err := ParseChecksums([]byte(line + "\n"))
		if err != nil {
			t.Errorf("ParseChecksums(%q): %v", line, err)
			continue
		}
		if got := lookupDigest(t, m, testAssetName); !bytes.Equal(got, want) {
			t.Errorf("ParseChecksums(%q): digest %x, want %x", line, got, want)
		}
	}
}

func TestParseChecksumsLineEndingsAndBlanks(t *testing.T) {
	// CRLF (A-08), no trailing newline (A-09iii), blank lines (A-09ii/iv).
	bodies := [][]byte{
		[]byte(testAssetHex + "  " + testAssetName + "\r\n"),
		[]byte(testAssetHex + "  " + testAssetName), // no trailing newline
		[]byte(testAssetHex + "  " + testAssetName + "\n\n"),
		[]byte("\n" + testAssetHex + "  " + testAssetName + "\n"),
		// BOM before the first line (A-17i) must not break parsing.
		[]byte("\xef\xbb\xbf" + testAssetHex + "  " + testAssetName + "\n"),
	}
	for _, body := range bodies {
		m, err := ParseChecksums(body)
		if err != nil {
			t.Errorf("ParseChecksums(%q): %v", body, err)
			continue
		}
		if _, ok := m[testAssetName]; !ok {
			t.Errorf("ParseChecksums(%q): asset entry missing", body)
		}
	}
}

func TestParseChecksumsUppercaseHex(t *testing.T) {
	// Uppercase hex decodes to the same bytes (A-10, coordinator rule).
	upper := strings.ToUpper(testAssetHex) + "  " + testAssetName + "\n"
	m, err := ParseChecksums([]byte(upper))
	if err != nil {
		t.Fatalf("ParseChecksums(uppercase): %v", err)
	}
	want, _ := hex.DecodeString(testAssetHex)
	if got := lookupDigest(t, m, testAssetName); !bytes.Equal(got, want) {
		t.Errorf("uppercase digest %x, want %x", got, want)
	}
}

func TestParseChecksumsExactMatchOnly(t *testing.T) {
	// Entries that merely contain the asset name must NOT match (A-04).
	other := sha256.Sum256([]byte("other"))
	otherHex := hex.EncodeToString(other[:])
	lines := []string{
		otherHex + "  x" + testAssetName,
		otherHex + "  " + testAssetName + ".bak",
		otherHex + "  ./" + testAssetName,
		otherHex + "  " + testAssetName + " ", // trailing space in filename
	}
	m, err := ParseChecksums(testChecksumsBody(t, lines...))
	if err != nil {
		t.Fatalf("ParseChecksums: %v", err)
	}
	if _, ok := m[testAssetName]; ok {
		t.Errorf("exact-match lookup found %q via a lookalike entry", testAssetName)
	}
	// A filename containing spaces parses as one filename (A-14) and
	// never matches the expected asset name.
	spaced := testChecksumsBody(t, testAssetHex+"  castctl 0.6.4.tar.gz")
	m, err = ParseChecksums(spaced)
	if err != nil {
		t.Fatalf("ParseChecksums(spaced): %v", err)
	}
	if _, ok := m[testAssetName]; ok {
		t.Error("spaced filename must not match the asset name")
	}
	if _, ok := m["castctl 0.6.4.tar.gz"]; !ok {
		t.Error("spaced filename must parse as a single filename")
	}
}

func TestParseChecksumsDuplicates(t *testing.T) {
	other := sha256.Sum256([]byte("other"))
	otherHex := hex.EncodeToString(other[:])
	// Identical duplicates are idempotent (A-05).
	m, err := ParseChecksums(testChecksumsBody(t,
		testAssetHex+"  "+testAssetName, testAssetHex+"  "+testAssetName))
	if err != nil {
		t.Fatalf("identical duplicates: %v", err)
	}
	if len(m) != 1 {
		t.Fatalf("identical duplicates: %d entries, want 1", len(m))
	}
	// Conflicting duplicates refuse in both orders (A-06).
	for _, lines := range [][]string{
		{testAssetHex + "  " + testAssetName, otherHex + "  " + testAssetName},
		{otherHex + "  " + testAssetName, testAssetHex + "  " + testAssetName},
	} {
		if _, err := ParseChecksums(testChecksumsBody(t, lines...)); err == nil {
			t.Errorf("conflicting duplicates %v: want error", lines)
		}
	}
	// A malformed duplicate must not be silently skipped (A-07).
	if _, err := ParseChecksums(testChecksumsBody(t,
		testAssetHex+"  "+testAssetName, "abc  "+testAssetName)); err == nil {
		t.Error("malformed duplicate: want error")
	}
}

func TestParseChecksumsMalformed(t *testing.T) {
	bad := [][]byte{
		[]byte(""),                             // empty (A-02)
		[]byte("abc  " + testAssetName + "\n"), // short hash (A-13)
		[]byte(testAssetHex + "a  " + testAssetName + "\n"),             // 65 chars (A-13)
		[]byte(strings.Repeat("g", 64) + "  " + testAssetName + "\n"),   // non-hex (A-13)
		[]byte("  " + testAssetName + "\n"),                             // empty hash (A-13)
		[]byte("-  " + testAssetName + "\n"),                            // dash hash (A-13)
		[]byte(testAssetHex + "  \n"),                                   // empty filename
		[]byte("\\" + testAssetHex + "  " + testAssetName + "\n"),       // escaped (A-15)
		[]byte(testAssetHex + "  " + testAssetName + "\x00x\n"),         // NUL (A-17ii)
		[]byte("\xff\xfe" + testAssetHex + "  " + testAssetName + "\n"), // invalid UTF-8 (A-17iii)
		[]byte(testAssetHex + "  " + testAssetName + "\n" + "garbage line without hash\n"),
	}
	for _, body := range bad {
		if _, err := ParseChecksums(body); err == nil {
			t.Errorf("ParseChecksums(%q): want error", body)
		}
	}
	// Oversized checksums file refuses (A-22): cap is 64 KiB.
	huge := bytes.Repeat([]byte("a"), maxChecksumsBytes+1)
	if _, err := ParseChecksums(huge); err == nil {
		t.Error("oversized checksums: want error")
	}
}

func TestParseChecksumsExtraEntriesIgnored(t *testing.T) {
	// Extra entries for other files are ignored (A-16).
	other := sha256.Sum256([]byte("other"))
	otherHex := hex.EncodeToString(other[:])
	m, err := ParseChecksums(testChecksumsBody(t,
		testAssetHex+"  "+testAssetName,
		otherHex+"  checksums.txt",
		otherHex+"  README.md",
		otherHex+"  evil.tar.gz"))
	if err != nil {
		t.Fatalf("ParseChecksums: %v", err)
	}
	if _, ok := m[testAssetName]; !ok {
		t.Error("asset entry missing among extra entries")
	}
}

func TestParseChecksumsRealShape(t *testing.T) {
	// Four archives, sorted by filename, sha256sum output (P4).
	asset := func(name string, body string) string {
		sum := sha256.Sum256([]byte(body))
		return hex.EncodeToString(sum[:]) + "  " + name
	}
	body := testChecksumsBody(t,
		asset("castctl_0.6.4_linux_amd64.tar.gz", "amd64"),
		asset("castctl_0.6.4_linux_amd64_no-plugin.tar.gz", "amd64np"),
		asset("castctl_0.6.4_linux_arm64.tar.gz", "arm64"),
		asset("castctl_0.6.4_linux_arm64_no-plugin.tar.gz", "arm64np"),
	)
	m, err := ParseChecksums(body)
	if err != nil {
		t.Fatalf("ParseChecksums: %v", err)
	}
	if len(m) != 4 {
		t.Fatalf("entries = %d, want 4", len(m))
	}
	want := sha256.Sum256([]byte("amd64"))
	if got := lookupDigest(t, m, "castctl_0.6.4_linux_amd64.tar.gz"); !bytes.Equal(got, want[:]) {
		t.Errorf("digest mismatch: got %x want %x", got, want)
	}
}
