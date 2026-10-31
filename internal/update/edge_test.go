// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package update

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Slice 3 RED: extraction tricks, replace failure injection,
// exec-check behaviours, asset-selection units. Some cases already
// pass against slice-2 code (hardening verification); the trailing
// gzip data cases and the exec timeout injection must fail first.

// buildTarEntries builds a gzip tar archive from explicit headers.
func buildTarEntries(t *testing.T, entries []tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		hdr := &tar.Header{
			Name: e.name, Mode: e.mode, Size: int64(len(e.body)),
			Typeflag: e.typeflag, Linkname: e.linkname,
			Format: e.format, PAXRecords: e.pax,
		}
		if e.sizeOverride >= 0 {
			hdr.Size = e.sizeOverride
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(e.body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

type tarEntry struct {
	name         string
	body         []byte
	mode         int64
	typeflag     byte
	linkname     string
	format       tar.Format
	pax          map[string]string
	sizeOverride int64 // -1 = use len(body); set in tests via -1 default below
}

func regEntry(name string, body []byte) tarEntry {
	return tarEntry{name: name, body: body, mode: 0o755, typeflag: tar.TypeReg, sizeOverride: -1}
}

// installFixture serves one archive for a live install and returns
// the target dir/exe. The archive's checksums are computed over the
// exact served bytes.
func installFixture(t *testing.T, archive []byte) (*fakeReleaseServer, string, string) {
	t.Helper()
	f := newFakeReleaseServer(t, "v0.6.4")
	assetName := "castctl_0.6.4_linux_amd64.tar.gz"
	f.assets[assetName] = &fakeAsset{body: archive}
	f.setChecksums()
	_, exe := makeTarget(t)
	return f, filepath.Dir(exe), exe
}

func TestExtractTraversalOtherMembersInert(t *testing.T) {
	bin := fakeBinary(t)
	cases := map[string][]byte{
		"dotdot":   buildTarEntries(t, []tarEntry{regEntry("../castctl", bin)}),
		"absolute": buildTarEntries(t, []tarEntry{regEntry("/tmp/evil", bin)}),
		"dotSlash": buildTarEntries(t, []tarEntry{regEntry("./castctl", bin)}),
		"case":     buildTarEntries(t, []tarEntry{regEntry("CASTCTL", bin)}),
		"noMember": buildTarEntries(t, []tarEntry{regEntry("LICENSE", []byte("x"))}),
	}
	for name, archive := range cases {
		t.Run(name, func(t *testing.T) {
			f, dir, exe := installFixture(t, archive)
			before := dirSnapshot(t, dir)
			delete(before, lockFileName)
			if _, err := runUpdate(t, f.baseOptions(exe)); err == nil {
				t.Fatal("want refusal for archive without an exact castctl member")
			}
			old, _ := os.ReadFile(exe)
			if string(old) != "old-binary-bytes" {
				t.Error("target modified on refusal")
			}
			after := dirSnapshot(t, dir)
			delete(after, lockFileName)
			if !snapshotsEqual(before, after) {
				t.Error("refusal left temp files behind")
			}
		})
	}
	// An absolute-path OTHER member alongside a valid castctl is
	// inert: it is never used as a path.
	f, _, exe := installFixture(t, buildTarEntries(t, []tarEntry{
		regEntry("castctl", bin), regEntry("/tmp/evil", []byte("x")),
	}))
	if _, err := runUpdate(t, f.baseOptions(exe)); err != nil {
		t.Fatalf("absolute other member must not block install: %v", err)
	}
}

func TestExtractLinkMembersRefuse(t *testing.T) {
	bin := fakeBinary(t)
	cases := map[string][]byte{
		"symlinkCastctl": buildTarEntries(t, []tarEntry{
			{name: "castctl", typeflag: tar.TypeSymlink, linkname: "/etc/passwd", sizeOverride: -1},
		}),
		"hardlinkCastctl": buildTarEntries(t, []tarEntry{
			{name: "castctl", typeflag: tar.TypeLink, linkname: "other", sizeOverride: -1},
		}),
		"dirCastctl": buildTarEntries(t, []tarEntry{
			{name: "castctl", typeflag: tar.TypeDir, sizeOverride: -1},
		}),
		"symlinkThenWrite": buildTarEntries(t, []tarEntry{
			{name: "dir", typeflag: tar.TypeSymlink, linkname: "/tmp/evil-dir", sizeOverride: -1},
			regEntry("dir/castctl", bin),
		}),
		"duplicate": buildTarEntries(t, []tarEntry{
			regEntry("castctl", bin), regEntry("castctl", []byte("different")),
		}),
		"duplicateReversed": buildTarEntries(t, []tarEntry{
			regEntry("castctl", []byte("different")), regEntry("castctl", bin),
		}),
		"fifoOther": buildTarEntries(t, []tarEntry{
			regEntry("castctl", bin),
			{name: "pipe", typeflag: tar.TypeFifo, sizeOverride: -1},
		}),
	}
	for name, archive := range cases {
		t.Run(name, func(t *testing.T) {
			f, _, exe := installFixture(t, archive)
			if _, err := runUpdate(t, f.baseOptions(exe)); err == nil {
				t.Fatalf("%s: want refusal", name)
			}
			old, _ := os.ReadFile(exe)
			if string(old) != "old-binary-bytes" {
				t.Errorf("%s: target modified", name)
			}
		})
	}
}

func TestExtractPAXOverrideRefuses(t *testing.T) {
	// PAX path override changes the effective name: the ustar name
	// "castctl" becomes "../evil", so no castctl member exists.
	// Go's tar.Writer sanitises user PAXRecords, so the archive is
	// hand-crafted: an 'x' extended header carrying
	// "16 path=../evil\n", then the ustar member header.
	archive := paxOverrideArchive(t)
	f, _, exe := installFixture(t, archive)
	if _, err := runUpdate(t, f.baseOptions(exe)); err == nil {
		t.Fatal("PAX path override: want refusal")
	}
}

// paxOverrideArchive builds a gzip tar archive whose single member
// has ustar name "castctl" but a PAX path override of "../evil".
func paxOverrideArchive(t *testing.T) []byte {
	t.Helper()
	rec := "16 path=../evil\n"
	var tarBytes []byte
	tarBytes = append(tarBytes, rawTarHeader("PaxHeaders/castctl", int64(len(rec)), 'x')...)
	tarBytes = append(tarBytes, padTo512([]byte(rec))...)
	tarBytes = append(tarBytes, rawTarHeader("castctl", int64(len(fakeBinary(t))), '0')...)
	tarBytes = append(tarBytes, padTo512(fakeBinary(t))...)
	tarBytes = append(tarBytes, make([]byte, 1024)...)
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(tarBytes); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func rawTarHeader(name string, size int64, typeflag byte) []byte {
	b := make([]byte, 512)
	copy(b[0:100], name)
	copy(b[100:108], "0000777\x00")
	copy(b[108:116], "0000000\x00")
	copy(b[116:124], "0000000\x00")
	copy(b[124:136], fmt.Sprintf("%011o\x00", size))
	copy(b[136:148], "00000000000\x00")
	copy(b[148:156], "        ")
	b[156] = typeflag
	copy(b[257:263], "ustar\x00")
	copy(b[263:265], "00")
	sum := 0
	for _, c := range b {
		sum += int(c)
	}
	copy(b[148:156], fmt.Sprintf("%06o\x00 ", sum))
	return b
}

func padTo512(b []byte) []byte {
	for len(b)%512 != 0 {
		b = append(b, 0)
	}
	return b
}

func TestExtractMemberModeIgnored(t *testing.T) {
	// Archive member modes (setuid, 0000) never reach the installed
	// binary: the old binary's mode is preserved (E-09).
	for _, mode := range []int64{0o4755, 0o0000, 0o777} {
		archive := buildTarEntries(t, []tarEntry{{
			name: "castctl", body: fakeBinary(t), mode: mode,
			typeflag: tar.TypeReg, sizeOverride: -1,
		}})
		f, _, exe := makeTargetFixture(t, archive)
		if _, err := runUpdate(t, f.baseOptions(exe)); err != nil {
			t.Fatalf("mode %04o: install: %v", mode, err)
		}
		fi, err := os.Stat(exe)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm()&0o111 == 0 {
			t.Errorf("mode %04o: installed binary is not executable: %v", mode, fi.Mode())
		}
		if fi.Mode().Perm()&0o4000 != 0 || fi.Mode().Perm()&0o2000 != 0 {
			t.Errorf("mode %04o: installed binary carries setuid/setgid: %v", mode, fi.Mode())
		}
	}
}

func makeTargetFixture(t *testing.T, archive []byte) (*fakeReleaseServer, string, string) {
	t.Helper()
	f, dir, exe := installFixture(t, archive)
	return f, dir, exe
}

func TestExtractCorruptArchivesRefuse(t *testing.T) {
	bin := fakeBinary(t)
	good := buildTar(t, map[string][]byte{"castctl": bin})
	cases := map[string][]byte{
		"truncatedHalf": good[:len(good)/2],
		"truncated10":   good[:10],
		"empty":         {},
		"plainText":     []byte("this is not a gzip stream at all"),
		"badGzipMagic":  append([]byte{0x00}, good[1:]...),
		"noMember":      buildTar(t, map[string][]byte{"LICENSE": []byte("x")}),
		"zeroLength":    buildTar(t, map[string][]byte{"castctl": {}}),
	}
	for name, archive := range cases {
		t.Run(name, func(t *testing.T) {
			f, _, exe := installFixture(t, archive)
			if _, err := runUpdate(t, f.baseOptions(exe)); err == nil {
				t.Fatalf("%s: want refusal", name)
			}
			old, _ := os.ReadFile(exe)
			if string(old) != "old-binary-bytes" {
				t.Errorf("%s: target modified", name)
			}
		})
	}
	// Huge declared size with a short stream refuses without
	// allocating for the declared size (B-08). The archive is
	// built without tar.Writer.Close so no zero padding is ever
	// materialised for the lying size.
	var hugeBuf bytes.Buffer
	hugeGz := gzip.NewWriter(&hugeBuf)
	hugeTw := tar.NewWriter(hugeGz)
	if err := hugeTw.WriteHeader(&tar.Header{
		Name: "castctl", Mode: 0o755, Size: 1 << 40, Typeflag: tar.TypeReg,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := hugeTw.Write([]byte("short")); err != nil {
		t.Fatal(err)
	}
	if err := hugeGz.Close(); err != nil {
		t.Fatal(err)
	}
	f, _, exe := installFixture(t, hugeBuf.Bytes())
	if _, err := runUpdate(t, f.baseOptions(exe)); err == nil {
		t.Fatal("huge declared size: want refusal")
	}
	// Entry-count bomb refuses (E-15): 70 tiny members, castctl last.
	var many []tarEntry
	for i := 0; i < 69; i++ {
		many = append(many, regEntry("file"+string(rune('a'+i%26))+itoa(i), []byte("x")))
	}
	many = append(many, regEntry("castctl", bin))
	f2, _, exe2 := installFixture(t, buildTarEntries(t, many))
	if _, err := runUpdate(t, f2.baseOptions(exe2)); err == nil {
		t.Fatal("entry-count bomb: want refusal")
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [8]byte
	p := len(b)
	for i > 0 {
		p--
		b[p] = byte('0' + i%10)
		i /= 10
	}
	return string(b[p:])
}

func TestExtractTrailingGzipDataRefuses(t *testing.T) {
	// A second gzip member carrying a different castctl, and
	// trailing garbage after the first member, must both refuse:
	// only hash-verified bytes from the single scanned archive may
	// reach disk (B-02/E-18).
	bin := fakeBinary(t)
	first := buildTar(t, map[string][]byte{"castctl": bin})
	second := buildTar(t, map[string][]byte{"castctl": []byte("different binary")})
	joined := append(append([]byte{}, first...), second...)
	f, _, exe := installFixture(t, joined)
	if _, err := runUpdate(t, f.baseOptions(exe)); err == nil {
		t.Fatal("second gzip member: want refusal")
	}
	garbage := append(append([]byte{}, first...), []byte("GARBAGEGARBAGE")...)
	f2, _, exe2 := installFixture(t, garbage)
	if _, err := runUpdate(t, f2.baseOptions(exe2)); err == nil {
		t.Fatal("trailing garbage: want refusal")
	}
}

// gunzipBytes decompresses a gzip stream (test helper).
func gunzipBytes(t *testing.T, gzipped []byte) []byte {
	t.Helper()
	gzr, err := gzip.NewReader(bytes.NewReader(gzipped))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(gzr)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// appendDecompressedTrailer returns archive re-gzipped with trailer
// bytes appended to the DECOMPRESSED tar stream, i.e. after the tar
// end-blocks as the tar reader sees them.
func appendDecompressedTrailer(t *testing.T, archive, trailer []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(append(append([]byte{}, gunzipBytes(t, archive)...), trailer...)); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func allZeroBytes(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

func TestExtractGnuTarRecordPaddingAccepted(t *testing.T) {
	// Live-test failure (Boss, stamped 0.6.2 build of 4fc53f8,
	// `update --dry-run` against the real v0.6.3 release, exit 1):
	// GNU tar pads archives with zeros to a 10240-byte record
	// boundary, and the trailing-data check refused that padding,
	// so every real release was refused. This test builds the
	// fixture with REAL GNU tar and drives the real update path;
	// it must install.
	out, err := exec.Command("tar", "--version").Output()
	if err != nil {
		t.Skipf("GNU tar required for this test: %v", err)
	}
	versionLine := strings.TrimRight(string(out), "\n")
	if nl := strings.IndexByte(versionLine, '\n'); nl >= 0 {
		versionLine = versionLine[:nl]
	}
	if !strings.Contains(versionLine, "GNU tar") {
		t.Skipf("GNU tar required for this test: %q", versionLine)
	}
	bin := fakeBinary(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "castctl"), bin, 0o755); err != nil {
		t.Fatal(err)
	}
	arc := filepath.Join(dir, "archive.tar.gz")
	cmd := exec.Command("tar", "--create", "--gzip", "--blocking-factor=20", "--file="+arc, "--directory="+dir, "castctl")
	if bout, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("GNU tar create: %v: %s", err, bout)
	}
	gzipped, err := os.ReadFile(arc)
	if err != nil {
		t.Fatal(err)
	}
	// Prove the fixture is genuine GNU tar output: the
	// decompressed stream is a multiple of the 10240-byte record
	// size, holds exactly one castctl member, ends with two zero
	// end-blocks, and carries a NON-EMPTY all-zero tail after
	// them. No zeros are appended by this test.
	raw := gunzipBytes(t, gzipped)
	if len(raw)%10240 != 0 {
		t.Fatalf("decompressed tar size %d is not a multiple of 10240", len(raw))
	}
	if len(raw) < 512 {
		t.Fatal("decompressed tar too short for a header")
	}
	hdr := raw[:512]
	if name := strings.TrimRight(string(hdr[:100]), "\x00"); name != "castctl" {
		t.Fatalf("first member name %q, want castctl", name)
	}
	size, err := strconv.ParseInt(strings.Trim(string(hdr[124:136]), "\x00 "), 8, 64)
	if err != nil {
		t.Fatalf("unparsable size field: %v", err)
	}
	if size != int64(len(bin)) {
		t.Fatalf("member size %d, want fake binary size %d", size, len(bin))
	}
	endOff := 512 + int((size+511)/512)*512
	if endOff+1024 > len(raw) {
		t.Fatalf("no room for end-blocks: end %d, tar size %d", endOff, len(raw))
	}
	if !allZeroBytes(raw[endOff : endOff+1024]) {
		t.Fatal("tar end-blocks are not zero")
	}
	trail := raw[endOff+1024:]
	if len(trail) == 0 {
		t.Fatal("no record padding after the end-blocks: fixture does not exercise the fix")
	}
	if len(trail) >= 10240 || !allZeroBytes(trail) {
		t.Fatalf("trailing padding %d bytes, all zero=%v", len(trail), allZeroBytes(trail))
	}
	// Real update path, unstubbed exec check: the fake binary
	// reports the target version, so the install must succeed.
	f, _, exe := installFixture(t, gzipped)
	res, err := runUpdate(t, f.baseOptions(exe))
	if err != nil {
		t.Fatalf("GNU tar archive must install: %v", err)
	}
	if !res.Replaced {
		t.Fatal("want Replaced=true")
	}
	got, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, bin) {
		t.Fatal("installed bytes differ from the archive member")
	}
}

func TestExtractAllZeroTrailingDataAccepted(t *testing.T) {
	// All-zero trailing bytes after the tar end-blocks are record
	// padding, not data: they must be accepted, including a tail
	// past the old 1 MiB read cap (the scan must reach EOF).
	bin := fakeBinary(t)
	base := buildTar(t, map[string][]byte{"castctl": bin})
	cases := map[string][]byte{
		"small": appendDecompressedTrailer(t, base, bytes.Repeat([]byte{0}, 100)),
		"beyondOldCap": appendDecompressedTrailer(t, base,
			bytes.Repeat([]byte{0}, 1<<20+123)),
	}
	for name, archive := range cases {
		t.Run(name, func(t *testing.T) {
			f, _, exe := installFixture(t, archive)
			res, err := runUpdate(t, f.baseOptions(exe))
			if err != nil {
				t.Fatalf("all-zero trailer must install: %v", err)
			}
			if !res.Replaced {
				t.Fatal("want Replaced=true")
			}
		})
	}
}

func TestExtractNonZeroTrailingDataRefuses(t *testing.T) {
	// Any non-zero byte after the tar end-blocks refuses: a
	// non-zero byte immediately after the end-blocks, zeros
	// followed by a late non-zero byte, and a late non-zero byte
	// past the old 1 MiB read cap.
	bin := fakeBinary(t)
	base := buildTar(t, map[string][]byte{"castctl": bin})
	cases := map[string][]byte{
		"immediate": appendDecompressedTrailer(t, base, []byte{0x01}),
		"late": appendDecompressedTrailer(t, base,
			append(bytes.Repeat([]byte{0}, 100), 0xff)),
		"lateBeyondOldCap": appendDecompressedTrailer(t, base,
			append(bytes.Repeat([]byte{0}, 1<<20+123), 0x01)),
	}
	for name, archive := range cases {
		t.Run(name, func(t *testing.T) {
			f, _, exe := installFixture(t, archive)
			if _, err := runUpdate(t, f.baseOptions(exe)); err == nil {
				t.Fatalf("%s: want refusal", name)
			}
			old, _ := os.ReadFile(exe)
			if string(old) != "old-binary-bytes" {
				t.Errorf("%s: target modified", name)
			}
		})
	}
}

func TestSelectAssetUnits(t *testing.T) {
	rel := func(assets ...releaseAsset) *releaseInfo {
		return &releaseInfo{tag: "v0.6.4", assets: assets}
	}
	good := releaseAsset{name: "castctl_0.6.4_linux_amd64.tar.gz", url: "https://github.com/x/y", size: 10, state: "uploaded"}
	if _, err := selectAsset(rel(good), good.name); err != nil {
		t.Fatalf("good asset: %v", err)
	}
	cases := []struct {
		name string
		rel  *releaseInfo
	}{
		{"none", rel()},
		{"otherArch", rel(releaseAsset{name: "castctl_0.6.4_linux_arm64.tar.gz", url: "https://github.com/x", size: 10, state: "uploaded"})},
		{"duplicate", rel(good, good)},
		{"notUploaded", rel(releaseAsset{name: good.name, url: good.url, size: 10, state: "created"})},
		{"zeroSize", rel(releaseAsset{name: good.name, url: good.url, size: 0, state: "uploaded"})},
		{"relativeURL", rel(releaseAsset{name: good.name, url: "/download/x", size: 10, state: "uploaded"})},
		{"javascriptURL", rel(releaseAsset{name: good.name, url: "javascript:alert(1)", size: 10, state: "uploaded"})},
		{"fileURL", rel(releaseAsset{name: good.name, url: "file:///etc/passwd", size: 10, state: "uploaded"})},
		{"prefixOnly", rel(releaseAsset{name: "castctl_0.6.4_linux_amd64.tar.gz.bak", url: good.url, size: 10, state: "uploaded"})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := selectAsset(tc.rel, good.name); err == nil {
				t.Errorf("%s: want error", tc.name)
			}
		})
	}
	// Checksums selection: missing and duplicate both refuse.
	if _, err := selectChecksumsAsset(rel(good)); err == nil {
		t.Error("missing checksums: want error")
	}
	chk := releaseAsset{name: "checksums.txt", url: "https://github.com/x/c", size: 10, state: "uploaded"}
	if _, err := selectChecksumsAsset(rel(good, chk)); err != nil {
		t.Fatalf("good checksums: %v", err)
	}
	if _, err := selectChecksumsAsset(rel(chk, chk)); err == nil {
		t.Error("duplicate checksums: want error")
	}
}

func TestRenameFailureLeavesOldIntact(t *testing.T) {
	f, dir, exe := installFixture(t, buildTar(t, map[string][]byte{"castctl": fakeBinary(t)}))
	prev := renameFunc
	renameFunc = func(old, new string) error { return errors.New("injected rename failure") }
	t.Cleanup(func() { renameFunc = prev })
	if _, err := runUpdate(t, f.baseOptions(exe)); err == nil || codeOf(err) != 1 {
		t.Fatalf("rename failure: err=%v code=%d, want code 1", err, codeOf(err))
	}
	old, _ := os.ReadFile(exe)
	if string(old) != "old-binary-bytes" {
		t.Error("rename failure modified the target")
	}
	for _, e := range mustReadDir(t, dir) {
		if strings.Contains(e, ".castctl-update-") {
			t.Errorf("rename failure left temp file %q", e)
		}
	}
}

func mustReadDir(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
	}
	return names
}

func TestLockHeldFailsFast(t *testing.T) {
	f, dir, exe := installFixture(t, buildTar(t, map[string][]byte{"castctl": fakeBinary(t)}))
	release, held, err := acquireUpdateLock(dir)
	if err != nil || held {
		t.Fatalf("pre-lock: release=%v held=%v err=%v", release != nil, held, err)
	}
	defer release()
	if _, err := runUpdate(t, f.baseOptions(exe)); err == nil {
		t.Fatal("lock held: want error")
	} else if !strings.Contains(err.Error(), "another update") {
		t.Fatalf("lock held error %q must say another update", err.Error())
	}
	if got := f.getCount("/download/"); got != 0 {
		t.Errorf("lock held: %d downloads happened, want 0", got)
	}
	old, _ := os.ReadFile(exe)
	if string(old) != "old-binary-bytes" {
		t.Error("lock held: target modified")
	}
}

func TestLockSymlinkRefuses(t *testing.T) {
	// A pre-planted lock symlink must not be followed (G-75).
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("victim-bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(dir, lockFileName)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := acquireUpdateLock(dir); err == nil {
		t.Fatal("symlink lock: want error")
	}
	got, _ := os.ReadFile(victim)
	if string(got) != "victim-bytes" {
		t.Error("symlink lock: victim modified")
	}
}

func TestConcurrentRunsNoTornState(t *testing.T) {
	// Two in-process concurrent runs serialise (mutex + flock) and
	// both report success; the disk ends on one complete generation.
	f, _, exe := installFixture(t, buildTar(t, map[string][]byte{"castctl": fakeBinary(t)}))
	results := make(chan error, 2)
	opts1 := f.baseOptions(exe)
	opts2 := f.baseOptions(exe)
	go func() { _, err := Run(context.Background(), opts1); results <- err }()
	go func() { _, err := Run(context.Background(), opts2); results <- err }()
	for i := 0; i < 2; i++ {
		if err := <-results; err != nil {
			t.Fatalf("concurrent run %d: %v", i, err)
		}
	}
	got, _ := os.ReadFile(exe)
	if !bytes.Equal(got, fakeBinary(t)) {
		t.Error("concurrent runs left a torn binary")
	}
}

func TestSymlinkTargetPreserved(t *testing.T) {
	// The resolved target file is replaced; the symlink itself
	// survives (G-70 pin ii).
	realDir := t.TempDir()
	linkDir := t.TempDir()
	realExe := filepath.Join(realDir, "castctl")
	if err := os.WriteFile(realExe, []byte("old-binary-bytes"), 0o755); err != nil {
		t.Fatal(err)
	}
	linkExe := filepath.Join(linkDir, "castctl")
	if err := os.Symlink(realExe, linkExe); err != nil {
		t.Fatal(err)
	}
	f := newFakeReleaseServer(t, "v0.6.4")
	f.assets["castctl_0.6.4_linux_amd64.tar.gz"] = &fakeAsset{body: buildTar(t, map[string][]byte{"castctl": fakeBinary(t)})}
	f.setChecksums()
	opts := f.baseOptions(linkExe)
	if _, err := runUpdate(t, opts); err != nil {
		t.Fatalf("symlink target: %v", err)
	}
	fi, err := os.Lstat(linkExe)
	if err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("symlink was replaced: fi=%v err=%v", fi, err)
	}
	got, _ := os.ReadFile(realExe)
	if !bytes.Equal(got, fakeBinary(t)) {
		t.Error("resolved target was not replaced")
	}
	// No new regular file appeared in the link dir.
	for _, e := range mustReadDir(t, linkDir) {
		if e != "castctl" {
			t.Errorf("unexpected file in link dir: %q", e)
		}
	}
	// Dangling symlink refuses.
	dangling := filepath.Join(linkDir, "dangling")
	if err := os.Symlink(filepath.Join(linkDir, "nonexistent"), dangling); err != nil {
		t.Fatal(err)
	}
	if _, err := runUpdate(t, f.baseOptions(dangling)); err == nil {
		t.Fatal("dangling symlink: want error")
	}
}

func TestHardlinkTargetKeepsOldInode(t *testing.T) {
	// Rename replaces the directory entry: another hardlink keeps
	// pointing at the old inode (H-94 pin).
	_, exe := makeTarget(t)
	other := exe + ".other"
	if err := os.Link(exe, other); err != nil {
		t.Fatal(err)
	}
	f, _, _ := installFixture(t, buildTar(t, map[string][]byte{"castctl": fakeBinary(t)}))
	// installFixture made its own target; point the run at exe.
	opts := f.baseOptions(exe)
	if _, err := runUpdate(t, opts); err != nil {
		t.Fatalf("hardlink target: %v", err)
	}
	got, _ := os.ReadFile(other)
	if string(got) != "old-binary-bytes" {
		t.Error("hardlink lost the old bytes")
	}
}

func TestDirSyncFailureReportsReplaced(t *testing.T) {
	f, _, exe := installFixture(t, buildTar(t, map[string][]byte{"castctl": fakeBinary(t)}))
	prev := syncDirFunc
	syncDirFunc = func(dir string) error { return errors.New("injected ENOSPC") }
	t.Cleanup(func() { syncDirFunc = prev })
	res, err := runUpdate(t, f.baseOptions(exe))
	if err == nil {
		t.Fatal("dir-sync failure: want error")
	}
	if !res.Replaced {
		t.Error("dir-sync failure must still report Replaced (the rename happened)")
	}
	if !strings.Contains(err.Error(), "durability") {
		t.Errorf("dir-sync error %q must mention durability", err.Error())
	}
	got, _ := os.ReadFile(exe)
	if !bytes.Equal(got, fakeBinary(t)) {
		t.Error("dir-sync failure: new binary is not in place")
	}
	// Tolerable dir-sync errors (ENOTSUP) succeed silently (H-92).
	syncDirFunc = func(dir string) error { return syscall.ENOTSUP }
	f2, _, exe2 := installFixture(t, buildTar(t, map[string][]byte{"castctl": fakeBinary(t)}))
	if _, err := runUpdate(t, f2.baseOptions(exe2)); err != nil {
		t.Fatalf("tolerable dir-sync error: %v", err)
	}
}

func TestCheckVersionOutput(t *testing.T) {
	want := mustParse(t, "0.6.4")
	cases := []struct {
		name string
		out  string
		ok   bool
	}{
		{"bare", "castctl 0.6.4\n", true},
		{"stamped", "castctl 0.6.4 (deadbeef 2026-01-01T00:00:00Z)\n", true},
		{"noTrailingNewline", "castctl 0.6.4", true},
		{"mismatch", "castctl 0.6.3\n", false},
		{"mismatchStamped", "castctl 9.9.9 (x y)\n", false},
		{"twoLines", "castctl 0.6.4\ninjected\n", false},
		{"versionSecondLine", "hello\ncastctl 0.6.4\n", false},
		{"ansi", "castctl 0.6.4\x1b[31m\n", false},
		{"nul", "castctl 0.6.4\x00\n", false},
		{"empty", "", false},
		{"noPrefix", "0.6.4\n", false},
		{"trailingGarbage", "castctl 0.6.4-evil\n", false},
		{"trailingSpace", "castctl 0.6.4 \n", false},
		{"badParen", "castctl 0.6.4 (unclosed\n", false},
		{"prereleaseMismatch", "castctl 0.6.4-rc.1\n", false},
		{"buildIgnored", "castctl 0.6.4+build\n", true}, // build ignored for precedence
		{"tooLong", "castctl " + strings.Repeat("x", 300) + "\n", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := checkVersionOutput([]byte(tc.out), want)
			if tc.ok && err != nil {
				t.Errorf("output %q: want accept, got %v", tc.out, err)
			}
			if !tc.ok && err == nil {
				t.Errorf("output %q: want refusal", tc.out)
			}
		})
	}
}

func TestExecCheckRealBinaries(t *testing.T) {
	// /bin/true exits 0 with no output: version check must refuse.
	// /bin/false exits 1: must refuse. Both prove the wait/status
	// handling without any fixture binary.
	for _, path := range []string{"/bin/true", "/bin/false"} {
		if _, err := os.Stat(path); err != nil {
			t.Skip(path + " absent")
		}
		if err := runExecCheck(context.Background(), path, mustParse(t, "0.6.4")); err == nil {
			t.Errorf("%s: want refusal", path)
		}
	}
	// The fake binary reports 0.6.4 and passes.
	if err := runExecCheck(context.Background(), fakeBinaryPathForExec(t), mustParse(t, "0.6.4")); err != nil {
		t.Fatalf("fake binary exec check: %v", err)
	}
	// Wrong target version refuses.
	if err := runExecCheck(context.Background(), fakeBinaryPathForExec(t), mustParse(t, "0.6.3")); err == nil {
		t.Fatal("wrong target version: want refusal")
	}
}

// fakeBinaryPathForExec returns a path to an executable copy of the
// fake binary (the shared build output is not executable-able twice
// concurrently without a copy in some sandboxes; copy defensively).
func fakeBinaryPathForExec(t *testing.T) string {
	t.Helper()
	b := fakeBinary(t)
	p := filepath.Join(t.TempDir(), "fakeversion")
	if err := os.WriteFile(p, b, 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestExecCheckHangTimesOut(t *testing.T) {
	// A hanging --version must be killed by the timeout, not hang
	// the parent (V-02). Timeout injected via the package var.
	prev := execCheckTimeout
	execCheckTimeout = 200 * time.Millisecond
	t.Cleanup(func() { execCheckTimeout = prev })
	hang := buildTestBinary(t, "fakehang")
	start := time.Now()
	err := runExecCheck(context.Background(), hang, mustParse(t, "0.6.4"))
	if err == nil {
		t.Fatal("hanging binary: want error")
	}
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Errorf("hanging binary took %v, timeout did not kill it", elapsed)
	}
	if !strings.Contains(err.Error(), "in time") {
		t.Errorf("hang error %q must mention the timeout", err.Error())
	}
}

func TestExecCheckFloodRefuses(t *testing.T) {
	flood := buildTestBinary(t, "fakeflood")
	if err := runExecCheck(context.Background(), flood, mustParse(t, "0.6.4")); err == nil {
		t.Fatal("flooding binary: want refusal")
	}
}

// buildTestBinary compiles a testdata helper program once per name.
func buildTestBinary(t *testing.T, name string) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), name)
	src := filepath.Join("testdata", name, "main.go")
	cmd := exec.Command("go", "build", "-o", out, src)
	if bout, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build %s: %v: %s", name, err, bout)
	}
	return out
}

func TestAssetAndChecksums404Refuse(t *testing.T) {
	// Asset listed but download 404s (C-01 family on the asset path).
	f := newFakeReleaseServer(t, "v0.6.4")
	assetName := "castctl_0.6.4_linux_amd64.tar.gz"
	f.assets[assetName] = &fakeAsset{body: buildTar(t, map[string][]byte{"castctl": fakeBinary(t)}), status: 404}
	f.setChecksums()
	_, exe := makeTarget(t)
	if _, err := runUpdate(t, f.baseOptions(exe)); err == nil || codeOf(err) != 1 {
		t.Fatalf("asset 404: err=%v code=%d, want code 1", err, codeOf(err))
	}
	// Checksums download 404s.
	f2 := newFakeReleaseServer(t, "v0.6.4")
	f2.assets[assetName] = &fakeAsset{body: buildTar(t, map[string][]byte{"castctl": fakeBinary(t)})}
	f2.setChecksums()
	f2.assets["checksums.txt"] = &fakeAsset{body: []byte(""), status: 404}
	_, exe2 := makeTarget(t)
	if _, err := runUpdate(t, f2.baseOptions(exe2)); err == nil {
		t.Fatal("checksums 404: want error")
	}
	// Dry-run with a checksum mismatch refuses with zero writes.
	f3 := newFakeReleaseServer(t, "v0.6.4")
	f3.assets[assetName] = &fakeAsset{body: buildTar(t, map[string][]byte{"castctl": fakeBinary(t)})}
	f3.setChecksums()
	sum := sha256.Sum256([]byte("different"))
	f3.assets["checksums.txt"] = &fakeAsset{body: []byte(hex.EncodeToString(sum[:]) + "  " + assetName + "\n")}
	_, exe3 := makeTarget(t)
	before := dirSnapshot(t, filepath.Dir(exe3))
	opts := f3.baseOptions(exe3)
	opts.DryRun = true
	if _, err := runUpdate(t, opts); err == nil {
		t.Fatal("dry-run checksum mismatch: want error")
	}
	if !snapshotsEqual(before, dirSnapshot(t, filepath.Dir(exe3))) {
		t.Error("dry-run mismatch changed the directory")
	}
}

func TestReadOnlyDirRefuses(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: permission bits do not block writes")
	}
	dir, exe := makeTarget(t)
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
	f, _, _ := installFixture(t, buildTar(t, map[string][]byte{"castctl": fakeBinary(t)}))
	if _, err := runUpdate(t, f.baseOptions(exe)); err == nil {
		t.Fatal("read-only dir: want error")
	}
	old, _ := os.ReadFile(exe)
	if string(old) != "old-binary-bytes" {
		t.Error("read-only dir: target modified")
	}
}

// TestClassifyTransportErrorTLSForms (loop 4, Technical D1): pins
// the exact measured mapping of classifyTransportError over TLS
// error forms, so the corrected carried wording cannot drift false
// again. The "tls" class IS reachable, but only for specific forms;
// a genuine self-signed-certificate handshake failure classifies as
// "transport" (see TestClassifyTransportErrorRealHandshake).
func TestClassifyTransportErrorTLSForms(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"unknownAuthorityPtr", &x509.UnknownAuthorityError{}, "tls"},
		{"certInvalidValue", x509.CertificateInvalidError{}, "tls"},
		{"certInvalidPtr", &x509.CertificateInvalidError{}, "transport"},
		{"hostnameValue", x509.HostnameError{}, "tls"},
		{"hostnamePtr", &x509.HostnameError{}, "transport"},
		{"recordHeaderValue", tls.RecordHeaderError{}, "tls"},
		{"recordHeaderPtr", &tls.RecordHeaderError{}, "transport"},
	}
	for _, c := range cases {
		if got := classifyTransportError(c.err); got != c.want {
			t.Errorf("%s: bare class=%s, want %s", c.name, got, c.want)
		}
		wrapped := &url.Error{Op: "Get", URL: "https://example.invalid/", Err: c.err}
		if got := classifyTransportError(wrapped); got != c.want {
			t.Errorf("%s: url-wrapped class=%s, want %s", c.name, got, c.want)
		}
	}
}

// TestClassifyTransportErrorRealHandshake (loop 4): a genuine TLS
// handshake failure against an untrusted (httptest) certificate
// surfaces as a VALUE x509.UnknownAuthorityError inside
// *tls.CertificateVerificationError inside *url.Error, which
// isTLSError's *x509.UnknownAuthorityError errors.As target does not
// match — so it classifies as "transport", not "tls". The client
// uses a cloned transport with Proxy nil so the probe is hermetic
// (no ambient proxy can reroute the loopback handshake).
func TestClassifyTransportErrorRealHandshake(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = nil
	client := &http.Client{Transport: tr}
	_, err := client.Get(srv.URL)
	if err == nil {
		t.Fatal("expected a TLS verification failure, got nil error")
	}
	if got := classifyTransportError(err); got != "transport" {
		t.Errorf("real handshake failure: class=%s, want transport", got)
	}
	if isTLSError(err) {
		t.Error("real handshake failure: isTLSError must be false")
	}
}
