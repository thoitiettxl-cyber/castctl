// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package pluginhost

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// buildVerneed synthesises a .gnu.version_r section body: one
// Verneed for fileName with the given version names. The
// string table is appended after the entries; vna_name
// offsets are relative to it. Verneed/Vernaux entries are
// 16 bytes in both ELF classes, so no class parameter is
// needed.
func buildVerneed(t *testing.T, fileName string, versions []string) ([]byte, []byte) {
	t.Helper()
	strtab := []byte{0}
	strOff := map[string]uint32{}
	addStr := func(s string) uint32 {
		if off, ok := strOff[s]; ok {
			return off
		}
		off := uint32(len(strtab))
		strtab = append(strtab, []byte(s)...)
		strtab = append(strtab, 0)
		strOff[s] = off
		return off
	}
	fileOff := addStr(fileName)
	nameOffs := make([]uint32, len(versions))
	for i, v := range versions {
		nameOffs[i] = addStr(v)
	}
	// Verneed (16 bytes) + one Vernaux (16 bytes) per version.
	body := make([]byte, 0, 16+16*len(versions))
	put16 := func(v uint16) {
		var b [2]byte
		binary.LittleEndian.PutUint16(b[:], v)
		body = append(body, b[:]...)
	}
	put32 := func(v uint32) {
		var b [4]byte
		binary.LittleEndian.PutUint32(b[:], v)
		body = append(body, b[:]...)
	}
	_ = fileName
	put16(1) // vn_version
	put16(uint16(len(versions)))
	put32(fileOff)
	put32(16) // vn_aux: first Vernaux right after Verneed
	if len(versions) > 0 {
		put32(0) // vn_next: single Verneed
	} else {
		put32(0)
	}
	for i, off := range nameOffs {
		put32(0) // vna_hash (unused by the parser)
		put16(0) // vna_flags
		put16(uint16(i + 2))
		put32(off)
		if i+1 < len(versions) {
			put32(16)
		} else {
			put32(0)
		}
	}
	return body, strtab
}

func TestParseVersionNeeds(t *testing.T) {
	body, strtab := buildVerneed(t, "libc.so.6", []string{"GLIBC_2.17", "GLIBC_2.34", "GLIBC_PRIVATE"})
	max, err := parseVersionNeeds(body, strtab, binary.LittleEndian)
	if err != nil {
		t.Fatal(err)
	}
	if max != "2.34" {
		t.Fatalf("max = %q, want %q", max, "2.34")
	}
	body, strtab = buildVerneed(t, "libc.so.6", []string{})
	max, err = parseVersionNeeds(body, strtab, binary.LittleEndian)
	if err != nil {
		t.Fatal(err)
	}
	if max != "" {
		t.Fatalf("max = %q, want empty", max)
	}
	body, strtab = buildVerneed(t, "libfoo.so.1", []string{"FOO_1.0"})
	max, err = parseVersionNeeds(body, strtab, binary.LittleEndian)
	if err != nil {
		t.Fatal(err)
	}
	if max != "" {
		t.Fatalf("max = %q, want empty for non-glibc versions", max)
	}
	if _, err := parseVersionNeeds([]byte{1, 2}, strtab, binary.LittleEndian); err == nil {
		t.Fatal("truncated section: want error")
	}
}

func TestParseVersionNeedsFailClosed(t *testing.T) {
	// Red-team cases: a bad numeric GLIBC_ name, a hidden
	// aux-chain maximum, and an out-of-range name offset
	// must all refuse — never silently downgrade the max.
	body, strtab := buildVerneed(t, "libc.so.6", []string{"GLIBC_2.34", "GLIBC_2.XX"})
	if _, err := parseVersionNeeds(body, strtab, binary.LittleEndian); err == nil {
		t.Fatal("unparseable GLIBC_ name: want error, not a downgraded max")
	}
	// Aux chain cut short of vn_cnt: two declared aux
	// entries, the first with next==0 hiding the second
	// (GLIBC_2.34) behind a GLIBC_2.2.5 name.
	body, strtab = buildVerneed(t, "libc.so.6", []string{"GLIBC_2.2.5", "GLIBC_2.34"})
	// Zero the first Vernaux's next field (offset 16 + 12).
	body[16+12] = 0
	body[16+13] = 0
	body[16+14] = 0
	body[16+15] = 0
	if max, err := parseVersionNeeds(body, strtab, binary.LittleEndian); err == nil {
		t.Fatalf("cut aux chain: want error, got max %q", max)
	}
	// Out-of-range name offset: patch the first Vernaux's
	// name offset (offset 16 + 8) to 0xFFFFFF00.
	body, strtab = buildVerneed(t, "libc.so.6", []string{"GLIBC_2.34"})
	binary.LittleEndian.PutUint32(body[16+8:], 0xFFFFFF00)
	if _, err := parseVersionNeeds(body, strtab, binary.LittleEndian); err == nil {
		t.Fatal("out-of-range name offset: want error")
	}
	// GLIBC_PRIVATE stays ignored (non-numeric name).
	body, strtab = buildVerneed(t, "libc.so.6", []string{"GLIBC_PRIVATE"})
	max, err := parseVersionNeeds(body, strtab, binary.LittleEndian)
	if err != nil || max != "" {
		t.Fatalf("GLIBC_PRIVATE: max=%q err=%v, want empty/nil", max, err)
	}
}

func TestMaxRequiredGLIBCRealBinary(t *testing.T) {
	if !testBinaryHasGLIBCReqs {
		t.Skip("test binary is not a dynamically linked glibc binary")
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	max, err := MaxRequiredGLIBC(self)
	if err != nil {
		t.Fatal(err)
	}
	if max == "" {
		t.Fatalf("MaxRequiredGLIBC(%s) = empty, want a GLIBC_ version", self)
	}
	if !strings.Contains(max, ".") {
		t.Fatalf("max = %q, want major.minor", max)
	}
	if _, err := MaxRequiredGLIBC("/dev/null"); err == nil {
		t.Fatal("non-ELF file: want error")
	}
}

func TestCheckPluginCompat(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	// The host binary itself must pass the compat gate: its
	// requirements are satisfiable by the running libc by
	// construction.
	if err := CheckPluginCompat(self); err != nil {
		t.Fatalf("CheckPluginCompat(self) = %v, want nil", err)
	}
	// A non-ELF file is outside the compat gate (format gate
	// is dlopen's job).
	if err := CheckPluginCompat("/dev/null"); err != nil {
		t.Fatalf("CheckPluginCompat(/dev/null) = %v, want nil for non-ELF", err)
	}
}

func TestGlibcVersionCompare(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"2.17", "2.17", 0},
		{"2.17", "2.34", -1},
		{"2.34", "2.17", 1},
		{"2.4", "2.17", -1},
		{"3.0", "2.99", 1},
		// Distro suffixes from real gnu_get_libc_version
		// strings (Debian glibc 2.44 reports "2.44-0"):
		// only leading digits matter.
		{"2.44-0", "2.44", 0},
		{"2.17-0ubuntu1", "2.17", 0},
		// The full triple is compared: a patch-level
		// requirement must not pass on a lower patch.
		{"2.44.1", "2.44", 1},
		{"2.44", "2.44.1", -1},
		{"2.3.4", "2.3.2", 1},
		{"2.3.2", "2.3.4", -1},
		{"2.2.5", "2.2.5", 0},
	}
	for _, tc := range cases {
		va, err := parseGlibcVersion(tc.a)
		if err != nil {
			t.Fatal(err)
		}
		vb, err := parseGlibcVersion(tc.b)
		if err != nil {
			t.Fatal(err)
		}
		if got := compareGlibcVersion(va, vb); got != tc.want {
			t.Fatalf("compare(%q,%q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
	if _, err := parseGlibcVersion("banana"); err == nil {
		t.Fatal("bad version: want error")
	}
	if _, err := parseGlibcVersion("2"); err == nil {
		t.Fatal("version without minor: want error")
	}
}

// TestCheckPluginCompatNoShadowPathLeak: compat-gate
// errors must never embed the checked path (the loader
// passes the shadow path, whose pid directory must not
// leak into skip reasons or check output).
func TestCheckPluginCompatNoShadowPathLeak(t *testing.T) {
	shadow := filepath.Join(t.TempDir(), "castctl-pluginhost", "pid-424242", "castctl-plugin-echo-abc.so")
	err := CheckPluginCompat(shadow)
	if err == nil {
		t.Fatal("missing file: want error")
	}
	if strings.Contains(err.Error(), "pid-424242") || strings.Contains(err.Error(), "castctl-pluginhost") {
		t.Fatalf("compat error leaked shadow path: %v", err)
	}
	if _, err := MaxRequiredGLIBC(shadow); err == nil {
		t.Fatal("MaxRequiredGLIBC missing file: want error")
	} else if strings.Contains(err.Error(), "pid-424242") || strings.Contains(err.Error(), "castctl-pluginhost") {
		t.Fatalf("MaxRequiredGLIBC error leaked shadow path: %v", err)
	}
}

// TestParseVersionNeedsShortVnNextRefuses (B-N8): a short
// vnNext that lands on an entry's own aux bytes must refuse
// the load with a clear error, never compute a downgraded
// maximum. Construction verbatim from the red-team probe:
// entry1 (GLIBC_2.17, vnNext=16) + entry2 (GLIBC_2.99 at
// offset 32). The well-formed control (vnNext=32) must
// still find 2.99.
func TestParseVersionNeedsShortVnNextRefuses(t *testing.T) {
	entry := func(vnCnt uint16, vnAux, vnNext uint32, auxes ...[]byte) []byte {
		b := make([]byte, 16)
		binary.LittleEndian.PutUint16(b[2:], vnCnt)
		binary.LittleEndian.PutUint32(b[8:], vnAux)
		binary.LittleEndian.PutUint32(b[12:], vnNext)
		out := append([]byte{}, b...)
		for _, a := range auxes {
			out = append(out, a...)
		}
		return out
	}
	aux := func(nameOff, next uint32) []byte {
		b := make([]byte, 16)
		binary.LittleEndian.PutUint32(b[8:], nameOff)
		binary.LittleEndian.PutUint32(b[12:], next)
		return b
	}
	strtab2 := []byte("GLIBC_2.17\x00GLIBC_2.99\x00")
	e1 := entry(1, 16, 16, aux(0, 0))
	e2 := entry(1, 16, 0, aux(11, 0))
	two := append(append([]byte{}, e1...), e2...)
	got, err := parseVersionNeeds(two, strtab2, binary.LittleEndian)
	if err == nil {
		t.Fatalf("short vnNext: want error, got max %q (downgraded maximum; true max is 2.99)", got)
	}
	if !strings.Contains(err.Error(), "vnNext") {
		t.Fatalf("short vnNext error must name vnNext: %v", err)
	}
	e1ok := entry(1, 16, 32, aux(0, 0))
	twoOK := append(append([]byte{}, e1ok...), e2...)
	got, err = parseVersionNeeds(twoOK, strtab2, binary.LittleEndian)
	if err != nil || got != "2.99" {
		t.Fatalf("well-formed vnNext=32: got=%q err=%v, want 2.99/nil", got, err)
	}
	// Headers-first layout, as real linkers emit (the
	// layout the qemu echo load exercises): both Verneed
	// headers first, then both aux entries. Entry1's
	// vnAux=32 skips past entry2's header; vnNext=16
	// stops before the aux range and is well-formed.
	header := func(vnCnt uint16, vnAux, vnNext uint32) []byte {
		b := make([]byte, 16)
		binary.LittleEndian.PutUint16(b[2:], vnCnt)
		binary.LittleEndian.PutUint32(b[8:], vnAux)
		binary.LittleEndian.PutUint32(b[12:], vnNext)
		return b
	}
	hf := append([]byte{}, header(1, 32, 16)...)
	hf = append(hf, header(1, 32, 0)...)
	hf = append(hf, aux(0, 0)...)
	hf = append(hf, aux(11, 0)...)
	got, err = parseVersionNeeds(hf, strtab2, binary.LittleEndian)
	if err != nil || got != "2.99" {
		t.Fatalf("headers-first layout: got=%q err=%v, want 2.99/nil", got, err)
	}
	// A vnNext inside the entry's own header refuses.
	e1hdr := entry(1, 16, 8, aux(0, 0))
	got, err = parseVersionNeeds(append(append([]byte{}, e1hdr...), e2...), strtab2, binary.LittleEndian)
	if err == nil {
		t.Fatalf("vnNext inside header: want error, got max %q", got)
	}
}
