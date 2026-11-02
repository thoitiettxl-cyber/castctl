// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package pluginhost

import (
	"debug/elf"
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

// TestParseVersionNeedsLongJumpVnNextRefuses (N8 long-jump):
// the verifier's exact headers-first probe. Header1
// {vnCnt=1, vnAux=32, vnNext=48} at offset 0, header2 at
// offset 16, aux1 at 32 = GLIBC_2.17, aux2 at 48 =
// GLIBC_2.99. A vnNext of 48 jumps over header2, and the
// aux bytes at 48 parse as a header with vnCnt=0 and
// vnNext=0, so the old past-ranges-only check returned
// "2.17" with no error. A long jump over a header must be
// refused, never returned as a silently downgraded
// maximum. The well-formed control (vnNext=32, i.e. the
// headers-first layout above) must still find 2.99.
func TestParseVersionNeedsLongJumpVnNextRefuses(t *testing.T) {
	header := func(vnCnt uint16, vnAux, vnNext uint32) []byte {
		b := make([]byte, 16)
		binary.LittleEndian.PutUint16(b[2:], vnCnt)
		binary.LittleEndian.PutUint32(b[8:], vnAux)
		binary.LittleEndian.PutUint32(b[12:], vnNext)
		return b
	}
	aux := func(nameOff, next uint32) []byte {
		b := make([]byte, 16)
		binary.LittleEndian.PutUint32(b[8:], nameOff)
		binary.LittleEndian.PutUint32(b[12:], next)
		return b
	}
	strtab := []byte("GLIBC_2.17\x00GLIBC_2.99\x00")
	probe := append([]byte{}, header(1, 32, 48)...)
	probe = append(probe, header(1, 32, 0)...)
	probe = append(probe, aux(0, 0)...)
	probe = append(probe, aux(11, 0)...)
	got, err := parseVersionNeeds(probe, strtab, binary.LittleEndian)
	if err == nil {
		t.Fatalf("long-jump vnNext=48: want error, got max %q (downgraded maximum; true max is 2.99)", got)
	}
	// Well-formed control: same layout with vnNext=32
	// (header1 jumps to its aux, header2 is reached via
	// vnNext=16 from header1's position) still finds
	// 2.99. This is the headers-first layout real linkers
	// emit, with header2's vnAux=32 reaching aux2 at 48.
	control := append([]byte{}, header(1, 32, 16)...)
	control = append(control, header(1, 32, 0)...)
	control = append(control, aux(0, 0)...)
	control = append(control, aux(11, 0)...)
	got, err = parseVersionNeeds(control, strtab, binary.LittleEndian)
	if err != nil || got != "2.99" {
		t.Fatalf("headers-first control vnNext=32: got=%q err=%v, want 2.99/nil", got, err)
	}
}

// TestParseVersionNeedsRealSection feeds parseVersionNeeds
// a REAL .gnu.version_r section extracted from the test
// binary itself (a real linker output on this VM), not a
// synthesised layout: the whole-section validation must
// accept real linker output. The result must agree with
// MaxRequiredGLIBC on the same binary.
func TestParseVersionNeedsRealSection(t *testing.T) {
	if !testBinaryHasGLIBCReqs {
		t.Skip("test binary is not a dynamically linked glibc binary")
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	f, err := elf.Open(self)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	sec := f.Section(".gnu.version_r")
	if sec == nil {
		t.Fatal("test binary has no .gnu.version_r section")
	}
	data, err := sec.Data()
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Fatal("real .gnu.version_r section is empty")
	}
	strtab, err := versionStringTable(f, sec)
	if err != nil {
		t.Fatal(err)
	}
	got, err := parseVersionNeeds(data, strtab, f.ByteOrder)
	if err != nil {
		t.Fatalf("real section: parseVersionNeeds = %v, want nil (section size %d, sh_info %d)", err, len(data), sec.Info)
	}
	want, err := MaxRequiredGLIBC(self)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("real section: parseVersionNeeds = %q, MaxRequiredGLIBC = %q, want agreement", got, want)
	}
	if got == "" {
		t.Fatal("real section: want a GLIBC_ version, got empty")
	}
}

// TestParseVersionNeedsStrtabBoundRedTeam reproduces the
// red-team vnCnt/vna_next divergence byte-for-byte at the
// section level: H1 {vnCnt=1, vnAux=16, vnNext=32}, aux1
// @16 = GLIBC_2.2.5 with vna_next=16, slot @32 as aux =
// GLIBC_2.34 (as a header: vnCnt=0, vnNext=0). The old
// chain walk returned "2.2.5" with no error. The strtab
// superset bound must report >= 2.34 or refuse.
func TestParseVersionNeedsStrtabBoundRedTeam(t *testing.T) {
	header := func(vnCnt uint16, vnAux, vnNext uint32) []byte {
		b := make([]byte, 16)
		binary.LittleEndian.PutUint16(b[2:], vnCnt)
		binary.LittleEndian.PutUint32(b[8:], vnAux)
		binary.LittleEndian.PutUint32(b[12:], vnNext)
		return b
	}
	aux := func(nameOff, next uint32) []byte {
		b := make([]byte, 16)
		binary.LittleEndian.PutUint32(b[8:], nameOff)
		binary.LittleEndian.PutUint32(b[12:], next)
		return b
	}
	strtab := []byte("GLIBC_2.2.5\x00GLIBC_2.34\x00")
	section := append([]byte{}, header(1, 16, 32)...)
	section = append(section, aux(0, 16)...)
	section = append(section, aux(11, 0)...)
	got, err := parseVersionNeeds(section, strtab, binary.LittleEndian)
	if err == nil && !atLeastVersion(t, got, "2.34") {
		t.Fatalf("red-team section: got max %q, want >= 2.34 or refusal (hidden requirement is GLIBC_2.34)", got)
	}
}

// TestParseVersionNeedsStrtabBoundVerifierTiling reproduces
// the verifier's 64-byte tiling section byte-for-byte: H1
// {vnCnt=2, vnAux=16, vnNext=48} @0, slot @16 as header
// {vnCnt=1, vnAux=32, vnNext=16} / as aux {nameOff=32
// ("zz"), next=16}, A1 @32 = GLIBC_2.17, slot @48 as
// header {vnCnt=0, vnAux=11, vnNext=0} / as aux
// {nameOff=11 (GLIBC_2.99), next=0}. The old chain walk
// returned "2.17" with no error. The strtab superset bound
// must report >= 2.99 or refuse.
func TestParseVersionNeedsStrtabBoundVerifierTiling(t *testing.T) {
	slot16 := make([]byte, 16)
	binary.LittleEndian.PutUint16(slot16[2:], 1)
	binary.LittleEndian.PutUint32(slot16[8:], 32)
	binary.LittleEndian.PutUint32(slot16[12:], 16)
	slot48 := make([]byte, 16)
	binary.LittleEndian.PutUint32(slot48[8:], 11)
	header := func(vnCnt uint16, vnAux, vnNext uint32) []byte {
		b := make([]byte, 16)
		binary.LittleEndian.PutUint16(b[2:], vnCnt)
		binary.LittleEndian.PutUint32(b[8:], vnAux)
		binary.LittleEndian.PutUint32(b[12:], vnNext)
		return b
	}
	aux := func(nameOff, next uint32) []byte {
		b := make([]byte, 16)
		binary.LittleEndian.PutUint32(b[8:], nameOff)
		binary.LittleEndian.PutUint32(b[12:], next)
		return b
	}
	strtab := []byte("GLIBC_2.17\x00GLIBC_2.99\x00")
	for len(strtab) < 32 {
		strtab = append(strtab, 0)
	}
	strtab = append(strtab, []byte("zz\x00")...)
	section := append([]byte{}, header(2, 16, 48)...)
	section = append(section, slot16...)
	section = append(section, aux(0, 0)...)
	section = append(section, slot48...)
	got, err := parseVersionNeeds(section, strtab, binary.LittleEndian)
	if err == nil && !atLeastVersion(t, got, "2.99") {
		t.Fatalf("verifier tiling section: got max %q, want >= 2.99 or refusal (hidden requirement is GLIBC_2.99)", got)
	}
}

// atLeastVersion reports whether got parses as a glibc
// version >= want. It fails the test on an unparseable
// got, since a reported maximum must always parse.
func atLeastVersion(t *testing.T, got, want string) bool {
	t.Helper()
	gv, err := parseGlibcVersion(got)
	if err != nil {
		t.Fatalf("reported max %q does not parse: %v", got, err)
	}
	wv, err := parseGlibcVersion(want)
	if err != nil {
		t.Fatal(err)
	}
	return compareGlibcVersion(gv, wv) >= 0
}

// TestParseVersionNeedsStrtabBoundScannerRules pins the
// conservative scanner semantics over the strtab the walk
// already uses: an unreferenced well-formed GLIBC_ string
// counts toward the maximum (it may be a hidden
// requirement), an unreferenced malformed numeric GLIBC_
// string refuses, and a non-numeric GLIBC_ name stays
// ignored.
func TestParseVersionNeedsStrtabBoundScannerRules(t *testing.T) {
	body, baseStrtab := buildVerneed(t, "libc.so.6", []string{"GLIBC_2.17"})
	cases := []struct {
		name    string
		extra   string
		want    string
		wantErr bool
	}{
		{"unreferenced higher version counts", "GLIBC_2.99\x00", "2.99", false},
		{"unreferenced malformed version refuses", "GLIBC_2.XX\x00", "", true},
		{"non-numeric name stays ignored", "GLIBC_PRIVATE\x00", "2.17", false},
		{"version string inside a longer string counts", "XGLIBC_2.99\x00", "2.99", false},
		{"version string with letter suffix refuses", "GLIBC_2.34x\x00", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			strtab := append(append([]byte{}, baseStrtab...), []byte(tc.extra)...)
			got, err := parseVersionNeeds(body, strtab, binary.LittleEndian)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("strtab extra %q: want error, got max %q", tc.extra, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("strtab extra %q: got error %v, want max %q", tc.extra, err, tc.want)
			}
			if got != tc.want {
				t.Fatalf("strtab extra %q: got max %q, want %q", tc.extra, got, tc.want)
			}
		})
	}
}

// TestParseVersionNeedsStrtabBoundRealSection is the
// real-section control for the bound: on a real linker
// output the bound must agree with MaxRequiredGLIBC and
// report a real version (the bound must not refuse or
// inflate real output).
func TestParseVersionNeedsStrtabBoundRealSection(t *testing.T) {
	if !testBinaryHasGLIBCReqs {
		t.Skip("test binary is not a dynamically linked glibc binary")
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	f, err := elf.Open(self)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	sec := f.Section(".gnu.version_r")
	if sec == nil {
		t.Fatal("test binary has no .gnu.version_r section")
	}
	data, err := sec.Data()
	if err != nil {
		t.Fatal(err)
	}
	strtab, err := versionStringTable(f, sec)
	if err != nil {
		t.Fatal(err)
	}
	got, err := parseVersionNeeds(data, strtab, f.ByteOrder)
	if err != nil {
		t.Fatalf("real section with strtab bound: %v", err)
	}
	want, err := MaxRequiredGLIBC(self)
	if err != nil {
		t.Fatal(err)
	}
	if got != want || got == "" {
		t.Fatalf("real section: parseVersionNeeds = %q, MaxRequiredGLIBC = %q, want agreement on a version", got, want)
	}
}

// verneedSingle builds one Verneed header plus one Vernaux
// in the given byte order, naming the string at nameOff.
func verneedSingle(order binary.ByteOrder, nameOff uint32) []byte {
	b := make([]byte, 32)
	order.PutUint16(b[2:], 1)
	order.PutUint32(b[8:], 16)
	order.PutUint32(b[12:], 0)
	order.PutUint32(b[16+8:], nameOff)
	order.PutUint32(b[16+12:], 0)
	return b
}

type craftedELFOptions struct {
	class32   bool
	bigEndian bool
	dynamic   string // "valid", "none", "badAddr", "missingStrsz"
	shInfo    uint32
	section   []byte
	strtab    []byte
}

// buildCraftedELF writes a minimal ELF64/ELF32, LE/BE file
// with one PT_LOAD covering the whole file, an optional
// PT_DYNAMIC, a .gnu.version_r section (Link = .dynstr
// index), a .dynstr section, and a .shstrtab. DT_STRTAB
// points at the .dynstr file bytes through the PT_LOAD
// mapping in the "valid" case. It returns the file path.
func buildCraftedELF(t *testing.T, opts craftedELFOptions) string {
	t.Helper()
	var order binary.ByteOrder = binary.LittleEndian
	if opts.bigEndian {
		order = binary.BigEndian
	}
	var ehsize, phentsize, shentsize, dynEntrySize int
	if opts.class32 {
		ehsize, phentsize, shentsize, dynEntrySize = 52, 32, 40, 8
	} else {
		ehsize, phentsize, shentsize, dynEntrySize = 64, 56, 64, 16
	}
	phnum := 1
	if opts.dynamic != "none" {
		phnum = 2
	}
	phoff := ehsize
	verneedOff := phoff + phnum*phentsize
	dynstrOff := verneedOff + len(opts.section)
	dynOff := dynstrOff + len(opts.strtab)
	dynCount := 0
	switch opts.dynamic {
	case "valid", "badAddr":
		dynCount = 3
	case "missingStrsz":
		dynCount = 2
	}
	dynSize := dynCount * dynEntrySize
	shstr := []byte("\x00.gnu.version_r\x00.dynstr\x00.shstrtab\x00")
	shstrOff := dynOff + dynSize
	shoff := shstrOff + len(shstr)
	fileSize := shoff + 4*shentsize
	var vaddrBase uint64 = 0x400000
	if opts.class32 {
		vaddrBase = 0x08048000
	}
	buf := make([]byte, fileSize)
	put16 := func(off int, v uint16) { order.PutUint16(buf[off:], v) }
	put32 := func(off int, v uint32) { order.PutUint32(buf[off:], v) }
	put64 := func(off int, v uint64) { order.PutUint64(buf[off:], v) }
	// ELF header.
	buf[0], buf[1], buf[2], buf[3] = 0x7f, 'E', 'L', 'F'
	if opts.class32 {
		buf[4] = 1
	} else {
		buf[4] = 2
	}
	if opts.bigEndian {
		buf[5] = 2
	} else {
		buf[5] = 1
	}
	buf[6] = 1
	put16(16, 3) // ET_DYN
	if opts.class32 {
		put16(18, 3) // EM_386
	} else {
		put16(18, 62) // EM_X86_64
	}
	put32(20, 1)
	if opts.class32 {
		put32(24, 0)
		put32(28, uint32(phoff))
		put32(32, uint32(shoff))
		put32(36, 0)
		put16(40, uint16(ehsize))
		put16(42, uint16(phentsize))
		put16(44, uint16(phnum))
		put16(46, uint16(shentsize))
		put16(48, 4)
		put16(50, 3)
	} else {
		put64(24, 0)
		put64(32, uint64(phoff))
		put64(40, uint64(shoff))
		put32(48, 0)
		put16(52, uint16(ehsize))
		put16(54, uint16(phentsize))
		put16(56, uint16(phnum))
		put16(58, uint16(shentsize))
		put16(60, 4)
		put16(62, 3)
	}
	// PT_LOAD program header.
	writePhdr := func(off int, typ uint32, fileOff, vaddr, filesz uint64, flags uint32) {
		if opts.class32 {
			put32(off+0, typ)
			put32(off+4, uint32(fileOff))
			put32(off+8, uint32(vaddr))
			put32(off+12, uint32(vaddr))
			put32(off+16, uint32(filesz))
			put32(off+20, uint32(filesz))
			put32(off+24, flags)
			put32(off+28, 0x1000)
			return
		}
		put32(off+0, typ)
		put32(off+4, flags)
		put64(off+8, fileOff)
		put64(off+16, vaddr)
		put64(off+24, vaddr)
		put64(off+32, filesz)
		put64(off+40, filesz)
		put64(off+48, 0x1000)
	}
	writePhdr(phoff, 1, 0, vaddrBase, uint64(fileSize), 4)
	if opts.dynamic != "none" {
		writePhdr(phoff+phentsize, 2, uint64(dynOff), vaddrBase+uint64(dynOff), uint64(dynSize), 6)
	}
	// Section contents.
	copy(buf[verneedOff:], opts.section)
	copy(buf[dynstrOff:], opts.strtab)
	copy(buf[shstrOff:], shstr)
	// PT_DYNAMIC entries.
	if opts.dynamic != "none" {
		strtabVaddr := vaddrBase + uint64(dynstrOff)
		if opts.dynamic == "badAddr" {
			strtabVaddr = vaddrBase + 0x100000
		}
		entries := [][2]uint64{{5, strtabVaddr}}
		if opts.dynamic != "missingStrsz" {
			entries = append(entries, [2]uint64{10, uint64(len(opts.strtab))})
		}
		entries = append(entries, [2]uint64{0, 0})
		for i, e := range entries {
			off := dynOff + i*dynEntrySize
			if opts.class32 {
				put32(off, uint32(int32(e[0])))
				put32(off+4, uint32(e[1]))
			} else {
				put64(off, e[0])
				put64(off+8, e[1])
			}
		}
	}
	// Section headers.
	writeShdr := func(off int, name, typ uint32, flags, addr, fileOff, size uint64, link, info uint32, align uint64) {
		if opts.class32 {
			put32(off+0, name)
			put32(off+4, typ)
			put32(off+8, uint32(flags))
			put32(off+12, uint32(addr))
			put32(off+16, uint32(fileOff))
			put32(off+20, uint32(size))
			put32(off+24, link)
			put32(off+28, info)
			put32(off+32, uint32(align))
			put32(off+36, 0)
			return
		}
		put32(off+0, name)
		put32(off+4, typ)
		put64(off+8, flags)
		put64(off+16, addr)
		put64(off+24, fileOff)
		put64(off+32, size)
		put32(off+40, link)
		put32(off+44, info)
		put64(off+48, align)
		put64(off+56, 0)
	}
	writeShdr(shoff, 0, 0, 0, 0, 0, 0, 0, 0, 0)
	writeShdr(shoff+shentsize, 1, 0x6ffffffe, 2, vaddrBase+uint64(verneedOff), uint64(verneedOff), uint64(len(opts.section)), 2, opts.shInfo, 8)
	writeShdr(shoff+2*shentsize, 16, 3, 2, vaddrBase+uint64(dynstrOff), uint64(dynstrOff), uint64(len(opts.strtab)), 0, 0, 1)
	writeShdr(shoff+3*shentsize, 24, 3, 0, 0, uint64(shstrOff), uint64(len(shstr)), 0, 0, 1)
	path := filepath.Join(t.TempDir(), "crafted.so")
	if err := os.WriteFile(path, buf, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestMaxRequiredGLIBCCraftedELFStrtabBound runs the two
// crafted sections end to end through MaxRequiredGLIBC on
// minimal ELFs with a valid PT_DYNAMIC/DT_STRTAB, plus
// well-formed controls in 64-bit LE/BE and 32-bit LE.
func TestMaxRequiredGLIBCCraftedELFStrtabBound(t *testing.T) {
	// Red-team section (see TestParseVersionNeedsStrtabBoundRedTeam).
	redSection := func(order binary.ByteOrder) []byte {
		header := func(vnCnt uint16, vnAux, vnNext uint32) []byte {
			b := make([]byte, 16)
			order.PutUint16(b[2:], vnCnt)
			order.PutUint32(b[8:], vnAux)
			order.PutUint32(b[12:], vnNext)
			return b
		}
		aux := func(nameOff, next uint32) []byte {
			b := make([]byte, 16)
			order.PutUint32(b[8:], nameOff)
			order.PutUint32(b[12:], next)
			return b
		}
		section := append([]byte{}, header(1, 16, 32)...)
		section = append(section, aux(0, 16)...)
		section = append(section, aux(11, 0)...)
		return section
	}
	redStrtab := []byte("GLIBC_2.2.5\x00GLIBC_2.34\x00")
	path := buildCraftedELF(t, craftedELFOptions{dynamic: "valid", shInfo: 2, section: redSection(binary.LittleEndian), strtab: redStrtab})
	got, err := MaxRequiredGLIBC(path)
	if err == nil && !atLeastVersion(t, got, "2.34") {
		t.Fatalf("crafted ELF red-team section: got max %q, want >= 2.34 or refusal", got)
	}
	// Verifier tiling section (see TestParseVersionNeedsStrtabBoundVerifierTiling).
	slot16 := make([]byte, 16)
	binary.LittleEndian.PutUint16(slot16[2:], 1)
	binary.LittleEndian.PutUint32(slot16[8:], 32)
	binary.LittleEndian.PutUint32(slot16[12:], 16)
	slot48 := make([]byte, 16)
	binary.LittleEndian.PutUint32(slot48[8:], 11)
	header := func(vnCnt uint16, vnAux, vnNext uint32) []byte {
		b := make([]byte, 16)
		binary.LittleEndian.PutUint16(b[2:], vnCnt)
		binary.LittleEndian.PutUint32(b[8:], vnAux)
		binary.LittleEndian.PutUint32(b[12:], vnNext)
		return b
	}
	aux := func(nameOff, next uint32) []byte {
		b := make([]byte, 16)
		binary.LittleEndian.PutUint32(b[8:], nameOff)
		binary.LittleEndian.PutUint32(b[12:], next)
		return b
	}
	tilingStrtab := []byte("GLIBC_2.17\x00GLIBC_2.99\x00")
	for len(tilingStrtab) < 32 {
		tilingStrtab = append(tilingStrtab, 0)
	}
	tilingStrtab = append(tilingStrtab, []byte("zz\x00")...)
	tiling := append([]byte{}, header(2, 16, 48)...)
	tiling = append(tiling, slot16...)
	tiling = append(tiling, aux(0, 0)...)
	tiling = append(tiling, slot48...)
	path = buildCraftedELF(t, craftedELFOptions{dynamic: "valid", shInfo: 2, section: tiling, strtab: tilingStrtab})
	got, err = MaxRequiredGLIBC(path)
	if err == nil && !atLeastVersion(t, got, "2.99") {
		t.Fatalf("crafted ELF verifier tiling section: got max %q, want >= 2.99 or refusal", got)
	}
	// Well-formed controls: single entry naming GLIBC_2.17.
	controlStrtab := []byte("\x00GLIBC_2.17\x00")
	controls := []struct {
		name string
		opts craftedELFOptions
	}{
		{"64-bit little-endian", craftedELFOptions{dynamic: "valid", shInfo: 1, section: verneedSingle(binary.LittleEndian, 1), strtab: controlStrtab}},
		{"64-bit big-endian", craftedELFOptions{bigEndian: true, dynamic: "valid", shInfo: 1, section: verneedSingle(binary.BigEndian, 1), strtab: controlStrtab}},
		{"32-bit little-endian", craftedELFOptions{class32: true, dynamic: "valid", shInfo: 1, section: verneedSingle(binary.LittleEndian, 1), strtab: controlStrtab}},
	}
	for _, tc := range controls {
		t.Run(tc.name, func(t *testing.T) {
			path := buildCraftedELF(t, tc.opts)
			got, err := MaxRequiredGLIBC(path)
			if err != nil || got != "2.17" {
				t.Fatalf("well-formed control: got=%q err=%v, want 2.17/nil", got, err)
			}
		})
	}
}

// TestMaxRequiredGLIBCRefusesUnresolvableDynStrtab pins the
// fail-closed side of the bound: a well-formed verneed
// section whose DT_STRTAB cannot be resolved consistently
// (no PT_DYNAMIC, DT_STRTAB outside every PT_LOAD, or no
// DT_STRSZ) must refuse, while the same ELF with a valid
// PT_DYNAMIC still reports its version.
func TestMaxRequiredGLIBCRefusesUnresolvableDynStrtab(t *testing.T) {
	controlStrtab := []byte("\x00GLIBC_2.17\x00")
	section := verneedSingle(binary.LittleEndian, 1)
	cases := []struct {
		name    string
		opts    craftedELFOptions
		wantErr bool
	}{
		{"valid dynamic reports version", craftedELFOptions{dynamic: "valid", shInfo: 1, section: section, strtab: controlStrtab}, false},
		{"no PT_DYNAMIC refuses", craftedELFOptions{dynamic: "none", shInfo: 1, section: section, strtab: controlStrtab}, true},
		{"DT_STRTAB outside PT_LOAD refuses", craftedELFOptions{dynamic: "badAddr", shInfo: 1, section: section, strtab: controlStrtab}, true},
		{"missing DT_STRSZ refuses", craftedELFOptions{dynamic: "missingStrsz", shInfo: 1, section: section, strtab: controlStrtab}, true},
		{"32-bit no PT_DYNAMIC refuses", craftedELFOptions{class32: true, dynamic: "none", shInfo: 1, section: section, strtab: controlStrtab}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := buildCraftedELF(t, tc.opts)
			got, err := MaxRequiredGLIBC(path)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("unresolvable DT_STRTAB: want error, got max %q", got)
				}
				if !strings.Contains(err.Error(), "DT_STRTAB") {
					t.Fatalf("unresolvable DT_STRTAB error must name DT_STRTAB: %v", err)
				}
				return
			}
			if err != nil || got != "2.17" {
				t.Fatalf("valid control: got=%q err=%v, want 2.17/nil", got, err)
			}
		})
	}
}
