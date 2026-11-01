// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package pluginhost

import (
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// openErrorWithoutPath strips the path from an os.Open-style
// error: *os.PathError embeds the checked path, and the
// loader passes the SHADOW path here (TempDir layout + pid
// directory), which must never leak into skip reasons or
// check output. The errno/reason survives; the layout does
// not. Non-PathError values pass through unchanged apart
// from the wrapping noun.
func openErrorWithoutPath(what string, err error) error {
	var pe *os.PathError
	if errors.As(err, &pe) {
		return fmt.Errorf("%s: %v", what, pe.Err)
	}
	return fmt.Errorf("%s: %v", what, err)
}

// isELFFile reports whether path starts with the ELF magic. A
// file shorter than the 4-byte magic cannot be ELF. A
// directory is an error: the compat gate must not silently
// pass a non-file. Errors never embed path (see
// openErrorWithoutPath).
func isELFFile(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, openErrorWithoutPath("cannot open plugin file", err)
	}
	defer func() { _ = f.Close() }()
	if info, err := f.Stat(); err != nil {
		return false, openErrorWithoutPath("cannot stat plugin file", err)
	} else if info.IsDir() {
		return false, fmt.Errorf("plugin file is a directory")
	}
	var magic [4]byte
	n, _ := f.Read(magic[:])
	if n < len(magic) {
		return false, nil
	}
	return magic[0] == 0x7f && magic[1] == 'E' && magic[2] == 'L' && magic[3] == 'F', nil
}

// Glibc compatibility gate: the loader must compare the
// plugin's highest required GLIBC_ symbol version against
// the running libc and refuse with a clear error instead of
// crashing. This check runs BEFORE dlopen: a too-new plugin
// must never reach the dynamic loader.
//
// Mechanism: parse the plugin ELF's .gnu.version_r (VERNEED)
// entries with debug/elf (no new dependency) and read the
// running libc version via gnu_get_libc_version on cgo/glibc
// builds (see version_glibc.go). On builds where the running
// version cannot be known (no-cgo, darwin, windows), a plugin
// WITH version requirements is refused fail-closed — the check
// is never claimed as passed when it did not run; a plugin
// with NO requirements is compatible by construction. The
// build-time readelf gate in module/build.sh and
// .github/workflows/release.yaml is a different check (it
// gates the CORE binary); it is not the runtime check here.
//
// Build floor vs running libc (documented in docs/plugins.md):
// official plugins build against GLIBC 2.17. The gate
// compares against the RUNNING libc, whatever it is; 2.17 is
// a documentation fact, not a constant in this check.
// Droidspaces provides its own glibc on the phone; its
// version is recorded only from the on-device check, never
// assumed here.

type glibcVersion struct {
	major int
	minor int
	patch int
}

func (v glibcVersion) String() string {
	s := strconv.Itoa(v.major) + "." + strconv.Itoa(v.minor)
	if v.patch != 0 {
		s += "." + strconv.Itoa(v.patch)
	}
	return s
}

// parseGlibcVersion parses "major.minor[.patch]", tolerating
// the distro suffixes and extra components real
// gnu_get_libc_version strings carry (e.g. Debian's
// "2.44-0"): only the leading digits of the first three
// dot-separated components matter. The full triple is
// compared: a plugin requiring GLIBC_2.3.4 must not pass on
// a 2.3.2 libc.
func parseGlibcVersion(s string) (glibcVersion, error) {
	parts := strings.Split(s, ".")
	if len(parts) < 2 {
		return glibcVersion{}, fmt.Errorf("invalid glibc version %q", s)
	}
	major, err := leadingInt(parts[0])
	if err != nil {
		return glibcVersion{}, fmt.Errorf("invalid glibc version %q", s)
	}
	minor, err := leadingInt(parts[1])
	if err != nil {
		return glibcVersion{}, fmt.Errorf("invalid glibc version %q", s)
	}
	v := glibcVersion{major: major, minor: minor}
	if len(parts) > 2 {
		patch, err := leadingInt(parts[2])
		if err != nil {
			return glibcVersion{}, fmt.Errorf("invalid glibc version %q", s)
		}
		v.patch = patch
	}
	return v, nil
}

// leadingInt parses the leading digit run of part.
func leadingInt(part string) (int, error) {
	i := 0
	for i < len(part) && part[i] >= '0' && part[i] <= '9' {
		i++
	}
	if i == 0 {
		return 0, fmt.Errorf("no leading digits")
	}
	return strconv.Atoi(part[:i])
}

func compareGlibcVersion(a, b glibcVersion) int {
	if a.major != b.major {
		if a.major < b.major {
			return -1
		}
		return 1
	}
	if a.minor != b.minor {
		if a.minor < b.minor {
			return -1
		}
		return 1
	}
	if a.patch != b.patch {
		if a.patch < b.patch {
			return -1
		}
		return 1
	}
	return 0
}

// MaxRequiredGLIBC returns the highest GLIBC_x.y version the ELF
// file at path requires, or "" when it requires none. A non-ELF
// file, or an ELF whose version section cannot be read, is an
// error: the loader must not guess. (Deliberate asymmetry
// with CheckPluginCompat, which returns nil for non-ELF
// files: the format gate belongs to dlopen, not to this
// check, while MaxRequiredGLIBC as a standalone reader must
// not silently report "" for a file it could not parse.
// Both behaviours are pinned by tests.) Errors never embed
// path (see openErrorWithoutPath).
func MaxRequiredGLIBC(path string) (string, error) {
	f, err := elf.Open(path)
	if err != nil {
		return "", openErrorWithoutPath("read plugin elf", err)
	}
	defer func() { _ = f.Close() }()
	sec := f.Section(".gnu.version_r")
	if sec == nil {
		return "", nil
	}
	data, err := sec.Data()
	if err != nil {
		return "", fmt.Errorf("read plugin version section: %w", err)
	}
	strtab, err := versionStringTable(f, sec)
	if err != nil {
		return "", err
	}
	max, err := parseVersionNeeds(data, strtab, f.ByteOrder)
	if err != nil {
		return "", err
	}
	return max, nil
}

func versionStringTable(f *elf.File, verneed *elf.Section) ([]byte, error) {
	if int(verneed.Link) >= len(f.Sections) {
		return nil, fmt.Errorf("plugin version section has invalid string table link")
	}
	strSec := f.Sections[verneed.Link]
	data, err := strSec.Data()
	if err != nil {
		return nil, fmt.Errorf("read plugin version string table: %w", err)
	}
	return data, nil
}

// parseVersionNeeds walks VERNEED entries (Elf_Verneed + Elf_Vernaux,
// 16 bytes each in both 32- and 64-bit forms) and returns the
// highest GLIBC_x.y[.z] name found, or "" when none is present.
// Names are offsets into strtab. Entries for other libraries and
// non-numeric GLIBC_ names (e.g. GLIBC_PRIVATE) are ignored.
// The parser fails CLOSED on any malformed version info: an
// unparseable numeric GLIBC_ name, a truncated entry, an aux
// chain cut short of vn_cnt entries, a vnNext that lands
// inside the entry's own aux chain, or an out-of-range name
// offset all refuse the plugin — a downgraded maximum is
// never silently computed.
func parseVersionNeeds(data, strtab []byte, order binary.ByteOrder) (string, error) {
	var max glibcVersion
	found := false
	off := 0
	// Walked regions, in data coordinates: a later entry
	// offset must never land inside one. Headers and aux
	// entries occupy disjoint regions, but their layout
	// varies: real linkers emit all Verneed headers first
	// and the aux entries after them (vn_aux past the
	// next header), while other sections interleave one
	// header with its aux entries. Only the aux RANGE
	// is off-limits for a vnNext target, never the span
	// from the header to the end of its aux chain.
	var auxRanges [][2]int
	var hdrRanges [][2]int
	for {
		for _, r := range auxRanges {
			if off >= r[0] && off < r[1] {
				return "", fmt.Errorf("invalid version need entry at offset %d: lands inside version auxiliary data (offsets %d-%d)", off, r[0], r[1])
			}
		}
		for _, r := range hdrRanges {
			if off > r[0] && off < r[1] {
				return "", fmt.Errorf("invalid version need entry at offset %d: lands inside a version need header (offsets %d-%d)", off, r[0], r[1])
			}
		}
		if off+16 > len(data) {
			if off == 0 && len(data) == 0 {
				return "", nil
			}
			return "", fmt.Errorf("truncated version need entry at offset %d", off)
		}
		hdrRanges = append(hdrRanges, [2]int{off, off + 16})
		vnCnt := order.Uint16(data[off+2:])
		vnAux := order.Uint32(data[off+8:])
		vnNext := order.Uint32(data[off+12:])
		if vnCnt > 0 && vnAux < 16 {
			return "", fmt.Errorf("invalid version need entry at offset %d: aux offset %d", off, vnAux)
		}
		auxOff := off + int(vnAux)
		// auxStart/auxEnd delimit this entry's aux
		// entries actually walked, wherever they sit:
		// immediately after the header (interleaved
		// layout) or after later headers (headers-first
		// layout, as real linkers emit).
		auxStart := auxOff
		auxEnd := auxOff
		for i := 0; i < int(vnCnt); i++ {
			if auxOff+16 > len(data) {
				return "", fmt.Errorf("truncated version auxiliary entry at offset %d", auxOff)
			}
			auxEnd = auxOff + 16
			nameOff := order.Uint32(data[auxOff+8:])
			next := order.Uint32(data[auxOff+12:])
			name, err := cstringAt(strtab, int(nameOff))
			if err != nil {
				return "", fmt.Errorf("invalid version name offset %d: %w", nameOff, err)
			}
			if strings.HasPrefix(name, "GLIBC_") {
				verStr := strings.TrimPrefix(name, "GLIBC_")
				if len(verStr) > 0 && verStr[0] >= '0' && verStr[0] <= '9' {
					v, err := parseGlibcVersion(verStr)
					if err != nil {
						return "", fmt.Errorf("unparseable glibc version %q: refusing to load", name)
					}
					if !found || compareGlibcVersion(v, max) > 0 {
						max = v
						found = true
					}
				}
				// Non-numeric GLIBC_ names (GLIBC_PRIVATE,
				// ...) carry no version requirement.
			}
			if next == 0 {
				if i < int(vnCnt)-1 {
					return "", fmt.Errorf("truncated version auxiliary chain at entry %d of %d", i, vnCnt)
				}
				break
			}
			auxOff += int(next)
		}
		if vnNext == 0 {
			break
		}
		// A vnNext landing inside this entry's own header
		// (1-15) or inside its aux range would re-parse
		// header/aux bytes as a header (vnCnt=0,
		// vnNext=0) and silently skip a later, higher
		// requirement: refuse instead of computing a
		// downgraded maximum. A vnNext that stops before
		// the aux range (headers-first layout) or at/after
		// it (interleaved layout) is well-formed.
		if vnNext < 16 {
			return "", fmt.Errorf("invalid version need entry at offset %d: vnNext %d lands inside the entry header", off, vnNext)
		}
		if vnCnt > 0 && int(vnNext) >= auxStart-off && int(vnNext) < auxEnd-off {
			return "", fmt.Errorf("invalid version need entry at offset %d: vnNext %d lands inside the entry's auxiliary data (offsets %d-%d)", off, vnNext, auxStart-off, auxEnd-off)
		}
		if vnCnt > 0 {
			auxRanges = append(auxRanges, [2]int{auxStart, auxEnd})
		}
		off += int(vnNext)
	}
	if !found {
		return "", nil
	}
	return max.String(), nil
}

func cstringAt(strtab []byte, off int) (string, error) {
	if off < 0 || off >= len(strtab) {
		return "", fmt.Errorf("name offset %d out of range (table size %d)", off, len(strtab))
	}
	end := off
	for end < len(strtab) && strtab[end] != 0 {
		end++
	}
	return string(strtab[off:end]), nil
}

// CheckPluginCompat refuses a plugin file whose highest required
// GLIBC_ version exceeds the running libc, or whose ELF cannot
// be read. It returns nil when the file has no GLIBC_
// requirements or satisfies the running libc, and nil for
// non-ELF files (PE/Dylib plugins have no .gnu.version_r; the
// format gate is dlopen/LoadLibrary, not this check). It must
// be called before dlopen.
func CheckPluginCompat(path string) error {
	isELF, err := isELFFile(path)
	if err != nil {
		return err
	}
	if !isELF {
		return nil
	}
	max, err := MaxRequiredGLIBC(path)
	if err != nil {
		return err
	}
	if max == "" {
		return nil
	}
	running, err := runningLibcVersion()
	if err != nil {
		return fmt.Errorf("plugin requires GLIBC_%s but the running libc version is unknown on this build: refusing to load (%v)", max, err)
	}
	required, err := parseGlibcVersion(max)
	if err != nil {
		return fmt.Errorf("plugin requires unparseable glibc version %q: refusing to load", max)
	}
	if compareGlibcVersion(required, running) > 0 {
		return fmt.Errorf("plugin requires GLIBC_%s, running libc is %s: refusing to load", max, running.String())
	}
	return nil
}
