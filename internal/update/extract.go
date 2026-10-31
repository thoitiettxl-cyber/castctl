// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package update

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"debug/elf"
	"errors"
	"io"
)

// extractCastctl extracts ONLY the regular file named exactly
// "castctl" from a gzip tar archive, writing its bytes to w. It
// returns the sha256 of the extracted bytes.
//
// Defence rules (failure-report §5): the member name is never joined
// onto a destination path, so traversal, absolute, and backslash
// names on regular members other than castctl are inert: such
// members are skipped unread, never used as paths. Only link and
// device typeflags refuse anywhere: a symlink, hardlink, device,
// or fifo member anywhere in the archive refuses (honest archives
// contain only the five regular files), including a castctl member
// with such a typeflag. A duplicate castctl member refuses, and an
// archive with no exact castctl member refuses (a PAX-renamed
// castctl refuses by this path: the tar reader applies PAX/GNU
// longname overrides transparently, so hdr.Name is always the
// effective name, and a PAX path override changes the effective
// name, which is then validated like any other name). Archive
// member modes and uids are ignored entirely — the installed mode
// comes from the old binary, never from the header. Entry count and
// member size are capped during streaming; the declared size must
// match the bytes read exactly.
func extractCastctl(r io.Reader, w io.Writer) ([]byte, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, newError(1, "update: the downloaded archive is not a valid gzip stream")
	}
	tr := tar.NewReader(gz)
	hash := sha256.New()
	found := false
	entries := 0
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, newError(1, "update: the downloaded archive is not a valid tar archive")
		}
		entries++
		if entries > maxTarEntries {
			return nil, newError(1, "update: the downloaded archive has too many entries")
		}
		if hdr.Name == "castctl" {
			if found {
				return nil, newError(1, "update: the downloaded archive has duplicate castctl members")
			}
			if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA {
				return nil, newError(1, "update: the castctl archive member is not a regular file")
			}
			if hdr.Size < 0 || hdr.Size > maxExtractedBytes {
				return nil, newError(1, "update: the castctl archive member size is out of bounds")
			}
			n, err := io.Copy(io.MultiWriter(w, hash), io.LimitReader(tr, hdr.Size+1))
			if err != nil {
				return nil, newError(1, "update: failed to read the castctl archive member")
			}
			if n != hdr.Size {
				return nil, newError(1, "update: the castctl archive member size does not match its contents")
			}
			found = true
			continue
		}
		// Every other member is skipped unread. A link or device
		// member anywhere refuses: honest archives have none.
		switch hdr.Typeflag {
		case tar.TypeSymlink, tar.TypeLink, tar.TypeChar, tar.TypeBlock, tar.TypeFifo:
			return nil, newError(1, "update: the downloaded archive contains a link or device member")
		}
	}
	if !found {
		return nil, newError(1, "update: the downloaded archive has no castctl member")
	}
	// After the tar end-blocks only all-zero padding may follow:
	// GNU tar pads archives with zeros to a 10240-byte record
	// boundary, so every real release archive carries zero padding
	// after the end-blocks, and refusing it refuses every real
	// release. Any NON-zero trailing byte still refuses: a second
	// gzip member or trailing garbage is never scanned as tar
	// members, so it must refuse rather than be silently ignored
	// (B-02/E-18). The hash already binds these bytes; this check
	// closes the "unscanned bytes reach the tar reader in a future
	// read" gap. The scan reads to EOF in fixed-size chunks and
	// holds no growing buffer, so a huge trailing member cannot
	// fill memory, and no non-zero byte past any cap can slip
	// through unread.
	var chunk [32 << 10]byte
	for {
		n, rerr := gz.Read(chunk[:])
		for _, b := range chunk[:n] {
			if b != 0 {
				return nil, newError(1, "update: trailing data after the tar archive")
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return nil, newError(1, "update: trailing data after the tar archive")
		}
	}
	return hash.Sum(nil), nil
}

// validateELF checks, without executing anything, that the extracted
// bytes are a 64-bit ELF executable for the running architecture.
// This proves format and architecture only — never identity, and
// never that the binary is castctl (failure-report §7).
func validateELF(r io.ReaderAt, goarch string) error {
	f, err := elf.NewFile(r)
	if err != nil {
		return newError(1, "update: the downloaded binary is not a valid ELF executable")
	}
	defer f.Close()
	var want elf.Machine
	switch goarch {
	case "amd64":
		want = elf.EM_X86_64
	case "arm64":
		want = elf.EM_AARCH64
	default:
		return newError(1, "update: unsupported architecture")
	}
	if f.Machine != want {
		return newError(1, "update: the downloaded binary is for a different architecture")
	}
	if f.Class != elf.ELFCLASS64 {
		return newError(1, "update: the downloaded binary is not a 64-bit executable")
	}
	if f.Type != elf.ET_EXEC && f.Type != elf.ET_DYN {
		return newError(1, "update: the downloaded binary is not an executable image")
	}
	return nil
}

// validateELFBytes is the in-memory form used by dry-run.
func validateELFBytes(b []byte, goarch string) error {
	return validateELF(bytes.NewReader(b), goarch)
}
