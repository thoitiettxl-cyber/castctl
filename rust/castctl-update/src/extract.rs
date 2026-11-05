// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Extract the `castctl` member from a gzip tar archive.
//!
//! Go source: `extractCastctl` (`internal/update/extract.go:38-122`).
//!
//! Defence rules (kept verbatim): the member name is never
//! joined onto a destination path, so traversal, absolute,
//! and backslash names on regular members other than
//! `castctl` are inert — such members are skipped unread,
//! never used as paths. Only link and device typeflags
//! refuse anywhere: a symlink, hardlink, device, or fifo
//! member anywhere in the archive refuses. A duplicate
//! `castctl` member refuses, and an archive with no exact
//! `castctl` member refuses (a PAX-renamed `castctl`
//! refuses by this path: the tar reader applies PAX/GNU
//! longname overrides transparently, so the effective name
//! is validated like any other name). Archive member modes
//! and uids are ignored entirely — the installed mode comes
//! from the old binary, never from the header. Entry count
//! and member size are capped during streaming; the declared
//! size must match the bytes read exactly.
//!
//! After the tar end-blocks only all-zero padding may
//! follow: GNU tar pads archives with zeros to a 10240-byte
//! record boundary, so every real release archive carries
//! zero padding after the end-blocks. Any NON-zero trailing
//! byte refuses: a second gzip member or trailing garbage
//! is never scanned as tar members, so it must refuse
//! rather than be silently ignored.
//!
//! Gzip multistream (R1 Q1, settled by the trailing-data
//! tests in this file): Go's `gzip.Reader` is multistream,
//! so a second gzip member's bytes reach the trailing scan
//! and refuse. `flate2::read::MultiGzDecoder` is the
//! matching decoder — it reads concatenated members —
//! while `GzDecoder` stops after the first member and
//! would silently ACCEPT a second member. The
//! `second_gzip_member_refuses` test pins this choice.

use std::io::Read;

use flate2::read::MultiGzDecoder;
use sha2::{Digest, Sha256};

use crate::error::UpdateError;

/// Maximum tar entries in one archive.
/// Source: `maxTarEntries = 64` (`internal/update/update.go:37`).
pub const MAX_TAR_ENTRIES: usize = 64;

/// Maximum extracted bytes.
/// Source: `maxExtractedBytes = 256 MiB` (`internal/update/update.go:36`).
pub const MAX_EXTRACTED_BYTES: u64 = 256 << 20;

/// Extract ONLY the regular file named exactly `"castctl"`
/// from a gzip tar archive, writing its bytes to `w`.
/// Returns the SHA-256 of the extracted bytes.
/// Source: `extractCastctl` (`internal/update/extract.go:38-122`).
pub fn extract_castctl<R: Read, W: std::io::Write>(
    r: R,
    w: &mut W,
) -> Result<[u8; 32], UpdateError> {
    // Peek the gzip magic without consuming: Go's
    // `gzip.NewReader` fails on a bad header with "not a
    // valid gzip stream", while a failure later in the
    // stream is a tar error. `MultiGzDecoder` reports both
    // lazily on read, so the magic peek restores the split.
    let mut buf_reader = std::io::BufReader::new(r);
    {
        use std::io::BufRead;
        let peek = buf_reader.fill_buf().map_err(|_| {
            UpdateError::failure("update: the downloaded archive is not a valid gzip stream")
        })?;
        if peek.len() < 2 || peek[0] != 0x1f || peek[1] != 0x8b {
            return Err(UpdateError::failure(
                "update: the downloaded archive is not a valid gzip stream",
            ));
        }
    }
    let gz = MultiGzDecoder::new(buf_reader);
    let mut archive = tar::Archive::new(gz);
    let mut hash = Sha256::new();
    let mut found = false;
    let mut entries_count = 0;
    let entries = archive.entries().map_err(|_| {
        UpdateError::failure("update: the downloaded archive is not a valid tar archive")
    })?;
    for entry in entries {
        let mut entry = entry.map_err(|_| {
            UpdateError::failure("update: the downloaded archive is not a valid tar archive")
        })?;
        entries_count += 1;
        if entries_count > MAX_TAR_ENTRIES {
            return Err(UpdateError::failure(
                "update: the downloaded archive has too many entries",
            ));
        }
        let header = entry.header();
        // The EFFECTIVE name: `Entry::path_bytes` applies
        // PAX/GNU-longname overrides, while
        // `Header::path_bytes` returns the raw header bytes
        // (a PAX-renamed `castctl` would otherwise slip
        // through with its old name). Type and size still
        // come from the header itself.
        let name = entry.path_bytes();
        if name.as_ref() == b"castctl" {
            if found {
                return Err(UpdateError::failure(
                    "update: the downloaded archive has duplicate castctl members",
                ));
            }
            let entry_type = header.entry_type();
            if entry_type != tar::EntryType::Regular && !is_regular_a(header) {
                return Err(UpdateError::failure(
                    "update: the castctl archive member is not a regular file",
                ));
            }
            let size = header.size().map_err(|_| {
                UpdateError::failure("update: the castctl archive member size is out of bounds")
            })?;
            if size > MAX_EXTRACTED_BYTES {
                return Err(UpdateError::failure(
                    "update: the castctl archive member size is out of bounds",
                ));
            }
            let mut remaining = size;
            let mut chunk = [0u8; 32 << 10];
            loop {
                let n = entry.read(&mut chunk).map_err(|_| {
                    UpdateError::failure("update: failed to read the castctl archive member")
                })?;
                if n == 0 {
                    break;
                }
                if (n as u64) > remaining {
                    return Err(UpdateError::failure(
                        "update: the castctl archive member size does not match its contents",
                    ));
                }
                remaining -= n as u64;
                hash.update(&chunk[..n]);
                w.write_all(&chunk[..n]).map_err(|_| {
                    UpdateError::failure("update: failed to read the castctl archive member")
                })?;
            }
            if remaining != 0 {
                return Err(UpdateError::failure(
                    "update: the castctl archive member size does not match its contents",
                ));
            }
            found = true;
            continue;
        }
        // Every other member is skipped unread. A link or
        // device member anywhere refuses.
        match header.entry_type() {
            tar::EntryType::Link
            | tar::EntryType::Symlink
            | tar::EntryType::Char
            | tar::EntryType::Block
            | tar::EntryType::Fifo => {
                return Err(UpdateError::failure(
                    "update: the downloaded archive contains a link or device member",
                ));
            }
            _ => {}
        }
    }
    if !found {
        return Err(UpdateError::failure(
            "update: the downloaded archive has no castctl member",
        ));
    }
    // Trailing scan: only all-zero bytes may follow the tar
    // end-blocks. Read to EOF in fixed-size chunks, holding
    // no growing buffer.
    let mut gz = archive.into_inner();
    let mut chunk = [0u8; 32 << 10];
    loop {
        match gz.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                if chunk[..n].iter().any(|b| *b != 0) {
                    return Err(UpdateError::failure(
                        "update: trailing data after the tar archive",
                    ));
                }
            }
            Err(_) => {
                return Err(UpdateError::failure(
                    "update: trailing data after the tar archive",
                ));
            }
        }
    }
    Ok(hash.finalize().into())
}

/// The `tar` crate maps the V7 `'\x00'` typeflag to
/// `Regular` on some paths; check the raw byte as well so
/// both `TypeReg` (`'0'`) and `TypeRegA` (`'\x00'`) are
/// accepted, exactly like Go (`extract.go:57`).
fn is_regular_a(header: &tar::Header) -> bool {
    header.as_bytes()[156] == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::io::Write;
    use tar::{Builder, EntryType, Header};

    const FAKE_ELF: &[u8] = b"\x7fELF\x02\x01\x01\x00fake-binary-bytes";

    fn gzip_tar(members: &[(&str, EntryType, &[u8])]) -> Vec<u8> {
        let mut tar_bytes = Vec::new();
        {
            let mut b = Builder::new(&mut tar_bytes);
            for (name, kind, data) in members {
                let mut h = Header::new_gnu();
                h.set_path(name).unwrap();
                h.set_size(data.len() as u64);
                h.set_entry_type(*kind);
                h.set_mode(0o755);
                h.set_cksum();
                b.append(&h, &data[..]).unwrap();
            }
            b.finish().unwrap();
        }
        let mut enc = GzEncoder::new(Vec::new(), Compression::default());
        enc.write_all(&tar_bytes).unwrap();
        enc.finish().unwrap()
    }

    fn extract(bytes: &[u8]) -> Result<(Vec<u8>, [u8; 32]), UpdateError> {
        let mut out = Vec::new();
        let hash = extract_castctl(bytes, &mut out)?;
        Ok((out, hash))
    }

    /// Hand-craft a raw 512-byte tar header (for PAX / `\0`
    /// typeflag cases the `tar` builder cannot express).
    fn raw_header(name: &str, entry_type: u8, size: u64, extra: &[u8]) -> Vec<u8> {
        let mut h = vec![0u8; 512];
        let name_b = name.as_bytes();
        h[..name_b.len()].copy_from_slice(name_b);
        // mode "0000755\0", uid/gid "0000000\0"
        h[100..108].copy_from_slice(b"0000755\0");
        h[108..116].copy_from_slice(b"0000000\0");
        h[116..124].copy_from_slice(b"0000000\0");
        // size: 11 octal digits + NUL (12 bytes). Sizes
        // that do not fit are a test bug, not a fixture:
        // use a smaller huge size instead.
        let size_s = format!("{size:011o}\0");
        assert_eq!(size_s.len(), 12, "size {size} does not fit in the octal field");
        h[124..136].copy_from_slice(size_s.as_bytes());
        // mtime "00000000000\0"
        h[136..148].copy_from_slice(b"00000000000\0");
        h[156] = entry_type;
        if !extra.is_empty() {
            // ustar magic + version "00": the `tar` crate
            // only treats a header as an extension header
            // (PAX `x` / GNU longname) when BOTH match
            // (`is_ustar` checks magic AND version). A
            // magic-only header is yielded as a plain entry.
            h[257..263].copy_from_slice(b"ustar\0");
            h[263..265].copy_from_slice(b"00");
        }
        // checksum: sum with the checksum field as spaces
        h[148..156].copy_from_slice(b"        ");
        let sum: u32 = h.iter().map(|b| *b as u32).sum();
        let cksum = format!("{sum:06o}\0 ");
        h[148..156].copy_from_slice(cksum.as_bytes());
        h
    }

    fn pad512(data: &[u8]) -> Vec<u8> {
        let mut out = data.to_vec();
        let rem = out.len() % 512;
        if rem != 0 {
            out.resize(out.len() + (512 - rem), 0);
        }
        out
    }

    fn gzip_bytes(tar_bytes: &[u8]) -> Vec<u8> {
        let mut enc = GzEncoder::new(Vec::new(), Compression::default());
        enc.write_all(tar_bytes).unwrap();
        enc.finish().unwrap()
    }

    #[test]
    fn extract_happy_path() {
        let gz = gzip_tar(&[("castctl", EntryType::Regular, FAKE_ELF)]);
        let (out, hash) = extract(&gz).unwrap();
        assert_eq!(out, FAKE_ELF);
        let want: [u8; 32] = Sha256::digest(FAKE_ELF).into();
        assert_eq!(hash, want);
    }

    #[test]
    fn extract_empty_castctl_member() {
        let gz = gzip_tar(&[("castctl", EntryType::Regular, b"")]);
        let (out, _) = extract(&gz).unwrap();
        assert!(out.is_empty());
    }

    /// Port of the traversal half of
    /// `TestExtractTraversalOtherMembersInert`
    /// (`internal/update/edge_test.go:96-133`): other members
    /// with traversal / absolute / dotted / case-variant
    /// names are inert when a valid `castctl` exists, and an
    /// archive with ONLY a traversal name has no member.
    /// Built with raw headers: the `tar` crate's
    /// `Header::set_path` refuses `..` names at fixture
    /// build time, so the builder cannot express them.
    #[test]
    fn extract_traversal_other_members_inert() {
        let mut tar_bytes = Vec::new();
        for (name, data) in [
            ("../castctl", b"evil" as &[u8]),
            ("/tmp/evil", b"evil"),
            ("./castctl", b"evil"),
            ("CASTCTL", b"evil"),
            ("castctl", FAKE_ELF),
        ] {
            tar_bytes.extend_from_slice(&raw_header(name, b'0', data.len() as u64, b""));
            tar_bytes.extend_from_slice(&pad512(data));
        }
        tar_bytes.extend_from_slice(&[0u8; 1024]);
        let (out, _) = extract(&gzip_bytes(&tar_bytes)).unwrap();
        assert_eq!(out, FAKE_ELF);
        let mut only = Vec::new();
        only.extend_from_slice(&raw_header("../castctl", b'0', 4, b""));
        only.extend_from_slice(&pad512(b"evil"));
        only.extend_from_slice(&[0u8; 1024]);
        assert_eq!(
            extract(&gzip_bytes(&only)).unwrap_err().to_string(),
            "update: the downloaded archive has no castctl member"
        );
    }

    /// Port of `TestExtractLinkMembersRefuse`
    /// (`edge_test.go:134-174`).
    #[test]
    fn extract_link_members_refuse() {
        for (name, kind) in [
            ("castctl", EntryType::Symlink),
            ("castctl", EntryType::Link),
            ("other", EntryType::Symlink),
            ("other", EntryType::Fifo),
            ("castctl", EntryType::Directory),
        ] {
            let gz = gzip_tar(&[
                (name, kind, b"x"),
                ("castctl", EntryType::Regular, FAKE_ELF),
            ]);
            // A directory `castctl` member is "not a regular
            // file"; link/device members refuse anywhere.
            assert!(extract(&gz).is_err(), "{name} {kind:?}");
        }
        // Duplicate castctl (both orders).
        let dup = gzip_tar(&[
            ("castctl", EntryType::Regular, FAKE_ELF),
            ("castctl", EntryType::Regular, FAKE_ELF),
        ]);
        assert_eq!(
            extract(&dup).unwrap_err().to_string(),
            "update: the downloaded archive has duplicate castctl members"
        );
    }

    /// Port of `TestExtractPAXOverrideRefuses`
    /// (`edge_test.go:175-236`): a PAX `path=../evil`
    /// override renames the `castctl` member, so the
    /// archive has no `castctl` member. This also proves
    /// the `tar` crate applies PAX overrides like Go's
    /// `archive/tar` (R3 §3.4 PAX parity).
    #[test]
    fn extract_pax_override_refuses() {
        // PAX data: "16 path=../evil\n" (length includes itself).
        let pax_data = b"16 path=../evil\n";
        let mut tar_bytes = Vec::new();
        tar_bytes.extend_from_slice(&raw_header("castctl", b'x', pax_data.len() as u64, b"pax"));
        tar_bytes.extend_from_slice(&pad512(pax_data));
        tar_bytes.extend_from_slice(&raw_header("castctl", b'0', FAKE_ELF.len() as u64, b""));
        tar_bytes.extend_from_slice(&pad512(FAKE_ELF));
        tar_bytes.extend_from_slice(&[0u8; 1024]); // end blocks
        let gz = gzip_bytes(&tar_bytes);
        assert_eq!(
            extract(&gz).unwrap_err().to_string(),
            "update: the downloaded archive has no castctl member"
        );
    }

    /// A V7 `'\x00'` typeflag is a regular file too
    /// (`extract.go:57`: `TypeReg` or `TypeRegA`).
    #[test]
    fn extract_v7_nul_typeflag_is_regular() {
        let mut tar_bytes = Vec::new();
        tar_bytes.extend_from_slice(&raw_header("castctl", 0, FAKE_ELF.len() as u64, b""));
        tar_bytes.extend_from_slice(&pad512(FAKE_ELF));
        tar_bytes.extend_from_slice(&[0u8; 1024]);
        let gz = gzip_bytes(&tar_bytes);
        let (out, _) = extract(&gz).unwrap();
        assert_eq!(out, FAKE_ELF);
    }

    /// Port of `TestExtractCorruptArchivesRefuse`
    /// (`edge_test.go:268-339`).
    #[test]
    fn extract_corrupt_archives_refuse() {
        assert_eq!(
            extract(b"").unwrap_err().to_string(),
            "update: the downloaded archive is not a valid gzip stream"
        );
        assert_eq!(
            extract(b"plain text, not gzip at all")
                .unwrap_err()
                .to_string(),
            "update: the downloaded archive is not a valid gzip stream"
        );
        // Bad gzip magic.
        assert!(extract(&[0x1f, 0x8c, 0, 0, 0]).is_err());
        // Truncated gzip stream.
        let gz = gzip_tar(&[("castctl", EntryType::Regular, FAKE_ELF)]);
        assert!(extract(&gz[..gz.len() / 2]).is_err());
        // No castctl member.
        let gz = gzip_tar(&[("other", EntryType::Regular, b"x")]);
        assert_eq!(
            extract(&gz).unwrap_err().to_string(),
            "update: the downloaded archive has no castctl member"
        );
        // Huge declared size refuses without allocating
        // (4 GiB > 256 MiB cap; fits the 11-digit octal field).
        let mut tar_bytes = Vec::new();
        tar_bytes.extend_from_slice(&raw_header("castctl", b'0', 1 << 32, b""));
        tar_bytes.extend_from_slice(&[0u8; 1024]);
        assert_eq!(
            extract(&gzip_bytes(&tar_bytes)).unwrap_err().to_string(),
            "update: the castctl archive member size is out of bounds"
        );
        // Entry-count bomb: 70 members > 64.
        let many: Vec<(&str, EntryType, &[u8])> = (0..70)
            .map(|_| ("f", EntryType::Regular, b"x" as &[u8]))
            .collect();
        // (names collide but the count check fires first on the
        // 65th entry, before any name rule matters)
        let gz = gzip_tar(&many);
        assert_eq!(
            extract(&gz).unwrap_err().to_string(),
            "update: the downloaded archive has too many entries"
        );
    }

    /// Port of `TestExtractTrailingGzipDataRefuses`
    /// (`edge_test.go:340-398`): a second gzip member refuses.
    /// This is the Q1 probe result: `MultiGzDecoder` reads
    /// concatenated members, so the second member's bytes
    /// reach the trailing scan (a single-member decoder
    /// would silently accept this archive).
    #[test]
    fn second_gzip_member_refuses() {
        let first = gzip_tar(&[("castctl", EntryType::Regular, FAKE_ELF)]);
        let second = gzip_tar(&[("castctl", EntryType::Regular, b"other")]);
        let mut both = first.clone();
        both.extend_from_slice(&second);
        assert_eq!(
            extract(&both).unwrap_err().to_string(),
            "update: trailing data after the tar archive"
        );
        // Trailing garbage inside the gzip stream refuses.
        let mut tar_bytes = Vec::new();
        {
            let mut b = Builder::new(&mut tar_bytes);
            let mut h = Header::new_gnu();
            h.set_path("castctl").unwrap();
            h.set_size(FAKE_ELF.len() as u64);
            h.set_entry_type(EntryType::Regular);
            h.set_mode(0o755);
            h.set_cksum();
            b.append(&h, &FAKE_ELF[..]).unwrap();
            b.finish().unwrap();
        }
        tar_bytes.extend_from_slice(b"GARBAGE-NONZERO");
        let gz = gzip_bytes(&tar_bytes);
        assert_eq!(
            extract(&gz).unwrap_err().to_string(),
            "update: trailing data after the tar archive"
        );
    }

    /// Port of `TestExtractAllZeroTrailingDataAccepted` and
    /// the GNU-tar padding lesson (`edge_test.go:399-540`):
    /// all-zero tails — including 1 MiB + 123 bytes — accept.
    #[test]
    fn all_zero_trailing_data_accepted() {
        for tail_len in [100usize, 1024, 1024 * 1024 + 123] {
            let mut tar_bytes = Vec::new();
            {
                let mut b = Builder::new(&mut tar_bytes);
                let mut h = Header::new_gnu();
                h.set_path("castctl").unwrap();
                h.set_size(FAKE_ELF.len() as u64);
                h.set_entry_type(EntryType::Regular);
                h.set_mode(0o755);
                h.set_cksum();
                b.append(&h, &FAKE_ELF[..]).unwrap();
                b.finish().unwrap();
            }
            tar_bytes.extend(std::iter::repeat_n(0u8, tail_len));
            let gz = gzip_bytes(&tar_bytes);
            let (out, _) = extract(&gz).unwrap();
            assert_eq!(out, FAKE_ELF, "tail_len {tail_len}");
        }
        // Non-zero trailing byte late in the tail refuses.
        let mut tar_bytes = Vec::new();
        {
            let mut b = Builder::new(&mut tar_bytes);
            let mut h = Header::new_gnu();
            h.set_path("castctl").unwrap();
            h.set_size(FAKE_ELF.len() as u64);
            h.set_entry_type(EntryType::Regular);
            h.set_mode(0o755);
            h.set_cksum();
            b.append(&h, &FAKE_ELF[..]).unwrap();
            b.finish().unwrap();
        }
        tar_bytes.extend(std::iter::repeat_n(0u8, 5000));
        tar_bytes.push(1);
        let gz = gzip_bytes(&tar_bytes);
        assert!(extract(&gz).is_err());
    }
}
