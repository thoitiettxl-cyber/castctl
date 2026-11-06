// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Hand-rolled ELF header validation (64-byte header only).
//!
//! Go source: `validateELF` / `validateELFBytes`
//! (`internal/update/extract.go:124-154`). Go uses
//! `debug/elf`; this port reads the 64-byte ELF header
//! directly, which is all the four checks need: magic,
//! class, machine, type. This proves format + architecture
//! only — never identity, never that the binary is castctl
//! (`extract.go:124-127`).

use crate::error::UpdateError;

/// ELF machine for `amd64` (`EM_X86_64`).
/// Source: `validateELF` (`internal/update/extract.go:133-136`).
pub const EM_X86_64: u16 = 62;
/// ELF machine for `arm64` (`EM_AARCH64`).
/// Source: `validateELF` (`internal/update/extract.go:136-138`).
pub const EM_AARCH64: u16 = 183;
/// Executable file type (`ET_EXEC`).
pub const ET_EXEC: u16 = 2;
/// Shared object type (`ET_DYN`, position-independent executables).
pub const ET_DYN: u16 = 3;
/// 64-bit class (`ELFCLASS64`).
pub const ELFCLASS64: u8 = 2;

/// Validate ELF bytes for `goarch` (`"amd64"` or `"arm64"`).
/// Source: `validateELF` (`internal/update/extract.go:124-154`).
pub fn validate_elf_bytes(b: &[u8], goarch: &str) -> Result<(), UpdateError> {
    let invalid =
        || UpdateError::failure("update: the downloaded binary is not a valid ELF executable");
    if b.len() < 64 {
        return Err(invalid());
    }
    if b[0] != 0x7f || b[1] != b'E' || b[2] != b'L' || b[3] != b'F' {
        return Err(invalid());
    }
    // e_ident[EI_VERSION] (byte 6): `EV_CURRENT` (1).
    // Go's `debug/elf` refuses anything else
    // (`elf/file.go:321-324`: `unknown ELF version`);
    // the old code never read byte 6 and ACCEPTED 0/99
    // (red-team B6, fix loop 1).
    if b[6] != 1 {
        return Err(invalid());
    }
    let want_machine: u16 = match goarch {
        "amd64" => EM_X86_64,
        "arm64" => EM_AARCH64,
        _ => {
            return Err(UpdateError::failure("update: unsupported architecture"));
        }
    };
    // e_ident[EI_DATA] (byte 5): 1 = little-endian, 2 = big-endian.
    let little_endian = match b[5] {
        1 => true,
        2 => false,
        _ => return Err(invalid()),
    };
    let u16_at = |off: usize| -> u16 {
        let bs = [b[off], b[off + 1]];
        if little_endian {
            u16::from_le_bytes(bs)
        } else {
            u16::from_be_bytes(bs)
        }
    };
    let machine = u16_at(18);
    if machine != want_machine {
        return Err(UpdateError::failure(
            "update: the downloaded binary is for a different architecture",
        ));
    }
    if b[4] != ELFCLASS64 {
        return Err(UpdateError::failure(
            "update: the downloaded binary is not a 64-bit executable",
        ));
    }
    let e_type = u16_at(16);
    if e_type != ET_EXEC && e_type != ET_DYN {
        return Err(UpdateError::failure(
            "update: the downloaded binary is not an executable image",
        ));
    }
    Ok(())
}

/// Validate the ELF header of the file at `path`.
/// Source: `validateELF` (`internal/update/extract.go:124-154`);
/// the file is read through `std::fs`, never executed.
pub fn validate_elf_file(path: &std::path::Path, goarch: &str) -> Result<(), UpdateError> {
    use std::io::Read;
    let mut f = std::fs::File::open(path).map_err(|_| {
        UpdateError::failure("update: the downloaded binary is not a valid ELF executable")
    })?;
    let mut header = [0u8; 64];
    f.read_exact(&mut header).map_err(|_| {
        UpdateError::failure("update: the downloaded binary is not a valid ELF executable")
    })?;
    validate_elf_bytes(&header, goarch)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal 64-byte ELF64 header for the tests.
    /// `version` is the `EI_VERSION` byte (6); Go refuses
    /// anything but 1 (`EV_CURRENT`).
    fn header(machine: u16, e_type: u16, class: u8) -> Vec<u8> {
        header_version(machine, e_type, class, 1)
    }

    fn header_version(machine: u16, e_type: u16, class: u8, version: u8) -> Vec<u8> {
        let mut h = vec![0u8; 64];
        h[0] = 0x7f;
        h[1] = b'E';
        h[2] = b'L';
        h[3] = b'F';
        h[4] = class;
        h[5] = 1; // little-endian
        h[6] = version;
        h[16..18].copy_from_slice(&e_type.to_le_bytes());
        h[18..20].copy_from_slice(&machine.to_le_bytes());
        h
    }

    #[test]
    fn valid_elf64_exec_amd64() {
        assert!(validate_elf_bytes(&header(EM_X86_64, ET_EXEC, ELFCLASS64), "amd64").is_ok());
        // PIE binaries (ET_DYN) are valid too.
        assert!(validate_elf_bytes(&header(EM_X86_64, ET_DYN, ELFCLASS64), "amd64").is_ok());
        assert!(validate_elf_bytes(&header(EM_AARCH64, ET_DYN, ELFCLASS64), "arm64").is_ok());
    }

    #[test]
    fn elf_rejections_match_go_messages() {
        // Not ELF at all.
        assert_eq!(
            validate_elf_bytes(b"#!/bin/sh\n", "amd64")
                .unwrap_err()
                .to_string(),
            "update: the downloaded binary is not a valid ELF executable"
        );
        // Too short.
        assert!(
            validate_elf_bytes(&header(EM_X86_64, ET_EXEC, ELFCLASS64)[..10], "amd64").is_err()
        );
        // Wrong architecture.
        assert_eq!(
            validate_elf_bytes(&header(EM_AARCH64, ET_DYN, ELFCLASS64), "amd64")
                .unwrap_err()
                .to_string(),
            "update: the downloaded binary is for a different architecture"
        );
        // 32-bit.
        assert_eq!(
            validate_elf_bytes(&header(EM_X86_64, ET_EXEC, 1), "amd64")
                .unwrap_err()
                .to_string(),
            "update: the downloaded binary is not a 64-bit executable"
        );
        // Relocatable object, not an executable image.
        assert_eq!(
            validate_elf_bytes(&header(EM_X86_64, 1, ELFCLASS64), "amd64")
                .unwrap_err()
                .to_string(),
            "update: the downloaded binary is not an executable image"
        );
        // Unsupported GOARCH.
        assert_eq!(
            validate_elf_bytes(&header(EM_X86_64, ET_EXEC, ELFCLASS64), "386")
                .unwrap_err()
                .to_string(),
            "update: unsupported architecture"
        );
        // EI_VERSION (byte 6) must be EV_CURRENT (1):
        // Go's `debug/elf` refuses 0 and 99 (red-team
        // B6, fix loop 1).
        for bad_version in [0u8, 99] {
            assert_eq!(
                validate_elf_bytes(
                    &header_version(EM_X86_64, ET_EXEC, ELFCLASS64, bad_version),
                    "amd64"
                )
                .unwrap_err()
                .to_string(),
                "update: the downloaded binary is not a valid ELF executable",
                "EI_VERSION={bad_version}"
            );
        }
        assert!(
            validate_elf_bytes(
                &header_version(EM_X86_64, ET_EXEC, ELFCLASS64, 1),
                "amd64"
            )
            .is_ok()
        );
    }
}
