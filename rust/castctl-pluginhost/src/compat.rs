// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Glibc compatibility gate: refuse a plugin whose
//! highest required `GLIBC_` version exceeds the running
//! libc, before it ever reaches the dynamic loader.
//!
//! Go source: `internal/pluginhost/compat.go` (all of it)
//! and `internal/pluginhost/version_glibc.go` /
//! `version_other.go` (running-version source).
//!
//! Mechanism: hand-rolled ELF parse (32/64-bit, LE/BE)
//! of the plugin's `.gnu.version_r` (VERNEED) entries
//! plus a conservative strtab superset bound (every
//! `GLIBC_` version string in the verneed string table
//! and in the `DT_STRTAB` range raises the reported
//! maximum). The running libc version is read WITHOUT
//! dlopen: `/proc/self/maps` locates the loaded
//! `libc.so.6`, whose `.gnu.version_d` (Verdef) entries
//! are parsed by the same hand-rolled reader.
//!
//! The reported maximum is a conservative preflight
//! upper bound, NOT an adversary-proof verneed parser:
//! plugins are fully trusted in-process code by design.
//! Known limitations (a)–(e) from `compat.go` apply
//! unchanged; see `docs/plugins.md` "Known limits".
//!
//! Errors never embed the checked path (see
//! `open_error_without_path` in `compat.go:24-30`).

use std::cmp::Ordering;
use std::path::Path;

use crate::error::PluginHostError;

/// A glibc version `major.minor[.patch]`.
/// Source: `glibcVersion` (`compat.go:93-97`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct GlibcVersion {
    pub major: i64,
    pub minor: i64,
    pub patch: i64,
}

impl GlibcVersion {
    /// `String()` omits the patch when it is 0.
    /// Source: `glibcVersion.String` (`compat.go:99-106`).
    #[must_use]
    pub fn to_version_string(self) -> String {
        if self.patch != 0 {
            format!("{}.{}.{}", self.major, self.minor, self.patch)
        } else {
            format!("{}.{}", self.major, self.minor)
        }
    }
}

impl std::fmt::Display for GlibcVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_version_string())
    }
}

/// Parse `"major.minor[.patch]"`, tolerating distro
/// suffixes and extra components (e.g. Debian's
/// `"2.44-0"`): only the leading digits of the first
/// three dot-separated components matter. The full
/// triple is compared.
/// Source: `parseGlibcVersion` (`compat.go:113-137`).
pub fn parse_glibc_version(s: &str) -> Result<GlibcVersion, PluginHostError> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() < 2 {
        return Err(PluginHostError::invalid(format!(
            "invalid glibc version {s:?}"
        )));
    }
    let major = leading_int(parts[0])
        .ok_or_else(|| PluginHostError::invalid(format!("invalid glibc version {s:?}")))?;
    let minor = leading_int(parts[1])
        .ok_or_else(|| PluginHostError::invalid(format!("invalid glibc version {s:?}")))?;
    let mut v = GlibcVersion {
        major,
        minor,
        patch: 0,
    };
    if parts.len() > 2 {
        v.patch = leading_int(parts[2])
            .ok_or_else(|| PluginHostError::invalid(format!("invalid glibc version {s:?}")))?;
    }
    Ok(v)
}

/// The leading digit run of a component.
/// Source: `leadingInt` (`compat.go:140-148`).
fn leading_int(part: &str) -> Option<i64> {
    let digits: String = part.chars().take_while(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() {
        return None;
    }
    digits.parse::<i64>().ok()
}

/// Full-triple compare, returning -1/0/1 like Go.
/// Source: `compareGlibcVersion` (`compat.go:150-168`).
#[must_use]
pub fn compare_glibc_version(a: GlibcVersion, b: GlibcVersion) -> i32 {
    match a.cmp(&b) {
        Ordering::Less => -1,
        Ordering::Equal => 0,
        Ordering::Greater => 1,
    }
}

// ---------------------------------------------------------------------------
// Minimal ELF reader (hand-rolled; 32/64-bit, LE/BE).
// Mirrors what Go's `debug/elf` exposes to `compat.go`:
// sections by name, program headers, byte order, class.
// ---------------------------------------------------------------------------

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const DT_NULL: i64 = 0;
const DT_STRTAB: i64 = 5;
const DT_STRSZ: i64 = 10;

#[derive(Debug, Clone)]
struct Section {
    off: u64,
    size: u64,
    link: u32,
    info: u32,
    name: String,
}

#[derive(Debug, Clone)]
struct Prog {
    typ: u32,
    off: u64,
    vaddr: u64,
    filesz: u64,
}

#[derive(Debug)]
struct Elf {
    data: Vec<u8>,
    class32: bool,
    big_endian: bool,
    sections: Vec<Section>,
    progs: Vec<Prog>,
}

fn read_u16(data: &[u8], off: usize, be: bool) -> Option<u16> {
    let b = data.get(off..off + 2)?;
    Some(if be {
        u16::from_be_bytes([b[0], b[1]])
    } else {
        u16::from_le_bytes([b[0], b[1]])
    })
}

fn read_u32(data: &[u8], off: usize, be: bool) -> Option<u32> {
    let b = data.get(off..off + 4)?;
    Some(if be {
        u32::from_be_bytes([b[0], b[1], b[2], b[3]])
    } else {
        u32::from_le_bytes([b[0], b[1], b[2], b[3]])
    })
}

fn read_u64(data: &[u8], off: usize, be: bool) -> Option<u64> {
    let b = data.get(off..off + 8)?;
    Some(if be {
        u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
    } else {
        u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
    })
}

fn cstr_lossy(data: &[u8], off: usize) -> String {
    let mut end = off;
    while end < data.len() && data[end] != 0 {
        end += 1;
    }
    String::from_utf8_lossy(&data[off..end]).into_owned()
}

impl Elf {
    /// Parse an ELF file's headers. Mirrors `elf.Open` /
    /// `elf.NewFile` as used by `compat.go`: magic, class,
    /// data encoding, program headers, section headers,
    /// section names via the shstrtab.
    fn parse(data: Vec<u8>) -> Result<Elf, PluginHostError> {
        let bad = |why: &str| PluginHostError::failed(format!("read plugin elf: {why}"));
        if data.len() < 16
            || data[0] != 0x7f
            || data[1] != b'E'
            || data[2] != b'L'
            || data[3] != b'F'
        {
            return Err(bad("invalid ELF header"));
        }
        let class32 = match data[4] {
            1 => true,
            2 => false,
            _ => return Err(bad("invalid ELF class")),
        };
        let big_endian = match data[5] {
            1 => false,
            2 => true,
            _ => return Err(bad("invalid ELF data encoding")),
        };
        if data[6] != 1 {
            return Err(bad("invalid ELF version"));
        }
        let u16h = |off: usize| {
            read_u16(&data, off, big_endian).ok_or_else(|| bad("truncated ELF header"))
        };
        let u32h = |off: usize| {
            read_u32(&data, off, big_endian).ok_or_else(|| bad("truncated ELF header"))
        };
        let u64h = |off: usize| {
            read_u64(&data, off, big_endian).ok_or_else(|| bad("truncated ELF header"))
        };
        let (phoff, shoff, phentsize, mut phnum, shentsize, mut shnum, mut shstrndx) = if class32 {
            (
                u32h(28)? as u64,
                u32h(32)? as u64,
                u16h(42)? as usize,
                u16h(44)? as usize,
                u16h(46)? as usize,
                u16h(48)? as usize,
                u16h(50)? as usize,
            )
        } else {
            (
                u64h(32)?,
                u64h(40)?,
                u16h(54)? as usize,
                u16h(56)? as usize,
                u16h(58)? as usize,
                u16h(60)? as usize,
                u16h(62)? as usize,
            )
        };
        // Program headers.
        let mut progs = Vec::new();
        if phoff != 0 && phnum != 0 {
            // PN_XNUM (0xffff): the real count is in the
            // first program header's p_info (u32 at +8 for
            // 64-bit, +28 for 32-bit is p_align; Go reads
            // the same field via debug/elf).
            if phnum == 0xffff {
                let info_off = phoff as usize + if class32 { 28 } else { 8 };
                phnum = read_u32(&data, info_off, big_endian)
                    .map(|v| v as usize)
                    .unwrap_or(0);
            }
            if phentsize == 0 {
                return Err(bad("invalid program header entry size"));
            }
            for i in 0..phnum {
                let off = phoff as usize + i * phentsize;
                let (typ, poff, vaddr, filesz) = if class32 {
                    (
                        read_u32(&data, off, big_endian)
                            .ok_or_else(|| bad("truncated program header"))?,
                        read_u32(&data, off + 4, big_endian)
                            .ok_or_else(|| bad("truncated program header"))?
                            as u64,
                        read_u32(&data, off + 8, big_endian)
                            .ok_or_else(|| bad("truncated program header"))?
                            as u64,
                        read_u32(&data, off + 16, big_endian)
                            .ok_or_else(|| bad("truncated program header"))?
                            as u64,
                    )
                } else {
                    (
                        read_u32(&data, off, big_endian)
                            .ok_or_else(|| bad("truncated program header"))?,
                        read_u64(&data, off + 8, big_endian)
                            .ok_or_else(|| bad("truncated program header"))?,
                        read_u64(&data, off + 16, big_endian)
                            .ok_or_else(|| bad("truncated program header"))?,
                        read_u64(&data, off + 32, big_endian)
                            .ok_or_else(|| bad("truncated program header"))?,
                    )
                };
                progs.push(Prog {
                    typ,
                    off: poff,
                    vaddr,
                    filesz,
                });
            }
        }
        // Section headers.
        let mut raw_sections: Vec<(u32, u64, u64, u32, u32)> = Vec::new();
        if shoff != 0 && shentsize != 0 {
            // Extended numbering: shnum 0 means the real
            // count is section 0's sh_size; shstrndx
            // 0xffff means section 0's sh_link.
            let first = |field_off: usize| -> Option<u32> {
                read_u32(&data, shoff as usize + field_off, big_endian)
            };
            if shnum == 0 {
                shnum = if class32 {
                    first(20).map(|v| v as usize).unwrap_or(0)
                } else {
                    first(32).map(|v| v as usize).unwrap_or(0)
                };
            }
            if shstrndx == 0xffff {
                shstrndx = first(40).map(|v| v as usize).unwrap_or(0);
            }
            for i in 0..shnum {
                let off = shoff as usize + i * shentsize;
                // `sh_type` / `sh_addr` are not read: the
                // walk locates `.gnu.version_r` /
                // `.gnu.version_d` by name and uses only
                // offset/size/link/info. Any truncation
                // still errors at a later field read.
                let (name, file_off, size, link, info) = if class32 {
                    (
                        read_u32(&data, off, big_endian)
                            .ok_or_else(|| bad("truncated section header"))?,
                        read_u32(&data, off + 16, big_endian)
                            .ok_or_else(|| bad("truncated section header"))?
                            as u64,
                        read_u32(&data, off + 20, big_endian)
                            .ok_or_else(|| bad("truncated section header"))?
                            as u64,
                        read_u32(&data, off + 24, big_endian)
                            .ok_or_else(|| bad("truncated section header"))?,
                        read_u32(&data, off + 28, big_endian)
                            .ok_or_else(|| bad("truncated section header"))?,
                    )
                } else {
                    (
                        read_u32(&data, off, big_endian)
                            .ok_or_else(|| bad("truncated section header"))?,
                        read_u64(&data, off + 24, big_endian)
                            .ok_or_else(|| bad("truncated section header"))?,
                        read_u64(&data, off + 32, big_endian)
                            .ok_or_else(|| bad("truncated section header"))?,
                        read_u32(&data, off + 40, big_endian)
                            .ok_or_else(|| bad("truncated section header"))?,
                        read_u32(&data, off + 44, big_endian)
                            .ok_or_else(|| bad("truncated section header"))?,
                    )
                };
                raw_sections.push((name, file_off, size, link, info));
            }
        }
        // Section names via the shstrtab.
        let shstrtab: &[u8] = if shstrndx != 0 && shstrndx < raw_sections.len() {
            let (_, off, size, _, _) = raw_sections[shstrndx];
            let start = off as usize;
            let end = start.saturating_add(size as usize).min(data.len());
            if start <= end { &data[start..end] } else { &[] }
        } else {
            &[]
        };
        let sections = raw_sections
            .into_iter()
            .map(|(name_off, off, size, link, info)| Section {
                off,
                size,
                link,
                info,
                name: if (name_off as usize) < shstrtab.len() {
                    cstr_lossy(shstrtab, name_off as usize)
                } else {
                    String::new()
                },
            })
            .collect();
        Ok(Elf {
            data,
            class32,
            big_endian,
            sections,
            progs,
        })
    }

    fn section_by_name(&self, name: &str) -> Option<&Section> {
        self.sections.iter().find(|s| s.name == name)
    }

    fn section_data(&self, sec: &Section) -> Result<&[u8], PluginHostError> {
        let start = sec.off as usize;
        let end = start.saturating_add(sec.size as usize);
        self.data.get(start..end).ok_or_else(|| {
            PluginHostError::failed("read plugin version section: section data out of range")
        })
    }
}

/// Whether the file starts with the ELF magic. A file
/// shorter than the 4-byte magic cannot be ELF. A
/// directory is an error: the compat gate must not
/// silently pass a non-file. Errors never embed path.
/// Source: `isELFFile` (`compat.go:37-55`).
pub fn is_elf_file(path: &Path) -> Result<bool, PluginHostError> {
    use std::io::Read;
    let mut f = std::fs::File::open(path)
        .map_err(|e| PluginHostError::failed(format!("cannot open plugin file: {e}")))?;
    let info = f
        .metadata()
        .map_err(|e| PluginHostError::failed(format!("cannot stat plugin file: {e}")))?;
    if info.is_dir() {
        return Err(PluginHostError::failed("plugin file is a directory"));
    }
    let mut magic = [0u8; 4];
    let n = f.read(&mut magic).unwrap_or(0);
    if n < magic.len() {
        return Ok(false);
    }
    Ok(magic == [0x7f, b'E', b'L', b'F'])
}

/// The highest `GLIBC_x.y` version the ELF file at
/// `path` requires, or `""` when it requires none. A
/// non-ELF file, or an ELF whose version section cannot
/// be read, is an error: the loader must not guess.
/// Source: `MaxRequiredGLIBC` (`compat.go:197-259`).
pub fn max_required_glibc(path: &Path) -> Result<String, PluginHostError> {
    let bytes = std::fs::read(path)
        .map_err(|e| PluginHostError::failed(format!("read plugin elf: {e}")))?;
    let elf = Elf::parse(bytes)?;
    max_required_glibc_in(&elf)
}

fn max_required_glibc_in(elf: &Elf) -> Result<String, PluginHostError> {
    let Some(sec) = elf.section_by_name(".gnu.version_r") else {
        return Ok(String::new());
    };
    let data = elf.section_data(sec)?;
    let strtab = version_string_table(elf, sec)?;
    let (max, count) = parse_version_needs_count(data, &strtab, elf.big_endian)?;
    // sh_info of a SHT_GNU_verneed section is the number
    // of Verneed entries. Cross-check it against the
    // headers the vnNext chain actually visited.
    if sec.info != 0 && sec.info as usize != count {
        return Err(PluginHostError::failed(format!(
            "plugin version section entry count mismatch: section header declares {} version need entries, vnNext chain found {}: refusing to load",
            sec.info, count
        )));
    }
    let dyn_bytes = dynamic_strtab_range(elf)?;
    let (dyn_bound, dyn_found) = scan_strtab_versions(&dyn_bytes)?;
    if dyn_found {
        if max.is_empty() {
            return Ok(dyn_bound.to_version_string());
        }
        let walk_max = parse_glibc_version(&max).map_err(|_| {
            PluginHostError::failed(format!(
                "plugin requires unparseable glibc version {max:?}: refusing to load"
            ))
        })?;
        if compare_glibc_version(dyn_bound, walk_max) > 0 {
            return Ok(dyn_bound.to_version_string());
        }
    }
    Ok(max)
}

/// The verneed section's string table, via `sh_link`.
/// Source: `versionStringTable` (`compat.go:261-270`).
fn version_string_table(elf: &Elf, verneed: &Section) -> Result<Vec<u8>, PluginHostError> {
    let link = verneed.link as usize;
    if link >= elf.sections.len() {
        return Err(PluginHostError::failed(
            "plugin version section has invalid string table link",
        ));
    }
    let str_sec = &elf.sections[link];
    elf.section_data(str_sec).map(|b| b.to_vec()).map_err(|_| {
        PluginHostError::failed("read plugin version string table: section data out of range")
    })
}

/// The `DT_STRTAB` byte range: `DT_STRTAB`/`DT_STRSZ`
/// taken from every `PT_DYNAMIC` program header and
/// mapped to a file offset through the `PT_LOAD`
/// segments. Any inconsistency refuses with an error
/// naming `DT_STRTAB`. Errors never embed path.
/// Source: `dynamicStrtabRange` (`compat.go:317-404`).
fn dynamic_strtab_range(elf: &Elf) -> Result<Vec<u8>, PluginHostError> {
    let dyn_progs: Vec<&Prog> = elf.progs.iter().filter(|p| p.typ == PT_DYNAMIC).collect();
    if dyn_progs.is_empty() {
        return Err(PluginHostError::failed(
            "cannot resolve DT_STRTAB: no PT_DYNAMIC program header: refusing to load",
        ));
    }
    let file_size = elf.data.len() as u64;
    let entry_size: usize = if elf.class32 { 8 } else { 16 };
    let mut strtab_addr: u64 = 0;
    let mut strsz: u64 = 0;
    let mut have_addr = false;
    let mut have_sz = false;
    for prog in &dyn_progs {
        if prog.filesz > file_size {
            return Err(PluginHostError::failed(
                "cannot resolve DT_STRTAB: PT_DYNAMIC size exceeds file size: refusing to load",
            ));
        }
        let start = prog.off as usize;
        let end = start.saturating_add(prog.filesz as usize);
        let raw = elf.data.get(start..end).ok_or_else(|| {
            PluginHostError::failed(
                "cannot resolve DT_STRTAB: cannot read PT_DYNAMIC: refusing to load",
            )
        })?;
        if raw.len() % entry_size != 0 {
            return Err(PluginHostError::failed(
                "cannot resolve DT_STRTAB: dynamic section size is not a multiple of the dynamic entry size: refusing to load",
            ));
        }
        let mut off = 0;
        while off < raw.len() {
            let (tag, val) = if entry_size == 8 {
                let tag = read_u32(raw, off, elf.big_endian)
                    .map(|v| v as i32 as i64)
                    .unwrap_or(0);
                let val = read_u32(raw, off + 4, elf.big_endian)
                    .map(|v| v as u64)
                    .unwrap_or(0);
                (tag, val)
            } else {
                let tag = read_u64(raw, off, elf.big_endian)
                    .map(|v| v as i64)
                    .unwrap_or(0);
                let val = read_u64(raw, off + 8, elf.big_endian).unwrap_or(0);
                (tag, val)
            };
            if tag == DT_NULL {
                break;
            }
            match tag {
                DT_STRTAB => {
                    if have_addr && strtab_addr != val {
                        return Err(PluginHostError::failed(
                            "cannot resolve DT_STRTAB: inconsistent DT_STRTAB values: refusing to load",
                        ));
                    }
                    strtab_addr = val;
                    have_addr = true;
                }
                DT_STRSZ => {
                    if have_sz && strsz != val {
                        return Err(PluginHostError::failed(
                            "cannot resolve DT_STRTAB: inconsistent DT_STRSZ values: refusing to load",
                        ));
                    }
                    strsz = val;
                    have_sz = true;
                }
                _ => {}
            }
            off += entry_size;
        }
    }
    if !have_addr || !have_sz {
        return Err(PluginHostError::failed(
            "cannot resolve DT_STRTAB: missing DT_STRTAB or DT_STRSZ dynamic entry: refusing to load",
        ));
    }
    if strsz == 0 {
        return Err(PluginHostError::failed(
            "cannot resolve DT_STRTAB: empty DT_STRSZ: refusing to load",
        ));
    }
    for p in elf.progs.iter().filter(|p| p.typ == PT_LOAD) {
        if strtab_addr < p.vaddr || strtab_addr - p.vaddr >= p.filesz {
            continue;
        }
        let rel = strtab_addr - p.vaddr;
        if strsz > p.filesz - rel {
            continue;
        }
        let off = p.off + rel;
        // Checked arithmetic: the C-style `off + strsz < off`
        // overflow test would panic in a Rust debug build
        // on overflow instead of refusing, so an overflowing
        // range refuses explicitly here.
        let Some(end) = off.checked_add(strsz) else {
            return Err(PluginHostError::failed(
                "cannot resolve DT_STRTAB: DT_STRTAB range exceeds file size: refusing to load",
            ));
        };
        if off < p.off || end > file_size {
            return Err(PluginHostError::failed(
                "cannot resolve DT_STRTAB: DT_STRTAB range exceeds file size: refusing to load",
            ));
        }
        let start = off as usize;
        let end = start.saturating_add(strsz as usize);
        return elf.data.get(start..end).map(|b| b.to_vec()).ok_or_else(|| {
            PluginHostError::failed(
                "cannot resolve DT_STRTAB: cannot read DT_STRTAB range: refusing to load",
            )
        });
    }
    Err(PluginHostError::failed(
        "cannot resolve DT_STRTAB: DT_STRTAB address is not covered by any PT_LOAD segment: refusing to load",
    ))
}

/// The highest `GLIBC_x.y[.z]` version named by any
/// string in `data`, searching for the `"GLIBC_"` prefix
/// ANYWHERE in the bytes. A string whose suffix starts
/// with a digit must be exactly `digits.digits[.digits]`;
/// anything else digit-led refuses. Non-numeric names
/// (e.g. `GLIBC_PRIVATE`) are ignored, matching the
/// chain walk.
/// Source: `scanStrtabVersions` (`compat.go:278-315`).
pub fn scan_strtab_versions(data: &[u8]) -> Result<(GlibcVersion, bool), PluginHostError> {
    let mut max = GlibcVersion {
        major: 0,
        minor: 0,
        patch: 0,
    };
    let mut found = false;
    let mut i = 0;
    while i + 6 <= data.len() {
        if data[i] != b'G' || &data[i..i + 6] != b"GLIBC_" {
            i += 1;
            continue;
        }
        let rest = &data[i + 6..];
        let mut end = 0;
        while end < rest.len() && rest[end] != 0 {
            end += 1;
        }
        let suffix = String::from_utf8_lossy(&rest[..end]).into_owned();
        if suffix.is_empty() || !suffix.as_bytes()[0].is_ascii_digit() {
            i += 1;
            continue;
        }
        let parts: Vec<&str> = suffix.split('.').collect();
        let mut malformed = parts.len() < 2 || parts.len() > 3;
        if !malformed {
            for p in &parts {
                if p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) {
                    malformed = true;
                    break;
                }
            }
        }
        if malformed {
            let mut display = suffix.clone();
            if display.len() > 64 {
                display.truncate(64);
            }
            return Err(PluginHostError::failed(format!(
                "unparseable glibc version string {display:?} in version string table: refusing to load"
            )));
        }
        let v = parse_glibc_version(&suffix).map_err(|_| {
            PluginHostError::failed(format!(
                "unparseable glibc version string {suffix:?} in version string table: refusing to load"
            ))
        })?;
        if !found || compare_glibc_version(v, max) > 0 {
            max = v;
            found = true;
        }
        i += 1;
    }
    Ok((max, found))
}

/// A NUL-terminated string at `off` in `strtab`.
/// Source: `cstringAt` (`compat.go:674-682`).
fn cstring_at(strtab: &[u8], off: usize) -> Result<String, PluginHostError> {
    if off >= strtab.len() {
        return Err(PluginHostError::failed(format!(
            "name offset {off} out of range (table size {})",
            strtab.len()
        )));
    }
    let mut end = off;
    while end < strtab.len() && strtab[end] != 0 {
        end += 1;
    }
    Ok(String::from_utf8_lossy(&strtab[off..end]).into_owned())
}

/// Walk VERNEED entries (16 bytes each in both 32- and
/// 64-bit forms) and return the highest `GLIBC_x.y[.z]`
/// name found, or `""` when none is present, plus the
/// number of Verneed headers the `vnNext` chain visited.
/// The parser fails CLOSED on any malformed version
/// info; the walk is validated against the WHOLE section
/// before any maximum is returned: every byte must be
/// covered exactly once by a visited header or aux entry.
/// Source: `parseVersionNeedsCount` (`compat.go:525-672`).
pub fn parse_version_needs_count(
    data: &[u8],
    strtab: &[u8],
    big_endian: bool,
) -> Result<(String, usize), PluginHostError> {
    let u16at = |off: usize| read_u16(data, off, big_endian).unwrap_or(0);
    let u32at = |off: usize| read_u32(data, off, big_endian).unwrap_or(0);
    let mut max = GlibcVersion {
        major: 0,
        minor: 0,
        patch: 0,
    };
    let mut found = false;
    let mut off: i64 = 0;
    let mut aux_ranges: Vec<(i64, i64)> = Vec::new();
    let mut hdr_ranges: Vec<(i64, i64)> = Vec::new();
    let mut covered = vec![false; data.len()];
    let mut visited: Vec<i64> = Vec::new();
    let mut header_count = 0usize;
    loop {
        if visited.contains(&off) {
            return Err(PluginHostError::failed(format!(
                "invalid version need entry at offset {off}: vnNext chain revisits an entry (cycle): refusing to load"
            )));
        }
        visited.push(off);
        for r in &aux_ranges {
            if off >= r.0 && off < r.1 {
                return Err(PluginHostError::failed(format!(
                    "invalid version need entry at offset {off}: lands inside version auxiliary data (offsets {}-{})",
                    r.0, r.1
                )));
            }
        }
        for r in &hdr_ranges {
            if off > r.0 && off < r.1 {
                return Err(PluginHostError::failed(format!(
                    "invalid version need entry at offset {off}: lands inside a version need header (offsets {}-{})",
                    r.0, r.1
                )));
            }
        }
        if off < 0 || off + 16 > data.len() as i64 {
            if off == 0 && data.is_empty() {
                let (bound, bound_found) = scan_strtab_versions(strtab)?;
                if bound_found {
                    return Ok((bound.to_version_string(), 0));
                }
                return Ok((String::new(), 0));
            }
            return Err(PluginHostError::failed(format!(
                "truncated version need entry at offset {off}"
            )));
        }
        // mark(off, off+16): overlap refuses.
        for i in off..off + 16 {
            if covered[i as usize] {
                return Err(PluginHostError::failed(format!(
                    "version need entries overlap at offset {i}: refusing to load"
                )));
            }
            covered[i as usize] = true;
        }
        hdr_ranges.push((off, off + 16));
        header_count += 1;
        let vn_cnt = u16at((off + 2) as usize) as i64;
        let vn_aux = u32at((off + 8) as usize) as i64;
        let vn_next = u32at((off + 12) as usize) as i64;
        if vn_cnt > 0 && vn_aux < 16 {
            return Err(PluginHostError::failed(format!(
                "invalid version need entry at offset {off}: aux offset {vn_aux}"
            )));
        }
        let mut aux_off = off + vn_aux;
        let mut this_aux_ranges: Vec<(i64, i64)> = Vec::new();
        for i in 0..vn_cnt {
            if aux_off < 0 || aux_off + 16 > data.len() as i64 {
                return Err(PluginHostError::failed(format!(
                    "truncated version auxiliary entry at offset {aux_off}"
                )));
            }
            for j in aux_off..aux_off + 16 {
                if covered[j as usize] {
                    return Err(PluginHostError::failed(format!(
                        "version need entries overlap at offset {j}: refusing to load"
                    )));
                }
                covered[j as usize] = true;
            }
            aux_ranges.push((aux_off, aux_off + 16));
            this_aux_ranges.push((aux_off, aux_off + 16));
            let name_off = u32at((aux_off + 8) as usize) as usize;
            let next = u32at((aux_off + 12) as usize) as i64;
            let name = cstring_at(strtab, name_off).map_err(|e| {
                PluginHostError::failed(format!("invalid version name offset {name_off}: {e}"))
            })?;
            if let Some(ver_str) = name.strip_prefix("GLIBC_")
                && !ver_str.is_empty()
                && ver_str.as_bytes()[0].is_ascii_digit()
            {
                    let v = parse_glibc_version(ver_str).map_err(|_| {
                        PluginHostError::failed(format!(
                            "unparseable glibc version {name:?}: refusing to load"
                        ))
                    })?;
                    if !found || compare_glibc_version(v, max) > 0 {
                        max = v;
                        found = true;
                    }
                // Non-numeric GLIBC_ names (GLIBC_PRIVATE,
                // ...) carry no version requirement.
            }
            if next == 0 {
                if i < vn_cnt - 1 {
                    return Err(PluginHostError::failed(format!(
                        "truncated version auxiliary chain at entry {i} of {vn_cnt}"
                    )));
                }
                break;
            }
            aux_off += next;
        }
        if vn_next == 0 {
            break;
        }
        if vn_next < 16 {
            return Err(PluginHostError::failed(format!(
                "invalid version need entry at offset {off}: vnNext {vn_next} lands inside the entry header"
            )));
        }
        for r in &this_aux_ranges {
            if vn_next >= r.0 - off && vn_next < r.1 - off {
                return Err(PluginHostError::failed(format!(
                    "invalid version need entry at offset {off}: vnNext {vn_next} lands inside the entry's auxiliary data (offsets {}-{})",
                    r.0 - off,
                    r.1 - off
                )));
            }
        }
        let next_off = off + vn_next;
        if next_off < off {
            return Err(PluginHostError::failed(format!(
                "invalid version need entry at offset {off}: vnNext {vn_next} overflows the section"
            )));
        }
        off = next_off;
    }
    // Whole-section validation: every byte must be
    // covered exactly once.
    for (i, c) in covered.iter().enumerate() {
        if !*c {
            let mut end = i + 1;
            while end < covered.len() && !covered[end] {
                end += 1;
            }
            return Err(PluginHostError::failed(format!(
                "version need section has uncovered bytes at offsets {i}-{end}: the vnNext chain skips over a version need entry or auxiliary entry: refusing to load"
            )));
        }
    }
    // Conservative strtab superset bound.
    let (bound, bound_found) = scan_strtab_versions(strtab)?;
    if bound_found && (!found || compare_glibc_version(bound, max) > 0) {
        max = bound;
        found = true;
    }
    if !found {
        return Ok((String::new(), header_count));
    }
    Ok((max.to_version_string(), header_count))
}

/// Walk VERNEED entries and return the highest
/// `GLIBC_x.y[.z]` name found, or `""` when none.
/// Source: `parseVersionNeeds` (`compat.go:517-521`).
pub fn parse_version_needs(
    data: &[u8],
    strtab: &[u8],
    big_endian: bool,
) -> Result<String, PluginHostError> {
    parse_version_needs_count(data, strtab, big_endian).map(|(max, _)| max)
}

/// The running libc version, WITHOUT dlopen: parse
/// `/proc/self/maps` to find the loaded `libc.so.6`
/// path, then hand-roll-parse its `.gnu.version_d`
/// (Verdef) entries; the max defined `GLIBC_x.y` is the
/// running version. Any failure is an error, and the
/// caller refuses fail-closed (matching Go
/// `version_other.go`).
/// Source: `runningLibcVersion` (`version_glibc.go:72-78`)
/// via `gnu_get_libc_version`; the Rust mechanism is a
/// [DEVIATION] recorded in PORTING.md (no dlopen, no
/// cgo) with the same fail-closed contract.
pub fn running_libc_version() -> Result<GlibcVersion, PluginHostError> {
    let maps = std::fs::read_to_string("/proc/self/maps")
        .map_err(|e| PluginHostError::failed(format!("cannot read /proc/self/maps: {e}")))?;
    let mut libc_path: Option<String> = None;
    for line in maps.lines() {
        if let Some(path) = line.split_whitespace().last() {
            let base = path.rsplit('/').next().unwrap_or(path);
            if base.starts_with("libc.so.6") || (base.starts_with("libc-") && base.ends_with(".so"))
            {
                libc_path = Some(path.to_string());
                break;
            }
        }
    }
    let path = libc_path
        .ok_or_else(|| PluginHostError::failed("no loaded libc.so.6 found in /proc/self/maps"))?;
    let bytes = std::fs::read(&path)
        .map_err(|e| PluginHostError::failed(format!("cannot read loaded libc: {e}")))?;
    let elf = Elf::parse(bytes)?;
    let Some(sec) = elf.section_by_name(".gnu.version_d") else {
        return Err(PluginHostError::failed(
            "loaded libc has no .gnu.version_d section",
        ));
    };
    let data = elf
        .section_data(sec)
        .map_err(|_| PluginHostError::failed("cannot read loaded libc version section"))?;
    let strtab = version_string_table(&elf, sec)
        .map_err(|_| PluginHostError::failed("cannot read loaded libc version string table"))?;
    let be = elf.big_endian;
    let mut max: Option<GlibcVersion> = None;
    let mut off: usize = 0;
    let mut seen = 0usize;
    loop {
        if off + 20 > data.len() {
            break;
        }
        let vd_cnt = read_u16(data, off + 6, be).unwrap_or(0) as usize;
        let vd_aux = read_u32(data, off + 12, be).unwrap_or(0) as usize;
        let vd_next = read_u32(data, off + 16, be).unwrap_or(0) as usize;
        let mut aux_off = off + vd_aux;
        for _ in 0..vd_cnt {
            if aux_off + 8 > data.len() {
                break;
            }
            let name_off = read_u32(data, aux_off, be).unwrap_or(0) as usize;
            let next = read_u32(data, aux_off + 4, be).unwrap_or(0) as usize;
            if let Ok(name) = cstring_at(&strtab, name_off)
                && let Some(ver) = name.strip_prefix("GLIBC_")
                && !ver.is_empty()
                && ver.as_bytes()[0].is_ascii_digit()
                && let Ok(v) = parse_glibc_version(ver)
            {
                max = Some(match max {
                    Some(m) if compare_glibc_version(v, m) <= 0 => m,
                    _ => v,
                });
            }
            if next == 0 {
                break;
            }
            aux_off += next;
        }
        seen += 1;
        if vd_next == 0 || seen > 4096 {
            break;
        }
        off += vd_next;
    }
    max.ok_or_else(|| PluginHostError::failed("no GLIBC version defined in loaded libc"))
}

/// Refuse a plugin file whose highest required `GLIBC_`
/// version exceeds the running libc, or whose ELF cannot
/// be read. Returns `Ok` when the file has no `GLIBC_`
/// requirements or satisfies the running libc, and `Ok`
/// for non-ELF files (the format gate is dlopen's job,
/// not this check). Must be called before dlopen.
/// Source: `CheckPluginCompat` (`compat.go:686-713`).
pub fn check_plugin_compat(path: &Path) -> Result<(), PluginHostError> {
    let is_elf = is_elf_file(path)?;
    if !is_elf {
        return Ok(());
    }
    let max = max_required_glibc(path)?;
    if max.is_empty() {
        return Ok(());
    }
    let running = running_libc_version().map_err(|e| {
        PluginHostError::failed(format!(
            "plugin requires GLIBC_{max} but the running libc version is unknown on this build: refusing to load ({e})"
        ))
    })?;
    let required = parse_glibc_version(&max).map_err(|_| {
        PluginHostError::failed(format!(
            "plugin requires unparseable glibc version {max:?}: refusing to load"
        ))
    })?;
    if compare_glibc_version(required, running) > 0 {
        return Err(PluginHostError::failed(format!(
            "plugin requires GLIBC_{max}, running libc is {running}: refusing to load"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- test helpers (ports of compat_test.go helpers) --

    /// Synthesise a `.gnu.version_r` section body: one
    /// Verneed for `file_name` with the given version
    /// names. Port of `buildVerneed`
    /// (`compat_test.go:18-70`).
    fn build_verneed(file_name: &str, versions: &[&str]) -> (Vec<u8>, Vec<u8>) {
        let mut strtab: Vec<u8> = vec![0];
        let mut str_off: std::collections::HashMap<String, u32> = std::collections::HashMap::new();
        let mut add_str = |s: &str, strtab: &mut Vec<u8>| -> u32 {
            if let Some(off) = str_off.get(s) {
                return *off;
            }
            let off = strtab.len() as u32;
            strtab.extend_from_slice(s.as_bytes());
            strtab.push(0);
            str_off.insert(s.to_string(), off);
            off
        };
        let file_off = add_str(file_name, &mut strtab);
        let mut name_offs = Vec::new();
        for v in versions {
            name_offs.push(add_str(v, &mut strtab));
        }
        let mut body: Vec<u8> = Vec::new();
        body.extend_from_slice(&1u16.to_le_bytes());
        body.extend_from_slice(&(versions.len() as u16).to_le_bytes());
        body.extend_from_slice(&file_off.to_le_bytes());
        body.extend_from_slice(&16u32.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        for (i, off) in name_offs.iter().enumerate() {
            body.extend_from_slice(&0u32.to_le_bytes());
            body.extend_from_slice(&0u16.to_le_bytes());
            body.extend_from_slice(&(i as u16 + 2).to_le_bytes());
            body.extend_from_slice(&off.to_le_bytes());
            body.extend_from_slice(
                &(if i + 1 < versions.len() { 16u32 } else { 0u32 }).to_le_bytes(),
            );
        }
        (body, strtab)
    }

    fn verneed_header(vn_cnt: u16, vn_aux: u32, vn_next: u32, be: bool) -> Vec<u8> {
        let mut b = vec![0u8; 16];
        if be {
            b[2..4].copy_from_slice(&vn_cnt.to_be_bytes());
            b[8..12].copy_from_slice(&vn_aux.to_be_bytes());
            b[12..16].copy_from_slice(&vn_next.to_be_bytes());
        } else {
            b[2..4].copy_from_slice(&vn_cnt.to_le_bytes());
            b[8..12].copy_from_slice(&vn_aux.to_le_bytes());
            b[12..16].copy_from_slice(&vn_next.to_le_bytes());
        }
        b
    }

    fn verneed_aux(name_off: u32, next: u32, be: bool) -> Vec<u8> {
        let mut b = vec![0u8; 16];
        if be {
            b[8..12].copy_from_slice(&name_off.to_be_bytes());
            b[12..16].copy_from_slice(&next.to_be_bytes());
        } else {
            b[8..12].copy_from_slice(&name_off.to_le_bytes());
            b[12..16].copy_from_slice(&next.to_le_bytes());
        }
        b
    }

    /// One Verneed header plus one Vernaux naming the
    /// string at `name_off`. Port of `verneedSingle`
    /// (`compat_test.go:602-611`).
    fn verneed_single(name_off: u32, be: bool) -> Vec<u8> {
        let mut b = vec![0u8; 32];
        if be {
            b[2..4].copy_from_slice(&1u16.to_be_bytes());
            b[8..12].copy_from_slice(&16u32.to_be_bytes());
            b[12..16].copy_from_slice(&0u32.to_be_bytes());
            b[16 + 8..16 + 12].copy_from_slice(&name_off.to_be_bytes());
            b[16 + 12..16 + 16].copy_from_slice(&0u32.to_be_bytes());
        } else {
            b[2..4].copy_from_slice(&1u16.to_le_bytes());
            b[8..12].copy_from_slice(&16u32.to_le_bytes());
            b[12..16].copy_from_slice(&0u32.to_le_bytes());
            b[16 + 8..16 + 12].copy_from_slice(&name_off.to_le_bytes());
            b[16 + 12..16 + 16].copy_from_slice(&0u32.to_le_bytes());
        }
        b
    }

    fn at_least_version(got: &str, want: &str) -> bool {
        let gv = parse_glibc_version(got).unwrap();
        let wv = parse_glibc_version(want).unwrap();
        compare_glibc_version(gv, wv) >= 0
    }

    /// Port of `TestParseVersionNeeds` (`compat_test.go:77-105`).
    #[test]
    fn parse_version_needs_cases() {
        let (body, strtab) =
            build_verneed("libc.so.6", &["GLIBC_2.17", "GLIBC_2.34", "GLIBC_PRIVATE"]);
        assert_eq!(parse_version_needs(&body, &strtab, false).unwrap(), "2.34");
        let (body, strtab) = build_verneed("libc.so.6", &[]);
        assert_eq!(parse_version_needs(&body, &strtab, false).unwrap(), "");
        let (body, strtab) = build_verneed("libfoo.so.1", &["FOO_1.0"]);
        assert_eq!(parse_version_needs(&body, &strtab, false).unwrap(), "");
        assert!(parse_version_needs(&[1, 2], &strtab, false).is_err());
    }

    /// Port of `TestParseVersionNeedsFailClosed`
    /// (`compat_test.go:107-140`).
    #[test]
    fn parse_version_needs_fail_closed() {
        let (body, strtab) = build_verneed("libc.so.6", &["GLIBC_2.34", "GLIBC_2.XX"]);
        assert!(parse_version_needs(&body, &strtab, false).is_err());
        // Aux chain cut short of vn_cnt.
        let (mut body, strtab) = build_verneed("libc.so.6", &["GLIBC_2.2.5", "GLIBC_2.34"]);
        body[16 + 12..16 + 16].copy_from_slice(&0u32.to_le_bytes());
        assert!(parse_version_needs(&body, &strtab, false).is_err());
        // Out-of-range name offset.
        let (mut body, strtab) = build_verneed("libc.so.6", &["GLIBC_2.34"]);
        body[16 + 8..16 + 12].copy_from_slice(&0xFFFF_FF00u32.to_le_bytes());
        assert!(parse_version_needs(&body, &strtab, false).is_err());
        // GLIBC_PRIVATE stays ignored.
        let (body, strtab) = build_verneed("libc.so.6", &["GLIBC_PRIVATE"]);
        assert_eq!(parse_version_needs(&body, &strtab, false).unwrap(), "");
    }

    /// Port of `TestGlibcVersionCompare`
    /// (`compat_test.go:183-229`).
    #[test]
    fn glibc_version_compare() {
        let cases: &[(&str, &str, i32)] = &[
            ("2.17", "2.17", 0),
            ("2.17", "2.34", -1),
            ("2.34", "2.17", 1),
            ("2.4", "2.17", -1),
            ("3.0", "2.99", 1),
            ("2.44-0", "2.44", 0),
            ("2.17-0ubuntu1", "2.17", 0),
            ("2.44.1", "2.44", 1),
            ("2.44", "2.44.1", -1),
            ("2.3.4", "2.3.2", 1),
            ("2.3.2", "2.3.4", -1),
            ("2.2.5", "2.2.5", 0),
        ];
        for (a, b, want) in cases {
            let va = parse_glibc_version(a).unwrap();
            let vb = parse_glibc_version(b).unwrap();
            assert_eq!(compare_glibc_version(va, vb), *want, "{a} vs {b}");
        }
        assert!(parse_glibc_version("banana").is_err());
        assert!(parse_glibc_version("2").is_err());
    }

    /// Port of `TestCheckPluginCompatNoShadowPathLeak`
    /// (`compat_test.go:231-252`).
    #[test]
    fn check_plugin_compat_no_shadow_path_leak() {
        let dir = tempfile::tempdir().unwrap();
        let shadow = dir
            .path()
            .join("castctl-pluginhost")
            .join("pid-424242")
            .join("castctl-plugin-echo-abc.so");
        let err = check_plugin_compat(&shadow).unwrap_err();
        assert!(!err.to_string().contains("pid-424242"));
        assert!(!err.to_string().contains("castctl-pluginhost"));
        let err = max_required_glibc(&shadow).unwrap_err();
        assert!(!err.to_string().contains("pid-424242"));
        assert!(!err.to_string().contains("castctl-pluginhost"));
    }

    /// Port of `TestParseVersionNeedsShortVnNextRefuses`
    /// (`compat_test.go:254-326`).
    #[test]
    fn parse_version_needs_short_vnnext_refuses() {
        let strtab = b"GLIBC_2.17\0GLIBC_2.99\0".to_vec();
        let mut e1 = verneed_header(1, 16, 16, false);
        e1.extend_from_slice(&verneed_aux(0, 0, false));
        let mut e2 = verneed_header(1, 16, 0, false);
        e2.extend_from_slice(&verneed_aux(11, 0, false));
        let mut two = e1.clone();
        two.extend_from_slice(&e2);
        let err = parse_version_needs(&two, &strtab, false).unwrap_err();
        assert!(err.to_string().contains("vnNext"), "got: {err}");
        // Well-formed control (vnNext=32) still finds 2.99.
        let mut e1ok = verneed_header(1, 16, 32, false);
        e1ok.extend_from_slice(&verneed_aux(0, 0, false));
        let mut two_ok = e1ok;
        two_ok.extend_from_slice(&e2);
        assert_eq!(
            parse_version_needs(&two_ok, &strtab, false).unwrap(),
            "2.99"
        );
        // Headers-first layout, as real linkers emit.
        let mut hf = verneed_header(1, 32, 16, false);
        hf.extend_from_slice(&verneed_header(1, 32, 0, false));
        hf.extend_from_slice(&verneed_aux(0, 0, false));
        hf.extend_from_slice(&verneed_aux(11, 0, false));
        assert_eq!(parse_version_needs(&hf, &strtab, false).unwrap(), "2.99");
        // A vnNext inside the entry's own header refuses.
        let mut e1hdr = verneed_header(1, 16, 8, false);
        e1hdr.extend_from_slice(&verneed_aux(0, 0, false));
        let mut bad = e1hdr;
        bad.extend_from_slice(&e2);
        assert!(parse_version_needs(&bad, &strtab, false).is_err());
    }

    /// Port of `TestParseVersionNeedsLongJumpVnNextRefuses`
    /// (`compat_test.go:328-370`).
    #[test]
    fn parse_version_needs_long_jump_vnnext_refuses() {
        let strtab = b"GLIBC_2.17\0GLIBC_2.99\0".to_vec();
        let mut probe = verneed_header(1, 32, 48, false);
        probe.extend_from_slice(&verneed_header(1, 32, 0, false));
        probe.extend_from_slice(&verneed_aux(0, 0, false));
        probe.extend_from_slice(&verneed_aux(11, 0, false));
        assert!(parse_version_needs(&probe, &strtab, false).is_err());
        // Well-formed control: vnNext=16.
        let mut control = verneed_header(1, 32, 16, false);
        control.extend_from_slice(&verneed_header(1, 32, 0, false));
        control.extend_from_slice(&verneed_aux(0, 0, false));
        control.extend_from_slice(&verneed_aux(11, 0, false));
        assert_eq!(
            parse_version_needs(&control, &strtab, false).unwrap(),
            "2.99"
        );
    }

    /// Port of `TestParseVersionNeedsStrtabBoundRedTeam`
    /// (`compat_test.go:423-454`).
    #[test]
    fn parse_version_needs_strtab_bound_red_team() {
        let strtab = b"GLIBC_2.2.5\0GLIBC_2.34\0".to_vec();
        let mut section = verneed_header(1, 16, 32, false);
        section.extend_from_slice(&verneed_aux(0, 16, false));
        section.extend_from_slice(&verneed_aux(11, 0, false));
        if let Ok(got) = parse_version_needs(&section, &strtab, false) {
            assert!(
                at_least_version(&got, "2.34"),
                "got max {got:?}, want >= 2.34 or refusal"
            );
        }
    }

    /// Port of `TestParseVersionNeedsStrtabBoundVerifierTiling`
    /// (`compat_test.go:456-512`).
    #[test]
    fn parse_version_needs_strtab_bound_verifier_tiling() {
        let mut slot16 = vec![0u8; 16];
        slot16[2..4].copy_from_slice(&1u16.to_le_bytes());
        slot16[8..12].copy_from_slice(&32u32.to_le_bytes());
        slot16[12..16].copy_from_slice(&16u32.to_le_bytes());
        let mut slot48 = vec![0u8; 16];
        slot48[8..12].copy_from_slice(&11u32.to_le_bytes());
        let mut strtab = b"GLIBC_2.17\0GLIBC_2.99\0".to_vec();
        while strtab.len() < 32 {
            strtab.push(0);
        }
        strtab.extend_from_slice(b"zz\0");
        let mut section = verneed_header(2, 16, 48, false);
        section.extend_from_slice(&slot16);
        section.extend_from_slice(&verneed_aux(0, 0, false));
        section.extend_from_slice(&slot48);
        if let Ok(got) = parse_version_needs(&section, &strtab, false) {
            assert!(
                at_least_version(&got, "2.99"),
                "got max {got:?}, want >= 2.99 or refusal"
            );
        }
    }

    /// Port of `TestParseVersionNeedsStrtabBoundScannerRules`
    /// (`compat_test.go:514-551`).
    #[test]
    fn parse_version_needs_strtab_bound_scanner_rules() {
        let (body, base_strtab) = build_verneed("libc.so.6", &["GLIBC_2.17"]);
        let cases: &[(&str, &str, &str, bool)] = &[
            (
                "unreferenced higher version counts",
                "GLIBC_2.99\0",
                "2.99",
                false,
            ),
            (
                "unreferenced malformed version refuses",
                "GLIBC_2.XX\0",
                "",
                true,
            ),
            (
                "non-numeric name stays ignored",
                "GLIBC_PRIVATE\0",
                "2.17",
                false,
            ),
            (
                "version string inside a longer string counts",
                "XGLIBC_2.99\0",
                "2.99",
                false,
            ),
            (
                "version string with letter suffix refuses",
                "GLIBC_2.34x\0",
                "",
                true,
            ),
        ];
        for (name, extra, want, want_err) in cases {
            let mut strtab = base_strtab.clone();
            strtab.extend_from_slice(extra.as_bytes());
            let got = parse_version_needs(&body, &strtab, false);
            if *want_err {
                assert!(got.is_err(), "{name}: want error, got {got:?}");
            } else {
                assert_eq!(got.unwrap(), *want, "{name}");
            }
        }
    }

    /// Port of `TestMaxRequiredGLIBCRealBinary`
    /// (`compat_test.go:142-163`) + `TestCheckPluginCompat`
    /// (`compat_test.go:165-181`) + real-section tests
    /// (`compat_test.go:372-421`, `553-600`).
    #[test]
    fn real_binary_compat() {
        let self_exe = std::env::current_exe().unwrap();
        // The Rust test binary is dynamically linked
        // against glibc on this VM.
        let max = max_required_glibc(&self_exe).unwrap();
        assert!(!max.is_empty(), "test binary must require a GLIBC_ version");
        assert!(max.contains('.'), "max = {max:?}, want major.minor");
        assert!(max_required_glibc(Path::new("/dev/null")).is_err());
        assert!(check_plugin_compat(&self_exe).is_ok());
        assert!(check_plugin_compat(Path::new("/dev/null")).is_ok());
        // Real .gnu.version_r section agrees with
        // MaxRequiredGLIBC.
        let bytes = std::fs::read(&self_exe).unwrap();
        let elf = Elf::parse(bytes).unwrap();
        let sec = elf.section_by_name(".gnu.version_r").unwrap();
        let data = elf.section_data(sec).unwrap();
        assert!(!data.is_empty());
        let strtab = version_string_table(&elf, sec).unwrap();
        let got = parse_version_needs(data, &strtab, elf.big_endian).unwrap();
        assert_eq!(got, max);
        assert!(!got.is_empty());
        // Running libc version is sane (cross-checked
        // against ldd/getconf on cue in the gate run).
        let running = running_libc_version().unwrap();
        assert!(running.major >= 2);
    }

    // -- crafted ELF builder (port of buildCraftedELF,
    // compat_test.go:613-792) --

    struct CraftedElfOptions {
        class32: bool,
        big_endian: bool,
        dynamic: &'static str, // "valid" | "none" | "badAddr" | "missingStrsz"
        sh_info: u32,
        section: Vec<u8>,
        strtab: Vec<u8>,
    }

    fn build_crafted_elf(opts: CraftedElfOptions) -> std::path::PathBuf {
        let (ehsize, phentsize, shentsize, dyn_entry_size) = if opts.class32 {
            (52usize, 32usize, 40usize, 8usize)
        } else {
            (64, 56, 64, 16)
        };
        let mut phnum = 1;
        if opts.dynamic != "none" {
            phnum = 2;
        }
        let phoff = ehsize;
        let verneed_off = phoff + phnum * phentsize;
        let dynstr_off = verneed_off + opts.section.len();
        let dyn_off = dynstr_off + opts.strtab.len();
        let dyn_count = match opts.dynamic {
            "valid" | "badAddr" => 3,
            "missingStrsz" => 2,
            _ => 0,
        };
        let dyn_size = dyn_count * dyn_entry_size;
        let shstr: &[u8] = b"\0.gnu.version_r\0.dynstr\0.shstrtab\0";
        let shstr_off = dyn_off + dyn_size;
        let shoff = shstr_off + shstr.len();
        let file_size = shoff + 4 * shentsize;
        let vaddr_base: u64 = if opts.class32 { 0x0804_8000 } else { 0x400_000 };
        let mut buf = vec![0u8; file_size];
        let put16 = |buf: &mut [u8], off: usize, v: u16| {
            let bytes = if opts.big_endian {
                v.to_be_bytes()
            } else {
                v.to_le_bytes()
            };
            buf[off..off + 2].copy_from_slice(&bytes);
        };
        let put32 = |buf: &mut [u8], off: usize, v: u32| {
            let bytes = if opts.big_endian {
                v.to_be_bytes()
            } else {
                v.to_le_bytes()
            };
            buf[off..off + 4].copy_from_slice(&bytes);
        };
        let put64 = |buf: &mut [u8], off: usize, v: u64| {
            let bytes = if opts.big_endian {
                v.to_be_bytes()
            } else {
                v.to_le_bytes()
            };
            buf[off..off + 8].copy_from_slice(&bytes);
        };
        buf[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        buf[4] = if opts.class32 { 1 } else { 2 };
        buf[5] = if opts.big_endian { 2 } else { 1 };
        buf[6] = 1;
        put16(&mut buf, 16, 3);
        put16(&mut buf, 18, if opts.class32 { 3 } else { 62 });
        put32(&mut buf, 20, 1);
        if opts.class32 {
            put32(&mut buf, 24, 0);
            put32(&mut buf, 28, phoff as u32);
            put32(&mut buf, 32, shoff as u32);
            put32(&mut buf, 36, 0);
            put16(&mut buf, 40, ehsize as u16);
            put16(&mut buf, 42, phentsize as u16);
            put16(&mut buf, 44, phnum as u16);
            put16(&mut buf, 46, shentsize as u16);
            put16(&mut buf, 48, 4);
            put16(&mut buf, 50, 3);
        } else {
            put64(&mut buf, 24, 0);
            put64(&mut buf, 32, phoff as u64);
            put64(&mut buf, 40, shoff as u64);
            put32(&mut buf, 48, 0);
            put16(&mut buf, 52, ehsize as u16);
            put16(&mut buf, 54, phentsize as u16);
            put16(&mut buf, 56, phnum as u16);
            put16(&mut buf, 58, shentsize as u16);
            put16(&mut buf, 60, 4);
            put16(&mut buf, 62, 3);
        }
        let write_phdr = |buf: &mut [u8],
                          off: usize,
                          typ: u32,
                          file_off: u64,
                          vaddr: u64,
                          filesz: u64,
                          flags: u32| {
            if opts.class32 {
                put32(buf, off, typ);
                put32(buf, off + 4, file_off as u32);
                put32(buf, off + 8, vaddr as u32);
                put32(buf, off + 12, vaddr as u32);
                put32(buf, off + 16, filesz as u32);
                put32(buf, off + 20, filesz as u32);
                put32(buf, off + 24, flags);
                put32(buf, off + 28, 0x1000);
            } else {
                put32(buf, off, typ);
                put32(buf, off + 4, flags);
                put64(buf, off + 8, file_off);
                put64(buf, off + 16, vaddr);
                put64(buf, off + 24, vaddr);
                put64(buf, off + 32, filesz);
                put64(buf, off + 40, filesz);
                put64(buf, off + 48, 0x1000);
            }
        };
        write_phdr(&mut buf, phoff, 1, 0, vaddr_base, file_size as u64, 4);
        if opts.dynamic != "none" {
            write_phdr(
                &mut buf,
                phoff + phentsize,
                2,
                dyn_off as u64,
                vaddr_base + dyn_off as u64,
                dyn_size as u64,
                6,
            );
        }
        buf[verneed_off..verneed_off + opts.section.len()].copy_from_slice(&opts.section);
        buf[dynstr_off..dynstr_off + opts.strtab.len()].copy_from_slice(&opts.strtab);
        buf[shstr_off..shstr_off + shstr.len()].copy_from_slice(shstr);
        if opts.dynamic != "none" {
            let mut strtab_vaddr = vaddr_base + dynstr_off as u64;
            if opts.dynamic == "badAddr" {
                strtab_vaddr = vaddr_base + 0x100_000;
            }
            let mut entries: Vec<(u64, u64)> = vec![(5, strtab_vaddr)];
            if opts.dynamic != "missingStrsz" {
                entries.push((10, opts.strtab.len() as u64));
            }
            entries.push((0, 0));
            for (i, e) in entries.iter().enumerate() {
                let off = dyn_off + i * dyn_entry_size;
                if opts.class32 {
                    put32(&mut buf, off, e.0 as u32);
                    put32(&mut buf, off + 4, e.1 as u32);
                } else {
                    put64(&mut buf, off, e.0);
                    put64(&mut buf, off + 8, e.1);
                }
            }
        }
        let write_shdr = |buf: &mut [u8],
                          off: usize,
                          name: u32,
                          typ: u32,
                          flags: u64,
                          addr: u64,
                          file_off: u64,
                          size: u64,
                          link: u32,
                          info: u32,
                          align: u64| {
            if opts.class32 {
                put32(buf, off, name);
                put32(buf, off + 4, typ);
                put32(buf, off + 8, flags as u32);
                put32(buf, off + 12, addr as u32);
                put32(buf, off + 16, file_off as u32);
                put32(buf, off + 20, size as u32);
                put32(buf, off + 24, link);
                put32(buf, off + 28, info);
                put32(buf, off + 32, align as u32);
                put32(buf, off + 36, 0);
            } else {
                put32(buf, off, name);
                put32(buf, off + 4, typ);
                put64(buf, off + 8, flags);
                put64(buf, off + 16, addr);
                put64(buf, off + 24, file_off);
                put64(buf, off + 32, size);
                put32(buf, off + 40, link);
                put32(buf, off + 44, info);
                put64(buf, off + 48, align);
                put64(buf, off + 56, 0);
            }
        };
        write_shdr(&mut buf, shoff, 0, 0, 0, 0, 0, 0, 0, 0, 0);
        write_shdr(
            &mut buf,
            shoff + shentsize,
            1,
            0x6fff_fffe,
            2,
            vaddr_base + verneed_off as u64,
            verneed_off as u64,
            opts.section.len() as u64,
            2,
            opts.sh_info,
            8,
        );
        write_shdr(
            &mut buf,
            shoff + 2 * shentsize,
            16,
            3,
            2,
            vaddr_base + dynstr_off as u64,
            dynstr_off as u64,
            opts.strtab.len() as u64,
            0,
            0,
            1,
        );
        write_shdr(
            &mut buf,
            shoff + 3 * shentsize,
            24,
            3,
            0,
            0,
            shstr_off as u64,
            shstr.len() as u64,
            0,
            0,
            1,
        );
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("crafted.so");
        std::fs::write(&path, &buf).unwrap();
        // Keep the tempdir alive for the test duration by
        // leaking it (test-only; the OS reclaims /tmp).
        let _ = dir.keep();
        path
    }

    /// Port of `TestMaxRequiredGLIBCCraftedELFStrtabBound`
    /// (`compat_test.go:794-880`).
    #[test]
    fn max_required_glibc_crafted_elf_strtab_bound() {
        let red_section = |be: bool| {
            let mut section = verneed_header(1, 16, 32, be);
            section.extend_from_slice(&verneed_aux(0, 16, be));
            section.extend_from_slice(&verneed_aux(11, 0, be));
            section
        };
        let red_strtab = b"GLIBC_2.2.5\0GLIBC_2.34\0".to_vec();
        let path = build_crafted_elf(CraftedElfOptions {
            class32: false,
            big_endian: false,
            dynamic: "valid",
            sh_info: 2,
            section: red_section(false),
            strtab: red_strtab,
        });
        if let Ok(got) = max_required_glibc(&path) {
            assert!(
                at_least_version(&got, "2.34"),
                "crafted ELF red-team: got {got:?}, want >= 2.34 or refusal"
            );
        }
        // Verifier tiling section.
        let mut slot16 = vec![0u8; 16];
        slot16[2..4].copy_from_slice(&1u16.to_le_bytes());
        slot16[8..12].copy_from_slice(&32u32.to_le_bytes());
        slot16[12..16].copy_from_slice(&16u32.to_le_bytes());
        let mut slot48 = vec![0u8; 16];
        slot48[8..12].copy_from_slice(&11u32.to_le_bytes());
        let mut tiling_strtab = b"GLIBC_2.17\0GLIBC_2.99\0".to_vec();
        while tiling_strtab.len() < 32 {
            tiling_strtab.push(0);
        }
        tiling_strtab.extend_from_slice(b"zz\0");
        let mut tiling = verneed_header(2, 16, 48, false);
        tiling.extend_from_slice(&slot16);
        tiling.extend_from_slice(&verneed_aux(0, 0, false));
        tiling.extend_from_slice(&slot48);
        let path = build_crafted_elf(CraftedElfOptions {
            class32: false,
            big_endian: false,
            dynamic: "valid",
            sh_info: 2,
            section: tiling,
            strtab: tiling_strtab,
        });
        if let Ok(got) = max_required_glibc(&path) {
            assert!(
                at_least_version(&got, "2.99"),
                "crafted ELF tiling: got {got:?}, want >= 2.99 or refusal"
            );
        }
        // Well-formed controls: single entry naming GLIBC_2.17.
        let control_strtab = b"\0GLIBC_2.17\0".to_vec();
        let controls: &[(&str, CraftedElfOptions)] = &[
            (
                "64-bit little-endian",
                CraftedElfOptions {
                    class32: false,
                    big_endian: false,
                    dynamic: "valid",
                    sh_info: 1,
                    section: verneed_single(1, false),
                    strtab: control_strtab.clone(),
                },
            ),
            (
                "64-bit big-endian",
                CraftedElfOptions {
                    class32: false,
                    big_endian: true,
                    dynamic: "valid",
                    sh_info: 1,
                    section: verneed_single(1, true),
                    strtab: control_strtab.clone(),
                },
            ),
            (
                "32-bit little-endian",
                CraftedElfOptions {
                    class32: true,
                    big_endian: false,
                    dynamic: "valid",
                    sh_info: 1,
                    section: verneed_single(1, false),
                    strtab: control_strtab.clone(),
                },
            ),
        ];
        for (name, opts) in controls {
            let path = build_crafted_elf(CraftedElfOptions {
                class32: opts.class32,
                big_endian: opts.big_endian,
                dynamic: opts.dynamic,
                sh_info: opts.sh_info,
                section: opts.section.clone(),
                strtab: opts.strtab.clone(),
            });
            let got = max_required_glibc(&path);
            assert_eq!(got.as_deref(), Ok("2.17"), "{name}: got {got:?}");
        }
    }

    /// Port of `TestMaxRequiredGLIBCRefusesUnresolvableDynStrtab`
    /// (`compat_test.go:882-914`).
    #[test]
    fn max_required_glibc_refuses_unresolvable_dyn_strtab() {
        let control_strtab = b"\0GLIBC_2.17\0".to_vec();
        let section = verneed_single(1, false);
        let cases: &[(&str, &str, bool, bool)] = &[
            ("valid dynamic reports version", "valid", false, false),
            ("no PT_DYNAMIC refuses", "none", false, true),
            ("DT_STRTAB outside PT_LOAD refuses", "badAddr", false, true),
            ("missing DT_STRSZ refuses", "missingStrsz", false, true),
            ("32-bit no PT_DYNAMIC refuses", "none", true, true),
        ];
        for (name, dynamic, class32, want_err) in cases {
            let path = build_crafted_elf(CraftedElfOptions {
                class32: *class32,
                big_endian: false,
                dynamic,
                sh_info: 1,
                section: section.clone(),
                strtab: control_strtab.clone(),
            });
            let got = max_required_glibc(&path);
            if *want_err {
                let err = got.unwrap_err();
                assert!(
                    err.to_string().contains("DT_STRTAB"),
                    "{name}: error must name DT_STRTAB: {err}"
                );
            } else {
                assert_eq!(got.as_deref(), Ok("2.17"), "{name}: got {got:?}");
            }
        }
    }
}
