// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Local-time rendering for the read-command shapes.
//!
//! Source: Go `internal/shared/sessions.go:64`
//! (`formatUpdatedAt`, `"%Y-%m-%d %H:%M"` in `loc`),
//! `internal/shared/usage.go:146` (`SummarizeUsage`
//! `resets_at`, `"%Y-%m-%dT%H:%M:%S%z"` in `loc`) and
//! `usage.go:239` (`UsageLines`, `time.Now().In(loc).Format("MST")`).
//!
//! Go takes an explicit `*time.Location`; the Rust functions
//! take an explicit `chrono::TimeZone` the same way, so unit
//! tests pass a fixed offset (mirroring Go's `ict(t)` /
//! `time.FixedZone`) instead of depending on the machine
//! zone. Production passes `chrono::Local`, which reads the
//! same tzdata (`/etc/localtime`, `TZ`) as Go's
//! `time.Local` — including historical offsets: Asia/Ho_Chi_Minh
//! was +08:00 at the epoch, so the epoch renders
//! `1970-01-01 08:00` under `Local` (as Go renders it) and
//! `1970-01-01 07:00` under a fixed +07 offset (as Go's own
//! test notes). A timestamp outside chrono's range falls back
//! to the epoch in the same zone (unreachable with real
//! gateway data; Go never fails there either).
//!
//! The timezone abbreviation (`UsageLines` appends
//! `time.Now().In(loc).Format("MST")`, e.g. `"+07"` on cue)
//! does NOT come from chrono: `chrono::Local` formats `%Z`
//! as the numeric offset (`"+07:00"`, measured on cue),
//! while Go renders the tzdata abbreviation (`"+07"`,
//! probed live on cue with a Go program: `now MST="+07"`,
//! `epoch MST="+08"`). The abbreviation is read from the
//! TZif file directly (`tz_abbr_at`, pure Rust, no
//! `unsafe`, no libc) — the same file Go's `time.Local`
//! consults.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use chrono::offset::Offset;
use chrono::{DateTime, Local, TimeZone, Utc};

/// Render epoch milliseconds as `"%Y-%m-%d %H:%M"` in `tz`.
/// Source: `internal/shared/sessions.go:64` (`formatUpdatedAt`).
pub fn format_updated_at_ms<Tz: TimeZone>(ms: i64, tz: &Tz) -> String
where
    Tz::Offset: std::fmt::Display,
{
    zoned_datetime_ms(ms, tz)
        .format("%Y-%m-%d %H:%M")
        .to_string()
}

/// Render epoch seconds as `"%Y-%m-%dT%H:%M:%S%z"` in `tz`.
/// Source: `internal/shared/usage.go:146` (`SummarizeUsage`
/// `resets_at`).
pub fn format_resets_at<Tz: TimeZone>(secs: i64, tz: &Tz) -> String
where
    Tz::Offset: std::fmt::Display,
{
    zoned_datetime(secs, tz)
        .format("%Y-%m-%dT%H:%M:%S%z")
        .to_string()
}

/// Go `time.Time` JSON rendering (RFC3339Nano): the
/// fraction trims ALL trailing zeros (`.5`, `.12`,
/// `.1234`, `.12345678`), the stored offset is kept, and
/// a zero offset renders `Z` — one shared helper for
/// every keeper render site (fix loop 1, B1), so the four
/// sites cannot drift again. Expected values are the
/// literal Go 1.27.3 probe outputs (see the tests).
///
/// Implementation mirrors `castctl-webui/src/chats.rs`
/// `rfc3339_nano` (which already trims this way for chat
/// times): 9-digit nanos, strip trailing zeros, drop the
/// dot when the fraction empties. `SecondsFormat::AutoSi`
/// is NOT used — it emits only 0/3/6/9 fraction digits
/// (`.500`, `.120`, `.123456780`), which Go never writes.
pub fn format_go_rfc3339_nano<Tz: TimeZone>(dt: &DateTime<Tz>) -> String
where
    Tz::Offset: std::fmt::Display,
{
    let base = dt.format("%Y-%m-%dT%H:%M:%S").to_string();
    let nanos = dt.timestamp_subsec_nanos();
    let frac = if nanos == 0 {
        String::new()
    } else {
        format!(".{}", format!("{:09}", nanos).trim_end_matches('0'))
    };
    format!(
        "{base}{frac}{}",
        go_offset_suffix(dt.offset().fix().local_minus_utc())
    )
}

/// Go `time.RFC3339` (seconds precision) for the login
/// status view: like [`format_go_rfc3339_nano`] but
/// without fractional seconds. Same Go-exact offset
/// suffix — chrono's `to_rfc3339_opts(Secs, true)` rounds
/// seconds-offsets the same way `%:z` does (fix loop 2,
/// technical N1), so it must not be used here either.
pub fn format_go_rfc3339_secs<Tz: TimeZone>(dt: &DateTime<Tz>) -> String
where
    Tz::Offset: std::fmt::Display,
{
    let base = dt.format("%Y-%m-%dT%H:%M:%S").to_string();
    format!(
        "{base}{}",
        go_offset_suffix(dt.offset().fix().local_minus_utc())
    )
}

/// Go's RFC3339 offset suffix, exactly as Go's `format.go`
/// renders `Z07:00`: a zero offset renders `Z`; otherwise
/// the offset is truncated (toward zero) to whole minutes
/// — Go computes `zone := offset / 60` (integer division)
/// and takes the sign from the truncated minutes, so
/// `+07:06:30` -> `+07:06`, `-07:06:30` -> `-07:06`, and
/// even `-30s` -> `+00:00` (the truncated zone is 0,
/// hence `+`). Chrono's `%:z` instead ROUNDS to the
/// nearest minute (`+07:06:30` -> `+07:07`) and must not
/// be used for Go output (fix loop 2, technical N1).
fn go_offset_suffix(offset_secs: i32) -> String {
    if offset_secs == 0 {
        return "Z".to_string();
    }
    let mut zone = offset_secs / 60; // truncates toward zero, like Go
    let sign = if zone < 0 {
        zone = -zone;
        '-'
    } else {
        '+'
    };
    format!("{sign}{:02}:{:02}", zone / 60, zone % 60)
}

fn zoned_datetime_ms<Tz: TimeZone>(ms: i64, tz: &Tz) -> DateTime<Tz> {
    match tz.timestamp_millis_opt(ms) {
        chrono::LocalResult::Single(dt) => dt,
        // Out of range (or ambiguous, impossible for a fixed
        // offset): the epoch in the same zone.
        _ => tz.timestamp_millis_opt(0).single().unwrap_or_else(|| {
            Utc.timestamp_millis_opt(0)
                .single()
                .unwrap()
                .with_timezone(tz)
        }),
    }
}

fn zoned_datetime<Tz: TimeZone>(secs: i64, tz: &Tz) -> DateTime<Tz> {
    match tz.timestamp_opt(secs, 0) {
        chrono::LocalResult::Single(dt) => dt,
        _ => tz
            .timestamp_opt(0, 0)
            .single()
            .unwrap_or_else(|| Utc.timestamp_opt(0, 0).single().unwrap().with_timezone(tz)),
    }
}

/// The machine-local timezone abbreviation right now
/// (Go `time.Now().In(loc).Format("MST")`, e.g. `"+07"` on
/// cue — probed live: Go renders the tzfile abbreviation,
/// which for Asia/Ho_Chi_Minh is `"+07"`, not `"ICT"`).
/// Read from the local TZif file; when the file cannot be
/// read (POSIX `TZ` string, missing tzdata) the fallback is
/// chrono's numeric offset rendering (`"+07:00"`), which
/// differs from Go's abbreviation — recorded in
/// `rust/PORTING.md` §M4b.
/// Source: `internal/shared/usage.go:239` (`UsageLines`).
pub fn local_abbr_now() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    if let Some(path) = local_zone_path()
        && let Some(abbr) = tz_abbr_at(&path, now)
    {
        return abbr;
    }
    Local::now().format("%Z").to_string()
}

/// Resolve the local zone file the way Go's `time.Local`
/// does: `TZ` unset/empty -> `/etc/localtime`; a `TZ` name
/// -> `/usr/share/zoneinfo/<name>`; an absolute `TZ` path
/// -> that file. A POSIX `TZ` string (no such file) yields
/// `None` (the caller falls back).
///
/// Read as bytes (`var_os`, fix loop 2 R2-B3): a non-UTF8
/// `TZ` is an unknown name (Go: `loadLocation` fails ->
/// UTC), not "unset" — `env::var` conflates the two.
/// An empty `TZ` is UTC in Go, so it yields `None` too
/// (the caller's chrono-`Local` fallback is UTC under an
/// empty `TZ`, matching Go); only a genuinely unset `TZ`
/// resolves to `/etc/localtime`.
fn local_zone_path() -> Option<PathBuf> {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
    match std::env::var_os("TZ") {
        Some(tz) if !tz.is_empty() => {
            let bytes = tz.as_encoded_bytes();
            let bytes = bytes.strip_prefix(b":").unwrap_or(bytes);
            if bytes.starts_with(b"/") {
                Some(PathBuf::from(OsStr::from_bytes(bytes)))
            } else {
                let candidate = PathBuf::from("/usr/share/zoneinfo").join(OsStr::from_bytes(bytes));
                if candidate.is_file() {
                    Some(candidate)
                } else {
                    None
                }
            }
        }
        None => Some(PathBuf::from("/etc/localtime")),
        Some(_) => None,
    }
}

/// Read the timezone abbreviation in effect at `unix` from
/// a TZif file (man tzfile / RFC 8536): the last transition
/// at or before `unix` selects the local-time type, whose
/// abbreviation index names the string. Before the first
/// transition the first non-DST type wins (else type 0),
/// matching tzcode's `localtime` choice. Both v1 (32-bit
/// transitions) and v2+ (64-bit) files are handled; the
/// trailing POSIX footer is ignored.
fn tz_abbr_at(path: &Path, unix: i64) -> Option<String> {
    let data = read_tzif_file(path)?;
    parse_tzif_abbr(&data, unix)
}

/// Go's cap on TZ files (`maxFileSize = 10 << 20`,
/// `zoneinfo_read.go:37`): Go's `readFile` rejects a file
/// past this size, so the offset/abbr lookups fall back to
/// UTC there (fix loop 2, R2-B2).
const MAX_TZIF_BYTES: usize = 10 << 20;

/// Read a TZif file, bounded like Go: at most
/// `MAX_TZIF_BYTES` are kept; a longer file is rejected
/// (returns `None`) instead of being loaded whole (fix
/// loop 2, R2-B1/R2-B2 — an unbounded `fs::read` also
/// loaded e.g. a multi-GB `/proc/kcore`). Reads at most
/// one byte past the cap to detect the overflow without
/// loading the file.
fn read_tzif_file(path: &Path) -> Option<Vec<u8>> {
    use std::io::Read;
    let mut f = std::fs::File::open(path).ok()?;
    let mut data = Vec::new();
    f.by_ref()
        .take((MAX_TZIF_BYTES + 1) as u64)
        .read_to_end(&mut data)
        .ok()?;
    if data.len() > MAX_TZIF_BYTES {
        return None;
    }
    Some(data)
}

/// The raw UTC offset (seconds east) in effect at `unix`
/// in the TZif file at `path` — the gmtoff of the local-time
/// type selected by the same rule as [`tz_abbr_at`]. Used
/// by the Go-compatible clock seam (fix loop 1, B5) to
/// resolve a named zone without chrono's `Local` (which
/// falls back to `/etc/localtime` for unknown names and
/// parses POSIX TZ strings — both unlike Go).
pub fn tz_offset_at(path: &Path, unix: i64) -> Option<i32> {
    let data = read_tzif_file(path)?;
    parse_tzif_offset(&data, unix)
}

fn be_u32(data: &[u8], off: usize) -> Option<u32> {
    let b = data.get(off..off + 4)?;
    Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

fn parse_tzif_abbr(data: &[u8], unix: i64) -> Option<String> {
    let block = select_tzif_block(data)?;
    lookup_abbr(&block, unix)
}

fn parse_tzif_offset(data: &[u8], unix: i64) -> Option<i32> {
    let block = select_tzif_block(data)?;
    lookup_offset(&block, unix)
}

/// Select the TZif data block in effect (the v1 block for
/// v1 files, the v2 64-bit block for v2+ files) — the
/// header walk shared by the abbreviation and offset
/// lookups. Returns `None` on truncation or a bad magic.
fn select_tzif_block(data: &[u8]) -> Option<TzifBlock> {
    if data.len() < 44 || &data[0..4] != b"TZif" {
        return None;
    }
    let version = data[4];
    let counts = |off: usize| -> Option<(usize, usize, usize, usize, usize, usize)> {
        Some((
            be_u32(data, off + 20)? as usize, // isutcnt
            be_u32(data, off + 24)? as usize, // isstdcnt
            be_u32(data, off + 28)? as usize, // leapcnt
            be_u32(data, off + 32)? as usize, // timecnt
            be_u32(data, off + 36)? as usize, // typecnt
            be_u32(data, off + 40)? as usize, // charcnt
        ))
    };
    let (isutcnt, isstdcnt, leapcnt, timecnt, typecnt, charcnt) = counts(0)?;
    let mut off = 44usize;
    // v1 block: transitions (i32), type indices (u8),
    // ttinfo (6 bytes each), abbreviation chars.
    let v1 = parse_tzif_block(data, &mut off, timecnt, typecnt, charcnt, false)?;
    if version == 0 || version == b'1' {
        return Some(v1);
    }
    // v2+: skip the v1 leap records (8 bytes each) and the
    // isstd/isut indicator bytes, then parse the v2 header
    // and its 64-bit block.
    off = off
        .checked_add(leapcnt.checked_mul(8)?)?
        .checked_add(isstdcnt)?
        .checked_add(isutcnt)?;
    if data.len() < off + 44 || &data[off..off + 4] != b"TZif" {
        return None;
    }
    let (_, _, _, timecnt2, typecnt2, charcnt2) = counts(off)?;
    let mut off2 = off + 44;
    parse_tzif_block(data, &mut off2, timecnt2, typecnt2, charcnt2, true)
}

/// One parsed TZif data block: transitions `(time, type
/// index)`, types `(gmtoff, isdst, abbrind)`, abbreviation
/// bytes.
type TzifBlock = (Vec<(i64, usize)>, Vec<(i32, bool, usize)>, Vec<u8>);

/// Parse one TZif data block. `wide` selects 64-bit (v2+)
/// over 32-bit (v1) transition times. Returns `None` on
/// truncation.
fn parse_tzif_block(
    data: &[u8],
    off: &mut usize,
    timecnt: usize,
    typecnt: usize,
    charcnt: usize,
    wide: bool,
) -> Option<TzifBlock> {
    // Fix loop 2, R2-B1: validate the header counts
    // against the remaining data BEFORE allocating — a
    // crafted header (`timecnt=0xFFFFFFFF`) previously
    // asked `Vec::with_capacity` for a 34 GB allocation
    // and aborted the process. A block needs `timecnt`
    // transition times, `timecnt` type indices, `typecnt`
    // ttinfo records and `charcnt` abbreviation bytes;
    // anything short of that is a corrupt file, not a
    // large one. (After this check every `with_capacity`
    // below is bounded by the data length, itself capped
    // at 10 MiB by `read_tzif_file`.)
    let elem = if wide { 8usize } else { 4usize };
    let need = timecnt
        .checked_mul(elem)?
        .checked_add(timecnt)?
        .checked_add(typecnt.checked_mul(6)?)?
        .checked_add(charcnt)?;
    if data.len().saturating_sub(*off) < need {
        return None;
    }
    // Transition times come first as one array, then the
    // type indices as a second array (not interleaved).
    let mut times = Vec::with_capacity(timecnt);
    for _ in 0..timecnt {
        let t = if wide {
            let b = data.get(*off..*off + 8)?;
            *off += 8;
            i64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
        } else {
            let b = data.get(*off..*off + 4)?;
            *off += 4;
            i32::from_be_bytes([b[0], b[1], b[2], b[3]]) as i64
        };
        times.push(t);
    }
    let mut trans = Vec::with_capacity(timecnt);
    for t in times {
        let idx = *data.get(*off)? as usize;
        *off += 1;
        trans.push((t, idx));
    }
    let mut types = Vec::with_capacity(typecnt);
    for _ in 0..typecnt {
        let b = data.get(*off..*off + 6)?;
        *off += 6;
        let gmtoff = i32::from_be_bytes([b[0], b[1], b[2], b[3]]);
        let isdst = b[4] != 0;
        let abbrind = b[5] as usize;
        types.push((gmtoff, isdst, abbrind));
    }
    let abbrs = data.get(*off..*off + charcnt)?.to_vec();
    *off += charcnt;
    Some((trans, types, abbrs))
}

fn lookup_abbr(block: &TzifBlock, unix: i64) -> Option<String> {
    let types = &block.1;
    let abbrs = &block.2;
    if types.is_empty() || abbrs.is_empty() {
        return None;
    }
    let ti = lookup_type_idx(block, unix)?;
    let (_, _, abbrind) = types.get(ti)?;
    let rest = abbrs.get(*abbrind..)?;
    let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
    std::str::from_utf8(&rest[..end]).ok().map(str::to_string)
}

/// The local-time type in effect at `unix`: the last
/// transition at or before `unix` selects it; before the
/// first transition Go's `lookupFirstZone`
/// (`zoneinfo.go:233-260`) applies — (1) zone 0 when it
/// is unused by any transition, (2) when the first
/// transition targets a DST zone, the closest non-DST
/// zone before that target's index, (3) the first
/// non-DST zone overall, (4) zone 0. Shared by the
/// abbreviation and offset lookups.
fn lookup_type_idx(block: &TzifBlock, unix: i64) -> Option<usize> {
    let (trans, types, _) = block;
    if types.is_empty() {
        return None;
    }
    let mut type_idx: Option<usize> = None;
    for (t, ti) in trans {
        if *t <= unix {
            type_idx = Some(*ti);
        } else {
            break;
        }
    }
    match type_idx {
        Some(ti) => Some(ti),
        None => {
            // Go `lookupFirstZone`, case 1: zone 0 unused
            // by any transition.
            if !trans.iter().any(|(_, ti)| *ti == 0) {
                return Some(0);
            }
            // Case 2: the first transition targets a DST
            // zone — the closest non-DST zone before that
            // target's index. (An out-of-range target
            // index is a corrupt file; fall through to
            // case 3 instead of indexing blindly.)
            if let Some((_, first_ti)) = trans.first()
                && types
                    .get(*first_ti)
                    .map(|(_, isdst, _)| *isdst)
                    .unwrap_or(false)
            {
                for zi in (0..*first_ti).rev() {
                    if let Some((_, isdst, _)) = types.get(zi)
                        && !isdst
                    {
                        return Some(zi);
                    }
                }
            }
            // Cases 3 and 4: first non-DST type, else 0.
            types.iter().position(|(_, isdst, _)| !isdst).or(Some(0))
        }
    }
}

/// The gmtoff of the local-time type in effect at `unix`.
fn lookup_offset(block: &TzifBlock, unix: i64) -> Option<i32> {
    let ti = lookup_type_idx(block, unix)?;
    block.1.get(ti).map(|(gmtoff, _, _)| *gmtoff)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::FixedOffset;
    use std::path::PathBuf;

    fn ict() -> FixedOffset {
        FixedOffset::east_opt(7 * 3600).unwrap()
    }

    fn utc() -> FixedOffset {
        FixedOffset::east_opt(0).unwrap()
    }

    fn zoneinfo(name: &str) -> PathBuf {
        PathBuf::from("/usr/share/zoneinfo").join(name)
    }

    #[test]
    fn updated_at_renders_in_zone() {
        // Go TestSessionRows: 1792821457000 ms in ICT.
        assert_eq!(
            format_updated_at_ms(1792821457000, &ict()),
            "2026-10-24 12:57"
        );
        assert_eq!(
            format_updated_at_ms(1792821457000, &utc()),
            "2026-10-24 05:57"
        );
        // Missing stamp -> epoch (Go: local epoch).
        assert_eq!(format_updated_at_ms(0, &ict()), "1970-01-01 07:00");
        assert_eq!(format_updated_at_ms(0, &utc()), "1970-01-01 00:00");
    }

    #[test]
    fn resets_at_renders_go_format() {
        // Go TestSummarizeUsage: 1792821457 s in ICT.
        assert_eq!(
            format_resets_at(1792821457, &ict()),
            "2026-10-24T12:57:37+0700"
        );
        assert_eq!(
            format_resets_at(1792821457, &utc()),
            "2026-10-24T05:57:37+0000"
        );
    }

    #[test]
    fn tz_abbr_reads_tzif_files() {
        // Fixed timestamps, real zoneinfo files (present on
        // any Debian system, including cue).
        assert_eq!(
            tz_abbr_at(&zoneinfo("UTC"), 1792821457),
            Some("UTC".to_string())
        );
        assert_eq!(
            tz_abbr_at(&zoneinfo("Asia/Ho_Chi_Minh"), 1792821457),
            Some("+07".to_string()),
            "tzfile abbr is +07, not ICT (probed Go: MST=\"+07\")"
        );
        // January 2026 is EST in New York; June 2025 is EDT.
        assert_eq!(
            tz_abbr_at(&zoneinfo("America/New_York"), 1767225600),
            Some("EST".to_string())
        );
        assert_eq!(
            tz_abbr_at(&zoneinfo("America/New_York"), 1750000000),
            Some("EDT".to_string())
        );
        // Before the first transition: a type still resolves.
        // At the epoch the zone was +08:00 (probed Go:
        // epoch MST="+08", offset 28800).
        assert_eq!(
            tz_abbr_at(&zoneinfo("Asia/Ho_Chi_Minh"), 0),
            Some("+08".to_string())
        );
        assert_eq!(tz_abbr_at(&zoneinfo("UTC"), -1), Some("UTC".to_string()));
        assert_eq!(tz_abbr_at(&PathBuf::from("/nonexistent"), 0), None);
    }

    #[test]
    fn go_rfc3339_nano_trims_trailing_zeros() {
        // Fix loop 1, B1: the shared Go-RFC3339Nano
        // renderer (one helper for every keeper render
        // site). Expected values are the literal Go 1.27.3
        // probe outputs (review1-technical §Probes), never
        // recomputed with the code under test.
        use chrono::Timelike;
        let plus7 = FixedOffset::east_opt(7 * 3600).unwrap();
        for (nanos, expected) in [
            (500_000_000u32, "2026-11-07T18:33:11.5+07:00"),
            (100_000_000, "2026-11-07T18:33:11.1+07:00"),
            (120_000_000, "2026-11-07T18:33:11.12+07:00"),
            (123_400_000, "2026-11-07T18:33:11.1234+07:00"),
            (123_456_780, "2026-11-07T18:33:11.12345678+07:00"),
            (10, "2026-11-07T18:33:11.00000001+07:00"),
            (123_000_000, "2026-11-07T18:33:11.123+07:00"),
            (123_456_000, "2026-11-07T18:33:11.123456+07:00"),
            (890_775_586, "2026-11-07T18:33:11.890775586+07:00"),
            (1, "2026-11-07T18:33:11.000000001+07:00"),
            (0, "2026-11-07T18:33:11+07:00"),
        ] {
            let dt = plus7
                .with_ymd_and_hms(2026, 11, 7, 18, 33, 11)
                .unwrap()
                .with_nanosecond(nanos)
                .unwrap();
            assert_eq!(format_go_rfc3339_nano(&dt), expected, "nanos={nanos}");
        }
        // A zero offset renders `Z`, not `+00:00` (Go
        // normalises `+00:00` to `Z`, R1 probe P2).
        let zero = FixedOffset::east_opt(0)
            .unwrap()
            .with_ymd_and_hms(2026, 11, 7, 11, 33, 11)
            .unwrap()
            .with_nanosecond(500_000_000)
            .unwrap();
        assert_eq!(format_go_rfc3339_nano(&zero), "2026-11-07T11:33:11.5Z");
        // A `Utc` instant renders `Z` too.
        let utc_dt = Utc
            .with_ymd_and_hms(2026, 12, 5, 0, 0, 0)
            .unwrap()
            .with_nanosecond(500_000_000)
            .unwrap();
        assert_eq!(format_go_rfc3339_nano(&utc_dt), "2026-12-05T00:00:00.5Z");
        // A negative offset is kept verbatim.
        let minus3 = FixedOffset::west_opt(3 * 3600)
            .unwrap()
            .with_ymd_and_hms(2026, 11, 7, 8, 33, 15)
            .unwrap()
            .with_nanosecond(63_157_834)
            .unwrap();
        assert_eq!(
            format_go_rfc3339_nano(&minus3),
            "2026-11-07T08:33:15.063157834-03:00"
        );
    }

    #[test]
    fn go_rfc3339_nano_truncates_seconds_offsets_like_go() {
        // Fix loop 2, technical N1: chrono's `%:z`
        // ROUNDS a seconds-offset to the nearest minute
        // (+07:06:30 -> +07:07); Go TRUNCATES it, taking
        // the sign from the truncated minutes
        // (`zone := offset/60`, format.go) — so +07:06:30
        // -> +07:06, -07:06:30 -> -07:06, and even -30s
        // -> +00:00 (truncated zone 0, hence '+').
        // Expected values are the literal Go 1.27.3 probe
        // outputs (FixedZone marshal), never recomputed.
        // Latent only (the parser rejects seconds-offsets)
        // — fixed anyway, the helper is the single funnel.
        use chrono::Timelike;
        for (secs, expected) in [
            (7 * 3600 + 6 * 60 + 30, "1850-01-01T12:00:00.5+07:06"),
            (-(7 * 3600 + 6 * 60 + 30), "1850-01-01T12:00:00.5-07:06"),
            (30, "1850-01-01T12:00:00.5+00:00"),
            (-30, "1850-01-01T12:00:00.5+00:00"),
            (561, "1850-01-01T12:00:00.5+00:09"),
            (-561, "1850-01-01T12:00:00.5-00:09"),
        ] {
            let off = FixedOffset::east_opt(secs).unwrap();
            let dt = off
                .with_ymd_and_hms(1850, 1, 1, 12, 0, 0)
                .unwrap()
                .with_nanosecond(500_000_000)
                .unwrap();
            assert_eq!(format_go_rfc3339_nano(&dt), expected, "offset_secs={secs}");
        }
    }

    #[test]
    fn tz_offset_at_reads_tzif_offsets() {
        // Fix loop 1, B5: the raw offset in effect at an
        // instant, read from the TZif file (shared by the
        // Go-compatible clock seam). Fixed timestamps,
        // real zoneinfo files.
        assert_eq!(tz_offset_at(&zoneinfo("UTC"), 1792821457), Some(0));
        assert_eq!(
            tz_offset_at(&zoneinfo("Asia/Ho_Chi_Minh"), 1792821457),
            Some(25200)
        );
        // At the epoch the zone was +08:00 (probed Go:
        // epoch offset 28800).
        assert_eq!(tz_offset_at(&zoneinfo("Asia/Ho_Chi_Minh"), 0), Some(28800));
        // January 2026 is EST in New York; June 2025 is EDT.
        assert_eq!(
            tz_offset_at(&zoneinfo("America/New_York"), 1767225600),
            Some(-18000)
        );
        assert_eq!(
            tz_offset_at(&zoneinfo("America/New_York"), 1750000000),
            Some(-14400)
        );
        assert_eq!(
            tz_offset_at(&zoneinfo("Etc/GMT+12"), 1792821457),
            Some(-43200)
        );
        assert_eq!(tz_offset_at(&PathBuf::from("/nonexistent"), 0), None);
    }

    /// A minimal v1 TZif header (44 bytes) with the given
    /// counts (`isutcnt`/`isstdcnt`/`leapcnt` zero).
    /// Used by the fix-loop-2 header-bomb tests (R2-B1):
    /// the body is appended by the caller.
    fn tzif_header(timecnt: u32, typecnt: u32, charcnt: u32) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(b"TZif");
        b.push(0); // version 0 = v1
        b.extend_from_slice(&[0u8; 15]);
        for c in [0u32, 0, 0, timecnt, typecnt, charcnt] {
            b.extend_from_slice(&c.to_be_bytes());
        }
        b
    }

    #[test]
    fn tzif_huge_timecnt_does_not_abort() {
        // Fix loop 2, R2-B1 (round-2 red-team): a 51-byte
        // TZif with timecnt=0xFFFFFFFF aborted the process
        // (exit 134, 34 GB allocation) because
        // parse_tzif_block trusted the header counts for
        // Vec::with_capacity before any length check. Go
        // returns UTC (None) on the same file. The
        // expected value is the Go behaviour, not the
        // code's: the file is corrupt, the process must
        // survive it.
        let mut data = tzif_header(0xFFFF_FFFF, 1, 1);
        data.extend_from_slice(&[0u8; 7]); // 51 bytes total, like the probe file
        assert_eq!(parse_tzif_offset(&data, 1792821457), None);
        assert_eq!(parse_tzif_abbr(&data, 1792821457), None);
    }

    #[test]
    fn tzif_huge_typecnt_does_not_abort() {
        // Same bomb via typecnt (fix loop 2, R2-B1).
        let mut data = tzif_header(0, 0xFFFF_FFFF, 1);
        data.extend_from_slice(&[0u8; 7]);
        assert_eq!(parse_tzif_offset(&data, 1792821457), None);
    }

    #[test]
    fn tzif_truncated_header_is_none() {
        // Guard: short / bad-magic inputs never reach the
        // block parser (already None before the fix — this
        // test pins the behaviour, it is not the R2-B1
        // regression proof).
        assert_eq!(parse_tzif_offset(b"TZif", 0), None);
        assert_eq!(parse_tzif_offset(&[0u8; 43], 0), None);
        assert_eq!(parse_tzif_offset(&[b'X'; 44], 0), None);
    }

    /// Build a minimal v1 TZif file from (gmtoff, isdst)
    /// types and (unix, type_idx) transitions. All
    /// abbreviations are the empty string (abbrind 0).
    /// Used by the fix-loop-2 `lookupFirstZone` tests.
    fn tzif_v1(types: &[(i32, bool)], trans: &[(i32, usize)]) -> Vec<u8> {
        let mut b = tzif_header(trans.len() as u32, types.len() as u32, 1);
        for (t, _) in trans {
            b.extend_from_slice(&t.to_be_bytes());
        }
        for (_, ti) in trans {
            b.push(*ti as u8);
        }
        for (off, isdst) in types {
            b.extend_from_slice(&off.to_be_bytes());
            b.push(*isdst as u8);
            b.push(0);
        }
        b.push(0);
        b
    }

    #[test]
    fn lookup_first_zone_matches_go_cases_1_and_2() {
        // Fix loop 2, technical N2: the pre-first-
        // transition choice must be Go's `lookupFirstZone`
        // (zoneinfo.go), not just "first non-DST type".
        // Expected offsets are Go's answers for the same
        // crafted files (read from the Go source cases),
        // never recomputed with the code under test.
        // Case 1: zone 0 unused by any transition -> zone
        // 0, even though it is a DST zone. Old code
        // returned the first non-DST type (+02:00).
        let data = tzif_v1(&[(3600, true), (7200, false)], &[(1000, 1)]);
        assert_eq!(parse_tzif_offset(&data, 0), Some(3600));
        // Case 2: zone 0 IS used, and the first transition
        // targets a DST zone -> the closest non-DST zone
        // *before* that target's index (type 2, +03:00),
        // not the first non-DST overall (type 0, +01:00).
        let data = tzif_v1(
            &[(3600, false), (7200, true), (10800, false), (14400, true)],
            &[(100, 3), (200, 0)],
        );
        assert_eq!(parse_tzif_offset(&data, 0), Some(10800));
        // Case 3 guard: zone 0 used, first transition
        // targets a DST zone at index 0 -> no zone below
        // it to scan, so the first non-DST type wins (both
        // old and new code agree: +02:00).
        let data = tzif_v1(&[(3600, true), (7200, false)], &[(100, 0)]);
        assert_eq!(parse_tzif_offset(&data, 0), Some(7200));
    }

    #[test]
    fn tz_offset_at_rejects_files_over_10mb_like_go() {
        // Fix loop 2, R2-B2: Go caps TZ files at 10 MiB
        // (maxFileSize = 10 << 20, zoneinfo_read.go:37);
        // an 11 MiB file falls back to UTC (None).
        // Exactly 10 MiB is accepted by Go's readFile
        // (it rejects only len > maxFileSize), so the
        // offset still reads there.
        let dir = std::env::temp_dir().join(format!("m7g-tzif-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let hcm = std::fs::read("/usr/share/zoneinfo/Asia/Ho_Chi_Minh").unwrap();
        let mut big = hcm.clone();
        big.resize(11 << 20, 0);
        let big_path = dir.join("big11m");
        std::fs::write(&big_path, &big).unwrap();
        assert_eq!(tz_offset_at(&big_path, 1792821457), None);
        let mut exact = hcm.clone();
        exact.resize(10 << 20, 0);
        let exact_path = dir.join("exact10m");
        std::fs::write(&exact_path, &exact).unwrap();
        assert_eq!(tz_offset_at(&exact_path, 1792821457), Some(25200));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn local_abbr_now_is_plus07_on_cue() {
        // Pinned only when the machine zone really is
        // Asia/Ho_Chi_Minh (cue: /etc/localtime symlink);
        // elsewhere only the non-empty fallback is checked.
        // Probed Go on cue: local MST="+07".
        let abbr = local_abbr_now();
        assert!(!abbr.is_empty(), "abbreviation must not be empty");
        let is_hcm = std::env::var("TZ").is_err()
            && std::fs::read_link("/etc/localtime")
                .map(|p| p.to_string_lossy().contains("Ho_Chi_Minh"))
                .unwrap_or(false);
        if is_hcm {
            assert_eq!(abbr, "+07", "cue local zone abbreviation");
        }
    }
}
