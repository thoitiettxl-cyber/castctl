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
fn local_zone_path() -> Option<PathBuf> {
    match std::env::var("TZ") {
        Ok(tz) if !tz.is_empty() => {
            let tz = tz.strip_prefix(':').unwrap_or(&tz);
            if tz.starts_with('/') {
                Some(PathBuf::from(tz))
            } else {
                let candidate = PathBuf::from("/usr/share/zoneinfo").join(tz);
                if candidate.is_file() {
                    Some(candidate)
                } else {
                    None
                }
            }
        }
        _ => Some(PathBuf::from("/etc/localtime")),
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
    let data = std::fs::read(path).ok()?;
    parse_tzif_abbr(&data, unix)
}

fn be_u32(data: &[u8], off: usize) -> Option<u32> {
    let b = data.get(off..off + 4)?;
    Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

fn parse_tzif_abbr(data: &[u8], unix: i64) -> Option<String> {
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
        return lookup_abbr(&v1, unix);
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
    let v2 = parse_tzif_block(data, &mut off2, timecnt2, typecnt2, charcnt2, true)?;
    lookup_abbr(&v2, unix)
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
    let (trans, types, abbrs) = block;
    if types.is_empty() || abbrs.is_empty() {
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
    let ti = match type_idx {
        Some(ti) => ti,
        None => types.iter().position(|(_, isdst, _)| !isdst).unwrap_or(0),
    };
    let (_, _, abbrind) = types.get(ti)?;
    let rest = abbrs.get(*abbrind..)?;
    let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
    std::str::from_utf8(&rest[..end]).ok().map(str::to_string)
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
