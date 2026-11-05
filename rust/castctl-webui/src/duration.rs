// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Go `time.Duration` parsing and rendering.
//!
//! Source: Go `time.ParseDuration` / `Duration.String`
//! (`time/time.go`). Durations are nanosecond counts (`i64`);
//! the web UI bounds are 1s..24h (rate-limit window),
//! 1m..720h (idle timeout) and 1m..30d (idle parse bound).
//! `webui.session_idle_timeout` and keeper `interval` render
//! as Go duration strings (`12h0m0s`, `5m0s`).

/// One second in nanoseconds.
pub const SECOND_NS: i64 = 1_000_000_000;
/// One minute in nanoseconds.
pub const MINUTE_NS: i64 = 60 * SECOND_NS;
/// One hour in nanoseconds.
pub const HOUR_NS: i64 = 60 * MINUTE_NS;

/// Parse a Go duration string (`time.ParseDuration`).
/// Syntax: optional sign, then one or more `<number><unit>`
/// pairs; units `ns`, `us`/`µs`/`μs`, `ms`, `s`, `m`, `h`.
/// The bare string `0` (with optional sign) is allowed with
/// no unit. Anything else is an error; no whitespace is
/// trimmed (callers trim first where Go trims).
pub fn parse_duration(s: &str) -> Result<i64, String> {
    if s.is_empty() {
        return Err("time: invalid duration \"\"".to_string());
    }
    let (neg, rest) = match s.strip_prefix('-') {
        Some(r) => (true, r),
        None => (false, s.strip_prefix('+').unwrap_or(s)),
    };
    if rest.is_empty() {
        return Err(format!("time: invalid duration {s:?}"));
    }
    if rest == "0" {
        return Ok(0);
    }
    let bytes = rest.as_bytes();
    let mut i = 0usize;
    let mut total: i128 = 0;
    let mut any = false;
    while i < bytes.len() {
        // Number: digits with optional fraction, or ".5".
        let num_start = i;
        let mut has_digits = false;
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            has_digits = true;
            i += 1;
        }
        let mut frac: i128 = 0;
        let mut frac_scale: i128 = 1;
        if i < bytes.len() && bytes[i] == b'.' {
            i += 1;
            let frac_start = i;
            while i < bytes.len() && bytes[i].is_ascii_digit() {
                frac = frac * 10 + (bytes[i] - b'0') as i128;
                frac_scale *= 10;
                i += 1;
            }
            if i == frac_start {
                has_digits = false;
            }
        }
        if !has_digits {
            return Err(format!("time: invalid duration {s:?}"));
        }
        let int_part: i128 = rest[num_start..i]
            .split('.')
            .next()
            .unwrap_or("0")
            .parse()
            .unwrap_or(0);
        // Unit.
        let unit_start = i;
        while i < bytes.len() && !bytes[i].is_ascii_digit() && bytes[i] != b'.' {
            i += 1;
        }
        let unit = &rest[unit_start..i];
        let mult: i128 = match unit {
            "ns" => 1,
            "us" | "µs" | "μs" => 1_000,
            "ms" => 1_000_000,
            "s" => 1_000_000_000,
            "m" => 60_000_000_000,
            "h" => 3_600_000_000_000,
            _ => return Err(format!("time: unknown unit {unit:?} in duration {s:?}")),
        };
        let part = int_part
            .checked_mul(mult)
            .and_then(|p| p.checked_add(frac * mult / frac_scale))
            .and_then(|p| total.checked_add(p));
        total = match part {
            Some(t) => t,
            None => return Err(format!("time: invalid duration {s:?}")),
        };
        if total > i64::MAX as i128 {
            return Err(format!("time: invalid duration {s:?}"));
        }
        any = true;
    }
    if !any {
        return Err(format!("time: invalid duration {s:?}"));
    }
    let out = if neg { -total } else { total };
    i64::try_from(out).map_err(|_| format!("time: invalid duration {s:?}"))
}

/// Render a duration as Go's `Duration.String()`: `0s`,
/// `5m0s`, `12h0m0s`, `1.5s`, `500ms`, `1m30s`.
pub fn format_duration(d: i64) -> String {
    if d == 0 {
        return "0s".to_string();
    }
    let neg = d < 0;
    let u: u64 = d.unsigned_abs();
    let mut out = String::new();
    if neg {
        out.push('-');
    }
    if u < SECOND_NS as u64 {
        // Sub-second: ns / µs / ms with a trimmed fraction.
        if u == 0 {
            return "0s".to_string();
        }
        if u < 1_000 {
            out.push_str(&format!("{u}ns"));
        } else if u < 1_000_000 {
            let (whole, frac) = (u / 1_000, u % 1_000);
            out.push_str(&format!("{whole}"));
            push_frac(&mut out, frac as i128, 3);
            out.push('µ');
            out.push('s');
        } else {
            let (whole, frac) = (u / 1_000_000, u % 1_000_000);
            out.push_str(&format!("{whole}"));
            push_frac(&mut out, frac as i128, 6);
            out.push_str("ms");
        }
        return out;
    }
    // Seconds and up: fraction (9 digits, trimmed), then
    // seconds, minutes, hours — Go's fmtFrac/fmtInt order.
    let frac = u % (SECOND_NS as u64);
    let mut secs = u / (SECOND_NS as u64);
    let mut frac_str = String::new();
    push_frac(&mut frac_str, frac as i128, 9);
    let seconds = secs % 60;
    secs /= 60;
    let minutes = secs % 60;
    secs /= 60;
    let hours = secs;
    let mut body = String::new();
    if hours > 0 {
        body.push_str(&format!("{hours}h"));
    }
    if hours > 0 || minutes > 0 {
        body.push_str(&format!("{minutes}m"));
    }
    body.push_str(&format!("{seconds}"));
    body.push_str(&frac_str);
    body.push('s');
    out.push_str(&body);
    out
}

/// Append a Go `fmtFrac` fraction: `.` + digits with trailing
/// zeros trimmed; nothing when the fraction is zero. `prec` is
/// the digit count of the unit scale (3 = µs, 6 = ms, 9 = s).
fn push_frac(out: &mut String, frac: i128, prec: u32) {
    if frac == 0 {
        return;
    }
    let mut digits = format!("{frac:0prec$}", prec = prec as usize);
    while digits.ends_with('0') {
        digits.pop();
    }
    out.push('.');
    out.push_str(&digits);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_go_durations() {
        assert_eq!(parse_duration("5m"), Ok(5 * MINUTE_NS));
        assert_eq!(parse_duration("12h"), Ok(12 * HOUR_NS));
        assert_eq!(parse_duration("1h30m"), Ok(90 * MINUTE_NS));
        assert_eq!(parse_duration("1.5h"), Ok(90 * MINUTE_NS));
        assert_eq!(parse_duration("0"), Ok(0));
        assert_eq!(parse_duration("300ms"), Ok(300_000_000));
        assert!(parse_duration("").is_err());
        assert!(parse_duration("5").is_err());
        assert!(parse_duration("1x").is_err());
        assert!(parse_duration("1.5").is_err());
    }

    #[test]
    fn format_go_durations() {
        // Go's Duration.String() outputs, verbatim.
        assert_eq!(format_duration(0), "0s");
        assert_eq!(format_duration(5 * MINUTE_NS), "5m0s");
        assert_eq!(format_duration(12 * HOUR_NS), "12h0m0s");
        assert_eq!(format_duration(90 * SECOND_NS), "1m30s");
        assert_eq!(format_duration(1500 * 1_000_000), "1.5s");
        assert_eq!(format_duration(500 * 1_000_000), "500ms");
        assert_eq!(format_duration(24 * HOUR_NS), "24h0m0s");
        assert_eq!(format_duration(720 * HOUR_NS), "720h0m0s");
        assert_eq!(format_duration(SECOND_NS), "1s");
        assert_eq!(format_duration(-5 * MINUTE_NS), "-5m0s");
    }

    #[test]
    fn fail_before_format() {
        // A naive "minutes only" renderer would print "5m"
        // for 300s; Go prints "5m0s". This pins the Go shape.
        assert_ne!(format_duration(300 * SECOND_NS), "5m");
        assert_eq!(format_duration(300 * SECOND_NS), "5m0s");
    }
}
