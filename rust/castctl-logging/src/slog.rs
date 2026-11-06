// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! The slog bridge: the second logger world (conn.Muse lines
//! and the bootstrap lookup line) writing through the SAME
//! sing-box factory and the SAME resolved level as the factory
//! logger. Port of Go `internal/logging/slog.go`.
//!
//! Level mapping: slog has no trace/fatal/panic. Slog levels
//! below Debug map to sing-box Trace; Debug→Debug, Info→Info,
//! Warn→Warn, Error and above→Error. The handler reads the
//! factory's level once at construction (castctl never calls
//! `SetLevel` after construction, so the captured value
//! cannot drift from the factory's gate).
//!
//! Redaction: every attr value and the message pass
//! `SafeString` (errors via `safe_err_for_level`, which
//! renders the allowlist summary at EVERY level including
//! trace under the loop-5 ruling — no body bytes at trace
//! either). `SafeString` strips labelled secret forms only;
//! field exclusion by construction still applies at the call
//! sites.

use std::error::Error;
use std::sync::Arc;

use castctl_log_redact::safe_string;

use crate::factory::{emit, Handle, Level, Logger};
use crate::safe_err_for_level;

/// A slog level: Go's `slog.Level` is an integer
/// (`Debug = -4`, `Info = 0`, `Warn = 4`, `Error = 8`);
/// arbitrary values (e.g. `Debug - 4`) are meaningful.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SlogLevel(pub i32);

impl SlogLevel {
    pub const DEBUG: SlogLevel = SlogLevel(-4);
    pub const INFO: SlogLevel = SlogLevel(0);
    pub const WARN: SlogLevel = SlogLevel(4);
    pub const ERROR: SlogLevel = SlogLevel(8);
}

fn sing_level(level: SlogLevel) -> Level {
    match level.0 {
        i32::MIN..=-5 => Level::TRACE,
        -4..=-1 => Level::DEBUG,
        0..=3 => Level::INFO,
        4..=7 => Level::WARN,
        _ => Level::ERROR,
    }
}

/// One slog attr value. Errors are kept as errors (rendered
/// via `safe_err_for_level` at log time); everything else is
/// rendered then passed through `SafeString`, so a
/// secret-bearing value cannot cross the boundary raw.
#[derive(Clone)]
pub enum SlogValue {
    Str(String),
    Int(i64),
    Float(f64),
    Bool(bool),
    Error(Arc<dyn Error + Send + Sync>),
    /// Pre-rendered text (e.g. a duration or a group value).
    Text(String),
}

impl SlogValue {
    pub fn error<E: Error + Send + Sync + 'static>(e: E) -> Self {
        SlogValue::Error(Arc::new(e))
    }
}

impl From<&str> for SlogValue {
    fn from(s: &str) -> Self {
        SlogValue::Str(s.to_string())
    }
}

impl From<String> for SlogValue {
    fn from(s: String) -> Self {
        SlogValue::Str(s)
    }
}

impl From<i64> for SlogValue {
    fn from(n: i64) -> Self {
        SlogValue::Int(n)
    }
}

impl From<i32> for SlogValue {
    fn from(n: i32) -> Self {
        SlogValue::Int(n as i64)
    }
}

impl From<bool> for SlogValue {
    fn from(b: bool) -> Self {
        SlogValue::Bool(b)
    }
}

impl From<f64> for SlogValue {
    fn from(x: f64) -> Self {
        SlogValue::Float(x)
    }
}

fn safe_attr_value(v: &SlogValue, level: Level) -> String {
    match v {
        SlogValue::Error(e) => safe_err_for_level(Some(e.as_ref()), level),
        SlogValue::Str(s) => safe_string(s),
        SlogValue::Int(n) => safe_string(&n.to_string()),
        SlogValue::Float(x) => safe_string(&format!("{x}")),
        SlogValue::Bool(b) => safe_string(&b.to_string()),
        SlogValue::Text(s) => safe_string(s),
    }
}

/// A `*slog.Logger` writing through the factory. `Handle`
/// below is `castctl-logging`'s factory handle, not the slog
/// handler: `SlogLogger::new(handle, tag)` mirrors Go's
/// `NewSlogLogger(factory, tag)`.
#[derive(Clone)]
pub struct SlogLogger {
    logger: Logger,
    max_level: Level,
    attrs: Vec<(String, SlogValue)>,
    groups: Vec<String>,
}

impl SlogLogger {
    pub fn new(handle: &Handle, tag: &str) -> Self {
        SlogLogger {
            logger: handle.logger(tag),
            max_level: handle.level(),
            attrs: Vec::new(),
            groups: Vec::new(),
        }
    }

    /// `Enabled`: the mapped level must pass the factory gate.
    pub fn enabled(&self, level: SlogLevel) -> bool {
        sing_level(level) <= self.max_level
    }

    /// `Handle`: append pre-set attrs first, then the record
    /// attrs; group names prefix each key (`g.key`, later
    /// groups outermost); the composed line goes through
    /// `Emit` at the mapped level.
    pub fn log(&self, level: SlogLevel, msg: &str, attrs: &[(&str, SlogValue)]) {
        let mapped = sing_level(level);
        if mapped > self.max_level {
            return;
        }
        let mut full = safe_string(msg);
        for (k, v) in self
            .attrs
            .iter()
            .map(|(k, v)| (k.as_str(), v))
            .chain(attrs.iter().map(|(k, v)| (*k, v)))
        {
            let mut key = k.to_string();
            for g in &self.groups {
                key = format!("{g}.{key}");
            }
            full.push_str(&format!(
                " {}={}",
                safe_string(&key),
                safe_attr_value(v, mapped)
            ));
        }
        emit(&self.logger, mapped, &full);
    }

    pub fn debug(&self, msg: &str, attrs: &[(&str, SlogValue)]) {
        self.log(SlogLevel::DEBUG, msg, attrs);
    }

    pub fn info(&self, msg: &str, attrs: &[(&str, SlogValue)]) {
        self.log(SlogLevel::INFO, msg, attrs);
    }

    pub fn warn(&self, msg: &str, attrs: &[(&str, SlogValue)]) {
        self.log(SlogLevel::WARN, msg, attrs);
    }

    pub fn error(&self, msg: &str, attrs: &[(&str, SlogValue)]) {
        self.log(SlogLevel::ERROR, msg, attrs);
    }

    /// `WithAttrs`: a new logger with these attrs prepended to
    /// every record's attrs.
    pub fn with_attrs(&self, attrs: &[(&str, SlogValue)]) -> Self {
        let mut out = self.clone();
        out.attrs
            .extend(attrs.iter().map(|(k, v)| (k.to_string(), v.clone())));
        out
    }

    /// `WithGroup`: a new logger with this group name
    /// prefixing every attr key.
    pub fn with_group(&self, name: &str) -> Self {
        let mut out = self.clone();
        out.groups.push(name.to_string());
        out
    }

    /// Expose the underlying factory logger (for `Emit`-style
    /// callers that already hold a `SlogLogger`).
    pub fn logger(&self) -> &Logger {
        &self.logger
    }

    /// The level this bridge was captured at.
    pub fn max_level(&self) -> Level {
        self.max_level
    }
}
