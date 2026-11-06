// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! The log factory: `Settings`, `Handle`, `Logger`, `Emit` and
//! the `openLogFile` identity guard.
//!
//! Port of Go `internal/logging/factory.go` at base `dev-rust`
//! `25a124e`. Two deliberate deviations from calling sing-box's
//! `log.New` directly are preserved from Go (see `factory.go`
//! `NewFactory` docs): the file is created by castctl at mode
//! 0600 (never 0644, never chmod of a pre-existing file), and
//! console output goes through the caller's writer.
//!
//! Differences from Go (recorded in PORTING.md §M7a):
//! - No pre-`Start` buffering: Go's factory buffers entries
//!   logged before `Start()`, but `NewFactory` starts the
//!   factory itself, so no caller can observe the buffer; the
//!   Rust factory is live at construction.
//! - `Handle::close` returns `()` (Rust `std::fs::File` has no
//!   fallible close); Go surfaces file-close errors.
//! - `stdout` output writes through `std::io::stdout()`; the Go
//!   test swaps the process stdout, which Rust cannot do
//!   hermetically — the ported test asserts construction +
//!   emission without panic, not the captured bytes.

use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use castctl_config::gopath::go_clean;
use castctl_log_redact::safe_string;

/// sing-box levels, inverted numbering (`level.go:9-17`):
/// `Panic = 0` … `Trace = 6`. A line is emitted iff its level
/// is numerically `<=` the configured level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Level(pub u8);

impl Level {
    pub const PANIC: Level = Level(0);
    pub const FATAL: Level = Level(1);
    pub const ERROR: Level = Level(2);
    pub const WARN: Level = Level(3);
    pub const INFO: Level = Level(4);
    pub const DEBUG: Level = Level(5);
    pub const TRACE: Level = Level(6);

    /// Lowercase name, as sing-box `FormatLevel` (`level.go:19-36`).
    pub fn name(self) -> &'static str {
        match self.0 {
            0 => "panic",
            1 => "fatal",
            2 => "error",
            3 => "warn",
            4 => "info",
            5 => "debug",
            6 => "trace",
            _ => "unknown",
        }
    }

    /// Uppercase label used in the line prefix.
    pub fn label(self) -> &'static str {
        match self.0 {
            0 => "PANIC",
            1 => "FATAL",
            2 => "ERROR",
            3 => "WARN",
            4 => "INFO",
            5 => "DEBUG",
            6 => "TRACE",
            _ => "UNKNOWN",
        }
    }

    /// ANSI colour code for the console label
    /// (`format.go:23-37` via aurora: White 37, Cyan 36,
    /// Yellow 33, Red 31).
    fn color_code(self) -> u8 {
        match self.0 {
            5 | 6 => 37,
            4 => 36,
            3 => 33,
            0..=2 => 31,
            _ => 37,
        }
    }
}

impl fmt::Display for Level {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Parse a level spelling, sing-box `ParseLevel`
/// (`level.go:40-58`): `trace/debug/info/warn/warning/error/
/// fatal/panic`, case-sensitive. The error never echoes the
/// supplied value (Go's error embeds it verbatim; a pasted
/// secret must never surface through it).
pub fn parse_level(s: &str) -> Result<Level, LogError> {
    match s {
        "trace" => Ok(Level::TRACE),
        "debug" => Ok(Level::DEBUG),
        "info" => Ok(Level::INFO),
        "warn" | "warning" => Ok(Level::WARN),
        "error" => Ok(Level::ERROR),
        "fatal" => Ok(Level::FATAL),
        "panic" => Ok(Level::PANIC),
        _ => Err(LogError::UnknownLevel),
    }
}

/// Errors from the factory and the log-file guard. Display text
/// is fixed except for `OpenFailed`, which carries the OS error
/// (Rust renders it as `No such file or directory (os error 2)`,
/// Go as a `*PathError` — same kind, different text; see
/// PORTING.md §M7a).
#[derive(Debug)]
pub enum LogError {
    /// Fixed message; never echoes the supplied level.
    UnknownLevel,
    /// The output path cannot be resolved at all (symlink cycle).
    CannotResolve,
    /// Symlink depth cap (40) exceeded while resolving.
    TooManySymlinks,
    /// The output file is a refused (protected) file.
    Refused,
    /// `OpenOptions::open` / metadata failure.
    OpenFailed(io::Error),
    /// `ResolveLogSettings` config error (exit 2).
    Config(castctl_config::errors::ConfigError),
}

impl fmt::Display for LogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LogError::UnknownLevel => f.write_str(
                "logging: unknown log level (expected trace, debug, info, warn, warning, error, fatal, or panic)",
            ),
            LogError::CannotResolve => {
                f.write_str("logging: cannot resolve log output path")
            }
            LogError::TooManySymlinks => {
                f.write_str("logging: too many symlinks resolving log path")
            }
            LogError::Refused => f.write_str(
                "logging: refusing to open a protected file as the log output",
            ),
            LogError::OpenFailed(e) => write!(f, "{e}"),
            LogError::Config(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for LogError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            LogError::OpenFailed(e) => Some(e),
            LogError::Config(e) => Some(e),
            _ => None,
        }
    }
}

impl From<castctl_config::errors::ConfigError> for LogError {
    fn from(e: castctl_config::errors::ConfigError) -> Self {
        LogError::Config(e)
    }
}

/// The resolved log configuration for one invocation: the
/// output of `resolve_log_settings`, translated into this
/// package's own type so logging never imports the config
/// parser. Mirrors Go `Settings` (`factory.go:14-34`).
#[derive(Debug, Clone, Default)]
pub struct Settings {
    pub disabled: bool,
    pub level: String,
    pub output: String,
    pub timestamp: bool,
    /// Absolute paths the factory must never open as a log file
    /// (the config file and cookies files, supplied by the
    /// runtime); see `open_log_file`.
    pub refused: Vec<String>,
}

/// The sing-box timestamp layout, a literal upstream
/// (`factory.go:36-38`, `log/log.go:51`).
const SING_BOX_TIMESTAMP_FORMAT: &str = "%z %Y-%m-%d %H:%M:%S";

struct FactoryInner {
    level: Level,
    disabled: bool,
    /// The sink, redacted per chunk (`safeWriter`) and
    /// serialised (`lockedWriter`); `None` once closed.
    writer: Mutex<Option<Box<dyn Write + Send>>>,
    base_time: Instant,
    disable_colors: bool,
    disable_timestamp: bool,
    full_timestamp: bool,
}

/// `Handle` owns one log factory and, for file output, the log
/// file handle (held inside the writer; taking it out on
/// `close` closes the file). Close is idempotent.
#[derive(Clone)]
pub struct Handle {
    inner: Arc<FactoryInner>,
}

impl Handle {
    /// The factory's configured level.
    pub fn level(&self) -> Level {
        self.inner.level
    }

    /// A tagged logger from the factory.
    pub fn logger(&self, tag: &str) -> Logger {
        Logger {
            inner: Arc::clone(&self.inner),
            tag: tag.to_string(),
        }
    }

    /// A `*slog.Logger`-equivalent writing through the factory
    /// at the factory's level; see `slog.rs`.
    pub fn slog_logger(&self, tag: &str) -> crate::SlogLogger {
        crate::SlogLogger::new(self, tag)
    }

    /// Close the factory and, for file output, the log file.
    /// Idempotent: a second call is a no-op.
    pub fn close(&self) {
        let mut w = self.inner.writer.lock().unwrap_or_else(|e| e.into_inner());
        *w = None;
    }
}

/// A tagged logger. Methods mirror sing-box's `ContextLogger`
/// minus the context (castctl passes `Background`, which
/// carries no ID, so there is no ID prefix to render).
#[derive(Clone)]
pub struct Logger {
    inner: Arc<FactoryInner>,
    tag: String,
}

impl Logger {
    pub fn trace(&self, msg: &str) {
        self.log(Level::TRACE, msg);
    }
    pub fn debug(&self, msg: &str) {
        self.log(Level::DEBUG, msg);
    }
    pub fn info(&self, msg: &str) {
        self.log(Level::INFO, msg);
    }
    pub fn warn(&self, msg: &str) {
        self.log(Level::WARN, msg);
    }
    pub fn error(&self, msg: &str) {
        self.log(Level::ERROR, msg);
    }
    /// Writes the line, then exits the process with code 1
    /// (sing-box `Fatal` semantics). For a disabled factory
    /// this is a no-op: sing-box's NOP logger `Fatal` is empty
    /// (`log/nop.go`), it does not exit.
    pub fn fatal(&self, msg: &str) {
        if self.inner.disabled {
            return;
        }
        self.log(Level::FATAL, msg);
        std::process::exit(1);
    }
    /// Writes the line, then panics with the formatted line
    /// (sing-box `Panic` semantics). For a disabled factory
    /// this is a no-op: sing-box's NOP logger `Panic` is empty
    /// (`log/nop.go`), it does not panic.
    pub fn panic(&self, msg: &str) {
        if self.inner.disabled {
            return;
        }
        let line = self.format_line(Level::PANIC, &safe_string(msg));
        self.write_raw(&line);
        panic!("{}", line.trim_end_matches('\n'));
    }

    pub fn log(&self, level: Level, msg: &str) {
        if self.inner.disabled || level > self.inner.level {
            return;
        }
        let line = self.format_line(level, &safe_string(msg));
        self.write_raw(&line);
    }

    /// Format one line, sing-box `Formatter::Format`
    /// (`format.go:48-72` + `writePrefix` `:96-125`): prefix,
    /// then `tag: ` when the tag is non-empty, then the message
    /// plus a trailing newline when missing. No ID prefix:
    /// castctl never sets a log ID.
    fn format_line(&self, level: Level, msg: &str) -> String {
        let mut out = String::new();
        let level_str = if self.inner.disable_colors {
            level.label().to_string()
        } else {
            format!("\x1b[{}m{}\x1b[0m", level.color_code(), level.label())
        };
        if self.inner.disable_timestamp {
            out.push_str(&level_str);
            out.push(' ');
        } else if self.inner.full_timestamp {
            out.push_str(
                &chrono::Local::now()
                    .format(SING_BOX_TIMESTAMP_FORMAT)
                    .to_string(),
            );
            out.push(' ');
            out.push_str(&level_str);
            out.push(' ');
        } else {
            let secs = self.inner.base_time.elapsed().as_secs();
            out.push_str(&level_str);
            out.push_str(&format!("[{secs:04}] "));
        }
        if !self.tag.is_empty() {
            out.push_str(&self.tag);
            out.push_str(": ");
        }
        out.push_str(msg);
        if !msg.ends_with('\n') {
            out.push('\n');
        }
        out
    }

    /// Write one formatted line through the redaction sink
    /// (`safeWriter`): every chunk passes `SafeString` before
    /// reaching the underlying writer, so no line — castctl's
    /// or sing-box's — can carry a labelled secret to the log
    /// destination. The mutex (`lockedWriter`) keeps lines
    /// whole under concurrent emission.
    fn write_raw(&self, line: &str) {
        let redacted = safe_string(line);
        let mut w = self.inner.writer.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(w) = w.as_mut() {
            let _ = w.write_all(redacted.as_bytes());
            let _ = w.flush();
        }
    }
}

/// `Emit` logs one pre-composed castctl event line at `level`
/// through `logger`, after the `SafeString` boundary
/// (`factory.go:434-455`). Callers compose only safe fields;
/// a caller composing error text into a line at ANY level
/// including trace must use `summarize_err` for the error.
pub fn emit(logger: &Logger, level: Level, msg: &str) {
    logger.log(level, msg);
}

/// A free function alias matching Go's `Emit` call shape for
/// callers that pass the logger by reference.
pub type EmitFn = fn(&Logger, Level, &str);

/// Build the single log factory for one invocation from
/// resolved settings (`factory.go:91-196`).
///
/// Disabled mirrors sing-box (`log/log.go:25-27`): the NOP
/// factory is returned before any level parsing or file
/// creation, so a disabled factory with a bogus level still
/// constructs and emits nothing. A bad file path (missing
/// parent) is a fail-closed error: no fallback to stderr.
pub fn new_factory(
    settings: Settings,
    stderr: Option<Box<dyn Write + Send>>,
) -> Result<Handle, LogError> {
    if settings.disabled {
        return Ok(Handle {
            inner: Arc::new(FactoryInner {
                level: Level::TRACE,
                disabled: true,
                writer: Mutex::new(Some(Box::new(io::sink()))),
                base_time: Instant::now(),
                disable_colors: true,
                disable_timestamp: true,
                full_timestamp: false,
            }),
        });
    }
    let level_name = if settings.level.is_empty() {
        "trace"
    } else {
        settings.level.as_str()
    };
    let level = parse_level(level_name)?;
    let (writer, is_file): (Box<dyn Write + Send>, bool) = match settings.output.as_str() {
        "" | "stderr" => (
            stderr.unwrap_or_else(|| Box::new(io::stderr()) as Box<dyn Write + Send>),
            false,
        ),
        "stdout" => (Box::new(io::stdout()), false),
        path => {
            let f = open_log_file(path, &settings.refused)?;
            (Box::new(f), true)
        }
    };
    Ok(Handle {
        inner: Arc::new(FactoryInner {
            level,
            disabled: false,
            writer: Mutex::new(Some(writer)),
            base_time: Instant::now(),
            // Formatter flags replicate `log.New`'s exactly
            // (`log/log.go:46-52`): DisableColors for files,
            // DisableTimestamp only for files when timestamp is
            // false, FullTimestamp from the setting.
            disable_colors: is_file,
            disable_timestamp: !settings.timestamp && is_file,
            full_timestamp: settings.timestamp,
        }),
    })
}

/// One path's identity for the A7 guard: its symlink-resolved
/// location plus, when the file exists, its device/inode.
#[derive(Debug, Clone)]
struct FileIdentity {
    resolved: String,
    dev: Option<u64>,
    ino: Option<u64>,
}

fn collect_file_identity(path: &str) -> Option<FileIdentity> {
    let resolved = resolve_log_path(path).ok()?;
    let mut id = FileIdentity {
        resolved,
        dev: None,
        ino: None,
    };
    if let Ok(md) = std::fs::metadata(&id.resolved) {
        id.dev = Some(md.dev());
        id.ino = Some(md.ino());
    }
    Some(id)
}

fn collect_refused_identities(refused: &[String]) -> Vec<FileIdentity> {
    let mut out = Vec::new();
    for r in refused {
        if r.is_empty() {
            continue;
        }
        if let Some(id) = collect_file_identity(r) {
            out.push(id);
        }
    }
    out
}

fn identities_equal(a: &FileIdentity, b: &FileIdentity) -> bool {
    if !a.resolved.is_empty() && a.resolved == b.resolved {
        return true;
    }
    matches!((a.dev, a.ino, b.dev, b.ino), (Some(d1), Some(i1), Some(d2), Some(i2)) if d1 == d2 && i1 == i2)
}

/// Open `path` for append/create/write-only with mode 0600 on
/// creation. Never truncates, never creates parent
/// directories. A pre-existing file is appended to WITHOUT any
/// chmod. The ONLY guard is the minimal A7 check: refuse,
/// before opening, when the output file's IDENTITY equals a
/// refused file's identity (resolved path AND dev/ino: a
/// hardlink shares its inode while its path differs, and a
/// symlink to a not-yet-existing refused target resolves
/// through its parent directory to the refused location).
/// After opening, the identity is RE-CHECKED against freshly
/// collected refused identities via fstat, and the open is
/// refused (file closed, no line written) if the opened file
/// is a refused file. There are NO other path restrictions:
/// symlinks to other targets and non-regular files are NOT
/// refused.
pub fn open_log_file(path: &str, refused: &[String]) -> Result<File, LogError> {
    let out_id = collect_file_identity(path).ok_or(LogError::CannotResolve)?;
    let refused_ids = collect_refused_identities(refused);
    for id in &refused_ids {
        if identities_equal(&out_id, id) {
            return Err(LogError::Refused);
        }
    }
    let f = OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .open(path)
        .map_err(LogError::OpenFailed)?;
    // Re-check after open: a swap between the check above and
    // the open that redirected the path at a refused file is
    // caught here, before any line is written.
    match f.metadata() {
        Ok(md) => {
            let fresh_refused = collect_refused_identities(refused);
            let out_id2 = collect_file_identity(path);
            for id in &fresh_refused {
                let same_file = matches!((id.dev, id.ino), (Some(d), Some(i)) if d == md.dev() && i == md.ino());
                if same_file {
                    return Err(LogError::Refused);
                }
                if let Some(o2) = &out_id2 {
                    if identities_equal(o2, id) {
                        return Err(LogError::Refused);
                    }
                }
            }
        }
        Err(e) => return Err(LogError::OpenFailed(e)),
    }
    Ok(f)
}

/// Canonical form of `path` for identity comparison: symlinks
/// are resolved component by component, including a final
/// symlink whose target does not exist yet — the longest
/// existing prefix is resolved and the remainder appended, so
/// a symlink to an absent target resolves to the target's
/// location instead of to the link's own path. A symlink cycle
/// is an error (fail closed).
fn resolve_log_path(path: &str) -> Result<String, LogError> {
    let abs = std::path::absolute(path).map_err(|_| LogError::CannotResolve)?;
    resolve_identity(&abs, 0).map(|p| p.to_string_lossy().into_owned())
}

fn resolve_identity(cur: &Path, depth: u32) -> Result<PathBuf, LogError> {
    if depth > 40 {
        return Err(LogError::TooManySymlinks);
    }
    match std::fs::symlink_metadata(cur) {
        Err(_) => {
            // Absent: resolve the parent, then append the base
            // name. The parent chain terminates at the root,
            // which always exists.
            let parent = match cur.parent() {
                Some(p) if p != cur => p,
                _ => return Ok(cur.to_path_buf()),
            };
            let resolved_parent = resolve_identity(parent, depth + 1)?;
            match cur.file_name() {
                Some(base) => Ok(resolved_parent.join(base)),
                None => Ok(resolved_parent),
            }
        }
        Ok(md) => {
            if md.file_type().is_symlink() {
                let target = std::fs::read_link(cur).unwrap_or_else(|_| cur.to_path_buf());
                let target = if target.is_absolute() {
                    target
                } else {
                    match cur.parent() {
                        Some(p) => p.join(target),
                        None => target,
                    }
                };
                let cleaned = go_clean(&target.to_string_lossy());
                resolve_identity(Path::new(&cleaned), depth + 1)
            } else {
                // Exists and is not itself a symlink: canonicalise
                // resolves any symlinked ancestors.
                match std::fs::canonicalize(cur) {
                    Ok(p) => Ok(p),
                    Err(_) => Ok(cur.to_path_buf()),
                }
            }
        }
    }
}
