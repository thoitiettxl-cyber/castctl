// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Subprocess plugin worker (Option A) + framed protocol
//! v2.
//!
//! The plugin never loads into the host process. One
//! worker process per loaded plugin (same binary
//! re-executed under the hidden `__plugin-worker`
//! subcommand, or the dedicated `castctl-plugin-worker`
//! binary) dlopens the `.so` with the `ffi` module and
//! speaks a framed protocol to the parent over a Unix
//! socketpair. The socketpair end is passed to the child
//! as stdin AND stdout (safe std only: `OwnedFd` ->
//! `Stdio`; no fd-number passing, no `unsafe` anywhere
//! in this module — the one exception is the
//! `PR_SET_PDEATHSIG` registration, which lives behind
//! the safe wrapper `ffi::set_parent_death_signal`
//! (fix loop 1, B7); the `unsafe` for it is confined
//! to `ffi`, never here). The worker's stderr is piped
//! to the parent and capped (last 4 KiB) into the crash
//! error.
//!
//! Protocol v2: frames are a 4-byte big-endian length
//! prefix + JSON bytes, capped at 16 MiB per frame
//! (M5a precedent). Version byte/field from day one:
//! every frame carries `"v": 2` and anything else is
//! refused.
//!
//! Parent -> worker ops: `open` (dlopen + init + ABI
//! checks in the worker), `call` (one envelope call),
//! `shutdown` (plugin shutdown, then exit 0).
//! Worker -> parent: replies (`ok` / error envelope),
//! plus reverse `host_call` frames while a call is
//! outstanding. DEADLOCK RULE: the parent must answer
//! `host_call` frames while a `call` is outstanding —
//! the parent's transact loop multiplexes, it never
//! blocks on the call reply alone. A parent that did
//! `write(call); read(reply)` would deadlock the first
//! time a plugin calls `host.log`.
//!
//! Deadline rule (fix loop 1, B1; narrowed fix loop
//! 2, technical N2): the per-transaction deadline is
//! enforced INSIDE every frame read *during a
//! transact* (parent) and every `host_call`
//! round-trip read (worker). `read_frame_deadline`
//! `poll`s with the recomputed remaining time before
//! every chunk read, so a peer trickling one byte at
//! a time cannot stretch a frame past the deadline.
//! The worker main loop's idle wait still uses the
//! plain deadline-less `read_frame` (safety R2-N6):
//! that read is the wait for the next parent frame,
//! and only the trusted host writes parent frames —
//! a dead parent there is covered by B7
//! (`PR_SET_PDEATHSIG`), so no deadline is needed.
//! A reply is accepted only
//! when its op is exactly `"reply"` and its id matches
//! the outstanding request (B2): any other op (other
//! than `host_call`) is a protocol violation, and a
//! forged frame can never stand in for the real reply.
//! Call ids start at a random 64-bit value (B2), not
//! at 1, so an outstanding id is not guessable.
//!
//! `host_call` budget (fix loop 1, B6): at most 1000
//! `host_call` frames and 4 MiB of dispatched callback
//! request bytes per transaction; past that the worker
//! is killed and the client fused with a
//! `"host callback flood"` error. Deliberate policy
//! (fix loop 2, safety R2-N5): each `host.log` message
//! is capped at 4096 bytes, so the effective bound is
//! ~1000 log lines per call — far past any legitimate
//! plugin (`host.log` is a log line, not a data
//! channel), and the byte bound covers the case where
//! each call carries a full 4 KiB message. A
//! verbose-but-legitimate plugin emitting more than
//! that in one `provider.call` is killed and fused;
//! that is the intended trade, not a bug. The
//! `plugin check` log sink is capped independently
//! (see `run.rs`).
//!
//! Mixed readers (fix loop 2, red-team N9 — audited,
//! safe by construction, fragile by design): the
//! worker main loop reads parent frames through the
//! buffered `StdinLock` while the `host_call`
//! dispatcher reads replies with raw-fd reads on fd
//! 0. No bytes are lost today because (a) `WORKER_IO`
//! serialises the two readers — they never read
//! concurrently, (b) the parent never pipelines: one
//! outstanding frame, so the `StdinLock`'s read-ahead
//! can only hold bytes of the frame the main loop is
//! itself consuming, and (c) the dispatcher reads
//! only while the main loop is blocked in plugin code
//! (not reading). Any future pipelining must give the
//! two readers one shared read path first.
//!
//! Parent death (fix loop 1, B7): the worker is
//! spawned with `PR_SET_PDEATHSIG` (SIGKILL), so it
//! dies with the parent even mid-call; the classic
//! fork/prctl race is closed by checking `getppid()`
//! right after the `prctl` in the child.
//!
//! Stdout hazard (fix loop 1, tech N12): the worker's
//! stdout IS the protocol socket, and the plugin
//! shares the worker process — a plugin that writes to
//! stdout injects bytes into the frame stream, which
//! the parent reads as a protocol violation and
//! reports as a worker crash. A plugin must not write
//! to stdout; there is no structural fix without
//! fd-passing (`pre_exec`), which this design does
//! not do (see PORTING §M6c-b).
//!
//! Crash detection (all three handled): EOF / read
//! error on the socket; `Child::wait()` returning an
//! `ExitStatus` whose `signal()` is `Some(n)`; a call
//! timeout expiring -> SIGKILL + reap. Crashes map to
//! `PluginCrashed` (signal in the error); timeout /
//! flood / protocol kills map to `ClientDead` (fix
//! loop 2, NB1) — both fuse the client at the `Host`
//! level, so a second call returns the same error,
//! never a silent reload.
//!
//! What this buys and does NOT buy (recorded in PORTING
//! §M6c-b): survival of segfault/SIGBUS/abort/stack
//! overflow in plugin code and plugin threads, in
//! `dlopen` init constructors, and in the Go runtime
//! inside the `.so`; containment of heap corruption to
//! the worker; a clean kill/timeout story for hung
//! plugins. It does NOT buy sandboxing — a malicious
//! worker can still dial out or read files it was given
//! (the trusted-plugin model from `docs/plugins.md` is
//! unchanged; this is crash isolation, not a security
//! boundary). A host callback from a plugin background
//! goroutine outside any outstanding call is delivered
//! late (on the next call's read loop); dropped if the
//! host closes first (fix loop 1: the old "not lost"
//! wording was wrong — no further call means no
//! delivery).

use std::ffi::OsString;
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::io::OwnedFd;
#[cfg(unix)]
use std::os::unix::net::UnixStream;
#[cfg(unix)]
use std::os::unix::process::ExitStatusExt;
#[cfg(unix)]
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::process::{Child, ChildStderr, Command, Stdio};
#[cfg(unix)]
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
#[cfg(unix)]
use std::time::Instant;

use base64::{Engine as _, engine::general_purpose::STANDARD as B64};

use crate::error::PluginHostError;
use crate::host::HostCallbackDispatcher;
use crate::host::{Client, ClientError};
use crate::text::{safe_plugin_text, strip_control_chars};

/// Protocol version. Every frame carries it; anything
/// else is refused.
pub const PROTOCOL_VERSION: u32 = 2;

/// Maximum frame size (16 MiB, M5a precedent). A larger
/// length prefix is a protocol violation, never a
/// bigger allocation.
pub const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;

/// Per-call deadline (load and call). A hung plugin is
/// SIGKILLed and reported as a timeout, never left
/// hanging the host.
pub const CALL_TIMEOUT: Duration = Duration::from_secs(30);

/// Shutdown deadline: the worker must answer (or die)
/// within this long, then it is killed and reaped.
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

/// `host_call` budget per transaction (fix loop 1,
/// B6): a plugin flooding `host.log` (or any reverse
/// callback) past either bound is killed and fused
/// with a `"host callback flood"` error, so an
/// accumulating log sink can never OOM the parent.
const MAX_HOST_CALLS_PER_TRANSACT: usize = 1000;
/// Total dispatched `host_call` request bytes per
/// transaction (decoded, not base64).
const MAX_HOST_CALL_BYTES_PER_TRANSACT: usize = 4 * 1024 * 1024;

/// Worker stderr tail kept for the crash error.
const STDERR_TAIL_CAP: usize = 4096;

/// One protocol frame. JSON; `request`/`response` are
/// base64 (raw JSON bytes would not survive JSON
/// framing). `ok`/`error` are present on replies only.
#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
struct Frame {
    /// Protocol version (always 2).
    v: u32,
    /// Request id (parent and worker id spaces are
    /// independent; a reply carries its request's id).
    id: u64,
    /// `open` / `call` / `shutdown` /
    /// `host_call` / `host_call_reply`.
    op: String,
    /// Shadow path to dlopen (`open` only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    path: Option<String>,
    /// Operator-supplied source path, for error strings
    /// (`open` only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    display_path: Option<String>,
    /// Envelope method (`call` / `host_call` only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    method: Option<String>,
    /// Request bytes, base64 (`call` / `host_call`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    request: Option<String>,
    /// Response bytes, base64 (replies only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    response: Option<String>,
    /// Reply success (replies only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ok: Option<bool>,
    /// Reply failure detail (replies only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    error: Option<FrameError>,
}

/// A reply failure: stable code + human message (the
/// message carries the Go-exact loader string).
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct FrameError {
    /// Stable code (`dlopen`, `missing_symbol`,
    /// `init_failed`, `abi_mismatch`,
    /// `incomplete_table`, `oversize_response`,
    /// `call_failed`, `failed`, ...).
    code: String,
    /// Human message (Go-exact where Go defines one).
    message: String,
}

impl Frame {
    fn ok(id: u64) -> Frame {
        Frame {
            v: PROTOCOL_VERSION,
            id,
            op: "reply".to_string(),
            ok: Some(true),
            ..Default::default()
        }
    }

    fn response(id: u64, bytes: Vec<u8>) -> Frame {
        Frame {
            v: PROTOCOL_VERSION,
            id,
            op: "reply".to_string(),
            response: Some(B64.encode(bytes)),
            ok: Some(true),
            ..Default::default()
        }
    }

    fn err(id: u64, code: &str, message: &str) -> Frame {
        Frame {
            v: PROTOCOL_VERSION,
            id,
            op: "reply".to_string(),
            ok: Some(false),
            error: Some(FrameError {
                code: code.to_string(),
                message: message.to_string(),
            }),
            ..Default::default()
        }
    }
}

/// Serialise one frame (length prefix + JSON).
fn frame_bytes(frame: &Frame) -> std::io::Result<Vec<u8>> {
    let bytes = serde_json::to_vec(frame)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let mut out = Vec::with_capacity(bytes.len() + 4);
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(&bytes);
    Ok(out)
}

/// Whether a serialised frame fits the cap (length
/// prefix excluded from the comparison: the cap is on
/// the JSON bytes, matching `write_frame`).
fn frame_fits(frame: &Frame) -> bool {
    frame_bytes(frame).is_ok_and(|b| b.len() - 4 <= MAX_FRAME_BYTES)
}

/// Write one length-prefixed frame + flush. A frame
/// over the cap is refused, never written.
fn write_frame(w: &mut impl Write, frame: &Frame) -> std::io::Result<()> {
    let bytes = frame_bytes(frame)?;
    if bytes.len() - 4 > MAX_FRAME_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "plugin worker frame too large",
        ));
    }
    w.write_all(&bytes)?;
    w.flush()
}

/// Write one frame on the parent side with a
/// deadline (fix loop 2, red-team N2 + technical
/// N10): serialises ONCE (the old `frame_fits` +
/// `write_frame` pair serialised the frame twice —
/// ~25 MiB of serialisation for a 12.5 MiB request),
/// refuses an over-cap frame with `InvalidInput`
/// before writing anything, then `poll`s for
/// writability with the remaining time before every
/// chunk write and fails `WouldBlock` at the
/// deadline. NOTE (round-3 red-team R3-N1): the
/// deadline bounds the polls, NOT a single blocking
/// `write()` — `poll_writable` returning true means
/// *some* space is free, but the socket is blocking,
/// so one up-to-8 KiB `write()` can run past the
/// deadline when the peer stops draining mid-write.
/// Every such hang is still bounded by the 30s call
/// timeout. Making the deadline hard is a one-line
/// follow-up (`set_nonblocking(true)` on the parent
/// socket + handling `WouldBlock` in the write loop),
/// recorded in PORTING §M6c-b. The worker side keeps
/// plain `write_frame`: the worker writes only while
/// the parent is in a transact read loop draining the
/// socket, and a dead parent kills the worker via
/// `PR_SET_PDEATHSIG` (or surfaces as EPIPE, never a
/// block).
#[cfg(unix)]
fn write_frame_deadline(
    sock: &mut UnixStream,
    frame: &Frame,
    deadline: Instant,
) -> std::io::Result<()> {
    use std::os::unix::io::AsRawFd;
    let bytes = frame_bytes(frame)?;
    if bytes.len() - 4 > MAX_FRAME_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "plugin worker frame too large",
        ));
    }
    let fd = sock.as_raw_fd();
    let mut rest = &bytes[..];
    while !rest.is_empty() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "plugin worker write timed out",
            ));
        }
        if !crate::ffi::poll_writable(fd, remaining)? {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "plugin worker write timed out",
            ));
        }
        match sock.write(&rest[..rest.len().min(8192)]) {
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "plugin worker write returned zero",
                ));
            }
            Ok(n) => rest = &rest[n..],
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(e),
        }
    }
    sock.flush()
}

/// Decode one frame's JSON bytes (length prefix
/// already stripped): version check included.
fn decode_frame(buf: &[u8]) -> std::io::Result<Frame> {
    let frame: Frame = serde_json::from_slice(buf)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    if frame.v != PROTOCOL_VERSION {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "unsupported plugin worker protocol version",
        ));
    }
    Ok(frame)
}

/// Read one length-prefixed frame. EOF mid-frame is
/// `UnexpectedEof` (the worker died); a bad version or
/// an over-cap length is `InvalidData`.
fn read_frame(r: &mut impl Read) -> std::io::Result<Frame> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "plugin worker frame too large",
        ));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    decode_frame(&buf)
}

/// One chunked read with a deadline, for the parent
/// side (fix loop 1, B1): `SO_RCVTIMEO` applies per
/// `recv`, and `read_exact` loops over many `read`s,
/// so a single per-read timeout cannot bound a
/// trickling peer. This loop `poll`s the socket with
/// the recomputed remaining time before every `read`
/// and fails with `WouldBlock` the moment the deadline
/// passes — including mid-frame, mid-length-prefix.
/// The socket stays blocking (`UnixStream` has no
/// user-space read buffer, so a `poll`-readable fd
/// always yields at least one byte); the deadline is
/// enforced by `poll`, never by `set_read_timeout`
/// (safety N4: no discarded `set_read_timeout`
/// result anywhere on this path).
#[cfg(unix)]
fn read_exact_deadline(
    sock: &mut UnixStream,
    mut buf: &mut [u8],
    deadline: Instant,
) -> std::io::Result<()> {
    use std::os::unix::io::AsRawFd;
    let fd = sock.as_raw_fd();
    while !buf.is_empty() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "plugin worker read timed out",
            ));
        }
        if !crate::ffi::poll_readable(fd, remaining)? {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "plugin worker read timed out",
            ));
        }
        let chunk_len = buf.len().min(8192);
        match sock.read(&mut buf[..chunk_len]) {
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "plugin worker closed the connection",
                ));
            }
            Ok(n) => {
                buf = &mut buf[n..];
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Read one frame on the parent side with a hard
/// deadline (fix loop 1, B1). Same framing as
/// `read_frame`, but the deadline is enforced inside
/// the read: a peer sending one byte every 29s is
/// killed at the deadline, not after ~16M × 30s.
#[cfg(unix)]
fn read_frame_deadline(sock: &mut UnixStream, deadline: Instant) -> std::io::Result<Frame> {
    let mut len_buf = [0u8; 4];
    read_exact_deadline(sock, &mut len_buf, deadline)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "plugin worker frame too large",
        ));
    }
    let mut buf = vec![0u8; len];
    read_exact_deadline(sock, &mut buf, deadline)?;
    decode_frame(&buf)
}

/// Read one frame on the worker side (fd 0, the
/// socketpair child end) with a deadline, for the
/// `host_call` round-trip (fix loop 1, red N6): the
/// worker's dispatcher must not block forever waiting
/// for a `host_call_reply`. Raw-fd reads (not the
/// `StdinLock`, whose buffer would defeat `poll`)
/// through the `ffi` wrappers; `WORKER_IO` serialises
/// this against the main loop's reads, so the two
/// readers never compete for the same bytes.
#[cfg(unix)]
fn read_frame_fd_deadline(fd: i32, deadline: Instant) -> std::io::Result<Frame> {
    let mut len_buf = [0u8; 4];
    read_exact_fd_deadline(fd, &mut len_buf, deadline)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "plugin worker frame too large",
        ));
    }
    let mut buf = vec![0u8; len];
    read_exact_fd_deadline(fd, &mut buf, deadline)?;
    decode_frame(&buf)
}

#[cfg(unix)]
fn read_exact_fd_deadline(fd: i32, mut buf: &mut [u8], deadline: Instant) -> std::io::Result<()> {
    while !buf.is_empty() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "plugin worker read timed out",
            ));
        }
        if !crate::ffi::poll_readable(fd, remaining)? {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "plugin worker read timed out",
            ));
        }
        let chunk_len = buf.len().min(8192);
        match crate::ffi::read_fd(fd, &mut buf[..chunk_len]) {
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "plugin worker closed the connection",
                ));
            }
            Ok(n) => {
                buf = &mut buf[n..];
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Stable error code for a loader/call failure, from
/// the Go-exact message text. The code is diagnostic
/// only; the message carries the truth.
fn error_code(err: &PluginHostError) -> &'static str {
    let m = err.to_string();
    if m.starts_with("dlopen ") {
        "dlopen"
    } else if m.starts_with("missing castctl_plugin_init") {
        "missing_symbol"
    } else if m.starts_with("castctl_plugin_init returned") {
        "init_failed"
    } else if m.starts_with("plugin ABI version") {
        "abi_mismatch"
    } else if m.starts_with("plugin function table is incomplete") {
        "incomplete_table"
    } else if m.contains("oversize response") {
        "oversize_response"
    } else if m.starts_with("plugin call ") {
        "call_failed"
    } else {
        "failed"
    }
}

// ---------------------------------------------------------------------
// Worker side
// ---------------------------------------------------------------------

/// Serialises all stdio frame traffic inside the
/// worker: the main loop and the host callback (which
/// may run on a plugin thread) share one stdin/stdout
/// pair, so a whole frame transaction (write + read for
/// the callback, read or write for the main loop) is
/// atomic. The main loop never holds it while executing
/// plugin code, so the callback can always take it.
#[cfg(unix)]
static WORKER_IO: Mutex<()> = Mutex::new(());

/// Ids for worker-initiated `host_call` frames.
#[cfg(unix)]
static HOST_CALL_ID: AtomicU64 = AtomicU64::new(1);

/// The worker's host-callback dispatcher: a synchronous
/// round-trip over the same socket (stdin for the reply,
/// stdout for the frame). `None` = delivery failed.
/// The round-trip has the same 30s deadline as a parent
/// transact (fix loop 1, red N6): `read_frame_fd_deadline`
/// aborts the wait at the deadline instead of blocking
/// forever on a parent that never answers.
#[cfg(unix)]
fn worker_host_dispatcher() -> HostCallbackDispatcher {
    Arc::new(|method: &str, request: &[u8]| -> Option<Vec<u8>> {
        let _guard = WORKER_IO.lock().unwrap_or_else(|e| e.into_inner());
        let id = HOST_CALL_ID.fetch_add(1, Ordering::SeqCst);
        let frame = Frame {
            v: PROTOCOL_VERSION,
            id,
            op: "host_call".to_string(),
            method: Some(method.to_string()),
            request: Some(B64.encode(request)),
            ..Default::default()
        };
        let mut out = std::io::stdout().lock();
        let input = std::io::stdin().lock();
        write_frame(&mut out, &frame).ok()?;
        drop(input);
        drop(out);
        // Raw-fd read, not the `StdinLock` (whose
        // buffer would defeat `poll`): `WORKER_IO`
        // serialises this against the main loop's
        // reads, so the two readers never compete.
        let deadline = Instant::now() + CALL_TIMEOUT;
        let reply = read_frame_fd_deadline(libc::STDIN_FILENO, deadline).ok()?;
        if reply.op != "host_call_reply" || reply.id != id || reply.ok != Some(true) {
            return None;
        }
        B64.decode(reply.response?).ok()
    })
}

/// Write one reply frame to the parent. An error (dead
/// parent, oversize frame) is returned so the caller
/// can exit the loop instead of waiting for a frame
/// that will never come (fix loop 1, safety N3).
#[cfg(unix)]
fn write_reply(frame: &Frame) -> std::io::Result<()> {
    let _guard = WORKER_IO.lock().unwrap_or_else(|e| e.into_inner());
    let mut out = std::io::stdout().lock();
    write_frame(&mut out, frame)
}

/// Whether the handshake token has the required shape
/// (32 hex chars). It is an accident-guard, not
/// authentication: it stops `castctl __plugin-worker`
/// from doing anything when typed by hand, and the
/// framed protocol is the real gate.
fn valid_token(token: &str) -> bool {
    token.len() == 32 && token.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Worker-mode entry. `args` is argv after the program
/// name: `["__plugin-worker", token]` for the castctl
/// binary, `[token]` for the dedicated worker binary.
/// Returns the process exit code.
pub fn run_worker(args: &[OsString]) -> i32 {
    let mut rest = args;
    if rest
        .first()
        .is_some_and(|a| a.to_string_lossy() == "__plugin-worker")
    {
        rest = &rest[1..];
    }
    if rest.len() != 1 {
        eprintln!("castctl: __plugin-worker takes exactly one handshake token");
        return 2;
    }
    let token = rest[0].to_string_lossy();
    if !valid_token(&token) {
        eprintln!("castctl: __plugin-worker handshake token is not 32 hex characters");
        return 2;
    }
    worker_main()
}

#[cfg(unix)]
fn worker_main() -> i32 {
    // Worker-initiated `host_call` ids start at a
    // random 64-bit value (fix loop 1, B2), like the
    // parent's ids: not guessable, not sequential.
    HOST_CALL_ID.store(rand::random::<u64>() | 1, Ordering::SeqCst);
    crate::ffi::hostcall::install_host_dispatcher(worker_host_dispatcher());
    let mut plugin: Option<crate::ffi::LoadedPlugin> = None;
    loop {
        let frame = {
            let _guard = WORKER_IO.lock().unwrap_or_else(|e| e.into_inner());
            match read_frame(&mut std::io::stdin().lock()) {
                Ok(f) => f,
                // Parent died or sent a bad frame: exit,
                // do not linger.
                Err(_) => return 1,
            }
        };
        match frame.op.as_str() {
            "open" => {
                let path = frame.path.clone().unwrap_or_default();
                let display = frame.display_path.clone().unwrap_or_default();
                match crate::ffi::open(Path::new(&path), &display) {
                    Ok(p) => {
                        plugin = Some(p);
                        // Fix loop 2, safety R2-N7: a
                        // failed reply write is a dead
                        // parent — exit instead of looping
                        // back to a read that fails anyway
                        // (consistent with the `call` arm's
                        // fail-fast rule).
                        if write_reply(&Frame::ok(frame.id)).is_err() {
                            return 1;
                        }
                    }
                    Err(e) => {
                        // The parent reaps the worker after
                        // a failed open reply; exit once the
                        // reply is out.
                        let _ = write_reply(&Frame::err(frame.id, error_code(&e), &e.to_string()));
                        return 1;
                    }
                }
            }
            "call" => {
                let Some(p) = plugin.as_ref() else {
                    if write_reply(&Frame::err(frame.id, "closed", "plugin client is closed"))
                        .is_err()
                    {
                        return 1;
                    }
                    continue;
                };
                let method = frame.method.clone().unwrap_or_default();
                let req = match frame.request.as_deref().map(|s| B64.decode(s)) {
                    Some(Ok(bytes)) => bytes,
                    Some(Err(_)) => {
                        if write_reply(&Frame::err(
                            frame.id,
                            "bad_frame",
                            "request is not valid base64",
                        ))
                        .is_err()
                        {
                            return 1;
                        }
                        continue;
                    }
                    None => Vec::new(),
                };
                match p.call(&method, &req) {
                    Ok(bytes) => {
                        // Oversize reply (fix loop 1, B5
                        // mirror / safety N3): a response
                        // whose frame would exceed the cap
                        // is answered with a clean
                        // `oversize_response` error frame
                        // — never swallowed and left for
                        // the parent to time out on, and
                        // never a SIGKILL of this healthy
                        // worker.
                        let reply = Frame::response(frame.id, bytes);
                        let reply = if frame_fits(&reply) {
                            reply
                        } else {
                            Frame::err(
                                frame.id,
                                "oversize_response",
                                "plugin call returned an oversize response",
                            )
                        };
                        if write_reply(&reply).is_err() {
                            return 1;
                        }
                    }
                    Err(e) => {
                        if write_reply(&Frame::err(frame.id, error_code(&e), &e.to_string()))
                            .is_err()
                        {
                            return 1;
                        }
                    }
                }
            }
            "shutdown" => {
                if let Some(mut p) = plugin.take() {
                    p.shutdown();
                }
                // Fix loop 2, safety R2-N7: same
                // fail-fast as the `open` arm — a dead
                // parent means the reply is unobservable
                // and the transact already failed.
                if write_reply(&Frame::ok(frame.id)).is_err() {
                    return 1;
                }
                return 0;
            }
            // Unknown op: drop it (fix loop 1, B2). The
            // parent never sends one; answering with a
            // reply-shaped error frame would let a
            // forged frame stand in for a real reply.
            // A dropped frame stalls the parent's
            // transact until its deadline — which is
            // exactly the fail-closed outcome for a
            // peer speaking an unknown op.
            _ => {}
        }
    }
}

#[cfg(not(unix))]
fn worker_main() -> i32 {
    eprintln!("castctl: plugin worker is not supported on this platform");
    2
}

// ---------------------------------------------------------------------
// Parent side
// ---------------------------------------------------------------------

/// The parent side of one loaded plugin: the worker
/// child, the socket, and the fused/dead state. One
/// `Mutex` serialises whole transactions (write +
/// multiplexed read loop), so calls never interleave
/// and a shutdown never races an in-flight call.
#[cfg(unix)]
pub(crate) struct WorkerClient {
    inner: Mutex<WorkerInner>,
}

#[cfg(unix)]
struct WorkerInner {
    child: Option<Child>,
    sock: Option<UnixStream>,
    stderr: Arc<Mutex<Vec<u8>>>,
    dispatcher: HostCallbackDispatcher,
    dead: Option<PluginHostError>,
    closed: bool,
    next_id: u64,
    shadow_path: Option<PathBuf>,
    /// Operator-supplied source path, for scrubbing
    /// the shadow path out of the stderr tail (fix
    /// loop 1, red N5).
    display_path: String,
    /// The last shutdown failure, if the worker died
    /// or timed out during `shutdown` (fix loop 1,
    /// B4). Read by `Client::shutdown_error` so
    /// `Host::close` can report it instead of
    /// swallowing it as `shutdown: ok`.
    shutdown_crash: Option<PluginHostError>,
}

/// Drain a worker's stderr into a capped buffer (last
/// 4 KiB). The thread is detached; it exits on EOF.
#[cfg(unix)]
fn spawn_stderr_drain(mut pipe: ChildStderr, buf: Arc<Mutex<Vec<u8>>>) {
    std::thread::spawn(move || {
        let mut chunk = [0u8; 1024];
        loop {
            match pipe.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    let mut b = buf.lock().unwrap_or_else(|e| e.into_inner());
                    b.extend_from_slice(&chunk[..n]);
                    if b.len() > STDERR_TAIL_CAP {
                        let overflow = b.len() - STDERR_TAIL_CAP;
                        b.drain(..overflow);
                    }
                }
                Err(_) => break,
            }
        }
    });
}

/// The worker's stderr tail, sanitised for an error
/// message (control chars stripped, secrets redacted,
/// capped at 2048 bytes) and scrubbed of the shadow
/// path (fix loop 1, red N5): a plugin printing its
/// own path must not leak the shadow directory layout
/// into a crash/timeout error.
#[cfg(unix)]
fn stderr_tail(
    buf: &Arc<Mutex<Vec<u8>>>,
    shadow_path: &Option<PathBuf>,
    display_path: &str,
) -> String {
    let bytes = buf.lock().unwrap_or_else(|e| e.into_inner()).clone();
    if bytes.is_empty() {
        return String::new();
    }
    let text = String::from_utf8_lossy(&bytes).into_owned();
    let stripped = strip_control_chars(&text);
    let scrubbed = match shadow_path {
        Some(shadow) => {
            crate::text::scrub_shadow_path(&stripped, &shadow.to_string_lossy(), display_path)
        }
        None => stripped,
    };
    let capped = if scrubbed.len() > 2048 {
        format!("{}…", crate::text::truncate_runes(&scrubbed, 2048))
    } else {
        scrubbed
    };
    safe_plugin_text(&capped)
}

#[cfg(unix)]
fn worker_token() -> String {
    let bytes: [u8; 16] = rand::random();
    hex::encode(bytes)
}

/// Spawn a worker for the plugin at `shadow_path` and
/// run the `open` frame in it. On any failure the child
/// is killed/reaped and the error returned; the caller
/// removes the shadow file. The spawned client owns
/// `shadow_path` afterwards and removes it on shutdown.
#[cfg(unix)]
pub(crate) fn spawn_worker(
    worker_bin: &Path,
    shadow_path: &Path,
    display_path: &str,
    dispatcher: HostCallbackDispatcher,
) -> Result<WorkerClient, PluginHostError> {
    let (parent_sock, child_sock) = UnixStream::pair()
        .map_err(|e| PluginHostError::failed(format!("create plugin worker socket: {e}")))?;
    let child_stdout = child_sock
        .try_clone()
        .map_err(|e| PluginHostError::failed(format!("create plugin worker socket: {e}")))?;
    // The socketpair end is the child's stdin AND stdout:
    // one duplex channel, no fd-number passing. The one
    // `pre_exec` in the codebase lives behind the safe
    // wrapper `ffi::set_parent_death_signal` (fix loop 1,
    // B7): `PR_SET_PDEATHSIG` (SIGKILL) so the worker
    // dies with the parent even mid-call, with the
    // fork/prctl race closed by a `getppid()` check in
    // the child. Stderr is piped separately for crash
    // diagnostics. The environment is scrubbed to a
    // minimal set; the worker needs the plugin path and
    // the socket, nothing else.
    let mut cmd = Command::new(worker_bin);
    crate::ffi::set_parent_death_signal(&mut cmd, std::process::id());
    cmd.arg("__plugin-worker")
        .arg(worker_token())
        .stdin(Stdio::from(OwnedFd::from(child_sock)))
        .stdout(Stdio::from(OwnedFd::from(child_stdout)))
        .stderr(Stdio::piped())
        .env_clear();
    if let Ok(path) = std::env::var("PATH") {
        cmd.env("PATH", path);
    }
    if let Ok(home) = std::env::var("HOME") {
        cmd.env("HOME", home);
    }
    if let Ok(tmp) = std::env::var("TMPDIR") {
        cmd.env("TMPDIR", tmp);
    }
    cmd.current_dir("/");
    let mut child = cmd
        .spawn()
        .map_err(|e| PluginHostError::failed(format!("spawn plugin worker {worker_bin:?}: {e}")))?;
    // Drop the `Command` NOW: its `Stdio::from(OwnedFd)`
    // fds are the child end of the socketpair, and they
    // stay open in the parent until `cmd` drops. If they
    // outlive the open transact, the death of the worker
    // can never deliver EOF (the parent holds the peer
    // end itself) and a crash in init reads as a 30s
    // timeout instead of `PluginCrashed`. The child
    // already holds its own dup'd copies on fds 0/1.
    drop(cmd);
    let stderr_buf = Arc::new(Mutex::new(Vec::new()));
    if let Some(err_pipe) = child.stderr.take() {
        spawn_stderr_drain(err_pipe, Arc::clone(&stderr_buf));
    }
    let client = WorkerClient {
        inner: Mutex::new(WorkerInner {
            child: Some(child),
            sock: Some(parent_sock),
            stderr: stderr_buf,
            dispatcher,
            dead: None,
            closed: false,
            // Call ids start at a random 64-bit value
            // (fix loop 1, B2): the outstanding id is
            // not guessable by a plugin thread writing
            // to fd 1, so a forged reply cannot name
            // it. Uniqueness within a client is all
            // the protocol needs.
            next_id: rand::random::<u64>() | 1,
            shadow_path: Some(shadow_path.to_path_buf()),
            display_path: display_path.to_string(),
            shutdown_crash: None,
        }),
    };
    let open_id = {
        let mut inner = client.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.next_id()
    };
    let open_frame = Frame {
        v: PROTOCOL_VERSION,
        id: open_id,
        op: "open".to_string(),
        path: Some(shadow_path.to_string_lossy().into_owned()),
        display_path: Some(display_path.to_string()),
        ..Default::default()
    };
    let opened = {
        let mut inner = client.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.transact(open_frame, CALL_TIMEOUT, "plugin load timed out")
    };
    match opened {
        Ok(reply) if reply.ok == Some(true) => Ok(client),
        Ok(reply) => {
            let msg = reply
                .error
                .map(|e| e.message)
                .unwrap_or_else(|| "plugin load failed".to_string());
            // The worker exits by itself after a failed
            // open reply; reap it.
            let mut inner = client.inner.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(mut child) = inner.child.take() {
                let _ = child.wait();
            }
            inner.sock = None;
            inner.dead = Some(PluginHostError::failed(msg.clone()));
            Err(PluginHostError::failed(msg))
        }
        Err(e) => {
            // transact() already marked the client dead
            // and reaped the child; make sure nothing
            // lingers.
            let mut inner = client.inner.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(mut child) = inner.child.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
            inner.sock = None;
            Err(e)
        }
    }
}

#[cfg(unix)]
impl WorkerInner {
    fn next_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    /// One request/response transaction, multiplexing
    /// reverse `host_call` frames while the call is
    /// outstanding (the deadlock rule). `timeout` is a
    /// deadline from now, enforced INSIDE every frame
    /// read (fix loop 1, B1). On EOF the worker died:
    /// reap it and report the crash. Every error fuses
    /// the client — except an oversize local write
    /// (fix loop 1, B5), which never touches the
    /// worker: a frame the host itself cannot send is
    /// a clean size error, not a crash.
    fn transact(
        &mut self,
        frame: Frame,
        timeout: Duration,
        timeout_msg: &'static str,
    ) -> Result<Frame, PluginHostError> {
        let deadline = Instant::now() + timeout;
        // B5: the size check happens INSIDE
        // `write_frame_deadline` (fix loop 2, tech
        // N10: one serialisation, not `frame_fits` +
        // `write_frame`). An over-cap frame is a clean
        // size error — the old code mapped ANY write
        // error to `reap_crash()`, SIGKILLing a healthy
        // worker and reporting signal 9 for a request
        // that was simply too big. The worker stays
        // alive and unfused; the caller gets a clear
        // size error and may retry smaller. A write
        // timeout kills the worker (fix loop 2, red
        // N2); any other write failure is a dead peer:
        // reap it.
        {
            let Some(sock) = self.sock.as_mut() else {
                return Err(PluginHostError::failed("plugin worker is gone"));
            };
            match write_frame_deadline(sock, &frame, deadline) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::InvalidInput => {
                    return Err(PluginHostError::failed("plugin worker frame too large"));
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    return Err(self.kill_timeout(timeout_msg));
                }
                Err(_) => {
                    return Err(self.reap_crash());
                }
            }
        }
        let mut host_call_count = 0usize;
        let mut host_call_bytes = 0usize;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(self.kill_timeout(timeout_msg));
            }
            let read_result = {
                let Some(sock) = self.sock.as_mut() else {
                    return Err(PluginHostError::failed("plugin worker is gone"));
                };
                read_frame_deadline(sock, deadline)
            };
            match read_result {
                Ok(f) => {
                    if f.op == "host_call" {
                        // B6: per-transaction budget.
                        host_call_count += 1;
                        let req_len = f
                            .request
                            .as_deref()
                            .and_then(|r| B64.decode(r).ok())
                            .map(|b| b.len())
                            .unwrap_or(0);
                        host_call_bytes += req_len;
                        if host_call_count > MAX_HOST_CALLS_PER_TRANSACT
                            || host_call_bytes > MAX_HOST_CALL_BYTES_PER_TRANSACT
                        {
                            return Err(self.kill_timeout(
                                "host callback flood: too many host calls in one transaction",
                            ));
                        }
                        match self.answer_host_call(&f, deadline) {
                            Ok(()) => continue,
                            Err(e) => return Err(e),
                        }
                    }
                    // B2: a frame is the reply only when
                    // its op is exactly "reply" AND its
                    // id matches. Any other op with the
                    // outstanding id is a forged or
                    // stray frame: protocol violation,
                    // kill + fuse, never a result.
                    if f.op != "reply" {
                        return Err(self.kill_protocol(
                            "plugin worker sent a non-reply frame for an outstanding call",
                        ));
                    }
                    if f.id != frame.id {
                        return Err(self.kill_protocol("plugin worker sent an unexpected frame"));
                    }
                    return Ok(f);
                }
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    return Err(self.reap_crash());
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    return Err(self.kill_timeout(timeout_msg));
                }
                Err(_) => {
                    return Err(self.reap_crash());
                }
            }
        }
    }

    /// Answer one reverse `host_call` frame: dispatch
    /// (never panicking across the boundary) and reply
    /// with the same id. A failed dispatch still gets a
    /// reply so the worker's callback unblocks. The
    /// dispatch runs on a helper thread bounded by the
    /// transaction deadline (fix loop 1, red N6): a log
    /// sink that blocks forever must not hang the
    /// transact past its deadline. `Err` is a typed
    /// kill: a dispatch timeout kills the worker
    /// (`kill_timeout`), a failed reply write reaps it
    /// (`reap_crash` — the peer is dead; fix loop 2,
    /// safety R2-N8, the old `let _ =` swallowed it
    /// and left the worker waiting out the dispatcher
    /// deadline). The helper thread itself is not
    /// joined on timeout: it stays parked in the
    /// blocking sink, but the client is dead/fused
    /// afterwards, so at most one leaked thread per
    /// loaded plugin — bounded by the number of loads,
    /// not by flood volume (safety R2-N5).
    fn answer_host_call(&mut self, f: &Frame, deadline: Instant) -> Result<(), PluginHostError> {
        let method = f.method.clone().unwrap_or_default();
        let req = f
            .request
            .as_deref()
            .and_then(|r| B64.decode(r).ok())
            .unwrap_or_default();
        let dispatcher = Arc::clone(&self.dispatcher);
        let (tx, rx) = std::sync::mpsc::channel::<Option<Vec<u8>>>();
        std::thread::spawn(move || {
            let dispatched = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                dispatcher(&method, &req)
            }));
            let _ = tx.send(dispatched.ok().flatten());
        });
        let remaining = deadline.saturating_duration_since(Instant::now());
        let dispatched = match rx.recv_timeout(remaining) {
            Ok(d) => d,
            Err(_) => return Err(self.kill_timeout("host callback timed out")),
        };
        let reply = match dispatched {
            Some(bytes) => {
                let reply = Frame {
                    v: PROTOCOL_VERSION,
                    id: f.id,
                    op: "host_call_reply".to_string(),
                    response: Some(B64.encode(bytes)),
                    ok: Some(true),
                    ..Default::default()
                };
                // A reply that would exceed the frame
                // cap (B5 mirror) is an error frame,
                // not a swallowed write failure.
                if frame_fits(&reply) {
                    reply
                } else {
                    Frame {
                        v: PROTOCOL_VERSION,
                        id: f.id,
                        op: "host_call_reply".to_string(),
                        ok: Some(false),
                        error: Some(FrameError {
                            code: "oversize_response".to_string(),
                            message: "host callback response too large".to_string(),
                        }),
                        ..Default::default()
                    }
                }
            }
            None => Frame {
                v: PROTOCOL_VERSION,
                id: f.id,
                op: "host_call_reply".to_string(),
                ok: Some(false),
                error: Some(FrameError {
                    code: "host_callback_failed".to_string(),
                    message: "host callback failed".to_string(),
                }),
                ..Default::default()
            },
        };
        // A reply write failure is a dead peer: reap
        // the worker instead of swallowing it (fix loop
        // 2, safety R2-N8). The write itself has the
        // transact deadline (fix loop 2, red-team N2):
        // a peer that stops draining cannot hang the
        // transact past its deadline.
        match self.sock.as_mut() {
            Some(sock) => {
                if let Err(e) = write_frame_deadline(sock, &reply, deadline) {
                    return Err(if e.kind() == std::io::ErrorKind::WouldBlock {
                        self.kill_timeout("host callback reply timed out")
                    } else {
                        self.reap_crash()
                    });
                }
            }
            None => return Err(self.reap_crash()),
        }
        Ok(())
    }

    /// The worker died: reap it and report the crash
    /// with the terminating signal when there is one.
    /// EOF with a still-running child (should not
    /// happen: EOF means its fds closed) is killed.
    fn reap_crash(&mut self) -> PluginHostError {
        let status = match self.child.as_mut() {
            Some(child) => match child.try_wait() {
                Ok(Some(status)) => Some(status),
                Ok(None) => {
                    let _ = child.kill();
                    child.wait().ok()
                }
                Err(_) => None,
            },
            None => None,
        };
        let signal = status.and_then(|s| s.signal());
        let detail = stderr_tail(&self.stderr, &self.shadow_path, &self.display_path);
        let err = PluginHostError::plugin_crashed(signal, detail);
        self.sock = None;
        self.child = None;
        self.dead = Some(err.clone());
        err
    }

    /// Timeout or protocol violation: SIGKILL the
    /// worker, reap it, fuse the client. The error is
    /// the typed `ClientDead` (fix loop 2, NB1), NOT a
    /// plain `Failed`: the worker is exactly as dead
    /// as after a crash, and the `Host` must fuse on
    /// it (see `PluginHostError::is_fatal_client_death`)
    /// instead of leaving `host.fused(tag)` empty for
    /// a client that can never succeed again.
    fn kill_timeout(&mut self, msg: &'static str) -> PluginHostError {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        self.sock = None;
        let detail = stderr_tail(&self.stderr, &self.shadow_path, &self.display_path);
        let err = if detail.is_empty() {
            PluginHostError::ClientDead(msg.to_string())
        } else {
            PluginHostError::ClientDead(format!("{msg} (worker stderr: {detail})"))
        };
        self.dead = Some(err.clone());
        err
    }

    fn kill_protocol(&mut self, msg: &'static str) -> PluginHostError {
        self.kill_timeout(msg)
    }
}

#[cfg(unix)]
impl Client for WorkerClient {
    fn call(&self, method: &str, request: &[u8]) -> Result<Vec<u8>, ClientError> {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(err) = &inner.dead {
            return Err(ClientError::Transport(err.clone()));
        }
        if inner.closed {
            return Err(ClientError::Transport(PluginHostError::failed(
                "plugin client is closed",
            )));
        }
        let id = inner.next_id();
        // Red-team N6 (fix loop 2): refuse an
        // over-cap request BEFORE base64-encoding it —
        // the old code transiently allocated ~4/3x the
        // request size and only then refused it in
        // `transact`. The bound is exact, not an
        // estimate: serialise the frame with an empty
        // request, take its JSON overhead, and invert
        // the base64 expansion (4 chars per 3 decoded
        // bytes). `transact`'s write path stays the
        // authoritative check; this only skips the
        // wasted encode. (A probe failure falls through
        // to `transact`, which refuses the same way.)
        let probe = Frame {
            v: PROTOCOL_VERSION,
            id,
            op: "call".to_string(),
            method: Some(method.to_string()),
            request: Some(String::new()),
            ..Default::default()
        };
        if let Ok(probe_bytes) = frame_bytes(&probe) {
            let overhead = probe_bytes.len() - 4;
            let max_decoded = 3 * (MAX_FRAME_BYTES - overhead) / 4;
            if request.len() > max_decoded {
                return Err(ClientError::Transport(PluginHostError::failed(
                    "plugin worker frame too large",
                )));
            }
        }
        let frame = Frame {
            v: PROTOCOL_VERSION,
            id,
            op: "call".to_string(),
            method: Some(method.to_string()),
            request: Some(B64.encode(request)),
            ..Default::default()
        };
        match inner.transact(frame, CALL_TIMEOUT, "plugin call timed out") {
            Ok(reply) => {
                if reply.ok == Some(true) {
                    match reply.response.as_deref() {
                        Some(encoded) => match B64.decode(encoded) {
                            Ok(bytes) => Ok(bytes),
                            Err(_) => Err(ClientError::Transport(PluginHostError::failed(
                                "plugin worker sent an invalid response",
                            ))),
                        },
                        None => Ok(Vec::new()),
                    }
                } else {
                    let msg = reply
                        .error
                        .map(|e| e.message)
                        .unwrap_or_else(|| "plugin call failed".to_string());
                    Err(ClientError::Transport(PluginHostError::failed(msg)))
                }
            }
            Err(e) => Err(ClientError::Transport(e)),
        }
    }

    fn shutdown(&self) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if inner.closed {
            return;
        }
        inner.closed = true;
        if inner.dead.is_some() {
            if let Some(mut child) = inner.child.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
            inner.sock = None;
            if let Some(p) = inner.shadow_path.take() {
                let _ = crate::shadow::remove_shadow_file(&p);
            }
            return;
        }
        let id = inner.next_id();
        let frame = Frame {
            v: PROTOCOL_VERSION,
            id,
            op: "shutdown".to_string(),
            ..Default::default()
        };
        // Fix loop 1, B4: EOF during shutdown is NOT
        // success. The old `eof_ok` path returned a
        // synthetic `Frame::ok` on EOF, so a worker
        // segfaulting inside plugin `shutdown` read as
        // a clean shutdown everywhere. Now EOF reaps
        // the child and reports the crash, which is
        // recorded here (and fused via `dead`) so
        // `Host::close` can surface it instead of
        // printing `shutdown: ok`.
        match inner.transact(frame, SHUTDOWN_TIMEOUT, "plugin shutdown timed out") {
            Ok(reply) => {
                if reply.ok != Some(true) {
                    let msg = reply
                        .error
                        .map(|e| e.message)
                        .unwrap_or_else(|| "plugin shutdown failed".to_string());
                    let err = PluginHostError::failed(msg);
                    inner.shutdown_crash = Some(err.clone());
                    inner.dead = Some(err);
                } else if let Some(child) = inner.child.as_mut()
                    && let Ok(Some(status)) = child.try_wait()
                    && let Some(signal) = status.signal()
                {
                    // Red-team N5 (fix loop 2): the
                    // worker answered `shutdown: ok` and
                    // then died by signal before exiting
                    // (e.g. a crashing `atexit`/runtime
                    // finaliser in the `.so`). The old
                    // code discarded the exit status and
                    // reported a clean shutdown. Only a
                    // child that ALREADY exited is checked
                    // here: a still-running child is killed
                    // below, and its SIGKILL (ours) must
                    // never be reported as a crash.
                    let detail =
                        stderr_tail(&inner.stderr, &inner.shadow_path, &inner.display_path);
                    inner.shutdown_crash =
                        Some(PluginHostError::plugin_crashed(Some(signal), detail));
                }
            }
            Err(e) => {
                inner.shutdown_crash = Some(e);
            }
        }
        if let Some(mut child) = inner.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        inner.sock = None;
        if let Some(p) = inner.shadow_path.take() {
            let _ = crate::shadow::remove_shadow_file(&p);
        }
    }

    /// The shutdown failure recorded by `shutdown`
    /// (fix loop 1, B4): `Some` when the worker died
    /// or timed out during plugin `shutdown`.
    fn shutdown_error(&self) -> Option<PluginHostError> {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .shutdown_crash
            .clone()
    }
}

#[cfg(unix)]
impl Drop for WorkerClient {
    fn drop(&mut self) {
        // Best-effort only: `Host::close` always calls
        // `shutdown()` explicitly. Never block here: if
        // a call is in flight on another thread, the
        // child is left to die with the process.
        if let Ok(mut inner) = self.inner.try_lock()
            && !inner.closed
        {
            inner.closed = true;
            if let Some(mut child) = inner.child.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
            inner.sock = None;
            if let Some(p) = inner.shadow_path.take() {
                let _ = crate::shadow::remove_shadow_file(&p);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pins the `call` frame JSON overhead (fix loop 1,
    /// B5): a `provider.call` frame is
    /// `{"v":2,"id":<id>,"op":"call","method":"provider.call","request":"<b64>"}`,
    /// 64 bytes of JSON around the base64 payload for a
    /// 1-digit id, 83 bytes for a 20-digit id. The
    /// effective decoded-payload cap is therefore
    /// `3 * floor((16 MiB - overhead) / 4)` =
    /// 12,582,864 (1-digit id) down to 12,582,849
    /// (20-digit id); the live test pins 12,500,000 OK
    /// / 13,000,000 refused.
    #[test]
    fn call_frame_overhead_is_pinned() {
        let frame = Frame {
            v: PROTOCOL_VERSION,
            id: 1,
            op: "call".to_string(),
            method: Some("provider.call".to_string()),
            request: Some("QUFB".to_string()),
            ..Default::default()
        };
        let bytes = frame_bytes(&frame).unwrap();
        // 4-byte length prefix + 68 bytes of JSON (64
        // overhead + 4 base64 chars).
        assert_eq!(bytes.len(), 72, "1-digit id frame: {bytes:?}");
        assert!(frame_fits(&frame));
        let frame = Frame {
            v: PROTOCOL_VERSION,
            id: u64::MAX,
            op: "call".to_string(),
            method: Some("provider.call".to_string()),
            request: Some("QUFB".to_string()),
            ..Default::default()
        };
        let bytes = frame_bytes(&frame).unwrap();
        assert_eq!(bytes.len(), 91, "20-digit id frame: {bytes:?}");
    }
}
