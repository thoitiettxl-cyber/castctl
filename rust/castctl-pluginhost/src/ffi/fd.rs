// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Safe wrappers over the two `libc` calls the worker
//! protocol needs for deadline enforcement (fix loop 1,
//! B1): `poll(2)` for readability with a timeout and
//! `read(2)` on a raw fd. Both live in `ffi` because
//! they are `unsafe` `libc` calls; callers in
//! `worker.rs` use only these safe wrappers.
//!
//! The worker's `host_call` round-trip reads its reply
//! from fd 0 with these wrappers instead of the
//! `StdinLock`: the lock's user-space buffer would
//! defeat `poll` (bytes already buffered look like no
//! data on the fd). `WORKER_IO` serialises the raw-fd
//! reads against the main loop's reads, so the two
//! readers never compete for the same bytes.

use std::io;
use std::time::{Duration, Instant};

/// Wait until `fd` is readable, or `timeout`
/// elapses. Returns `Ok(true)` when readable,
/// `Ok(false)` on timeout. `EINTR` retries
/// internally against the REMAINING time (fix loop
/// 2, safety R2-N2: the old loop re-armed the full
/// timeout on every retry, so a signal storm could
/// stretch one call past its deadline); any other
/// `poll` failure is an error (a deadline that
/// cannot be armed must fail the transaction, never
/// silently become unbounded). A `POLLERR` /
/// `POLLHUP` / `POLLNVAL` result is readable too:
/// the caller must attempt the read, which yields
/// EOF / the real error and is reported as a crash,
/// not mislabelled a timeout.
#[cfg(unix)]
pub fn poll_readable(fd: i32, timeout: Duration) -> io::Result<bool> {
    poll_fd(fd, timeout, libc::POLLIN)
}

/// Wait until `fd` is writable, or `timeout`
/// elapses (fix loop 2, red-team N2: the parent's
/// transact write previously had no deadline — a
/// peer that stops draining while the parent writes
/// a ~16 MiB frame could hang the transact past its
/// deadline). Same retry / error semantics as
/// `poll_readable`, for `POLLOUT`.
#[cfg(unix)]
pub fn poll_writable(fd: i32, timeout: Duration) -> io::Result<bool> {
    poll_fd(fd, timeout, libc::POLLOUT)
}

#[cfg(unix)]
fn poll_fd(fd: i32, timeout: Duration, events: i16) -> io::Result<bool> {
    let deadline = Instant::now() + timeout;
    let mut pfd = libc::pollfd {
        fd,
        events,
        revents: 0,
    };
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(false);
        }
        let timeout_ms = remaining.as_millis().min(i32::MAX as u128) as i32;
        // SAFETY: `pfd` is a valid one-element array;
        // `poll` only reads it.
        let r = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
        if r > 0 {
            // Readable/writable, or an error/hangup on
            // the fd: attempt the I/O and let it report
            // EOF / the real error. (A `POLLPRI`-only
            // result is none of these: poll again with
            // the remaining time; a socketpair peer
            // never produces out-of-band data.)
            return Ok(
                pfd.revents & (events | libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0,
            );
        }
        if r == 0 {
            return Ok(false);
        }
        let err = io::Error::last_os_error();
        if err.kind() == io::ErrorKind::Interrupted {
            continue;
        }
        return Err(err);
    }
}

/// One `read(2)` on a raw fd. `EINTR` retries
/// internally; `EAGAIN` surfaces as `WouldBlock` for
/// the caller's poll loop.
#[cfg(unix)]
pub fn read_fd(fd: i32, buf: &mut [u8]) -> io::Result<usize> {
    loop {
        // SAFETY: `fd` is the worker's stdin (the
        // socketpair child end, held open for the
        // worker's lifetime); `buf` is a valid
        // writable slice of its length.
        let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n >= 0 {
            return Ok(n as usize);
        }
        let err = io::Error::last_os_error();
        if err.kind() == io::ErrorKind::Interrupted {
            continue;
        }
        return Err(err);
    }
}
