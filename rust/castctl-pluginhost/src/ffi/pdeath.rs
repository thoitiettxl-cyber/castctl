// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Safe wrapper for `PR_SET_PDEATHSIG` (fix loop 1,
//! B7): a worker whose parent dies mid-call must not
//! outlive it as an orphan. The `unsafe` (`pre_exec`
//! and `prctl`) lives here, in `ffi` — the only module
//! where `unsafe` is allowed. `worker.rs` calls only
//! this safe function.
//!
//! The classic fork/`prctl` race (parent dies between
//! `fork` and the `prctl`, so no signal is ever
//! delivered) is closed in the child: after the
//! `prctl`, the child checks `getppid()` against the
//! parent pid captured before `spawn`; a mismatch
//! means the parent already died, and the child exits
//! immediately. `prctl` + `getppid` + `_exit` are all
//! async-signal-safe, as required between `fork` and
//! `exec`.

use std::io;
use std::process::Command;

/// Register `PR_SET_PDEATHSIG` (SIGKILL) on the child
/// this `Command` will spawn, so the worker dies when
/// its parent dies — even while blocked inside a plugin
/// call, where no socket EOF can ever arrive.
/// `parent_pid` is the spawning process's pid, captured
/// before `spawn` for the race check. This is the one
/// `pre_exec` in the codebase; the "no `pre_exec`"
/// design note in `worker.rs` is amended by it.
#[cfg(unix)]
pub fn set_parent_death_signal(cmd: &mut Command, parent_pid: u32) {
    use std::os::unix::process::CommandExt;
    // SAFETY: the closure runs in the child between
    // `fork` and `exec` and only calls async-signal-safe
    // functions (`prctl`, `getppid`, `_exit`). It
    // captures only `parent_pid` (a `u32`, `Copy`).
    unsafe {
        cmd.pre_exec(move || {
            // SAFETY: see the function docs.
            let r = libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
            if r != 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: see the function docs.
            let ppid = libc::getppid();
            if ppid != parent_pid as libc::pid_t {
                // Parent died before the `prctl`
                // landed: exit now, do not linger as
                // an orphan.
                libc::_exit(127);
            }
            Ok(())
        });
    }
}
