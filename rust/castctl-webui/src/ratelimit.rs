// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Fixed-window login rate limiter (`internal/webui/ratelimit.go`).
//!
//! - Window: fixed, per remote-addr host part (port stripped).
//! - Defaults: 5 attempts per 5 minutes; per-field defaults
//!   apply when only one field is set. Attempts bound 1..100,
//!   window bound 1s..24h (bounds enforced at config parse /
//!   settings PUT; the limiter itself trusts its inputs).
//! - Store cap: 1024 addresses. At the cap, a newcomer fails
//!   closed (429 even with a valid token); `exceeded` never
//!   mutates the count.
//! - `record_failure`: fresh window starts at count 1; an
//!   expired window is replaced (not incremented past the
//!   window). `record_success` deletes the entry.
//! - A 429 carries `Retry-After` = window seconds (the
//!   configured window, not the remaining time).
//! - The check runs BEFORE auth (middleware order: rate-limit
//!   → auth), so a locked-out client gets 429 even with a
//!   valid token, and WS upgrades 429 too. WS success/failure
//!   never feeds the counter.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Maximum tracked addresses (Go `maxRateLimitEntries`).
pub const MAX_ENTRIES: usize = 1024;

/// One limiter: a fixed-window store. The attempts/window
/// pair is NOT stored here: Go resolves the effective pair
/// from the current config on every request
/// (`loginLimits`), so each call takes them as parameters.
pub struct RateLimiter {
    entries: HashMap<String, (u32, Instant)>,
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl RateLimiter {
    /// Build one limiter (empty store).
    pub fn new() -> Self {
        Self { entries: HashMap::new() }
    }

    /// `exceeded(addr, attempts, window)`: true when the
    /// address already used all its attempts inside the
    /// current window. Attempts < 1 or a non-positive window
    /// never limits. A newcomer at a full store fails closed
    /// — but only after pruning expired entries. An expired
    /// window is deleted (not counted). Never mutates the
    /// count of a live window.
    pub fn exceeded(&mut self, host: &str, attempts: u32, window: Duration) -> bool {
        if attempts < 1 || window.is_zero() {
            return false;
        }
        match self.entries.get(host) {
            Some((count, started)) => {
                if started.elapsed() >= window {
                    self.entries.remove(host);
                    false
                } else {
                    *count >= attempts
                }
            }
            None => {
                self.prune_expired(window);
                self.entries.len() >= MAX_ENTRIES
            }
        }
    }

    /// `recordFailure(addr, window)`: fresh window starts
    /// at count 1; an expired window is replaced; a live
    /// window increments. When the address is new and the
    /// store is full, only expired entries are evicted; if
    /// none has expired the failure is dropped without
    /// inserting, so the store never evicts a limited
    /// address's entry to make room. A non-positive window
    /// records nothing.
    pub fn record_failure(&mut self, host: &str, window: Duration) {
        if window.is_zero() {
            return;
        }
        let now = Instant::now();
        match self.entries.get_mut(host) {
            Some((count, started)) => {
                if started.elapsed() >= window {
                    *count = 1;
                    *started = now;
                } else {
                    *count = count.saturating_add(1);
                }
            }
            None => {
                if self.entries.len() >= MAX_ENTRIES {
                    self.prune_expired(window);
                    if self.entries.len() >= MAX_ENTRIES {
                        return;
                    }
                }
                self.entries.insert(host.to_string(), (1, now));
            }
        }
    }

    /// `recordSuccess(addr)`: delete the entry, so a
    /// successful login resets the counter for that address.
    pub fn record_success(&mut self, host: &str) {
        self.entries.remove(host);
    }

    /// Drop entries whose window has expired.
    fn prune_expired(&mut self, window: Duration) {
        self.entries.retain(|_, (_, started)| started.elapsed() < window);
    }
}

/// `retryAfterSeconds`: a window as whole seconds for
/// `Retry-After`, at least 1 (a sub-second configured
/// window still tells the client to wait).
pub fn retry_after_seconds(window: Duration) -> String {
    let secs = window.as_secs();
    if secs < 1 { "1".to_string() } else { secs.to_string() }
}

/// `clientKey`: the host part of a remote address
/// (`net.SplitHostPort` when it parses, else the whole
/// value). `127.0.0.1:54321` → `127.0.0.1`,
/// `[::1]:54321` → `::1`; a bare `::1` has no port and is
/// returned as-is.
pub fn host_part(remote_addr: &str) -> &str {
    if let Some(bracketed) = remote_addr.strip_prefix('[') {
        if let Some(end) = bracketed.find(']') {
            if bracketed[end + 1..].starts_with(':') {
                return &bracketed[..end];
            }
        }
        return remote_addr;
    }
    if remote_addr.matches(':').count() == 1 {
        if let Some(idx) = remote_addr.rfind(':') {
            return &remote_addr[..idx];
        }
    }
    remote_addr
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_window_five_then_429() {
        let mut limiter = RateLimiter::new();
        let host = "127.0.0.1";
        let window = Duration::from_secs(300);
        for _ in 0..5 {
            assert!(!limiter.exceeded(host, 5, window));
            limiter.record_failure(host, window);
        }
        assert!(limiter.exceeded(host, 5, window));
        // A successful login resets the counter.
        limiter.record_success(host);
        assert!(!limiter.exceeded(host, 5, window));
    }

    #[test]
    fn exceeded_never_mutates_count() {
        let mut limiter = RateLimiter::new();
        let window = Duration::from_secs(300);
        limiter.record_failure("10.0.0.1", window);
        assert!(limiter.exceeded("10.0.0.1", 1, window));
        assert!(limiter.exceeded("10.0.0.1", 1, window));
        limiter.record_success("10.0.0.1");
        assert!(!limiter.exceeded("10.0.0.1", 1, window));
    }

    #[test]
    fn expired_window_frees_the_address() {
        let mut limiter = RateLimiter::new();
        let window = Duration::from_millis(10);
        limiter.record_failure("10.0.0.2", window);
        assert!(limiter.exceeded("10.0.0.2", 1, window));
        std::thread::sleep(Duration::from_millis(20));
        assert!(!limiter.exceeded("10.0.0.2", 1, window));
        limiter.record_failure("10.0.0.2", window);
        assert!(limiter.exceeded("10.0.0.2", 1, window));
    }

    #[test]
    fn host_part_strips_port() {
        assert_eq!(host_part("127.0.0.1:54321"), "127.0.0.1");
        assert_eq!(host_part("[::1]:54321"), "::1");
        assert_eq!(host_part("127.0.0.1"), "127.0.0.1");
        assert_eq!(host_part("::1"), "::1");
    }

    #[test]
    fn fail_before_rate_limit() {
        // If the check were dropped, the 6th bad token would
        // still get a 401 instead of 429: this pins the gate.
        let mut limiter = RateLimiter::new();
        let window = Duration::from_secs(300);
        for _ in 0..5 {
            limiter.record_failure("127.0.0.1", window);
        }
        assert!(limiter.exceeded("127.0.0.1", 5, window));
    }
}
