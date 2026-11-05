// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Chrome launch — port of `internal/keeper/launch.go`
//! (with_chromedp) and `launch_types.go`.
//!
//! The launch fallback is a castctl-owned Chrome for
//! screencast login when no attachable browser exists.
//!
//! Fail-closed BEFORE spawning: a nil inbound fails every
//! `Run` before anything spawns. The ONLY egress is the
//! profile-routed inbound supplied by the command layer;
//! the screencast path passes nil today, so it still fails
//! closed before spawning anything.
//!
//! The launched browser's user-data dir is persistent
//! per-profile (`<profile-dir>/chromium-profile`, 0700):
//! the browser's state survives across logins, like a real
//! profile. It persists by design and is never rotated; a
//! FAILED launch attempts to remove a dir that launch
//! created (best effort).
//!
//! [DEVIATION] Go spawns Chrome through chromedp's exec
//! allocator; Rust spawns the Chrome process directly with
//! the same flags. The flag list is copied verbatim from
//! `launch.go:157-178`; whether chromedp's `VisibleWindow`
//! maps to exactly `--headless=new` absent / `--headless`
//! absent (i.e. a visible window) is [CHƯA KIỂM CHỨNG] on
//! the wire — the live gate must prove the spawned Chrome
//! behaves as a visible window, not a headless one.

use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use tokio::process::Command;

use crate::error::KeeperError;

/// The environment override for the browser executable,
/// after `--browser-path`, before PATH search
/// (`launch.go:108`).
pub const CHROMIUM_PATH_ENV: &str = "CASTCTL_CHROMIUM_PATH";

/// The launch-unavailable error: returned when the
/// feature is off (Go `ErrLaunchUnavailable` in the stub
/// build) or when no inbound is supplied.
pub struct LaunchUnavailable;

impl std::fmt::Display for LaunchUnavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "chrome launch unavailable")
    }
}

impl std::fmt::Debug for LaunchUnavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "LaunchUnavailable")
    }
}

impl std::error::Error for LaunchUnavailable {}

/// The inbound builder supplied by the command layer
/// (the S2 loopback proxy): builds the profile-routed
/// inbound and returns its proxy URL plus a cleanup
/// closure. The launched browser's ONLY egress is this
/// proxy.
#[async_trait::async_trait]
pub trait InboundBuilder: Send + Sync {
    /// Build the inbound; returns the proxy URL and a
    /// cleanup to run when the browser exits.
    async fn build_inbound(
        &self,
        profile_name: &str,
    ) -> Result<(String, Box<dyn FnOnce() + Send + Sync>), KeeperError>;
}

/// The persistent per-profile user-data dir (0700)
/// (`launch.go:127-137`): `<profile-dir>/chromium-profile`.
/// For the default profile it sits in the base dir; named
/// profiles under `profiles/<name>/`.
pub fn browser_profile_dir(base_dir: &str, profile_name: &str) -> Result<String, KeeperError> {
    let paths = castctl_config::profile::profile_paths(base_dir, profile_name)?;
    Ok(PathBuf::from(paths.dir)
        .join("chromium-profile")
        .display()
        .to_string())
}

/// The browser detection order (`launch.go:114-125`):
/// `--browser-path` > `CASTCTL_CHROMIUM_PATH` > PATH
/// search (`""` lets the spawn resolve it). No download, no
/// install. A relative path is accepted verbatim and
/// resolved by the OS/exec search at spawn time.
pub fn resolve_browser_path(flag_path: &str) -> String {
    if !flag_path.is_empty() {
        return flag_path.to_string();
    }
    if let Ok(env) = std::env::var(CHROMIUM_PATH_ENV) {
        if !env.is_empty() {
            return env;
        }
    }
    String::new()
}

/// The Chrome flags for a VISIBLE-window launch
/// (`launch.go:157-178`): undo the automation markers (a
/// login browser must look like a browser, not a bot),
/// ephemeral debug port (discovered from the
/// `DevToolsActivePort` file in the user-data dir), the
/// persistent user-data dir, and the ONLY egress (the
/// profile-routed inbound proxy URL).
pub fn visible_launch_flags(profile_dir: &str, proxy_url: &str) -> Vec<String> {
    vec![
        "--enable-automation=false".to_string(),
        "--disable-blink-features=AutomationControlled".to_string(),
        "--remote-debugging-port=0".to_string(),
        format!("--user-data-dir={profile_dir}"),
        format!("--proxy-server={proxy_url}"),
    ]
}

/// The Chrome flags for the HEADLESS re-login driver
/// (`relogin_chromedp.go:291-296`): headless + the same
/// automation-marker undo + ephemeral debug port +
/// user-data dir + proxy. [CHƯA KIỂM CHỨNG] which Chrome
/// flag chromedp's `Headless` emits (`--headless=new` vs
/// `--headless`); this port uses `--headless=new`
/// (Chrome 155 headless mode).
pub fn headless_launch_flags(profile_dir: &str, proxy_url: &str) -> Vec<String> {
    let mut flags = vec!["--headless=new".to_string()];
    flags.extend(visible_launch_flags(profile_dir, proxy_url));
    flags
}

/// A spawned Chrome process. Dropping it does NOT kill the
/// process; call [`LaunchedChrome::kill`] (the launch
/// runner owns its browser: cancelling kills the process
/// it started).
pub struct LaunchedChrome {
    child: tokio::process::Child,
    /// The persistent user-data dir.
    pub profile_dir: String,
}

impl LaunchedChrome {
    /// Spawn Chrome with the given flags. `browser_path`
    /// empty means PATH search. Stdout/stderr are null;
    /// stdin is null (the browser never reads stdin).
    pub async fn spawn(
        browser_path: &str,
        profile_dir: &str,
        flags: &[String],
        extra_args: &[String],
    ) -> Result<Self, KeeperError> {
        let exe = if browser_path.is_empty() {
            "chromium".to_string()
        } else {
            browser_path.to_string()
        };
        let mut cmd = Command::new(&exe);
        cmd.args(flags).args(extra_args);
        cmd.stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let child = cmd
            .spawn()
            .map_err(|e| KeeperError::Other(format!("cannot spawn browser {exe}: {e}")))?;
        Ok(Self {
            child,
            profile_dir: profile_dir.to_string(),
        })
    }

    /// Kill the process and wait for it to exit.
    pub async fn kill(mut self) -> Result<(), KeeperError> {
        let _ = self.child.kill().await;
        let _ = self.child.wait().await;
        Ok(())
    }

    /// Wait for the process to exit (bounded by `timeout`);
    /// returns `true` when it exited in time.
    pub async fn wait_timeout(&mut self, timeout: Duration) -> bool {
        tokio::time::timeout(timeout, self.child.wait())
            .await
            .is_ok()
    }
}

/// Resolve the debug port from the `DevToolsActivePort`
/// file in the persistent profile dir
/// (`launch.go:62-104`). The file format (first line:
/// port number) is read defensively: anything else fails
/// closed. A symlink at the port-file path is refused.
pub fn debug_port_from_file(profile_dir: &str) -> Result<u16, KeeperError> {
    let port_path = PathBuf::from(profile_dir).join("DevToolsActivePort");
    let meta = std::fs::symlink_metadata(&port_path).map_err(|e| {
        KeeperError::Other(format!("launched browser debug port file unreadable: {e}"))
    })?;
    if meta.file_type().is_symlink() {
        return Err(KeeperError::Other(
            "launched browser debug port file is a symlink".to_string(),
        ));
    }
    let raw = std::fs::read_to_string(&port_path).map_err(|e| {
        KeeperError::Other(format!("launched browser debug port file unreadable: {e}"))
    })?;
    let first = raw.split('\n').next().unwrap_or("").trim();
    let port: i64 = first.parse().map_err(|_| {
        KeeperError::Other("launched browser debug port file has no valid port".to_string())
    })?;
    if !(1..=65535).contains(&port) {
        return Err(KeeperError::Other(
            "launched browser debug port file has no valid port".to_string(),
        ));
    }
    Ok(port as u16)
}

/// Ensure the persistent profile dir exists at 0700,
/// enforcing 0700 even when it already exists (`MkdirAll`
/// leaves an existing directory's mode alone —
/// `launch.go:145-153`).
pub fn ensure_browser_profile_dir(profile_dir: &str) -> Result<(), KeeperError> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(profile_dir).map_err(KeeperError::Io)?;
    std::fs::set_permissions(profile_dir, std::fs::Permissions::from_mode(0o700))
        .map_err(KeeperError::Io)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_browser_path_order() {
        assert_eq!(resolve_browser_path("/bin/chrome"), "/bin/chrome");
        // Env override only applies when the flag is empty.
        unsafe { std::env::set_var(CHROMIUM_PATH_ENV, "/env/chrome") };
        assert_eq!(resolve_browser_path(""), "/env/chrome");
        assert_eq!(resolve_browser_path("/flag/chrome"), "/flag/chrome");
        unsafe { std::env::remove_var(CHROMIUM_PATH_ENV) };
        assert_eq!(resolve_browser_path(""), "");
    }

    #[test]
    fn browser_profile_dir_layout() {
        let dir = browser_profile_dir("/tmp/base", "default").unwrap();
        assert_eq!(dir, "/tmp/base/chromium-profile");
        let dir2 = browser_profile_dir("/tmp/base", "no.0").unwrap();
        assert_eq!(dir2, "/tmp/base/profiles/no.0/chromium-profile");
    }

    #[test]
    fn debug_port_file_parsing() {
        let d =
            std::env::temp_dir().join(format!(
                "castctl-keeper-launch-test-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let ds = d.to_str().unwrap();
        // Missing file fails closed.
        assert!(debug_port_from_file(ds).is_err());
        std::fs::write(
            d.join("DevToolsActivePort"),
            "9226\n/devtools/browser/abc\n",
        )
        .unwrap();
        assert_eq!(debug_port_from_file(ds).unwrap(), 9226);
        std::fs::write(d.join("DevToolsActivePort"), "0\n").unwrap();
        assert!(debug_port_from_file(ds).is_err());
        std::fs::write(d.join("DevToolsActivePort"), "notaport\n").unwrap();
        assert!(debug_port_from_file(ds).is_err());
        // Symlink refused.
        let target = d.join("real-port");
        std::fs::write(&target, "9227\n").unwrap();
        let _ = std::fs::remove_file(d.join("DevToolsActivePort"));
        std::os::unix::fs::symlink(&target, d.join("DevToolsActivePort")).unwrap();
        assert!(debug_port_from_file(ds).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn headless_flags_include_new_headless_and_no_enable_automation() {
        let flags = headless_launch_flags("/tmp/p", "http://127.0.0.1:18080");
        assert!(flags.contains(&"--headless=new".to_string()));
        assert!(flags.contains(&"--enable-automation=false".to_string()));
        assert!(!flags.iter().any(|f| f == "--enable-automation"));
        assert!(flags.contains(&"--remote-debugging-port=0".to_string()));
    }
}
