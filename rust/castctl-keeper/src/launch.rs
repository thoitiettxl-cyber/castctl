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
//! the same effective argv, computed from chromedp's
//! `DefaultExecAllocatorOptions` + `VisibleWindow` /
//! `Headless` + Go's own options (see `default_flags`).
//! Whether the spawned Chrome behaves as a visible window
//! (not headless) is [CHƯA KIỂM CHỨNG] on the wire — the
//! live gate must prove it.

use std::path::{Path, PathBuf};
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
        write!(
            f,
            "launch fallback unavailable: no profile-inbound plumbing at this base (S2 gate); attach to an already-running Chrome via the keeper browser URL, or use auth import"
        )
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
    if let Ok(env) = std::env::var(CHROMIUM_PATH_ENV)
        && !env.is_empty()
    {
        return env;
    }
    String::new()
}

/// The Chrome flags for a VISIBLE-window launch: the
/// effective argv of Go's `launch.go:157-178` —
/// `DefaultExecAllocatorOptions` (chromedp `allocate.go`,
/// in `flagOrder`) + `VisibleWindow` (deletes `headless`,
/// `hide-scrollbars`, `mute-audio`, `enable-automation`,
/// `disable-extensions`; appends `--start-maximized`) +
/// Go's own options. `Flag("enable-automation", false)`
/// re-sets the flag to false, and chromedp's `flagArgs`
/// OMITS a false bool from argv entirely — so Go passes
/// NO `--enable-automation` flag at all (the old
/// `--enable-automation=false` was wrong: Chrome's
/// `HasSwitch` still sees the switch). Undo the automation
/// markers (a login browser must look like a browser, not
/// a bot), ephemeral debug port (discovered from the
/// `DevToolsActivePort` file in the user-data dir), the
/// persistent user-data dir, and the ONLY egress (the
/// profile-routed inbound proxy URL).
pub fn visible_launch_flags(profile_dir: &str, proxy_url: &str) -> Vec<String> {
    let mut flags = default_flags(false);
    flags.push("--start-maximized".to_string());
    flags.extend(go_launch_tail(profile_dir, proxy_url));
    flags
}

/// The Chrome flags for the HEADLESS re-login driver
/// (`relogin_chromedp.go:291-296`): `Headless` is
/// `--headless` bare (chromedp `Headless` sets the bool
/// flag `headless`, which `flagArgs` renders bare —
/// NOT `--headless=new`), plus the same automation-marker
/// undo + ephemeral debug port + user-data dir + proxy.
pub fn headless_launch_flags(profile_dir: &str, proxy_url: &str) -> Vec<String> {
    let mut flags = default_flags(true);
    flags.extend(go_launch_tail(profile_dir, proxy_url));
    flags
}

/// chromedp `DefaultExecAllocatorOptions` rendered to
/// argv, in `flagOrder` (`allocate.go:90-118` +
/// `flagArgs`: a true bool renders as a bare `--name`, a
/// false bool is OMITTED, a string as `--name=value`).
/// `headless` selects the `Headless` trio (`--headless`,
/// `--hide-scrollbars`, `--mute-audio`); `VisibleWindow`
/// deletes those three plus `enable-automation` and
/// `disable-extensions`. `enable-automation` is false in
/// both Go launch paths, so it never appears.
fn default_flags(headless: bool) -> Vec<String> {
    let mut flags = vec![
        "--no-first-run".to_string(),
        "--no-default-browser-check".to_string(),
    ];
    if headless {
        flags.push("--headless".to_string());
        flags.push("--hide-scrollbars".to_string());
        flags.push("--mute-audio".to_string());
    }
    flags.extend(
        [
            "--disable-background-networking",
            "--enable-features=NetworkService,NetworkServiceInProcess",
            "--disable-background-timer-throttling",
            "--disable-backgrounding-occluded-windows",
            "--disable-breakpad",
            "--disable-client-side-phishing-detection",
            "--disable-default-apps",
            "--disable-dev-shm-usage",
        ]
        .iter()
        .map(|s| s.to_string()),
    );
    if headless {
        flags.push("--disable-extensions".to_string());
    }
    flags.extend(
        [
            "--disable-features=Translate,BlinkGenPropertyTrees",
            "--disable-hang-monitor",
            "--disable-ipc-flooding-protection",
            "--disable-popup-blocking",
            "--disable-prompt-on-repost",
            "--disable-renderer-backgrounding",
            "--disable-sync",
            "--force-color-profile=srgb",
            "--metrics-recording-only",
            "--safebrowsing-disable-auto-update",
            "--password-store=basic",
            "--use-mock-keychain",
        ]
        .iter()
        .map(|s| s.to_string()),
    );
    flags
}

/// Go's own options appended after the defaults, in
/// order (`launch.go:157-178`, `relogin_chromedp.go:291-296`).
fn go_launch_tail(profile_dir: &str, proxy_url: &str) -> Vec<String> {
    vec![
        "--disable-blink-features=AutomationControlled".to_string(),
        "--remote-debugging-port=0".to_string(),
        format!("--user-data-dir={profile_dir}"),
        format!("--proxy-server={proxy_url}"),
    ]
}

/// The chromedp binary search order for unix-like
/// systems (`allocate.go:635-695` `execLocations` +
/// `findExecPath`): `headless_shell`, `headless-shell`,
/// `chromium`, `chromium-browser`, `google-chrome`,
/// `google-chrome-stable`, `google-chrome-beta`,
/// `google-chrome-unstable`, `/usr/bin/google-chrome`,
/// `/usr/local/bin/chrome`, `/snap/bin/chromium`,
/// `chrome`; fallback `"google-chrome"`. A bare name is
/// resolved through `path_env` (like `exec.LookPath`); an
/// absolute path is used when it names an executable file.
pub fn find_browser_executable(path_env: &str) -> String {
    const CANDIDATES: [&str; 12] = [
        "headless_shell",
        "headless-shell",
        "chromium",
        "chromium-browser",
        "google-chrome",
        "google-chrome-stable",
        "google-chrome-beta",
        "google-chrome-unstable",
        "/usr/bin/google-chrome",
        "/usr/local/bin/chrome",
        "/snap/bin/chromium",
        "chrome",
    ];
    find_browser_executable_in(path_env, &CANDIDATES)
}

fn find_browser_executable_in(path_env: &str, candidates: &[&str]) -> String {
    for cand in candidates {
        if cand.contains('/') {
            if is_executable_file(PathBuf::from(cand).as_path()) {
                return cand.to_string();
            }
        } else {
            for dir in path_env.split(':') {
                if dir.is_empty() {
                    continue;
                }
                let p = PathBuf::from(dir).join(cand);
                if is_executable_file(&p) {
                    return p.display().to_string();
                }
            }
        }
    }
    "google-chrome".to_string()
}

fn is_executable_file(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    match std::fs::metadata(p) {
        Ok(m) => m.is_file() && m.permissions().mode() & 0o111 != 0,
        Err(_) => false,
    }
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
    /// empty means the chromedp binary search order
    /// (`find_browser_executable`). Stdout/stderr are null;
    /// stdin is null (the browser never reads stdin).
    pub async fn spawn(
        browser_path: &str,
        profile_dir: &str,
        flags: &[String],
        extra_args: &[String],
    ) -> Result<Self, KeeperError> {
        let exe = if browser_path.is_empty() {
            find_browser_executable(&std::env::var("PATH").unwrap_or_default())
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
        let d = std::env::temp_dir().join(format!(
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
    fn launch_flags_go_parity() {
        // R-6: the effective argv of Go's launch paths —
        // chromedp defaults in `flagOrder`, `Headless` as
        // bare `--headless` (not `--headless=new`), and NO
        // `--enable-automation` flag at all (Go sets it
        // false; chromedp omits a false bool from argv).
        let headless = headless_launch_flags("/tmp/p", "http://127.0.0.1:18080");
        assert_eq!(headless[0], "--no-first-run");
        assert_eq!(headless[1], "--no-default-browser-check");
        assert_eq!(headless[2], "--headless");
        assert_eq!(headless[3], "--hide-scrollbars");
        assert_eq!(headless[4], "--mute-audio");
        assert!(headless.contains(&"--disable-dev-shm-usage".to_string()));
        assert!(headless.contains(&"--disable-extensions".to_string()));
        assert!(headless.contains(&"--disable-blink-features=AutomationControlled".to_string()));
        assert!(headless.contains(&"--remote-debugging-port=0".to_string()));
        assert!(headless.contains(&"--user-data-dir=/tmp/p".to_string()));
        assert!(headless.contains(&"--proxy-server=http://127.0.0.1:18080".to_string()));
        assert!(
            !headless
                .iter()
                .any(|f| f.starts_with("--enable-automation"))
        );
        assert!(!headless.iter().any(|f| f == "--headless=new"));
        assert!(!headless.iter().any(|f| f == "--start-maximized"));

        let visible = visible_launch_flags("/tmp/p", "http://127.0.0.1:18080");
        assert!(!visible.iter().any(|f| f == "--headless"));
        assert!(!visible.iter().any(|f| f == "--hide-scrollbars"));
        assert!(!visible.iter().any(|f| f == "--mute-audio"));
        assert!(!visible.iter().any(|f| f == "--disable-extensions"));
        assert!(!visible.iter().any(|f| f.starts_with("--enable-automation")));
        assert!(visible.contains(&"--start-maximized".to_string()));
        assert!(visible.contains(&"--disable-blink-features=AutomationControlled".to_string()));
        // `--start-maximized` (VisibleWindow) precedes
        // Go's own tail flags.
        let sm = visible
            .iter()
            .position(|f| f == "--start-maximized")
            .unwrap();
        let db = visible
            .iter()
            .position(|f| f == "--disable-blink-features=AutomationControlled")
            .unwrap();
        assert!(sm < db);
    }

    #[test]
    fn find_browser_executable_order() {
        // R-7: chromedp `execLocations` order, resolved
        // through a fake PATH (pure function, no env).
        let d = std::env::temp_dir().join(format!(
            "castctl-keeper-findbin-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        for name in ["google-chrome", "chromium"] {
            let p = d.join(name);
            std::fs::write(&p, "#!/bin/sh\n").unwrap();
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let path_env = d.to_str().unwrap().to_string();
        // `chromium` precedes `google-chrome`.
        assert_eq!(
            find_browser_executable(&path_env),
            d.join("chromium").display().to_string()
        );
        // A non-executable candidate is skipped.
        std::fs::remove_file(d.join("chromium")).unwrap();
        assert_eq!(
            find_browser_executable(&path_env),
            d.join("google-chrome").display().to_string()
        );
        // Nothing found: the chromedp fallback. The real
        // candidate list always contains absolute paths
        // that may exist on the test machine (cue has
        // `/usr/bin/google-chrome`), so the fallback is
        // pinned through the injectable list instead.
        assert_eq!(
            find_browser_executable_in("", &["/nonexistent-1", "/nonexistent-2"]),
            "google-chrome"
        );
        let _ = std::fs::remove_dir_all(&d);
    }
}
