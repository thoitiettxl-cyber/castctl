// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! One self-update run: `Run(Options)`-equivalent.
//!
//! Go sources: `Run` / `run` (`internal/update/update.go:227-302`),
//! `selectRelease` / `selectLatest` / `selectExplicit` /
//! `fallbackLatest` / `fallbackSelection` / `fallbackTag`
//! (`update.go:610-915`), `install` / `dryRun` /
//! `fetchChecksums` / `hashFile` (`internal/update/replace.go:88-300`).
//!
//! Adaptations vs Go (recorded, not silent):
//! - Go's `Deps` carries `*http.Client` and `*debug.BuildInfo`.
//!   Rust has neither: `Deps` carries a boxed [`Fetcher`]
//!   (default [`StdFetcher`]) and the `CGO_ENABLED` build
//!   settings as `(key, value)` pairs, which
//!   [`flavour_from_cgo_settings`] maps exactly like Go's
//!   `flavourFromBuildInfo`. A caller that cannot supply the
//!   settings passes `None` and gets Go's "unknown flavour"
//!   refusal, never a guess.
//! - Go's failure-injection hooks are package-level vars
//!   (`renameFunc` / `syncDirFunc` / `execCheckFn`,
//!   `replace.go:29-34`). Rust puts the same three seams on
//!   [`Deps`] as `Option<fn>` fields; production passes
//!   `None` and gets the real syscalls.
//! - Go's `context.Context` deadlines are per-request
//!   socket timeouts here (see `http.rs`); there is no
//!   whole-run cancellation token.
//! - Go's `Error` carries the cause via `Unwrap` for the
//!   logging boundary; [`UpdateError`] carries only the
//!   fixed message (the cause's `HttpError` summary is
//!   never rendered into the message in either language).
//! - The CLI wiring (`internal/commands/update.go` flags,
//!   help, exit mapping; Telegram `/update` caller) is OUT
//!   of scope for this crate: `run` returns
//!   `(Result, Result<(), UpdateError>)` and the caller
//!   maps `UpdateError::code()` to the process exit code.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use crate::checksums::parse_checksums;
use crate::elf::validate_elf_file;
use crate::error::UpdateError;
use crate::extract::extract_castctl;
use crate::http::{
    Fetcher, MAX_CHECKSUMS_BYTES, MAX_RELEASE_JSON_BYTES, METADATA_TIMEOUT, StdFetcher,
    download_asset, fetch_bytes,
};
use crate::lock::{LockOutcome, acquire_update_lock};
use crate::replace::{is_dir_sync_tolerable, open_for_sync, run_exec_check, sync_dir};
use crate::select::{
    ReleaseInfo, Selection, decide, fallback_tag_from_location_path, flavour_from_cgo_settings,
    parse_url,
};
use crate::semver::{Version, parse_version};

/// Serialises concurrent runs in-process, like Go's
/// `updateMu` (`internal/update/update.go:228`).
static UPDATE_MU: Mutex<()> = Mutex::new(());

/// `execCheckTimeout` (10s). Source:
/// `internal/update/update.go:41-43`.
pub const EXEC_CHECK_TIMEOUT: Duration = Duration::from_secs(10);

/// Failure-injection seam type for the `--version` exec
/// check (`replace.go:33`).
type ExecCheckFn = fn(&Path, &Version, Duration) -> std::result::Result<(), UpdateError>;

/// Dependencies of one run. Mirrors Go's `Deps`
/// (`internal/update/update.go:63-75`) with the adaptations
/// noted in the module docs.
#[derive(Default)]
pub struct Deps {
    /// HTTP fetcher; `None` means the production
    /// [`StdFetcher`]. Go: `HTTPClient *http.Client`.
    pub http_fetcher: Option<Box<dyn Fetcher>>,
    /// Override for the running binary path. `None` means
    /// `std::env::current_exe()`. Go: `Executable string`
    /// (an `Options` field; kept here so tests can point
    /// at a tempdir target without touching the real binary).
    pub executable: Option<String>,
    /// `CGO_ENABLED` build settings as `(key, value)` pairs.
    /// `None` means "no build info": flavour is unknown and
    /// the run refuses, exactly like Go with a nil
    /// `*debug.BuildInfo`. Go: `BuildInfo *debug.BuildInfo`.
    pub cgo_settings: Option<Vec<(String, String)>>,
    /// API base override; empty means
    /// `https://api.github.com`. Go: `Options.APIBase`.
    pub api_base: String,
    /// GitHub web base override; empty means
    /// `https://github.com`. Go: `Options.GitHubBase`.
    pub github_base: String,
    /// Failure-injection seam for the rename step.
    /// `None` means `std::fs::rename`. Go: `renameFunc`
    /// (`replace.go:31`).
    pub rename_fn: Option<fn(&Path, &Path) -> std::io::Result<()>>,
    /// Failure-injection seam for the post-rename directory
    /// sync. `None` means [`sync_dir`]. Go: `syncDirFunc`
    /// (`replace.go:32`).
    pub sync_dir_fn: Option<fn(&Path) -> std::io::Result<()>>,
    /// Failure-injection seam for the `--version` exec check.
    /// `None` means [`run_exec_check`]. Go: `execCheckFn`
    /// (`replace.go:33`).
    pub exec_check_fn: Option<ExecCheckFn>,
}

/// Options for one run. Mirrors Go's `Options`
/// (`internal/update/update.go:77-95`).
pub struct Options {
    /// Dependencies (fetcher, executable override, ...).
    pub deps: Deps,
    /// Current version string (as stamped, e.g. `"0.6.3"`).
    pub current_version: String,
    /// Build commit stamp; empty + empty build date refuses.
    pub commit: String,
    /// Build date stamp.
    pub build_date: String,
    /// Explicit `--version` target; `""` means latest.
    pub target_version: String,
    /// Dry-run: verify everything, write nothing.
    pub dry_run: bool,
    /// Allow a downgrade.
    pub allow_downgrade: bool,
    /// Allow a prerelease target.
    pub allow_prerelease: bool,
    /// Outcome report sink; `None` discards it.
    /// Go: `Stdout io.Writer`.
    pub stdout: Option<Box<dyn Write>>,
}

/// What one run did. Mirrors Go's `Result`
/// (`internal/update/update.go:97-105`).
#[derive(Debug, Clone)]
pub struct Result {
    /// Current version (parsed).
    pub current: Version,
    /// Target version (parsed); equal to `current` on a no-op.
    pub target: Version,
    /// Asset file name (empty on a no-op).
    pub asset_name: String,
    /// Resolved path of the running binary.
    pub target_path: String,
    /// True when the binary was replaced (also true when
    /// the rename succeeded but the directory sync failed).
    pub replaced: bool,
    /// True when this was a dry run.
    pub dry_run: bool,
}

/// The release-fetch failure: the error plus the HTTP status
/// (0 on transport failure), so callers can decide the 403
/// fallback themselves. Mirrors Go's `fetchRelease`
/// triple `(rel, status, err)` (`update.go:795-814`).
struct FetchReleaseError {
    err: UpdateError,
    status: u16,
}

/// One run's mutable state: options + fetcher + output sink.
struct Updater {
    opts: Options,
    fetcher: Box<dyn Fetcher>,
    out: Box<dyn Write>,
}

impl Updater {
    fn printf(&mut self, line: &str) {
        let _ = writeln!(self.out, "{line}");
    }

    fn api_base(&self) -> String {
        let base = self.opts.deps.api_base.trim_end_matches('/');
        if base.is_empty() {
            "https://api.github.com".to_string()
        } else {
            base.to_string()
        }
    }

    fn github_base(&self) -> String {
        let base = self.opts.deps.github_base.trim_end_matches('/');
        if base.is_empty() {
            "https://github.com".to_string()
        } else {
            base.to_string()
        }
    }

    fn user_agent(&self) -> String {
        format!("castctl/{}", self.opts.current_version)
    }

    /// Fetch and decode a release object.
    /// Source: `fetchRelease` (`update.go:795-814`).
    fn fetch_release(&mut self, url: &str) -> std::result::Result<ReleaseInfo, FetchReleaseError> {
        let ua = self.user_agent();
        let body = match fetch_bytes(
            self.fetcher.as_mut(),
            url,
            &ua,
            MAX_RELEASE_JSON_BYTES,
            METADATA_TIMEOUT,
        ) {
            Ok(b) => b,
            Err(e) => {
                return Err(FetchReleaseError {
                    status: e.status,
                    err: UpdateError::failure("update: failed to fetch release information"),
                });
            }
        };
        // `serde_json::from_slice` rejects trailing garbage
        // after the object, like Go's `json.Unmarshal`;
        // unknown fields are tolerated by default.
        #[derive(serde::Deserialize)]
        struct ReleaseJson {
            #[serde(default)]
            tag_name: String,
            #[serde(default)]
            draft: bool,
            #[serde(default)]
            prerelease: bool,
            #[serde(default)]
            assets: Vec<AssetJson>,
        }
        #[derive(serde::Deserialize)]
        struct AssetJson {
            #[serde(default)]
            name: String,
            #[serde(default)]
            browser_download_url: String,
            #[serde(default)]
            size: i64,
            #[serde(default)]
            state: String,
        }
        let decoded: ReleaseJson = match serde_json::from_slice(&body) {
            Ok(d) => d,
            Err(_) => {
                return Err(FetchReleaseError {
                    status: 200,
                    err: UpdateError::failure("update: release information is malformed"),
                });
            }
        };
        Ok(ReleaseInfo {
            tag: decoded.tag_name,
            draft: decoded.draft,
            prerelease: decoded.prerelease,
            assets: decoded
                .assets
                .into_iter()
                .map(|a| crate::select::ReleaseAsset {
                    name: a.name,
                    url: a.browser_download_url,
                    size: a.size,
                    state: a.state,
                })
                .collect(),
        })
    }

    /// The 403 fallback for `/latest`: probe the public web
    /// redirect once (no-follow) and extract the tag.
    /// Source: `fallbackTag` (`update.go:855-908`).
    fn fallback_tag(&mut self) -> std::result::Result<String, UpdateError> {
        let url = format!(
            "{}/thoitiettxl-cyber/castctl/releases/latest",
            self.github_base()
        );
        let ua = self.user_agent();
        let (status, location) = match self.fetcher.get_no_follow(&url, &ua, METADATA_TIMEOUT) {
            Ok(t) => t,
            Err(_) => return Err(rate_limit_error()),
        };
        if !matches!(status, 301 | 302 | 303 | 307 | 308) {
            return Err(rate_limit_error());
        }
        let Some(loc) = location else {
            return Err(rate_limit_error());
        };
        let Some(loc_url) = parse_url(&loc) else {
            return Err(rate_limit_error());
        };
        let base_host = parse_url(&self.github_base())
            .map(|u| u.host)
            .unwrap_or_default();
        if loc_url.host != base_host && loc_url.host != "github.com" {
            return Err(rate_limit_error());
        }
        match fallback_tag_from_location_path(&loc_url.path) {
            Some(tag) => Ok(tag),
            None => Err(rate_limit_error()),
        }
    }

    /// Source: `fallbackLatest` (`update.go:816-837`).
    fn fallback_latest(
        &mut self,
        current: &Version,
        flavour: &str,
        goarch: &str,
    ) -> std::result::Result<Selection, UpdateError> {
        let tag = self.fallback_tag()?;
        let target = match parse_version(&tag) {
            Ok(t) => t,
            Err(_) => {
                return Err(UpdateError::failure(
                    "update: GitHub API rate limit reached and the fallback could not determine a valid release tag; try again later",
                ));
            }
        };
        if target.has_build() {
            return Err(UpdateError::failure(
                "update: GitHub API rate limit reached and the fallback release tag carries build metadata; try again later",
            ));
        }
        if !target.prerelease().is_empty() && !self.opts.allow_prerelease {
            return Err(UpdateError::usage(
                "update: the latest release is a prerelease; pass --allow-prerelease to install it",
            ));
        }
        let tag = format!("v{}", target.asset_version());
        decide(
            current,
            target,
            tag,
            flavour,
            goarch,
            &self.github_base(),
            None,
            true,
            self.opts.allow_downgrade,
            self.opts.allow_prerelease,
        )
    }

    /// Source: `fallbackSelection` (`update.go:839-853`).
    fn fallback_selection(
        &mut self,
        current: &Version,
        flavour: &str,
        goarch: &str,
        tag: String,
        target: Version,
    ) -> std::result::Result<Selection, UpdateError> {
        if !target.prerelease().is_empty() && !self.opts.allow_prerelease {
            return Err(UpdateError::usage(
                "update: the requested release is a prerelease; pass --allow-prerelease to install it",
            ));
        }
        decide(
            current,
            target,
            tag,
            flavour,
            goarch,
            &self.github_base(),
            None,
            true,
            self.opts.allow_downgrade,
            self.opts.allow_prerelease,
        )
    }

    /// Source: `selectExplicit` (`update.go:613-646`).
    fn select_explicit(
        &mut self,
        current: &Version,
        flavour: &str,
        goarch: &str,
    ) -> std::result::Result<Selection, UpdateError> {
        let target = match parse_version(&self.opts.target_version) {
            Ok(t) => t,
            Err(_) => {
                return Err(UpdateError::usage("update: invalid --version value"));
            }
        };
        if target.has_build() {
            return Err(UpdateError::usage(
                "update: --version must not carry build metadata",
            ));
        }
        let tag = format!("v{}", target.asset_version());
        let url = format!(
            "{}/repos/thoitiettxl-cyber/castctl/releases/tags/{}",
            self.api_base(),
            tag
        );
        let rel = match self.fetch_release(&url) {
            Ok(r) => r,
            Err(e) => {
                if e.status == 403 {
                    return self.fallback_selection(current, flavour, goarch, tag, target);
                }
                if e.status == 404 {
                    return Err(UpdateError::usage(
                        "update: no release exists for the requested version",
                    ));
                }
                return Err(e.err);
            }
        };
        if rel.draft {
            return Err(UpdateError::usage(
                "update: the requested release is a draft",
            ));
        }
        if rel.prerelease && !self.opts.allow_prerelease {
            return Err(UpdateError::usage(
                "update: the requested release is a prerelease; pass --allow-prerelease to install it",
            ));
        }
        decide(
            current,
            target,
            tag,
            flavour,
            goarch,
            &self.github_base(),
            Some(&rel),
            false,
            self.opts.allow_downgrade,
            self.opts.allow_prerelease,
        )
    }

    /// Source: `selectLatest` (`update.go:648-680`).
    fn select_latest(
        &mut self,
        current: &Version,
        flavour: &str,
        goarch: &str,
    ) -> std::result::Result<Selection, UpdateError> {
        let url = format!(
            "{}/repos/thoitiettxl-cyber/castctl/releases/latest",
            self.api_base()
        );
        let rel = match self.fetch_release(&url) {
            Ok(r) => r,
            Err(e) => {
                if e.status == 403 {
                    return self.fallback_latest(current, flavour, goarch);
                }
                if e.status == 404 {
                    return Err(UpdateError::usage("update: no release found"));
                }
                return Err(e.err);
            }
        };
        if rel.draft || rel.prerelease {
            return Err(UpdateError::usage(
                "update: the latest release is not a stable release; refusing to install it",
            ));
        }
        let target = match parse_version(&rel.tag) {
            Ok(t) => t,
            Err(_) => {
                return Err(UpdateError::usage(
                    "update: the latest release tag is not a valid version",
                ));
            }
        };
        if target.has_build() {
            return Err(UpdateError::usage(
                "update: the latest release tag carries build metadata; refusing to install it",
            ));
        }
        let tag = format!("v{}", target.asset_version());
        decide(
            current,
            target,
            tag,
            flavour,
            goarch,
            &self.github_base(),
            Some(&rel),
            false,
            self.opts.allow_downgrade,
            self.opts.allow_prerelease,
        )
    }

    fn select_release(
        &mut self,
        current: &Version,
        flavour: &str,
        goarch: &str,
    ) -> std::result::Result<Selection, UpdateError> {
        if !self.opts.target_version.is_empty() {
            return self.select_explicit(current, flavour, goarch);
        }
        self.select_latest(current, flavour, goarch)
    }

    /// Source: `fetchChecksums` (`replace.go:271-290`).
    fn fetch_checksums(
        &mut self,
        sel: &Selection,
    ) -> std::result::Result<std::collections::BTreeMap<String, [u8; 32]>, UpdateError> {
        let ua = self.user_agent();
        let body = match fetch_bytes(
            self.fetcher.as_mut(),
            &sel.checksums_url,
            &ua,
            MAX_CHECKSUMS_BYTES,
            METADATA_TIMEOUT,
        ) {
            Ok(b) => b,
            Err(e) => {
                if e.status == 404 {
                    return Err(UpdateError::failure(
                        "update: the release has no checksums file",
                    ));
                }
                return Err(UpdateError::failure(
                    "update: failed to fetch the checksums file",
                ));
            }
        };
        parse_checksums(&body)
            .map_err(|_| UpdateError::failure("update: the checksums file is malformed"))
    }

    /// Source: `install` (`replace.go:88-265`).
    fn install(
        &mut self,
        res: Result,
        sel: &Selection,
        target: &Path,
        target_mode: u32,
    ) -> (Result, std::result::Result<(), UpdateError>) {
        let dir = target.parent().unwrap_or(Path::new("."));
        // Acquire once and keep the guard alive for the whole
        // install; dropping it releases the flock.
        let lock = match acquire_update_lock(dir) {
            Ok(LockOutcome::Held(lock)) => lock,
            Ok(LockOutcome::AlreadyHeld) => {
                return (
                    Result::empty(),
                    Err(UpdateError::failure(
                        "update: another update is already in progress",
                    )),
                );
            }
            Err(_) => {
                return (
                    Result::empty(),
                    Err(UpdateError::failure(
                        "update: cannot lock the update directory",
                    )),
                );
            }
        };
        let (res, err) = self.install_locked(res, sel, target, target_mode, dir);
        drop(lock);
        (res, err)
    }

    /// The install pipeline proper, entered with the lock held.
    /// Kept separate so the lock's lifetime is explicit.
    fn install_locked(
        &mut self,
        mut res: Result,
        sel: &Selection,
        target: &Path,
        target_mode: u32,
        dir: &Path,
    ) -> (Result, std::result::Result<(), UpdateError>) {
        // (The lock is held by the `UpdateLock` value in
        // `install`; this helper runs under it.)
        let sums = match self.fetch_checksums(sel) {
            Ok(s) => s,
            Err(e) => return (Result::empty(), Err(e)),
        };
        let Some(want_digest) = sums.get(&sel.asset_name) else {
            return (
                Result::empty(),
                Err(UpdateError::failure(
                    "update: the checksums file has no entry for the release asset",
                )),
            );
        };
        let want_digest = *want_digest;
        // Download to a temp file in the SAME directory as the
        // target (same filesystem, so the rename cannot hit
        // EXDEV), 0600, O_EXCL random suffix. Removed on every
        // path below.
        let (asset_tmp_path, mut asset_tmp) = match create_temp_file(dir) {
            Ok(t) => t,
            Err(_) => {
                return (
                    Result::empty(),
                    Err(UpdateError::failure(
                        "update: cannot create a temporary file in the binary directory",
                    )),
                );
            }
        };
        let ua = self.user_agent();
        let digest = download_asset(
            self.fetcher.as_mut(),
            &sel.asset_url,
            &ua,
            sel.asset_size,
            &mut asset_tmp,
        );
        drop(asset_tmp);
        let digest = match digest {
            Ok(d) => d,
            Err(e) => {
                let _ = std::fs::remove_file(&asset_tmp_path);
                return (Result::empty(), Err(e));
            }
        };
        if digest != want_digest {
            let _ = std::fs::remove_file(&asset_tmp_path);
            return (
                Result::empty(),
                Err(UpdateError::failure(
                    "update: the downloaded asset does not match the checksums file",
                )),
            );
        }
        // Extract to a second temp file in the same directory.
        let (extracted_tmp_path, mut extracted_tmp) = match create_temp_file(dir) {
            Ok(t) => t,
            Err(_) => {
                let _ = std::fs::remove_file(&asset_tmp_path);
                return (
                    Result::empty(),
                    Err(UpdateError::failure(
                        "update: cannot create a temporary file in the binary directory",
                    )),
                );
            }
        };
        let extracted_hash = (|| -> std::result::Result<[u8; 32], UpdateError> {
            let asset_file = std::fs::File::open(&asset_tmp_path)
                .map_err(|_| UpdateError::failure("update: cannot re-read the downloaded asset"))?;
            let hash = extract_castctl(asset_file, &mut extracted_tmp)?;
            extracted_tmp
                .sync_all()
                .map_err(|_| UpdateError::failure("update: cannot sync the extracted binary"))?;
            drop(extracted_tmp);
            Ok(hash)
        })();
        let extracted_hash = match extracted_hash {
            Ok(h) => h,
            Err(e) => {
                let _ = std::fs::remove_file(&asset_tmp_path);
                let _ = std::fs::remove_file(&extracted_tmp_path);
                return (Result::empty(), Err(e));
            }
        };
        let _ = std::fs::remove_file(&asset_tmp_path);
        // Preserve the target's Perm() bits now, BEFORE the
        // exec check and the rename: setuid/setgid/sticky
        // bits of the old binary are dropped (Perm() carries
        // rwx bits only).
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(target_mode);
            if let Err(e) = std::fs::set_permissions(&extracted_tmp_path, perms) {
                let _ = std::fs::remove_file(&extracted_tmp_path);
                return (
                    Result::empty(),
                    Err(UpdateError::failure(format!(
                        "update: cannot set permissions on the new binary: {e}"
                    ))),
                );
            }
        }
        // ELF/arch validation on the extracted file.
        if let Err(e) = validate_elf_file(&extracted_tmp_path, goarch_name()) {
            let _ = std::fs::remove_file(&extracted_tmp_path);
            return (Result::empty(), Err(e));
        }
        // Exec check AFTER checksum verification only.
        let exec_check = self.opts.deps.exec_check_fn.unwrap_or(run_exec_check);
        if let Err(e) = exec_check(&extracted_tmp_path, &sel.target, EXEC_CHECK_TIMEOUT) {
            let _ = std::fs::remove_file(&extracted_tmp_path);
            return (Result::empty(), Err(e));
        }
        // Re-hash immediately before rename.
        let rehash = match hash_file(&extracted_tmp_path) {
            Ok(h) => h,
            Err(_) => {
                let _ = std::fs::remove_file(&extracted_tmp_path);
                return (
                    Result::empty(),
                    Err(UpdateError::failure(
                        "update: cannot re-read the extracted binary",
                    )),
                );
            }
        };
        if rehash != extracted_hash {
            let _ = std::fs::remove_file(&extracted_tmp_path);
            return (
                Result::empty(),
                Err(UpdateError::failure(
                    "update: the extracted binary changed between verification and replace; refusing to install it",
                )),
            );
        }
        // Fsync the temp file (mode already set above),
        // rename once, fsync the directory. The open
        // retries ETXTBSY briefly.
        let sync_result = (|| -> std::result::Result<(), UpdateError> {
            let sync_file = open_for_sync(&extracted_tmp_path)
                .map_err(|_| UpdateError::failure("update: cannot re-open the new binary"))?;
            sync_file
                .sync_all()
                .map_err(|_| UpdateError::failure("update: cannot sync the new binary"))?;
            drop(sync_file);
            Ok(())
        })();
        if let Err(e) = sync_result {
            let _ = std::fs::remove_file(&extracted_tmp_path);
            return (Result::empty(), Err(e));
        }
        let rename = self
            .opts
            .deps
            .rename_fn
            .unwrap_or(|a, b| std::fs::rename(a, b));
        if let Err(e) = rename(&extracted_tmp_path, target) {
            let _ = std::fs::remove_file(&extracted_tmp_path);
            return (
                Result::empty(),
                Err(UpdateError::failure(format!(
                    "update: cannot replace the running binary: {e}"
                ))),
            );
        }
        // The rename succeeded: the deferred Remove is now a
        // no-op (the temp path no longer exists).
        let sync_dir_fn = self.opts.deps.sync_dir_fn.unwrap_or(sync_dir);
        if let Err(e) = sync_dir_fn(dir) {
            if is_dir_sync_tolerable(&e) {
                // Filesystems that do not support directory
                // fsync still hold the rename; tolerated
                // silently (H-92).
            } else {
                res.replaced = true;
                res.target = sel.target.clone();
                res.asset_name = sel.asset_name.clone();
                return (
                    res,
                    Err(UpdateError::failure(
                        "update: directory sync failed after replace; the new binary is in place but its durability is not guaranteed",
                    )),
                );
            }
        }
        res.replaced = true;
        res.target = sel.target.clone();
        res.asset_name = sel.asset_name.clone();
        self.printf(&format!(
            "castctl updated: {} -> {} ({})",
            res.current, sel.target, sel.asset_name
        ));
        (res, Ok(()))
    }

    /// Source: `dryRun` (`replace.go:266-300`). Zero writes:
    /// no lock file, no temp files, no directory changes.
    fn dry_run(
        &mut self,
        mut res: Result,
        sel: &Selection,
        target: &Path,
        target_mode: u32,
    ) -> (Result, std::result::Result<(), UpdateError>) {
        let sums = match self.fetch_checksums(sel) {
            Ok(s) => s,
            Err(e) => return (Result::empty(), Err(e)),
        };
        let Some(want_digest) = sums.get(&sel.asset_name) else {
            return (
                Result::empty(),
                Err(UpdateError::failure(
                    "update: the checksums file has no entry for the release asset",
                )),
            );
        };
        let want_digest = *want_digest;
        let mut asset_buf: Vec<u8> = Vec::new();
        let ua = self.user_agent();
        let digest = match download_asset(
            self.fetcher.as_mut(),
            &sel.asset_url,
            &ua,
            sel.asset_size,
            &mut asset_buf,
        ) {
            Ok(d) => d,
            Err(e) => return (Result::empty(), Err(e)),
        };
        if digest != want_digest {
            return (
                Result::empty(),
                Err(UpdateError::failure(
                    "update: the downloaded asset does not match the checksums file",
                )),
            );
        }
        let mut extracted_buf: Vec<u8> = Vec::new();
        if let Err(e) = extract_castctl(&asset_buf[..], &mut extracted_buf) {
            return (Result::empty(), Err(e));
        }
        if let Err(e) = crate::elf::validate_elf_bytes(&extracted_buf, goarch_name()) {
            return (Result::empty(), Err(e));
        }
        res.target = sel.target.clone();
        res.asset_name = sel.asset_name.clone();
        self.printf(&format!(
            "dry-run: would update {} -> {}",
            res.current, sel.target
        ));
        self.printf(&format!(
            "dry-run: asset {} ({})",
            sel.asset_name, sel.asset_url
        ));
        self.printf("dry-run: checksums verified (sha256 against checksums.txt)");
        self.printf(&format!(
            "dry-run: would replace {} (permissions {:04o} preserved)",
            target.display(),
            target_mode
        ));
        self.printf(
            "dry-run: exec check skipped in dry-run; it runs before replace in a real update",
        );
        (res, Ok(()))
    }
}

impl Result {
    fn empty() -> Result {
        Result {
            current: parse_version("0.0.0").expect("0.0.0 parses"),
            target: parse_version("0.0.0").expect("0.0.0 parses"),
            asset_name: String::new(),
            target_path: String::new(),
            replaced: false,
            dry_run: false,
        }
    }
}

/// The rate-limit error. Source: `rateLimitError`
/// (`update.go:911-913`).
fn rate_limit_error() -> UpdateError {
    UpdateError::failure(
        "update: GitHub API rate limit reached; try again later (unauthenticated API requests are limited to 60 per hour)",
    )
}

/// Create a temp file in `dir` with the Go `os.CreateTemp`
/// shape: `.castctl-update-*`, mode 0600, `O_EXCL`.
/// Returns the path and the open handle.
/// Source: `install` (`replace.go:118-124`).
fn create_temp_file(dir: &Path) -> std::io::Result<(PathBuf, std::fs::File)> {
    use std::os::unix::fs::OpenOptionsExt;
    // `rand` is not a dependency of this crate; use
    // time+pid as the random suffix (the Go suffix is
    // random, the Rust one only needs to be unique per
    // attempt — `O_EXCL` retries on collision).
    for _ in 0..100 {
        let suffix = format!(
            "{:x}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
                ^ (std::process::id() as u128) << 64
        );
        let path = dir.join(format!(".castctl-update-{suffix}"));
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
        {
            Ok(f) => return Ok((path, f)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "could not create a unique temp file",
    ))
}

/// SHA-256 of a file's bytes. Source: `hashFile`
/// (`replace.go:292-300`).
fn hash_file(path: &Path) -> std::io::Result<[u8; 32]> {
    use sha2::{Digest, Sha256};
    let mut f = std::fs::File::open(path)?;
    let mut h = Sha256::new();
    std::io::copy(&mut f, &mut h)?;
    Ok(h.finalize().into())
}

/// Resolve the target binary: follow symlinks, require a
/// regular file, return `(resolved path, Perm() bits)`.
/// Source: `resolveTarget` (`update.go:918-935`).
fn resolve_target(exe_override: Option<&str>) -> std::result::Result<(PathBuf, u32), UpdateError> {
    let exe = match exe_override {
        Some(e) => PathBuf::from(e),
        None => std::env::current_exe()
            .map_err(|_| UpdateError::failure("update: cannot resolve the running binary"))?,
    };
    let resolved = std::fs::canonicalize(&exe)
        .map_err(|_| UpdateError::failure("update: cannot resolve the running binary"))?;
    let meta = std::fs::metadata(&resolved)
        .map_err(|_| UpdateError::failure("update: cannot resolve the running binary"))?;
    if !meta.is_file() {
        return Err(UpdateError::failure(
            "update: cannot resolve the running binary",
        ));
    }
    use std::os::unix::fs::PermissionsExt;
    Ok((resolved, meta.permissions().mode() & 0o777))
}

/// Map `std::env::consts::ARCH` to the Go GOARCH value used
/// in asset names and ELF validation.
fn goarch_name() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => other,
    }
}

/// Perform one self-update. It never loads config, never
/// writes state, and never uses credentials. Exit-code
/// contract: 0 success / already-latest no-op / dry-run
/// report; 2 usage and policy refusals; 1 every fetch,
/// verify, or replace failure. Source: `Run` / `run`
/// (`internal/update/update.go:227-302`).
pub fn run(mut opts: Options) -> (Result, std::result::Result<(), UpdateError>) {
    let _guard = UPDATE_MU.lock().unwrap_or_else(|e| e.into_inner());
    let goos = std::env::consts::OS;
    let goarch = goarch_name();
    // 1. Dev/stamped check: both empty refuses in ALL modes,
    // before any network or filesystem access.
    if opts.commit.is_empty() && opts.build_date.is_empty() {
        return (
            Result::empty(),
            Err(UpdateError::usage(
                "update: cannot determine running version: this build was not stamped with commit and build date; refusing to guess the version",
            )),
        );
    }
    let current = match parse_version(&opts.current_version) {
        Ok(v) => v,
        Err(_) => {
            return (
                Result::empty(),
                Err(UpdateError::usage(
                    "update: cannot determine running version",
                )),
            );
        }
    };
    // 2. Flavour from build info.
    let flavour = match &opts.deps.cgo_settings {
        Some(settings) => flavour_from_cgo_settings(settings),
        None => None,
    };
    let Some(flavour) = flavour else {
        return (
            Result::empty(),
            Err(UpdateError::usage(
                "update: cannot determine build flavour (glibc or no-plugin); refusing to guess",
            )),
        );
    };
    // 3. Platform: release assets exist for Linux amd64/arm64
    // only.
    if goos != "linux" || (goarch != "amd64" && goarch != "arm64") {
        return (
            Result::empty(),
            Err(UpdateError::usage(format!(
                "update: no release asset for {goos}/{goarch}"
            ))),
        );
    }
    // 4. Resolve the target once; every later step uses the
    // resolved path.
    let (target, target_mode) = match resolve_target(opts.deps.executable.as_deref()) {
        Ok(t) => t,
        Err(_) => {
            return (
                Result::empty(),
                Err(UpdateError::failure(
                    "update: cannot resolve the running binary",
                )),
            );
        }
    };
    if target_mode & 0o111 == 0 {
        return (
            Result::empty(),
            Err(UpdateError::failure(
                "update: the running binary is not executable; refusing to replace it",
            )),
        );
    }
    let mut res = Result {
        current: current.clone(),
        target: current.clone(),
        asset_name: String::new(),
        target_path: target.display().to_string(),
        replaced: false,
        dry_run: opts.dry_run,
    };
    let fetcher: Box<dyn Fetcher> = opts
        .deps
        .http_fetcher
        .take()
        .unwrap_or_else(|| Box::new(StdFetcher));
    let out: Box<dyn Write> = opts
        .stdout
        .take()
        .unwrap_or_else(|| Box::new(std::io::sink()));
    let mut updater = Updater { opts, fetcher, out };
    // 5. Select the target release (latest or explicit, with
    // the 403 fallback). This may return a no-op result.
    let sel = match updater.select_release(&current, flavour, goarch) {
        Ok(s) => s,
        Err(e) => return (Result::empty(), Err(e)),
    };
    if sel.noop {
        res.target = sel.target.clone();
        updater.printf(&format!("castctl is up to date: {current}"));
        return (res, Ok(()));
    }
    res.target = sel.target.clone();
    res.asset_name = sel.asset_name.clone();
    if updater.opts.dry_run {
        return updater.dry_run(res, &sel, &target, target_mode);
    }
    updater.install(res, &sel, &target, target_mode)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `run` refuses a dev build (no commit, no build date)
    /// in ALL modes, before any network or filesystem access
    /// — including with a fetcher that would panic on use.
    /// Source: `run` step 1 (`update.go:250-253`).
    #[test]
    fn dev_build_refuses_before_network() {
        let opts = Options {
            deps: Deps::default(),
            current_version: "0.6.3".to_string(),
            commit: String::new(),
            build_date: String::new(),
            target_version: String::new(),
            dry_run: false,
            allow_downgrade: false,
            allow_prerelease: false,
            stdout: None,
        };
        let (_res, err) = run(opts);
        let err = err.expect_err("dev build must refuse");
        assert_eq!(err.code(), 2);
        assert!(
            err.to_string()
                .starts_with("update: cannot determine running version")
        );
    }

    /// Invalid current version refuses with code 2.
    #[test]
    fn invalid_current_version_refuses() {
        let opts = Options {
            deps: Deps {
                cgo_settings: Some(vec![("CGO_ENABLED".to_string(), "1".to_string())]),
                ..Deps::default()
            },
            current_version: "not-a-version".to_string(),
            commit: "abc".to_string(),
            build_date: "2026-10-30".to_string(),
            target_version: String::new(),
            dry_run: false,
            allow_downgrade: false,
            allow_prerelease: false,
            stdout: None,
        };
        let (_res, err) = run(opts);
        assert_eq!(err.expect_err("must refuse").code(), 2);
    }

    /// Unknown flavour (no CGO settings) refuses with code 2.
    #[test]
    fn unknown_flavour_refuses() {
        let opts = Options {
            deps: Deps::default(),
            current_version: "0.6.3".to_string(),
            commit: "abc".to_string(),
            build_date: "2026-10-30".to_string(),
            target_version: String::new(),
            dry_run: false,
            allow_downgrade: false,
            allow_prerelease: false,
            stdout: None,
        };
        let (_res, err) = run(opts);
        let err = err.expect_err("must refuse");
        assert_eq!(err.code(), 2);
        assert!(err.to_string().contains("build flavour"));
    }
}
