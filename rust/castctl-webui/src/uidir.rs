// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! On-disk frontend directory (`internal/webui/uidir.go`).
//!
//! When `ui_dir` is set, the unauthenticated static shell
//! is served from that directory instead of the embedded
//! frontend. Containment is re-run per request with the
//! symlink-aware helpers (`resolveAgainst` / `pathWithin`):
//! no verdict is cached across renames, symlinks that leave
//! the root are refused, directories never list, and only
//! regular files are served. Dotfiles are refused on the
//! request path and again on the resolved root-relative
//! path. The root-vs-config overlap rule is re-checked per
//! request. A missing file under a valid root falls back to
//! the on-disk shell (SPA hash routing). A present-but-broken
//! root is rejected at startup and never silently falls back
//! to the embedded frontend.
//!
//! The shell file itself (`index.html`) is never served
//! through a symlink: any symlinked index.html is refused
//! at startup (exit 2) and per request (fixed 404), even
//! when its target stays inside the root.
//!
//! Residual (documented honestly, as in Go): between the
//! per-request containment resolution and the open, a
//! symlink swapped into an intermediate path component can
//! redirect the read, and a swapped-in FIFO could block one
//! request task (check-then-open TOCTOU). The final
//! component is Lstat-checked before the open and the
//! opened file must be the same file the Lstat saw
//! (`SameFile`) on both the asset and shell paths.
//! Hardlinks are undetectable.

use crate::contain::{path_within, resolve_against, resolve_path_best_effort};
use crate::server::{Resp, error_resp, not_found_resp, shell_headers};
use std::path::{Path, PathBuf};

/// `uiDirMIME`: the closed extension allowlist for
/// on-disk frontend files. Anything unlisted is served as
/// `application/octet-stream`. The host MIME database is
/// never consulted.
pub fn ui_dir_content_type(name: &str) -> &'static str {
    let ext = Path::new(name)
        .extension()
        .map(|e| e.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    match ext.as_str() {
        "html" => "text/html; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "json" | "map" => "application/json",
        "txt" => "text/plain; charset=utf-8",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "svg" => "image/svg+xml",
        "webp" => "image/webp",
        "avif" => "image/avif",
        "ico" => "image/x-icon",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "otf" => "font/otf",
        "wasm" => "application/wasm",
        _ => "application/octet-stream",
    }
}

/// `UIDirError`: a fail-closed ui_dir configuration error
/// from `checkUIDir`. A distinct type so callers map it to
/// exit 2 (configuration) rather than exit 1 (operational
/// startup failure). Messages name the rule only, never
/// the path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UIDirError(pub String);

impl std::fmt::Display for UIDirError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for UIDirError {}

/// `checkUIDir` (startup): a directory, holding a regular
/// non-symlink `index.html`, resolved against the config
/// directory, not overlapping it in either direction
/// (equal, inside, or ancestor — symlink-resolved), and
/// containing none of the cookies files when any are
/// supplied. The index.html check uses Lstat.
pub fn check_ui_dir(
    config_dir: &Path,
    ui_dir: &str,
    cookies_files: &[String],
) -> Result<PathBuf, UIDirError> {
    let root = resolve_against(config_dir, ui_dir);
    let md = std::fs::metadata(&root)
        .map_err(|_| UIDirError("webui: ui_dir is not a readable directory".to_string()))?;
    if !md.is_dir() {
        return Err(UIDirError(
            "webui: ui_dir is not a readable directory".to_string(),
        ));
    }
    let base = resolve_path_best_effort(config_dir);
    if path_within(&root, &base) || path_within(&base, &root) {
        return Err(UIDirError(
            "webui: ui_dir must not overlap the config directory".to_string(),
        ));
    }
    for cookies_file in cookies_files {
        if cookies_file.is_empty() {
            continue;
        }
        if path_within(&resolve_path_best_effort(Path::new(cookies_file)), &root) {
            return Err(UIDirError(
                "webui: ui_dir must not contain a cookies file".to_string(),
            ));
        }
    }
    let index = root.join("index.html");
    let lst = std::fs::symlink_metadata(&index)
        .map_err(|_| UIDirError("webui: ui_dir has no readable index.html".to_string()))?;
    if lst.file_type().is_symlink() || !lst.is_file() {
        return Err(UIDirError(
            "webui: ui_dir has no readable index.html".to_string(),
        ));
    }
    Ok(root)
}

/// Whether the per-request resolved root overlaps the
/// config directory in either direction (re-checked on
/// every request).
pub fn uidir_root_overlaps_config(config_dir: &Path, root: &Path) -> bool {
    let base = resolve_path_best_effort(config_dir);
    path_within(root, &base) || path_within(&base, root)
}

/// `serveUIDir`: serve one request from the on-disk
/// frontend root. `method` is the request method,
/// `path` the decoded request path (percent-decoding is
/// the dispatcher's job — see `server.rs`). Only GET
/// requests read disk files; anything else gets the shell.
pub fn serve_ui_dir(config_dir: &Path, ui_dir: &str, method: &str, path: &str) -> Resp {
    let root = resolve_against(config_dir, ui_dir);
    if uidir_root_overlaps_config(config_dir, &root) {
        return not_found_resp();
    }
    // /api/v1 precedence: an API path that fell through to
    // the static handler never reads a disk file.
    if path == "/api/v1" || path.starts_with("/api/v1/") {
        return serve_ui_dir_shell(config_dir, &root);
    }
    if method != "GET" {
        return serve_ui_dir_shell(config_dir, &root);
    }
    let rel = path.strip_prefix('/').unwrap_or(path);
    // Dotfiles are never served on the request path.
    for comp in rel.split('/') {
        if comp != "." && comp != ".." && comp.starts_with('.') {
            return not_found_resp();
        }
    }
    let resolved = resolve_against(&root, rel);
    if !path_within(&resolved, &root) {
        return not_found_resp();
    }
    // A symlink at the resolved path is refused.
    let lst = std::fs::symlink_metadata(&resolved).ok();
    if let Some(lst) = &lst
        && lst.file_type().is_symlink()
    {
        return not_found_resp();
    }
    // Dotfiles are re-checked on the resolved,
    // root-relative path.
    let rel_resolved = match resolved.strip_prefix(&root) {
        Ok(r) => r.to_path_buf(),
        Err(_) => return not_found_resp(),
    };
    for comp in rel_resolved.components() {
        if let std::path::Component::Normal(name) = comp {
            let name = name.to_string_lossy();
            if name.starts_with('.') {
                return not_found_resp();
            }
        }
    }
    let st = match std::fs::metadata(&resolved) {
        Ok(st) => st,
        Err(_) => {
            // Missing file under a valid root: SPA fallback.
            return serve_ui_dir_shell(config_dir, &root);
        }
    };
    if st.is_dir() {
        // Directories never list: SPA fallback.
        return serve_ui_dir_shell(config_dir, &root);
    }
    if !st.is_file() {
        // FIFO, socket, device: fixed 404, never opened.
        return not_found_resp();
    }
    let data = match std::fs::read(&resolved) {
        Ok(data) => data,
        Err(_) => return error_resp(500, "internal_error", "internal error"),
    };
    // Open-then-verify: the opened file must be the same
    // file the Lstat saw (same inode), so a symlink swapped
    // in between the Lstat and the open is refused.
    if let Some(lst) = &lst
        && let Ok(fst) = std::fs::metadata(&resolved)
    {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if lst.ino() != fst.ino() || lst.dev() != fst.dev() {
                return not_found_resp();
            }
        }
    }
    let mut headers = shell_headers();
    headers.push((
        "Content-Type".to_string(),
        ui_dir_content_type(resolved.to_str().unwrap_or("")).to_string(),
    ));
    headers.push(("Content-Length".to_string(), data.len().to_string()));
    Resp {
        status: 200,
        headers,
        body: data,
    }
}

/// `serveUIDirShell`: serve the on-disk shell (the root's
/// `index.html`) for SPA fallback paths. A root whose
/// index.html vanished mid-run is a fixed 500; a symlinked
/// index.html is a fixed 404.
pub fn serve_ui_dir_shell(config_dir: &Path, root: &Path) -> Resp {
    if uidir_root_overlaps_config(config_dir, root) {
        return not_found_resp();
    }
    let index = root.join("index.html");
    let lst = match std::fs::symlink_metadata(&index) {
        Ok(lst) => lst,
        Err(_) => return error_resp(500, "internal_error", "internal error"),
    };
    if lst.file_type().is_symlink() {
        return not_found_resp();
    }
    if !lst.is_file() {
        return error_resp(500, "internal_error", "internal error");
    }
    let data = match std::fs::read(&index) {
        Ok(data) => data,
        Err(_) => return error_resp(500, "internal_error", "internal error"),
    };
    // Open-then-verify: same file the Lstat saw.
    if let Ok(fst) = std::fs::metadata(&index) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if lst.ino() != fst.ino() || lst.dev() != fst.dev() {
                return not_found_resp();
            }
        }
    }
    let headers = shell_headers();
    Resp {
        status: 200,
        headers,
        body: data,
    }
}
