// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Plugin host: lifecycle (`ApplyConfig`), the
//! `host.log`-only reverse callback, panic/timeout
//! isolation at the host boundary, and egress-proxy
//! adoption.
//!
//! Go source: `internal/pluginhost/host.go` (all of it).
//!
//! The loader and lifecycle mirror CLIProxyAPI's
//! pluginhost at pin 250d5981 (renamed into the castctl
//! namespace and cut down to the approved v1 design).
//! What was deliberately NOT copied is listed in
//! `docs/plugins.md`: `host.auth.*`, the
//! store/registry, `min_version`/`allow_downgrade`,
//! random shadow names, load-time signature checks,
//! and any sandbox promise.
//!
//! Trust boundary (BQ1, closed): plugins are trusted,
//! first-party, in-process, with no sandbox. A native
//! crash (segfault, Go runtime crash, `os.Exit`, memory
//! corruption) in plugin code cannot be contained by
//! this host; only host-adapter panics (recovered in
//! the guarded call) and plugin-returned envelope errors
//! are isolated. See `docs/plugins.md`
//! "Native-panic limit".
//!
//! Rust adaptations (recorded in PORTING.md, M6c):
//!
//!   - `Client`/`Loader` are traits; the fake client
//!     models Go panic-injection as an error variant
//!     (`ClientError::Panicked`), NOT a real panic. A
//!     real Rust panic inside a client call is still
//!     recovered by the guarded call
//!     (`catch_unwind`), with the recovered value's
//!     type reported the way Go's `%T` does.
//!   - The guarded call runs on a spawned thread and
//!     waits with `recv_timeout`; a timeout fuses the
//!     plugin and abandons the thread, like Go's
//!     ctx-cancellation path.
//!   - The egress proxy is held behind the
//!     `EgressProxyHandle` trait (`set_cookie_hosts` /
//!     `close`) so host tests need no async runtime; the
//!     concrete `egress::EgressProxy` implements it.
//!     Reference counting is by `Arc` pointer identity,
//!     like Go's pointer dedup.
//!   - `ApplyConfig` takes no context: registration
//!     calls run without a deadline (Go passes the
//!     `ApplyConfig` ctx, which callers supply as
//!     `Background`); `Call` takes an explicit
//!     `Option<Duration>` timeout instead.
//!   - The config fragment is parsed to JSON when
//!     building the register request; an invalid
//!     fragment fails fast at the host instead of being
//!     sent verbatim for the plugin to reject (Go sends
//!     the raw bytes via `json.RawMessage`).
//!   - `Host` state lives behind one `Mutex<HostState>`
//!     (Go's `mu`); `ApplyConfig` works on clones of
//!     the loaded entry and writes back, because Rust
//!     cannot hold a map entry across lock releases the
//!     way Go holds a `*loadedPlugin`.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::mpsc;
use std::time::Duration;

use crate::checksum::verify_file_checksum;
use crate::discovery::{PluginFile, validate_plugin_id};
use crate::error::PluginHostError;
use crate::loader;
use crate::pluginabi::{
    self, Capabilities, Command, Egress, Envelope, Identity, Metadata, RegisterRequest,
    Registration,
};
use crate::shadow::cleanup_shadow_dir;
use crate::text::{safe_plugin_text, strip_control_chars};

/// One loaded plugin image. `Call` exchanges one JSON
/// envelope (see `call_envelope`). `Shutdown` detaches
/// the client logically; the image is never unloaded.
/// Source: `Client` (`host.go:56-60`).
pub trait Client: Send + Sync {
    /// One envelope call. A transport failure is a
    /// `Transport` error (passes through unchanged); a
    /// host-adapter panic is modelled as `Panicked`
    /// (see `ClientError`).
    fn call(&self, method: &str, request: &[u8]) -> Result<Vec<u8>, ClientError>;
    /// Detach the client logically.
    fn shutdown(&self);
}

/// A client-call failure.
/// Source: the `(response, err)` pair of
/// `Client.Call` (`host.go:56-60`) plus the recovered
/// panic of the guarded call (`host.go:806-830`).
#[derive(Debug, Clone)]
pub enum ClientError {
    /// A transport failure: passes through unchanged.
    Transport(PluginHostError),
    /// A host-adapter panic, modelled as an error
    /// variant of the fake client (NOT a real panic).
    /// The payload is the recovered value's type name,
    /// as Go's `%T` reports it (a string panic is
    /// `"string"`).
    Panicked(String),
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientError::Transport(e) => write!(f, "{e}"),
            ClientError::Panicked(t) => write!(f, "panic: {t}"),
        }
    }
}

/// Opens a plugin file into a `Client`. The default
/// loader is the STOPPED loader (see `loader.rs`).
/// Source: `Loader` (`host.go:64-67`).
pub trait Loader: Send + Sync {
    /// Open `file` into a client. `host` is passed so
    /// a loader can dispatch reverse callbacks
    /// (`dispatch_host_call`) to it.
    fn open(&self, file: &PluginFile, host: &Host) -> Result<Arc<dyn Client>, PluginHostError>;
}

/// The STOPPED default loader: every open refuses with
/// `LoaderUnavailable`.
pub struct StoppedLoader;

impl Loader for StoppedLoader {
    fn open(&self, file: &PluginFile, _host: &Host) -> Result<Arc<dyn Client>, PluginHostError> {
        // `open_plugin` always refuses (see `loader.rs`);
        // the `?` propagates its `LoaderUnavailable`.
        loader::open_plugin(&file.path)?;
        Err(PluginHostError::LoaderUnavailable)
    }
}

/// The running loopback egress proxy, behind a narrow
/// trait so the host lifecycle stays testable without
/// an async runtime. Implemented by
/// `egress::EgressProxy`.
pub trait EgressProxyHandle: Send + Sync {
    /// Apply the plugin's declared cookie hosts
    /// (fail-closed: no declaration means no injection).
    fn set_cookie_hosts(&self, hosts: &[String]);
    /// Close the proxy, revoking its credentials.
    /// Idempotent.
    fn close(&self);
    /// Whether the proxy is closed (test seam).
    fn is_closed(&self) -> bool;
}

/// One plugin the caller wants loaded: a config entry
/// (tag/type/fragment) plus the binary path resolved by
/// discovery and the per-session handoff
/// (identity/egress). Two `Desired` entries may share
/// one path: each gets its own registration and its own
/// host-side state.
/// Source: `Desired` (`host.go:74-119`).
///
/// Manual `Debug`: `egress_proxy` is a trait object
/// (`Arc<dyn EgressProxyHandle>`), which has no `Debug`
/// impl; the proxy is shown by whether it is closed.
#[derive(Clone)]
pub struct Desired {
    /// Plugin tag.
    pub tag: String,
    /// Plugin type.
    pub type_: String,
    /// The plugin binary to load.
    pub path: String,
    /// The config fragment verbatim (entry object minus
    /// tag/type).
    pub fragment: Vec<u8>,
    /// The secret-stripped outbound identity, or `None`
    /// when the caller supplies none.
    pub identity: Option<Identity>,
    /// The per-session loopback proxy description, or
    /// `None` when the caller supplies none.
    pub egress: Option<Egress>,
    /// The loopback proxy this plugin's traffic goes
    /// through, owned by the wiring that built it. The
    /// host adopts it so its credentials die with the
    /// host. `None` means no proxy is handed over.
    /// Ownership: the host adopts the proxy only when a
    /// registration succeeds. If a fresh load fails, the
    /// proxy is never adopted and stays caller-owned.
    pub egress_proxy: Option<Arc<dyn EgressProxyHandle>>,
    /// When set, names a checksums.txt manifest the
    /// binary must verify against before it is loaded.
    pub manifest_path: String,
}

impl std::fmt::Debug for Desired {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Desired")
            .field("tag", &self.tag)
            .field("type_", &self.type_)
            .field("path", &self.path)
            .field("fragment", &self.fragment)
            .field("identity", &self.identity)
            .field("egress", &self.egress)
            .field(
                "egress_proxy_closed",
                &self.egress_proxy.as_ref().map(|p| p.is_closed()),
            )
            .field("manifest_path", &self.manifest_path)
            .finish()
    }
}

impl Desired {
    /// A minimal desired entry (tag/type/path only).
    #[must_use]
    pub fn new(tag: &str, type_: &str, path: &str) -> Self {
        Desired {
            tag: tag.to_string(),
            type_: type_.to_string(),
            path: path.to_string(),
            fragment: Vec::new(),
            identity: None,
            egress: None,
            egress_proxy: None,
            manifest_path: String::new(),
        }
    }
}

/// The host log callback: `fn(level, message)`.
type LogFn = Arc<dyn Fn(&str, &str) + Send + Sync>;

/// Options configuring a `Host`.
/// Source: `Options` (`host.go:121-130`).
#[derive(Default)]
pub struct Options {
    /// Overrides the default (STOPPED) loader; tests
    /// use a fake. `None` means the default loader.
    pub loader: Option<Box<dyn Loader>>,
    /// Receives host.log callback entries and lifecycle
    /// warnings. It must not block: it may be called
    /// from a plugin thread. `None` discards.
    pub log: Option<LogFn>,
}

/// The host-side view of a registered plugin.
/// Source: `LoadedPlugin` (`host.go:152-160`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedPlugin {
    /// Plugin tag.
    pub tag: String,
    /// Plugin type.
    pub type_: String,
    /// Plugin metadata.
    pub metadata: Metadata,
    /// Declared capabilities.
    pub capabilities: Capabilities,
    /// Schema version.
    pub schema_version: u32,
    /// Commands (only with `command_provider`).
    pub commands: Vec<Command>,
    /// The loaded image's path.
    pub path: String,
}

/// One desired plugin `ApplyConfig` did not load, with
/// the reason (a warn-and-skip record, never a secret
/// value).
/// Source: `Skipped` (`host.go:164-167`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skipped {
    /// Plugin tag.
    pub tag: String,
    /// Skip reason.
    pub reason: String,
}

/// The result of `ApplyConfig`: the tags that are loaded
/// AND callable afterwards, and the desired entries that
/// were skipped. A tag is never in `Loaded` when a fuse
/// is recorded for its loaded path and generation, even
/// when its image is still resident.
/// Source: `ApplyReport` (`host.go:169-177`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ApplyReport {
    /// Loaded and callable tags.
    pub loaded: Vec<String>,
    /// Skipped entries with reasons.
    pub skipped: Vec<Skipped>,
}

/// Why a plugin is fused and WHICH image was fused: its
/// path and its load generation. A fuse is per path AND
/// generation.
/// Source: `fusedEntry` (`host.go:142-150`).
#[derive(Debug, Clone)]
struct FusedEntry {
    reason: String,
    path: String,
    generation: u64,
}

#[derive(Clone)]
struct LoadedEntry {
    desired: Desired,
    client: Arc<dyn Client>,
    registered: bool,
    metadata: Metadata,
    capabilities: Capabilities,
    schema: u32,
    commands: Vec<Command>,
    path: String,
    generation: u64,
    egress: Option<Arc<dyn EgressProxyHandle>>,
}

struct HostState {
    loaded: HashMap<String, LoadedEntry>,
    fused: HashMap<String, FusedEntry>,
    /// The next load generation, monotonically
    /// increasing for the life of the host: each loaded
    /// image gets a distinct generation, so a fuse
    /// recorded for a superseded image can never be
    /// mistaken for the current image's fuse.
    next_gen: u64,
}

/// Owns loaded plugins and applies desired
/// configurations to them. A `Host` is safe for
/// concurrent use: `ApplyConfig` calls serialize, and
/// `Call` may run concurrently with `ApplyConfig` for a
/// different tag.
/// Source: `Host` (`host.go:132-149`).
pub struct Host {
    loader: Box<dyn Loader>,
    log: Option<LogFn>,
    apply_mu: Mutex<()>,
    state: Mutex<HostState>,
    egress_mu: Mutex<Vec<Arc<dyn EgressProxyHandle>>>,
}

/// Identifies one loaded plugin image for a guarded
/// call: the tag, the image path, and its generation.
/// A panic or timeout fuses exactly this image.
struct CallTarget<'a> {
    tag: &'a str,
    path: &'a str,
    generation: u64,
}

impl Host {
    /// Build a `Host`. No plugin is loaded until
    /// `ApplyConfig`. Constructing a host sweeps stale
    /// shadow directories left by dead processes
    /// (best-effort).
    /// Source: `New` (`host.go:193-208`).
    #[must_use]
    pub fn new(opts: Options) -> Host {
        let loader: Box<dyn Loader> = opts.loader.unwrap_or_else(|| Box::new(StoppedLoader));
        crate::shadow::sweep_stale_shadow_dirs();
        Host {
            loader,
            log: opts.log,
            apply_mu: Mutex::new(()),
            state: Mutex::new(HostState {
                loaded: HashMap::new(),
                fused: HashMap::new(),
                next_gen: 0,
            }),
            egress_mu: Mutex::new(Vec::new()),
        }
    }

    fn logf(&self, level: &str, message: &str) {
        if let Some(log) = &self.log {
            log(level, message);
        }
    }

    /// Whether `tag` is fused (skipped until replaced),
    /// and the fuse reason.
    /// Source: `Fused` (`host.go:214-220`).
    #[must_use]
    pub fn fused(&self, tag: &str) -> Option<String> {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .fused
            .get(tag)
            .map(|e| e.reason.clone())
    }

    /// The registered plugin for `tag`, if any. A fuse
    /// is per path and generation: only a fuse recorded
    /// for the loaded image's own path and generation
    /// hides it.
    /// Source: `Loaded` (`host.go:228-252`).
    #[must_use]
    pub fn loaded(&self, tag: &str) -> Option<LoadedPlugin> {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let lp = state.loaded.get(tag)?;
        if !lp.registered {
            return None;
        }
        if let Some(entry) = state.fused.get(tag)
            && entry.path == lp.path
            && entry.generation == lp.generation
        {
            return None;
        }
        Some(LoadedPlugin {
            tag: lp.desired.tag.clone(),
            type_: lp.desired.type_.clone(),
            metadata: lp.metadata.clone(),
            capabilities: lp.capabilities,
            schema_version: lp.schema,
            commands: lp.commands.clone(),
            path: lp.path.clone(),
        })
    }

    /// Register a loopback proxy with the host so
    /// `Close` closes it (revoking its credentials).
    /// The host never creates proxies and never adopts
    /// the same proxy twice. Adoption is
    /// reference-counted by pointer across loaded tags.
    /// Source: `AdoptEgress` (`host.go:263-285`).
    pub fn adopt_egress(&self, p: &Arc<dyn EgressProxyHandle>) {
        let mut egresses = self.egress_mu.lock().unwrap_or_else(|e| e.into_inner());
        if egresses.iter().any(|e| Arc::ptr_eq(e, p)) {
            return;
        }
        egresses.push(Arc::clone(p));
    }

    /// Close `p` when no loaded tag references it
    /// anymore (reference-counted by pointer).
    /// Source: `maybeCloseEgress` (`host.go:297-316`).
    fn maybe_close_egress(&self, p: &Arc<dyn EgressProxyHandle>) {
        let refs = {
            let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            state
                .loaded
                .values()
                .filter(|lp| lp.egress.as_ref().is_some_and(|e| Arc::ptr_eq(e, p)))
                .count()
        };
        if refs == 0 {
            p.close();
        }
    }

    /// Shut down every loaded plugin (detach only;
    /// images stay mapped), close adopted egress proxies
    /// (revoking their credentials), remove this
    /// process's shadow directory, and clear host state.
    /// Idempotent. Serialises against `ApplyConfig` via
    /// `apply_mu`.
    /// Source: `Close` (`host.go:327-354`).
    pub fn close(&self) {
        let _apply = self.apply_mu.lock().unwrap_or_else(|e| e.into_inner());
        let (clients, proxies) = {
            let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            let clients: Vec<Arc<dyn Client>> = state
                .loaded
                .values()
                .map(|lp| Arc::clone(&lp.client))
                .collect();
            state.loaded.clear();
            state.fused.clear();
            drop(state);
            let mut egresses = self.egress_mu.lock().unwrap_or_else(|e| e.into_inner());
            let proxies = std::mem::take(&mut *egresses);
            (clients, proxies)
        };
        for c in clients {
            c.shutdown();
        }
        for p in proxies {
            p.close();
        }
        // Best-effort: a shadow-cleanup failure must
        // never fail shutdown.
        cleanup_shadow_dir();
    }

    /// Load, reconfigure, replace, and detach plugins
    /// to match `desired`. A per-plugin failure never
    /// fails the whole call: it is recorded in the
    /// report and the previously loaded plugin (if any)
    /// keeps running. Returns only when every desired
    /// entry has been attempted.
    /// Source: `ApplyConfig` (`host.go:367-535`).
    pub fn apply_config(&self, desired: Vec<Desired>) -> ApplyReport {
        let _apply = self.apply_mu.lock().unwrap_or_else(|e| e.into_inner());
        let mut report = ApplyReport::default();
        let mut seen: HashMap<String, bool> = HashMap::new();
        let mut desired_by_tag: HashMap<String, Desired> = HashMap::new();
        let mut ordered: Vec<Desired> = Vec::new();
        for d in desired {
            if seen.contains_key(&d.tag) {
                report.skipped.push(Skipped {
                    tag: d.tag.clone(),
                    reason: "duplicate plugin tag in desired config".to_string(),
                });
                continue;
            }
            seen.insert(d.tag.clone(), true);
            desired_by_tag.insert(d.tag.clone(), d.clone());
            ordered.push(d);
        }

        // Detach unselected plugins. Shutdown calls run
        // outside the state lock; detached egress proxies
        // are released after the map update.
        let (detached, detached_egress) = {
            let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            let mut detached = Vec::new();
            let mut detached_egress = Vec::new();
            let tags: Vec<String> = state.loaded.keys().cloned().collect();
            for tag in tags {
                if !desired_by_tag.contains_key(&tag) {
                    if let Some(lp) = state.loaded.remove(&tag) {
                        detached.push(lp.client);
                        if let Some(e) = lp.egress {
                            detached_egress.push(e);
                        }
                    }
                    state.fused.remove(&tag);
                }
            }
            (detached, detached_egress)
        };
        for c in detached {
            c.shutdown();
        }
        for p in detached_egress {
            self.maybe_close_egress(&p);
        }

        for d in ordered {
            let (fuse_entry, is_fused, existing) = {
                let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
                (
                    state.fused.get(&d.tag).cloned(),
                    state.fused.contains_key(&d.tag),
                    state.loaded.get(&d.tag).cloned(),
                )
            };
            // A fuse is per-path: the same path stays
            // fused (skipped), a different path replaces
            // and clears the fuse.
            if is_fused {
                if let Some(fuse) = &fuse_entry
                    && fuse.path == d.path
                {
                    report.skipped.push(Skipped {
                        tag: d.tag.clone(),
                        reason: format!("fused: {}", strip_control_chars(&fuse.reason)),
                    });
                    continue;
                }
                self.state
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .fused
                    .remove(&d.tag);
            }
            if let Some(mut existing) = existing {
                if existing.path == d.path {
                    // Same image: reconfigure in place.
                    if let Err(err) = self.reconfigure(&mut existing, &d, true) {
                        // Rollback: re-register with the
                        // old fragment.
                        let old_desired = existing.desired.clone();
                        if let Err(rerr) = self.register(&mut existing, &old_desired, true) {
                            self.fuse(
                                &d.tag,
                                &format!(
                                    "reconfigure failed and rollback failed: {}",
                                    short_err(&rerr)
                                ),
                                &existing.path,
                                existing.generation,
                            );
                            self.state
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .loaded
                                .remove(&d.tag);
                            existing.client.shutdown();
                            if let Some(e) = &existing.egress {
                                let e = Arc::clone(e);
                                self.maybe_close_egress(&e);
                            }
                            report.skipped.push(Skipped {
                                tag: d.tag.clone(),
                                reason: "reconfigure failed and rollback failed".to_string(),
                            });
                        } else {
                            report.skipped.push(Skipped {
                                tag: d.tag.clone(),
                                reason: "reconfigure failed, rolled back to previous config"
                                    .to_string(),
                            });
                            if !self.fused_for_loaded(&d.tag, &existing) {
                                report.loaded.push(d.tag.clone());
                            }
                        }
                        let _ = err;
                        continue;
                    }
                    report.loaded.push(d.tag.clone());
                    continue;
                }
                // Different image: quiesce before replace.
                // A quiesce failure is logged, never fatal.
                if self.quiesce(&existing).is_err() {
                    self.logf("warn", &format!("plugin quiesce failed for tag {}", d.tag));
                }
                match self.load_one(&d) {
                    Err(_) => {
                        // Rollback: re-register the old
                        // image with its old fragment.
                        let old_desired = existing.desired.clone();
                        if let Err(rerr) = self.register(&mut existing, &old_desired, true) {
                            self.fuse(
                                &d.tag,
                                &format!(
                                    "replacement failed and rollback failed: {}",
                                    short_err(&rerr)
                                ),
                                &existing.path,
                                existing.generation,
                            );
                            self.state
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .loaded
                                .remove(&d.tag);
                            existing.client.shutdown();
                            if let Some(e) = &existing.egress {
                                let e = Arc::clone(e);
                                self.maybe_close_egress(&e);
                            }
                            report.skipped.push(Skipped {
                                tag: d.tag.clone(),
                                reason: "replacement failed and rollback failed".to_string(),
                            });
                        } else {
                            report.skipped.push(Skipped {
                                tag: d.tag.clone(),
                                reason: "replacement failed, rolled back to previous image"
                                    .to_string(),
                            });
                            if !self.fused_for_loaded(&d.tag, &existing) {
                                report.loaded.push(d.tag.clone());
                            }
                        }
                        continue;
                    }
                    Ok(replacement) => {
                        // Shut the old image down before
                        // installing the replacement,
                        // outside the state lock.
                        existing.client.shutdown();
                        {
                            let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
                            state.loaded.insert(d.tag.clone(), replacement);
                            state.fused.remove(&d.tag);
                        }
                        if let Some(e) = &existing.egress {
                            let e = Arc::clone(e);
                            self.maybe_close_egress(&e);
                        }
                        report.loaded.push(d.tag.clone());
                        continue;
                    }
                }
            }
            // Fresh load.
            match self.load_one(&d) {
                Err(err) => {
                    report.skipped.push(Skipped {
                        tag: d.tag.clone(),
                        reason: short_err(&err),
                    });
                    continue;
                }
                Ok(lp) => {
                    self.state
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .loaded
                        .insert(d.tag.clone(), lp);
                    self.state
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .fused
                        .remove(&d.tag);
                    report.loaded.push(d.tag.clone());
                }
            }
        }
        report
    }

    /// Whether a fuse is recorded for `lp`'s own path
    /// and generation. It never clears the fuse.
    /// Source: `fusedForLoaded` (`host.go:592-601`).
    fn fused_for_loaded(&self, tag: &str, lp: &LoadedEntry) -> bool {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        match state.fused.get(tag) {
            Some(entry) => entry.path == lp.path && entry.generation == lp.generation,
            None => false,
        }
    }

    fn fuse(&self, tag: &str, reason: &str, path: &str, generation: u64) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        // A fuse recorded for a superseded image must
        // NEVER overwrite the fuse of the currently
        // loaded image: a stale in-flight timeout fuse
        // landing after a newer panic fuse would
        // otherwise make the panicking image callable
        // again. When no image is loaded the fuse is
        // recorded as-is.
        if let Some(cur) = state.loaded.get(tag)
            && let Some(existing) = state.fused.get(tag)
            && existing.path == cur.path
            && existing.generation == cur.generation
            && (path != cur.path || generation != cur.generation)
        {
            return;
        }
        state.fused.insert(
            tag.to_string(),
            FusedEntry {
                reason: reason.to_string(),
                path: path.to_string(),
                generation,
            },
        );
    }

    /// The next monotonically increasing load
    /// generation. Generations are never reused within a
    /// host's life, including across `Close`.
    /// Source: `nextGeneration` (`host.go:603-608`).
    fn next_generation(&self) -> u64 {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.next_gen += 1;
        state.next_gen
    }

    fn store_loaded(&self, tag: &str, entry: LoadedEntry) {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .loaded
            .insert(tag.to_string(), entry);
    }

    /// Open (the loader shadow-copies and compat-gates)
    /// and register one desired plugin. On any failure
    /// the client is detached and the error returned.
    /// Source: `loadOne` (`host.go:617-649`).
    fn load_one(&self, d: &Desired) -> Result<LoadedEntry, PluginHostError> {
        // Tag and type are validated at the Host layer
        // with the same regex as config/discovery BEFORE
        // any filename use.
        if !validate_plugin_id(&d.tag) {
            return Err(PluginHostError::invalid(format!(
                "invalid plugin tag {:?}",
                d.tag
            )));
        }
        if !validate_plugin_id(&d.type_) {
            return Err(PluginHostError::invalid(format!(
                "invalid plugin type {:?}",
                d.type_
            )));
        }
        if d.path.is_empty() {
            return Err(PluginHostError::invalid(format!(
                "plugin {:?} has no binary path",
                d.tag
            )));
        }
        if !d.manifest_path.is_empty() {
            verify_file_checksum(
                std::path::Path::new(&d.path),
                std::path::Path::new(&d.manifest_path),
            )?;
        }
        let file = PluginFile {
            id: d.tag.clone(),
            path: std::path::PathBuf::from(&d.path),
            version: String::new(),
            manifest_path: std::path::PathBuf::from(&d.manifest_path),
        };
        let client = self.loader.open(&file, self)?;
        let mut lp = LoadedEntry {
            desired: d.clone(),
            client: Arc::clone(&client),
            registered: false,
            metadata: Metadata {
                name: String::new(),
                version: String::new(),
                author: String::new(),
                github_repository: String::new(),
            },
            capabilities: Capabilities {
                provider: false,
                command_provider: false,
            },
            schema: 0,
            commands: Vec::new(),
            path: d.path.clone(),
            generation: self.next_generation(),
            egress: None,
        };
        if let Err(err) = self.register(&mut lp, d, false) {
            client.shutdown();
            return Err(err);
        }
        Ok(lp)
    }

    /// Marshal one register/reconfigure request (the
    /// fragment is sent verbatim; an empty fragment is
    /// sent as `{}`) and return the validated
    /// registration. Register and reconfigure differ
    /// only in the method name.
    /// Source: `sendRegistration` (`host.go:656-684`).
    fn send_registration(
        &self,
        lp: &LoadedEntry,
        method: &str,
        d: &Desired,
    ) -> Result<(Registration, u32), PluginHostError> {
        let fragment: serde_json::Value = if d.fragment.is_empty() {
            serde_json::Value::Object(serde_json::Map::new())
        } else {
            serde_json::from_slice(&d.fragment).map_err(|e| {
                PluginHostError::invalid(format!(
                    "plugin {:?} fragment is not valid json: {e}",
                    d.tag
                ))
            })?
        };
        let req = RegisterRequest {
            config_json: fragment,
            schema_version: pluginabi::SCHEMA_VERSION,
            tag: d.tag.clone(),
            type_: d.type_.clone(),
            identity: d.identity.clone(),
            egress: d.egress.clone(),
        };
        let req_bytes = serde_json::to_vec(&req).map_err(|e| {
            PluginHostError::failed(format!("cannot marshal register request: {e}"))
        })?;
        let result = self.call_envelope(lp, method, &req_bytes)?;
        let reg: Registration = serde_json::from_slice(&result).map_err(|e| {
            PluginHostError::failed(format!(
                "plugin {:?} registration is not valid json: {e}",
                d.tag
            ))
        })?;
        let schema = pluginabi::validate_registration(&reg)
            .map_err(|e| PluginHostError::failed(format!("plugin {:?}: {e}", d.tag)))?;
        Ok((reg, schema))
    }

    /// Store a validated registration on `lp` and
    /// return its previous egress proxy (the caller
    /// releases it after writing `lp` back to the map,
    /// so the refcount scan sees the new state).
    /// Source: `applyRegistration` (`host.go:693-725`).
    fn apply_registration(
        &self,
        lp: &mut LoadedEntry,
        d: &Desired,
        reg: &Registration,
        schema: u32,
    ) -> Option<Arc<dyn EgressProxyHandle>> {
        lp.metadata = reg.metadata.clone();
        lp.capabilities = reg.capabilities;
        lp.schema = schema;
        lp.commands = reg.commands.clone();
        lp.desired = d.clone();
        lp.registered = true;
        let old_egress = lp.egress.clone();
        if d.egress_proxy.is_some() {
            lp.egress = d.egress_proxy.clone();
        }
        old_egress
    }

    /// Send `plugin.register` and apply the
    /// schema/metadata/capability gate. When `in_map`
    /// is true the entry is already in the map and is
    /// written back before the egress side effects run
    /// (so `maybe_close_egress` scans the new state).
    /// Source: `register` (`host.go:730-737`).
    fn register(
        &self,
        lp: &mut LoadedEntry,
        d: &Desired,
        in_map: bool,
    ) -> Result<(), PluginHostError> {
        let (reg, schema) = self.send_registration(lp, pluginabi::METHOD_PLUGIN_REGISTER, d)?;
        let old_egress = self.apply_registration(lp, d, &reg, schema);
        if in_map {
            self.store_loaded(&d.tag, lp.clone());
        }
        if let Some(proxy) = &d.egress_proxy {
            self.adopt_egress(proxy);
        }
        // Nil EgressProxy keeps the existing proxy: the
        // new registration's cookie scope still applies
        // to it.
        if let Some(egress) = &lp.egress {
            egress.set_cookie_hosts(&reg.cookie_hosts);
        }
        if let Some(old) = old_egress {
            let same = lp.egress.as_ref().is_some_and(|cur| Arc::ptr_eq(&old, cur));
            if !same {
                self.maybe_close_egress(&old);
            }
        }
        Ok(())
    }

    /// Send `plugin.reconfigure` (same shape as
    /// `register`).
    /// Source: `reconfigure` (`host.go:739-746`).
    fn reconfigure(
        &self,
        lp: &mut LoadedEntry,
        d: &Desired,
        in_map: bool,
    ) -> Result<(), PluginHostError> {
        let (reg, schema) = self.send_registration(lp, pluginabi::METHOD_PLUGIN_RECONFIGURE, d)?;
        let old_egress = self.apply_registration(lp, d, &reg, schema);
        if in_map {
            self.store_loaded(&d.tag, lp.clone());
        }
        if let Some(proxy) = &d.egress_proxy {
            self.adopt_egress(proxy);
        }
        if let Some(egress) = &lp.egress {
            egress.set_cookie_hosts(&reg.cookie_hosts);
        }
        if let Some(old) = old_egress {
            let same = lp.egress.as_ref().is_some_and(|cur| Arc::ptr_eq(&old, cur));
            if !same {
                self.maybe_close_egress(&old);
            }
        }
        Ok(())
    }

    /// Send `plugin.quiesce` (`{}` request).
    /// Source: `quiesce` (`host.go:748-751`).
    fn quiesce(&self, lp: &LoadedEntry) -> Result<(), PluginHostError> {
        self.call_envelope(lp, pluginabi::METHOD_PLUGIN_QUIESCE, b"{}")
            .map(|_| ())
    }

    /// Send one envelope method call to a loaded plugin
    /// and return the envelope Result on success.
    /// `timeout` bounds the wait: on expiry the plugin
    /// is fused and the call abandoned (the plugin
    /// thread keeps running). `None` waits without a
    /// deadline (registration/quiesce calls).
    /// Source: `Call` (`host.go:773-805`) and
    /// `callEnvelopeClient` (`host.go:819-857`).
    pub fn call(
        &self,
        tag: &str,
        method: &str,
        request: &[u8],
        timeout: Option<Duration>,
    ) -> Result<Vec<u8>, PluginHostError> {
        let (client, path, generation) = {
            let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            let lp = state.loaded.get(tag);
            let fuse_entry = state.fused.get(tag).cloned();
            let is_fused = state.fused.contains_key(tag);
            let (client, path, generation, ok) = match lp {
                Some(lp) => (
                    Some(Arc::clone(&lp.client)),
                    lp.path.clone(),
                    lp.generation,
                    true,
                ),
                None => (None, String::new(), 0, false),
            };
            // A fused plugin is never re-called: fail
            // fast with the stored fuse reason. Only a
            // fuse recorded for this image's own path and
            // generation fail-fasts.
            if is_fused
                && let Some(fuse) = fuse_entry
                && (!ok || (fuse.path == path && fuse.generation == generation))
            {
                return Err(PluginHostError::failed(format!(
                    "plugin {tag:?} is fused: {}",
                    fuse.reason
                )));
            }
            (client, path, generation)
        };
        let Some(client) = client else {
            return Err(PluginHostError::failed(format!(
                "plugin {tag:?} is not loaded"
            )));
        };
        self.call_envelope_client(
            &client,
            method,
            request,
            CallTarget {
                tag,
                path: &path,
                generation,
            },
            timeout,
        )
    }

    /// The guarded call for a loaded entry
    /// (registration, reconfigure, quiesce): no
    /// deadline.
    /// Source: `callEnvelope` (`host.go:808-817`).
    fn call_envelope(
        &self,
        lp: &LoadedEntry,
        method: &str,
        request: &[u8],
    ) -> Result<Vec<u8>, PluginHostError> {
        self.call_envelope_client(
            &lp.client,
            method,
            request,
            CallTarget {
                tag: &lp.desired.tag,
                path: &lp.path,
                generation: lp.generation,
            },
            None,
        )
    }

        /// The guarded call: the call runs on a spawned
    /// thread, a recovered panic fuses the plugin, and
    /// a timeout abandons the call without killing the
    /// plugin thread.
    /// Source: `callEnvelopeClient` (`host.go:819-857`).
    fn call_envelope_client(
        &self,
        client: &Arc<dyn Client>,
        method: &str,
        request: &[u8],
        target: CallTarget<'_>,
        timeout: Option<Duration>,
    ) -> Result<Vec<u8>, PluginHostError> {
        enum Outcome {
            Ok(Vec<u8>),
            Transport(PluginHostError),
            Panicked(String),
        }
        let (tx, rx) = mpsc::channel::<Outcome>();
        let client = Arc::clone(client);
        let method_owned = method.to_string();
        let request_owned = request.to_vec();
        std::thread::spawn(move || {
            let outcome = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                client.call(&method_owned, &request_owned)
            })) {
                Ok(Ok(bytes)) => Outcome::Ok(bytes),
                Ok(Err(ClientError::Transport(e))) => Outcome::Transport(e),
                Ok(Err(ClientError::Panicked(t))) => Outcome::Panicked(t),
                Err(payload) => {
                    let type_name = if payload.is::<&str>() || payload.is::<String>() {
                        "string"
                    } else {
                        "unknown"
                    };
                    Outcome::Panicked(type_name.to_string())
                }
            };
            let _ = tx.send(outcome);
        });
        let received = match timeout {
            Some(d) => rx.recv_timeout(d),
            None => rx.recv().map_err(|_| mpsc::RecvTimeoutError::Disconnected),
        };
        match received {
            Ok(Outcome::Ok(bytes)) => parse_envelope(&bytes, target.tag),
            Ok(Outcome::Transport(e)) => Err(e),
            Ok(Outcome::Panicked(type_name)) => {
                let reason = format!("{method} panic: {type_name}");
                self.fuse(target.tag, &reason, target.path, target.generation);
                Err(PluginHostError::failed(format!("plugin {:?}: {reason}", target.tag)))
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                self.fuse(
                    target.tag,
                    &format!("call timed out or cancelled: {method}"),
                    target.path,
                    target.generation,
                );
                Err(PluginHostError::failed("context deadline exceeded"))
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                let reason = format!("{method} panic: unknown");
                self.fuse(target.tag, &reason, target.path, target.generation);
                Err(PluginHostError::failed(format!("plugin {:?}: {reason}", target.tag)))
            }
        }
    }

    /// Handle one reverse callback from a plugin. The
    /// allowlist has exactly one method, `host.log`.
    /// Everything else is rejected with an error
    /// envelope. The returned bytes are always an
    /// envelope.
    /// Source: `dispatchHostCall` (`host.go:899-954`).
    pub fn dispatch_host_call(&self, method: &str, request: &[u8]) -> Vec<u8> {
        if method != pluginabi::METHOD_HOST_LOG {
            let env = pluginabi::new_error_envelope(
                "unsupported_host_callback",
                &format!("unsupported host callback {method}"),
            );
            return serde_json::to_vec(&env).unwrap_or_default();
        }
        #[derive(serde::Deserialize)]
        struct HostLogRequest {
            #[serde(default)]
            level: String,
            #[serde(default)]
            message: String,
        }
        let req: HostLogRequest = match serde_json::from_slice(request) {
            Ok(r) => r,
            Err(e) => {
                let env = pluginabi::new_error_envelope(
                    "invalid_host_log_request",
                    &format!("decode host log request: {e}"),
                );
                return serde_json::to_vec(&env).unwrap_or_default();
            }
        };
        let mut message = req.message.trim().to_string();
        if message.is_empty() {
            message = "plugin log".to_string();
        }
        message = strip_control_chars(&message);
        message = safe_plugin_text(&message);
        // The level is an allowlist, not free text:
        // unknown levels become "info".
        let mut level = req.level.trim().to_ascii_lowercase();
        match level.as_str() {
            "info" | "warn" | "warning" | "error" | "debug" => {}
            _ => level = "info".to_string(),
        }
        if level == "warning" {
            level = "warn".to_string();
        }
        self.logf(&level, &message);
        let env = Envelope {
            ok: true,
            result: Some(serde_json::Value::Object(serde_json::Map::new())),
            error: None,
        };
        serde_json::to_vec(&env).unwrap_or_default()
    }
}

/// Skip reasons are rendered output: strip control
/// characters BEFORE the cap/redact path, so a
/// plugin-chosen newline or escape in a loader error
/// can never forge a second output line or inject a
/// terminal sequence downstream.
/// Source: `shortErr` (`host.go:537-549`).
fn short_err(err: &PluginHostError) -> String {
    safe_plugin_text(&strip_control_chars(&err.to_string()))
}

/// Decode one response envelope. A non-JSON or error
/// envelope is an error; an ok envelope yields Result
/// (empty when absent).
/// Source: `parseEnvelope` (`host.go:860-880`).
fn parse_envelope(response: &[u8], tag: &str) -> Result<Vec<u8>, PluginHostError> {
    let env: Envelope = serde_json::from_slice(response).map_err(|e| {
        PluginHostError::failed(format!("plugin {tag:?} returned invalid envelope: {e}"))
    })?;
    if !env.ok {
        if let Some(err) = env.error {
            return Err(PluginHostError::failed(format!(
                "plugin {tag:?}: {}: {}",
                strip_control_chars(&err.code),
                safe_plugin_text(&strip_control_chars(&err.message))
            )));
        }
        return Err(PluginHostError::failed(format!(
            "plugin {tag:?} returned a failed envelope without an error"
        )));
    }
    match env.result {
        Some(v) => serde_json::to_vec(&v)
            .map_err(|e| PluginHostError::failed(format!("cannot marshal envelope result: {e}"))),
        None => Ok(Vec::new()),
    }
}

/// Whether bytes decode as a failed envelope. The
/// loader uses it to distinguish a plugin error
/// envelope from a transport failure.
/// Source: `isErrorEnvelope` (`host.go:883-890`).
#[must_use]
pub fn is_error_envelope(response: &[u8]) -> bool {
    match serde_json::from_slice::<Envelope>(response) {
        Ok(env) => !env.ok && env.error.is_some(),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Instant;

    // -- fakes (ports of internal/plugintest/fake.go) --

    fn register_response(
        schema: u32,
        name: &str,
        version: &str,
        author: &str,
        caps: Capabilities,
    ) -> Vec<u8> {
        let reg = Registration {
            schema_version: schema,
            metadata: Metadata {
                name: name.to_string(),
                version: version.to_string(),
                author: author.to_string(),
                github_repository: "https://github.com/thoitiettxl-cyber/castctl".to_string(),
            },
            capabilities: caps,
            commands: vec![],
            cookie_hosts: vec![],
        };
        let env = Envelope {
            ok: true,
            result: Some(serde_json::to_value(reg).unwrap()),
            error: None,
        };
        serde_json::to_vec(&env).unwrap()
    }

    fn ok_response(result: serde_json::Value) -> Vec<u8> {
        let env = Envelope {
            ok: true,
            result: Some(result),
            error: None,
        };
        serde_json::to_vec(&env).unwrap()
    }

    fn error_response(code: &str, message: &str) -> Vec<u8> {
        serde_json::to_vec(&pluginabi::new_error_envelope(code, message)).unwrap()
    }

    /// The fake-client call hook: `fn(method, request) -> response`.
    type CallHook =
        Arc<dyn Fn(&str, &[u8]) -> Result<Vec<u8>, ClientError> + Send + Sync>;

    struct FakeClientInner {
        calls: Vec<(String, Vec<u8>)>,
        shutdowns: usize,
        on_call: Option<CallHook>,
        panic_methods: HashSet<String>,
        block_methods: HashSet<String>,
    }

    pub struct FakeClient {
        inner: Mutex<FakeClientInner>,
    }

    impl FakeClient {
        fn new() -> Arc<FakeClient> {
            Arc::new(FakeClient {
                inner: Mutex::new(FakeClientInner {
                    calls: Vec::new(),
                    shutdowns: 0,
                    on_call: None,
                    panic_methods: HashSet::new(),
                    block_methods: HashSet::new(),
                }),
            })
        }

        fn set_on_call(&self, f: CallHook) {
            self.inner.lock().unwrap().on_call = Some(f);
        }

        fn clear_on_call(&self) {
            self.inner.lock().unwrap().on_call = None;
        }

        fn set_panic_methods(&self, methods: &[&str]) {
            self.inner.lock().unwrap().panic_methods =
                methods.iter().map(|s| s.to_string()).collect();
        }

        fn set_block_methods(&self, methods: &[&str]) {
            self.inner.lock().unwrap().block_methods =
                methods.iter().map(|s| s.to_string()).collect();
        }

        fn call_count(&self, method: &str) -> usize {
            self.inner
                .lock()
                .unwrap()
                .calls
                .iter()
                .filter(|(m, _)| m == method)
                .count()
        }

        fn last_request(&self, method: &str) -> Option<Vec<u8>> {
            self.inner
                .lock()
                .unwrap()
                .calls
                .iter()
                .rev()
                .find(|(m, _)| m == method)
                .map(|(_, r)| r.clone())
        }

        fn shutdowns(&self) -> usize {
            self.inner.lock().unwrap().shutdowns
        }
    }

    impl Client for FakeClient {
        fn call(&self, method: &str, request: &[u8]) -> Result<Vec<u8>, ClientError> {
            let (on_call, panics, blocks) = {
                let mut inner = self.inner.lock().unwrap();
                inner.calls.push((method.to_string(), request.to_vec()));
                (
                    inner.on_call.clone(),
                    inner.panic_methods.contains(method),
                    inner.block_methods.contains(method),
                )
            };
            // Panic injection is modelled as an error
            // variant, NOT a real panic (see the module
            // docs). Go panics with a string, so %T is
            // "string".
            if panics {
                return Err(ClientError::Panicked("string".to_string()));
            }
            if blocks {
                // Block forever: the guarded call's
                // timeout abandons this thread, like
                // Go's ctx-cancellation path.
                loop {
                    std::thread::park();
                }
            }
            if let Some(f) = on_call {
                return f(method, request);
            }
            match method {
                pluginabi::METHOD_PLUGIN_REGISTER | pluginabi::METHOD_PLUGIN_RECONFIGURE => {
                    Ok(register_response(
                        1,
                        "fake",
                        "0.1.0",
                        "plugintest",
                        Capabilities {
                            provider: true,
                            command_provider: false,
                        },
                    ))
                }
                pluginabi::METHOD_PLUGIN_QUIESCE => Ok(ok_response(serde_json::json!({}))),
                pluginabi::METHOD_PROVIDER_CALL => {
                    let req: serde_json::Value =
                        serde_json::from_slice(request).unwrap_or(serde_json::Value::Null);
                    let input = req.get("input").and_then(|v| v.as_str()).unwrap_or("");
                    Ok(ok_response(
                        serde_json::json!({"payload": format!("echo:{input}")}),
                    ))
                }
                _ => Ok(error_response(
                    "unknown_method",
                    &format!("unknown method: {method}"),
                )),
            }
        }

        fn shutdown(&self) {
            self.inner.lock().unwrap().shutdowns += 1;
        }
    }

    /// The fake-loader open hook: `fn(file, host) -> client`.
    type OpenFn = Arc<
        dyn Fn(&PluginFile, &Host) -> Result<Arc<dyn Client>, PluginHostError> + Send + Sync,
    >;

    struct FakeLoaderInner {
        clients: HashMap<String, Arc<FakeClient>>,
        open_err: HashMap<String, PluginHostError>,
        opens: Vec<String>,
        open_func: Option<OpenFn>,
    }

    pub struct FakeLoader {
        inner: Mutex<FakeLoaderInner>,
    }

    impl FakeLoader {
        fn new() -> Arc<FakeLoader> {
            Arc::new(FakeLoader {
                inner: Mutex::new(FakeLoaderInner {
                    clients: HashMap::new(),
                    open_err: HashMap::new(),
                    opens: Vec::new(),
                    open_func: None,
                }),
            })
        }

        fn add_client(&self, path: &str) -> Arc<FakeClient> {
            let c = FakeClient::new();
            self.inner
                .lock()
                .unwrap()
                .clients
                .insert(path.to_string(), Arc::clone(&c));
            c
        }

        fn set_open_err(&self, path: &str, err: PluginHostError) {
            self.inner
                .lock()
                .unwrap()
                .open_err
                .insert(path.to_string(), err);
        }

        fn open_count(&self, path: &str) -> usize {
            self.inner
                .lock()
                .unwrap()
                .opens
                .iter()
                .filter(|p| p.as_str() == path)
                .count()
        }
    }

    impl Loader for FakeLoader {
        fn open(&self, file: &PluginFile, host: &Host) -> Result<Arc<dyn Client>, PluginHostError> {
            let mut inner = self.inner.lock().unwrap();
            inner.opens.push(file.path.to_string_lossy().to_string());
            if let Some(f) = &inner.open_func {
                return f(file, host);
            }
            if let Some(err) = inner.open_err.get(&file.path.to_string_lossy().to_string()) {
                return Err(err.clone());
            }
            match inner.clients.get(&file.path.to_string_lossy().to_string()) {
                Some(c) => Ok(Arc::clone(c) as Arc<dyn Client>),
                None => Err(PluginHostError::failed(format!(
                    "no fake plugin for path {}",
                    file.path.display()
                ))),
            }
        }
    }

    impl Loader for Arc<FakeLoader> {
        fn open(&self, file: &PluginFile, host: &Host) -> Result<Arc<dyn Client>, PluginHostError> {
            (**self).open(file, host)
        }
    }

    struct FakeEgressInner {
        cookie_hosts: Vec<String>,
        closed: bool,
    }

    pub struct FakeEgress {
        inner: Mutex<FakeEgressInner>,
    }

    impl FakeEgress {
        fn new() -> Arc<FakeEgress> {
            Arc::new(FakeEgress {
                inner: Mutex::new(FakeEgressInner {
                    cookie_hosts: Vec::new(),
                    closed: false,
                }),
            })
        }

        fn cookie_hosts(&self) -> Vec<String> {
            self.inner.lock().unwrap().cookie_hosts.clone()
        }
    }

    impl EgressProxyHandle for FakeEgress {
        fn set_cookie_hosts(&self, hosts: &[String]) {
            self.inner.lock().unwrap().cookie_hosts = hosts.to_vec();
        }

        fn close(&self) {
            self.inner.lock().unwrap().closed = true;
        }

        fn is_closed(&self) -> bool {
            self.inner.lock().unwrap().closed
        }
    }

    fn new_fake_host(loader: Arc<FakeLoader>, logs: Arc<Mutex<Vec<String>>>) -> Host {
        let logs_clone = Arc::clone(&logs);
        Host::new(Options {
            loader: Some(Box::new(Arc::clone(&loader))),
            log: Some(Arc::new(move |level: &str, message: &str| {
                logs_clone
                    .lock()
                    .unwrap()
                    .push(format!("{level}:{message}"));
            })),
        })
    }

    fn fake_setup(paths: &[&str]) -> (Arc<FakeLoader>, HashMap<String, Arc<FakeClient>>) {
        let loader = FakeLoader::new();
        let mut clients = HashMap::new();
        for p in paths {
            let c = loader.add_client(p);
            clients.insert(p.to_string(), c);
        }
        (loader, clients)
    }

    fn desired(tag: &str, path: &str) -> Desired {
        Desired::new(tag, "echo", path)
    }

    fn desired_with_fragment(tag: &str, path: &str, fragment: &str) -> Desired {
        Desired {
            fragment: fragment.as_bytes().to_vec(),
            ..Desired::new(tag, "echo", path)
        }
    }

    /// Port of `TestHostLoadAndCall` (`host_test.go:41-85`).
    #[test]
    fn host_load_and_call() {
        let (loader, clients) = fake_setup(&["/plugins/echo.so"]);
        let logs = Arc::new(Mutex::new(Vec::new()));
        let h = new_fake_host(Arc::clone(&loader), Arc::clone(&logs));
        let report = h.apply_config(vec![desired_with_fragment(
            "echo",
            "/plugins/echo.so",
            r#"{"greeting":"hi"}"#,
        )]);
        assert!(report.skipped.is_empty(), "{report:?}");
        assert_eq!(report.loaded, vec!["echo"]);
        let loaded = h.loaded("echo").expect("echo not loaded");
        assert_eq!(loaded.metadata.name, "fake");
        assert_eq!(loaded.schema_version, 1);
        assert!(loaded.capabilities.provider);
        let req = clients["/plugins/echo.so"]
            .last_request(pluginabi::METHOD_PLUGIN_REGISTER)
            .unwrap();
        let reg_req: RegisterRequest = serde_json::from_slice(&req).unwrap();
        assert_eq!(
            serde_json::to_string(&reg_req.config_json).unwrap(),
            r#"{"greeting":"hi"}"#
        );
        assert_eq!(reg_req.schema_version, 1);
        assert_eq!(reg_req.tag, "echo");
        assert_eq!(reg_req.type_, "echo");
        let out = h
            .call(
                "echo",
                pluginabi::METHOD_PROVIDER_CALL,
                br#"{"input":"ping"}"#,
                None,
            )
            .unwrap();
        assert_eq!(String::from_utf8_lossy(&out), r#"{"payload":"echo:ping"}"#);
        let err = h
            .call("missing", pluginabi::METHOD_PROVIDER_CALL, &[], None)
            .unwrap_err();
        assert!(err.to_string().contains("not loaded"), "{err}");
        h.close();
    }

    /// Port of `TestHostReconfigureSamePathAndRollback`
    /// (`host_test.go:86-134`).
    #[test]
    fn host_reconfigure_same_path_and_rollback() {
        let (loader, clients) = fake_setup(&["/plugins/echo.so"]);
        let logs = Arc::new(Mutex::new(Vec::new()));
        let h = new_fake_host(Arc::clone(&loader), Arc::clone(&logs));
        h.apply_config(vec![desired_with_fragment(
            "echo",
            "/plugins/echo.so",
            r#"{"v":1}"#,
        )]);
        let fake = &clients["/plugins/echo.so"];
        let report = h.apply_config(vec![desired_with_fragment(
            "echo",
            "/plugins/echo.so",
            r#"{"v":2}"#,
        )]);
        assert!(report.skipped.is_empty(), "{report:?}");
        assert_eq!(fake.call_count(pluginabi::METHOD_PLUGIN_RECONFIGURE), 1);
        assert_eq!(fake.call_count(pluginabi::METHOD_PLUGIN_REGISTER), 1);
        let req = fake
            .last_request(pluginabi::METHOD_PLUGIN_RECONFIGURE)
            .unwrap();
        let reg_req: RegisterRequest = serde_json::from_slice(&req).unwrap();
        assert_eq!(
            serde_json::to_string(&reg_req.config_json).unwrap(),
            r#"{"v":2}"#
        );
        // Make reconfigure fail: rollback re-registers
        // the old fragment.
        fake.set_on_call(Arc::new(|method: &str, _req: &[u8]| {
            if method == pluginabi::METHOD_PLUGIN_RECONFIGURE {
                return Ok(error_response("reconfigure_failed", "nope"));
            }
            if method == pluginabi::METHOD_PLUGIN_REGISTER {
                return Ok(register_response(
                    1,
                    "fake",
                    "0.1.0",
                    "plugintest",
                    Capabilities {
                        provider: true,
                        command_provider: false,
                    },
                ));
            }
            Ok(ok_response(serde_json::json!({})))
        }));
        let report = h.apply_config(vec![desired_with_fragment(
            "echo",
            "/plugins/echo.so",
            r#"{"v":3}"#,
        )]);
        assert_eq!(report.skipped.len(), 1);
        assert!(
            report.skipped[0].reason.contains("rolled back"),
            "{report:?}"
        );
        assert!(h.loaded("echo").is_some(), "echo must stay loaded");
        let last_register = fake
            .last_request(pluginabi::METHOD_PLUGIN_REGISTER)
            .unwrap();
        let reg_req: RegisterRequest = serde_json::from_slice(&last_register).unwrap();
        assert_eq!(
            serde_json::to_string(&reg_req.config_json).unwrap(),
            r#"{"v":2}"#,
            "rollback fragment must be the previous (v2) fragment"
        );
        h.close();
    }

    /// Port of `TestHostReplaceDifferentPathQuiesceAndRollback`
    /// (`host_test.go:135-169`).
    #[test]
    fn host_replace_different_path_quiesce_and_rollback() {
        let (loader, clients) = fake_setup(&["/plugins/v1.so", "/plugins/v2.so"]);
        let logs = Arc::new(Mutex::new(Vec::new()));
        let h = new_fake_host(Arc::clone(&loader), Arc::clone(&logs));
        h.apply_config(vec![desired_with_fragment("echo", "/plugins/v1.so", "{}")]);
        let old = &clients["/plugins/v1.so"];
        let report = h.apply_config(vec![desired_with_fragment("echo", "/plugins/v2.so", "{}")]);
        assert!(report.skipped.is_empty(), "{report:?}");
        assert_eq!(old.call_count(pluginabi::METHOD_PLUGIN_QUIESCE), 1);
        assert_eq!(old.shutdowns(), 1);
        assert_eq!(
            clients["/plugins/v2.so"].call_count(pluginabi::METHOD_PLUGIN_REGISTER),
            1
        );
        // Replacement failure: the new image fails to
        // open, the old image is re-registered.
        loader.set_open_err("/plugins/v3.so", PluginHostError::failed("dlopen failed"));
        let report = h.apply_config(vec![desired_with_fragment("echo", "/plugins/v3.so", "{}")]);
        assert_eq!(report.skipped.len(), 1);
        assert!(
            report.skipped[0].reason.contains("rolled back"),
            "{report:?}"
        );
        assert!(h.loaded("echo").is_some(), "echo must stay loaded");
        assert_eq!(
            clients["/plugins/v2.so"].call_count(pluginabi::METHOD_PLUGIN_REGISTER),
            2,
            "old register calls: initial + rollback"
        );
        h.close();
    }

    /// Port of `TestHostDetachUnselected` (`host_test.go:170-184`).
    #[test]
    fn host_detach_unselected() {
        let (loader, clients) = fake_setup(&["/plugins/echo.so"]);
        let logs = Arc::new(Mutex::new(Vec::new()));
        let h = new_fake_host(Arc::clone(&loader), Arc::clone(&logs));
        h.apply_config(vec![desired("echo", "/plugins/echo.so")]);
        h.apply_config(vec![]);
        assert!(h.loaded("echo").is_none(), "echo must be detached");
        assert_eq!(clients["/plugins/echo.so"].shutdowns(), 1);
        h.close();
    }

    /// Port of `TestHostBadPluginSkipped` (`host_test.go:185-208`).
    #[test]
    fn host_bad_plugin_skipped() {
        let (loader, clients) = fake_setup(&["/plugins/bad.so"]);
        let logs = Arc::new(Mutex::new(Vec::new()));
        let h = new_fake_host(Arc::clone(&loader), Arc::clone(&logs));
        let fake = &clients["/plugins/bad.so"];
        fake.set_on_call(Arc::new(|_method: &str, _req: &[u8]| {
            Ok(error_response("register_failed", "bad plugin"))
        }));
        let report = h.apply_config(vec![desired("bad", "/plugins/bad.so")]);
        assert_eq!(report.skipped.len(), 1, "{report:?}");
        assert!(h.loaded("bad").is_none(), "bad plugin must not load");
        loader.set_open_err(
            "/plugins/gone.so",
            PluginHostError::failed("dlopen: file not found"),
        );
        let report = h.apply_config(vec![desired("gone", "/plugins/gone.so")]);
        assert_eq!(report.skipped.len(), 1, "{report:?}");
        h.close();
    }

    /// Port of `TestHostVersionMismatch` (`host_test.go:209-255`).
    #[test]
    fn host_version_mismatch() {
        let cases: &[(&str, u32, Capabilities, Metadata, bool, &str)] = &[
            (
                "schema higher rejected",
                2,
                Capabilities {
                    provider: true,
                    command_provider: false,
                },
                Metadata {
                    name: "x".into(),
                    version: "1".into(),
                    author: "a".into(),
                    github_repository: String::new(),
                },
                false,
                "not supported",
            ),
            (
                "schema missing becomes 1",
                0,
                Capabilities {
                    provider: true,
                    command_provider: false,
                },
                Metadata {
                    name: "x".into(),
                    version: "1".into(),
                    author: "a".into(),
                    github_repository: String::new(),
                },
                true,
                "",
            ),
            (
                "no capabilities rejected",
                1,
                Capabilities {
                    provider: false,
                    command_provider: false,
                },
                Metadata {
                    name: "x".into(),
                    version: "1".into(),
                    author: "a".into(),
                    github_repository: String::new(),
                },
                false,
                "at least one capability",
            ),
            (
                "empty name rejected",
                1,
                Capabilities {
                    provider: true,
                    command_provider: false,
                },
                Metadata {
                    name: "".into(),
                    version: "1".into(),
                    author: "a".into(),
                    github_repository: String::new(),
                },
                false,
                "name is required",
            ),
        ];
        for (name, schema, caps, meta, want_ok, want) in cases {
            let (loader, clients) = fake_setup(&["/plugins/p.so"]);
            let logs = Arc::new(Mutex::new(Vec::new()));
            let h = new_fake_host(Arc::clone(&loader), Arc::clone(&logs));
            let reg = Registration {
                schema_version: *schema,
                metadata: meta.clone(),
                capabilities: *caps,
                commands: vec![],
                cookie_hosts: vec![],
            };
            let env = serde_json::to_vec(&Envelope {
                ok: true,
                result: Some(serde_json::to_value(reg).unwrap()),
                error: None,
            })
            .unwrap();
            clients["/plugins/p.so"].set_on_call(Arc::new(move |method: &str, _req: &[u8]| {
                if method == pluginabi::METHOD_PLUGIN_REGISTER {
                    return Ok(env.clone());
                }
                Ok(ok_response(serde_json::json!({})))
            }));
            let report = h.apply_config(vec![desired("p", "/plugins/p.so")]);
            let loaded = h.loaded("p");
            if *want_ok {
                assert!(
                    loaded.is_some() && report.skipped.is_empty(),
                    "{name}: {report:?}"
                );
                assert_eq!(loaded.unwrap().schema_version, 1, "{name}");
            } else {
                assert!(loaded.is_none(), "{name}: must not load");
                assert_eq!(report.skipped.len(), 1, "{name}: {report:?}");
                assert!(
                    report.skipped[0].reason.contains(want),
                    "{name}: reason {:?} must contain {want:?}",
                    report.skipped[0].reason
                );
            }
            h.close();
        }
    }

    /// Port of `TestHostPanicIsolationAndFuse`
    /// (`host_test.go:256-286`).
    #[test]
    fn host_panic_isolation_and_fuse() {
        let (loader, clients) = fake_setup(&["/plugins/echo.so", "/plugins/v2.so"]);
        let logs = Arc::new(Mutex::new(Vec::new()));
        let h = new_fake_host(Arc::clone(&loader), Arc::clone(&logs));
        h.apply_config(vec![desired("echo", "/plugins/echo.so")]);
        let fake = &clients["/plugins/echo.so"];
        fake.set_panic_methods(&[pluginabi::METHOD_PROVIDER_CALL]);
        let err = h
            .call("echo", pluginabi::METHOD_PROVIDER_CALL, &[], None)
            .unwrap_err();
        assert!(err.to_string().contains("panic"), "{err}");
        let reason = h.fused("echo").expect("must be fused");
        assert!(reason.contains("panic"), "{reason}");
        let report = h.apply_config(vec![desired("echo", "/plugins/echo.so")]);
        assert_eq!(report.skipped.len(), 1);
        assert!(report.skipped[0].reason.contains("fused"), "{report:?}");
        fake.set_panic_methods(&[]);
        let report = h.apply_config(vec![desired("echo", "/plugins/v2.so")]);
        assert!(report.skipped.is_empty(), "{report:?}");
        assert!(h.fused("echo").is_none(), "fuse must clear");
        h.close();
    }

    /// Port of `TestHostTimeoutFusesAndReturns`
    /// (`host_test.go:287-309`).
    #[test]
    fn host_timeout_fuses_and_returns() {
        let (loader, clients) = fake_setup(&["/plugins/echo.so"]);
        let logs = Arc::new(Mutex::new(Vec::new()));
        let h = new_fake_host(Arc::clone(&loader), Arc::clone(&logs));
        h.apply_config(vec![desired("echo", "/plugins/echo.so")]);
        clients["/plugins/echo.so"].set_block_methods(&[pluginabi::METHOD_PROVIDER_CALL]);
        let start = Instant::now();
        let err = h
            .call(
                "echo",
                pluginabi::METHOD_PROVIDER_CALL,
                &[],
                Some(Duration::from_millis(60)),
            )
            .unwrap_err();
        let elapsed = start.elapsed();
        assert!(
            err.to_string().contains("deadline exceeded"),
            "err = {err}, want deadline exceeded"
        );
        assert!(
            elapsed < Duration::from_secs(2),
            "call took {elapsed:?}, want prompt return on deadline"
        );
        assert!(h.fused("echo").is_some(), "hung plugin must be fused");
        h.close();
    }

    /// Port of `TestHostCallEnvelopeErrors`
    /// (`host_test.go:310-338`).
    #[test]
    fn host_call_envelope_errors() {
        let (loader, clients) = fake_setup(&["/plugins/echo.so"]);
        let logs = Arc::new(Mutex::new(Vec::new()));
        let h = new_fake_host(Arc::clone(&loader), Arc::clone(&logs));
        h.apply_config(vec![desired("echo", "/plugins/echo.so")]);
        let fake = &clients["/plugins/echo.so"];
        fake.set_on_call(Arc::new(|method: &str, _req: &[u8]| {
            if method == pluginabi::METHOD_PLUGIN_REGISTER {
                return Ok(register_response(
                    1,
                    "fake",
                    "0.1.0",
                    "plugintest",
                    Capabilities {
                        provider: true,
                        command_provider: false,
                    },
                ));
            }
            Ok(error_response("upstream_down", "upstream is down"))
        }));
        let err = h
            .call("echo", pluginabi::METHOD_PROVIDER_CALL, &[], None)
            .unwrap_err();
        assert!(err.to_string().contains("upstream_down"), "{err}");
        assert!(err.to_string().contains("upstream is down"), "{err}");
        fake.set_on_call(Arc::new(|method: &str, _req: &[u8]| {
            if method == pluginabi::METHOD_PLUGIN_REGISTER {
                return Ok(register_response(
                    1,
                    "fake",
                    "0.1.0",
                    "plugintest",
                    Capabilities {
                        provider: true,
                        command_provider: false,
                    },
                ));
            }
            Ok(b"not json".to_vec())
        }));
        let err = h
            .call("echo", pluginabi::METHOD_PROVIDER_CALL, &[], None)
            .unwrap_err();
        assert!(err.to_string().contains("invalid envelope"), "{err}");
        h.close();
    }

    /// Port of `TestHostRegisterRequestCarriesNoSecrets`
    /// (`host_test.go:339-366`).
    #[test]
    fn host_register_request_carries_no_secrets() {
        let (loader, clients) = fake_setup(&["/plugins/echo.so"]);
        let logs = Arc::new(Mutex::new(Vec::new()));
        let h = new_fake_host(Arc::clone(&loader), Arc::clone(&logs));
        let mut d = desired_with_fragment("echo", "/plugins/echo.so", r#"{"note":"hello"}"#);
        d.identity = Some(Identity {
            outbound_tag: "direct".to_string(),
            outbound_hash: "abc123".to_string(),
        });
        d.egress = Some(Egress {
            proxy_url: "http://127.0.0.1:0".to_string(),
            username: "u".to_string(),
            password: "ephemeral".to_string(),
        });
        h.apply_config(vec![d]);
        let req = clients["/plugins/echo.so"]
            .last_request(pluginabi::METHOD_PLUGIN_REGISTER)
            .unwrap();
        let text = String::from_utf8_lossy(&req).to_string();
        for forbidden in [
            "\"cookies\"",
            "\"cookie_file\"",
            "\"cookies_file\"",
            "\"private_key\"",
            "\"token\"",
            "\"Cookie\"",
            "\"WG\"",
            "\"wireguard\"",
        ] {
            assert!(
                !text.contains(forbidden),
                "register request contains forbidden key {forbidden}: {text}"
            );
        }
        assert!(text.contains("\"outbound_hash\":\"abc123\""), "{text}");
        assert!(
            text.contains("\"proxy_url\":\"http://127.0.0.1:0\""),
            "{text}"
        );
        h.close();
    }

    /// Port of `TestHostDuplicateDesiredTags`
    /// (`host_test.go:367-383`).
    #[test]
    fn host_duplicate_desired_tags() {
        let (loader, _clients) = fake_setup(&["/plugins/echo.so"]);
        let logs = Arc::new(Mutex::new(Vec::new()));
        let h = new_fake_host(Arc::clone(&loader), Arc::clone(&logs));
        let report = h.apply_config(vec![
            desired("echo", "/plugins/echo.so"),
            desired("echo", "/plugins/echo.so"),
        ]);
        assert_eq!(report.skipped.len(), 1);
        assert!(report.skipped[0].reason.contains("duplicate"), "{report:?}");
        assert_eq!(report.loaded.len(), 1);
        h.close();
    }

    /// Port of `TestHostCommandProviderCommands`
    /// (`host_test.go:384-404`).
    #[test]
    fn host_command_provider_commands() {
        let (loader, clients) = fake_setup(&["/plugins/cmd.so"]);
        let logs = Arc::new(Mutex::new(Vec::new()));
        let h = new_fake_host(Arc::clone(&loader), Arc::clone(&logs));
        let reg = Registration {
            schema_version: 1,
            metadata: Metadata {
                name: "cmd".into(),
                version: "1".into(),
                author: "a".into(),
                github_repository: String::new(),
            },
            capabilities: Capabilities {
                provider: false,
                command_provider: true,
            },
            commands: vec![Command {
                name: "fake-cmd".into(),
                usage: "fake command".into(),
            }],
            cookie_hosts: vec![],
        };
        let env = serde_json::to_vec(&Envelope {
            ok: true,
            result: Some(serde_json::to_value(reg).unwrap()),
            error: None,
        })
        .unwrap();
        clients["/plugins/cmd.so"]
            .set_on_call(Arc::new(move |_method: &str, _req: &[u8]| Ok(env.clone())));
        let mut d = desired("cmd", "/plugins/cmd.so");
        d.type_ = "cmd".to_string();
        let report = h.apply_config(vec![d]);
        assert!(report.skipped.is_empty(), "{report:?}");
        let loaded = h.loaded("cmd").expect("cmd not loaded");
        assert_eq!(loaded.commands.len(), 1);
        assert_eq!(loaded.commands[0].name, "fake-cmd");
        h.close();
    }

    /// Port of `TestHostCallFailsFastWhenFused`
    /// (`host_hardening_test.go:26-51`).
    #[test]
    fn host_call_fails_fast_when_fused() {
        let (loader, clients) = fake_setup(&["/plugins/echo.so"]);
        let logs = Arc::new(Mutex::new(Vec::new()));
        let h = new_fake_host(Arc::clone(&loader), Arc::clone(&logs));
        h.apply_config(vec![desired("echo", "/plugins/echo.so")]);
        let fake = &clients["/plugins/echo.so"];
        fake.set_panic_methods(&[pluginabi::METHOD_PROVIDER_CALL]);
        assert!(
            h.call("echo", pluginabi::METHOD_PROVIDER_CALL, &[], None)
                .is_err()
        );
        let before = fake.call_count(pluginabi::METHOD_PROVIDER_CALL);
        let err = h
            .call("echo", pluginabi::METHOD_PROVIDER_CALL, &[], None)
            .unwrap_err();
        assert!(err.to_string().contains("fused"), "{err}");
        assert_eq!(
            fake.call_count(pluginabi::METHOD_PROVIDER_CALL),
            before,
            "fused plugin must not be re-called"
        );
        h.close();
    }

    /// Port of `TestHostFuseIsPerPath`
    /// (`host_hardening_test.go:53-131`).
    #[test]
    fn host_fuse_is_per_path() {
        let (loader, clients) = fake_setup(&["/plugins/echo.so", "/plugins/v2.so"]);
        let logs = Arc::new(Mutex::new(Vec::new()));
        let h = new_fake_host(Arc::clone(&loader), Arc::clone(&logs));
        let first = desired_with_fragment("echo", "/plugins/echo.so", r#"{"n":1}"#);
        let report = h.apply_config(vec![first.clone()]);
        assert_eq!(report.loaded.len(), 1, "{report:?}");
        let fake = &clients["/plugins/echo.so"];
        fake.set_on_call(Arc::new(|method: &str, _req: &[u8]| {
            if method == pluginabi::METHOD_PLUGIN_RECONFIGURE {
                return Err(ClientError::Transport(PluginHostError::failed(
                    "reconfigure boom",
                )));
            }
            if method == pluginabi::METHOD_PLUGIN_REGISTER {
                return Err(ClientError::Transport(PluginHostError::failed(
                    "rollback boom",
                )));
            }
            Ok(error_response("unexpected", "unexpected call"))
        }));
        // Same path, new fragment: reconfigure fails,
        // rollback register fails -> fused, deleted.
        let report = h.apply_config(vec![desired_with_fragment(
            "echo",
            "/plugins/echo.so",
            r#"{"n":2}"#,
        )]);
        assert_eq!(report.skipped.len(), 1);
        assert!(
            report.skipped[0].reason.contains("rollback failed"),
            "{report:?}"
        );
        assert!(
            report.loaded.is_empty(),
            "fused tag reported Loaded: {report:?}"
        );
        let reason = h.fused("echo").expect("must be fused");
        assert!(reason.contains("rollback"), "{reason}");
        assert!(h.loaded("echo").is_none(), "loaded entry must be deleted");
        let calls_before = fake.call_count(pluginabi::METHOD_PROVIDER_CALL);
        let err = h
            .call("echo", pluginabi::METHOD_PROVIDER_CALL, &[], None)
            .unwrap_err();
        assert!(err.to_string().contains("fused"), "{err}");
        assert_eq!(
            fake.call_count(pluginabi::METHOD_PROVIDER_CALL),
            calls_before
        );
        // Same-path ApplyConfig skips WITHOUT re-opening.
        let opens_before = loader.open_count("/plugins/echo.so");
        let report = h.apply_config(vec![first]);
        assert_eq!(report.skipped.len(), 1);
        assert!(report.skipped[0].reason.contains("fused"), "{report:?}");
        assert!(report.loaded.is_empty());
        assert_eq!(loader.open_count("/plugins/echo.so"), opens_before);
        // Different path loads and clears the fuse.
        fake.clear_on_call();
        let report = h.apply_config(vec![desired_with_fragment(
            "echo",
            "/plugins/v2.so",
            r#"{"n":1}"#,
        )]);
        assert_eq!(report.loaded.len(), 1, "{report:?}");
        assert!(report.skipped.is_empty());
        assert!(h.fused("echo").is_none());
        assert!(
            h.call(
                "echo",
                pluginabi::METHOD_PROVIDER_CALL,
                br#"{"input":"ping"}"#,
                None
            )
            .is_ok()
        );
        h.close();
    }

    /// Port of `TestHostLoadedIgnoresStaleFuseForDifferentPath`
    /// (`host_hardening_test.go:132-185`).
    #[test]
    fn host_loaded_ignores_stale_fuse_for_different_path() {
        let (loader, clients) = fake_setup(&["/plugins/echo.so", "/plugins/v2.so"]);
        let logs = Arc::new(Mutex::new(Vec::new()));
        let h = new_fake_host(Arc::clone(&loader), Arc::clone(&logs));
        let first = desired_with_fragment("echo", "/plugins/echo.so", r#"{"n":1}"#);
        let report = h.apply_config(vec![first]);
        assert_eq!(report.loaded.len(), 1, "{report:?}");
        // The replacement image panics on register: the
        // panic fuses the tag with the NEW path, loadOne
        // fails, and the rollback re-register succeeds.
        clients["/plugins/v2.so"].set_panic_methods(&[pluginabi::METHOD_PLUGIN_REGISTER]);
        let report = h.apply_config(vec![desired_with_fragment(
            "echo",
            "/plugins/v2.so",
            r#"{"n":2}"#,
        )]);
        assert_eq!(report.loaded.len(), 1, "{report:?}");
        assert!(
            report.skipped[0].reason.contains("rolled back"),
            "{report:?}"
        );
        let loaded = h.loaded("echo").expect("old image must stay loaded");
        assert_eq!(loaded.path, "/plugins/echo.so");
        assert!(
            h.call(
                "echo",
                pluginabi::METHOD_PROVIDER_CALL,
                br#"{"input":"ping"}"#,
                None
            )
            .is_ok()
        );
        // The stale fuse entry is still recorded for the
        // new path.
        assert!(h.fused("echo").is_some());
        let opens_before = loader.open_count("/plugins/v2.so");
        let report = h.apply_config(vec![desired_with_fragment(
            "echo",
            "/plugins/v2.so",
            r#"{"n":2}"#,
        )]);
        assert_eq!(report.skipped.len(), 1);
        assert!(report.skipped[0].reason.contains("fused"), "{report:?}");
        assert_eq!(loader.open_count("/plugins/v2.so"), opens_before);
        assert!(h.loaded("echo").is_some());
        h.close();
    }

    /// Port of `TestHostSkippedReasonStripsForgedControls`
    /// (`host_hardening_test.go:186-219`).
    #[test]
    fn host_skipped_reason_strips_forged_controls() {
        let (loader, clients) = fake_setup(&["/plugins/echo.so"]);
        let logs = Arc::new(Mutex::new(Vec::new()));
        let h = new_fake_host(Arc::clone(&loader), Arc::clone(&logs));
        clients["/plugins/echo.so"].set_on_call(Arc::new(|method: &str, _req: &[u8]| {
            if method == pluginabi::METHOD_PLUGIN_REGISTER {
                return Err(ClientError::Transport(PluginHostError::failed(
                    "register boom\nFORGED-LINE\u{1b}[31mRED\u{85}TAIL\u{9b}31mEND",
                )));
            }
            Ok(error_response("unexpected", "unexpected call"))
        }));
        let report = h.apply_config(vec![desired("echo", "/plugins/echo.so")]);
        assert_eq!(report.skipped.len(), 1);
        assert!(report.loaded.is_empty(), "{report:?}");
        let reason = &report.skipped[0].reason;
        assert!(
            !reason.contains(['\n', '\r', '\u{1b}']),
            "kept controls: {reason:?}"
        );
        for r in reason.chars() {
            assert!(
                !(('\u{80}'..='\u{9f}').contains(&r)),
                "kept C1 control U+{:04X}: {reason:?}",
                r as u32
            );
        }
        assert!(!reason.contains("[31m"), "kept CSI remnant: {reason:?}");
        assert!(reason.contains("register boom"), "{reason:?}");
        assert!(reason.contains("FORGED-LINE"), "{reason:?}");
        h.close();
    }

    /// Port of `TestHostTagAndTypeValidation`
    /// (`host_hardening_test.go:220-243`).
    #[test]
    fn host_tag_and_type_validation() {
        let (loader, _clients) = fake_setup(&["/plugins/echo.so"]);
        let logs = Arc::new(Mutex::new(Vec::new()));
        let h = new_fake_host(Arc::clone(&loader), Arc::clone(&logs));
        let mut cases: Vec<Desired> = Vec::new();
        let mut d = Desired::new("../../evil", "echo", "/plugins/echo.so");
        cases.push(d.clone());
        d = Desired::new("echo", "../evil", "/plugins/echo.so");
        cases.push(d.clone());
        d = Desired::new("", "echo", "/plugins/echo.so");
        cases.push(d.clone());
        d = Desired::new("echo", "", "/plugins/echo.so");
        cases.push(d.clone());
        d = Desired::new("echo\nx", "echo", "/plugins/echo.so");
        cases.push(d);
        for d in cases {
            let report = h.apply_config(vec![d.clone()]);
            assert_eq!(report.skipped.len(), 1, "{d:?}: {report:?}");
            assert!(report.loaded.is_empty());
            assert!(h.loaded(&d.tag).is_none(), "tag {:?} loaded", d.tag);
        }
        h.close();
    }

    /// Port of `TestHostEmptyFragmentSentAsObject`
    /// (`host_hardening_test.go:244-262`).
    #[test]
    fn host_empty_fragment_sent_as_object() {
        let (loader, clients) = fake_setup(&["/plugins/echo.so"]);
        let logs = Arc::new(Mutex::new(Vec::new()));
        let h = new_fake_host(Arc::clone(&loader), Arc::clone(&logs));
        h.apply_config(vec![desired("echo", "/plugins/echo.so")]);
        let raw = clients["/plugins/echo.so"]
            .last_request(pluginabi::METHOD_PLUGIN_REGISTER)
            .unwrap();
        let req: RegisterRequest = serde_json::from_slice(&raw).unwrap();
        assert_eq!(
            serde_json::to_string(&req.config_json).unwrap(),
            "{}",
            "config_json must be {{}}, never null"
        );
        h.close();
    }

    /// Port of `TestHostEnvelopeErrorRedacted`
    /// (`host_hardening_test.go:263-288`).
    #[test]
    fn host_envelope_error_redacted() {
        let (loader, clients) = fake_setup(&["/plugins/echo.so"]);
        let logs = Arc::new(Mutex::new(Vec::new()));
        let h = new_fake_host(Arc::clone(&loader), Arc::clone(&logs));
        h.apply_config(vec![desired("echo", "/plugins/echo.so")]);
        let fake = &clients["/plugins/echo.so"];
        fake.set_on_call(Arc::new(|method: &str, _req: &[u8]| {
            if method == pluginabi::METHOD_PLUGIN_REGISTER {
                return Ok(register_response(
                    1,
                    "fake",
                    "0.1.0",
                    "plugintest",
                    Capabilities {
                        provider: true,
                        command_provider: false,
                    },
                ));
            }
            Ok(error_response(
                "boom",
                "failed with hatch_sess=SECRETVALUE and {\"api_key\":\"abc123\"}",
            ))
        }));
        let err = h
            .call("echo", pluginabi::METHOD_PROVIDER_CALL, &[], None)
            .unwrap_err();
        assert!(
            !err.to_string().contains("SECRETVALUE"),
            "error leaks plugin text: {err}"
        );
        assert!(
            !err.to_string().contains("abc123"),
            "error leaks plugin text: {err}"
        );
        h.close();
    }

    fn register_with_hosts(hosts: Vec<String>) -> CallHook {
        Arc::new(move |method: &str, _req: &[u8]| {
            if method == pluginabi::METHOD_PLUGIN_REGISTER
                || method == pluginabi::METHOD_PLUGIN_RECONFIGURE
            {
                let reg = Registration {
                    schema_version: 1,
                    metadata: Metadata {
                        name: "fake".into(),
                        version: "0.1.0".into(),
                        author: "plugintest".into(),
                        github_repository: String::new(),
                    },
                    capabilities: Capabilities {
                        provider: true,
                        command_provider: false,
                    },
                    commands: vec![],
                    cookie_hosts: hosts.clone(),
                };
                let env = Envelope {
                    ok: true,
                    result: Some(serde_json::to_value(reg).unwrap()),
                    error: None,
                };
                return Ok(serde_json::to_vec(&env).unwrap());
            }
            Ok(ok_response(serde_json::json!({})))
        })
    }

    /// Port of `TestHostCloseRevokesEgressCreds`
    /// (`host_hardening_test.go:289-313`): with a fake
    /// proxy, `Close` closes every adopted proxy and a
    /// second `Close` is idempotent.
    #[test]
    fn host_close_revokes_egress_creds() {
        let (loader, _clients) = fake_setup(&["/plugins/echo.so"]);
        let logs = Arc::new(Mutex::new(Vec::new()));
        let h = new_fake_host(Arc::clone(&loader), Arc::clone(&logs));
        let proxy = FakeEgress::new();
        h.adopt_egress(&(Arc::clone(&proxy) as Arc<dyn EgressProxyHandle>));
        assert!(!proxy.is_closed());
        h.close();
        assert!(proxy.is_closed(), "adopted proxy must close with Host");
        h.close();
    }

    /// Port of `TestHostCookieHostsAppliedFromRegistration`
    /// (`host_hardening_test.go:314-365`): the host
    /// applies the plugin's declared cookie_hosts to the
    /// adopted proxy after registration.
    #[test]
    fn host_cookie_hosts_applied_from_registration() {
        let (loader, clients) = fake_setup(&["/plugins/echo.so"]);
        let logs = Arc::new(Mutex::new(Vec::new()));
        let h = new_fake_host(Arc::clone(&loader), Arc::clone(&logs));
        let proxy = FakeEgress::new();
        clients["/plugins/echo.so"]
            .set_on_call(register_with_hosts(vec!["declared.invalid".to_string()]));
        let mut d = desired("echo", "/plugins/echo.so");
        d.egress_proxy = Some(Arc::clone(&proxy) as Arc<dyn EgressProxyHandle>);
        let report = h.apply_config(vec![d]);
        assert!(report.skipped.is_empty(), "{report:?}");
        assert_eq!(proxy.cookie_hosts(), vec!["declared.invalid"]);
        h.close();
    }

    /// Port of `TestHostSupersededEgressClosed`
    /// (`host_hardening_test.go:391-445`): reconfiguring
    /// with a different egress proxy closes the old one
    /// and applies the new scope to the new one.
    #[test]
    fn host_superseded_egress_closed() {
        let (loader, clients) = fake_setup(&["/plugins/echo.so"]);
        let logs = Arc::new(Mutex::new(Vec::new()));
        let h = new_fake_host(Arc::clone(&loader), Arc::clone(&logs));
        let old_proxy = FakeEgress::new();
        let new_proxy = FakeEgress::new();
        let fake = &clients["/plugins/echo.so"];
        fake.set_on_call(register_with_hosts(vec!["declared.invalid".to_string()]));
        let mut d = desired_with_fragment("echo", "/plugins/echo.so", r#"{"n":1}"#);
        d.egress_proxy = Some(Arc::clone(&old_proxy) as Arc<dyn EgressProxyHandle>);
        let report = h.apply_config(vec![d]);
        assert_eq!(report.loaded.len(), 1, "{report:?}");
        fake.set_on_call(register_with_hosts(vec!["other.invalid".to_string()]));
        let mut d = desired_with_fragment("echo", "/plugins/echo.so", r#"{"n":2}"#);
        d.egress_proxy = Some(Arc::clone(&new_proxy) as Arc<dyn EgressProxyHandle>);
        let report = h.apply_config(vec![d]);
        assert_eq!(report.loaded.len(), 1, "{report:?}");
        assert!(old_proxy.is_closed(), "superseded proxy must close");
        assert!(!new_proxy.is_closed(), "new proxy must stay open");
        assert_eq!(new_proxy.cookie_hosts(), vec!["other.invalid"]);
        assert_eq!(old_proxy.cookie_hosts(), vec!["declared.invalid"]);
        h.close();
    }

    /// Port of `TestHostDetachedEgressClosed`
    /// (`host_hardening_test.go:446-469`).
    #[test]
    fn host_detached_egress_closed() {
        let (loader, clients) = fake_setup(&["/plugins/echo.so"]);
        let logs = Arc::new(Mutex::new(Vec::new()));
        let h = new_fake_host(Arc::clone(&loader), Arc::clone(&logs));
        let proxy = FakeEgress::new();
        clients["/plugins/echo.so"].set_on_call(register_with_hosts(vec![]));
        let mut d = desired("echo", "/plugins/echo.so");
        d.egress_proxy = Some(Arc::clone(&proxy) as Arc<dyn EgressProxyHandle>);
        let report = h.apply_config(vec![d]);
        assert_eq!(report.loaded.len(), 1, "{report:?}");
        h.apply_config(vec![]);
        assert!(proxy.is_closed(), "detached proxy must close");
        h.close();
    }

    /// Port of `TestHostSharedEgressNotClosedEarly`
    /// (`host_hardening_test.go:470-508`).
    #[test]
    fn host_shared_egress_not_closed_early() {
        let (loader, clients) = fake_setup(&["/plugins/echo.so", "/plugins/v2.so"]);
        let logs = Arc::new(Mutex::new(Vec::new()));
        let h = new_fake_host(Arc::clone(&loader), Arc::clone(&logs));
        let proxy = FakeEgress::new();
        for c in clients.values() {
            c.set_on_call(register_with_hosts(vec![]));
        }
        let proxy_handle = Arc::clone(&proxy) as Arc<dyn EgressProxyHandle>;
        let mut d1 = desired("echo", "/plugins/echo.so");
        d1.egress_proxy = Some(Arc::clone(&proxy_handle));
        let mut d2 = Desired::new("v2", "echo", "/plugins/v2.so");
        d2.egress_proxy = Some(Arc::clone(&proxy_handle));
        let report = h.apply_config(vec![d1.clone(), d2]);
        assert_eq!(report.loaded.len(), 2, "{report:?}");
        h.apply_config(vec![d1]);
        assert!(!proxy.is_closed(), "shared proxy must survive one detach");
        h.apply_config(vec![]);
        assert!(
            proxy.is_closed(),
            "shared proxy must close after last detach"
        );
        h.close();
    }

    /// Port of `TestHostNilEgressKeepsExisting`
    /// (`host_hardening_test.go:509-560`).
    #[test]
    fn host_nil_egress_keeps_existing() {
        let (loader, clients) = fake_setup(&["/plugins/echo.so"]);
        let logs = Arc::new(Mutex::new(Vec::new()));
        let h = new_fake_host(Arc::clone(&loader), Arc::clone(&logs));
        let proxy = FakeEgress::new();
        let fake = &clients["/plugins/echo.so"];
        fake.set_on_call(register_with_hosts(vec!["declared.invalid".to_string()]));
        let mut d = desired_with_fragment("echo", "/plugins/echo.so", r#"{"n":1}"#);
        d.egress_proxy = Some(Arc::clone(&proxy) as Arc<dyn EgressProxyHandle>);
        let report = h.apply_config(vec![d]);
        assert_eq!(report.loaded.len(), 1, "{report:?}");
        fake.set_on_call(register_with_hosts(vec!["other.invalid".to_string()]));
        let report = h.apply_config(vec![desired_with_fragment(
            "echo",
            "/plugins/echo.so",
            r#"{"n":2}"#,
        )]);
        assert_eq!(report.loaded.len(), 1, "{report:?}");
        assert!(
            !proxy.is_closed(),
            "nil-egress reconfigure must keep the proxy"
        );
        assert_eq!(proxy.cookie_hosts(), vec!["other.invalid"]);
        h.close();
    }

    /// Port of `TestHostLoadedVsReconfigureRace`
    /// (`host_hardening_test.go:602-618`): the fake-loader
    /// half of the B-R1 hammer — registration fields
    /// written by applyRegistration must not race
    /// Loaded() reads.
    #[test]
    fn host_loaded_vs_reconfigure_race() {
        let (loader, _clients) = fake_setup(&["/plugins/echo.so"]);
        let logs = Arc::new(Mutex::new(Vec::new()));
        let h = Arc::new(new_fake_host(Arc::clone(&loader), Arc::clone(&logs)));
        let report = h.apply_config(vec![desired_with_fragment(
            "echo",
            "/plugins/echo.so",
            r#"{"v":0}"#,
        )]);
        assert_eq!(report.loaded.len(), 1, "{report:?}");
        let stop = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let h = Arc::clone(&h);
            let stop = Arc::clone(&stop);
            handles.push(std::thread::spawn(move || {
                while stop.load(Ordering::Relaxed) == 0 {
                    let _ = h.call(
                        "echo",
                        pluginabi::METHOD_PROVIDER_CALL,
                        br#"{"input":"ping"}"#,
                        None,
                    );
                }
            }));
        }
        for n in 0..3 {
            let h = Arc::clone(&h);
            let stop = Arc::clone(&stop);
            handles.push(std::thread::spawn(move || {
                let mut j = 0;
                while stop.load(Ordering::Relaxed) == 0 {
                    let _ = h.apply_config(vec![desired_with_fragment(
                        "echo",
                        "/plugins/echo.so",
                        &format!("{{\"v\":{}}}", n * 1000 + j),
                    )]);
                    j += 1;
                }
            }));
        }
        {
            let h = Arc::clone(&h);
            let stop = Arc::clone(&stop);
            handles.push(std::thread::spawn(move || {
                while stop.load(Ordering::Relaxed) == 0 {
                    let _ = h.loaded("echo");
                    let _ = h.fused("echo");
                }
            }));
        }
        std::thread::sleep(Duration::from_secs(2));
        stop.store(1, Ordering::Relaxed);
        for handle in handles {
            let _ = handle.join();
        }
        h.close();
    }

    /// Port of `TestHostEnvelopeErrorControlStripped`
    /// (`host_hardening_test.go:620-654`).
    #[test]
    fn host_envelope_error_control_stripped() {
        let (loader, clients) = fake_setup(&["/plugins/echo.so"]);
        let logs = Arc::new(Mutex::new(Vec::new()));
        let h = new_fake_host(Arc::clone(&loader), Arc::clone(&logs));
        clients["/plugins/echo.so"].set_on_call(Arc::new(|method: &str, _req: &[u8]| {
            if method == pluginabi::METHOD_PLUGIN_REGISTER
                || method == pluginabi::METHOD_PLUGIN_RECONFIGURE
            {
                return Ok(register_response(
                    1,
                    "fake",
                    "0.1.0",
                    "plugintest",
                    Capabilities {
                        provider: true,
                        command_provider: false,
                    },
                ));
            }
            Ok(error_response(
                "bad\ncode\u{1b}[31m",
                "line1\nFORGED-LINE\u{1b}[31m",
            ))
        }));
        let report = h.apply_config(vec![desired("echo", "/plugins/echo.so")]);
        assert_eq!(report.loaded.len(), 1, "{report:?}");
        let err = h
            .call("echo", pluginabi::METHOD_PROVIDER_CALL, &[], None)
            .unwrap_err();
        assert!(
            !err.to_string().contains(['\n', '\r', '\u{1b}', '\0']),
            "envelope error kept controls: {err:?}"
        );
        assert!(err.to_string().contains("FORGED-LINE"), "{err}");
        h.close();
    }

    /// Port of `TestHostSharedEgressScopeLastWriterWins`
    /// (`host_hardening_test.go:655-703`): cookie scope
    /// lives on the PROXY, not per tag.
    #[test]
    fn host_shared_egress_scope_last_writer_wins() {
        let (loader, clients) = fake_setup(&["/plugins/a.so", "/plugins/b.so"]);
        let logs = Arc::new(Mutex::new(Vec::new()));
        let h = new_fake_host(Arc::clone(&loader), Arc::clone(&logs));
        let proxy = FakeEgress::new();
        clients["/plugins/a.so"].set_on_call(register_with_hosts(vec!["a.invalid".to_string()]));
        clients["/plugins/b.so"].set_on_call(register_with_hosts(vec!["b.invalid".to_string()]));
        let proxy_handle = Arc::clone(&proxy) as Arc<dyn EgressProxyHandle>;
        let mut da = Desired::new("a", "a", "/plugins/a.so");
        da.egress_proxy = Some(Arc::clone(&proxy_handle));
        let mut db = Desired::new("b", "b", "/plugins/b.so");
        db.egress_proxy = Some(Arc::clone(&proxy_handle));
        let report = h.apply_config(vec![da, db]);
        assert_eq!(report.loaded.len(), 2, "{report:?}");
        // Last writer (b) wins.
        assert_eq!(proxy.cookie_hosts(), vec!["b.invalid"]);
        h.close();
    }

    /// Port of
    /// `TestHostRollbackReportExcludesFusedReconfigurePanic`
    /// (`host_hardening_test.go:704-738`).
    #[test]
    fn host_rollback_report_excludes_fused_reconfigure_panic() {
        let (loader, clients) = fake_setup(&["/plugins/echo.so"]);
        let logs = Arc::new(Mutex::new(Vec::new()));
        let h = new_fake_host(Arc::clone(&loader), Arc::clone(&logs));
        let first = desired_with_fragment("echo", "/plugins/echo.so", r#"{"n":1}"#);
        let report = h.apply_config(vec![first]);
        assert_eq!(report.loaded.len(), 1, "{report:?}");
        let fake = &clients["/plugins/echo.so"];
        fake.set_panic_methods(&[pluginabi::METHOD_PLUGIN_RECONFIGURE]);
        let report = h.apply_config(vec![desired_with_fragment(
            "echo",
            "/plugins/echo.so",
            r#"{"n":2}"#,
        )]);
        assert!(
            report.loaded.is_empty(),
            "report Loaded = {:?}, want empty",
            report.loaded
        );
        assert_eq!(report.skipped.len(), 1);
        assert!(
            report.skipped[0].reason.contains("rolled back"),
            "{report:?}"
        );
        assert!(h.loaded("echo").is_none(), "Loaded() must be false");
        assert!(h.fused("echo").is_some(), "fuse must still be recorded");
        let err = h
            .call("echo", pluginabi::METHOD_PROVIDER_CALL, &[], None)
            .unwrap_err();
        assert!(err.to_string().contains("fused"), "{err}");
        h.close();
    }

    /// Port of
    /// `TestHostRollbackReportExcludesFusedQuiescePanic`
    /// (`host_hardening_test.go:739-780`).
    #[test]
    fn host_rollback_report_excludes_fused_quiesce_panic() {
        let (loader, clients) = fake_setup(&["/plugins/echo.so", "/plugins/v2.so"]);
        let logs = Arc::new(Mutex::new(Vec::new()));
        let h = new_fake_host(Arc::clone(&loader), Arc::clone(&logs));
        let report = h.apply_config(vec![desired_with_fragment(
            "echo",
            "/plugins/echo.so",
            r#"{"n":1}"#,
        )]);
        assert_eq!(report.loaded.len(), 1, "{report:?}");
        clients["/plugins/echo.so"].set_panic_methods(&[pluginabi::METHOD_PLUGIN_QUIESCE]);
        clients["/plugins/v2.so"].set_on_call(Arc::new(|method: &str, _req: &[u8]| {
            if method == pluginabi::METHOD_PLUGIN_REGISTER {
                return Err(ClientError::Transport(PluginHostError::failed(
                    "replacement register boom",
                )));
            }
            Ok(error_response("unexpected", "unexpected call"))
        }));
        let report = h.apply_config(vec![desired_with_fragment(
            "echo",
            "/plugins/v2.so",
            r#"{"n":2}"#,
        )]);
        assert!(
            report.loaded.is_empty(),
            "report Loaded = {:?}, want empty",
            report.loaded
        );
        assert_eq!(report.skipped.len(), 1);
        assert!(
            report.skipped[0]
                .reason
                .contains("rolled back to previous image"),
            "{report:?}"
        );
        assert!(h.loaded("echo").is_none());
        let reason = h
            .fused("echo")
            .expect("quiesce-panic fuse must be recorded");
        assert!(reason.contains("quiesce"), "{reason}");
        let err = h
            .call("echo", pluginabi::METHOD_PROVIDER_CALL, &[], None)
            .unwrap_err();
        assert!(err.to_string().contains("fused"), "{err}");
        h.close();
    }

    /// Port of `TestHostStaleFuseDoesNotClobberCurrentFuse`
    /// (`host_hardening_test.go:781-859`): 60 iterations.
    #[test]
    fn host_stale_fuse_does_not_clobber_current_fuse() {
        let mut reinvocations = 0;
        for iter in 0..60 {
            let (loader, clients) = fake_setup(&["/plugins/echo.so", "/plugins/v2.so"]);
            let logs = Arc::new(Mutex::new(Vec::new()));
            let h = Arc::new(new_fake_host(Arc::clone(&loader), Arc::clone(&logs)));
            let report = h.apply_config(vec![desired("echo", "/plugins/echo.so")]);
            assert_eq!(report.loaded.len(), 1, "iter {iter} initial: {report:?}");
            let old_fake = Arc::clone(&clients["/plugins/echo.so"]);
            let new_fake = Arc::clone(&clients["/plugins/v2.so"]);
            old_fake.set_block_methods(&[pluginabi::METHOD_PROVIDER_CALL]);
            let h_call = Arc::clone(&h);
            let call_handle = std::thread::spawn(move || {
                h_call.call(
                    "echo",
                    pluginabi::METHOD_PROVIDER_CALL,
                    br#"{"input":"ping"}"#,
                    Some(Duration::from_millis(120)),
                )
            });
            std::thread::sleep(Duration::from_millis(10));
            let report = h.apply_config(vec![desired("echo", "/plugins/v2.so")]);
            assert_eq!(report.loaded.len(), 1, "iter {iter} replace: {report:?}");
            new_fake.set_panic_methods(&[pluginabi::METHOD_PROVIDER_CALL]);
            assert!(
                h.call("echo", pluginabi::METHOD_PROVIDER_CALL, &[], None)
                    .is_err(),
                "iter {iter}: panicking call must error"
            );
            let before = new_fake.call_count(pluginabi::METHOD_PROVIDER_CALL);
            let err = h
                .call("echo", pluginabi::METHOD_PROVIDER_CALL, &[], None)
                .unwrap_err();
            assert!(err.to_string().contains("fused"), "iter {iter}: {err}");
            assert_eq!(
                new_fake.call_count(pluginabi::METHOD_PROVIDER_CALL),
                before,
                "iter {iter}: fused plugin re-called before stale fuse landed"
            );
            let _ = call_handle.join();
            assert!(h.fused("echo").is_some(), "iter {iter}: must stay fused");
            assert!(
                h.loaded("echo").is_none(),
                "iter {iter}: Loaded() must be false"
            );
            let before = new_fake.call_count(pluginabi::METHOD_PROVIDER_CALL);
            let err = h
                .call("echo", pluginabi::METHOD_PROVIDER_CALL, &[], None)
                .unwrap_err();
            let after = new_fake.call_count(pluginabi::METHOD_PROVIDER_CALL);
            if after != before {
                reinvocations += 1;
            }
            let _ = err;
            h.close();
        }
        assert_eq!(
            reinvocations, 0,
            "stale fuse clobbered the current fuse in {reinvocations}/60 iterations"
        );
    }

    /// Port of `TestHostFusedSkipReasonStripsForgedControls`
    /// (`host_hardening_test.go:860-895`).
    #[test]
    fn host_fused_skip_reason_strips_forged_controls() {
        let (loader, clients) = fake_setup(&["/plugins/echo.so"]);
        let logs = Arc::new(Mutex::new(Vec::new()));
        let h = new_fake_host(Arc::clone(&loader), Arc::clone(&logs));
        let report = h.apply_config(vec![desired("echo", "/plugins/echo.so")]);
        assert_eq!(report.loaded.len(), 1, "{report:?}");
        clients["/plugins/echo.so"].set_on_call(Arc::new(|method: &str, _req: &[u8]| {
            if method == pluginabi::METHOD_PLUGIN_RECONFIGURE {
                return Err(ClientError::Transport(PluginHostError::failed(
                    "reconfigure boom",
                )));
            }
            if method == pluginabi::METHOD_PLUGIN_REGISTER {
                return Err(ClientError::Transport(PluginHostError::failed(
                    "rollback boom \u{9b}[31mRED\u{85}TAIL",
                )));
            }
            Ok(error_response("unexpected", "unexpected call"))
        }));
        let report = h.apply_config(vec![desired_with_fragment(
            "echo",
            "/plugins/echo.so",
            r#"{"n":2}"#,
        )]);
        assert_eq!(report.skipped.len(), 1, "{report:?}");
        let report = h.apply_config(vec![desired("echo", "/plugins/echo.so")]);
        assert_eq!(report.skipped.len(), 1);
        assert!(report.skipped[0].reason.contains("fused"), "{report:?}");
        let reason = &report.skipped[0].reason;
        assert!(!reason.contains("\u{9b}[31m"));
        assert!(!reason.contains('\u{85}'));
        for r in reason.chars() {
            assert!(
                !(('\u{80}'..='\u{9f}').contains(&r)),
                "kept C1 control U+{:04X}: {reason:?}",
                r as u32
            );
        }
        assert!(!reason.contains("[31m"), "kept CSI remnant: {reason:?}");
        h.close();
    }

    /// `dispatch_host_call`: the allowlist has exactly
    /// one method, `host.log`. Port of the
    /// `dispatchHostCall` cases in `host.go:899-954`.
    #[test]
    fn dispatch_host_call() {
        let (loader, _clients) = fake_setup(&[]);
        let logs = Arc::new(Mutex::new(Vec::new()));
        let h = new_fake_host(Arc::clone(&loader), Arc::clone(&logs));
        // Unknown method -> error envelope.
        let out = h.dispatch_host_call("host.auth.get", b"{}");
        let env: Envelope = serde_json::from_slice(&out).unwrap();
        assert!(!env.ok);
        assert_eq!(env.error.unwrap().code, "unsupported_host_callback");
        // Bad JSON -> error envelope.
        let out = h.dispatch_host_call(pluginabi::METHOD_HOST_LOG, b"not json");
        let env: Envelope = serde_json::from_slice(&out).unwrap();
        assert!(!env.ok);
        assert_eq!(env.error.unwrap().code, "invalid_host_log_request");
        // host.log: level allowlist, message sanitised.
        let out = h.dispatch_host_call(
            pluginabi::METHOD_HOST_LOG,
            br#"{"level":"warning","message":"hello\nworld"}"#,
        );
        let env: Envelope = serde_json::from_slice(&out).unwrap();
        assert!(env.ok);
        assert_eq!(env.result, Some(serde_json::json!({})));
        let guard = logs.lock().unwrap();
        assert_eq!(guard.len(), 1);
        assert_eq!(guard[0], "warn:hello world");
        drop(guard);
        // Empty message -> "plugin log"; unknown level -> info.
        let out = h.dispatch_host_call(
            pluginabi::METHOD_HOST_LOG,
            br#"{"level":"bogus","message":"   "}"#,
        );
        assert!(serde_json::from_slice::<Envelope>(&out).unwrap().ok);
        let guard = logs.lock().unwrap();
        assert_eq!(guard.len(), 2);
        assert_eq!(guard[1], "info:plugin log");
        h.close();
    }

    #[test]
    fn is_error_envelope_cases() {
        assert!(is_error_envelope(error_response("boom", "x").as_slice()));
        assert!(!is_error_envelope(
            ok_response(serde_json::json!({})).as_slice()
        ));
        assert!(!is_error_envelope(b"not json"));
    }
}
