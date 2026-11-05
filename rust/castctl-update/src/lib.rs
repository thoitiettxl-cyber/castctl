// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Self-update: release selection, download, verification, safe replace.
//!
//! Go sources: `internal/update/semver.go`, `checksums.go`,
//! `extract.go`, `lock_unix.go`, `replace.go`, `update.go`
//! (all at `dev-rust` `25a124e`). No Go code was changed.
//!
//! Crate map:
//!
//! | Module | Go source | Contents |
//! |---|---|---|
//! | `error` | `update.go:130-160` | `UpdateError` (exit-code contract) + `HttpError` summary |
//! | `semver` | `semver.go` | Hand-rolled semver 2.0.0 parser + comparison |
//! | `checksums` | `checksums.go` | `sha256sum`-format parser (update flavour) |
//! | `extract` | `extract.go:38-122` | `extract_castctl` (gzip tar, castctl member only) |
//! | `elf` | `extract.go:124-154` | Hand-rolled 64-byte ELF header validation |
//! | `lock` | `lock_unix.go` | Non-blocking advisory flock on `.castctl-update.lock` |
//! | `replace` | `replace.go` | `open_for_sync` ETXTBSY retry, `sync_dir`, exec check |
//! | `select` | `update.go:602-857` | Asset selection, `decide`, redirect policy, URL validation, transport-error taxonomy |
//! | `http` | `update.go:383-570` | Sync HTTP fetcher (TcpStream + rustls for https) behind the `Fetcher` trait |
//! | `run` | `update.go:227-302`, `replace.go:88-265` | `run` / `install` / `dry_run` (`Run(Options)`-equivalent) |
//!
//! Security invariants (Go `update.go:130-145`, `replace.go:322-328`):
//! no signature verification exists in Go and none is added here
//! (see `docs/architecture.md:213-216`); error messages are built
//! only from constants, parsed versions, and constructed asset
//! names — never from server bytes, URLs, or transport error text;
//! the exec check runs only on checksum-verified bytes.

pub mod checksums;
pub mod elf;
pub mod error;
pub mod extract;
pub mod http;
pub mod lock;
pub mod replace;
pub mod run;
pub mod select;
pub mod semver;

pub use error::{HttpError, UpdateError};
pub use run::{Deps, Options, Result, run};
pub use semver::{Version, compare_versions, parse_version};
