//! Single-file config parse/validate/render and profile
//! resolution, ported from castctl's Go `internal/profile` (M2).
//!
//! Scope (D-M2-1): the config/profile surface that is computable
//! without sing-box's option registry. Sing-box option validation
//! (tag graph, DNS, WireGuard) is deferred and recorded in
//! PORTING.md; the deferred blocks are stored raw and rendered
//! verbatim.
//!
//! No `unsafe`, no `unwrap()`/`expect()` on external input. Every
//! public item cites its Go source at base `dev-rust` `85a8d5e`.

pub mod blocks;
pub mod config;
pub mod configlocation;
pub mod errors;
pub mod fingerprint;
pub mod gopath;
pub mod gostr;
pub mod jsonvalue;
pub mod log;
pub mod oserr;
pub mod profile;
pub mod telegram;

pub use errors::{ConfigError, config_error};
