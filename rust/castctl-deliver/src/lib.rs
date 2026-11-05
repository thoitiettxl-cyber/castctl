// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Offline library commands (M7a): port of Go
//! `internal/deliver`.
//!
//! This package does NOT deliver messages or turn output:
//! it is the offline library behind `session-*`,
//! `stop`, `wake`, `auth list` and `auth export`
//! (`session.go`, `stop.go`, `wake.go`, `authlist.go`,
//! `authexport.go`). `deliverFinal`
//! (`telegram_turn.go:793`) is M5b scope, not ported here.
//!
//! Deliberate adaptations (recorded in PORTING.md §M7a):
//! - Go's `context.Context` is dropped: cancellation is by
//!   dropping the future, as everywhere else in the Rust
//!   port. The one Wake sub-test asserting a cancelled
//!   context reaches the wake helper is not portable and is
//!   recorded, not ported. The 15s `WakeTimeout` bound is
//!   enforced with `tokio::time::timeout` instead.
//! - `gateway.WakeVM` has no Rust counterpart yet
//!   (`internal/gateway/wake.go` is not ported in M7a), so
//!   the compile-time wiring test
//!   `TestWakeFuncMatchesGatewayWakeVM` is not portable;
//!   `Wake` takes the helper as an injected `WakeFn` and
//!   the commands layer will pass the Rust helper once it
//!   exists.
//! - Request bodies are `castctl_config::JsonValue`
//!   (insertion-ordered), not `serde_json::Value`: Go
//!   marshals these bodies from structs (field order),
//!   and the ported tests compare exact body JSON. Reply
//!   values stay `serde_json::Value` (the gateway decodes
//!   them that way).
//!
//! No `unsafe`, no `unwrap()`/`expect()` on external input.

use std::error::Error;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use castctl_config::errors::ConfigError;
use castctl_config::jsonvalue::{JsonValue, OrderedObject};
use castctl_transport::TransportError;
use serde_json::Value;

pub mod authexport;
pub mod authlist;
pub mod session;
pub mod stop;
pub mod wake;

pub use authexport::{EXPORT_GUIDANCE, ExportError, auth_export};
pub use authlist::{AuthList, ProfileRow, format_auth_list, list_profiles};
pub use session::{SessionOpKind, session_op, session_start};
pub use stop::stop_turn;
pub use wake::{WAKE_TIMEOUT, WakeDeps, WakeResult, WakeFn, wake};

/// A boxed error.
pub type BoxError = Box<dyn Error + Send + Sync>;

/// Errors from the deliver package.
#[derive(Debug)]
pub enum DeliverError {
    /// A gateway failure, verbatim.
    Transport(TransportError),
    /// A config failure (profile discovery / load).
    Config(ConfigError),
    /// A local-filesystem failure.
    Io(std::io::Error),
    /// A plain-message error.
    Message(String),
    /// A context-wrapped error (Go's `fmt.Errorf("...: %w")`).
    /// `Display` is `"{context}: {source}"`; `source()` is
    /// the wrapped error, so `error_is`-style walks see
    /// through it.
    Wrapped {
        /// Wrapping context (includes the trailing detail,
        /// e.g. `"deliver: wake: fetch access token"`).
        context: String,
        /// The wrapped error.
        source: BoxError,
    },
    /// No wake helper was injected (Go's
    /// `ErrWakeUnavailable` sentinel).
    WakeUnavailable,
}

impl DeliverError {
    /// A plain-message error.
    pub fn msg(message: impl Into<String>) -> DeliverError {
        DeliverError::Message(message.into())
    }

    /// Wrap an error with context (Go's
    /// `fmt.Errorf("<context>: %w", err)`).
    pub fn wrap(context: impl Into<String>, source: BoxError) -> DeliverError {
        DeliverError::Wrapped {
            context: context.into(),
            source,
        }
    }

    /// Whether this error is an auth failure (Go
    /// `errors.As(err, &AuthError)`).
    pub fn is_auth(&self) -> bool {
        matches!(self, DeliverError::Transport(TransportError::Auth { .. }))
    }
}

impl fmt::Display for DeliverError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DeliverError::Transport(e) => fmt::Display::fmt(e, f),
            DeliverError::Config(e) => fmt::Display::fmt(e, f),
            DeliverError::Io(e) => fmt::Display::fmt(e, f),
            DeliverError::Message(m) => f.write_str(m),
            DeliverError::Wrapped { context, source } => {
                write!(f, "{context}: {source}")
            }
            DeliverError::WakeUnavailable => {
                f.write_str("deliver: wake helper not available")
            }
        }
    }
}

impl Error for DeliverError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            DeliverError::Transport(e) => Some(e),
            DeliverError::Config(e) => Some(e),
            DeliverError::Io(e) => Some(e),
            DeliverError::Message(_) => None,
            DeliverError::Wrapped { source, .. } => {
                Some(source.as_ref() as &(dyn Error + 'static))
            }
            DeliverError::WakeUnavailable => None,
        }
    }
}

impl From<TransportError> for DeliverError {
    fn from(e: TransportError) -> DeliverError {
        DeliverError::Transport(e)
    }
}

impl From<ConfigError> for DeliverError {
    fn from(e: ConfigError) -> DeliverError {
        DeliverError::Config(e)
    }
}

impl From<std::io::Error> for DeliverError {
    fn from(e: std::io::Error) -> DeliverError {
        DeliverError::Io(e)
    }
}

/// Whether an error chain contains an error of type `T`
/// anywhere (Go's `errors.Is` / `errors.As` walk).
pub fn error_is<T: Error + 'static>(err: &(dyn Error + 'static)) -> bool {
    let mut current: Option<&(dyn Error + 'static)> = Some(err);
    while let Some(e) = current {
        if e.downcast_ref::<T>().is_some() {
            return true;
        }
        current = e.source();
    }
    false
}

/// The minimal gateway surface this package needs: one
/// unary JSON call (Go `deliver.Gateway`). Go's deliver
/// calls pass no timeout (the gateway default applies).
/// The body is an ordered JSON value (see the module
/// docs); the reply is returned verbatim as decoded JSON.
pub trait DeliverGateway: Send + Sync {
    /// One call.
    fn call_json(
        &self,
        method: &str,
        body: JsonValue,
    ) -> Pin<Box<dyn Future<Output = Result<Value, DeliverError>> + Send + '_>>;
}

/// Build an ordered JSON object from key/value pairs in
/// the given order.
pub fn obj(pairs: &[(&str, JsonValue)]) -> JsonValue {
    let mut o = OrderedObject::new();
    for (k, v) in pairs {
        o.set(k.to_string(), v.clone());
    }
    JsonValue::Object(o)
}
