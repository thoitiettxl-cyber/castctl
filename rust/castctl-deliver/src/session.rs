// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Session commands (M7a): port of Go
//! `internal/deliver/session.go`.

use std::sync::Arc;

use castctl_config::jsonvalue::{JsonValue, OrderedObject};
use serde_json::Value;

use crate::{DeliverError, DeliverGateway, obj};

/// One session operation, named after the subcommand
/// suffix in the argparse loop (Go `SessionOpKind`).
/// The string value is the gateway method suffix: the
/// method is `"session." + kind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SessionOpKind {
    /// Rename a session.
    Rename,
    /// Pin a session.
    Pin,
    /// Unpin a session.
    Unpin,
    /// Archive a session.
    Archive,
    /// Unarchive a session.
    Unarchive,
    /// Delete a session.
    Delete,
}

impl SessionOpKind {
    /// The kind string (Go's `SessionOpKind` value).
    pub fn as_str(&self) -> &'static str {
        match self {
            SessionOpKind::Rename => "rename",
            SessionOpKind::Pin => "pin",
            SessionOpKind::Unpin => "unpin",
            SessionOpKind::Archive => "archive",
            SessionOpKind::Unarchive => "unarchive",
            SessionOpKind::Delete => "delete",
        }
    }

    /// Parse a kind string (Go's `SessionOpKind` cast).
    /// Unknown strings parse to `None`; `session_op`
    /// reports those as an error without a round trip.
    pub fn parse(s: &str) -> Option<SessionOpKind> {
        match s {
            "rename" => Some(SessionOpKind::Rename),
            "pin" => Some(SessionOpKind::Pin),
            "unpin" => Some(SessionOpKind::Unpin),
            "archive" => Some(SessionOpKind::Archive),
            "unarchive" => Some(SessionOpKind::Unarchive),
            "delete" => Some(SessionOpKind::Delete),
            _ => None,
        }
    }

    /// The six valid kinds, in argparse order (Go's
    /// `validSessionOpKinds`).
    pub fn all() -> [SessionOpKind; 6] {
        [
            SessionOpKind::Rename,
            SessionOpKind::Pin,
            SessionOpKind::Unpin,
            SessionOpKind::Archive,
            SessionOpKind::Unarchive,
            SessionOpKind::Delete,
        ]
    }
}

/// Start a new side chat and return the server reply
/// verbatim (parsed JSON) (Go `SessionStart`). An empty
/// title is omitted from the params, exactly as in
/// Python. The body field order is the Python dict order:
/// `method`, `params{origin, lifecycle, title?}`.
pub async fn session_start(
    gw: Option<&Arc<dyn DeliverGateway>>,
    title: &str,
) -> Result<Value, DeliverError> {
    let gw = match gw {
        Some(gw) => gw,
        None => {
            return Err(DeliverError::msg("deliver: session start: nil gateway"));
        }
    };
    let mut params = OrderedObject::new();
    params.set("origin".to_string(), JsonValue::Str("fresh".to_string()));
    params.set(
        "lifecycle".to_string(),
        JsonValue::Str("persistent".to_string()),
    );
    if !title.is_empty() {
        params.set("title".to_string(), JsonValue::Str(title.to_string()));
    }
    let body = obj(&[
        ("method", JsonValue::Str("/api/session/start".to_string())),
        ("params", JsonValue::Object(params)),
    ]);
    gw.call_json("session.start", body).await
}

/// Rename, pin, unpin, archive, unarchive, or delete one
/// session and return the server reply verbatim (Go
/// `SessionOp`). Rename sends `{"session_id", "title"}`;
/// every other kind sends `{"method":
/// "/api/session/<kind>", "session_id"}`. The title
/// argument is ignored for kinds other than rename. An
/// unknown kind is an error: the argparse loop only ever
/// produces the six kinds above, so an unknown kind is a
/// caller bug, not a server round trip.
pub async fn session_op(
    gw: Option<&Arc<dyn DeliverGateway>>,
    kind: &str,
    session_id: &str,
    title: &str,
) -> Result<Value, DeliverError> {
    let gw = match gw {
        Some(gw) => gw,
        None => {
            return Err(DeliverError::msg(format!(
                "deliver: session {kind}: nil gateway"
            )));
        }
    };
    let kind = match SessionOpKind::parse(kind) {
        Some(kind) => kind,
        None => {
            return Err(DeliverError::msg(format!(
                "deliver: unknown session operation {kind:?}"
            )));
        }
    };
    let method = format!("session.{}", kind.as_str());
    if kind == SessionOpKind::Rename {
        let body = obj(&[
            ("session_id", JsonValue::Str(session_id.to_string())),
            ("title", JsonValue::Str(title.to_string())),
        ]);
        return gw.call_json(&method, body).await;
    }
    let body = obj(&[
        (
            "method",
            JsonValue::Str(format!("/api/session/{}", kind.as_str())),
        ),
        ("session_id", JsonValue::Str(session_id.to_string())),
    ]);
    gw.call_json(&method, body).await
}
