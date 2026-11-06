// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Stop-turn command (M7a): port of Go
//! `internal/deliver/stop.go`.

use std::sync::Arc;

use castctl_config::jsonvalue::JsonValue;
use serde_json::Value;

use crate::{DeliverError, DeliverGateway, obj};

/// Stop Muse's current turn (the web app's Stop
/// button) (Go `StopTurn`). The body is `{}` for the main
/// chat (empty thread) or `{"session_id": thread}` for a
/// side chat, as the web client sends it. The server reply
/// is returned verbatim (parsed JSON), e.g.
/// `{"cancelled": true}`.
pub async fn stop_turn(
    gw: Option<&Arc<dyn DeliverGateway>>,
    thread: &str,
) -> Result<Value, DeliverError> {
    let gw = match gw {
        Some(gw) => gw,
        None => return Err(DeliverError::msg("deliver: stop: nil gateway")),
    };
    let body = if thread.is_empty() {
        JsonValue::Object(Default::default())
    } else {
        obj(&[("session_id", JsonValue::Str(thread.to_string()))])
    };
    gw.call_json("chat.cancel", body).await
}
