// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Plugins endpoint (`internal/webui/plugins.go`).
//!
//! Always 200 `{available:false, reason:"plugin support
//! is not available in this build (plugin core lands
//! separately; a follow-up wires list/enable/disable)",
//! plugins:[]}` — plugin support is not available in
//! this build, and the handler says so explicitly instead
//! of serving fake data.

use crate::go_json::encode_go_json_line;
use crate::server::{Resp, api_headers};
use castctl_config::jsonvalue::{JsonValue, OrderedObject};

/// `handleGetPlugins`: the fixed 200 response. Keys in Go
/// struct order: available, plugins, reason (the Go struct
/// declares them in that order — see `plugins.go`).
pub fn handle_get_plugins() -> Resp {
    let mut data = OrderedObject::new();
    data.set("available".to_string(), JsonValue::Bool(false));
    data.set("plugins".to_string(), JsonValue::Array(vec![]));
    data.set(
        "reason".to_string(),
        JsonValue::Str(
            "plugin support is not available in this build (plugin core lands separately; a follow-up wires list/enable/disable)"
                .to_string(),
        ),
    );
    let mut envelope = OrderedObject::new();
    envelope.set("data".to_string(), JsonValue::Object(data));
    Resp {
        status: 200,
        headers: api_headers(),
        body: encode_go_json_line(&JsonValue::Object(envelope)).into_bytes(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plugins_always_unavailable() {
        let resp = handle_get_plugins();
        assert_eq!(resp.status, 200);
        let text = String::from_utf8(resp.body).unwrap();
        assert_eq!(
            text,
            "{\"data\":{\"available\":false,\"plugins\":[],\"reason\":\"plugin support is not available in this build (plugin core lands separately; a follow-up wires list/enable/disable)\"}}\n"
        );
    }
}
