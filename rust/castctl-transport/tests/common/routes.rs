// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

/// A route table with exactly the methods the RPC tests need,
/// in the `routes.json` shape (the real table is covered by the
/// unit tests in `routes.rs`).
pub fn test_routes() -> castctl_transport::RouteTable {
    castctl_transport::RouteTable::parse(
        r#"[{"method":"connection.ping","http":"GET","path":"/ping"},
            {"method":"chat.history","http":"GET","path":"/chat/history"},
            {"method":"chat.mark_seen","http":"POST","path":"/api/chat/{thread_id}/seen"},
            {"method":"egress.approval.decide","http":"POST","path":"/egress/decide"},
            {"method":"fs.read","http":"POST","path":"/fs/read"}]"#,
    )
    .expect("INVARIANT: test route table parses")
}
