// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! User-facing chat texts, GENERATED from Go source — do
//! not hand-edit. Regenerate with
//! `python3 rust/parity/gen_chat_texts.py` (it extracts
//! the constants byte-exact from `internal/commands/chat.go`
//! (`chatHelpText`) and `internal/deliver/authexport.go`
//! (`ExportGuidance`)).

/// The `/help` text (`chat.go` `chatHelpText`).
pub const CHAT_HELP_TEXT: &str = r#"Commands:
  /chats          list your conversations
  /open N         switch to conversation number N from /chats
  /main           switch to your main chat
  /new [title]    start a new conversation
  /history [N]    read the last N messages here (default 10)
  /login          save your muse.ai login from Chrome again (same as `castctl auth export`)
  /exit           quit (Ctrl+C works too)"#;

/// The `/login` + startup-auth guidance
/// (`deliver/authexport.go` `ExportGuidance`).
pub const EXPORT_GUIDANCE: &str = r#"cookie export is not available in this build: no automatic cookie extraction is implemented yet.

Log in at https://muse.ai/ in your browser, leave the tab open, and run "castctl auth export" again after a cookie source exists.

Copy the login by hand instead:
  1. In your browser, open https://muse.ai/ and log in.
  2. Open the browser developer tools and read the cookies for https://muse.ai/.
  3. Write one line to the active profile's cookies.txt file:
       hatch_sess=VALUE; other_name=other_value
     hatch_sess is required. Separate cookies with "; ".
  4. Set the file mode to 600.
  5. Run "castctl status" to check the login.

No file was written or changed."#;
