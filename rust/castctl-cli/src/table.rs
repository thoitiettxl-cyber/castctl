//! The 46-command table (`internal/commands/commands.go`,
//! `commandOrder`, `registerFlags` calls in `read.go`, `wait.go`,
//! `deliver.go`, `fs.go`, `keeper.go`, `telegram.go`, `update.go`,
//! `profilecmd.go`, `plugincheck.go`, `chat.go`, `webui.go` at base
//! `dev-rust` `85a8d5e`).
//!
//! The short `help` field of Go's `commandSpec` is never printed
//! and is not ported. Help texts come from the generated
//! `help_texts` module (verbatim Go raw-string consts); usage lines
//! come from `registerFlags` and are used only on parser errors.

use crate::help_texts::*;
use crate::parser::{FlagDef, FlagKind, bool_flag, int_flag, int_flag_no_def, str_flag};

/// `commandOrder` (`commands.go:766`).
pub const COMMAND_ORDER: [&str; 46] = [
    "chat",
    "status",
    "usage",
    "invite",
    "redeem",
    "threads",
    "history",
    "send",
    "wait",
    "approvals",
    "approve",
    "auto-approve",
    "deny",
    "files",
    "download",
    "watch",
    "feed",
    "feed-status",
    "feed-react",
    "feed-prompt",
    "goals",
    "goal",
    "ideas",
    "idea",
    "idea-exec",
    "unread",
    "seen",
    "session-start",
    "session-rename",
    "session-pin",
    "session-unpin",
    "session-archive",
    "session-unarchive",
    "session-delete",
    "stop",
    "wake",
    "raw",
    "fs",
    "auth",
    "profile",
    "config",
    "telegram",
    "keeper",
    "update",
    "webui",
    "plugin",
];

/// Positional-argument handling for a `parseOrHelp` command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PositionalSpec {
    /// `checkPositionals` with the given names.
    Names(&'static [&'static str]),
    /// Manual 0-or-1 check (`profile show`/`test`, `fs ls`/`tree`):
    /// more than one is `unrecognized arguments: <extras>`.
    AtMostOne,
    /// Manual 1-or-2 check (`feed-react`): fewer than one is
    /// `the following arguments are required: unit`; more than two
    /// is `unrecognized arguments: <from 3rd>`.
    FeedReact,
    /// Manual 0-or-1 plus `approveDecision` plus the
    /// all-or-ID check (`approve`).
    Approve,
    /// Manual 0-to-2 plus state/once choice checks
    /// (`auto-approve`).
    AutoApprove,
    /// No positional check at parse time (the handler decides;
    /// `auth export` ignores extras entirely).
    None,
}

/// One registered command: its help text, usage line, flag defs,
/// and positional spec.
#[derive(Debug, Clone)]
pub struct CommandSpec {
    /// Command name.
    pub name: &'static str,
    /// Full `--help` text (verbatim Go const).
    pub help_text: &'static str,
    /// One-line usage for parser errors (`registerFlags` usage).
    pub usage_line: &'static str,
    /// Flag definitions (empty = only the implicit `--help`).
    pub defs: Vec<FlagDef>,
    /// Positional handling after a successful parse.
    pub positionals: PositionalSpec,
}

fn spec(
    name: &'static str,
    help_text: &'static str,
    usage_line: &'static str,
    defs: Vec<FlagDef>,
    positionals: PositionalSpec,
) -> CommandSpec {
    CommandSpec {
        name,
        help_text,
        usage_line,
        defs,
        positionals,
    }
}

/// The full command table, in `commandOrder` order.
pub fn command_table() -> Vec<CommandSpec> {
    vec![
        spec(
            "chat",
            CHAT_HELP_USAGE_TEXT,
            "chat",
            vec![],
            PositionalSpec::Names(&[]),
        ),
        spec(
            "status",
            STATUS_HELP_TEXT,
            "status",
            vec![],
            PositionalSpec::Names(&[]),
        ),
        spec(
            "usage",
            USAGE_HELP_TEXT,
            "usage [--json] [--raw]",
            vec![bool_flag("json"), bool_flag("raw")],
            PositionalSpec::Names(&[]),
        ),
        spec(
            "invite",
            INVITE_HELP_TEXT,
            "invite [--create] [--json] [--raw]",
            vec![bool_flag("json"), bool_flag("raw"), bool_flag("create")],
            PositionalSpec::Names(&[]),
        ),
        spec(
            "redeem",
            REDEEM_HELP_TEXT,
            "redeem CODE [--json]",
            vec![bool_flag("json")],
            PositionalSpec::Names(&["code"]),
        ),
        spec(
            "threads",
            THREADS_HELP_TEXT,
            "threads [--all]",
            vec![bool_flag("all")],
            PositionalSpec::Names(&[]),
        ),
        spec(
            "history",
            HISTORY_HELP_TEXT,
            "history [--thread ID] [--limit N] [--raw] [--download DIR]",
            vec![
                str_flag("thread"),
                int_flag("limit", 0, 10),
                bool_flag("raw"),
                str_flag("download"),
            ],
            PositionalSpec::Names(&[]),
        ),
        spec(
            "send",
            SEND_HELP_TEXT,
            "send TEXT [--thread ID] [--wait SECONDS] [--until-done] [--text] [--ack-timeout SECONDS] [--download DIR] [--auto-approve|--no-auto-approve] [--auto-allow-once|--no-auto-allow-once]",
            vec![
                str_flag("thread"),
                int_flag("wait", 0, 90),
                bool_flag("until-done"),
                bool_flag("text"),
                int_flag("ack-timeout", 0, 30),
                str_flag("download"),
                bool_flag("auto-approve"),
                bool_flag("no-auto-approve"),
                bool_flag("auto-allow-once"),
                bool_flag("no-auto-allow-once"),
            ],
            PositionalSpec::Names(&["text"]),
        ),
        spec(
            "wait",
            WAIT_HELP_TEXT,
            "wait [--thread ID] [--after-seq N] [--timeout SECONDS] [--json] [--require-running] [--auto-approve|--no-auto-approve] [--auto-allow-once|--no-auto-allow-once]",
            vec![
                str_flag("thread"),
                int_flag_no_def("after-seq"),
                int_flag("timeout", 0, 600),
                bool_flag("json"),
                bool_flag("require-running"),
                bool_flag("auto-approve"),
                bool_flag("no-auto-approve"),
                bool_flag("auto-allow-once"),
                bool_flag("no-auto-allow-once"),
            ],
            PositionalSpec::Names(&[]),
        ),
        spec(
            "approvals",
            APPROVALS_HELP_TEXT,
            "approvals [--recent] [--raw] [--approve-all]",
            vec![
                bool_flag("recent"),
                bool_flag("raw"),
                bool_flag("approve-all"),
            ],
            PositionalSpec::Names(&[]),
        ),
        spec(
            "approve",
            APPROVE_HELP_TEXT,
            "approve [ID] [--all] [--once|--session|--today|--always]",
            vec![
                bool_flag("all"),
                bool_flag("once"),
                bool_flag("session"),
                bool_flag("today"),
                bool_flag("always"),
            ],
            PositionalSpec::Approve,
        ),
        spec(
            "auto-approve",
            AUTO_APPROVE_HELP_TEXT,
            "auto-approve [on|always|off|status] [once on|off|status]",
            vec![],
            PositionalSpec::AutoApprove,
        ),
        spec(
            "deny",
            DENY_HELP_TEXT,
            "deny ID [--always]",
            vec![bool_flag("always")],
            PositionalSpec::Names(&["id"]),
        ),
        spec(
            "files",
            FILES_HELP_TEXT,
            "files [--thread ID] [--limit N]",
            vec![str_flag("thread"), int_flag("limit", 0, 20)],
            PositionalSpec::Names(&[]),
        ),
        spec(
            "download",
            DOWNLOAD_HELP_TEXT,
            "download REF [-o DIR] [--thread ID] [--limit N] [-f]",
            vec![
                FlagDef {
                    name: "output",
                    short: b'o',
                    kind: FlagKind::Str,
                    def_int: None,
                },
                str_flag("thread"),
                int_flag("limit", 0, 50),
                FlagDef {
                    name: "force",
                    short: b'f',
                    kind: FlagKind::Bool,
                    def_int: None,
                },
            ],
            PositionalSpec::Names(&["ref"]),
        ),
        spec(
            "watch",
            WATCH_HELP_TEXT,
            "watch [--timeout SECONDS] [--n N] [--all] [--thread ID]",
            vec![
                int_flag("timeout", 0, 60),
                int_flag("n", 0, 50),
                bool_flag("all"),
                str_flag("thread"),
            ],
            PositionalSpec::Names(&[]),
        ),
        spec(
            "feed",
            FEED_HELP_TEXT,
            "feed [--limit N] [--raw]",
            vec![int_flag_no_def("limit"), bool_flag("raw")],
            PositionalSpec::Names(&[]),
        ),
        spec(
            "feed-status",
            FEED_STATUS_HELP_TEXT,
            "feed-status",
            vec![],
            PositionalSpec::Names(&[]),
        ),
        spec(
            "feed-react",
            FEED_REACT_HELP_TEXT,
            "feed-react UNIT [REACTION]",
            vec![],
            PositionalSpec::FeedReact,
        ),
        spec(
            "feed-prompt",
            FEED_PROMPT_HELP_TEXT,
            "feed-prompt",
            vec![],
            PositionalSpec::Names(&[]),
        ),
        spec(
            "goals",
            GOALS_HELP_TEXT,
            "goals",
            vec![],
            PositionalSpec::Names(&[]),
        ),
        spec(
            "goal",
            GOAL_HELP_TEXT,
            "goal ID",
            vec![],
            PositionalSpec::Names(&["id"]),
        ),
        spec(
            "ideas",
            IDEAS_HELP_TEXT,
            "ideas",
            vec![],
            PositionalSpec::Names(&[]),
        ),
        spec(
            "idea",
            IDEA_HELP_TEXT,
            "idea ID",
            vec![],
            PositionalSpec::Names(&["id"]),
        ),
        spec(
            "idea-exec",
            IDEA_EXEC_HELP_TEXT,
            "idea-exec ID [--thread ID]",
            vec![str_flag("thread")],
            PositionalSpec::Names(&["id"]),
        ),
        spec(
            "unread",
            UNREAD_HELP_TEXT,
            "unread",
            vec![],
            PositionalSpec::Names(&[]),
        ),
        spec(
            "seen",
            SEEN_HELP_TEXT,
            "seen THREAD",
            vec![],
            PositionalSpec::Names(&["thread"]),
        ),
        spec(
            "session-start",
            SESSION_START_HELP_TEXT,
            "session-start [--title TITLE]",
            vec![str_flag("title")],
            PositionalSpec::Names(&[]),
        ),
        spec(
            "session-rename",
            SESSION_OP_HELP_TEXT,
            "session-rename",
            vec![],
            PositionalSpec::Names(&["id", "title"]),
        ),
        spec(
            "session-pin",
            SESSION_OP_HELP_TEXT,
            "session-pin",
            vec![],
            PositionalSpec::Names(&["id"]),
        ),
        spec(
            "session-unpin",
            SESSION_OP_HELP_TEXT,
            "session-unpin",
            vec![],
            PositionalSpec::Names(&["id"]),
        ),
        spec(
            "session-archive",
            SESSION_OP_HELP_TEXT,
            "session-archive",
            vec![],
            PositionalSpec::Names(&["id"]),
        ),
        spec(
            "session-unarchive",
            SESSION_OP_HELP_TEXT,
            "session-unarchive",
            vec![],
            PositionalSpec::Names(&["id"]),
        ),
        spec(
            "session-delete",
            SESSION_OP_HELP_TEXT,
            "session-delete",
            vec![],
            PositionalSpec::Names(&["id"]),
        ),
        spec(
            "stop",
            STOP_HELP_TEXT,
            "stop [--thread ID]",
            vec![str_flag("thread")],
            PositionalSpec::Names(&[]),
        ),
        spec(
            "wake",
            WAKE_HELP_TEXT,
            "wake",
            vec![],
            PositionalSpec::Names(&[]),
        ),
        spec(
            "raw",
            RAW_HELP_TEXT,
            "raw METHOD [--body JSON] [--param KEY=VALUE] [--timeout SECONDS]",
            vec![
                str_flag("body"),
                FlagDef {
                    name: "param",
                    short: 0,
                    kind: FlagKind::StringList,
                    def_int: None,
                },
                int_flag("timeout", 0, 30),
            ],
            PositionalSpec::Names(&["method"]),
        ),
        spec(
            "fs",
            FS_HELP_TEXT,
            "fs <subcommand> [options]",
            vec![],
            PositionalSpec::None,
        ),
        spec(
            "auth",
            AUTH_HELP_TEXT,
            "auth <subcommand> [options]",
            vec![],
            PositionalSpec::None,
        ),
        spec(
            "profile",
            PROFILE_HELP_TEXT,
            "profile <subcommand> [options]",
            vec![],
            PositionalSpec::None,
        ),
        spec(
            "config",
            CONFIG_HELP_TEXT,
            "config <subcommand> [options]",
            vec![],
            PositionalSpec::None,
        ),
        spec(
            "telegram",
            TELEGRAM_HELP_TEXT,
            "telegram <subcommand> [options]",
            vec![],
            PositionalSpec::None,
        ),
        spec(
            "keeper",
            KEEPER_HELP_TEXT,
            "keeper <subcommand> [options]",
            vec![],
            PositionalSpec::None,
        ),
        spec(
            "update",
            UPDATE_HELP_TEXT,
            "update [--dry-run] [--version TAG] [--allow-downgrade] [--allow-prerelease]",
            vec![
                bool_flag("dry-run"),
                str_flag("version"),
                bool_flag("allow-downgrade"),
                bool_flag("allow-prerelease"),
            ],
            PositionalSpec::Names(&[]),
        ),
        spec(
            "webui",
            WEBUI_HELP_TEXT,
            "webui <subcommand> [options]",
            vec![],
            PositionalSpec::None,
        ),
        spec(
            "plugin",
            PLUGIN_CHECK_HELP_TEXT,
            "plugin check <path> [--tag TAG] [--type TYPE]",
            vec![],
            PositionalSpec::None,
        ),
    ]
}

/// Look up a command by name.
pub fn command_spec(name: &str) -> Option<CommandSpec> {
    command_table().into_iter().find(|s| s.name == name)
}

/// `fsSubcommands` (`fs.go`).
pub const FS_SUBCOMMANDS: [&str; 12] = [
    "ls", "tree", "stat", "cat", "get", "find", "put", "write", "edit", "mkdir", "mv", "rm",
];

/// `fsDefs` (`fs.go`): flag defs + help text per fs subcommand.
pub fn fs_defs(sub: &str) -> (Vec<FlagDef>, &'static str) {
    match sub {
        "ls" => (
            vec![
                FlagDef {
                    name: "long",
                    short: b'l',
                    kind: FlagKind::Bool,
                    def_int: None,
                },
                FlagDef {
                    name: "all",
                    short: b'a',
                    kind: FlagKind::Bool,
                    def_int: None,
                },
                bool_flag("json"),
            ],
            FS_LS_HELP_TEXT,
        ),
        "tree" => (
            vec![
                int_flag("depth", 0, 2),
                FlagDef {
                    name: "all",
                    short: b'a',
                    kind: FlagKind::Bool,
                    def_int: None,
                },
                bool_flag("json"),
            ],
            FS_TREE_HELP_TEXT,
        ),
        "stat" => (vec![], FS_STAT_HELP_TEXT),
        "cat" => (
            vec![int_flag_no_def("max-bytes"), bool_flag("binary")],
            FS_CAT_HELP_TEXT,
        ),
        "get" => (
            vec![
                FlagDef {
                    name: "output",
                    short: b'o',
                    kind: FlagKind::Str,
                    def_int: None,
                },
                FlagDef {
                    name: "recursive",
                    short: b'r',
                    kind: FlagKind::Bool,
                    def_int: None,
                },
            ],
            FS_GET_HELP_TEXT,
        ),
        "find" => (vec![int_flag_no_def("limit")], FS_FIND_HELP_TEXT),
        "put" => (
            vec![
                FlagDef {
                    name: "recursive",
                    short: b'r',
                    kind: FlagKind::Bool,
                    def_int: None,
                },
                FlagDef {
                    name: "no-clobber",
                    short: b'n',
                    kind: FlagKind::Bool,
                    def_int: None,
                },
            ],
            FS_PUT_HELP_TEXT,
        ),
        "write" => (
            vec![
                bool_flag("append"),
                FlagDef {
                    name: "no-clobber",
                    short: b'n',
                    kind: FlagKind::Bool,
                    def_int: None,
                },
            ],
            FS_WRITE_HELP_TEXT,
        ),
        "edit" => (
            vec![FlagDef {
                name: "replace",
                short: 0,
                kind: FlagKind::PairList,
                def_int: None,
            }],
            FS_EDIT_HELP_TEXT,
        ),
        "mkdir" => (vec![], FS_MKDIR_HELP_TEXT),
        "mv" => (
            vec![FlagDef {
                name: "force",
                short: b'f',
                kind: FlagKind::Bool,
                def_int: None,
            }],
            FS_MV_HELP_TEXT,
        ),
        "rm" => (
            vec![
                FlagDef {
                    name: "recursive",
                    short: b'r',
                    kind: FlagKind::Bool,
                    def_int: None,
                },
                bool_flag("yes"),
            ],
            FS_RM_HELP_TEXT,
        ),
        _ => (vec![], ""),
    }
}

/// Positional names for an fs subcommand (`fsPositionals` calls in
/// `fs.go`); `None` means the 0-or-1 manual check (`fsLs`/`fsTree`).
pub fn fs_positional_names(sub: &str) -> Option<&'static [&'static str]> {
    match sub {
        "ls" | "tree" => None,
        "stat" | "cat" | "get" | "mkdir" | "rm" => Some(&["path"]),
        "find" => Some(&["name"]),
        "put" => Some(&["local", "remote"]),
        "write" | "edit" => Some(&["remote"]),
        "mv" => Some(&["src", "dst"]),
        _ => Some(&[]),
    }
}

/// `profileSubcommands` (`profilecmd.go:50`).
pub const PROFILE_SUBCOMMANDS: [&str; 8] = [
    "list",
    "show",
    "add",
    "rm",
    "set-outbound",
    "set-fingerprint",
    "set-tls-engine",
    "test",
];

/// `telegramSubcommands` (`telegram.go:80`).
pub const TELEGRAM_SUBCOMMANDS: [&str; 2] = ["run", "status"];

/// `keeper` subcommands (`keeper.go`, `cmdKeeper`).
pub const KEEPER_SUBCOMMANDS: [&str; 3] = ["run", "check", "status"];

/// Help text for a profile subcommand.
pub fn profile_sub_help(sub: &str) -> &'static str {
    match sub {
        "list" => PROFILE_LIST_HELP_TEXT,
        "show" => PROFILE_SHOW_HELP_TEXT,
        "add" => PROFILE_ADD_HELP_TEXT,
        "rm" => PROFILE_RM_HELP_TEXT,
        "set-outbound" => PROFILE_SET_OUTBOUND_HELP_TEXT,
        "set-fingerprint" => PROFILE_SET_FINGERPRINT_HELP_TEXT,
        "set-tls-engine" => PROFILE_SET_TLS_ENGINE_HELP_TEXT,
        "test" => PROFILE_TEST_HELP_TEXT,
        _ => "",
    }
}

/// Flag defs for a profile subcommand (`profileParse` calls).
pub fn profile_sub_defs(sub: &str) -> Vec<FlagDef> {
    match sub {
        "add" => vec![
            str_flag("cookies-file"),
            str_flag("outbound"),
            bool_flag("set-default"),
            bool_flag("outbound-from-env"),
            str_flag("fingerprint"),
            str_flag("tls-engine"),
        ],
        "rm" => vec![bool_flag("yes")],
        _ => vec![],
    }
}

/// Help text for a keeper subcommand.
pub fn keeper_sub_help(sub: &str) -> &'static str {
    match sub {
        "run" => KEEPER_RUN_HELP_TEXT,
        "check" => KEEPER_CHECK_HELP_TEXT,
        "status" => KEEPER_STATUS_HELP_TEXT,
        _ => "",
    }
}

/// Help text for an auth subcommand.
pub fn auth_sub_help(sub: &str) -> &'static str {
    match sub {
        "list" => AUTH_LIST_HELP_TEXT,
        "export" => AUTH_EXPORT_HELP_TEXT,
        "import" => AUTH_IMPORT_HELP_TEXT,
        "login" => AUTH_LOGIN_HELP_TEXT,
        "status" => AUTH_STATUS_HELP_TEXT,
        "observe-login" => AUTH_OBSERVE_LOGIN_HELP_TEXT,
        _ => "",
    }
}

/// Flag defs for an auth subcommand.
pub fn auth_sub_defs(sub: &str) -> Vec<FlagDef> {
    match sub {
        "list" => vec![bool_flag("json")],
        "login" => vec![
            str_flag("profile"),
            str_flag("timeout"),
            str_flag("browser-path"),
            bool_flag("experimental-login"),
        ],
        "status" => vec![str_flag("profile"), bool_flag("all")],
        "observe-login" => vec![str_flag("profile"), str_flag("login-url")],
        _ => vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_command_order_matches_go() {
        let table = command_table();
        assert_eq!(table.len(), 46);
        let names: Vec<&str> = table.iter().map(|s| s.name).collect();
        assert_eq!(names, COMMAND_ORDER.to_vec());
    }

    #[test]
    fn test_global_help_lists_45_names() {
        // globalHelpText lists 45 names (no plugin) while the
        // invalid-choice message lists all 46: keep verbatim.
        assert!(!GLOBAL_HELP_TEXT.contains("plugin"));
        assert!(GLOBAL_HELP_TEXT.contains("webui"));
        assert!(GLOBAL_HELP_TEXT.ends_with('\n'));
        assert!(!GLOBAL_HELP_TEXT.ends_with("\n\n"));
    }

    #[test]
    fn test_session_commands_share_one_help_text() {
        for name in [
            "session-rename",
            "session-pin",
            "session-unpin",
            "session-archive",
            "session-unarchive",
            "session-delete",
        ] {
            assert_eq!(
                command_spec(name).unwrap().help_text,
                SESSION_OP_HELP_TEXT,
                "{name}"
            );
        }
    }

    #[test]
    fn test_usage_lines_match_register_flags() {
        assert_eq!(
            command_spec("invite").unwrap().usage_line,
            "invite [--create] [--json] [--raw]"
        );
        // The invite HELP text lacks --raw (help.go); the usage
        // line has it. Do not "fix" either.
        assert!(!INVITE_HELP_TEXT.contains("--raw"));
        assert_eq!(
            command_spec("feed").unwrap().usage_line,
            "feed [--limit N] [--raw]"
        );
        assert_eq!(
            command_spec("plugin").unwrap().usage_line,
            "plugin check <path> [--tag TAG] [--type TYPE]"
        );
        assert_eq!(
            command_spec("plugin").unwrap().help_text,
            PLUGIN_CHECK_HELP_TEXT
        );
    }

    #[test]
    fn test_int_defaults_match_go() {
        let history = command_spec("history").unwrap();
        let limit = history.defs.iter().find(|d| d.name == "limit").unwrap();
        assert_eq!(limit.def_int, Some(10));
        let feed = command_spec("feed").unwrap();
        let limit = feed.defs.iter().find(|d| d.name == "limit").unwrap();
        assert_eq!(limit.def_int, None);
        let wait = command_spec("wait").unwrap();
        let after = wait.defs.iter().find(|d| d.name == "after-seq").unwrap();
        assert_eq!(after.def_int, None);
        let timeout = wait.defs.iter().find(|d| d.name == "timeout").unwrap();
        assert_eq!(timeout.def_int, Some(600));
    }
}
