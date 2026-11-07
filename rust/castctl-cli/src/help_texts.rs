// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

// Help and usage texts, extracted VERBATIM from the Go sources at
// the M2 base (dev-rust 85a8d5e) by /tmp/gen_help.py (mechanical
// extraction from backtick raw-string consts; nothing retyped).
// Do not edit by hand: re-run the generator after a Go-side change.
//
// Go source file:line citations are in the command table
// (commands.rs), which references these consts by name.

pub const GLOBAL_HELP_TEXT: &str = r#"usage: castctl [--profile NAME] [--config PATH] <command> [options]

Drive your Muse personal agent from the terminal (Go port of muse-cli 0.6.1).

Global options:
  --profile NAME   profile to use: --profile flag, then CASTCTL_PROFILE,
                   then the default_profile in the resolved config, then
                   "default".
  --config PATH    config file location. Precedence: --config PATH, then
                   CASTCTL_CONFIG, then the platform config directory
                   (XDG_CONFIG_HOME on Linux, ~/Library/Application
                   Support on macOS, %AppData% on Windows) under
                   "castctl". An explicit path names a config.json file;
                   a missing explicit file or a directory is an error,
                   except that "config migrate --write" may create it.
                   The directory of the resolved file is the config home
                   for the whole invocation (profiles, cookies, chat
                   state). A relative --config path is relative to the
                   current directory; no tilde expansion is performed.
  --log-level LEVEL
                   log level for this invocation: trace, debug, info,
                   warn, error, fatal, or panic ("warning" is accepted
                   as an alias for warn). Precedence: --log-level,
                   then the "log" block in config.json, then the
                   sing-box default (trace, stderr). An invalid level
                   exits 2. See
                   "Log" in docs/config.md.
  --version        print "castctl <version>" and exit.
  --help, -h       print this help and exit.

Commands (agent-facing CLI build; see rust/AGENT-CLI-SCOPE.md for
the surfaces this build does not ship):
  chat, status, usage, invite, redeem, threads, history, send, wait,
  approvals, approve, auto-approve, deny, files, download,
  watch, feed, feed-status, feed-react, feed-prompt, goals, goal,
  ideas, idea, idea-exec, unread, seen, session-start,
  session-rename, session-pin, session-unpin, session-archive,
  session-unarchive, session-delete, stop, wake, raw, fs, auth,
  profile, config, keeper, update

Run "castctl <command> --help" for per-command help.

Authentication: no new login flow is implemented in this port yet.
Login research is pending; "auth export" prints guidance only. The
fingerprint and tls_engine settings are recorded only: the runtime
stays on the uTLS chrome fingerprint (see "profile set-fingerprint
--help"). No browser is assumed: the screencast-login browser
dependency is optional and runtime-detected, and no-browser setups
fall back to auth import.
"#;

pub const CHAT_HELP_USAGE_TEXT: &str = r#"usage: castctl chat

Interactive chat (the default with no command). Type /help for
commands, /exit to quit.
"#;

pub const STATUS_HELP_TEXT: &str = r#"usage: castctl status

Show the VM id, session count, unread counts and identity as JSON.
No options.
"#;

pub const USAGE_HELP_TEXT: &str = r#"usage: castctl usage [--json] [--raw]

Show token usage for the active profile (subscription action).

options:
  --json    print the summary object as JSON instead of the text lines.
  --raw     print the raw subscription object as JSON.
"#;

pub const INVITE_HELP_TEXT: &str = r#"usage: castctl invite [--create] [--json]

Show the active profile's invite code, or create one.

options:
  --create  create a new invite code, then show it.
  --json    print the invite object as JSON instead of text.
"#;

pub const REDEEM_HELP_TEXT: &str = r#"usage: castctl redeem CODE [--json]

Redeem an invite code. The code is uppercased and validated
(6-16 uppercase letters/digits) before any request.

options:
  --json    print the result object as JSON instead of text.
"#;

pub const THREADS_HELP_TEXT: &str = r#"usage: castctl threads [--all]

List chats and side chats as JSON rows.

options:
  --all     include archived sessions.
"#;

pub const HISTORY_HELP_TEXT: &str = r#"usage: castctl history [--thread ID] [--limit N] [--raw] [--download DIR]

Read chat messages as JSON.

options:
  --thread ID    side chat session id (default: the main chat).
  --limit N      number of events (default 10).
  --raw          print the whole history object as JSON.
  --download DIR also save files (images/videos) from these messages
                 into DIR; with --raw the downloads are included in
                 the object, otherwise {"messages": [...],
                 "downloads": [...]} is printed.
"#;

pub const FILES_HELP_TEXT: &str = r#"usage: castctl files [--thread ID] [--limit N]

List files (images/videos) in recent messages as JSON rows.

options:
  --thread ID  side chat session id (default: the main chat).
  --limit N    number of events (default 20).
"#;

pub const DOWNLOAD_HELP_TEXT: &str = r#"usage: castctl download REF [-o DIR] [--thread ID] [--limit N] [-f]

Download a file the agent produced: a sandbox:// path, a media URL,
a message id, or a history seq. Prints the save rows as JSON. Any
row error exits 3; no file found exits 1.

options:
  -o, --output DIR  directory to save into (default .).
  --thread ID       side chat to search for a message id/seq.
  --limit N         messages to search for a message id/seq
                    (default 50).
  -f, --force       overwrite existing files.
"#;

pub const WATCH_HELP_TEXT: &str = r#"usage: castctl watch [--timeout SECONDS] [--n N] [--all] [--thread ID]

Tail live agent events: one JSON row per event as it arrives.

options:
  --timeout SECONDS  idle and overall timeout in seconds (default 60).
  --n N              maximum records (default 50).
  --all              include agent.status events (dropped by default).
  --thread ID        side chat session id (default: main chat).
"#;

pub const FEED_HELP_TEXT: &str = r#"usage: castctl feed [--limit N] [--raw]

List feed units as JSON rows.

options:
  --limit N  number of units (when set, also sent as the query limit).
  --raw      print the whole feed.list object as JSON.
"#;

pub const FEED_STATUS_HELP_TEXT: &str = r#"usage: castctl feed-status

Show feed refresh status as JSON. No options.
"#;

pub const FEED_REACT_HELP_TEXT: &str = r#"usage: castctl feed-react UNIT [REACTION]

React to a feed unit. REACTION defaults to "love".
"#;

pub const FEED_PROMPT_HELP_TEXT: &str = r#"usage: castctl feed-prompt

Show the feed prompt as JSON. No options.
"#;

pub const GOALS_HELP_TEXT: &str = r#"usage: castctl goals

List goals as JSON rows. No options.
"#;

pub const GOAL_HELP_TEXT: &str = r#"usage: castctl goal ID

Show one goal as JSON.
"#;

pub const IDEAS_HELP_TEXT: &str = r#"usage: castctl ideas

List idea cards as JSON rows. No options.
"#;

pub const IDEA_HELP_TEXT: &str = r#"usage: castctl idea ID

Show one idea card as JSON.
"#;

pub const IDEA_EXEC_HELP_TEXT: &str = r#"usage: castctl idea-exec ID [--thread ID]

Execute an idea (the agent acts on it, full mode).

options:
  --thread ID  side chat session id to run it in.
"#;

pub const UNREAD_HELP_TEXT: &str = r#"usage: castctl unread

Show unread counts as JSON. No options.
"#;

pub const SEEN_HELP_TEXT: &str = r#"usage: castctl seen THREAD

Mark a thread seen. Prints the result as JSON.
"#;

pub const SESSION_START_HELP_TEXT: &str = r#"usage: castctl session-start [--title TITLE]

Start a new side chat. Prints the session object as JSON.

options:
  --title TITLE  title for the new session.
"#;

pub const SESSION_OP_HELP_TEXT: &str = r#"usage: castctl session-rename ID TITLE
       castctl session-pin ID
       castctl session-unpin ID
       castctl session-archive ID
       castctl session-unarchive ID
       castctl session-delete ID

Rename, pin, unpin, archive, unarchive or delete a session. Prints
the result as JSON. No options.
"#;

pub const STOP_HELP_TEXT: &str = r#"usage: castctl stop [--thread ID]

Stop Muse's current turn (like the app's Stop button).

options:
  --thread ID  side chat session id (default: main chat).
"#;

pub const WAKE_HELP_TEXT: &str = r#"usage: castctl wake

Request a VM wake over plain HTTPS (no gateway connection). Prints
{"status": N, "body": ...} as JSON. No options.
"#;

pub const RAW_HELP_TEXT: &str = r#"usage: castctl raw METHOD [--body JSON] [--param KEY=VALUE]... [--timeout SECONDS]

Call any gateway method (escape hatch). Unknown methods exit 2. A
bad --body or --param exits 2. A non-JSON reply is printed as text,
otherwise the reply prints as JSON.

options:
  --body JSON         JSON request body (absent means no body).
  --param KEY=VALUE   path parameter, repeatable.
  --timeout SECONDS   request timeout in seconds (default 30).
"#;

pub const WAIT_HELP_TEXT: &str = r#"usage: castctl wait [--thread ID] [--after-seq N] [--timeout SECONDS] [--json] [--require-running] [--auto-approve|--no-auto-approve] [--auto-allow-once|--no-auto-allow-once]

Block until the agent's turn ends. Exit 0 turn done, 2 failed,
4 needs a human (a question or a pending approval), 124 timeout.

options:
  --thread ID    side chat session id (default: the main chat).
  --after-seq N  only replies after this seq (default: read the
                 boundary from history).
  --timeout SECONDS
                 give up after this long (default 600).
  --json         print the result as JSON.
  --require-running
                 ignore an already-finished status until a new run
                 starts (accepted; no live effect in this port).
  --auto-approve approve pending approvals with allow_always and
                 keep waiting (per-call override of the profile
                 setting and MUSE_AUTO_APPROVE).
  --no-auto-approve
                 stop with exit 4 on approvals even if auto-approve
                 is on.
  --auto-allow-once
                 when auto-approve is on, approve approvals with no
                 forever option with allow_once and keep waiting.
  --no-auto-allow-once
                 leave approvals with no forever option for a human.
"#;

pub const SEND_HELP_TEXT: &str = r#"usage: castctl send TEXT [--thread ID] [--wait SECONDS] [--until-done] [--text] [--ack-timeout SECONDS] [--download DIR] [--auto-approve|--no-auto-approve] [--auto-allow-once|--no-auto-allow-once]

Send the agent a message and wait for the turn. Exits 5 when no
delivery ack arrives within --ack-timeout; otherwise the wait
exit codes apply (0 done, 2 failed, 4 needs a human, 124 timeout).

options:
  --thread ID    side chat session id (default: the main chat).
  --wait SECONDS wait this long for the turn (default 90; 0 means
                 return once delivered).
  --until-done   wait up to 24h instead of --wait.
  --text         print the reply as plain text instead of JSON.
  --ack-timeout SECONDS
                 give up waiting for the delivery ack after this
                 long (default 30).
  --download DIR also save files (images/videos) from the turn's
                 replies into DIR.
  --auto-approve, --no-auto-approve, --auto-allow-once,
  --no-auto-allow-once
                 as in castctl wait.
"#;

pub const APPROVALS_HELP_TEXT: &str = r#"usage: castctl approvals [--recent] [--raw] [--approve-all]

List pending approvals (network access etc.) as JSON.

options:
  --recent       also list recent decisions.
  --raw          print the whole egress.approvals result as JSON.
  --approve-all  approve every pending approval with allow_always
                 (skips approvals with no forever option).
"#;

pub const APPROVE_HELP_TEXT: &str = r#"usage: castctl approve [ID] [--all] [--once|--session|--today|--always]

Approve a pending request, or every pending approval with --all.
The decision defaults to allow_once.

options:
  --all          approve every pending approval.
  --once         allow_once (default).
  --session      allow_session.
  --today        allow_today.
  --always       allow_always.
"#;

pub const AUTO_APPROVE_HELP_TEXT: &str = r#"usage: castctl auto-approve [on|always|off|status] [once on|off|status]

Let wait/send approve every approval with allow_always (on|off|
status); once on|off controls the allow_once fallback. With no
arguments, or status, prints the resolved settings as JSON.
Settings persist in the active profile's single config file.

Precedence per toggle: per-call flag, MUSE_AUTO_APPROVE /
MUSE_AUTO_ALLOW_ONCE, config. Defaults off.
"#;

pub const DENY_HELP_TEXT: &str = r#"usage: castctl deny ID [--always]

Deny a pending request.

options:
  --always       deny_always instead of deny.
"#;

pub const FS_HELP_TEXT: &str = r#"usage: castctl fs <subcommand> [options]

Operate on the Muse sandbox filesystem over the gateway.

Subcommands: ls, tree, stat, cat, get, find, put, write, edit, mkdir,
mv, rm. Run "castctl fs <subcommand> --help" for per-subcommand help.
"#;

pub const AUTH_HELP_TEXT: &str = r#"usage: castctl auth <subcommand> [options]

Authentication helpers. "auth export" prints guidance only (exit 1,
no writes). "auth import" reads cookies from stdin and writes the
active profile's cookies.txt (see "castctl auth import --help").
"auth login" is the experimental screencast login (see "castctl
auth login --help"; off by default). "auth status" reports the
session state from files only, no network (see "castctl auth
status --help"). "auth observe-login" prints the read-only,
redacted login-page inventory for the contract fixture (see
"castctl auth observe-login --help").

Subcommands: list, export, import, login, status, observe-login. Run "castctl auth <subcommand> --help"
for per-subcommand help.
"#;

pub const PROFILE_HELP_TEXT: &str = r#"usage: castctl profile <subcommand> [options]

Manage profiles. All writes go through the profile library's
atomic/flock/sha256 path; this command never writes config files
directly.

Subcommands: list, show, add, rm, set-outbound, set-fingerprint,
set-tls-engine, test. Run "castctl profile <subcommand> --help"
for per-subcommand help.

The fingerprint and tls_engine settings are recorded only: the
runtime stays on the uTLS chrome fingerprint regardless of what is
stored (see "profile set-fingerprint --help" and
"profile set-tls-engine --help").
"#;

pub const CONFIG_HELP_TEXT: &str = r#"usage: castctl config <subcommand> [options]

Config maintenance. Subcommands: migrate. Run
"castctl config <subcommand> --help" for per-subcommand help.
"#;

pub const KEEPER_HELP_TEXT: &str = r#"usage: castctl keeper <subcommand> [options]

Session keeper: watch profile cookies for expiry (cheap chain
only: GET /api/session -> POST /api/auth/check), re-export them
from the attached browser when they die, and report. Requires a
"keeper" block in config.json (see docs/config.md).

subcommands:
  run       tick every entry in the foreground until interrupted
  check     run one tick now (exit 0/2/3/4, see below)
  status    show per-entry state from state files only (no network)

selection (run/check/status):
  --tag TAG          only the entry with this tag
  --profile NAME     only the entry for this profile

Default cadence is 24h per entry (the "interval" key; the
adaptive rule shortens it once a cookie expiry is observed).

check exit codes:
  0  healthy (or skipped: login in progress / lock held)
  1  hard failure: lock (other than held), state-directory, or state-save failure (outcome "error", never skipped)
  2  config error (no keeper block, dangling refs, bad selection)
  3  entry stopped (auth expired) or export failed
  4  tick timeout

run prints one summary line per tick to stdout. check prints
one JSON object per entry. status prints a JSON array.
"#;

pub const CONFIG_MIGRATE_HELP_TEXT: &str = r#"usage: castctl config migrate [--write] [--from <dir>]

Migrate legacy per-profile config files into the single
config.json. Dry-run by default: prints the JSON plan and writes
nothing. --write performs the migration atomically (mode 0600,
never deletes or edits the old files). An already-migrated config
exits 0; a differing single config refuses with exit 2. Only
"config migrate --write" may create a missing explicit --config
file.

--from <dir> reads legacy profiles ONLY from <dir> and writes
the single config ONLY to the --config file's directory (or the
default config directory when no --config is given); the source
directory is never written. Without --from, source and
destination are the --config file's directory. A missing source
directory exits 2. When --from names the destination directory
itself, including through a symlink, behaviour is exactly as
without --from.

When the existing single config has no "dns" section and every
profile shares one outbound tag, --write also authors the interim
global "dns" section (DoH to 1.1.1.1 through that tag; see
docs/config.md). Otherwise no "dns" section is written and the
result reports why in "dns_refusal".

When the existing single config HAS a top-level "dns" section,
--write distributes it into every profile's own "dns" block
(verbatim copy; empty detours filled with the profile's own
detour tag, own/reachable detours kept, unreachable detours
refuse with exit 2) and removes the top-level section in the
same atomic write; dry-run reports "dns_distributed" and
writes nothing. See docs/config.md.
"#;

pub const AUTH_LIST_HELP_TEXT: &str = r#"usage: castctl auth list [--json]

List profiles with their cookie presence and auto-approve setting.
The active profile is marked.

options:
  --json    print {"active": ..., "profiles": [...]} as JSON instead
            of the padded text table.
"#;

pub const AUTH_EXPORT_HELP_TEXT: &str = r#"usage: castctl auth export

Print guidance for exporting cookies from a signed-in browser.
Guidance only: exit 1, writes nothing, opens no browser.
"#;

pub const AUTH_IMPORT_HELP_TEXT: &str = r#"usage: castctl auth import

Read cookies from stdin and write them to the active profile's
cookies.txt file, replacing its previous contents (kept as
cookies.txt.bak). Stdin only: cookies are never taken from argv.
No network request is made; run "castctl status" afterwards to
check the login.

Accepted input forms (hatch_sess is required, with a non-empty value):

  one-line:  hatch_sess=VALUE; other_name=other_value
             (pairs separated by "; ")
  Netscape:  a tab-separated cookie jar, one cookie per line
             (domain, flag, path, secure, expires, name, value)
  JSON:      {"cookies": {"hatch_sess": "VALUE", ...}} or a flat
             {"hatch_sess": "VALUE", ...} object

The input is stored verbatim (after line-ending normalisation),
with a single trailing newline. The file mode is 600.
"#;

pub const PROFILE_LIST_HELP_TEXT: &str = r#"usage: castctl profile list

List profiles as JSON: {"active", "default_profile", "source",
"profiles": [...]}. "source" is single or none.
"#;

pub const PROFILE_SHOW_HELP_TEXT: &str = r#"usage: castctl profile show [NAME]

Show one profile (default: the active profile): the redacted
profile object, its paths, and warnings. No --raw: secrets inside
outbound objects (header values such as Authorization) are always
redacted in the display layer.
"#;

pub const PROFILE_ADD_HELP_TEXT: &str = r#"usage: castctl profile add NAME [--cookies-file PATH] [--outbound TAG|FILE] [--set-default] [--outbound-from-env] [--fingerprint VALUE] [--tls-engine VALUE]

Create a profile. Refuses when the old single-file layout has not
been migrated. Creates no cookies file and no profile directory
until a later write needs one.

options:
  --cookies-file PATH   cookies file for the profile (relative paths
                        resolve under the resolved config directory;
                        a named profile's path inside that directory
                        must be its own cookies file, anything else
                        there is a config error).
  --outbound TAG|FILE   outbound tag from the config, or a file holding
                        one outbound/endpoint object (use - for stdin).
  --set-default         make the new profile the default.
  --outbound-from-env   build the outbound from the proxy environment
                        variables instead of --outbound (mutually
                        exclusive with --outbound).
  --fingerprint VALUE   recorded fingerprint preset: chrome, firefox,
                        ios or safari (default chrome). Recorded only;
                        the runtime is unchanged (uTLS chrome).
  --tls-engine VALUE    recorded TLS engine: cronet, stdlib or utls
                        (default utls). Recorded only; the runtime is
                        unchanged (uTLS chrome). The TLS-engine
                        decision: default utls on every platform;
                        cronet is an opt-in future build flavour only.
"#;

pub const PROFILE_RM_HELP_TEXT: &str = r#"usage: castctl profile rm NAME --yes

Remove a profile's single-file entry. Refuses without --yes.

options:
  --yes     confirm the removal.
"#;

pub const PROFILE_SET_OUTBOUND_HELP_TEXT: &str = r#"usage: castctl profile set-outbound NAME FILE|-

Replace a profile's outbound with one option.Outbound/option.Endpoint
object read from FILE (or stdin with -). No {"outbound": {...}}
wrapper is accepted. A wireguard object becomes an endpoint; a
tagged object becomes a list entry referenced by tag; an untagged
object is inlined under the auto tag "profile:<name>".
"#;

pub const PROFILE_SET_FINGERPRINT_HELP_TEXT: &str = r#"usage: castctl profile set-fingerprint NAME VALUE

Record a fingerprint preset for a profile: chrome, firefox, ios or
safari. An empty VALUE resets to the default (chrome) and removes
the key. STORAGE ONLY: the value is validated and displayed, the
runtime stays on the uTLS chrome fingerprint. Do not rely on the
stored value changing TLS behaviour.
"#;

pub const PROFILE_SET_TLS_ENGINE_HELP_TEXT: &str = r#"usage: castctl profile set-tls-engine NAME VALUE

Record a TLS engine for a profile: cronet, stdlib or utls. An empty
VALUE resets to the default (utls) and removes the key. STORAGE
ONLY: the value is validated and displayed, the runtime stays on
uTLS chrome. The TLS-engine decision: default utls on every
platform; cronet is an opt-in future build flavour (a sidecar,
hash-verified, linux-glibc + Windows) only after a probe matches
real Chrome of the same version; it is not wired in this port.
"#;

pub const PROFILE_TEST_HELP_TEXT: &str = r#"usage: castctl profile test [NAME]

Test a profile end to end, one phase at a time: config load, DNS
resolution via the outbound, TLS + GET https://muse.ai/api/session,
egress IP through the same outbound, then a Noise handshake that is
closed immediately (no chat send, no session creation, no file
writes). Timings are measured externally. Exit 4 on timeout, 2 on
config failure, 3 on gateway failure. An egress-IP failure reports
a null egress_ip plus a warning and is not fatal.
"#;

pub const KEEPER_RUN_HELP_TEXT: &str = r#"usage: castctl keeper run [--tag TAG | --profile NAME]

Tick every selected keeper entry in the foreground until
interrupted (Ctrl-C, exit 130) or every entry stops. A second
"keeper run" for the same entry refuses while the first is
alive (single-flight owner file).
"#;

pub const KEEPER_CHECK_HELP_TEXT: &str = r#"usage: castctl keeper check [--tag TAG | --profile NAME]

Run one tick now for each selected entry and print one JSON
object per entry: tag, profile, outcome, stopped, cookies
seen, whether the cookies file was written, and the next
check time. Exit codes: 0 healthy, 1 hard failure
(lock other than held, state-directory, or state-save
failure; outcome "error", never "skipped"), 2 config, 3 entry
stopped (auth expired) or export failed, 4 timeout (90s per
entry).
A transient error surfaces through the normal error
contract instead (GatewayError 3, timeout 4, other 1).
"#;

pub const KEEPER_STATUS_HELP_TEXT: &str = r#"usage: castctl keeper status [--tag TAG | --profile NAME]

Show per-entry state from the state files only: no network, no
browser contact. Exit 0 even when an entry is logged out or
stopped. Prints a JSON array.
"#;

pub const FS_LS_HELP_TEXT: &str = r#"usage: castctl fs ls [PATH] [-l] [-a] [--json]

List a folder (default: System Files root).

options:
  -l, --long   long listing: type, size, modification time, name.
  -a, --all    include dotfiles.
  --json       print the entries as JSON instead of names.
"#;

pub const FS_TREE_HELP_TEXT: &str = r#"usage: castctl fs tree [PATH] [--depth N] [-a] [--json]

Recursive listing.

options:
  --depth N    recursion depth (default 2; a negative depth behaves like 0: one level).
  -a, --all    include dotfiles (any path component starting with ".").
  --json       print [{"path": ..., **entry}] as JSON instead of text.
"#;

pub const FS_STAT_HELP_TEXT: &str = r#"usage: castctl fs stat PATH

Print file/folder metadata as JSON.
"#;

pub const FS_CAT_HELP_TEXT: &str = r#"usage: castctl fs cat PATH [--max-bytes N] [--binary]

Print a file to stdout. A NUL byte in the first 8192 bytes without
--binary refuses with exit 1.

options:
  --max-bytes N  read at most N bytes.
  --binary       allow binary output.
"#;

pub const FS_GET_HELP_TEXT: &str = r#"usage: castctl fs get PATH [-o DIR] [-r]

Download a file (or a folder with -r) into DIR.

options:
  -o, --output DIR   directory to save into (default .).
  -r, --recursive    download folders recursively.
"#;

pub const FS_FIND_HELP_TEXT: &str = r#"usage: castctl fs find NAME [--limit N]

Search by name substring. Prints the matching entries as JSON.

options:
  --limit N    maximum results.
"#;

pub const FS_PUT_HELP_TEXT: &str = r#"usage: castctl fs put LOCAL REMOTE [-r] [-n]

Upload a local file (or folder with -r) to a remote path.

options:
  -r, --recursive    upload folders recursively.
  -n, --no-clobber   refuse to overwrite an existing remote file.
"#;

pub const FS_WRITE_HELP_TEXT: &str = r#"usage: castctl fs write REMOTE [--append] [-n]

Write stdin to a remote file. --append reads the old content first
and overwrites with old+new (one full write; chunking is owned by
the fs client).

options:
  --append         append to the existing content.
  -n, --no-clobber  refuse to overwrite an existing remote file.
"#;

pub const FS_EDIT_HELP_TEXT: &str = r#"usage: castctl fs edit REMOTE [--replace OLD NEW]...

Edit a remote file: apply --replace pairs in order (repeatable), or
open $VISUAL/$EDITOR (default vi) when no --replace is given. An
unchanged file prints {"path": ..., "changed": false} and writes
nothing.

options:
  --replace OLD NEW  replace every occurrence of OLD with NEW.
"#;

pub const FS_MKDIR_HELP_TEXT: &str = r#"usage: castctl fs mkdir PATH

Create a folder, with parents. Prints the result as JSON.
"#;

pub const FS_MV_HELP_TEXT: &str = r#"usage: castctl fs mv SRC DST [-f]

Move/rename a remote path.

options:
  -f, --force    overwrite the destination.
"#;

pub const FS_RM_HELP_TEXT: &str = r#"usage: castctl fs rm PATH [-r] [--yes]

Delete a remote path. Refuses without --yes, before connecting.

options:
  -r, --recursive  delete folders recursively.
  --yes            confirm the deletion.
"#;

pub const AUTH_LOGIN_HELP_TEXT: &str = r#"usage: castctl auth login [--profile NAME] [--timeout 15m] [--browser-path PATH] [--experimental-login]

Log in to Muse through a screencast session (EXPERIMENTAL).

The human completes the login in a Chrome window. Type "done"
on stdin when logged in, or "cancel" to abandon. Cookies are
exported from the browser and saved only on "done", after the
session is validated against the cheap chain.

  --profile NAME        profile to log in (default: active profile)
  --timeout DURATION    session timeout, 60s-60min (default 15m)
  --browser-path PATH   Chrome/Chromium binary for the launch fallback
  --experimental-login  enable this experimental command

Also enabled by CASTCTL_EXPERIMENTAL_LOGIN=1. Without it, use
"castctl auth import" instead (paste a cookies.txt export).
"#;

pub const AUTH_STATUS_HELP_TEXT: &str = r#"usage: castctl auth status [--profile NAME | --all]

Show the session status for a profile from state files only:
no network, no browser contact. The status is ok, expiring
(the driving cookie expires within the keeper entry's
expiring_within window, default 72h), or expired (the
driving expiry is past, or the keeper stopped the entry for
a dead session).

Prints one JSON object (or a JSON array with --all) with:
profile, status, liveness_checked, driving_cookie (name only),
driving_expiry, last_checked_at, keeper_stopped,
keeper_stopped_reason, headless_available, headless_reason,
needs_action.

The report never verifies the session is alive: a revoked
cookie still reports expiring until its expiry passes or the
keeper stops the entry, so liveness_checked is always false.
Use "keeper check" for a live verdict.

headless_reason is "" when headless re-login is available,
or one of: no_keeper_entry, no_chromedp, no_credentials,
no_contract (the login-form contract is not yet established).

Exit codes: 0 ok, 1 expiring, 2 config error, 3 expired.
"#;

pub const AUTH_OBSERVE_LOGIN_HELP_TEXT: &str = r#"usage: castctl auth observe-login [--profile NAME] [--login-url URL]

Observe the provider login page read-only (headless) and print
its redacted form-control inventory as JSON: element tag, type,
name, id, classes, and aria-label presence only. No values, no
page text, no links, no screenshots. Nothing is entered or
submitted; nothing is written to the profile.

  --profile NAME    profile whose outbound routes the page load
                    (default: active profile)
  --login-url URL   page to observe (default: https://muse.ai/;
                    must be an https URL with a host and no userinfo)

The observation always launches a headless browser; it never
attaches to a running browser. The printed "url" is the final
URL with query, fragment, and userinfo stripped; the printed
"login_url" is the supplied URL stripped the same way.
"#;

// updateHelpText (internal/commands/update.go) — appended mechanically;
// the M2 generator pass missed this file. Verbatim extraction, not retyped.
pub const UPDATE_HELP_TEXT: &str = r#"usage: castctl update [--dry-run] [--version TAG] [--allow-downgrade] [--allow-prerelease]

Self-update castctl from the latest stable GitHub release.

The release asset matching this platform and build flavour is
downloaded, its sha256 is verified against the release
checksums.txt BEFORE any replace, the extracted binary is
validated (ELF/arch sanity and an unsandboxed --version run of
the checksummed candidate), and only then the running binary
is replaced atomically (same-directory rename, the resolved
target's Perm() (0777 rwx) bits preserved, setuid/setgid/sticky
bits dropped, fsync of file and directory). The resolved target
is followed through symlinks, including out of the directory.
Every failure before the rename leaves the old binary intact
and partial downloads are deleted; a directory-sync failure
after a successful rename returns an error with the new binary
in place (durability unproven). There is no signature
verification: GitHub releases carry no signatures, so the
checksums prove only that the bytes match what the release
published, over HTTPS.

The running build must be stamped (release -X flags): unstamped
dev builds refuse with "cannot determine running version" in
every mode. The build flavour (glibc vs no-plugin) is read from
the build info CGO_ENABLED setting; an unknown flavour refuses.
Linux only: no release assets exist for other platforms.

  --dry-run          Report what would be downloaded, verified
                     and replaced, without writing anything.
                     Dry-run takes no lock and skips the exec
                     check, the chmod, and the re-hash.
  --version TAG      Update to a specific release tag (with or
                     without a leading v). Must name a stable
                     release unless --allow-prerelease is given.
  --allow-downgrade  Allow installing an older version than the
                     running one. Refused by default.
  --allow-prerelease
                     Allow a pre-release target. Refused by
                     default.

Exit codes: 0 success, already-latest no-op, or dry-run report;
2 = usage and policy refusals (no download, no replace; release
metadata may have been fetched first);
1 operational failures (network, checksums, validation, replace).
"#;
