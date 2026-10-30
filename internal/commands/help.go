// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package commands

import "fmt"

const globalHelpText = `usage: muse-cli [--profile NAME] [--config PATH] <command> [options]

Drive your Muse personal agent from the terminal (Go port of muse-cli 0.6.1).

Global options:
  --profile NAME   profile to use: --profile flag, then MUSE_CLI_PROFILE,
                   then the default_profile in the resolved config, then
                   "default".
  --config PATH    config file location. Precedence: --config PATH, then
                   MUSE_CLI_CONFIG, then the platform config directory
                   (XDG_CONFIG_HOME on Linux, ~/Library/Application
                   Support on macOS, %AppData% on Windows) under
                   "muse-cli". An explicit path names a config.json file;
                   a missing explicit file or a directory is an error,
                   except that "config migrate --write" may create it.
                   The directory of the resolved file is the config home
                   for the whole invocation (profiles, cookies, chat
                   state). A relative --config path is relative to the
                   current directory; no tilde expansion is performed.
  --version        print "muse-cli <version>" and exit.
  --help, -h       print this help and exit.

Commands (PR4 wired send, wait, approvals and the chat REPL;
telegram and update are carried to PR5):
  chat, status, usage, invite, redeem, threads, history, send, wait,
  approvals, approve, auto-approve, deny, files, download,
  watch, feed, feed-status, feed-react, feed-prompt, goals, goal,
  ideas, idea, idea-exec, unread, seen, session-start,
  session-rename, session-pin, session-unpin, session-archive,
  session-unarchive, session-delete, stop, wake, raw, fs, auth,
  profile, config

Run "muse-cli <command> --help" for per-command help.

Authentication: no new login flow is implemented in this port yet.
Login research is pending; "auth export" prints guidance only. The
fingerprint and tls_engine settings are recorded only: the runtime
stays on the uTLS chrome fingerprint (see "profile set-fingerprint
--help"). No browser is assumed: the screencast-login browser
dependency is optional and runtime-detected, and no-browser setups
fall back to auth import.
`

// deferredHelpText prints a short help stub for a deferred command:
// the Python description plus the explicit not-implemented note, so
// --help still exits 0 for deferred commands.
func deferredHelpText(cmd, pr string) string {
	descs := map[string]string{
		"send":         "send a message to Muse and optionally wait for the turn to end",
		"wait":         "wait for Muse's current turn to end and print the final replies",
		"approvals":    "list pending approval prompts",
		"approve":      "decide a pending approval (allow once / always / deny)",
		"deny":         "deny a pending approval",
		"auto-approve": "manage the auto-approve toggle (status/on/off/once)",
		"telegram":     "Telegram bot that operates your Muse (setup, run, install-service, status)",
		"update":       "check for and install updates from the fork's main branch",
		"chat":         "interactive chat REPL (bare invocation with no command)",
	}
	desc, ok := descs[cmd]
	if !ok {
		desc = ""
	}
	return fmt.Sprintf("usage: muse-cli %s [options]\n\n%s\n\n%s is not implemented in the Go port yet (%s).\n", cmd, desc, cmd, pr)
}

const statusHelpText = `usage: muse-cli status

Show the VM id, session count, unread counts and identity as JSON.
No options.
`

const usageHelpText = `usage: muse-cli usage [--json] [--raw]

Show token usage for the active profile (subscription action).

options:
  --json    print the summary object as JSON instead of the text lines.
  --raw     print the raw subscription object as JSON.
`

const inviteHelpText = `usage: muse-cli invite [--create] [--json]

Show the active profile's invite code, or create one.

options:
  --create  create a new invite code, then show it.
  --json    print the invite object as JSON instead of text.
`

const redeemHelpText = `usage: muse-cli redeem CODE [--json]

Redeem an invite code. The code is uppercased and validated
(6-16 uppercase letters/digits) before any request.

options:
  --json    print the result object as JSON instead of text.
`

const threadsHelpText = `usage: muse-cli threads [--all]

List chats and side chats as JSON rows.

options:
  --all     include archived sessions.
`

const historyHelpText = `usage: muse-cli history [--thread ID] [--limit N] [--raw] [--download DIR]

Read chat messages as JSON.

options:
  --thread ID    side chat session id (default: the main chat).
  --limit N      number of events (default 10).
  --raw          print the whole history object as JSON.
  --download DIR also save files (images/videos) from these messages
                 into DIR; with --raw the downloads are included in
                 the object, otherwise {"messages": [...],
                 "downloads": [...]} is printed.
`

const filesHelpText = `usage: muse-cli files [--thread ID] [--limit N]

List files (images/videos) in recent messages as JSON rows.

options:
  --thread ID  side chat session id (default: the main chat).
  --limit N    number of events (default 20).
`

const downloadHelpText = `usage: muse-cli download REF [-o DIR] [--thread ID] [--limit N] [-f]

Download a file the agent produced: a sandbox:// path, a media URL,
a message id, or a history seq. Prints the save rows as JSON. Any
row error exits 3; no file found exits 1.

options:
  -o, --output DIR  directory to save into (default .).
  --thread ID       side chat to search for a message id/seq.
  --limit N         messages to search for a message id/seq
                    (default 50).
  -f, --force       overwrite existing files.
`

const watchHelpText = `usage: muse-cli watch [--timeout SECONDS] [--n N] [--all] [--thread ID]

Tail live agent events: one JSON row per event as it arrives.

options:
  --timeout SECONDS  idle and overall timeout in seconds (default 60).
  --n N              maximum records (default 50).
  --all              include agent.status events (dropped by default).
  --thread ID        side chat session id (default: main chat).
`

const feedHelpText = `usage: muse-cli feed [--limit N] [--raw]

List feed units as JSON rows.

options:
  --limit N  number of units (when set, also sent as the query limit).
  --raw      print the whole feed.list object as JSON.
`

const feedStatusHelpText = `usage: muse-cli feed-status

Show feed refresh status as JSON. No options.
`

const feedReactHelpText = `usage: muse-cli feed-react UNIT [REACTION]

React to a feed unit. REACTION defaults to "love".
`

const feedPromptHelpText = `usage: muse-cli feed-prompt

Show the feed prompt as JSON. No options.
`

const goalsHelpText = `usage: muse-cli goals

List goals as JSON rows. No options.
`

const goalHelpText = `usage: muse-cli goal ID

Show one goal as JSON.
`

const ideasHelpText = `usage: muse-cli ideas

List idea cards as JSON rows. No options.
`

const ideaHelpText = `usage: muse-cli idea ID

Show one idea card as JSON.
`

const ideaExecHelpText = `usage: muse-cli idea-exec ID [--thread ID]

Execute an idea (the agent acts on it, full mode).

options:
  --thread ID  side chat session id to run it in.
`

const unreadHelpText = `usage: muse-cli unread

Show unread counts as JSON. No options.
`

const seenHelpText = `usage: muse-cli seen THREAD

Mark a thread seen. Prints the result as JSON.
`

const sessionStartHelpText = `usage: muse-cli session-start [--title TITLE]

Start a new side chat. Prints the session object as JSON.

options:
  --title TITLE  title for the new session.
`

const sessionOpHelpText = `usage: muse-cli session-rename ID TITLE
       muse-cli session-pin ID
       muse-cli session-unpin ID
       muse-cli session-archive ID
       muse-cli session-unarchive ID
       muse-cli session-delete ID

Rename, pin, unpin, archive, unarchive or delete a session. Prints
the result as JSON. No options.
`

const stopHelpText = `usage: muse-cli stop [--thread ID]

Stop Muse's current turn (like the app's Stop button).

options:
  --thread ID  side chat session id (default: main chat).
`

const wakeHelpText = `usage: muse-cli wake

Request a VM wake over plain HTTPS (no gateway connection). Prints
{"status": N, "body": ...} as JSON. No options.
`

const rawHelpText = `usage: muse-cli raw METHOD [--body JSON] [--param KEY=VALUE]... [--timeout SECONDS]

Call any gateway method (escape hatch). Unknown methods exit 2. A
bad --body or --param exits 2. A non-JSON reply is printed as text,
otherwise the reply prints as JSON.

options:
  --body JSON         JSON request body (absent means no body).
  --param KEY=VALUE   path parameter, repeatable.
  --timeout SECONDS   request timeout in seconds (default 30).
`

const fsHelpText = `usage: muse-cli fs <subcommand> [options]

Operate on the Muse sandbox filesystem over the gateway.

Subcommands: ls, tree, stat, cat, get, find, put, write, edit, mkdir,
mv, rm. Run "muse-cli fs <subcommand> --help" for per-subcommand help.
`

const authHelpText = `usage: muse-cli auth <subcommand> [options]

Authentication helpers. "auth export" prints guidance only (exit 1,
no writes). "auth import" reads cookies from stdin and writes the
active profile's cookies.txt (see "muse-cli auth import --help").

Subcommands: list, export, import. Run "muse-cli auth <subcommand> --help"
for per-subcommand help.
`

const authListHelpText = `usage: muse-cli auth list [--json]

List profiles with their cookie presence and auto-approve setting.
The active profile is marked.

options:
  --json    print {"active": ..., "profiles": [...]} as JSON instead
            of the padded text table.
`

const authExportHelpText = `usage: muse-cli auth export

Print guidance for exporting cookies from a signed-in browser.
Guidance only: exit 1, writes nothing, opens no browser.
`

const authImportHelpText = `usage: muse-cli auth import

Read cookies from stdin and write them to the active profile's
cookies.txt file, replacing its previous contents (kept as
cookies.txt.bak). Stdin only: cookies are never taken from argv.
No network request is made; run "muse-cli status" afterwards to
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
`

const profileHelpText = `usage: muse-cli profile <subcommand> [options]

Manage profiles. All writes go through the profile library's
atomic/flock/sha256 path; this command never writes config files
directly.

Subcommands: list, show, add, rm, set-outbound, set-fingerprint,
set-tls-engine, test. Run "muse-cli profile <subcommand> --help"
for per-subcommand help.

The fingerprint and tls_engine settings are recorded only: the
runtime stays on the uTLS chrome fingerprint regardless of what is
stored (see "profile set-fingerprint --help" and
"profile set-tls-engine --help").
`

const profileListHelpText = `usage: muse-cli profile list

List profiles as JSON: {"active", "default_profile", "source",
"profiles": [...]}. "source" is single, legacy, mixed or none.
`

const profileShowHelpText = `usage: muse-cli profile show [NAME]

Show one profile (default: the active profile): the redacted
profile object, its paths, and warnings. No --raw: secrets inside
outbound objects (header values such as Authorization) are always
redacted in the display layer.
`

const profileAddHelpText = `usage: muse-cli profile add NAME [--cookies-file PATH] [--outbound TAG|FILE] [--set-default] [--outbound-from-env] [--fingerprint VALUE] [--tls-engine VALUE]

Create a profile. Refuses when the old single-file layout has not
been migrated. Creates no cookies file and no profile directory
until a later write needs one.

options:
  --cookies-file PATH   cookies file for the profile (relative paths
                        resolve under the resolved config directory).
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
`

const profileRmHelpText = `usage: muse-cli profile rm NAME --yes

Remove a profile's single-file entry. Refuses without --yes.

options:
  --yes     confirm the removal.
`

const profileSetOutboundHelpText = `usage: muse-cli profile set-outbound NAME FILE|-

Replace a profile's outbound with one option.Outbound/option.Endpoint
object read from FILE (or stdin with -). No {"outbound": {...}}
wrapper is accepted. A wireguard object becomes an endpoint; a
tagged object becomes a list entry referenced by tag; an untagged
object is inlined under the auto tag "profile:<name>".
`

const profileSetFingerprintHelpText = `usage: muse-cli profile set-fingerprint NAME VALUE

Record a fingerprint preset for a profile: chrome, firefox, ios or
safari. An empty VALUE resets to the default (chrome) and removes
the key. STORAGE ONLY: the value is validated and displayed, the
runtime stays on the uTLS chrome fingerprint. Do not rely on the
stored value changing TLS behaviour.
`

const profileSetTLSEngineHelpText = `usage: muse-cli profile set-tls-engine NAME VALUE

Record a TLS engine for a profile: cronet, stdlib or utls. An empty
VALUE resets to the default (utls) and removes the key. STORAGE
ONLY: the value is validated and displayed, the runtime stays on
uTLS chrome. The TLS-engine decision: default utls on every
platform; cronet is an opt-in future build flavour (a sidecar,
hash-verified, linux-glibc + Windows) only after a probe matches
real Chrome of the same version; it is not wired in this port.
`

const profileTestHelpText = `usage: muse-cli profile test [NAME]

Test a profile end to end, one phase at a time: config load, DNS
resolution via the outbound, TLS + GET https://muse.ai/api/session,
egress IP through the same outbound, then a Noise handshake that is
closed immediately (no chat send, no session creation, no file
writes). Timings are measured externally. Exit 4 on timeout, 2 on
config failure, 3 on gateway failure. An egress-IP failure reports
a null egress_ip plus a warning and is not fatal.
`

const configHelpText = `usage: muse-cli config <subcommand> [options]

Config maintenance. Subcommands: migrate. Run
"muse-cli config <subcommand> --help" for per-subcommand help.
`

const configMigrateHelpText = `usage: muse-cli config migrate [--write]

Migrate legacy per-profile config files into the single
config.json. Dry-run by default: prints the JSON plan and writes
nothing. --write performs the migration atomically (mode 0600,
never deletes or edits the old files). An already-migrated config
exits 0; a differing single config refuses with exit 2. Only
"config migrate --write" may create a missing explicit --config
file.
`

const waitHelpText = `usage: muse-cli wait [--thread ID] [--after-seq N] [--timeout SECONDS] [--json] [--require-running] [--auto-approve|--no-auto-approve] [--auto-allow-once|--no-auto-allow-once]

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
`

const sendHelpText = `usage: muse-cli send TEXT [--thread ID] [--wait SECONDS] [--until-done] [--text] [--ack-timeout SECONDS] [--download DIR] [--auto-approve|--no-auto-approve] [--auto-allow-once|--no-auto-allow-once]

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
                 as in muse-cli wait.
`

const approvalsHelpText = `usage: muse-cli approvals [--recent] [--raw] [--approve-all]

List pending approvals (network access etc.) as JSON.

options:
  --recent       also list recent decisions.
  --raw          print the whole egress.approvals result as JSON.
  --approve-all  approve every pending approval with allow_always
                 (skips approvals with no forever option).
`

const approveHelpText = `usage: muse-cli approve [ID] [--all] [--once|--session|--today|--always]

Approve a pending request, or every pending approval with --all.
The decision defaults to allow_once.

options:
  --all          approve every pending approval.
  --once         allow_once (default).
  --session      allow_session.
  --today        allow_today.
  --always       allow_always.
`

const denyHelpText = `usage: muse-cli deny ID [--always]

Deny a pending request.

options:
  --always       deny_always instead of deny.
`

const autoApproveHelpText = `usage: muse-cli auto-approve [on|always|off|status] [once on|off|status]

Let wait/send approve every approval with allow_always (on|off|
status); once on|off controls the allow_once fallback. With no
arguments, or status, prints the resolved settings as JSON.
Settings persist in the active profile's single config file.

Precedence per toggle: per-call flag, MUSE_AUTO_APPROVE /
MUSE_AUTO_ALLOW_ONCE, config. Defaults off.
`

const chatHelpUsageText = `usage: muse-cli chat

Interactive chat (the default with no command). Type /help for
commands, /exit to quit.
`
