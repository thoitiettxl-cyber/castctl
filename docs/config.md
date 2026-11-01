# Config

Single-file config: one `config.json` holding every profile, plus
shared `outbounds`, `endpoints`, per-profile `dns`, and the
(interim, global-compat) top-level `dns` and `wireguard_dns`
sections below.
Location: `--config`, then `CASTCTL_CONFIG`, then `XDG_CONFIG_HOME`
via `os.UserConfigDir` semantics. An explicit `--config` path must
name a `config.json` file (a directory, or a file with another
basename, is an error — see the `--config` help text). When the `castctl` home does not
exist but the pre-migration `muse-cli` home does, the old home is
used with a one-line warning; nothing is moved or deleted (the
directory fallback — the config *directory* only; see
[Migration](#migration) for the per-profile file layout, which
profile loading refuses (only `config migrate` reads it)).

## Single-file schema

Top-level keys (exactly these ten; unknown keys are rejected):

| Key | Value |
|---|---|
| `default_profile` | string: name of the default profile |
| `profiles` | object: profile name → profile entry (below) |
| `outbounds` | array of sing-box outbound objects (shared, tag-addressed) |
| `endpoints` | array of sing-box endpoint objects (e.g. WireGuard, tag-addressed) |
| `dns` | object: the interim global DNS section (below, compat fallback only) |
| `wireguard_dns` | object: endpoint tag → array of DNS server addresses read by branch 2 (see [Per-profile DNS](#per-profile-dns)); castctl-side state, not a sing-box field — hand-written/preserved, not imported: no import-path wiring from a wg-quick `DNS=` line exists yet (follow-up) |
| `log` | object: logging settings (see [The `log` section](#the-log-section)) |
| `telegram` | object: Telegram bot settings (see [The `telegram` section](#the-telegram-section)) |
| `keeper` | array: session-keeper entries (see [The `keeper` section](#the-keeper-section)) |
| `webui` | object: web UI server settings (see [The `webui` section](#the-webui-section)) |

A profile entry accepts exactly these ten keys (unknown keys
are rejected — see [Per-profile DNS](#per-profile-dns)):

| Key | Value |
|---|---|
| `cookies_file` | string: path to the cookie file (relative paths resolve under `CONFIG_DIR`) |
| `vm_id` | string |
| `node_id` | string |
| `auto_approve` | `"always"` or `"off"` only — any other value, including `"on"`, is a config error |
| `auto_allow_once` | bool |
| `subscription_action_id` | string |
| `fingerprint` | string (browser fingerprint preset name) |
| `tls_engine` | string (`utls`, `cronet`, …; storage-only in the current build) |
| `outbound` | string tag (shared outbound/endpoint), an inline outbound object, or absent (= direct) |
| `dns` | object: the profile's own DNS section, parsed exactly like the top-level section (see [Per-profile DNS](#per-profile-dns)) |

Strictness: the file is parsed strictly — unknown fields anywhere
in the config are rejected, including inside `dns` servers and
rules. A malformed single file is an error (exit 2), never a
silent fallback. Cookies are never inline in the config:
`cookies`/`cookie` keys are rejected.

A profile with no entry in `profiles` and no config file of its
own still exists (its directory is its home) and loads with
defaults (`SourceNone`, direct, `auto_approve` off). A profile
directory with no config file is *not* a legacy layout.

## The `log` section

The top-level `log` block configures castctl's logging, following
sing-box's `LogOptions` semantics exactly WHEN THE BLOCK IS
PRESENT (see `docs/provenance.md` §1 for the upstream
citations). One resolved level governs every emission —
sing-box's own logs and castctl's own events — through a single
factory. The block is optional; all four fields are optional.
An absent field means the sing-box default below. An absent
BLOCK is different: see the off-gate rule below. There is no
hardcoded default log path — the user sets `output` freely, or
leaves it empty for stderr.

**Off-gate (castctl rule on top of sing-box defaults, Boss
decision 2026-10-30):** when the config has NO `log` block AND
no `--log-level` flag was given, logging is OFF: stderr carries
only the typed JSON error, exactly as before the `log` block
existed, and no log file is written. A present block — including
an empty `{}` block — turns logging ON at sing-box defaults
(level `trace`, output stderr). `--log-level` with no block
also turns logging ON, at that level with stderr output. A
block with `"disabled": true` stays off even with `--log-level`.

| Field | Type | Default | Meaning |
|---|---|---|---|
| `disabled` | bool | `false` | `true` suppresses ALL log output (castctl and sing-box), including fatal/panic lines. Normal command output (stdout JSON/text) and config errors are unaffected. |
| `level` | string | `"trace"` | One of `trace`, `debug`, `info`, `warn`, `error`, `fatal`, `panic`. sing-box's `"warning"` spelling is accepted as an alias for `warn`. Any other value (including `"TRACE"`) is a config error (exit 2), and the value is never echoed. An empty level means trace, exactly as sing-box parses it. |
| `output` | string | `""` (stderr) | `""` or `"stderr"` writes to stderr; `"stdout"` writes to stdout; any other string is a file path, opened for append. |
| `timestamp` | bool | `false` | Timestamp format, sing-box style: console output carries a full timestamp when `true` and a relative elapsed-seconds prefix when `false`; file output carries no timestamp when `false` and a full timestamp when `true`. |

Precedence, when logging is on: the `--log-level LEVEL` global
CLI flag beats the config block, which beats the sing-box
default (`trace`). An invalid `--log-level` value exits 2 and
never echoes the value. There is no `--verbose`/`--debug` flag.

**Typed JSON on stderr:** error output is one JSON line
(`{"type": ..., "error": ...}`) written after every log line.
When logging is OFF (no block, no flag) it is the only stderr
line, so whole-stderr JSON parsing works. When logging is ON
with stderr output, log lines precede it and the JSON stays the
LAST stderr line, intact — that last-line rule is the contract
consumers can rely on in that case. When log output is a file,
stderr carries only the JSON.

File output: castctl owns log-file creation — files are created
with mode `0600` and appended to (never truncated); a
pre-existing file is appended to without any chmod (castctl
never changes the mode of a file it did not create). Parent
directories are not created; an uncreatable path is a startup
error (exit 2). There is no log rotation. Console colour follows
sing-box's default (coloured level labels on a terminal); there
is no `disable_color` field in the schema.

The only path guard: the factory refuses (exit 2, before
opening, and re-checked after opening) a log output whose file
IDENTITY equals castctl's own config file or any of its cookies
files — identity means the symlink-resolved location and the
file's dev/ino, so hardlinks and symlinks to not-yet-existing
targets are refused too. There are no other path restrictions:
symlinks to other targets and non-regular files are not
refused. A refused output is a startup error; the protected
file is left untouched, and a file the factory did not create
is never chmodded.

Secrets: log lines never carry cookies, tokens, URLs with query
credentials, WireGuard keys, or header values. Secret-bearing
fields are excluded from log emissions by construction, and
every free-form log field passes a redaction boundary
(`internal/logging`). Server response bodies are never
emitted in any error, diagnostic, or log emission — not in log
lines at any level including trace, not in stderr typed JSON,
not in error strings, and not in panic renderings. (Chat
replies, history, watch rows, raw and wake output, and
opt-in raw dumps are data output the user explicitly
requested, not error/diagnostic/log emissions, and are out
of scope for this rule.) Instead, an error carrying a server
body renders as an allowlist summary only: status code,
error class, body length (byte count — when the producer
knows the wire length: a known 0-byte body renders
`body_length=0`, while an unknown length renders no
`body_length` field at all, never the length of the summary
text; the subscription server-action call's 401/403 branch is
an unknown-length case — it reads the body, capped at 4 MiB,
before checking the status, then discards it and returns 0
with the length marked unknown (the read length is discarded);
no summary is rendered from this branch at all — the error is
a status-only AuthError, returned immediately — so no
`body_length` is reported from that branch), content-type (media type, parameters dropped), and specific known-safe fields
parsed by key from known Muse response schemas — the `error`
field of the `{"ok":false,"error":...}` / `{"success":...,
"error":...}` envelopes, the `status` field of the
`/api/session` body (extracted only inside the summary
builder), and the `reason` field of the redeem response
(retained in the closed list, although no current producer
extracts it through the summary builder — the exact
producers are documented in `internal/gateway/summary.go`).
No other body key is ever emitted. Each extracted value is capped at 64
runes, still passed through the SafeString backstop, and a
value over the cap is replaced by `[omitted]` — never emitted
truncated. The trace level gets the same summary; there is
no trace allowance for body bytes. (Python parity on raw
payload bytes is waived; error-kind classification and retry
semantics are unchanged.)

The `approveAll` / `logAutoApproved` stderr lines are
structural in their approval fields, not redacted prose: the
title, options, id, decision, kind, and scope slots emit no
peer free text at all. An approval title renders as `title_length` only
(the title's BYTE length, the same byte convention as
`body_length`); offered decision options render as
`option_count` only (the number of options), and only on skip
renderings — the `approveAll` skipped line and the skip-error
`underlying` slot on the `SKIPPED` / `FAILED` lines — the
auto-approved lines carry no options slot, only `title_length`; an approval id
renders only if it is 1–64 runes of `[A-Za-z0-9_-]`,
else `[omitted]`; a decision renders only if it is one of
`allow_always`, `allow_once`, `allow_session`,
`allow_today`, else `[omitted]`; a kind renders only if it
is one of `browse`, `network_access`, `shell`, else
`[omitted]`; a scope always renders `[omitted]` (it is an
unconstrained host string, so no enum set exists). Carve-out:
the `SKIPPED` and `FAILED` lines in `logAutoApproved` also carry
an `underlying` slot for the decide error, and that slot is NOT
structural. For a skip error (no forever option offered) it
renders structurally as `no forever option option_count=N`; for
any other decide error it renders via the settled `SummarizeErr`
rule: the `LogSummary` of the first error in the chain that
implements it — a `GatewayError` renders its body allowlist
summary; an `AuthError` renders `conn: auth_failed
message_length=N` only; a `ConnectionError` renders its
cause's `LogSummary` when the cause has one, otherwise
`conn: connection error error_length=N` (bare `conn:
connection error` with no cause); a close-summary error
renders `gateway: websocket closed (close_code=N
reason_length=N)` — and an error with no `LogSummary` in the
chain renders via SafeString). Nothing here
implies `underlying` is structural. The
SafeString backstop is not the control on the structural slots
and is unchanged; on the `underlying` slot it remains the
rendering for errors with no `LogSummary` in the chain, via
`SummarizeErr`.
JSON stdout data output is unaffected: it
still carries the full title, options, id, kind, scope,
and decision.

Recorded backlog (NOT fixed): four SafeString bypass shapes
were observed in earlier loops and are carried here as a
record, not a fix. (O1) A JSON pair whose colon is spaced
with NBSP (U+00A0) -- e.g. `{"token"<NBSP>: "..."}` -- bypasses
SafeString's quoted-key scan. (O2) Wider Unicode spaces
(U+2009, U+3000, U+202F) between a label and its separator
bypass the closed separator set. (O3) A `public_key` label
separated by NBSP in the `=` form (`public_key<NBSP>=...`)
bypasses the listed vocabulary: `rePublicKey` allows only
ASCII whitespace around `=`, so the NBSP form misses it, and
the `reKeyValue` fallback leaves a `public_key` label
unchanged. The `:` form does not bypass: `reKeyColon`'s closed
separator set includes NBSP, so `public_key<NBSP>: ...` is
caught and reduced to the `wgKeyPrefix` form (the first 8
runes of the value, plus an ellipsis when the value is longer
than 8 runes; a value of 8 or fewer runes is returned
unchanged). (O4) An escaped-quote
JSON pair — e.g. `{\"token\": \"...\"}` — whose quoted key or
value string itself contains an unescaped literal newline or
carriage return reached by the scan bypasses SafeString's
escaped-quote scan, which fails on a literal newline or
carriage return at a scan position inside a quoted string
while the plain-quote scan tolerates a literal newline inside
the string — so the pair is left verbatim. A newline or
carriage return consumed as the second byte of a backslash
escape pair does not defeat the scan (the scan consumes a
backslash plus the next byte regardless, so the newline
check, which applies only at a scan position, never sees the
second byte). Separator
newlines do not trigger this: newlines between the key and
the colon, or between the colon and the value, are skipped
before the colon/value scan, so a separator newline alone
does not defeat the pair. `%q` cannot create this condition:
it escapes a literal newline to the two-byte sequence `\n`.
That is not a redaction guarantee: an unescaped literal
newline is sufficient, not necessary, for the bypass — a
`%q` rendering of text that already contains escaped quotes
is a separate route that doubles the backslashes and leaves
that escaped-quoted pair verbatim, secret included, with no
newline anywhere, while other parts of the same rendering,
such as a `token:` pair, still redact. None of these shapes
can leak through
the structural slots of the `approveAll` / `logAutoApproved`
stderr lines above, because those slots emit no peer free text
at all (only lengths, counts, gated ids, and enum members).
That statement does not cover the `underlying` slot on the
`SKIPPED` / `FAILED` lines, which renders via `SummarizeErr`
(see above). What would settle each shape is a future explicit
decision about whether SafeString's scanner
should be extended to cover it; no scanner change is made
or implied here, and no claim is made that the shapes are
fixed elsewhere.

The events castctl emits at debug/trace
are: `dns_source` (resolved DNS source + first server tag),
`outbound_chain` (profile + detour-chain tags), dial
start/done with a per-connection ID, `tls_alpn` (negotiated
protocol string only), `ws_handshake` (only the parsed
handshake status: a 3-digit code as `status_code` (from a
response) or `status_token` (from a malformed status line); a
numeric response code whose decimal length is not 3 renders
as its length only under `status_code_length`; a malformed-
status token that is token-shaped — ASCII letters, digits,
`.`, `_`, `-` only — but not a 3-digit code renders as its
length only under `status_token_length`; no token at all
for a shape-invalid, empty, or absent token, in which case no
event line is emitted and the failure error renders a fixed
message), and retries (attempt counter + summarised error).

`config migrate` carries an existing `log` block into the new
file verbatim and never invents one: a migrated file without a
`log` block stays without one.

## The `telegram` section

The optional top-level `telegram` block configures the Telegram
bot (`telegram run` / `telegram status`). It is sing-box style:
one block, linked to a profile by tag, with no separate file.
The block is optional; an absent block means the bot is off and
both subcommands exit 2. The block accepts exactly these five
keys (unknown keys are rejected):

| Field | Type | Default | Meaning |
|---|---|---|---|
| `profile` | string | — (required) | Tag of the profile the bot serves. The tag must name a profile in `profiles`; a dangling tag is a config error (exit 2). `telegram run` always serves this profile: an explicit `--profile` or `CASTCTL_PROFILE` naming a different profile is exit 2 naming both tags. |
| `token` | string | — (required) | The bot token from @BotFather. Shape-checked (`digits`, a colon, then 20 or more token characters, mirroring the Python check in `src/muse_cli/tgapi.py:49-52`); a shape-invalid token is a config error (exit 2) and the value is never echoed. The token is a secret: errors leaving the bot carry scrubbed copies whose text, verbose (`%+v`) and Go-syntax (`%#v`) forms, and every reachable error layer are token-free, and bot log lines render class/length summaries only, with no method field and no verbatim error text (no server body, description, or raw update bytes, at any size or shape); the one approval-metadata warn line carries only a gated approval_id (1–64 runes of `[A-Za-z0-9_-]`, else `[omitted]`) and kind/scope/title lengths, no field bytes; `telegram status` reports only shape validity. The scrubbed copies preserve only `errors.As` to the 429/migrate error types (with scrubbed messages) and `errors.Is` to the library sentinel classes — no other typed error view survives scrubbing. |
| `allowed_user_ids` | array of integers | — (required, non-empty) | The allowlist: sender user ids permitted to use the bot. Every id must be positive. The gate is on the sender's user id only (never chat id or chat type), mirroring Python `src/muse_cli/tgbot.py:643-648,989-1000`: a non-allowlisted sender's update is dropped silently — no reply, no state change. The sender is derived from the dispatched update kind (a callback sender gates a callback query even when the update also carries a message). Callback routing reads the message chat from a regular or inaccessible (`date:0`) message. A missing or empty allowlist refuses to start (exit 2, no token use, no polling). |
| `auto_approve` | bool | `false` | Auto-decide approvals that offer a forever option. Default source: the castctl profile-entry default (`parseProfileEntry` treats a missing entry as off). Bool-only in this block: the profile entry's `on`/`off` word spelling is not carried over. |
| `auto_allow_once` | bool | `false` | When `auto_approve` is on, also auto-decide approvals that offer only a once option, with the `allow_once` decision. Default source: the Python bot-state default (`src/muse_cli/tgbot.py:630`, `auto_allow_once: False`). `allow_once` is a decision string for one approval id gated by this toggle, not a consumed one-shot grant; the manual Allow-once button ignores the toggle (`src/muse_cli/tgbot.py:1703-1723`). |

The bot dials only through the linked profile's outbound: its
HTTP client is the profile runtime's client (proxy explicitly
nil), never the environment proxy and never another profile's
outbound. The binder accepts only an `*http.Transport` with a
custom dial path (rejecting delegating wrappers and the
default direct-dial transport) and refuses HTTP redirects, so
the token-bearing path is never sent to a second server.
Polling is long polling only (`getUpdates`,
timeout 25s), mirroring Python `src/muse_cli/tgbot.py:2435-2462`.
Dedupe remembers the last 1024 update ids (older redeliveries
may be handled again); per-chat queues hold 64 updates and
drop (counted) arrivals past that rather than stalling other
chats; idle queues are reaped after 5 minutes; shutdown
drains queues for at most 10 seconds, then abandons the
remainder (counted as dropped).

Deliberate deviations from 0.6.1 beyond the in-memory state
above: `edit_plain` swallows every edit error (Python catches
only Telegram/connection errors — the scrubbed-error contract
cannot express that distinction); and the claim protocol's
storm (a slow decider with a short claim wait lets every
concurrent caller decide the same id — the mirrored Python
protocol's own defect, kept as surveyed; gateway-side
idempotency is required in step 5). The production bot
logger falls back to the default slog logger, bypassing the
logging factory (step-5 follow-up; every bot log line carrying
error text renders a class/length summary first, and every
other bot log line carries only numeric ids, fixed-vocabulary
kinds, a gated approval_id, or field lengths — no verbatim
caller/server text — so this is a routing issue, not
a leak).

Save behaviour: config renders carry the block verbatim when
present in raw form, and re-render it field-by-field otherwise
(including the stored token value); the token is never written
to logs.

What this build does NOT wire (roadmap step 5): Muse turn
execution from Telegram messages, the full slash-command and
callback surface beyond decide/approve-all, media, `/login`,
persistent offset/dedupe state, and `telegram setup` /
`install-service`. `telegram run` answers every message with an
explicit placeholder notice and fails approval decisions closed
until that wiring lands.

## The `keeper` section

The optional top-level `keeper` block configures the session
keeper (`keeper run` / `keeper check` / `keeper status`). It is
sing-box style: a LIST of entries, each linked to a profile by
tag. An absent block means the keeper is off: all three
subcommands exit 2. The block accepts exactly these five keys
per entry (unknown keys are rejected):

| Field | Type | Default | Meaning |
|---|---|---|---|
| `tag` | string | — (required) | Entry tag, unique across entries. A second entry with the same tag, or two entries for the same profile, is a config error (exit 2). Tags are exact: surrounding whitespace is rejected (never trimmed); `/`, `\`, control characters (including newline), and the tags `.`/`..` are rejected — tags name owner files under the profile directory. |
| `profile` | string | — (required) | Tag of the profile whose cookies are watched. Must name a profile in `profiles`; a dangling tag is a config error (exit 2). |
| `browser` | string | — (required) | CDP URL of the already-running Chrome to re-export cookies from. `http://` and `ws://` loopback URLs only, with an explicit port, no userinfo, no query/fragment; any non-loopback URL is a config error (exit 2, fail closed). Example: `http://127.0.0.1:9226`. Two entries sharing one browser (after canonicalisation of spelling variants such as a trailing slash, host case, or the `http://`/`ws://` scheme — the scheme is not part of the dedup key) is a config error. |
| `interval` | duration string | `24h` | Tick cadence. Zero or absent means the documented default cadence of 24h; a present value must parse with `time.ParseDuration`, be positive, and be at most 1 year (`8760h`, the jitter-arithmetic bound). The effective delay is adaptive: when a driving cookie expiry is known, the next delay is `min(interval, clamp(remaining/4, 1h, 7d))`, ±20% jitter, re-drawn per wait. |
| `notify` | string | `""` (off) | Only `""` or `"telegram"`. `"telegram"` sends fixed-content notices through the single `telegram` block (which must exist); any other value, or `"telegram"` with no telegram block, is a config error (exit 2). |

Behaviour:

- **Expiry detection.** Each tick runs the cheap chain only
  (GET `/api/session` → POST `/api/auth/check`, no hatch/token,
  no WebSocket, no chat) through the profile's own outbound,
  with the profile identity. An AuthError means expired: the
  entry stops (sticky stopped state), is marked logged out,
  and notifies once — never loop-retried. Transient errors
  back off on a 5m/15m/45m ±20% ladder, max 3 retries per tick.
- **Re-export.** On expiry, cookies are re-exported from the
  configured browser over CDP (`Storage.getCookies` primary,
  `Network.getCookies` fallback) and merged. Only `muse.ai`
  and `auth.muse.ai` cookies are kept; everything else is
  dropped (count only). A merged set is written only if it
  contains a non-empty `hatch_sess` and the earliest
  FILTERED-domain expiry is not already past: an expired
  cookie from an unrelated domain is preserved verbatim by
  the merge and never vetoes a valid re-export. CDP
  snapshots are faithful: an exported cookie is recorded
  exactly as the browser holds it (an empty value with a
  future expiry is written verbatim), and a filtered cookie
  absent from the snapshot is dropped. Builds without
  `-tags with_chromedp` detect and report expiry but cannot
  re-export: the entry stops with the typed unavailable
  outcome instead.
- **Cookie save.** Netscape jar only (7 columns, LF, trailing
  newline, deterministic sort). Set-Cookie updates merge into
  a stored jar; a stored non-jar file is left untouched by
  Set-Cookie capture (the tick still runs, state records the
  observed expiry), while a CDP export REPLACES a non-jar file
  with the validated export (dropped count recorded). The
  merge key ignores the leading dot on domains: a host-only
  stored entry and a Domain-scoped update are the same cookie
  for merge purposes. Set-Cookie semantics: a present Domain
  normalises to a leading-dot domain; Max-Age wins over
  Expires; an empty value with a future expiry REPLACES
  (expiry-only deletion is never assumed from an empty
  value); an empty value with no expiry information deletes
  (the Max-Age=0 clear shape). Writes happen only on
  byte-difference, atomically, mode 0600 with a 0600 `.bak`,
  under a per-cookies-file lock: the previous file is copied
  to `.bak` first and the new file is then renamed over the
  target, so the target is never absent mid-write. Cookie
  values are never logged or printed, anywhere. The keeper's jar parser
  requires exactly 7 columns; the legacy gateway reader
  accepts 7 or more — the divergence is intentional (the
  keeper rewrites the file and must not silently drop extra
  columns) and is bridged by the state-only reset path.
- **State file.** Per profile, `session-state.json` (mode
  0600) next to — never inside — `config.json`, schema v1:
  `logged_out`, `keeper_stopped` + reason, `last_checked_at`,
  `last_tick_outcome`, per-cookie `expires_at`/`session`/
  `last_seen` (names and dates only, never values),
  `earliest_expiry`, `driving_cookie`/`driving_expiry`,
  `next_check_at`, warn markers, and login provenance fields
  (written by the login flow only). It is observed state, not
  configuration; `keeper status` reads it with no network.
  The driving cookie is `hatch_sess` when present with a
  non-session expiry, else the earliest expiry; both fields
  are carried in state so the choice stays a resolver change.
  The profile directory is created (0700, including the
  default profile's config dir) when a tick first needs it,
  including when the profile's cookies file lives outside the
  config dir, and re-ensured before every state save. If the
  directory cannot be created, or any lock or state-save step
  fails for any reason other than a held lock, the tick
  reports outcome `error` and `keeper check` exits non-zero
  with the problem named — never `skipped`, which is
  reserved for a login in progress or a held lock (matched
  by exact sentinel errors only). A cancelled context is
  not an exception: a tick timeout surfaces as outcome
  `error` carrying the context error (`keeper check` exit
  4), and a parent interrupt exits 130 with no JSON
  printed.
  A corrupt or unknown-version state file does NOT brick the
  keeper: ticks substitute a fresh state, re-observe from the
  cookies file, and flag `state_corrupt` in `keeper check`
  output and `keeper status` (reason `state_corrupt`); the
  next successful save replaces the corrupt file, and the
  import/login reset always succeeds. Manual remedy: delete
  `session-state.json` in the profile directory (observed
  state is rebuilt on the next tick; the cookies file is
  untouched).
- **Run/check behaviour.** `keeper run` prints one summary
  line per tick and exits 2 naming the entry when an entry's
  factory fails (the entry never ticked) instead of exiting 0
  silently. `keeper check` ticks every selected entry even
  when one errors transiently (the first typed error is
  returned after all entries print), and an interrupt ends
  the command instead of being swallowed as a skip. A
  state-directory failure likewise surfaces as a non-zero
  exit (outcome `error`, with `wrote_cookies` reporting
  whether the cookies file was actually rewritten), never
  as `skipped`. The same holds for any other lock or
  state-save failure other than a held lock.
- **Notifications.** Fixed content only: profile name,
  outcome, the re-login path (`auth login` / `auth import`),
  and "No action was taken automatically." No secrets, no
  cookie names, no error text. At most one notice per
  false→true logged-out transition; a failed send stays
  pending for a later tick. Deduplication is at-least-once
  across crashes: a crash between a successful send and the
  marker-clear may re-send once. Targeting: the notice goes to the
  FIRST `allowed_user_ids` entry of the telegram block, on
  the assumption that a user id is a valid chat id for a 1:1
  bot chat. Delivery to that id is UNVERIFIED offline and is
  a live-test gate; if it fails, the fix is a chat registry,
  not a silent change here. The notice travels through the
  telegram block's LINKED profile outbound, bounded by a 30s
  timeout.
- **Shared session.** Exported cookies share the browser's
  session: a server-side revoke kills both the browser and
  the profile session. The keeper validates liveness with the
  cheap chain, never by mere `hatch_sess` presence.
- **Logging.** The keeper core emits no log lines of its
  own: when no `log` block is configured, logging is OFF and
  the state file plus `keeper run`'s stdout summary lines
  (tag, outcome, counts, next delay — never values) are the
  visible channel.
- **Screencast login.** `castctl auth login` is experimental
  and off by default (`--experimental-login` or
  `CASTCTL_EXPERIMENTAL_LOGIN=1`); without the flag it exits 2
  pointing at `auth import`. It attaches to the keeper entry's
  browser first; launching a castctl-owned Chrome is only the
  fallback when no attachable browser exists, and at this
  base the launch fails closed (no fail-closed routed inbound
  exists yet) rather than launching a direct-egress browser.
  The human completes the login; captcha/2FA are never
  auto-solved. Honesty note on the attach path: castctl's own
  code sends no Runtime/JS calls and the browser-level export
  path sends only `Storage.getCookies`, but chromedp's target
  attach bootstrap enables Runtime, DOM, CSS, Log, Inspector,
  and Page, sets `Target.setDiscoverTargets` /
  `Target.setAutoAttach`, enables
  `Page.setLifecycleEventsEnabled`, and evaluates the constant
  `"self"` (the full observed set is listed in
  `internal/keeper/screencast.go` and pinned exactly by the
  wire-recording test) — the CDP allowlist discipline covers
  castctl's own calls, not the library bootstrap. See
  `castctl auth login --help`.

## The `webui` section

Optional. Absent means no web UI: `castctl webui serve` fails
closed (exit 2) and nothing listens. The block accepts exactly
three keys:

| Key | Value |
|---|---|
| `listen` | string: loopback `host:port` the server binds (default `127.0.0.1:8317` when the block is present without `listen`) |
| `token` | string: the management token, write-only (see below) |
| `ui_dir` | string: directory of static frontend files served instead of the embedded frontend (see below) |

`ui_dir` (optional) names a directory of public static files
(HTML/JS/CSS/assets) that `webui serve` serves WITHOUT auth in
place of the embedded single-file frontend. A relative value
resolves against the directory holding `config.json`. When the
key is absent, the embedded frontend is served byte-identical;
when the key is present but broken (missing, not a directory,
or without a regular `index.html`), `webui serve` fails closed
(exit 2) instead of silently falling back to the embedded
frontend. A symlinked `index.html` is refused at startup
(exit 2) and per request (fixed 404) — any symlink, even one
whose target stays inside the root — because the shell path
must only ever serve the regular file startup validated. A missing file under a valid `ui_dir` falls back to
the on-disk shell (SPA hash routing). Serving is GET-only, with
no directory listing, no dotfiles, and symlink-aware
containment re-checked per request: a path escaping the root
through `..` or a symlink gets a fixed 404, and only regular
files are served. `/api/v1` keeps precedence and its Bearer
gate: an API path never reads a disk file. The `/api/v1/status`
`bundle_sha256` is the SHA-256 of the on-disk `index.html`
while `ui_dir` is active, and the embedded hash only in
fallback mode.

`ui_dir` must never overlap the config directory — equal to,
inside, or an ancestor of it — and must not contain any
profile's cookies file: the static shell is unauthenticated,
so an overlapping directory would serve `config.json` and
cookies to anyone on loopback with no token. The rule is
enforced at parse time (lexical), at serve time (symlink
resolved), and at API save time for new or changed values
(an authenticated user must not be able to `PUT /config` a
`ui_dir` over the config tree and then fetch the secrets
unauthenticated). `ui_dir` is not a secret and is shown
verbatim in redacted config views. The on-disk directory is
trusted input: populate it only from verified module installs
or explicit updates, never point it at a user-writable or
shared directory. Its content is trusted same-origin code —
the frontend keeps the token in `sessionStorage`, so a
malicious file served from `ui_dir` could read it: serve only
content from a trusted source. A check-then-open TOCTOU residual remains
between the per-request containment check and the file open
(the open is followed by an fstat re-check, so a non-regular
file is never served, but a symlink swapped in the same
window could redirect one read).

Loopback-only is enforced at parse time: `listen` must be a
bare `host:port` with a loopback host (`127.0.0.0/8`, `::1`, or
`localhost`, case-insensitive) and an explicit port 1–65535.
Anything else — `0.0.0.0`, `::`, a non-loopback address or
hostname, a URL, userinfo, a path, a query, or a fragment — is a
config error (exit 2) whose message never echoes the value.
Present-but-empty `listen`/`token` is a config error. The
`--listen`/`--port` flags of `webui serve` override within a
present block only, and are re-validated loopback-only; both
flags together are an error.

The effective token is `CASTCTL_WEBUI_KEY` when set (non-empty,
exact value, no trimming), else the block's `token`. A
whitespace-only `CASTCTL_WEBUI_KEY` counts as unset (it could
never authenticate, since the token is compared exactly). With
neither set, `webui serve` fails closed (exit 2) and never
starts unauthenticated. The token is never printed, logged, or
returned: the startup line names the listen address only, and
the API answers every route (including `/status`) only with a
valid Bearer token. The static frontend shell is served without
auth (it carries no secrets); the single-use screencast session
token travels in the WebSocket URL query, never the Bearer
token. See `castctl webui serve --help` and
[Security](security.md).

The block is stored verbatim in the 0600 file like any other
block (raw preservation on save); write-only is an API-layer
property: GET endpoints return redacted views, and the token can
only be set or replaced, never read back. Note the first-save
reorder caveat that applies to every web UI save: the first
web UI save may reorder keys within sections; semantics are
preserved.
Remote access is loopback-only by design: reach the server from
another device through an SSH tunnel forwarding the loopback
port, never by binding a non-loopback address.

## The `dns` section — INTERIM, GLOBAL, COMPAT-ONLY

> **INTERIM.** The top-level `dns` section is global: one section
> serves every profile in the file. That is a compat fallback
> only, kept for one cycle (see [Per-profile DNS](#per-profile-dns)
> for the implemented model and the precedence order). Do not design
> multi-profile DNS behaviour around the global section: it cannot
> express per-profile resolvers. `config migrate` distributes it
> into profile entries (verbatim copy per profile, detours
> filled/kept/refused per profile — gated decision G4, see
> [DNS distribution by `config migrate`](#dns-distribution-by-config-migrate))
> and removes the top-level section in the same write. A profile
> entry carrying its own `dns` block and
> a file carrying a top-level `dns` section together are a config
> error (exit 2): the two are never silently shadowed. The
> compat cycle ends in a hard error in a later PR (documented
> future step, not yet implemented).

The section is parsed by sing-box (v1.14) `option.DNSOptions`.
No field is required at parse level; an empty section (`{}`) is
accepted by the parser but fails at runtime (see Semantics).
Fields:

| Field | Type | Notes |
|---|---|---|
| `servers` | array of server objects | see below |
| `rules` | array of rule objects | see below |
| `final` | string | tag of the server used when no rule matches |
| `reverse_mapping` | bool | reverse (PTR) mapping |
| `strategy` | string | `""` (default), `as_is`, `prefer_ipv4`, `prefer_ipv6`, `ipv4_only`, `ipv6_only`; anything else is a parse error |
| `timeout` | string duration, e.g. `"5s"` | per-query timeout |
| `disable_cache` | bool | disable the DNS cache |
| `disable_expire` | bool | serve expired cache entries |
| `independent_cache` | bool | **deprecated** in sing-box: accepted, only a deprecation is reported; do not rely on any other effect |
| `cache_capacity` | int | cache size |
| `optimistic` | bool or `{"enabled": bool, "timeout": duration}` | optimistic (stale-while-revalidate) answers |
| `client_subnet` | string | EDNS client subnet sent with queries |

### Servers

`type` is one of: `udp`, `tcp`, `tls`, `https`, `quic`, `h3`,
`local`, `hosts`, `fakeip`, `dhcp`, `mdns`, `tailscale`,
`openconnect`, `openvpn`. An empty or `legacy` type is rejected
with a migration message. Availability depends on the build:
`quic`/`h3` need the `with_quic` tag (present in the canonical
castctl build); `dhcp` needs `with_dhcp` (absent — a `dhcp`
server fails at transport creation); `tailscale`/`openconnect`/
`openvpn` are stubs unless built with their tags. There is no
`resolved` DNS transport type.

Common fields (all servers): the dialer options — `detour`,
`bind_interface`, `inet4_bind_address`, `inet6_bind_address`,
`bind_address_no_port`, `protect_path`, `routing_mark`,
`reuse_addr`, `netns`, `connect_timeout`, `tcp_fast_open`,
`tcp_multi_path`, `disable_tcp_keep_alive`, `tcp_keep_alive*`,
`udp_fragment`, `domain_resolver`, `network_strategy`,
`network_type`, `fallback_network_type`, `fallback_delay`
(plus the deprecated `domain_strategy`). `detour` names the
outbound/endpoint tag DNS traffic travels through; it must
resolve to a tag in the config's tag namespace (shared
`outbounds`, `endpoints`, or an inline profile outbound — the
runtime-only `"direct"` outbound and the synthetic
`"castctl-dialer"` are NOT valid detour tags, except for the
per-profile synthesised direct tag, which is valid only as its
own direct profile's detour — see
[Per-profile DNS](#per-profile-dns)).

Per-type fields:

| Type | Fields |
|---|---|
| `udp`, `tcp` | `server` (required: hostname or IP), `server_port` (default 53) |
| `tls` | remote fields + TLS options (`tls.enabled`, `server_name`, `insecure`, `alpn`, certificates); `server_port` default 853 |
| `https` | TLS fields + `path` (default `/dns-query`), `method`, `headers`; TLS is forced on for `https` transports; `server_port` default 443 |
| `local` | `prefer_go` (bool), `neighbor_domain`; **no** `server` field — it queries the system resolver |
| `hosts` | `path`, `predefined` (static host mappings) |
| `fakeip` | `inet4_range`, `inet6_range` |
| `dhcp`, `mdns` | local fields + `interface` |

### Rules

A rule has `type` (`default` or `logical`) plus match fields,
and an action. Match fields include: `inbound`, `ip_version`
(4/6), `query_type`, `query_client_subnet`, `query_dnssec`,
`network` (`tcp`/`udp`), `auth_user`, `protocol`, `domain`,
`domain_suffix`, `domain_keyword`, `domain_regex`,
`source_ip_cidr`, `source_ip_is_private`, `source_port`,
`source_port_range`, `port`, `port_range`, `process_name`,
`process_path`, `process_path_regex`, `package_name`,
`package_name_regex`, `user`, `user_id`, `outbound`,
`clash_mode`, `network_type`, `network_is_expensive`,
`network_is_constrained`, `wifi_ssid`, `wifi_bssid`,
`interface_address`, `network_interface_address`,
`default_interface_address`, `source_mac_address`,
`source_hostname`, `preferred_by`, `rule_set`,
`rule_set_ip_cidr_match_source`, `match_response`, `ip_cidr`,
`ip_is_private`, `ip_accept_any`, `response_rcode`,
`response_answer`, `response_ns`, `response_extra`, `invert`
(plus deprecated geosite/geoip fields).

Actions (`action`): `route` (with `server` + `speculative`),
`evaluate`, `respond`, `route-options`, `reject`, `predefined`.

Rule `inbound` matching: castctl defines no inbounds, so how an
`inbound` match field behaves in this build is
[UNVERIFIED] — do not assume it is inert, rejected, or
match-all; verify against a live run before relying on it.

### Semantics (current build)

- **No single config file → no DNS client.** Domain
  destinations fail closed with `outbound: no DNS resolver
  registered` (`ErrNoResolver`); IP-literal destinations still
  work. There is no silent fallback to the system resolver.
  With a single config file, a resolver is always built: a
  profile with no resolver of its own gets the synthesised
  default (see [Per-profile DNS](#per-profile-dns)), never a
  nil client.
- **Empty `servers` list → construction error** (`dns: no DNS
  servers configured: refusing to fall back to the system
  resolver`). An explicitly present but empty per-profile
  `"dns": {}` is the same construction error, never a silent
  synthesis: presence distinguishes "configured badly" (error)
  from "configured nothing" (synthesised default).
- DNS is built and registered before outbounds, and started
  before the outbound manager starts; one DNS client per
  invocation/profile, with a per-client cache and per-manager
  detour resolution (no cross-profile cache/pool sharing).
- **Bootstrap is the sole system-resolver use.** A remote
  server addressed by domain name is bootstrapped through the
  system resolver so its address can be dialled through the
  detour. IP-literal servers need no bootstrap. `local`,
  `hosts`, and `fakeip` servers are unaffected by bootstrap.
- **WireGuard key-sharing check includes dns detours.**
  A dns server whose detour is a WireGuard endpoint participates
  in the same private-key comparison as profile outbounds: two
  profiles (or a profile and the dns section) sharing one
  WireGuard private key are rejected. Per-profile dns detours
  are checked per profile: a profile's own dns detour sharing a
  key with that profile's outbound (through a different tag) is
  an error naming the profile and `dns`; a dns detour naming
  the profile's own endpoint tag is one config, not an error.

## Per-profile DNS

A `dns` block inside a profile entry is the profile's own
resolver. It parses exactly like the top-level section
(sing-box `option.DNSOptions`, strict), is preserved verbatim
on save, and is shown by `profile show` (via the profile entry
rendering) and by `profile test` Phase 1 (first server tag plus
the source below).

**Validation (parse time, exit 2).** Each server's `detour`
must be non-empty (G2: an empty detour would dial the DNS
server directly, outside the profile's outbound) and must lie
in the owning profile's reachable set: the profile's outbound
tag (or inline tag), every tag reachable from it through
detour chains and selector/urltest member lists, plus — for
direct profiles only — the profile's synthesised direct tag
(below). A detour naming another profile's inline outbound, a
dangling tag, a duplicate server tag within the block, or a
`final` naming no server tag in the same block are all errors.
The runtime creates the active profile's own inline outbound
in its own manager under its tag, so an own-inline detour
resolves at DNS Start; other profiles' inline outbounds are
never created there. Server tags are scoped per profile: two profiles may both use
tag `dns1` with no collision.

**Precedence** for the active profile, in order
(`profile.ResolveProfileDNS`):

1. The profile's own `dns` block.
2. Else the WireGuard endpoint's DNS servers from the
   `wireguard_dns` state, reached through that tunnel (see
   below). When this branch fires while a top-level `dns`
   section is present, the section is shadowed, and a one-line
   stderr warning says so (same channel as the compat
   warning). The warning directs the operator to remove the
   top-level section by hand: distribution with
   `config migrate --write` refuses while the profile
   resolves WireGuard DNS (see below). Removing the section
   by hand also changes every non-WireGuard profile's
   resolver: those profiles stop using the compat section
   and fall through to the synthesised default (item 4) —
   the section's servers are not preserved for them unless
   they were distributed into per-profile blocks first.
3. Else the top-level `dns` section, compat fallback for one
   cycle, with a one-line stderr warning telling the operator
   to run `config migrate --write` to distribute it into
   profile entries (see [DNS distribution by `config
   migrate`](#dns-distribution-by-config-migrate)). The
   warning is printed only when a runtime is built for the
   profile; read-only commands such as `profile show` and
   `profile list` print nothing on stderr for the legacy
   form. Compat sits
   before the default deliberately: a config migrated by the
   removal PR carries an authored global section that must keep
   working for one cycle, and the warning must be observable
   (if the synthesised default always won, the compat branch
   could never fire). This ordering differs from the pre-gate
   design doc §3.3, which ordered synthesis before the global
   fallback; that order would make compat dead code.
4. Else the synthesised default: DoH to 1.1.1.1 (`https`,
   IP-literal, no bootstrap), with detour = the profile's
   outbound. It applies only when the file carries no resolver
   at all. Synthesised defaults are runtime-only and are never
   written into the config file.

**The synthesis mechanism, named explicitly.** For a direct
profile there is no config tag to detour to, and sing-box
rejects a detour to an empty direct outbound at transport
Start (`detour to an empty direct outbound makes no sense`).
The runtime therefore synthesises, per profile, a tagged
direct outbound named `castctl-direct:<profile>` — created in
`createOutbounds` (after the plain `"direct"` outbound, before
DNS Start, so the detour resolves by Start time) and only in
the active profile's own manager. It is made non-empty by
exactly one explicit dialer field, `udp_fragment: false`
(`SynthesizedDirectOutbound`): that field affects only UDP
packet dialing through this outbound, which carries
DNS-detour traffic only (never profile traffic, which dials
through `"direct"`), and for the DoH default (TCP/TLS) it
changes no dialing behaviour. No sing-box guard is weakened:
`DisableEmptyDirectCheck` is never set (it is `json:"-"` and
no DNS transport dialer sets it), the plain `"direct"`
outbound stays empty, and a detour naming `"direct"` still
fails exactly as before (pinned by
`internal/dns/gate2_test.go`). A direct profile's own `dns`
block may also detour to its synthesised tag; that is the
only way a hand-written block detours to a direct outbound.
The `castctl-direct:` prefix is reserved: any config
outbound, endpoint, or inline outbound tag carrying it is a
parse-time error (exit 2), and `createOutbounds` fails loudly
if the synthesised tag is already taken, so a config tag can
never capture the default DoH detour.

**WireGuard DNS (branch 2).** `wg-quick DNS=` has no field in
sing-box's `WireGuardEndpointOptions`. Branch 2 reads the
top-level `wireguard_dns` key (endpoint tag → server
addresses; each key must name a WireGuard endpoint in the same
file) — hand-written/preserved castctl-side state, NOT an
import: `outbound.ParseWireGuardConfWithDNS` can capture
`DNS=` from a wg-quick conf, but no production caller wires
that capture into `wireguard_dns` yet (import-path wiring is
a follow-up). Branch 2 builds one `udp` server (port 53) per
listed address, all detouring through that endpoint tag. The
legacy `ParseWireGuardConf` entry point still drops `DNS=`,
preserving its contract.

**`local` is never the default: explicit-only.** A hand-written
`local` server keeps sing-box's default `prefer_go=false`.
[UNVERIFIED until live proof: on systemd-resolved hosts, when
the system resolver reports `SystemdResolved` and `prefer_go`
is false, queries go via D-Bus to `org.freedesktop.resolve1`,
NOT through the detour — so `local`+detour leak-freedom is not
claimed here, and live traversal of `local`+detour is unproven.
Prefer an explicit `https`/`tls` server with a detour over
`local` until live proof exists.] `local` has no hermetic
fake-upstream test (it reads the OS resolver config); the
fake-upstream tests prove the `tcp` detour mechanism, not
`local`.

**Live proof (post-merge, not claimed from fake-upstream
tests).** For each profile: `profile test` Phase 1 `ok: true`
with the effective source shown (`profile` / `wireguard` /
`global-compat` / `default`), plus a real lookup through the
profile's outbound. A profile whose outbound is down must not
break another profile's `profile test`.

[UNVERIFIED-LIVE: sandbox blocks raw TCP] DNS live traversal is
NOT proven. The sandbox intercepts raw outbound TCP, so the
earlier `profile test` failure is not evidence against
castctl/config. Outside-sandbox live proof is deferred to the
end-to-end core test step; `other_tcp` is NOT flipped.

## Migration

The legacy per-profile layout — flat `config.json` files in
three shapes: `config.json` at the config dir (when no single
file exists), `profiles/<name>/config.json` for any named
profile, and `profiles/default/config.json` — is **refused by
profile loading, never read** by it. The refusal fires ONLY
for names WITHOUT a single-file entry, and for those it is
layout-wide: `LoadProfile` exits 2 for such a name — including
a ghost name with no file of its own — whenever ANY legacy
file exists anywhere in the layout — for example, a single
file holding `default` plus a leftover
`profiles/work/config.json` refuses even a load of `zzz` (no
entry). A name WITH a single-file entry loads wholly from
that entry, unaffected by leftover legacy files. The error is:

```
profile: legacy layout found at "<path>"; run `castctl config migrate --write` first
```

The message names the migration command and the legacy file
path only — never file contents, cookie/token/key values, or
identifiers. The old files are never deleted or modified by any
command; they are the backup. Migrate itself is the only reader
of legacy files, deliberately, through a migrate-only parser.

Symlink-to-file loud fail: a `profiles/<name>` entry that is a
symlink resolving to a regular file fails loudly (exit 2,
naming the path) and writes nothing — it is never silently
dropped and never replaced by a synthetic default (pinned by
`TestMigrateFromSymlinkedProfileFile`). A symlinked profile
*directory* is followed, not dropped.

On top of the `LoadProfile` refusal, the CLI's own guards
refuse two more shapes: `profile show` for a name with no
single-file entry, no own config file, and no profile
directory exits 2 ("does not exist"), and `profile add`
refuses when no single file exists and any legacy file is
present, or when the added name's own legacy file exists
(`profiles/default/config.json` counts as `default`'s own
legacy file). Only when a name has no single-file entry AND
no legacy file exists anywhere in the layout does
`LoadProfile` synthesise defaults — a bare profile directory
with no config file still synthesises.

Procedure:

```sh
castctl config migrate            # dry-run: print the plan, write nothing
castctl config migrate --write    # migrate atomically (mode 0600)
```

Properties (all tested): dry-run by default; `--write` writes
atomically under a config lock held across decide+write (mode
0600, temp file + rename; no `.bak` file is kept for
`config.json` — the old files are left untouched and are the
backup; `.bak` exists only for cookies files); refuse-overwrite
— an existing single file that differs from the migration
result refuses with exit 2 (there is no `--overwrite`);
a base file with no `profiles` key that carries single-format
sections (`dns`, `outbounds`, `endpoints`, `wireguard_dns`,
`log`, or `default_profile` in single-config shape) refuses
a fresh migration with exit 2 and is left unchanged, instead
of being overwritten with the sections deleted (see below);
idempotent — re-running after a successful migration reports
`already-migrated`; all-or-nothing — any profile error aborts
the whole migration and nothing is written; existing
single-file `outbounds`, `endpoints`, and
`default_profile` are carried verbatim, and a top-level `dns`
section is distributed into profile entries instead (see
[DNS distribution by `config migrate`](#dns-distribution-by-config-migrate));
no outbound is ever
invented; `node_id` is generated only on `--write` when no
single file exists yet.

A base `config.json` with no `profiles` key is normally a
legacy flat file and migrates as one — but when it carries
single-format sections in single-config shape (an object
`dns` section, an `outbounds`/`endpoints` array with any
element an object carrying a non-empty string `type`, a
`wireguard_dns` object with any value array containing any
string, a `log` object with any key a log-block key
(`disabled`, `level`, `output`, `timestamp`), or
a string `default_profile`), a fresh migration would
overwrite it and delete those sections. That shape refuses
instead (exit 2, file unchanged, in dry-run and `--write`,
at the destination under `--from` too): add a `profiles`
object so the file parses as a single config, or remove the
sections by hand first. Unshaped values (a string `dns`, an
empty `outbounds` array, an array with no shaped outbound
such as a lone outbound object without a `type`, a
`wireguard_dns` object with no string in any value array, a
`log` object with no log-block key) keep the legacy path, as
before. An empty `log` object (`{}`) also keeps the legacy
path: it carries no keys or values, so there is no shaped
state to lose — the same empty-section reasoning as an empty
`outbounds` array. A `log` object mixing a log-block key
with any other key now refuses, because the `log` check is
existential over keys: one log-block key proves the section
is single-format. A file with a `profiles` key, including an empty
`profiles: {}`, takes the single-file path, where the
zero-profile distribution refusal applies instead.

### Migrating from a different directory (`--from`)

`--from <dir>` separates the migration source from the
destination: legacy profiles are read ONLY from `<dir>`, and the
single config is written ONLY to the `--config` file's directory
(or the default config directory when no `--config` is given).
The source directory is never written, locked, or modified in
any way — verify this by hash before and after; the old files
stay in the source as the backup. Cookies files stay in the
source too: migrated entries point at them by absolute path.
A missing source directory exits 2 and writes nothing anywhere.
Refuse-overwrite applies at the destination. When `--from`
names the destination directory itself, including through a
symlink, behaviour is exactly the in-directory behaviour above:
source and destination are one directory, and the run writes
the single config to that directory as usual. The
source-never-written guarantee applies only when `--from`
resolves to a different directory than the destination; when
either path cannot be resolved, the two are treated as
different directories. The dry-run plan reports
`source_dir` and `destination_dir` (paths only, no file
contents) and writes nothing to either directory.

```sh
castctl --config ~/.config/castctl/config.json config migrate --from ~/.config/muse-cli            # dry-run: plan only
castctl --config ~/.config/castctl/config.json config migrate --from ~/.config/muse-cli --write     # migrate into the new directory
```

Note on the `source` label in the plan: migrate enumerates
profiles by directory discovery and reports every profile it
builds from the old layout as `source: "legacy"` — including a
profile whose directory holds no config file at all (defaults
only). That label is a discovery label, not a finding that a
legacy config file exists: the load refusal and the
`profile add` block fire only on an actual legacy config file
(a flat base `config.json` without the `profiles` marker, or a
`profiles/<name>/config.json`), never on a bare directory alone.

### DNS authoring by `config migrate`

When the migrated config has no `dns` section, `config migrate`
may author the interim global section — but only in one shape:

- **Only** when every profile shares one outbound tag to detour
  through (a single profile, or all profiles referencing the
  same tag / inline non-direct outbound / endpoint tag).
- **Only** onto a config that is otherwise already migrated
  (the existing single file, ignoring `dns`, equals the
  migration result).

The authored section is the gated default (3) only:

```json
{"servers":[{"tag":"castctl-doh","type":"https","server":"1.1.1.1","server_port":443,"path":"/dns-query","detour":"<shared tag>"}],"final":"castctl-doh"}
```

DoH to 1.1.1.1, `https`, IP-literal (no bootstrap hostname),
detour = the shared outbound tag. No `tls` override is authored.
Its live behaviour (SNI/`server_name` acceptance for the
IP-literal server) is [UNVERIFIED until live proof].

Otherwise no `dns` section is written and the result records
why in `dns_refusal` (JSON field; also shown by the command),
naming the profile: a direct-only profile has no outbound tag
to detour through — a fresh legacy migration is always
direct-only, so it always records a refusal and migrates
without a `dns` section. A tag that resolves to a direct
outbound (in `outbounds`, `endpoints`, or an inline profile
outbound) counts the same way: naming it as a detour would
write a config sing-box refuses at runtime, so it records a
refusal instead. The migration itself still succeeds.
A differing single config still refuses to overwrite, with no
authoring attempted. An existing `dns` section is never
authored over: it is handled by distribution below. Authoring
is validated with the
same checks a hand-written section faces; a validation failure
records a refusal instead of writing an invalid config.

### DNS distribution by `config migrate`

When the existing single config carries a top-level `dns`
section, `config migrate` distributes it into every profile's
own `dns` block and removes the top-level section in the same
atomic write (mode 0600, under the config lock). Dry-run by
default: the plan reports `dns_distributed` and writes
nothing; `--write` performs the distribution. No new
subcommand, flag, or config key: the surface stays
`config migrate [--write] [--from <dir>]`, and distribution
works through `--from` on the destination file like the rest
of migrate.

- **Only** onto a config that is otherwise already migrated
  (the existing single file, ignoring `dns`, equals the
  migration result): the distribution diff must be exactly
  the dns move. A pending legacy profile addition keeps the
  run at refuse-overwrite, with no distribution attempted.
- **Verbatim copy.** The whole top-level `dns` value is
  copied field-for-field into each profile: `servers`,
  `rules`, `final`, `reverse_mapping`, and all client
  options (`strategy`, `timeout`, cache options, `client_subnet`,
  …). Server tags, `final`, and rule `server` references are
  scoped per block, so identical tags in every profile do
  not collide and no renaming is needed. `wireguard_dns`
  and `log` are untouched.
- **Detour mapping, per profile** (sing-box tag refs: a
  server's `detour` names an outbound/endpoint tag). Every
  distributed dialer-carrying server carries an explicit
  `detour`; an omitted detour would dial directly, outside
  the profile's outbound, never through it:
  - empty/missing detour → filled with the profile's own
    detour tag: its outbound tag, its inline outbound tag
    (`profile:<name>`), or the synthesised
    `castctl-direct:<profile>` tag for a direct profile;
  - detour equal to the profile's own tag → kept verbatim;
  - detour reachable from the profile's outbound (through
    detour chains and selector/urltest members) but
    different from the own tag → kept verbatim; rewriting
    it would silently reroute DNS onto another tunnel;
  - any other detour → the whole run refuses (below).
  `hosts`/`fakeip` servers carry no detour field and are
  copied untouched; a per-profile block cannot express a
  detour-less server (G2), so a section containing one
  refuses distribution (below) rather than distributing a
  block the loader rejects.
- **Removal.** The top-level `dns` key is removed in the
  same write. Keeping it alongside any per-profile block
  would make the file unparseable (G1, exit 2 on every
  load), so copy-without-removal is not an end state. The
  pre-distribution file survives only in the operator's
  backup: no `.bak` is kept for `config.json`, as with all
  migrate writes. After distribution the compat warning no
  longer fires when a runtime is built for that file,
  because no top-level section remains.
- **Refusals (all-or-nothing, exit 2, nothing written).**
  The result records the reason in
  `dns_distribution_refusal`, naming the profile and the
  field/tag (never values from the dns block):
  - a profile already has its own `dns` block (in practice
    this state cannot be loaded at all: top-level + any
    per-profile block is a G1 parse error, exit 2, before
    migrate runs);
  - a profile resolves WireGuard DNS through its tunnel
    (`wireguard_dns` state): an own block would outrank
    WireGuard DNS and shadow it, so distribution refuses
    instead of silently changing the effective resolver;
  - a server detour is unreachable from its profile's
    outbound (never silently rewritten to the own tag);
  - no profile would receive a distributed block: the file
    carries a top-level `dns` section but has zero profiles
    with a `profiles` key present (an empty `profiles: {}`),
    so distribution would delete the section without
    distributing it; the run refuses instead of silently
    deleting it. A file with no `profiles` key at all never
    reaches distribution: a single-format base file is
    refused by the fresh-migration guard above, and a
    genuine legacy file migrates as a legacy file;
  - the distributed candidate fails validation (duplicate
    server tags, a `final` naming no server, a `hosts` or
    `fakeip` server, or a WireGuard key-sharing failure):
    the candidate is validated exactly as a hand-written
    file before any write. An empty section (`{}`) refuses
    via an explicit guard before distribution, not via
    this validation step.
- **Idempotent.** A second run on a distributed file
  reports `already-migrated`, writes nothing, and leaves
  the file byte-identical. A config with no top-level
  section is a no-op for distribution.

Live traversal of a distributed block (a real lookup through
each profile's outbound) is [UNVERIFIED-LIVE: sandbox blocks
raw TCP]; fake-upstream tests prove the detour mechanism
only (see [Per-profile DNS](#per-profile-dns)).

## Default precedence (implemented model)

The gated model is implemented as described in
[Per-profile DNS](#per-profile-dns): own block, then
WireGuard DNS (from `wireguard_dns` state), then the top-level section (compat
fallback, one cycle, with warning), then the synthesised DoH
default to 1.1.1.1 (`https`, IP-literal, no bootstrap) with
detour = the profile's outbound (for direct profiles, the
synthesised `castctl-direct:<profile>` outbound — see the
synthesis mechanism in [Per-profile DNS](#per-profile-dns)).
Synthesised defaults are runtime-only and are never written
into the config file.

`local` is **never** the default: it is explicit-only. A
`local` server queries the system resolver — [UNVERIFIED until
live proof: on systemd-resolved hosts that may bypass the
tunnel via D-Bus unless the resolver is reached through the
detour, and live traversal of `local`+detour is unproven].
The model documents `prefer_go=false` for `local` servers
(the Go resolver path stays off). Until live proof exists,
prefer an explicit `https`/`tls` server with a detour over
`local`. Live proof of DoH-via-detour on the real migrated
config is a post-merge step (see [Per-profile DNS](#per-profile-dns));
fake-upstream tests do not claim it.
