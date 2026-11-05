# Porting notes — Rust M1 (pure-logic workspace)

Scope: four pure-logic crates under `rust/`, ported 1:1 from Go at
`origin/main` `13966975d116d54ae090464d7005e04b86e223ab` (merge PR #59).
No Go code was changed. Decisions D-edition, D-deps, D-json, D-chain,
D-redact, D-url, D5, D6, D8, D9, D-split0, D-safe, D-extra-tests and
D-scope-note from `~/workspace/plans/active/castctl-rust-m1.md` were
applied as written; where a decision proved unworkable the evidence is
recorded in §6 instead of silently substituting another choice.

Toolchain (measured on cue, the only authoritative host):
`rustc 1.97.1 (8bab26f4f 2026-07-14)`, `cargo 1.97.1`, edition 2024,
`resolver = "2"`. Sole dependency: `regex = "=1.13.1"` (exact pin,
measured from the cue-built `Cargo.lock`; reason: Go's `regexp` is RE2
and the Rust `regex` crate is its analogue — every in-scope pattern
uses only constructs both support). No serde, no `url` crate, no
network crates. `rust/Cargo.lock` is committed. No `unsafe` anywhere.
No `unwrap()`/`expect()` on external input; the only `expect` calls
guard static regex initialisation (naming the pattern) and internal
scanner invariants, never caller data.

## 1. Crate map

| Crate | Go source | Contents |
|---|---|---|
| `castctl-tg-text` | `internal/telegram/text.go` (266 lines) | Message text/HTML/splitting |
| `castctl-tg-files` | `internal/telegram/files.go` (pure part) | File kinds, doc names |
| `castctl-shared` | `internal/shared/resources.go`, `values.go`, `firstStringPtr` (`event.go:64`) | Event resources, JSON values |
| `castctl-log-redact` | `internal/logging/safe.go`, `internal/redact/*`, `internal/telegram/bot.go:740–1193` | Log scrubbing, error classification |

## 2. API mapping

Constructors/accessors with no Go function counterpart (for
example `ChainLevel::plain`, `ChainLevel::leaf`,
`ErrorChain::plain`, `ErrorClass::label`, `Resource::new`) cite
their Go type/vocabulary source — the struct definition, the
chain-model region, or the label vocabulary they model — and
their doc comments state explicitly that there is no direct Go
function counterpart and the item is a Rust-side
constructor/accessor. No Go function line is fabricated for
such items.

### 2.1 `castctl-tg-text`

| Go (`text.go`) | Rust | Notes |
|---|---|---|
| `ChunkSize = 3800` (`:26`) | `CHUNK_SIZE: usize = 3800` | |
| `TextLimit = 4096` (`:30`) | `TEXT_LIMIT: usize = 4096` | |
| `CaptionLimit = 1024` (`:34`) | `CAPTION_LIMIT: usize = 1024` | |
| `EscapeText` (`:38`) | `escape_text` (pub) | Only `&<>`, single pass |
| `MDToHTML` (`:62`) | `md_to_html` (pub) | Fence loop, lang via `escape_text` |
| `inlineHTML` (`:88`) | `inline_html` (pub(crate)) | Stash code/links, bold, headings |
| `applyBold` (`:117`) | `apply_bold` (pub(crate)) | Manual scan, first closing wins |
| `StripTags` (`:151`) | `strip_tags` (pub) | Tags removed first, then unescape |
| `SplitText` (`:163`) | `split_text` (pub) | |
| `splitTextLimit` (`:167`) | `split_text_limit` (pub(crate)) | See §4, cut-at-zero guard |
| `longestCodeBlock` (`:241`) | `longest_code_block` (pub) | Complete pairs only, body untrimmed |
| `needsDocument` (`:254`) | `needs_document` (pub) | Strict `>` on both bounds |
| `ButtonText` (`:260`) | `button_text` (pub) | First 64 chars |
| `html.UnescapeString` (stdlib) | `unescape` module (private) | Full HTML5 table, see §5 |

Go regexes are ported verbatim with two systematic rewrites: Go RE2
`\d`/`\s` are ASCII-only, spelled `[\t\n\f\r]` / `[0-9]` in Rust
(Rust `regex` is Unicode-aware by default); Go `\b` is ASCII-only,
spelled `(?-u:\b)` — see §6, where the golden comparison caught the
first draft using a Unicode `\b`.

### 2.2 `castctl-tg-files`

| Go (`files.go`) | Rust | Notes |
|---|---|---|
| `UploadLimit = 49<<20` (`:36`) | `UPLOAD_LIMIT: i64` | |
| `PhotoLimit = 10<<20` (`:41`) | `PHOTO_LIMIT: i64` | |
| `FileKind` (`:51–61`) | `FileKind` enum {Document, Photo, Video, Audio} | `Display`/`as_str` = Go strings |
| `FileKindFor` | `file_kind_for(name, mime, size: i64)` | `i64`, negative = unknown size |
| `fileExtension` (unexported) | `file_extension` (pub) | D8: lowercases internally, see §4 |
| `docName` | `doc_name(stem, text)` | Sanitize runs, cap 40 chars |
| `strings.ToLower` | `go_lower` (private) | First char of `char::to_lowercase` per rune (simple folding: `İ`→`i`, no final sigma) |

### 2.3 `castctl-shared`

| Go | Rust | Notes |
|---|---|---|
| `Resource` struct | `Resource` (field order preserved) | `kind` is a plain `String` (`"cla"`, `""` possible) |
| `FileRow` struct | `FileRow` | `seq`/`message_id` serialise as `null` when absent; `mime`/`byte_len`/`label`/`variants` honour `omitempty` (`Some("")` IS emitted) |
| `EventResources` | `event_resources` | Sorted keys via `BTreeMap` (D9); kind = key minus ALL trailing `s` |
| `FileRows` | `file_rows` | |
| `LocalName` | `local_name` | Go `path.Base` + `filepath.Join`/`Clean` emulation |
| `values.go` helpers | `value.rs` (`pub(crate)`) | `as_int64`, `truthy`, `payload_of`, field accessors; no invented values table (D5) |
| `encoding/json` for `FileRow` | `file_row_to_json` (hand-rolled, D-json) | Field order, `omitempty`, HTML-escaping, float format; see §4 |

`JsonValue` has no `UInt` variant: `uint64 > i64::MAX` fixture values
are unmodelled (Go `asInt64` returns false for them; documented gap,
no test pins one).

### 2.4 `castctl-log-redact`

| Go | Rust | Notes |
|---|---|---|
| `SafeString` (`safe.go:883–906`) | `safe_string` | 12 passes, in order; see §3 |
| `SafeHost` | `safe_host` | Host-shaped or `"[redacted]"` |
| `SafeErr` (`safe.go:1028`) | `safe_err_text(Option<&str>)` | `None` → `""` (preserves Go nil; R2's `&str` proposal dropped the case) |
| `redact.String` (`string.go`) | `redact_string` | 7 steps, split markers (`<redacted>` userinfo, `[redacted]` others) |
| `redact.RedactURLUserinfo` | `redact_url_userinfo` | Greedy to last `@` |
| `redact.IsSecretKey` (`value.go:93`) | `is_secret_key` | Exact-after-lowercase, 43 keys |
| `redact.Marker` (`value.go:16`) / `"[redacted]"` literal (`string.go`) | `MARKER` / `REDACTED` | No `Redacted` symbol exists in Go |
| `summarize` (`bot.go:740`) / `summarizeClass` (`bot.go:1092`) / `formatSummary` (`bot.go:750`) | `summarize`, `summarize_class`, `format_summary` | String-only path; decode prefix `telegram poll error:` |
| `fallbackClass` (`bot.go:1015`) | `fallback_class` | Never matches decode phrases (load-bearing split) |
| `anchoredDecodeClass` (`bot.go:907`) | `anchored_decode_class` | `HasPrefix` only |
| `httpClassFromPrefix` (`bot.go:925`) | `http_class_from_prefix` | 3 ASCII digits at the anchored position, checked on bytes |
| `isTLSFailure` (`bot.go:999`) | `is_tls_failure_text` | Lowercased first 256 runes |
| `classifyError` (7 steps, `bot.go:817`) | `classify_error` + `ErrorChain`/`ChainLevel`/`LevelKind` | Tree model, depth cap 32 on anchored passes only |
| `scrub` (`bot.go:1125`) / `scrubErr` (`bot.go:1156`) | `scrub_text`, `scrub_chain` | New owned chain; transport/context kinds dropped; scrub keeps the first TMR/Migrate match in pre-order DFS |
| `ErrorClass` (20 labels) | `ErrorClass` (20 variants) | Exact `Display` labels |
| `net/url` slice for `redactParsedURL` | `url.rs` (private) | Hand-rolled (D-url); see §4 |

Excluded from the port (Go-only, by construction): `redact.Value`
(reflection over structured values), `WrapErr`/`redactedError`,
`SummarizeErr`/`SafeErrForLevel` (trait + sing-box levels),
`SaveRow`/`downloadRef`, `truncateToRunes` (`bot.go:1495`, belongs to
a later Bot milestone).

## 3. `SafeString`: the 12 passes

In order (`safe.go:883–906`): (1) URL → `redactURLAllQuery`;
(2) pct-query → `label=[redacted]`; (3) `normalizePctLabels`;
(4) `redact.String`; (5) `redactJSONSecrets`; (6) key-colon +
`redactColonSecretMatch` (public-key labels keep an 8-char prefix);
(7) public-key pattern + `wgKeyPrefix`; (8) key-value +
`redactKeyValueMatch`; (9) `Authorization: Basic`;
(10) bare `Basic` + digit gate; (11) bare fragment;
(12) `peer(ABCD…WXYZ)`. Empty input → empty. Idempotent.

Vocabularies are verbatim: 28-alt `secretKeyVocab`, 32-alt
`secretLabelVocab`, 30-alt inline list for `reKeyValue` (omits the two
public-key spellings), 43 exact keys for `is_secret_key`. The
separator class is exactly `[\t\n\v\f\r \u00A0\u2003]` (TAB LF VT FF
CR SPACE NBSP EM SPACE); other Unicode spaces are NOT covered.
`SafeString` is a backstop only: bare secrets with no label are NOT
stripped; callers exclude them by construction. `summarize` output
contains only fixed vocabulary plus a rune count — never raw server
text, and no preview/snippet variant exists.

## 4. Deliberate differences and preserved quirks

- **D8** — Rust `file_extension` lowercases its input internally
  (Go helper relies on the caller lowercasing; `files.go:77,97–101`).
  `file_extension("PIC.PNG") == ".png"`.
- **D-split0 + cut-at-zero guard** — `split_text_limit(limit == 0)`
  returns the whole text as one piece; Go loops forever (observed:
  the Go probe hung 56 s on `splitTextLimit("a b c d e f g h", 1)`
  and was terminated). For limits 1–2 the Rust cutter forces a hard
  cut when the break search lands at 0 ONLY if the remainder does
  not start with `'\n'` (Round 1 fix F2): the guard fires iff that
  cut-0 iteration would repeat the same remainder — with `cut == 0`
  Go's next remainder is `lstripNewlines(r)`, identity iff the
  remainder does not start with `'\n'`. A `'\n'`-led remainder
  therefore progresses on that iteration only (the strip removes
  at least one `'\n'`); it does not guarantee overall termination,
  because the strip can expose a space-led remainder that then
  loops — Go hangs on `"\n ABCDEF"` / `"\n AB"` at limit 2, and
  the port terminates those with hard-cut pieces (documented
  deviation class, no terminating Go trace to match). On
  terminating `'\n'`-led traces the port reproduces Go exactly
  (`split_text_limit("\nABCDEF", 2) == ["", "AB", "CD", "EF"]`).
  No Go case pins either behaviour.
- **Chain traversal contracts (Round 1 fixes F3a/F3b)** — the
  URL-inner TLS step of `transport_class` checks ONLY the first
  `*url.Error` level in pre-order DFS (Go `errors.As` in
  `transportClass`, `bot.go:956`); deeper `UrlError` levels are
  never consulted. The `scrub_chain` TMR/Migrate preservation
  scans walk in pre-order DFS and keep the FIRST match (Go
  `errors.As` in `scrubErr`, `bot.go:1156`), not the last.
  Step-1/3/4 existence scans and `chain_prefix_class` DFS order
  are unchanged (order-insensitive / verified matching Go).
- **Pct-label lossy conversion (Round 1 finding F4, documented
  difference, no behaviour change)** — `normalize_pct_labels`
  EMITS the decoded label form (it is not match-only): when the
  decoded label bytes are invalid UTF-8, Rust emits U+FFFD where
  Go emits the raw bytes (e.g. `token%C3%28=` → Go keeps byte
  `0xC3`, Rust emits U+FFFD). No invariant leak: the value
  survives unredacted in both implementations (the malformed
  label breaks the key=value pattern in both), and both are
  idempotent on probed inputs. The pinned ASCII `%XX` corpus is
  unaffected.
- **D-safe** — `SafeString` is 12 passes (not 11); no 400-byte code
  cap (400 is a test assertion only); `summarize_class` does NOT
  lowercase (quirk preserved).
- **D9** — JSON object model uses `BTreeMap`/explicit sorted keys;
  `HashMap` iteration is forbidden for `EventResources` visit order.
- **Float formatting** — `file_row_to_json` reproduces Go
  `encoding/json` floats (scientific when `|f| < 1e-6` or
  `|f| >= 1e21`, exponent sign always shown, leading zero stripped:
  `1e+21`, `1e-7`). Non-finite floats serialise as `null` (Go would
  error) — documented gap, unpinned by any test.
- **`as_int64` float wrap** — out-of-range floats map to
  `Some(i64::MIN)`, matching Go amd64 `int64(f)` conversion
  (probe P-6: `1e100`/`-1e100` → `MIN`; NaN/±Inf → `None`).
- **`truthy` NaN quirk** — NaN is truthy (via the `as_int64` path:
  `truthy` falls back to `as_int64`, and NaN fails that check the
  same way Go's does — preserved, probe P-6).
- **URL approximations** — hand-rolled IPv6 validation (Go delegates
  to `net.ParseIP`); host serialisation escapes only non-ASCII bytes
  (Go's `encodeHost` table is wider, but every probed host shape
  round-trips identically); userinfo content is validated but
  discarded. `RawPath` semantics, `ForceQuery`, fragment
  presence/non-emptiness, and Go's `validEncoded` allow-list
  (sub-delims + `:`/`@` + `[`/`]`) are reproduced exactly, including
  the idempotence retry (`[redacted]`/`<redacted>` → `REDACTED0`).
- **Sentinel texts** — go-telegram sentinel `Display` texts are not
  in the repo; chain leaves for sentinels carry `""` text and
  classification uses identity only. The typed `Error()` renderings
  (`"M: retry_after 5"`, `"M: migrate_to_chat_id 42"`) are
  reproduced from G1 measurements as root texts in tests.
- **`NetTimeout` merge** — `net.Error` timeout and
  `os.ErrDeadlineExceeded` share one kind (behaviourally identical
  for classification; documented).
- **`safe_err_text` shape** — `Option<&str>` instead of R2's `&str`,
  preserving Go's nil → `""` case.
- **Scrub guard** — `scrub_text` with an empty token returns the
  input unchanged (Rust `str::replace` with an empty pattern would
  insert at every boundary; Go's `scrub` guards it). Labelled probe
  test, not a ported case.

## 5. Entity-table provenance

`castctl-tg-text/src/entities.rs` (2,285 lines: 2,138 single-char +
91 double-char entities + 32 Windows-1252 replacements) was
mechanically extracted from the Go standard library sources on cue
(`/usr/local/go/src/html/entity.go`, `entity`/`entity2` tables, and
the replacement table in `/usr/local/go/src/html/escape.go`), which
are BSD-licensed Go stdlib tables. The extraction was verified by
re-reading the generated file against the Go tables and by the
`probe_unescape_corpus` test, which covers the full measured corpus
(longest-prefix fallback, no-semicolon legacy forms, surrogate /
out-of-range / zero → U+FFFD, 32-bit wrapping accumulation, no
surrogate-pair combining). Invisible characters in the table
(U+200B, U+2060, U+00AD) are spelled as `\u{...}` escapes (clippy
`invisible_characters`).

## 6. Differential probes and golden comparison

Probes R1 §6 (P-1–P-10) and R2 §7 ran on cue against Go at
`1396697` (scratch clone `/tmp/probe-repo`, throwaway test files in
`/tmp` only, never in the repo tree). Findings that changed the
port, all re-verified after the fix:

1. **ASCII `\b` (golden round 3)** — the first draft used Rust's
   Unicode `\b` for the six `\b` patterns. The golden comparison
   showed `ésession=VAL` unredacted in Rust while Go redacts it:
   Go RE2 `\b` is ASCII-only (boundary between non-ASCII `é` and
   `s`), so the fix spells `(?-u:\b)` in `reKeyColon`,
   `reKeyValue`, `rePublicKey`, `reBareBasic`, `reCookieToken`,
   `reBareBearer`, keeping `(?i)` Unicode. The earlier "Unicode
   `\b`" reading of probe round 2 was wrong about the mechanism;
   the golden corpus now pins both directions (`ésession=`,
   `ÉSESSION=`, `éBearer`, `éprivate_key:` redact;
   `xsession=`, `1session=`, `_session=`, `xBearer` do not).
2. **RawPath / `validEncoded` (golden round 3)** — the first draft
   rejected `[`, `!`, `'`, `(`, `)`, `*` in the raw-path validity
   check and re-escaped them. Go `setPath`/`EscapedPath` keep the
   raw path verbatim when `validEncoded` (sub-delims + `:`/`@` +
   `[`/`]` always fine) and the unescape-equality hold. Fixed in
   `url.rs`; verified against Go's `encoding_table.go` and
   `validEncoded`/`setPath`/`EscapedPath` sources on cue.
3. **Chain depth cap (Go probe `TestZZChainCap`, PASS)** — Go
   confirms: anchored decode/HTTP passes inspect depths 0–32 only
   (a decode marker at depth 33 → unclassified, at 32 → decode);
   step-1 sentinel search is uncapped (sentinel at depth 40 wins);
   `EHOSTDOWN`/`ENETDOWN` → unreachable; non-4/5 first HTTP digit
   and short-rest HTTP → unclassified. The Rust probe tests pin
   the same behaviour.
4. **Go `splitTextLimit` non-termination** — see §4.
5. **Unicode/case** — Go `unicode.IsSpace` = Rust
   `char::is_whitespace` exactly; `strings.ToLower` = simple
   per-rune folding (reproduced by `go_lower`).

### 6.4 Round 1 fix loop: review findings and their fixes

Round 1 reviews (technical / safety / red-team) found three
blocking parity breaks, fixed in the fix loop with RED-then-GREEN
regression tests (labelled `regression_*`, outside the ported-case
counts in §7):

6. **F1 — multibyte HTTP code window** — `http_class_from_prefix`
   sliced `&rest[i+2..i+5]` and panicked mid-char; Go checks bytes.
   Fixed to byte-level digit checks (no `&str` slicing); regression
   tests pin the three multibyte inputs to `None` plus ASCII
   neighbours (500→`http 5xx`, 422→`http 4xx`, 302/5/`5é0`→`None`).
7. **F2 — cut-at-zero guard scope** — the guard fired on every
   cut == 0, falsifying Go's terminating `\n`-led traces at limit 2.
   Fixed to the conditioned guard (see §4); regression tests pin
   `"\nABC"`/`"\nABCDEF"` at limit 2, the limit-0 guard, and the
   space-led deviation.
8. **F3a/F3b — chain traversal discipline** — `transport_class`
   scanned every `UrlError` level (Go: first only); `scrub_chain`
   kept the LAST TMR/Migrate match (Go `errors.As`: first, in
   pre-order DFS). Both fixed; regression tests pin the
   hiding-wrapper chain (unclassified) and the two-TMR / two-Migrate
   first-match preservation. See §4 for the traversal contracts.
9. **F4 — pct-label lossy conversion** — documented difference, no
   behaviour change; see §4. `normalize_pct_labels` EMITS the
   decoded label form: invalid-UTF-8 decoded bytes become U+FFFD
   in Rust where Go emits the raw bytes.
10. **F5 — `Debug` hardening** — `ChainLevel`/`LevelKind` now have
    hand-written `Debug` impls that print only rune lengths for
    text/message fields, never raw text; a regression test asserts
    an unscrubbed chain's `Debug` output is token-free.
11. **S1/S3/C1 (docs/hygiene)** — Go `file:line` citations in
    `castctl-log-redact` corrected (e.g. `string.go:59`,
    `redact.go:114`, `value.go:93`, `Marker` at `value.go:16`;
    `bot.go` line numbers added for every summarize/chain fn);
    doc comments added to the three public consts in
    `castctl-tg-text`; log-safety warnings added to the raw-text
    primitives `first_runes`/`scrub_text`. `split_text_limit` no
    longer casts limits through `isize` (safety S1): all cut
    arithmetic is `usize` with `Option`-absence instead of a -1
    sentinel; a regression test pins `limit == usize::MAX`.

**Round-3 golden comparison (final):** 137 corpus lines
(`SAFE` + `UNESC`, incl. marker URLs, DEL in URL, `[` in path,
`!()*'` in path, `%25` zone IPv6, `%FF` bytes, JSON-scanner edges,
vocab boundaries, pct labels, and the full HTML-entity edge corpus
incl. `&#x100000041;` overflow) — Go output vs Rust output
byte-identical, `diff` empty (0 lines). No remaining divergences on
the probed corpus. Exotic unpinned edges stay as documented
approximations in §4, never silent behaviour changes.

## 7. Test mapping

Counts are Rust test functions / Go test functions; case counts are
table entries. Probe tests are labelled `probe_*`, live outside the
ported-case count, and are listed separately. Fix-loop regression
tests are labelled `regression_*` and likewise live outside the
ported-case counts (see §6.4): 2 in `castctl-tg-text` (F2, S1) and
5 in `castctl-log-redact` (F1 ×2, F3a, F3b, F5).

### 7.1 `castctl-tg-text` — 7 Go fns → 7 Rust fns, 20 assertions

| Go test | Rust test | Cases |
|---|---|---|
| `TestSplitText` | `test_split_text` | 4 |
| `TestSplitTextSmallLimit` | `test_split_text_small_limit` | 1 |
| `TestSplitTextFenceCarry` | `test_split_text_fence_carry` | 3 |
| `TestMDToHTML` | `test_md_to_html` | 4 (4th kept weak: unclosed fence asserts only `Contains "```go"`) |
| `TestStripTags` | `test_strip_tags` | 2 |
| `TestButtonText` | `test_button_text` | 2 |
| `TestNeedsDocument` | `test_needs_document` | 4 |

0 direct cases, ported with an explicit note (D6): `escape_text`,
`inline_html`, `apply_bold`, `longest_code_block` (covered only
indirectly, via `md_to_html`/`strip_tags`/`needs_document`).
Probe (not ported): `probe_unescape_corpus` (full entity corpus).

### 7.2 `castctl-tg-files` — 2 Go fns → 2 Rust fns, 50 cases

| Go test | Rust test | Cases |
|---|---|---|
| `TestFileKindFor` | `test_file_kind_for` | 37 |
| `TestDocName` | `test_doc_name` | 13 |

Excluded, Go-only (needs `Bot` + fake Telegram HTTP server +
retry/fallback; reason written in the test file): the 8
`TestSendFile*` API functions.

### 7.3 `castctl-shared` — 6 Go fns → 6 Rust fns

| Go test | Rust test | Cases |
|---|---|---|
| `TestEventResourcesVideosAndLinksDedupe` | `test_event_resources_videos_and_links_dedupe` | 1 |
| `TestEventResourcesNoFiles` | `test_event_resources_no_files` | 1 |
| `TestEventResourcesRules` | `test_event_resources_rules` | 13 (full `PartialEq`) |
| `TestFileRows` | `test_file_rows` | 1 |
| `TestFileRowJSONOrder` | `test_file_row_json_order` | 1 exact string |
| `TestLocalName` | `test_local_name` | 6 (basename-only assertion, matching Go's strength) |

Excluded, Go-only: the 4 `TestSaveResources*` functions (fake
Downloader + temp dirs + connection errors). No invented `values`
table (D5); `int_field`, `bool_ptr_field`, `first_string` have 0
cases and are covered only via the resource tests (noted with
`#[allow(dead_code)]` + reason).
Probe (not ported): `probe_json_float_format` (float-format and
string-escaping goldens for the hand-rolled serializer).

### 7.4 `castctl-log-redact`

Safe/string tests — 21 Go fns in `safe_test.go` → 21 Rust fns, plus
the portable allowlist fn:

| Go test | Rust test |
|---|---|
| `TestSafeStringWSURL` … `TestSafeStringLoop7NewlineJSONValue` (21 fns) | Same names, `test_safe_string_*` (21 fns) |
| `TestSafeStringListedVocabulary` (`allowlist_test.go`, 45 cases) | `test_safe_string_listed_vocabulary` |

Redact tests:

| Go test | Rust test | Cases |
|---|---|---|
| `TestString` (`string_test.go`) | `test_string` | 21 + per-case idempotence |
| `TestRedactURLUserinfo` (`redact_test.go`) | `test_redact_url_userinfo` | 24 (source file has 24, not the 25 estimated in R2) |
| `TestIsSecretKey` (`value_test.go`) | `test_is_secret_key` | 43 true keys + 29 case/exactness (13 true + 16 false) |

Summarize/chain tests — 7 Go fns → 7 Rust fns, 60 inputs:

| Go test | Rust test | Inputs |
|---|---|---|
| `TestSummarizeNeverEmitsServerText` | `test_summarize_never_emits_server_text` | 5 |
| `TestSummarizeHostileBodyBoundedWork` | `test_summarize_hostile_body_bounded_work` | 1 (5 MB, <10 s) |
| `TestSummarizeErrorClasses` | `test_summarize_error_classes` | 44 (G1-measured texts) |
| `TestSummarizeErrorHostileDescriptionNotDecode` | `test_summarize_error_hostile_description_not_decode` | 2 (H1/H2) |
| `TestSummarizeErrorHugeInputBounded` | `test_summarize_error_huge_input_bounded` | 2 |
| `TestSummarizeUnclassifiedFallback` | `test_summarize_unclassified_fallback` | 2 exact strings |
| `TestSummarizeLoop4NoMethodField` | `test_summarize_loop4_no_method_field` | 4 |

Plus the first 3 subcases of
`TestBotScrubbedErrorTokenFreeAtObjectLevel`
(`test_scrubbed_error_token_free_at_object_level`; TMR / sentinel /
Migrate). Chain probes (not ported): depth cap 32/33, step-order
synthetics, anchored DFS order, unpinned branches (`EHOSTDOWN`/
`ENETDOWN`, non-4/5 digit, short rest), empty-token scrub guard.
URL probes (not ported): `probe_url_parse_serialize`,
`probe_query_escape_tables`.

Excluded, Go-only (reason written in the test file / here):
`TestSafeErrForLevelTraceIsSummary` (sing-box log levels +
`SafeErrForLevel`); the `TestValue*` family (reflection-based
`redact.Value`); `WrapErr`/`SummarizeErr`/`SafeErrForLevel`;
the fake-server `Send` subcase of the scrubbed-error test and its
`isParseError` assertion; the hostile-body/log-output tests
(`TestBotHostileBodyNotLogged`, `TestBotHostileDescriptionNotLogged`,
`TestBotHostileDecodeUpdateNotLogged`, the `EditPlain`/handler/
method-injection log tests — need the bot runtime + fake server).

Fixture tokens: Rust tests use a different invented 32-char
placeholder (`RUSTFIX-TOKEN-PLACEHOLDER-012345`) at the same length
as the Go fixture, so G1-measured rune counts reproduce. The Go
fixture value is never printed in reports or outputs.

## 8. Verification (on cue, rustc/cargo 1.97.1)

```console
$ rustc --version && cargo --version
rustc 1.97.1 (8bab26f4f 2026-07-14)
cargo 1.97.1 (c980f4866 2026-06-30)
$ cargo build --workspace
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 4.24s
BUILD_EXIT=0
$ cargo test --workspace
test result: ok. 46 passed; 0 failed  (castctl-log-redact)
test result: ok. 7 passed; 0 failed   (castctl-shared)
test result: ok. 2 passed; 0 failed   (castctl-tg-files)
test result: ok. 10 passed; 0 failed   (castctl-tg-text)
TEST_EXIT=0
$ cargo clippy --workspace -- -D warnings
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 3.08s
CLIPPY_EXIT=0
$ cargo fmt --check
FMT_EXIT=0
```

`cargo clippy --workspace --all-targets -- -D warnings` is also
clean. `git diff --stat` shows only additions under `rust/`; the Go
tree is untouched (verified before commit). The `dev-rust` branch
was verified on origin at `13966975d116d54ae090464d7005e04b86e223ab`
before this work branched from it.

---

# Porting notes — Rust M2 (config + CLI surface)

Scope: two new crates (`castctl-config`, `castctl-cli`) plus the
`castctl-rs` binary and the `rust/parity/` golden harness, ported
from Go at `dev-rust` `85a8d5eaa529237d38de1192d992261ed1db7557`
(branch `feat/rust-m2-config-cli`, local only, never pushed). No Go
code was changed. Parent decisions D-M2-1..D-M2-7 (plan file
`~/workspace/plans/active/castctl-rust-m2.md`) were applied as
written; §5 records the places where Go's own pre-handler order
differs from the generic stub-order statement, implemented
Go-faithfully and flagged, not silently substituted.

Toolchain (measured on cue, the only authoritative host):
`rustc 1.97.1 (8bab26f4f 2026-07-14)`, `cargo 1.97.1`,
`clippy 0.1.97`, `rustfmt 1.9.0-stable`, edition 2024,
`resolver = "2"`, `rust-version = "1.85"`. No new dependencies:
the workspace still has the sole M1 dep `regex = "=1.13.1"`. No
serde, no `url` crate, no network crates. `rust/Cargo.lock` is
committed (updated for the three new workspace members). No
`unsafe` anywhere in `src` (grep = 0; the only two `unsafe`
mentions are doc comments stating the rule). No `unwrap()` on
external input; the single non-test `expect` guards a
parser-internal invariant and carries an `INVARIANT:` comment
naming the loop that establishes it (`parser.rs`, `consumeLong`).

## M2.1 Crate map

| Crate | Go source | Contents |
|---|---|---|
| `castctl-config` | `internal/profile/{config,jsonvalue,configlocation,errors,telegram,profile,fingerprint,log,guard,dns,keeper,webui,plugins,credentials,wireguard,outbound}.go` | Single-config parse/validate/render, profile entries, config-location resolution, Go `filepath`/`strings`/`strconv`/`encoding/json` semantics |
| `castctl-cli` | `internal/commands/{commands,help,read,wait,deliver,chat,fs,keeper,telegram,update,webui,plugincheck,profilecmd,authimport,authlogin,authstatus,authobserve}.go`, `internal/deliver/authexport.go` (guidance const), `internal/logging/level.go` (summary identity) | Command table, flag parser, help/usage rendering, exit mapping, subcommand dispatchers, stub |
| `castctl-rs` (bin) | `cmd/castctl/main.go` | Wires only the offline surface; `args_os` + lossy conversion |
| `rust/parity/` (harness, not a crate) | — | `cases.json` (55 cases), `gen_golden.py`/`gen_golden.sh`, `fixtures/`, `golden/` (generated on cue, incl. `manifest.json`), `castctl-rs/tests/parity.rs` |

## M2.2 API mapping

Every public item has a doc comment citing its Go source
`file:line` at the M2 base. The mapping below is the crate-level
index; the doc comments are authoritative.

### `castctl-config`

| Go | Rust | Notes |
|---|---|---|
| `decodeOrderedJSON` / `decodeOrderedValue` / `orderedObject` / `rawOf` / `marshalScalar` / `encodeSingleConfig` (`jsonvalue.go`, `guard.go:283`) | `jsonvalue::{JsonValue, OrderedObject, decode_ordered_json, decode_ordered_object, encode_ordered_json, encode_ordered_json_indent, raw_of, encode_go_string}` | Token-state-machine decoder reproducing `encoding/json` `Decoder.Token` + scanner states; number literals preserved verbatim; indent-2 + exactly one trailing `\n` |
| `strings.TrimSpace` / `ToLower` / `strconv.Quote` / `QuoteRune` / `ParseInt` / `utf8.DecodeRune` | `gostr::{go_trim_space, go_lower, go_quote, go_quote_char, go_parse_int64, go_decode_rune}` | `quoteChar` is Go's `encoding/json` scanner form (`'"'` unescaped, `'\''` escaped), NOT `strconv.QuoteRune` — the corpus probe decided this |
| `filepath.Clean/Join/Dir/Base/IsAbs/Rel` | `gopath::{go_clean, go_join, go_dir, go_base, go_is_abs, go_rel, is_inside_dir}` | `go_rel` returns `None` on mixed absolute/relative (Go error value never surfaced by callers) |
| `Error` / `newConfigError` / `newInvalidProfileError` / `newLegacyLayoutError` / `ExitCode` (`errors.go`) | `errors::{ConfigError, config_error, config_errorf, invalid_profile_error, legacy_layout_error, refuse_error}` | `refuse_error` is migrate-only, unused in M2 |
| `os` error texts (`*PathError`) | `oserr::{is_not_exist, strerror, os_message, stat_error_text, open_error_text}` | `IsNotExist` = raw errno ENOENT (2) only, not ENOTDIR |
| `ValidateProfileName` / `ResolveProfileName` / `ProfilePaths` / `DiscoverProfileNames` / `Source` / `OutboundRef` / `parseProfileEntry` / `resolveCookiesFile` / `ensureInlineTag` / `parseAutoAllowOnceValue` (`profile.go`, `config.go:463,619,655,798`) | `profile::{validate_profile_name, resolve_profile_name, profile_paths, discover_profile_names, Source, OutboundKind, OutboundRef, Profile, parse_auto_allow_once_value, ensure_inline_tag, resolve_cookies_file, parse_profile_entry}` | `OutboundRef.Type` = raw `type` string if present, `From` empty (deferred tag graph); `" direct "` is a tag ref with spaces kept; inline auto-tag inserted right after `"type"` |
| `ValidLogLevel` / log block (`log.go`, `level.go`) | `log::{LOG_LEVELS, valid_log_level, LogConfig, parse_log_block, render_log_block}` | Level value never echoed |
| Telegram block + `validateTelegram` / `ResolveTelegram` (`telegram.go`) | `telegram::{TelegramConfig, valid_telegram_token_shape, parse_telegram_block, validate_telegram}` | Token shape `^[0-9]+:[A-Za-z0-9_-]{20,}$` ASCII-only on the stripped value; hand-written `Debug` impl prints `[redacted]` for the token, never the token itself |
| Keeper tag rule / plugin ID rule / keeper-webui-plugins-credentials shapes (`keeper.go:381`, `plugins.go`, `credentials.go`) | `blocks::{validate_keeper_tag, valid_plugin_id, validate_plugin_tag, validate_plugin_type, PluginEntry, CredentialEntry, PluginsBlock, CredentialsBlock, parse_wireguard_dns_map, check_keeper_shape, check_webui_shape, parse_plugins_block, parse_credentials_block, validate_plugins, validate_credentials, check_endpoint_wireguard_system}` | Credential username/password values are validated then DROPPED (secrets); plugin parse errors carry the DOUBLE `profile: ` prefix Go produces via `%v` (`plugins.go:176,185`); endpoint wireguard-`system:true` check is a raw-field approximation (only when `type=="wireguard"` string AND `system===true` bool) |
| Fingerprint/TLS sets (`fingerprint.go`) | `fingerprint::{DEFAULT_FINGERPRINT, DEFAULT_TLS_ENGINE, validate_fingerprint_value, validate_tls_engine_value}` | Exact sets only, no fold/trim |
| `ParseSingleConfig` / `buildSingleFileOrdered` / `buildProfileEntry` / `LoadSingleConfig` / `LoadProfile` / `ResolveActiveProfile` / `HasProfilesMarker` / `scanLegacyConfigFile` / `applyEnvFill` / `profileExists` (`config.go`) | `config::{SingleConfig, has_profiles_marker, parse_single_config, build_single_file_ordered, render_telegram_block, build_profile_entry, encode_single_config, load_single_config, scan_legacy_config_file, apply_env_fill, load_profile, profile_exists, resolve_active_profile}` | Tail checks run in Go order; deferred ones are skipped, never faked (see §M2.3) |
| `ResolveConfigLocation` / `RequirePresent` / `userConfigDir` / `configHomeDir` (`configlocation.go`) | `configlocation::{ConfigLocation, Getenv, resolve_config_location}` + `ConfigLocation::require_present` | Plan9 `userConfigDir` branch not reproduced (no Rust target); env via `var_os` + lossy; relative-XDG warning + fallback reproduce the DOUBLE `profile: ` prefix exactly |

### `castctl-cli`

| Go | Rust | Notes |
|---|---|---|
| `commandOrder` / `commandSpec` / `registerFlags` / `usageLine` | `table::{COMMAND_ORDER, CommandSpec, PositionalSpec, command_table, command_spec}` | The short `help` field is never printed and is not ported; session-op commands share one help text (not deduped) |
| `flagDef` / `intFlag` / `argParser` / `findLong` / `findShort` / `consumeLong` / `looksLikeNegativeNumber` / `setValue` / `checkPositionals` | `parser::{FlagKind, FlagDef, bool_flag, str_flag, int_flag, int_flag_no_def, Parsed, ParserError, ParseOutcome, ArgParser, check_positionals}` | Short flags index BYTES (Go `rest[0]`); `-h` in a bundle shows help immediately; help after `--` is not help |
| `scanGlobal` / `globalOpts` / `versionString` | `run::{GlobalOpts, VERSION, scan_global}` | `VERSION = "0.9.0"` (D-M2-7); prefix-branch order log-level → profile/config → help → version; `--vers`/`--hel` exact forms kept |
| `resolveConfig` | `run::resolve_config` | Warnings printed before basename/presence errors; `allowMissingCreate` only for migrate `--write`/`--from` |
| `parseOrHelp` / `profileParse` / `fsParse` / inline parsers / `usageErr` / `classifyError` (plain branch) / `errCode` / `errHelpShown` | `run::{parse_or_help, profile_parse, fs_parse, inline_parse, usage_err, run}` | 3-line / 2-line / 1-line stderr shapes per parser family, pinned by tests; `errCode(2, nil)` prints NOTHING extra |
| `cmdFS` / `fsDefs` / `fsPositionals` | `run::cmd_fs`, `table::{FS_SUBCOMMANDS, fs_defs, fs_positional_names}` | |
| `cmdAuth` / auth subcommand parsers | `run::cmd_auth`, `table::{auth_sub_defs, auth_sub_help}` | `auth export` prints `ExportGuidance` verbatim, exit 1, no config resolution, no positional check |
| `cmdProfile` / `profileParse` | `run::cmd_profile`, `table::{PROFILE_SUBCOMMANDS, profile_sub_defs, profile_sub_help}` | `rm --yes` refusal precedes config resolution |
| `cmdConfig` / `cmdConfigMigrate` | `run::cmd_config` | `--from` empty check precedes resolution; migrate execution dropped (D-M2-5) |
| `cmdTelegram` / `cmdTelegramRun` / `cmdTelegramStatus` | `run::cmd_telegram`, `table::TELEGRAM_SUBCOMMANDS` | Takes-no-args error is 1 line, `errCode(2, nil)` |
| `cmdKeeper` / `parseKeeperSelection` | `run::cmd_keeper`, `table::{KEEPER_SUBCOMMANDS, keeper_sub_help}` | Tag/profile mutual exclusion after positionals, before resolution |
| `cmdWebUI` / `cmdWebUIServe` | `run::cmd_webui` | Unknown subcommand appends full `webuiHelpText` (only dispatcher that does) |
| `cmdPlugin` / `cmdPluginCheck` / `pluginhost.ValidatePluginID` | `run::cmd_plugin` | No-arg prints help text ONLY on stderr; tag validated (`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`) before the stub; no config resolution |
| `approveDecision` / `parseAutoToggles` / `cmdAutoApprove` checks / `feed-react` manual check | `run::{approve_decision, parse_auto_toggles, check_spec_positionals}` | Check order preserved (positionals → decision/toggles → state/once) |
| `ExportGuidance` (`deliver/authexport.go`) | `run::EXPORT_GUIDANCE` | Verbatim const; printed + `\n` (Go `Fprintln` of the classify text) |
| Help texts (74 consts) | `help_texts` (generated) | Mechanically extracted from the Go sources by `/tmp/gen_help.py`; `updateHelpText` appended by the same mechanical extraction (the generator pass missed `update.go`); `telegramBotHelpText` is a Telegram bot message, NOT CLI help, and is correctly absent. `inviteHelpText` lacks `--raw` while the usage line has it — both kept verbatim |

## M2.3 Deferred (D-M2-1): raw-preserve + no sing-box validation

The blocks below are stored as raw compact JSON and re-rendered
verbatim. Sing-box option parsing/validation is NOT recreated (no
hand-written sing-box schema): an invalid sing-box config that Go
rejects at exit 2 parses "successfully" in Rust. Never claim full
parity for invalid sing-box configs. Deferred areas and the Go
tests that cover them:

| Deferred area | Go tests covering it (base `85a8d5e`) |
|---|---|
| Tag graph: duplicate/dangling/detour/selector/reserved-prefix checks, `validateTagGraph` | `internal/profile/config_test.go` (25 tests), `outbound_test.go` (3) |
| G1 coexistence is PARTIALLY implemented (top-level `dns` + per-profile `dns` refusal); the remaining G1 tag-shape cases | `config_test.go`, `dns_test.go` (21) |
| Profile DNS, WireGuard DNS, WireGuard private keys (`validateProfileDNS`, `validateWireGuardDNS`, `validateWireGuardPrivateKeys`) | `dns_test.go`, `wireguard_test.go` (7), `dns_distribute_test.go` |
| Sing-box outbound/endpoint/DNS option parsing (types, enums, unknown fields) | sing-box upstream option tests (external dep, not in this repo) + `outbound_test.go` |
| Keeper cross-checks (`validateKeeper`), credential refs (`validateCredentialRefs`), keeper/webui deep field validation | `keeper_test.go` (16), `credentials_test.go` (7), `webui_test.go` (13) |
| `rawProfiles` (migrate-clone-only in Go) | `migrate_test.go` (30) — Rust does not store it; render never uses it |
| `config migrate` execution (legacy parse, refuse-overwrite, node_id generation, DNS author/distribute, lock + atomic 0600 write) | `migrate_test.go` (30), `guard_test.go` (10) |
| Synthesised render for keeper/webui/plugins/credentials/outbounds/endpoints/dns (no-raw branches) | `config_test.go`, `guard_test.go` — without raw JSON those blocks are omitted; unreachable from the parse path, which always captures raw |

Implemented instead (fixed-message, string-field-only): array
shape for outbounds/endpoints; the wireguard-`system:true`
raw-field approximation; `wireguard_dns` full shape parse;
`log`/`telegram` full parse; keeper/webui array/object shape;
plugins tag/type presence+shape+dup; credentials required-keys
+shape+dup; `validateTelegram`, `validateCredentials`,
`validatePlugins` cross-checks; the G1 dns-coexistence refusal.

Deferred keeper/webui check groups (no implementation; listed
so the boundary is explicit): keeper — `parseKeeperBlock`
(full entry parse: tag/profile/duration/interval/retry/
relogin/observe fields and their defaults), `validateKeeper`
(cross-checks: entry profile existence, keeper tag/profile
refs, allowed-hosts, browser URL), `ResolveKeeper` /
`KeeperEntryForProfile` / `Effective*` defaults;
`validateKeeperBrowserURL` / `canonicalBrowserURL`; webui —
`parseWebUIBlock` (listen/session/token/rate-limit fields),
`validateWebUIListen`, `parseLoginRateLimitBlock`,
`ResolveWebUI` / `EffectiveListen` / `EffectiveSessionIdleTimeout`
/ `EffectiveLoginRateLimit`. Go tests: `keeper_test.go` (16),
`webui_test.go` (13).

## M2.4 Decisions D-M2-1..D-M2-7 (as applied)

- **D-M2-1** raw-preserve + deferred sing-box validation (§M2.3).
  P-1 decoder messages: verbatim for the whole probed corpus
  (§M2.6); no unmapped message was encountered, so no
  `[DEVIATION]` label was needed; messages outside the probed
  corpus are approximations (§M2.5).
- **D-M2-2 / D19** — the synthesised telegram render drops
  `owner_id` EXACTLY like Go (`config.go:1411-1421`): regression
  test `test_telegram_d19_synthesized_render_drops_owner_id`
  (hand-built config renders without it; parsed-from-file config
  keeps it via raw). Do not fix the bug.
- **D-M2-3** — stub order: global scan → parse → positional
  checks → config-location resolution (basename/presence/
  directory, warnings, exit 2) → config-file parse
  (`LoadSingleConfig`, exit 2 on a bad config; fix-loop F5,
  mirroring Go `resolveActive`/`runWithProfile`) → stub
  (exit 1, one fixed stderr line `castctl: not ported yet in
  the Rust port`, empty stdout, no argv echo) → BEFORE
  active-profile resolution. The stub wording is Rust-only by
  argument in the PR body: the command exists in Go and is
  unported here, never "not implemented in the Go port" (Go's
  deferred-table wording).
- **D-M2-4** — 55 cases: 46 × `<cmd> --help` in `commandOrder` +
  9 (`--version`, `--help`, `bogus`, `redeem`, `goal`, `seen`,
  `--log-level xyz`, `--config /nonexistent`, and the fix-loop
  F5 case `status` with a bad-JSON config). The parity test
  asserts golden count == argv-list length. The missing-
  positional trio is redeem/goal/seen (send behaves the same
  shape and is covered by unit tests, not golden).
- **D-M2-5** — `config migrate` execution DROPPED. Kept:
  `config --help`, `config migrate --help`, dispatcher usage
  errors, parse + positional + `--from` checks, resolution with
  `allowMissingCreate`; parse-successful migrate → stub.
- **D-M2-6** — the 34 subcommand `--help` cases are NOT in the
  golden set and were NOT required dispatch work; they fall out
  of the dispatcher tables and were probe-verified 34/34
  byte-identical on cue (not golden). Recorded here, not in the
  golden count.
- **D-M2-7** — version const `0.9.0`, bare `castctl 0.9.0` (Go
  `commands.go` `Version` var + `-X` stamp mechanism; code
  default is `0.6.1`, the installed binary is stamped `0.9.0`).
  N2 CORRECTED from R3: strip the optional
  ` (<commit> <date>)` stamp suffix from the `--version` line on
  BOTH sides and compare `castctl <version>` exactly. R3's
  `(VERSION)` token form would mismatch an unstamped binary.

## M2.5 Deviations and approximations

- **AGENTS.md rules 5/6 deviation (brief override)** — the M2
  scope is `rust/` ONLY: no `docs/*` update and no
  `docs/provenance.md` + NOTICE update ride along, although the
  repo's AGENTS.md rules 5/6 require them. Recorded here and in
  the PR body; do not fix by editing docs/NOTICE in this branch.
- **Config-resolution exceptions** — `update`, `plugin check`,
  and `auth export` NEVER resolve config in Go (probed batch 4)
  and do not in Rust either; `config migrate` resolves config
  location but never parses the file (it reads the legacy
  layout itself). The code above is Go-faithful: the uniform
  stub-order rule (stub after config-location resolution and
  config parse) is the one place the stub paths diverge from
  Go, and only in that the stub fires instead of profile
  resolution. The three exceptions are documented, not silently
  substituted.
- **Pre-resolveConfig handler checks (Go-faithful, flagged)** —
  Go performs some checks before `resolveConfig`, and Rust
  reproduces them in the same position: `profile rm` without
  `--yes`, `fs rm` without `--yes` (different message),
  `profile add` `--outbound` + `--outbound-from-env`
  mutual exclusion, `auth status` `--profile`+`--all`, keeper
  tag/profile exclusion, `config migrate --from` empty,
  `plugin check` tag validation, `auth login` experimental gate
  then the tag-off CDP gate, `auth observe-login` tag-off
  relogin gate. The CDP/relogin gates reflect the default
  release build (no `with_chromedp` tag in the release
  workflow); a tag-on build behaves differently by design.
- **Pre-config checks NOT reproduced (documented divergences)**
  — `raw` route-table lookup / `--body` JSON parse / `--param`
  `k=v` check (Q8: route lookup first, then body, then params;
  all before config resolution), `fs` path `Norm` checks,
  `profile set-outbound` file read, `auth import` stdin
  read + cookie validation. In Rust the stub fires after config
  resolution instead. `auth import` with bad stdin input and a
  bad config therefore reports the config error in Rust where
  Go reports the stdin error.
- **Stub before active-profile resolution** — `--profile nosuch`
  validation, `default_profile` existence, and `ensureNodeID`
  never run in M2; the stub fires first. A stubbed command with
  an invalid profile flag exits 1 in Rust where Go exits 2.
- **Legacy flat config still stubs (F5 remainder)** — a valid
  JSON config without the `profiles` marker is a legacy flat
  file: Go's `LoadProfile` refuses it (legacy-layout error,
  exit 2), but the M2 stub path only parses via
  `LoadSingleConfig`, which reports "not found" for it, so the
  stub fires (exit 1). Full `LoadProfile` behaviour (legacy
  refusal, profile existence, env fill, outbound validation)
  is a later milestone.
- **`Debug` never prints secrets (fix-loop F1)** — hand-written
  `Debug` impls for `TelegramConfig`, `SingleConfig`,
  `Profile`, and `OutboundRef` print only lengths/markers
  (token → `[redacted]`, raw blocks → presence/kind markers),
  never credential or outbound content. Regression tests
  assert `format!("{:?}")` contains neither the fake token nor
  fake credential/outbound values.
- **JSON nesting cap 10000 (fix-loop F2)** — decoder and
  encoder mirror Go `encoding/json` `maxNestingDepth`: the
  10001st nested container errors `exceeded max depth`
  (decoder: `profile: invalid json: exceeded max depth`,
  exit 2) instead of overflowing the stack. Probe-measured:
  10000 `[` decode OK, 10001 errors. Both are ITERATIVE
  (explicit stacks, no recursion per level): the first
  recursive implementation overflowed the 8MB main stack at
  depth 10000 on cue, so the cap alone did not prevent the
  crash. The encoder-side message
  (`profile: exceeded max depth`) is a Rust-side
  approximation — Go's marshal-side depth behaviour was not
  probed; only the clean-error/no-crash property is claimed.
- **`Getenv=None` convention (fix-loop N-b)** — `None` ALWAYS
  means the process environment, everywhere in
  `castctl-config` (`resolve_profile_name`,
  `resolve_active_profile`, `apply_env_fill`,
  `resolve_config_location`): this matches Go production
  behaviour (callers pass `os.LookupEnv`). The Go nil-getenv
  guards (skip env entirely) do not apply to this API; tests
  needing isolation pass `Some` with a stub getter.
- **Harness no-write limitation (red-team H6)** — the
  generator and the parity test assert the fixture config is
  byte-identical and the work dir stays empty after each case,
  but writes elsewhere under `$HOME`/`$XDG_CONFIG_HOME`
  (outside the fixture config path) are not snapshotted. A
  case that wrote elsewhere would go undetected; no case is
  known to do so.
- **`"dns": null` / `"dns": []` (probe N4)** — Go rejects
  both at parse (`parse dns: expected json object start, but
  starts with nil` / `cannot unmarshal array ...`), because
  `parseDNS` validates the shape. Rust's deferred sing-box
  handling (D-M2-1) stores the raw value without that check,
  so these parse "successfully" here. Recorded as part of the
  deferred-validation boundary, not fixed.
- **Go map-iteration order** — Go's tail validation iterates a
  map for multi-violation cases (order unspecified); Rust
  iterates profiles in sorted order. Single-violation messages
  are identical; multi-violation order may differ.
- **`wireguard_dns` non-raw render order** — Go marshals a map
  (random order); Rust renders stored input order. The parse
  path always has raw JSON, so this branch is unreachable from
  parsed configs.
- **Decoder messages (binary-measured, fix-loop round 2)** —
  the `Token()`/scanner reproduction is verified against the
  corpus in `jsonvalue.rs` tests, measured byte-for-byte
  against the installed Go binary on cue (`/usr/local/bin/
  castctl` 0.9.0 @1396697, isolated HOME/XDG, `--config
  <fixture> status`) — NOT against toolchain-version
  reasoning. Four shapes were fixed in round 2 after direct
  binary probes (see §M2.6c): (A) truncated input reports
  plain `EOF` only while waiting for a value or a key's
  colon, and "unexpected end of JSON input" in every other
  token state; (B) number errors use the single context
  "in numeric literal" for fraction and exponent alike;
  (C) a bad simple escape reports `invalid escape sequence`
  with the two-byte span, quoted per `go_quote_escape_span`;
  (D) a bad `\u` escape reports the same form with a fixed
  six-byte span from the backslash (truncated at end of
  input), while EOF inside the window with no bad byte is
  "unexpected EOF". Span quoting: backticks iff the span is
  valid UTF-8 and every rune is printable and neither a
  space nor a backtick; otherwise `%q` over the decoded
  runes with invalid bytes as `\xHH`. Outside the probed
  corpus, `quoteChar` for control/Latin-1 bytes, deep UTF-8
  lossy edges, and the plan9 branch remain approximations.
  `json.Indent`'s error branch is unreachable from the
  port's own compact output. Probe N3 (fix loop): Go decodes
  a lone high surrogate `"\uD800\u0041"` as U+FFFD + `A`,
  matching Rust — no fix needed.
- **`%q`/`IsPrint` for runes > 0xFF** — `go_quote`/`go_quote_char`
  reproduce the probed cases (incl. `0xFF`→`'ÿ'`, NBSP→
  `'\u00a0'`, DEL→`'\x7f'`). Separator runes (Zs/Zl/Zp:
  U+00A0, U+1680, U+2000–U+200A, U+2028, U+2029, U+202F,
  U+205F, U+3000) are escaped, probe-verified against
  `strconv.IsPrint` on cue (fix-loop F8). Other unprobed
  categories (private-use, unassigned) remain an approximation:
  Go rejects them, Rust currently treats them as printable.
- **Non-UTF8 argv / env** — argv via `args_os` + lossy
  conversion; env values via `var_os` + lossy. Go receives
  raw bytes; a non-UTF8 argv token or env value is a documented
  approximation.
- **Plan9 `userConfigDir` branch** — not reproduced (no Rust
  target); the Unix branch applies. Documented, unprobed.
- **No signal handling** — SIGINT → exit 130 (`main.go:38`,
  `classifyError` on `context.Canceled`) is not ported in M2.
- **Indexmap decision (R3 P15 / R1 P-8)** — NO indexmap. `Vec`
  suffices: `test_ordered_object_set_semantics`
  (duplicate-key last-wins/first-position) and
  `test_decode_values_and_order` pin the only ordering
  operations the port needs. No measurement was required
  because no dependency was added; no `Cargo.lock` dep diff
  exists to report.
- **`marshalScalar` on malformed hand-built numbers (R1 P-3)**
  — not on the parse path; Rust returns
  `json: invalid number literal %q`, documented.

## M2.6 Probes (all on cue unless noted; log in `~/workspace/tmp/castctl-rust-m2-notes/m2-probes.log`)

- Batches 1–3 (binary surface), stdlib probes
  (`encoding/json` scanner/stream/decode sources + the
  `/tmp/m2dec3` scratch Go program re-verifying the full decode
  error corpus, Go 1.26.8), batch 4 (config exceptions +
  34 subcommand helps + stdout byte counts).
- Batch 5 (2026-11-05): Q6 empty token `""` and lone `-`
  (empty → chat/auth-failure path, no hang, no stdin read;
  `-` → invalid choice, 46 names); Q4 `config migrate`
  dry-run prints the migration-report JSON, exit 0, no write,
  and `--write` migrates (observed, D-M2-5 unchanged); Q8
  `raw chat.history --param nokey` → 1-line
  `bad --param 'nokey': expected k=v` exit 2 (route lookup
  precedes the param check; unknown method reports 258 known
  methods); `raw … --param` with no value → 3-line parse error.
- 34 subcommand `--help` cases: Go vs Rust binary, isolated
  env, byte-compare of stdout/stderr/exit code — TOTAL=34,
  MISMATCHES=0 (probe, not golden).
- P-14: `CARGO_BIN_EXE_castctl-rs` (dash spelling) confirmed
  via a throwaway probe test on cue (underscore spelling is
  `None`); the probe file was deleted after the run.
- P-15: no indexmap measurement needed (see §M2.5).
- P-1/P-3/P-6/P-7/P-10/P-11: corpus-verbatim decoder messages;
  P-3 documented; P-6 N/A by design (no sing-box errors are
  emitted); P-7 documented (§M2.5); P-10 LoadProfile
  filesystem cases covered by temp-dir tests in `config.rs`;
  P-11 no-write asserted by both the generator and the parity
  test (fixture config bytes + empty work dir after each case).
- Open: Q7 (producer of exit 124) — out of scope, note only.

## M2.6b Fix-loop probes (round 1, all on cue)

- S1/S3/S4 confirmations (isolated env, both binaries):
  bad-JSON config + `status` → Go exit 2 `invalid json`,
  Rust (pre-fix) exit 1 stub; `fs rm` without `--yes` → Go
  exit 2 `refusing to delete without --yes`; `profile add`
  with both outbound flags → Go exit 2 mutual-exclusion
  (even with `--config /nonexistent`). All three fixed (F5/F6/F7).
- D2/F8: Go escapes U+2028/U+2029/Zs in `%q`
  (`strconv.IsPrint` probe: false for U+2028/29, U+00A0,
  U+1680, U+2000–U+200A, U+202F, U+205F, U+3000, U+200B,
  U+FEFF, U+00AD, private-use, unassigned; true for marks,
  U+0020, U+00FF, U+20AC, emoji) — `go_is_print` extended.
- N3: lone surrogate `"\uD800\u0041"` → U+FFFD + `A` in Go,
  matching Rust. N4: `"dns": null` / `[]` rejected by Go
  `parseDNS` — deferred-validation limitation, recorded.
- F2 nesting: `decodeOrderedJSON` at 10000 `[` OK, 10001
  errors `exceeded max depth`; `ParseSingleConfig` at 10000
  errors (wrapper depth). The message text comes from Go's
  stdlib scanner, not repo code.
- Decoder re-probe (Go 1.27.3 toolchain): the full corpus +
  key/comma/missing-value shapes were re-measured through
  `decodeOrderedJSON` in the module (go 1.27.3, jsonv2
  default). The Phase-2 corpus expectations for 11 shapes
  were WRONG (they encoded Go 1.26 v1 `stream.go` reasoning,
  verified against a scratch program outside the module):
  key-position, comma-anchored, missing-value, truncation,
  number-context, and escape messages all differ under
  1.27. The implementation then matched Go 1.27 for every
  probed shape except six documented divergences (§M2.5);
  those six were fixed in round 2 by direct binary probes
  (§M2.6c), and the corpus tests now pin the binary-measured
  messages. Scratch dirs on cue: `/tmp/decprobe` (module
  clone at `85a8d5e`), `/tmp/tokprobe` (standalone Token
  probe, go 1.26 semantics — NOT authoritative).
- H1/H7 tamper probes (after F9): editing one golden byte,
  and editing one manifest digest, each make the parity test
  FAIL with a manifest-digest assertion; restoring makes it
  pass. The generator refuses a wrong-version `GO_BIN`
  (exit 2, golden dir untouched).
- Depth binary probes: 10000-deep config → clean exit 2
  (`config must be a json object`, parsed OK, no crash);
  10001-deep → clean exit 2 `exceeded max depth`.

## M2.6c Fix-loop probes (round 2, all on cue, Go binary only)

Ground truth: the installed Go binary only — no reviewer
notes, no toolchain-version reasoning. Each probe ran Go
with an isolated HOME/XDG, minimal env, stdin `/dev/null`,
cwd = fresh work dir, argv `--config <fixture> status`.

- (A) Truncation state rule, 36 variants + 21 nested-state
  confirmations: `EOF` at TopValue (empty/whitespace),
  ObjectColon (after a key), ObjectValue (after `:`);
  "unexpected end of JSON input" at ObjectStart,
  ObjectKey (after a comma in an object), ObjectComma
  (after a value), ArrayStart, ArrayValue (after a comma
  in an array), ArrayComma (after an element), including
  nested states; "unexpected EOF" mid-token (unterminated
  string, literal, number).
- (B) Number errors, 21 variants: every bad character in
  the fraction and in the exponent (sign or digits, any
  delimiter) reports "in numeric literal"; `-}`/`-x`
  likewise; EOF mid-number is "unexpected EOF".
- (C) Simple escapes, 14 variants + byte probes: span is
  exactly `\` + the offending byte (byte, not rune);
  measured for `q x 0 ' space DEL 0x01 0xC3 0x80` and
  with trailing input.
- (D) `\u` escapes, 21 variants: span is six bytes from
  the backslash (fewer at end of input); a non-hex byte
  anywhere in the four slots errors with the span even at
  EOF; EOF with no bad byte is "unexpected EOF".
- Span quoting, 24 + 10 + 3 hex-checked variants: backtick
  form iff the span is valid UTF-8 and all runes are
  printable, non-space, non-backtick (incl. complete `é`,
  `€`, CJK literal); `%q` form for space, tab, CR, VT,
  FF, control bytes, DEL, backtick, invalid bytes
  (`\xHH` per byte), NBSP and U+2028 (complete but
  non-printable, rendered `\u00a0`/`\u2028`).
- Re-verification: all 92 + 45 + 10 + 3 probe cases and
  all 26 decoder-probe fixtures re-run against the fixed
  Rust binary — 0 decoder mismatches; the 5 non-decoder
  mismatches (legacy-layout/runtime vs stub) are
  unchanged in kind (see §M2.5, F5 remainder).

## M2.7 Test mapping (cue counts; M1 crates unchanged)

| Crate | Rust tests | Notes |
|---|---|---|
| `castctl-config` | 87 | Decoder corpus (binary-measured Go messages, incl. the round-2 state-dependent EOF rule, single number context, and escape-sequence spans) + trailing-data quirks + order/number/surrogate/indent rules; profile/config/telegram/log/blocks/configlocation rules; LoadProfile filesystem cases (single/legacy/stray/dir/env-fill); D19 regression; round-trip idempotence with raw key reorder + `<>&`; Debug-redaction, depth-cap, ENOTDIR, separator-quote, strerror, empty-number tests |
| `castctl-cli` | 41 | Parser (abbreviations, bundling, negative numbers, defaults incl. int-set separation, lists/pairs, help short-circuit); table (order, usage lines, int defaults); dispatch (2-/3-line shapes, dispatcher quirks, stub order, gates, approve/auto-approve/keeper/migrate checks, export guidance, fs-rm/profile-add pre-checks) |
| `castctl-rs` | 2 integration (`parity.rs`) | 59/59 golden cases, 0 mismatches (see §M2.8); SHA-256 known-answer test |
| M1 crates | 46 + 7 + 2 + 10 | Unchanged counts, all green |

Go test files consulted directly (behaviour pinned from code +
probes, not 1:1 test ports): `internal/profile/` —
`config_test.go`, `telegram_test.go`, `jsonvalue_test.go`,
`configlocation_test.go`, `profile_test.go`, `log_test.go`,
`plugins_test.go`, `credentials_test.go`, `keeper_test.go`,
`webui_test.go`, `dns_test.go`, `wireguard_test.go`,
`outbound_test.go`, `guard_test.go`, `migrate_test.go`,
`autoapprove_test.go`, `errors_test.go`, `fingerprint_test.go`;
`internal/commands/` handler tests for the parser/dispatcher
shapes. Deferred Go tests are listed in §M2.3.

## M2.8 Verification (on cue, rustc/cargo 1.97.1)

Scratch: `/tmp/dfix2` (sources synced by tar over SSH;
`target/` never synced). Host key verified before the first
login: `SHA256:6ExOBaFLBXhnN4GX3Qjh6DbdjJev2p7nR61IwERRhcs`
— MATCHED. Fix-loop round 1 (F1–F10 + nits, incl. the
iterative decoder/encoder rewrite) and fix-loop round 2
(decoder messages A–D, binary-measured on cue) verified here
from the final local tree; the golden files +
`manifest.json` in the repo are the output of
`gen_golden.sh` on cue (59 cases).

```console
$ cargo --version && rustc --version && cargo clippy --version && cargo fmt --version
cargo 1.97.1 (c980f4866 2026-06-30)
rustc 1.97.1 (8bab26f4f 2026-07-14)
clippy 0.1.97
rustfmt 1.9.0-stable
$ /usr/local/bin/castctl --version
castctl 0.9.0 (1396697 2026-11-04T21:38:36Z)
$ cargo build --workspace
BUILD-EXIT=0
$ sh parity/gen_golden.sh
GEN-EXIT=0  (59 golden files + manifest.json written; count verified with ls)
$ cargo test --workspace
test result: ok. 41 passed; 0 failed  (castctl-cli)
test result: ok. 87 passed; 0 failed  (castctl-config)
test result: ok. 46 passed; 0 failed  (castctl-log-redact)
test result: ok. 7 passed; 0 failed   (castctl-shared)
test result: ok. 2 passed; 0 failed   (castctl-tg-files)
test result: ok. 10 passed; 0 failed  (castctl-tg-text)
test result: ok. 2 passed; 0 failed   (parity integration: sha256 known-answer + golden_parity, 59/59 cases, 0 mismatches)
TEST-EXIT=0
$ cargo clippy --workspace --all-targets -- -D warnings
CLIPPY-EXIT=0
$ cargo fmt --check
FMT-EXIT=0
$ cargo doc --workspace --no-deps
DOC-EXIT=0
$ grep -rn unsafe (src) → 0 code hits (2 doc-comment mentions of the rule)
```

`git diff --stat` shows only `rust/` (plus the new `rust/`
crates/harness as untracked additions, committed on the feature
branch); the Go tree is untouched (verified before commit). The
`dev-rust` base was verified on origin at
`85a8d5eaa529237d38de1192d992261ed1db7557` before the branch was
created, and `feat/rust-m2-config-cli` was absent on origin.
Nothing was pushed; no PR was opened.

---

# Porting notes — Rust M3 (transport via honk, NO WireGuard)

Scope: one new crate (`castctl-transport`) plus workspace wiring
(honk pin + `[patch]` replication), SPDX headers on all 44 `.rs`
files, `rust/LICENSE` (byte-identical to root `LICENSE`),
`rust/NOTICE`, root `NOTICE` honk entry, and
`docs/provenance.md` §13 — the last two close the M2.5 docs debt
for the Rust/honk part (the §M2.5 note is history and is not
rewritten). Base: `dev-rust` `664f26315c2481a5b4302b8d89f4e4c49f7ecefc`.
Branch: `feat/rust-m3-transport`, LOCAL ONLY — nothing pushed,
no PR opened, no merge (the parent task explicitly forbids
push/PR/merge for this writer; the reviewer/parent decides the
next step after the toolchain blocker below). No Go code was
changed. Parent decisions D-M3-1..D-M3-8 (plan file
`~/workspace/plans/active/castctl-rust-m3-transport.md`) were
applied as written; the two PR split (M3, then M3d WireGuard)
follows the plan: M3d is NOT in this branch.

Toolchain (measured on cue, the only authoritative host):
`rustc 1.97.1 (8bab26f4f 2026-07-14)`, `cargo 1.97.1`, edition
2024, `resolver = "2"`, `rust-version = "1.85"`.
`rust/Cargo.lock` is committed (updated: 276 packages).

## M3.1 Crate map

| Crate | Go source | Contents |
|---|---|---|
| `castctl-transport` | `internal/gateway/routes.go`, `internal/conn/gateway.go`, `internal/gateway/calls.go`, `internal/gateway/jsonutil.go`, `internal/gateway/stream.go`, `internal/gateway/summary.go`, `internal/conn/shared.go`, `internal/conn/errors.go`, `internal/outbound/dialer.go`, `internal/outbound/tls.go`, `internal/telegram/bot.go`, `internal/commands/commands.go`, `internal/profile/outbound.go` (dispatch shape only) + honk-outbound (engine, called not copied) | Route table, sing-box→honk dispatch + TLS/REALITY, Dialer trait + direct/honk dialers, HTTP/1.1 client over a dialer, retry policy, `call_json` RPC client |

## M3.2 API mapping

Every public item has a doc comment citing its Go source
`file:line` at the M3 base. Items with no direct Go function
counterpart (e.g. `RedirectRefused`, `TlsMode`,
`Dispatch::Honk`) say so in their docs and cite the Go type /
vocabulary they model; no Go function line is fabricated.

| Go | Rust | Notes |
|---|---|---|
| `RouteTable.LookupRoute`, `ParseRoutes`, `DefaultRoutes` (`internal/gateway/routes.go:78-116`), `Route` (`internal/conn/gateway.go:132-137`), `Gateway.LookupRoute` (`internal/conn/gateway.go:316-318`), `internal/proto/routes.json` | `routes::{Route, Service, RouteTable::default_routes/parse/lookup_route, build_path, quote_path_param}` | Table embedded via `include_str!` of the Go JSON (258 entries at M3 base); first-wins duplicates; absent service → `daemon`; path quoting = Go `quotePython(v, "")` (`media.go:19-35`); query = `url.Values.Encode` (sorted keys) |
| `parseOutbound` (`internal/profile/outbound.go:96-138`), `CreateOutbound`/`CreateEndpoint` (`internal/outbound/manager.go:243-272,479-494`), `GatewayTLSOptions`/`BuildTLSConfig` (`internal/outbound/tls.go:16-76`), WS ALPN pin (`internal/gateway/connector.go:240`) | `config::{Dispatch, TlsMode, dispatch_outbound, tls_mode_for, apply_tls_mode, validate_reality, decode_base64url}` | Subset only (D-M3-3): socks→socks5, shadowsocks, vmess, vless, trojan, hysteria2, tuic → honk; direct/block as before; wireguard → "→ M3d" error; all other types → `Unsupported`; detour → `Unsupported`; SS plugin → `Unsupported`; WS ALPN pinned `http/1.1`; unknown fields ignored (deviation, see §M3.3) |
| `DialContext`/`Resolve`/`DialTLS`/`HTTPClient` (`internal/outbound/dialer.go:127-236`), `Manager.Dialer` (`internal/outbound/manager.go:585-597`) | `dialer::{Dialer, DialTarget, DirectDialer, HonkDialer, DIAL_TIMEOUT, resolve_target}` | `Dialer` is the M3d seam (object-safe boxed future); dial failure → `ConnectionDown`; DIAL_TIMEOUT 10s = Go `TLSHandshakeTimeout`; no proxy env reads anywhere in `src/`; both dialers try EVERY resolved address (M3c: a per-address timeout no longer aborts the whole dial — only after all addresses fail is the result `ConnectionDown`) |
| `BoundClient`/`noFollowRedirect` (`internal/telegram/bot.go:316-352`) | `http::{HttpClient, HttpResponse, MAX_RESPONSE_BODY}` | Hyper http1 client conn over the dialed stream; no proxy concept (structural, not a flag); ANY 3xx → `RedirectRefused`, never a second request; no cookie jar; one fresh stream per call (no pool → Go 90s idle / 100-conn pool have no counterpart); HTTP/1.1 only (Go `ForceAttemptHTTP2` not ported); hyper handshake failure → `ConnectionDown` (nothing sent yet, M3c); 16 MiB body guard is M3-local, not Go parity, enforced DURING the read (frame-by-frame stream cap, M3c — the old collect-then-check order could OOM first); over-cap body → `Gateway` (exit 3, never retried) |
| `retryCall` (`internal/conn/shared.go:148-221`), `safeToRepeat`/`safeFor` (`:46-56,136-147`), constants (`internal/conn/gateway.go:21-55`) | `retry::{RetryPolicy, RETRY_FOR, RETRY_PAUSE_INITIAL, RETRY_PAUSE_MAX, POST_READ_METHODS, safe_to_repeat, should_retry, run_with_retry}` | Budget 30s (NOT a fixed attempt count — only `SubscribeRaw` has one: 3 attempts, not ported); ladder 250ms doubling to 4s; `ConnectionDown` always, `ConnectionError` only when safe; `Auth` never; Go's `gw()` reconnect branch is covered because a dial failure surfaces as `ConnectionDown`; the RPC layer additionally wraps the whole call in the request timeout (M3c overall cap — per-attempt timeouts alone reset every attempt and could stretch the call past it) |
| `CallJSON`/`Request` (`internal/gateway/calls.go:26-220`), `encodeBody`/`bodyToQuery`/`pythonStr` (`internal/gateway/jsonutil.go:28-138`), `buildPath`/`resolveRoute` (`internal/gateway/stream.go:188-220`), `summarizeBody`/`gatewayErrorFromSummary` (`internal/gateway/summary.go:213-224`) | `rpc::{RpcClient, DEFAULT_REQUEST_TIMEOUT, body_to_query, decode_response}` | HTTP-over-outbound RPC (D-M3-2), NOT the WS+Noise+protobuf gateway (deferred, see §M3.3); timeout 30s; GET body → query (nil dropped, top-level bool `True`/`False`, nested values via `pythonStr` `%v` — M3c, the old "Go does not define" doc was wrong); empty body → `{}`; envelope `ok`/`result` rules verbatim (M3c: only a BOOLEAN false `ok` errors; `result` wins with `ok` absent or non-bool); numbers via `serde_json::Number` + `arbitrary_precision` (never `f64`, literals kept past u64 — M3c); non-JSON/boolean-false-`ok` → `GatewayError(-1, summary)`; status non-2xx → `GatewayError(status, summary)`; NO body bytes in any error |
| `AuthError`/`GatewayError`/`ConnectionDown`/`ConnectionError`/`TimeoutError` (`internal/conn/errors.go`), `ValidationError` (`internal/gateway/jsonutil.go`), `classifyError` (`internal/commands/commands.go:268-337`) | `error::{TransportError, BodySummary, validate_content_type, validate_error_code, truncate}` | `exit_code`: auth 2, gateway 3, timeout 4, cancel 130, validation 2, else 1 — NOT `phaseExitCode` (`profilecmd.go:901-929`, auth 3); `Display`/`Debug` (hand-written) print summaries only; `log_summary` prints class + lengths, never message bytes; `RedirectRefused` carries no `Location` value (M3c: nothing reads one); `Unsupported` → 1 here — the CLI layer must map config rejections to 2 itself (M3c: documented in `error.rs` and here, code unchanged) |

## M3.3 Deferred / deviations (deliberate, not silent)

- WS+Noise+protobuf gateway transport (`internal/gateway/stream.go`
  `open`, phases `PhaseNotSent`/`PhaseSentNoReply`/`PhaseStreaming`):
  DEFERRED. An HTTP client has no stream phases, so none are faked.
- `RequestOptions` fields with no HTTP equivalent: `Route`
  override (M3 always uses the table), separate `Query` input,
  absolute `Deadline`, `Track`: not ported.
- `DownloadFile` (300s), `Ping` (10s), subscriptions,
  `CancelStream`, `OpenStream` (`safe=false`) / `DownloadFile`
  (`safe=true`) retry variants: recorded in `retry.rs` docs,
  not implemented (no such calls exist in M3).
- Per-profile DNS router: M3 direct dials use the system
  resolver, NOT Go's fail-closed `ErrNoResolver`
  (`dialer.go:127-145`). Domain dials through `direct` are
  therefore not fail-closed in M3; fixing that is M4 DNS work.
- HTTP/2: not negotiated in M3 (hyper http1 only).
- `tls_engine` stdlib/cronet, non-chrome fingerprints, explicit
  UTLS disable, `spider_x`: `Unsupported` fail-closed (D-M3-4),
  never silently mapped to Chrome.
- Honk Chrome-mode is process-global: two profiles with
  different TLS modes in one process are an M3 limitation.
- Unknown sing-box JSON fields ignored (M2 raw-preserve),
  while sing-box `badjson` rejects them.
- `HonkDialer` requires `ProxyRegistry: Send + Sync` via the
  `Dialer: Send + Sync` bound — UNVERIFIED until a build runs
  (see blocker); if the registry is not `Sync`, the dialer will
  need a lock or a non-`Sync` redesign, decided after the
  toolchain decision, not pre-empted here.
- No network CLI commands are wired in M3; `castctl-rs` still
  builds the offline surface only (unchanged behaviour).
- TLS `enabled` has TWO different Go rules, and `build_tls`
  follows only one (M3c, NB6): the OUTBOUND path parses
  sing-box JSON, where `OutboundUTLSOptions` /
  `OutboundRealityOptions` are pointers and their `Enabled`
  fields are plain bools — a missing block means "apply
  the Go default", a present block with a missing field
  means false (sing-box v1.14.4 `option/tls.go`,
  `common/tls/client.go:103`, `reality_client.go:60`).
  The GATEWAY-dial path (`internal/outbound/dialer.go`
  `DialTLS`, `:161-168`) is different: it FORCES
  `Enabled=true` whenever TLS is requested at all
  (`BuildTLSConfig`, `internal/outbound/tls.go:56-60`,
  returns nil when `!Enabled`). Porting the gateway-dial
  rule is M4 work at the gateway-dial call site — it
  must NOT be folded into `build_tls`, which serves
  the outbound path.
- `HonkDialer::new` bypasses dispatch (M3c, NB10,
  watch-item for M4): a caller that builds a `Node` by
  hand and passes it to `HonkDialer::new` skips
  `dispatch_outbound` validation AND `apply_tls_mode`,
  so it dials with honk's default TLS mode, not
  Chrome-mode. M4 must route node construction through
  dispatch or restrict the constructor. Related: QUIC
  nodes (hysteria2/tuic) NEVER pass `apply_tls_mode`
  (`build_tls` is TCP/TLS only), so QUIC-TLS mode is
  always honk's default regardless of profile — the
  profile's TLS settings do not reach QUIC dials.
- 3xx exit code is an M4 decision (M3c, NB13):
  `RedirectRefused` maps to exit 1 (the generic bucket)
  now; whether a gateway 3xx should stay 1 or become
  exit 3 (gateway error, Go's classification for
  gateway HTTP failures) must be settled explicitly
  in M4, not inherited silently.
- `Unsupported` → exit 1 vs Go config-parse → exit 2
  (M3c, N6): code UNCHANGED — this crate has no CLI,
  so the CLI layer must map config rejections to 2
  itself (documented in `error.rs` `Unsupported` docs
  and in the §M3.2 error row).
- QUIC `tls.insecure` is not mapped by dispatch
  (M3c, NB9 follow-up): hysteria2/tuic dispatch uses
  `quic: Default::default()`, so node QUIC TLS
  verification is always on (webpki roots) and a
  self-signed or private-CA server cannot work
  through dispatch, even though sing-box hysteria2
  outbound HAS `tls.insecure` (the Go control used
  it). Mapping it is future work, explicit opt-in
  only — see §M3.8 for the proof.

## M3.4 Pin + license (Boss decision, verbatim)

Pin: `honk-outbound = { git =
"https://github.com/daeuniverse/honk", rev =
"9e31cc0bd28825afdc0e384dc989bc3f076e69cf",
features = ["rprx"] }` (workspace root; `honk-config` same
rev), plus replicated `[patch.crates-io]` for `boring-sys`
(Glassyiris `3beb573b65ecaa69b7eefe3c2fecd074b97facd2`)
and `quinn`/`quinn-proto` (Glassyiris
`11f1de84c28305a3c98ace6d681c35219a8d1e6c`). Choice:
git-dep, NOT vendor. Reason + measurements (cue):
`cargo vendor` trial in a temp dir took 33.8s and produced
387M / 281 dirs (honk-outbound 4.9M, honk-config 2.4M);
vendor only wins if an offline-build requirement is proven,
which it is not for M3. New dep pins (exact, from the cue
`Cargo.lock`): tokio `=1.48.0`, serde `=1.0.228`,
serde_json `=1.0.145`, hyper `=1.8.1`, http `=1.3.1`,
http-body-util `=0.1.3`, bytes `=1.11.0` (all matched the
first cue resolution exactly — no pin had to be corrected).

License (Boss decision, quoted verbatim): artifact Rust là
GPL-3.0-only vì link honk; binary Go vẫn GPL-3.0-or-later;
2 artifact, 2 license. Realisation: SPDX header
`// SPDX-License-Identifier: GPL-3.0-only` + `// Copyright (c)
2026 muse-cli contributors` (holder reused verbatim from
the Go headers, which are uniform across the repo) on all
44 `.rs` files (33 M1/M2 + 11 new, tests included);
`[workspace.package] license = "GPL-3.0-only"` +
`license.workspace = true` on all 8 crates;
`rust/LICENSE` byte-identical to root `LICENSE`
(sha256 `3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986`,
674 lines, `cmp` clean); `rust/NOTICE`; root `NOTICE` §(b)
honk entry + the sing-box sentence scoped to "The Go
binary". "No unsafe" (D-M3-7): glue code in this crate
contains zero `unsafe` by construction (grep check below
is for the record; it could not be compiler-verified
because of the blocker). The dependency tree DOES contain
`unsafe` (honk-outbound alone: 65 hits in the probe) and C
code (BoringSSL via boring-sys) — the Rust binary is NOT
claimed unsafe-free anywhere in this PR.

## M3.5 Verification on cue — BLOCKER (read this first)

Gate 1 (PASSED on cue):
```
$ cargo tree -p castctl-transport --edges normal
honk-config v0.1.0 (https://github.com/daeuniverse/honk?rev=9e31cc0bd28825afdc0e384dc989bc3f076e69cf#9e31cc0b)
honk-outbound v0.1.0 (https://github.com/daeuniverse/honk?rev=9e31cc0bd28825afdc0e384dc989bc3f076e69cf#9e31cc0b)
boring-sys v5.2.0 (https://github.com/Glassyiris/boring-sys?rev=3beb573b65ecaa69b7eefe3c2fecd074b97facd2#3beb573b)
quinn v0.11.12 (https://github.com/Glassyiris/quinn?rev=11f1de84c28305a3c98ace6d681c35219a8d1e6c#11f1de84)
quinn-proto v0.11.19 (https://github.com/Glassyiris/quinn?rev=11f1de84c28305a3c98ace6d681c35219a8d1e6c#11f1de84)
```
All three git sources resolve to the forks, not crates.io.
`cargo tree` also resolved 276 packages (lock committed).

Gate 2 (FAILED on cue — BLOCKER, work stopped here per the
M3 brief: do NOT change the sha, do NOT upgrade the cue
toolchain without a Boss decision):
```
$ cargo build -p castctl-transport
error: rustc 1.97.1 is not supported by the following packages:
  aya@0.16.0 requires rustc 1.98.0
  aya-build@0.2.1 requires rustc 1.98.0
  aya-ebpf-bindings@0.3.0 requires rustc 1.98.0
  aya-ebpf-cty@0.4.0 requires rustc 1.98.0
  aya-obj@0.6.0 requires rustc 1.98.0
Either upgrade rustc or select compatible dependency versions with
`cargo update <name>@<current-ver> --precise <compatible-ver>`
```
Root cause (verified, not guessed): honk's workspace pins
`aya = "0.16"` (for `honk-ebpf-common`, pulled in by
`honk-outbound`), honk's own `Cargo.lock` pins `aya
0.16.0`, and honk's `rust-toolchain.toml` is `1.99.1`.
Downgrading aya below 0.16 would violate honk's own version
requirement, so there is no lock-only fix. Cue has only
`1.97.1-x86_64-unknown-linux-gnu` (`rustup toolchain list`;
no other toolchain installed). Consequences, stated
plainly: `cargo build --workspace`, `cargo test
--workspace`, `cargo clippy --workspace -- -D warnings`
could NOT run on cue — cargo refuses before compiling
anything, so even the non-honk modules are unverified by
the compiler. `cargo fmt --check` DID run on cue and is
clean (after `cargo fmt` on cue; formatted sources were
synced back). Everything below that needs a compiler is
therefore [CHƯA XÁC MINH], not passed:
- All unit + integration tests (invariant tests, retry,
  error mapping, token redaction, env-proxy, redirect).
- Hyper compatibility with `Box<dyn AsyncReadWrite>`
  (handshake over a honk stream) — code written against
  the hyper 1.x API as documented, never compiled.
- `HonkDialer: Send + Sync` (see §M3.3).
- TLS parity (JA3/JA4 Go vs Rust), QUIC handshake, and
  every build-time number (cold/warm build times are
  unmeasured — no number is invented here).

Two options for Boss (writer takes neither unilaterally):
(a) upgrade the cue toolchain to rustc ≥ 1.98 (e.g.
`rustup toolchain install` a newer stable) and re-run the
full M3 gate; or (b) pick an older honk sha whose
`honk-ebpf-common` does not require aya 0.16 / rustc 1.98,
and re-run the gate with the new sha recorded everywhere
the old one appears. Until one is chosen, this branch is
LOCAL ONLY and must not be presented as passing.

Static checks that DID run (no compiler needed):
```
$ find rust -name '*.rs' | wc -l
44
$ while read -r f; do head -3 "$f" | grep -q 'SPDX-License-Identifier: GPL-3.0-only' || echo "MISSING: $f"; done < <(find rust -name '*.rs' | sort)
(no output — all 44 files carry the header)
$ grep -rn 'GPL-3.0-or-later' rust --include='*.rs'
(no output — no or-later in Rust sources)
$ grep -rn 'HTTP_PROXY\|HTTPS_PROXY\|ALL_PROXY\|NO_PROXY' rust/castctl-transport/src
(no hits outside the doc comment in dialer.rs that names
the variables to forbid them — see the grep output in the
writer report for the exact lines)
$ grep -rn 'unsafe' rust/castctl-transport/src
(no code hits; the word appears only in comments — the
D-M3-7 rule statement and one test comment meaning
"not safe-to-repeat", not the keyword)
$ grep -rn 'unsafe {' rust/castctl-transport/src rust/castctl-transport/tests
(no unsafe blocks in src/; the only two unsafe blocks are
the env set_var/remove_var blocks in tests/env_proxy.rs,
unsafe in edition 2024 by design, each with a SAFETY comment)
$ grep -rn 'unwrap()\|expect(' rust/castctl-transport/src
(all hits inside #[cfg(test)] modules, on static fixtures;
zero in non-test code)
$ cmp LICENSE rust/LICENSE && echo byte-identical
byte-identical (sha256 3972dc97…dfb36986, 674 lines)
```

`git diff --stat` at submission is confined to `rust/`,
`NOTICE` and `docs/provenance.md` (verified before commit;
the Go tree is untouched). Nothing was pushed; no PR was
opened; CI Go status is therefore "not run for this
branch" — not claimed green.

## M3.6 Toolchain pin 1.99.1 (Boss decision, hướng (a))

Supersedes the 1.97.1 toolchain line above for the M3b
rerun; the M3 submission history in §M3.5 is not rewritten.
Reason for the pin, measured: honk at the pinned rev
(`9e31cc0`) pulls `aya 0.16.0` through `honk-ebpf-common`
(`aya = "0.16"` in honk's workspace; `Cargo.lock` reverse
lookup shows only `honk-outbound` depends on
`honk-ebpf-common`), and `aya 0.16.0` requires rustc >=
1.98 — the exact M3 blocker error (`aya@0.16.0 requires
rustc 1.98.0`, §M3.5). There is no lock-only fix (lowering
aya would violate honk's own version requirement), and the
sha is NOT changed (Boss direction: no sha change). 1.99.1
is chosen because it matches honk's own
`rust-toolchain.toml`; the pin lives in
`rust/rust-toolchain.toml` (`channel = "1.99.1"`,
components `clippy` + `rustfmt`, `profile = "minimal"`)
so any machine reproduces the build without changing its
default toolchain.

Cue toolchain install (Boss direction, verbatim shape:
`rustup toolchain install 1.99.1 --profile minimal`,
then `rustup component add --toolchain 1.99.1 clippy
rustfmt`), run on cue 2026-11-05:
```
$ rustup toolchain list   (before)
1.97.1-x86_64-unknown-linux-gnu (active, default)
$ rustup toolchain install 1.99.1 --profile minimal
info: latest update on 2026-10-15 for version 1.99.1 (58cf8f9c3 2026-10-13)
1.99.1-x86_64-unknown-linux-gnu installed - rustc 1.99.1 (58cf8f9c3 2026-10-13)
$ rustup component list --toolchain 1.99.1 | grep -E "^(clippy|rustfmt)-"
clippy-x86_64-unknown-linux-gnu (installed)
rustfmt-x86_64-unknown-linux-gnu (installed)
$ rustup toolchain list   (after)
1.97.1-x86_64-unknown-linux-gnu (active, default)
1.99.1-x86_64-unknown-linux-gnu
$ rustc --version; cargo --version   (outside any rust/ dir)
rustc 1.97.1 (8bab26f4f 2026-07-14)
cargo 1.97.1 (c980f4866 2026-06-30)
$ cargo +1.99.1 --version; cargo +1.99.1 clippy --version; cargo +1.99.1 fmt --version
cargo 1.99.1 (5f94df478 2026-08-27)
clippy 0.1.99 (58cf8f9c35 2026-10-13)
rustfmt 1.10.0-stable (58cf8f9c35 2026-10-13)
```
Default NOT changed, old toolchain NOT deleted (both
lines above prove it). Side effect, recorded honestly:
rustup itself self-updated 1.29.1 → 1.29.3 during the
install check; that changes the rustup binary, not any
toolchain or default. Whether the rustup shim on cue
honors `rust/rust-toolchain.toml` (vs explicit
`cargo +1.99.1` invocation) is probed in §M3.7 before
any claim is made about the file.

Transitive-only note (also in `rust/NOTICE` and
`docs/provenance.md` §13): `aya` / `honk-ebpf-common`
are transitive dependencies NOT used by castctl code —
no castctl source imports them (grep clean in
`rust/castctl-transport/{src,tests}` and the workspace
`Cargo.toml`). The nuance, checked against the cargo git
checkout on cue and recorded in §M3.7 (not assumed
here): `aya` is pure transitive (no `aya::` reference
in honk-outbound source either), while
`honk-ebpf-common` IS used by honk-outbound itself
(socket-mark constants in its direct dial path) —
castctl never touches either crate.

## M3.7 — Gate green on cue with toolchain 1.99.1 (M3b)

Toolchain-shim proof (cue, `/tmp/castctl-rust-m3/rust`):
`cargo --version` prints `cargo 1.99.1 (5f94df478
2026-08-27)` and `rustup show` reports the toolchain
active because it is "overridden by
'/tmp/castctl-rust-m3/rust/rust-toolchain.toml'". The
gates below therefore ran under 1.99.1 via the plain
`cargo` shim, not via an explicit `cargo +1.99.1`
invocation (that invocation was also verified in §M3.6
and gives the same toolchain).

Cue provisioning for the build (environment, not code):
`cmake` 3.28.3 (`apt-get install -y cmake`, after the
boring-sys build failed with "is `cmake` not
installed?") and `libclang-dev` (libclang-18, after
bindgen 0.72.1 failed with "Unable to find libclang");
`ninja` still absent, `make` is the fallback generator.
rustup self-updated 1.29.1 → 1.29.3 during the toolchain
install; that changes the rustup binary, not any
toolchain or default.

Gate run "attempt 6" (cue, plain `cargo`, 1.99.1):
- `cargo fmt` (apply) exit 0, then `cargo fmt --check`
  exit 0 (formatting synced back to the local tree).
- `cargo build --workspace` exit 0, cold, 1m 35s.
- `cargo test --workspace` exit 0: 229 passed, 0 failed,
  0 ignored — castctl-cli 41, castctl-config 87,
  castctl-log-redact 46, castctl-rs 0, parity 2,
  castctl-shared 7, castctl-tg-files 2, castctl-tg-text
  10, castctl-transport lib 25, env_proxy 1, rpc 8,
  doc-tests 0 (7 targets). Invariant tests present:
  `env_proxy_is_ignored`, `redirect_is_refused_and_
  second_server_gets_nothing`,
  `token_in_request_body_never_appears_in_errors`,
  retry-matrix tests.
- `cargo clippy --workspace -- -D warnings` exit 0,
  1m 07s, no `#[allow]` added (no blanket allows at all).

Code fixes between the M3 submission and the green
gate (all in `rust/castctl-transport`, no sha or
toolchain change, no lowered criterion):
- E0119 conflicting `Debug` impls for
  `config::Dispatch`: removed `#[derive(Debug)]`, kept
  the hand-written redacting impl (passwords never
  printed; covered by
  `dispatch_debug_never_prints_passwords`).
- E0277 hyper `rt::Read/Write` not satisfied for honk's
  tokio stream: wrapped the dialed stream with
  `hyper_util::rt::TokioIo` (canonical hyper↔tokio
  adapter, zero-copy wrapper) in `http.rs`; added
  `hyper-util` to the workspace (`=0.1.20`, resolved on
  cue to 0.1.20, checksum
  `96547c2556ec9d12fb1578c4eaf448b04993e7fb79cbaad930a656880a6bdfa0`)
  and to `castctl-transport` (`features = ["tokio"]`).
  This resolves the writer's uncompiled hyper-handshake
  uncertainty from §M3.
- Format-string bug in the vless-reality test
  (`config.rs`): one extra `}` removed from the tail.
- `Dispatch::Honk(Box<Node>)` (was `Node`): fixes
  clippy `large_enum_variant` (728-byte variant vs.
  unit variants); construction updated to
  `Box::new(node)`.
- Merged nested reality `if`s into one `&&`
  (`collapsible_if`); struct-literal `Node { …,
  ..Default::default() }` init
  (`field_reassign_with_default`); factored
  `DialFuture<'a>` alias (`type_complexity`);
  `split_once('/')` in `validate_content_type`
  (`manual_split_once`, semantics identical);
  blank doc line in `retry.rs` and moving the alias doc
  after the trait (`doc_lazy_continuation` ×7 + ×2);
  `200` → `200u16` and `|_: &RequestRecord|` closure
  annotation in `tests/env_proxy.rs` (E0271 + Fn
  generality); rustfmt normalization in `config.rs` /
  `dialer.rs`.
- Non-gate warning left as-is (recorded, not churned):
  `cargo test` shows `field 'headers' is never read`
  for `RequestRecord.headers` in
  `tests/common/mod.rs:26` (rpc test target); the
  clippy gate has no `--all-targets`, so it does not
  fail the gate.

Ebpf nuance (verified on cue, corrects the "only to
satisfy the dependency graph" phrasing for one crate):
- `aya` 0.16.0 (+ aya-build, aya-ebpf-bindings,
  aya-ebpf-cty, aya-obj): pure transitive. No `aya::`
  reference in honk-outbound source (grep empty in the
  cue checkout
  `crates/honk-outbound/src`); it enters only via
  `honk-ebpf-common`'s own dependencies. Only
  `honk-outbound` depends on `honk-ebpf-common`
  (Cargo.lock reverse lookup).
- `honk-ebpf-common`: NOT used by castctl code (grep
  clean), but honk-outbound itself uses its constants
  in the direct dial path: `CLASSIFIED_MARK` in
  `proxy/direct.rs:32` (`DirectMark::socket_mark`,
  used at lines 51/87) and `DAE_BYPASS_MARK` in
  `util.rs:29`, plus a test-only import in
  `proxy/packet/socket_mark_tests.rs:6`. It is a
  live honk dependency (SO_MARK for direct sockets),
  not dead weight inside honk. The Boss line stands
  for castctl: neither crate is used by castctl code.

## M3.8 — TLS / QUIC parity on cue (M3b, after the gate)

Method (same parser both sides, so parser quirks
cancel out): a record-only Python TCP listener on
127.0.0.1 captures the first TLS record (ClientHello);
a Python parser reports JA3 (classic, GREASE kept),
JA4-like (this parser's variant: version from
supported_versions, SNI d/i, 2-digit cipher/
extension counts excluding SNI+ALPN, ALPN first+last
char of the first advertised value, GREASE→0000
BEFORE sorting, first 12 hex of SHA256 over sorted
ciphers and over sorted extensions + presented-order
signature algorithms), plus all raw ordered lists.
Standard JA4 (FoxIO: GREASE excluded ENTIRELY from
lists and counts, same hash construction otherwise,
ALPN = first advertised value's first+last char)
was recomputed from the SAME captures in M3c with
an independent script (`notes/parity/ja4std-m3c.py`,
kept outside the repo tree for re-review); the
alternative ALPN convention (first char of the
first value + last char of the LAST value) would
give `h1` instead of `h2` in the ALPN field and is
not the column published here.
N = 5 runs per side per row. Go side: scratch clone
on cue (`/tmp/parity-go`, never in the repo tree) +
throwaway test `TestZZParityClientHello` with the
canonical castctl tags
`with_utls,with_quic,with_wireguard,with_gvisor`
(docs/development.md:10). Rust side: cue-only example
`castctl-transport/examples/parity_dial.rs` (never
committed; removed by the final local→cue sync).
Fixture (ephemeral, same both sides): SNI
`example.com`, trojan (plain TLS row) and vless +
REALITY (reality row, short_id `0123abcd`, one
ephemeral X25519 public key — public only, no
private key generated or stored; password/UUID are
fake test values). Cue Go notes: `/usr/local/bin/go`
is a wrapper that exports `GOTOOLCHAIN=local`
(castctl's go.mod needs ≥ 1.27.3, cue's go is 1.26.8),
so parity used the real `/usr/local/go/bin/go` with
`GOTOOLCHAIN=auto` (toolchain downloaded on demand);
the wrapper itself was NOT modified. Reality key
encoding differs between stacks: sing-box rejects
the padded base64 form ("illegal base64 data at
input byte 43", the trailing `=`), so the Go side
used the same key bytes unpadded while honk accepts
the padded form.

Parser bug found by recomputation (disclosed, not
hidden): the first JA4 implementation sorted cipher/
extension lists BEFORE normalising GREASE, so the
random GREASE value leaked into the hash through its
sort position and JA4 varied run to run. Fixed to
normalise-then-sort; all JA4 values below are the
corrected ones. Raw fields (cipher/extension sets,
groups, sigalgs) were never affected. JA3 varies per
run on both sides by design (GREASE kept, presented
order) — 5 distinct JA3 per side per row — so JA3
equality is not the comparison; the stable sets are.

M3c label correction (NB7): the M3b values were
called "JA4", but the parser's GREASE→0000-then-sort
+ count-with-GREASE convention is NOT standard JA4
(FoxIO excludes GREASE entirely from lists and
counts). The M3b values are relabelled JA4-like
above, and the standard-JA4 column was recomputed
from the same captures with an independent script
(fresh TLS walk + JA4 construction, kept as
`notes/parity/ja4std-m3c.py` outside the repo tree
for re-review). The parity
conclusion is unchanged under both variants: Go ≠
Rust on both rows.

TLS row (trojan, utls chrome both sides; SNI
`example.com`, ALPN `[h2, http/1.1]` both sides):
- Go JA4-like (stable ×5):
  `t13d1616h2_74c5f98c3854_f20eef27beb5`.
  Rust JA4-like (stable ×5):
  `t13d1814h2_4be38248e33f_2ecda25e495a`.
  Standard JA4 (same captures, GREASE excluded
  entirely, recomputed independently in M3c): Go
  `t13d1514h2_8daaf6152771_d8a2da3f94cd`, Rust
  `t13d1712h2_5b57614c22b0_a7c1ad54107f`.
  Fingerprints differ under BOTH variants (JA4-like
  cipher count 16 vs 18, extension count 16 vs 14;
  standard 15 vs 17, 14 vs 12) — a listed difference,
  NOT a gate failure, and NOT claimed as a match.
- Cipher sets (non-GREASE, sorted): Go 15 suites
  `1301,1302,1303,c02b,c02c,c02f,c030,cca8,cca9,
  c013,c014,009c,009d,002f,0035` (+1 GREASE = 16).
  Rust 17 suites: the same 15 + `c009,c00a`
  (ECDHE-ECDSA AES-SHA CBC suites utls-chrome does
  not send) (+1 GREASE = 18).
- Extension sets (non-GREASE, sorted): shared 11
  `000a,000b,000d,0017,001b,0023,002b,002d,0033,
  fe0d,ff01` (+ SNI `0000` + ALPN `0010` both sides).
  Go-only: `0005` (status_request), `0012`
  (signed_certificate_timestamp). Rust-only: none —
  `44cd` (Go) and `4469` (Rust) are the SAME
  extension, ALPS: both are fixed (present in all 5
  runs on their side) with byte-identical 5-byte
  payloads `00 03 02 68 32` (ALPS advertising `h2`),
  and honk attaches ALPS at codepoint 0x4469 (see
  research-honk) while utls-chrome uses the older
  0x44cd codepoint. Confidence: measured from the
  captures + the honk anchor; utls source was NOT
  grepped for the literal, so this is identification
  by payload + anchor, not by source proof. After
  unifying ALPS, the TLS-row extension difference
  is exactly Go-only `0005` + `0012`.
- Same both sides: supported_groups
  `{11ec,001d,0017,0018}` (+ GREASE; `11ec` =
  X25519MLKEM768), key_share groups
  `{GREASE,11ec,001d}`, supported_versions
  `{GREASE,0304,0303}`, signature_algorithms
  `0403,0804,0401,0503,0805,0501,0806,0601`,
  extension order fully permuted on every run
  (no two runs share an order — both sides permute
  like Chrome).
- Record length: Go 1721–1817 bytes, Rust
  1712–1776 bytes (variation within a side is
  GREASE/session randomness, not a set change).

REALITY row (vless + REALITY, utls chrome both sides):
- Go JA4-like = its TLS JA4-like exactly
  (`t13d1616h2_74c5f98c3854_f20eef27beb5`, ×5),
  and Go standard JA4 = its TLS standard JA4
  (`t13d1514h2_8daaf6152771_d8a2da3f94cd`, ×5):
  same cipher set, same extension set, same
  sigalgs as Go TLS. Differences vs Go TLS: no
  `11ec` group (supported_groups `{GREASE,001d,
  0017,0018}`, key_share `{GREASE,001d}` — REALITY
  drops the MLKEM768 hybrid, X25519 only) and much
  smaller records (499–595 bytes, no MLKEM768 key
  share).
- Rust JA4-like (stable ×5):
  `t13d0412h2_16c83510387f_a735005f8dcf`, standard
  JA4 (stable ×5):
  `t13d0310h2_55b375c5d22e_6fb7db78d84a` — a
  DIFFERENT, TLS-1.3-only profile: 3 + GREASE
  ciphers (`1301,1302,1303` only), 12 + SNI + ALPN
  extensions (includes `0005` + `0012` like Go,
  ALPS at `4469` = Go's `44cd` with the same
  `00 03 02 68 32` payload, lacks `000b`, `0017`,
  `0023` and `ff01`), supported_groups
  `{GREASE,11ec,001d}` (MLKEM768 KEPT, no
  `0017`/`0018`), supported_versions `{GREASE,0304}`
  only, record length 1706–1770 bytes. Honk's
  REALITY ClientHello does not match sing-box/utls
  chrome REALITY ClientHello — the largest parity
  gap in this section, listed, not a gate failure.

QUIC (hysteria2): controlled server = sing-box
v1.14.4 installed on cue via `go install -tags
with_quic,with_utls` (version string "unknown", as
expected for a module install), hysteria2 inbound
on 127.0.0.1:18900/18901, self-signed cert
(SAN localhost + 127.0.0.1), password fake.
- Go control client (sing-box hysteria2 outbound,
  same server): handshake + auth + connect PROVEN
  by the server log (`inbound connection from
  127.0.0.1:38043`, `inbound connection to
  127.0.0.1:18080`, `outbound connection to
  127.0.0.1:18080`). Its echo round-trip then
  failed with `read: EOF` (test-harness artifact,
  not investigated further — the handshake proof
  stands on the server log).
- Rust honk client, M3b: handshake NOT proven. Dial
  fails fast with `connection down: QUIC connect to
  127.0.0.1:18900 (attempt 3)` (same on 18901),
  and the server log shows NO Rust connection
  attempt at all. Against a blackhole UDP listener
  on 18902 the same client sends 26 valid-looking
  QUIC v1 Initial packets (1200 bytes, 3 bursts =
  3 attempts, DCIDs `38cc…`, `1575…`, `2c03…`)
  and retransmits until the 30 s timeout — so
  packets leave the client, and the failure is NOT
  packet loss. The M3b report attributed it to a
  handshake-content mismatch (ALPN / transport
  parameters / TLS profile inside honk's Initial);
  that attribution was UNPROVEN (the Initial
  payload was NOT decrypted — QUIC Initial keys are
  derivable from the DCID, but that analysis was
  not done).
- Rust honk client, M3c (NB9, decisive): the
  content-mismatch attribution is REFUTED. On a
  fresh controlled server (same shape: sing-box
  v1.14.4, hysteria2 127.0.0.1:18900, self-signed
  cert SAN localhost + 127.0.0.1, password fake,
  echo on 18080), the dispatch-default client
  reproduces the M3b failure verbatim
  (`QUIC connect to 127.0.0.1:18900 (attempt 3)`),
  while the SAME client with ONLY node-level
  `quic.tls.skip_cert_verify = true` (set via
  `Node::tls_mut()` in a cue-only harness, never
  through dispatch) dials OK and echoes
  (`read 2 bytes: [111, 107]` = "ok"). The server
  log shows no connection for the failing case
  (the client aborts before auth, so sing-box never
  logs an inbound connection) and the full
  connection + data path for the passing case.
  Root cause of the M3b failure: client-side
  certificate verification — honk verifies the
  server cert against its webpki-only root store
  (`tls.rs` `root_store`, Mozilla roots, NOT the
  system store), so a self-signed server cert is
  rejected; the Go control worked because it used
  `tls.insecure=true`. Packets, ALPN, transport
  parameters and the TLS profile were all fine —
  the handshake completes and data flows once
  verification is skipped. The Go control was NOT
  re-run in M3c: the passing Rust run against the
  same server subsumes its role (proving the server
  works). Artifacts (cue-only harness + run log +
  server log): `notes/parity/quic_m3c.rs`,
  `quic-m3c-runs.log`, `quic-m3c-server.log`.
  Follow-up, NOT in this loop: M3 dispatch maps
  hysteria2 with `quic: Default::default()` and
  never surfaces an insecure option, while sing-box
  hysteria2 outbound HAS `tls.insecure`. Mapping
  `tls.insecure` → node `quic.tls.skip_cert_verify`
  is future work and must stay explicit opt-in,
  never a default. Also note for that work: honk's
  webpki-only store means even a private CA trusted
  by the system would fail; only skip (or a
  publicly-trusted cert) works through honk today.
- QUIC verdict: Rust QUIC handshake against a
  controlled server through DISPATCH: FAILED (the
  dispatch path cannot skip verification, so a
  self-signed server cannot work through it); the
  honk QUIC stack itself is PROVEN working once
  verification is skipped. This is a parity finding,
  not a gate failure: the M3 gates are the four
  commands in §M3.7, all green.
- Go control scope note (M3b, kept): the Go control
  proved handshake + auth + connect by server log
  only — its echo round-trip failed with
  `read: EOF` (harness artifact), so the Go control
  proves no data path. Data-path QUIC is now proven
  on the Rust side (M3c echo above), not on the Go
  side.

## M3.9 — Build prerequisites on cue (supplement)

What a fresh cue checkout needs before `cargo build
--workspace` (all verified on cue; no other host is
claimed):
- Rust toolchain 1.99.1 via `rust/rust-toolchain.toml`
  (rustup installs it on demand with profile minimal
  + clippy/rustfmt; 1.97.1 stays the default on cue).
  MSRV note (M3c, NB11): `rust-version` in
  `rust/Cargo.toml` is 1.98, not the M3-submission
  1.85 — honk pulls aya 0.16.0 via honk-ebpf-common,
  and aya 0.16 requires rustc ≥ 1.98. The pin only
  works through the RUSTUP SHIM: a standalone cargo
  install ignores `rust-toolchain.toml` entirely and
  stays on its own toolchain, so on a machine with
  only cargo 1.97.1 the build fails on aya with a
  confusing "requires rustc 1.98" error before
  compiling anything. Always run plain `cargo` (the
  shim) from inside `rust/` so the pin applies.
- `cmake` 3.28.3 (`apt-get install -y cmake`):
  boring-sys's build script shells out to cmake
  (without it: "is `cmake` not installed?").
  `ninja` is NOT installed on cue and NOT needed:
  `make` is the fallback generator and the gates
  pass with it (ninja would only speed the
  BoringSSL build, not unblock it).
- `libclang-dev` (`apt-get install -y libclang-dev`,
  provides libclang-18): bindgen 0.72.1 needs
  libclang to build boring-sys v5.2.0 (without it:
  "Unable to find libclang ... set the
  LIBCLANG_PATH environment variable ...").
  `clang` (the compiler binary) is NOT installed on
  cue and NOT needed: bindgen needs the shared
  library, not the compiler driver.
- `LIBCLANG_PATH` status, measured, not assumed:
  after the libclang-dev install, the build passes
  WITHOUT `LIBCLANG_PATH` (attempt-6 gates and the
  final-verify gates both ran without it), because
  bindgen finds the dev symlink
  `/usr/lib/llvm-18/lib/libclang.so` (which points
  at `/lib/x86_64-linux-gnu/libclang-18.so.18`;
  ldconfig lists `libclang-18.so.18` and
  `libclang-18.so`). The parent-supplied fallback
  `LIBCLANG_PATH=/usr/lib/llvm-18/lib` was ALSO
  tested and is a valid value (see the timing run
  below — it succeeds with the variable exported),
  but it was NOT the fix and is NOT required on
  cue as configured; do not claim otherwise. The
  earlier `warm2` bindgen failure predates the
  libclang-dev install (the file did not exist at
  all then), so it is not evidence that bindgen
  cannot discover an existing libclang.
  Two M3c clarifications (NB12), both about what
  the measurements do NOT prove: (a) the
  `LIBCLANG_PATH` trial ran WITH libclang-dev
  already installed, so it does NOT prove that
  `LIBCLANG_PATH` alone substitutes for libclang-dev
  on a fresh machine — a fresh machine still needs
  the `apt-get install -y cmake libclang-dev` step
  above (the Boss-ordered sequence — try
  `LIBCLANG_PATH` first, apt only if it fails — is
  preserved as history; its outcome was that apt
  was needed and is sufficient). (b) Runtime lib vs
  dev symlink: the runtime package provides only the
  versioned soname (`libclang-18.so.18`, seen via
  ldconfig); bindgen needs the UNVERSIONED dev
  symlink `libclang.so` that only libclang-dev
  installs — pointing `LIBCLANG_PATH` at a directory
  holding just the versioned soname does NOT satisfy
  bindgen. This reconciles the two observations that
  looked contradictory: the file Boss saw existing
  was the dev symlink AFTER the install, while the
  `warm2` failure happened BEFORE the install, when
  no libclang of either kind was present.
- boring-sys first-build cost (measured on cue, 8
  CPUs): `cargo clean -p boring-sys` removed 5527
  files / 483.3 MiB, then `time LIBCLANG_PATH=
  /usr/lib/llvm-18/lib cargo build -p boring-sys`
  finished in real 0m 48.8 s (user 2m 27.2 s, sys
  0m 26.6 s), exit 0. Full cold workspace build:
  1m 31s–1m 35s (§M3.7, final verify).

## M3.10 — Fix loop vòng 1 (M3c, trên `feab242`)

Phase 3 review của M3 (technical FAIL với 2 blocking,
safety PASS với 2 non-blocking, red-team FAIL với 1
blocking) được sửa trong loop này. Mọi thay đổi đều
trong `rust/`, `NOTICE`, `docs/provenance.md`; không
đổi sha honk, không đổi toolchain pin (1.99.1), không
sửa Go, không wire CLI mạng, không WireGuard. Test
mới được viết ĐỎ trước rồi sửa cho xanh ở những chỗ
có thể (blocking T-B1/T-B2/R-B1 đều có test mới).

Blocking (đã sửa):
- T-B1 — `rpc.rs decode_response` theo đúng thứ tự Go
  `CallJSON`: chỉ `ok` BOOLEAN false mới lỗi; còn lại
  có `result` là trả `result` (kể cả `ok` vắng mặt hay
  non-bool). Test mới:
  `decode_result_without_ok_and_with_non_bool_ok`.
  Claim "verbatim" ở §M3.2 giờ mới đúng.
- T-B2 — `config.rs build_tls` phân biệt block vắng vs
  field vắng: `utls` vắng → `None` (default chrome);
  block có mặt → `Some(field.unwrap_or(false))` (thiếu
  field = tắt → `Unsupported`); reality chỉ bật khi
  `tls.enabled && reality.enabled == Some(true)`; TLS
  tắt ⇒ reality fields `None` (trước đây honk
  `TlsOptions::is_secure()` = enabled OR reality key
  present sẽ chạy REALITY handshake cho node tắt TLS).
  Test mới: `tls_presence_block_vs_field` (4 trường
  hợp: utls thiếu field → `Unsupported`; utls vắng →
  default; reality thiếu field → không key; TLS tắt +
  reality bật → không key; control dương: TLS bật +
  reality bật → có key).
- R-B1 — `http.rs` đọc body theo frame với cap trong
  lúc đọc (trước đây `collect()` rồi mới kiểm tra >
  16 MiB → OOM trước khi câu if chạy). Vượt cap →
  `Gateway` (exit 3, không retry được: retry sẽ tải
  lại đúng body quá lớn tới hết budget; quyết định
  này khớp class server-side failure của Go, và
  `BodySummary` cho trường hợp này mang
  `body_length` None — độ dài thật không biết, chỉ
  biết vượt cap — thay vì ghi MAX+1 như độ dài thật).
  Test mới: `oversized_body_is_gateway_exit_3_not_success`
  (17 MiB) và `endless_body_aborts_early_with_gateway_error`
  (chunked vô hạn, abort sớm, không đọc hết).

Non-blocking (đã sửa):
- N1 (= red NB1) — hyper handshake failure →
  `ConnectionDown` (chưa gửi byte request nào, Go
  "nothing sent"). Test trực tiếp cho nhánh handshake
  không quan sát được ở tầng HTTP/1.1 (xem [CHƯA XÁC
  MINH]); test mới pin phía đối chứng:
  `send_after_peer_close_is_connection_error_not_down`
  (lỗi SAU khi gửi là `ConnectionError`, không phải
  `ConnectionDown`).
- N2 — bật `serde_json` feature `arbitrary_precision`
  (chỉ `castctl-transport` dùng serde_json trong
  workspace nên an toàn); test mới
  `decode_numbers_beyond_u64_keep_literal` (2^64 và
  thập phân dài giữ literal; `json!` không tạo được
  số > u64 nên fixture là JSON text thô).
- N3 (= red NB5) — `body_to_query` implement `%v` cho
  giá trị lồng (`pythonStr` default branch): array
  `[elem elem]`, object `map[k:v …]` key đã sort,
  bool lồng `true`/`false` (khác top-level
  `True`/`False`), null lồng `<nil>`; doc cũ "Go does
  not define" là SAI và đã sửa. Test mới
  `get_body_to_query_nested_python_str`; test cũ assert
  nested → lỗi đã đổi theo.
- N4 — `routes.rs` doc sửa: duplicate bị drop, `len()`
  đếm distinct (không còn câu "duplicates still count
  toward the total").
- N5 — `tests/common/mod.rs` bỏ field
  `RequestRecord.headers` (không test nào đọc) + code
  populate nó; header vẫn được parse local để lấy
  `content-length`.
- N6 — KHÔNG đổi code; doc đã có trong `error.rs`
  (`Unsupported`: "CLI layer must map config
  rejections to 2 itself") và đã bổ sung vào §M3.2 —
  trạng thái: documented/verified.
- Safety NB-1 — `HttpResponse` viết tay `Debug` chỉ in
  status + body length (mẫu `BodySummary`); test mới
  `http_response_debug_hides_headers_and_body`
  (Set-Cookie + body secret không xuất hiện).
- Safety NB-2 — bỏ field `location` khỏi
  `RedirectRefused` (thành unit variant): grep xác
  nhận không code nào trong crate đọc field (chỉ doc
  ở `http.rs`, code tạo lỗi, và test dùng pattern
  `{..}`); pattern test đã đổi thành unit.
- Red NB2 — `DirectDialer`: timeout 10s của 1 addr
  không còn trả `Timeout` ngay; thử hết addrs, hết
  thì `ConnectionDown`. Test mới
  `direct_dialer_unanswered_address_is_connection_down_not_timeout`
  (10.255.255.1, tối đa 10s khi thật sự treo) và
  `direct_dialer_falls_back_to_working_address`
  (localhost, caveat thứ tự resolver — xem dưới).
- Red NB3 — `call_json` bọc toàn bộ `run_with_retry`
  trong `tokio::time::timeout` bằng request timeout
  (overall cap; expiry → `Timeout`, không retry).
  Test mới `overall_timeout_caps_retrying_slow_failures`
  (server đóng không đáp: retry budget 5s, request
  timeout 300ms → lỗi `Timeout` sau ~300ms, đã retry
  ≥ 2 lần trước khi cap cắt).
- Red NB4 — `HonkDialer` lặp qua mọi addr thay vì
  chỉ `addrs[0]`. Test mới
  `honk_dialer_falls_back_to_working_address` (direct
  node qua registry, localhost; cùng caveat resolver).
- Red NB6 — KHÔNG đổi code `build_tls`: hai đường
  TLS khác nhau thật (xem §M3.3) — outbound parse
  theo sing-box pointer semantics, gateway DialTLS ép
  `Enabled=true` là việc M4. Trạng thái: documented.
- Red NB7 — nhãn "JA4" của M3b đổi thành JA4-like;
  cột JA4 CHUẨN (GREASE loại hoàn toàn) recompute
  từ cùng captures bằng script độc lập
  (`notes/parity/ja4std-m3c.py`, ngoài cây repo):
  Go TLS/REALITY
  `t13d1514h2_8daaf6152771_d8a2da3f94cd`, Rust TLS
  `t13d1712h2_5b57614c22b0_a7c1ad54107f`, Rust
  REALITY `t13d0310h2_55b375c5d22e_6fb7db78d84a`
  (ổn định ×5 mỗi hàng; ALPN = ký tự đầu+cuối của
  giá trị ALPN đầu tiên; biến thể first-of-first +
  last-of-last cho `h1` được ghi chú trong §M3.8).
  Kết luận parity (Go ≠ Rust) ĐỨNG dưới cả hai
  biến thể. `rust/NOTICE` + `docs/provenance.md`
  cập nhật nhãn tương ứng; root `NOTICE` không nhắc
  JA4 nên không đổi.
- Red NB8 — `44cd` (Go) / `4469` (Rust) là CÙNG ALPS:
  payload byte-identical `00 03 02 68 32` cả hai
  hàng, honk gắn ALPS ở 0x4469 (anchor
  research-honk). Mức tin cậy: đo từ .bin + anchor,
  chưa grep source utls nên không tuyệt đối. Sau khi
  hợp nhất ALPS, diff hàng TLS còn Go-only `0005` +
  `0012`; hàng REALITY còn Go-only `000b`, `0017`,
  `0023`, `ff01`.
- Red NB9 — ĐÃ CHỨNG MINH BẰNG THỰC NGHIỆM (không
  còn là giả thuyết): trên server đối chứng mới
  (sing-box v1.14.4, hysteria2 127.0.0.1:18900,
  cert tự ký SAN localhost + 127.0.0.1, echo
  18080), client dispatch-default tái hiện đúng lỗi
  M3b (`QUIC connect to 127.0.0.1:18900 (attempt
  3)`); cùng client chỉ khác
  `quic.tls.skip_cert_verify = true` (đặt qua
  `Node::tls_mut()` trong harness chỉ-trên-cue, không
  qua dispatch) thì dial OK + echo "ok" (2 byte
  [111, 107]). Kết luận: chẩn đoán "content
  mismatch" của M3b bị BÁC — nguyên nhân là verify
  chứng chỉ client-side (honk chỉ tin webpki roots,
  không dùng system store). Verdict cập nhật: QUIC
  qua DISPATCH vẫn FAILED (dispatch không có đường
  skip verify); bản thân stack QUIC của honk đã
  ĐƯỢC CHỨNG MINH là làm việc khi skip verify.
  Wording §M3.8 đã sửa theo; artifact:
  `notes/parity/quic_m3c.rs` (harness, sha256
  741f9118…e0de0d, byte-identical với bản chạy
  trên cue), `quic-m3c-runs.log`,
  `quic-m3c-server.log` (server log không có
  connection cho case lỗi, có đủ connection + data
  path cho case pass). Go control KHÔNG chạy lại
  trong M3c: run Rust pass trên cùng server đã thay
  vai trò chứng minh server làm việc. Follow-up
  (ngoài loop): map `tls.insecure` → skip_cert_verify,
  explicit opt-in only — xem §M3.3.
- Red NB10 — chỉ document (§M3.3 watch-item M4):
  `HonkDialer::new` bypass validation +
  `apply_tls_mode`; node QUIC không bao giờ qua
  `apply_tls_mode` nên mode QUIC-TLS luôn là default
  của honk. Không đổi API.
- Red NB11 — `rust-version` 1.85 → 1.98 trong
  `rust/Cargo.toml` (workspace duy nhất có dòng này;
  mọi crate con đều `rust-version.workspace = true`);
  §M3.9 thêm tiền đề rustup shim (cargo standalone
  bỏ qua `rust-toolchain.toml`, kẹt 1.97.1 → fail
  aya khó hiểu). §M3 intro (dòng 998) giữ nguyên
  1.85 vì đó là record lúc nộp M3, không viết lại
  lịch sử.
- Red NB12 — §M3.9 làm rõ: (a) lần thử LIBCLANG_PATH
  có sẵn libclang-dev nên không chứng minh nó thay
  được libclang-dev trên máy mới (máy mới vẫn cần
  apt cmake + libclang-dev; thứ tự Boss chỉ đạo giữ
  nguyên như lịch sử); (b) runtime lib (versioned
  soname `libclang-18.so.18`) vs dev symlink
  (`libclang.so`, chỉ libclang-dev mới có) mà bindgen
  cần — hòa giải: file Boss thấy tồn tại là dev
  symlink SAU khi cài, lỗi `warm2` xảy ra TRƯỚC khi
  cài khi chưa có libclang nào.
- Red NB13 — chỉ document (§M3.3 + doc variant trong
  `error.rs`): 3xx → `RedirectRefused` exit 1 hiện
  tại; M4 phải chốt 1 vs 3 explicitly. Không đổi code.
- Red NB14 — `decode_base64url` siết cho khớp Go:
  whitespace bất kỳ đâu → lỗi (Go chỉ bỏ qua \r\n
  nhưng key thật không chứa whitespace nào nên siết
  toàn bộ là fail-closed, đã ghi rõ trong doc),
  độ dài ≡ 1 mod 4 → lỗi, bit thừa ≠ 0 → lỗi, data
  sau padding và padding sai độ dài → lỗi. Padding
  đúng chuẩn vẫn được chấp nhận (key test cũ
  43×`A` + `=` vẫn pass). Test mới
  `base64url_rejects_what_go_rejects`.

Clippy repair ngoài danh sách finding (bắt buộc để
gate xanh, hệ quả trực tiếp của NB11): nâng
`rust-version` 1.85 → 1.98 làm clippy 0.1.99 BẬT LẠI
lint `collapsible_if` dạng let-chain (với MSRV 1.85,
clippy kìm lint này vì let-chain cần rustc ≥ 1.88;
với 1.98 thì lint bật) — 22 lỗi ở code M1/M2 không
đụng tới (castctl-config 18, castctl-shared 4) làm
gate clippy fail ở vòng đầu. Bằng chứng cơ chế:
chạy clippy trên cây pristine `feab242` (MSRV 1.85)
trên cue → exit 0, 0 lỗi, trong khi cùng lệnh trên
cây M3c → 22 lỗi; toolchain giống nhau (rustc
1.99.1, clippy 0.1.99). Cách sửa: `cargo clippy
--fix --workspace` trên cue (tổng 40 chỗ: 18 config
+ 4 shared + 10 log-redact + 3 cli + 5 transport
— config 2, http 2, retry 1 — trong đó các crate phụ
thuộc chỉ lộ lỗi sau khi root đã sửa, vì vòng gate
đầu dừng ở config/shared trước), sync ngược về
local, review toàn bộ diff: mọi hunk đều là collapse
if lồng thành let-chain (`if A { if let … }` →
`if A && let …`), không dòng logic nào bị xóa hay
đổi (chỉ header `if` và dấu `}` thừa biến mất;
semantics short-circuit giữ nguyên). Các file đổi
thêm ngoài danh sách finding: castctl-config (5
file), castctl-shared (2), castctl-log-redact (3),
castctl-cli (2) — tất cả đều chỉ chứa collapse cơ
học này, không sửa logic, không đổi API. Không dùng
`#[allow]` để bịt lint.

Gate trên cue ở head M3c (chạy từ `/tmp/castctl-rust-m3`,
cargo shim 1.99.1 nhờ `rust-toolchain.toml`, trên đúng
cây sẽ commit):
- `cargo fmt --check` exit 0 (sau `cargo fmt` trên
  cue: vòng đầu fmt exit 1 vì output của `cargo
  clippy --fix` không đúng rustfmt — toàn bộ diff
  fmt chỉ đặt lại dấu `{` của let-chain, không đổi
  logic; sau fmt, cả 4 gate chạy lại trên cây này).
- `cargo build --workspace` exit 0.
- `cargo test --workspace` exit 0: 242 passed, 0
  failed (229 cũ + 13 test mới: transport lib 34,
  rpc 12; xem §M3.10 trên).
- `cargo clippy --workspace -- -D warnings` exit 0,
  0 error.
Vòng gate trước fmt (cùng cây trừ whitespace fmt)
cũng cho build 0 / test 242 / clippy 0, chỉ fmt 1 —
nên số test không đổi sau fmt.

[CHƯA XÁC MINH] (giữ nguyên tới khi có bằng chứng):
- Thứ tự resolver trong test fallback NB2/NB4: nếu
  resolver trả 127.0.0.1 trước, test pass mà không
  exercise fallback thật — giới hạn này được ghi
  trong test và báo cáo, không giấu.
- QUIC Initial decrypt (phân tích ALPN/transport
  params/SNI từ capture blackhole): chưa làm trong
  M3b và chưa làm trong M3c; sau kết quả NB9 thì
  phân tích này không còn cần để xác định nguyên
  nhân (cert verify đã chứng minh), nhưng vẫn là
  việc mở nếu ai muốn đối chiếu payload Initial.

Đã xác minh trong M3c (không còn trong danh sách
trên):
- Hyper 1.8.1 `Builder::handshake` (http1) chỉ tạo
  channel + Conn + Dispatcher rồi trả `Ok`, không
  thực hiện I/O nào — đọc trực tiếp source trên cue
  (`/usr/local/cargo/registry/src/.../hyper-1.8.1/
  src/client/conn/http1.rs:514-570`). Đây là cơ sở
  cho nhận xét "test trực tiếp nhánh handshake là
  không quan sát được ở tầng HTTP/1.1".
- Sing-box v1.14.4 `option/tls.go` trên cue module
  cache: `UTLS *OutboundUTLSOptions` và `Reality
  *OutboundRealityOptions` (dòng 134-135, pointer),
  `OutboundUTLSOptions.Enabled bool` (247-249) và
  `OutboundRealityOptions.Enabled bool` (252-256,
  plain bool) — tự kiểm, không còn dựa vào
  technical review cho claim này.

## M3e — TLS/REALITY fingerprint + QUIC insecure opt-in (one measurement round)

Scope: branch `feat/rust-m3e-fingerprint`, base `dev-rust`
`e89ebe3` (M1/M2/M3 merged). One measurement round only, per the
Boss brief: pull the Rust TLS/REALITY fingerprint as close to the
Go one as the boring/honk API allows, and open the QUIC path by
mapping `tls.insecure` to honk's `quic.tls.skip_cert_verify`.
No Go code changed, honk sha unchanged (`9e31cc0`), no honk
fork/vendor/patch. Harness reused from M3 (copied, not edited in
place): `listener.py` / `parse.py` (JA4-like) /
`ja4std-m3c.py` (standard JA4, FoxIO) / `run_tls.sh`
(`$D=/tmp/m3e-parity`, Go scratch clone `/tmp/parity-go`,
Rust binary `/tmp/castctl-rust-m3e/rust/target/debug/examples/
parity_dial` — cue-only example, never committed). N=5 per
(side, row); JA3 is not compared (GREASE + presented order make
it vary per run); sets are compared GREASE-normalised.

### M3e.1 QUIC: `tls.insecure` → `quic.tls.skip_cert_verify` — CLOSED (dispatch-level for hysteria2/tuic; live-proven for hysteria2 only)

Change (`rust/castctl-transport/src/config.rs`, `dispatch_outbound`):
the hysteria2 and tuic arms no longer build `quic:
Default::default()`; they now build `QuicOptions { tls:
TlsOptions { skip_cert_verify: tls.enabled &&
tls.skip_cert_verify, sni:
tls.sni.clone(), ..Default::default() }, ..Default::default() }`
from the `build_tls` result already computed at `:481`
(`skip_cert_verify` = `get_bool(tls, "insecure").unwrap_or(false)`,
plain bool, absent = false, gated on the already-computed
`tls.enabled` in the two QUIC arms — fix-loop round 1, F1 →
fail-closed).

Two deliberate decisions, both recorded here:

- `sni` is mapped as well as `skip_cert_verify`. Honk's
  hysteria2/tuic dial paths take the QUIC TLS server name from
  `quic.tls.sni`, falling back to the node host
  (`honk-outbound/src/proxy/hysteria2/mod.rs:606-610`,
  `proxy/tuic.rs:457-462`; the name feeds `ssl.set_hostname` +
  `SSL_set1_host` in `quic/boring.rs:626-633`). Leaving `sni`
  unset would silently drop the configured `tls.server_name`
  for QUIC while the TCP/TLS arms use it. `sni` is a plain
  `Option<String>` with no ALPN interaction, so carrying it is
  safe.
- `alpn` is deliberately NOT copied. Honk's QUIC client config
  rejects a non-empty `tls.alpn` on QUIC nodes
  (`honk-outbound/src/quic.rs:348-353`, "TCP TLS ALPN is
  unsupported for QUIC; use protocol-specific ALPN"); the
  protocol ALPN (`h3` / `tuic`) is supplied by the dial path
  itself. Copying the whole `TlsOptions` would break QUIC dial
  for any node carrying a `tls.alpn` value.
- `tls.enabled=false` (or an absent `tls` block) on
  hysteria2/tuic is NOT turned into a dispatch error in this
  PR, although Go returns `ErrTLSRequired`
  (`sing-box@v1.14.4/protocol/hysteria2/outbound.go:50-57`).
  Honk's QUIC path never reads `tls.enabled` (grep over
  `honk-outbound/src/proxy/hysteria2/mod.rs`,
  `proxy/tuic.rs`, `quic.rs` = 0 hits), and no M3 test
  dispatches hysteria2/tuic at all, so adding the rejection
  would be new dispatch behaviour smuggled into a
  fingerprint-measurement PR. Recorded deviation: `skip_cert_verify`
  is true only when `tls.enabled` is true AND `insecure:true` is
  explicitly set (fix-loop round 1, F1: the carried value is gated
  on the already-computed `enabled` in the two QUIC arms); with
  `tls` absent/disabled, `skip_cert_verify` stays false, so a
  self-signed/private-CA server still fails verification; only a
  publicly-trusted cert would dial where Go refuses.
  A dispatch-level `ErrTLSRequired` equivalent is a separate
  decision for a later PR.

Test: red → green. New unit test
`config::tests::quic_insecure_maps_to_skip_cert_verify`
(hysteria2 insecure true/absent/false/no-tls/alpn +
enabled:false with insecure:true/absent, tuic true/absent)
failed before the fix (`config.rs:881`, "insecure:true
must set skip_cert_verify") and passes after. Fix-loop
round 1 added the two `enabled:false` cases; the
`enabled:false + insecure:true` case fails on the pre-fix
code (RED log `/tmp/m3e-fix1-red.log`, panic
"enabled:false + insecure:true must stay false") and
passes after the gate. One test-side
correction during green: a hysteria2 node with NO `tls` block
has `quic.tls.sni == None`, not `Some(host)` — `build_tls`
returns `TlsOptions::default()` when the tls object is absent,
so no server-name default is applied; honk falls back to the
node host at dial time, so the behaviour is still correct.

Live proof on cue (sing-box hysteria2 `127.0.0.1:18900`,
self-signed cert SAN `localhost` + `127.0.0.1`, echo TCP
`127.0.0.1:18080`; cue-only example `quic_m3e.rs`, NEVER
committed, dispatches the node JSON and does NOT call
`node.tls_mut()` — the only variable between cases is the node
JSON itself), 2026-11-05 05:51 UTC:

- Case 1, `tls.insecure:true` → `dispatched quic tls:
  skip_cert_verify=true sni=Some("localhost")`, `dial OK`,
  `echo: read 2 bytes: [111, 107]` (`"ok"`); server log gained
  `inbound connection from 127.0.0.1:36800`, `inbound
  connection to 127.0.0.1:18080`, `outbound/direct[direct]:
  outbound connection to 127.0.0.1:18080`.
- Case 2, `insecure` absent → `skip_cert_verify=false`,
  `dial err: connection down: QUIC connect to 127.0.0.1:18900
  (attempt 3)`; server log gained NO new inbound lines.
- Case 3, `insecure:false` → same failure as case 2
  (`attempt 3`, no new server-log inbound).

### M3e.2 TLS/REALITY re-measurement: QUIC change causes zero drift

Baseline (unmodified tree, 20/20 captures ok, 0 fail) and
re-measurement after the QUIC change (20/20 ok, 0 fail) are
IDENTICAL on every compared field (JA4-like, JA4 standard,
GREASE-normalised cipher/extension/group/key-share/version/
sigalg sets, SNI, ALPN) for all 20 (side, row, run) pairs.
Record lengths vary run to run (GREASE + key-share randomness)
and are not compared. The task's "40 captures" is an
arithmetic slip: the M3 design is 4 (side, row) combos × 5 runs
= 20 captures; both M3e rounds ran all 20.

| Row | Go JA4-like | Go standard | Rust JA4-like | Rust standard |
|---|---|---|---|---|
| TLS (trojan), before | `t13d1616h2_74c5f98c3854_f20eef27beb5` | `t13d1514h2_8daaf6152771_d8a2da3f94cd` | `t13d1814h2_4be38248e33f_2ecda25e495a` | `t13d1712h2_5b57614c22b0_a7c1ad54107f` |
| TLS (trojan), after | same | same | same | same |
| REALITY (vless), before | `t13d1616h2_74c5f98c3854_f20eef27beb5` | `t13d1514h2_8daaf6152771_d8a2da3f94cd` | `t13d0412h2_16c83510387f_a735005f8dcf` | `t13d0310h2_55b375c5d22e_6fb7db78d84a` |
| REALITY (vless), after | same | same | same | same |

Baseline matches the published M3 §1.7 numbers exactly on both
JA4 columns, so the harness/tree did not drift before the change.

Stable sets (run 1, GREASE shown as `0000`; identical before
and after):

- TLS Go: ciphers 16 (15+GREASE, no `c009`/`c00a`); ext
  `0005,000a,000b,000d,0012,0017,001b,0023,002b,002d,0033,44cd,
  fe0d,ff01` (+SNI/ALPN); groups `{GREASE,11ec,001d,0017,0018}`;
  key_share `{GREASE,11ec,001d}`; versions `{GREASE,0304,0303}`;
  sigalgs 8 (`0401,0403,0501,0503,0601,0804,0805,0806`).
- TLS Rust: ciphers 18 (17+GREASE, extra `c009,c00a`); ext as
  Go minus `0005,0012`, ALPS at `4469` instead of `44cd`
  (payload identical `00 03 02 68 32`); groups/key_share/
  versions/sigalgs identical to Go.
- REALITY Go: = TLS Go, except groups `{GREASE,001d,0017,0018}`
  and key_share `{GREASE,001d}` (group `11ec` dropped only).
- REALITY Rust: ciphers 4 (3+GREASE: `1301,1302,1303`); ext
  `0005,000a,000d,0012,001b,002b,002d,0033,4469,fe0d` (+SNI/ALPN,
  missing `000b,0017,0023,ff01` vs Go); groups
  `{GREASE,11ec,001d}`; key_share `{GREASE,11ec,001d}`;
  versions `{GREASE,0304}`; sigalgs 9 (Go's 8 + `0807`).

### M3e.3 Deviations — TLS (a)–(d) NOT closed in this round

Verified from the castctl side (this round): a grep over
`honk-config/src/` for `cipher_list|set_cipher|alps|ocsp|
signed_cert|sct` returns 0 hits — `TlsOptions` carries only
`enabled, sni, skip_cert_verify, ech_*, reality_*, pin_sha256,
alpn` (`honk-config/src/node/protocol.rs:10-22`) — and the
public honk-outbound TLS API is `set_tls_mode` /
`set_utls_imitate` (process-global) plus `build_connector(node)`
/ `build_reality_connector(chrome)` with no per-node
cipher/extension/ALPS parameters
(`honk-outbound/src/tls.rs:394-420,571,702`). The fixes below
all sit inside honk; per the brief they are recorded as
deviations, NOT patched, NOT forked, NOT vendored. Each needs a
Boss decision on a honk patch before it can close.

- **(a) Cipher list — deviation, needs honk patch.**
  Rust TLS sends 18 ciphers (17+GREASE) vs Go 15+GREASE; the
  extra two are `c009`/`c00a` (ECDHE-ECDSA AES-CBC-SHA).
  The API exists (`boring` 5.2.0
  `SslContextBuilder::set_cipher_list`, `src/ssl/mod.rs:1503-1511`)
  and honk already owns the exact Chrome string without those
  two suites (`CHROME_CIPHER_LIST`,
  `honk-outbound/src/tls.rs:143-152`) and already calls it in
  exactly one place — the REALITY connector (`tls.rs:715`).
  The plain-TLS path (`build_connector`, `tls.rs:571-...`)
  never calls it, so BoringSSL falls back to its default
  `"ALL"` (`deps/boringssl/ssl/ssl_lib.cc:434`,
  `include/openssl/ssl.h:1712-1714`), which includes the
  non-deprecated `c009`/`c00a` (`ssl_cipher.cc:170-184`).
  Fix (honk, +1 line): `builder.set_cipher_list(
  CHROME_CIPHER_LIST)?;` in `build_connector`. NOT done here.
- **(b) Extensions `0005`/`0012` — deviation, needs honk patch.**
  Rust TLS lacks status_request (`0005`) and
  signed_certificate_timestamp (`0012`); Go has both. There
  is NO generic "add a ClientHello extension" hook in
  BoringSSL (grep `add_clienthello_tlsext` in
  `deps/boringssl/include/openssl/ssl.h` = 0 hits), but the
  two dedicated APIs exist (`boring` 5.2.0
  `enable_ocsp_stapling` / `enable_signed_cert_timestamps`,
  `src/ssl/mod.rs:2053-2062`) and honk already calls both —
  but only in `build_reality_connector` (`tls.rs:717-718`),
  which is why the Rust REALITY row DOES carry `0005`+`0012`
  while the plain-TLS row does not. Fix (honk, +2 lines):
  the same two calls in `build_connector`. NOT done here.
- **(c) ALPS codepoint — deviation, needs honk patch.**
  Rust sends ALPS at `4469`, Go (Chrome 133) at `44cd`;
  payload is byte-identical (`00 03 02 68 32`). Honk
  hard-codes the old codepoint: `add_chrome_alps`
  (`honk-outbound/src/tls.rs:269-282`, doc comment admits
  "this compatibility choice is not parity") calls
  `SSL_set_alps_use_new_codepoint(ssl.as_ptr(), 0)`; `0`
  selects the old codepoint, `1` (also the BoringSSL
  default) selects the new one
  (`deps/boringssl/include/openssl/ssl.h:3499-3501`,
  `include/openssl/tls1.h:118-119`: 17513 = `0x4469`,
  17613 = `0x44cd`). Fix (honk, 1 argument): change `0` to
  `1`, or drop the call; `add_chrome_alps` is called from
  both the plain-TLS path (`tls.rs:201`) and the REALITY
  path (`reality.rs:125`), so one change fixes both rows.
  NOT done here.
- **(d) REALITY profile — deviation, forced by honk's own
  choices, needs honk patch + live interop probe.** Rust
  REALITY is TLS1.3-only with 3+GREASE ciphers, versions
  `{GREASE,0304}`, groups `{GREASE,11ec,001d}`, key_share
  `{GREASE,11ec,001d}`, 9 sigalgs (extra `0807`); Go REALITY
  keeps the full TLS profile and only drops group `11ec`
  (`sing-box@v1.14.4/common/tls/reality_client.go:137-165`:
  build HelloChrome_133, filter `X25519MLKEM768` out of the
  supported-curves and key-share extensions, rebuild). The
  Rust shape is forced by two honk choices, not by BoringSSL
  and not by the REALITY protocol (Go is the counterexample
  on the same protocol): (i) `build_reality_connector`
  sets min TLS 1.3 (`honk-outbound/src/tls.rs:712`,
  `set_min_proto_version(Some(SslVersion::TLS1_3))`, vs
  TLS 1.2 in `base_builder`, `tls.rs:476-488`), which makes
  BoringSSL skip the TLS-1.2 cipher loop entirely
  (`deps/boringssl/ssl/handshake_client.cc:147`) and drop
  the TLS-1.2-only extensions `ff01`/`0017`/`0023`/`000b`
  (`deps/boringssl/ssl/extensions.cc:705,858-862,940,1823`);
  (ii) `setup_reality_ssl` pins the groups list to
  `X25519MLKEM768:X25519` with 2 key shares
  (`honk-outbound/src/reality.rs:296-349`) and a sigalg list
  that deliberately differs from Chrome (comment in code:
  "deliberately differs from the Chrome-derived list").
  Fix (honk): relax min version to TLS 1.2 in
  `build_reality_connector` + change the groups list toward
  Go (drop `11ec`, keep `001d,0017,0018`). That is a
  handshake-behaviour change with interop risk (sealed
  session_id / resumption / HRR interaction via
  `reality_fixup_cb`, `reality.rs:255-295`, which seals once
  and refuses to re-seal), so it needs a live probe against
  a real REALITY server, not just a wire capture. NOT done
  here. [NEEDS-MEASUREMENT]

### M3e.4 Gates (cue, toolchain 1.99.1 per `rust/rust-toolchain.toml`)

- `cargo fmt --check` exit 0.
- `cargo build --workspace` exit 0.
- `cargo test --workspace` exit 0: 243 passed, 0 failed (242
  baseline + 1 new `quic_insecure_maps_to_skip_cert_verify`).
- `cargo clippy --workspace -- -D warnings` exit 0.
- `git diff --stat` only `rust/castctl-transport/src/
  config.rs` (+ `rust/PORTING.md` §M3e + `docs/provenance.md`
  §13 M3e note); no Go change, no honk sha change, no new
  dependency (NOTICE unchanged — no new dep was added).
- No new `unsafe`; no `unwrap()` on external input (the new
  test's `expect` calls guard test fixtures, as in M3).
- CI Go: not run for this branch in this round (no Go code
  changed); recorded as not run, not claimed green.

[CHƯA XÁC MINH] (carried from M3c, unchanged): QUIC Initial
decrypt analysis; resolver order in the NB2/NB4 fallback
tests. New in M3e: tuic live dial was NOT run (no tuic server
on cue; the tuic mapping is covered by the dispatch unit test
only, same code path as hysteria2 but a different honk dial
path — `proxy/tuic.rs:487`); the REALITY honk-patch interop
probe (§M3e.3(d)) was not run; Go CI for this branch was not
run.

# Porting notes — Rust M3d (userspace WireGuard)

## M3d.1 Crate map

| File | Contents |
| `castctl-transport/src/wireguard.rs` | `WireGuardConfig` / `WireGuardPeerConfig` (typed, sing-box spellings), `WireGuardDialer::new` + `impl Dialer`, `WgStream` (`AsyncRead`/`AsyncWrite`), one tokio pump task per dialer (`PumpCore`: boringtun `Tunn` + smoltcp `Interface` + `SocketSet`), hand-rolled DNS codec, `parse_wireguard_endpoint` JSON parser, unit tests |
| `castctl-transport/src/config.rs` | `dispatch_endpoint(endpoint, wireguard_dns)` + `Dispatch::WireGuard(Arc<WireGuardDialer>)`; the `wireguard` arm in `dispatch_outbound` STAYS an error (message updated to `"not an outbound type"`) |
| `castctl-transport/src/lib.rs` | `pub mod wireguard` + re-exports |
| `castctl-transport/tests/wireguard.rs` | REAL data-path tests: in-process boringtun server + smoltcp server stack + TCP echo, loopback only |

Design (one paragraph): a `WireGuardDialer` owns one tunnel
(one boringtun `Tunn`, one UDP socket to the peer, one smoltcp
`Interface`). A single tokio pump task owns the `Tunn` /
`Interface` / sockets; `dial()` and `WgStream` talk to it over
bounded channels (`CtrlMsg` control, per-stream data channels,
cap 64). The pump is driven by smoltcp `poll_delay` capped at
100 ms (never a fixed sleep alone). Backpressure: bytes already
consumed from smoltcp by `recv_slice` are ACKed — the peer
will never retransmit them — so a full stream channel parks
them in a bounded per-socket pending buffer (`pending_rx`,
plus `pending_eof` / `pending_failed`), retried on every cycle
before any new `recv_slice`; nothing already consumed is ever
dropped. (The M3d draft claimed "a full stream channel stops
the pump draining smoltcp, so … nothing is dropped" — that was
false: the drain ran first and the buffer was dropped on a
full channel. Loop 1 fixed it; see §M3d.10.) Half-close: app
shutdown defers the FIN (`shutdown_pending`) until the send
queue drains, then smoltcp `close()` (FIN); read stays open;
peer FIN → `poll_read Ok(0)`, observed promptly (the receive
loop also probes in CloseWait/FinWait2/TimeWait, where
`may_recv()` is false on an empty buffer — without the probe
EOF waited for the 10 s TIME-WAIT close timer). Tunnel
teardown → `ConnectionError` on the next read/write. Dropping
a stream aborts its socket and sends an RST (`abort_socket`:
the socket stays in the set for one more `poll` so smoltcp
emits the single RST, then it is retired — removing it in the
same cycle as `abort()` meant the RST was never sent, found
by the keepalive test, §M3d.10). `WgStream` holds an
`Arc<Tunnel>`, so dropping the dialer does not kill live
streams; the pump stops when the last `Arc<Tunnel>` drops (or
fatally errors, setting `dead` so the next dial rebuilds). One
overall `dial_timeout` (default 10 s, `DIAL_TIMEOUT`) covers
the WireGuard handshake + TCP connect inside the tunnel.

## M3d.2 Pins + versions + why

Workspace pins (exact, `rust/Cargo.toml` + `Cargo.lock`):

- boringtun `=0.7.1` (BSD-3-Clause, Cloudflare,
  <https://github.com/cloudflare/boringtun>, lock checksum
  `15dd6a8a89cbe8997f37ca0cf035e6ea4d64cd2ecea4aed83ffb9f99f7126939`):
  userspace WireGuard — the Noise_IKpsk2 handshake, session
  keys, data packet AEAD. `default-features = false`, no
  features: the `device` (TUN device, needs root) feature is
  NOT enabled by castctl-transport (boringtun's `default = []`,
  `device = ["socket2", "thiserror"]` in its `Cargo.toml:33-38`).
  The lock lists the `device` feature's optional deps
  (`ip_network`, `ip_network_table`, `nix`, `parking_lot`)
  because Cargo.lock records all possible deps; they are not
  built for this crate's use.
- smoltcp `=0.14.0` (0BSD,
  <https://github.com/smoltcp-rs/smoltcp>, lock checksum
  `b6f8b28ad56c6e35524a37dd492af5d1a47e31e1a4d175cd12f89c075f01980f`):
  userspace TCP/IP stack. Features: `std, log, medium-ip,
  proto-ipv4, proto-ipv6, socket-tcp, socket-udp,
  socket-tcp-cubic, async`. MSRV 1.91 (≤ 1.99.1); builds on
  1.99.1, so the D10 fallback (`=0.13.1`) was NOT needed.
- base64 `=0.22.1` (MIT OR Apache-2.0, lock checksum
  `72b3254f16251a8381aa12e40e3c4d2f0199f8c6508fbecb9d91f575e0fbb8c6`):
  strict Std-base64 decoding of WireGuard key strings
  (already in the lock via boringtun; no new crate entered
  the tree for M3d).

No boringtun / smoltcp source code is copied into `rust/`:
both are called as dependencies only (see `docs/provenance.md`
§14 for the full license inventory, taken from
`cargo metadata` on cue).

## M3d.3 Algorithm sources

- The Noise_IKpsk2 key schedule and the TCP state machine are
  NOT reimplemented: boringtun owns the handshake/session keys
  and smoltcp owns TCP/IP. This module only maps castctl
  config onto those two libraries and drives them.
- Handshake test method (test (a)): boringtun's own two-`Tunn`
  test shape (its `noise::tests` drive a client and a server
  `Tunn` against each other the same way). No fixed published
  vector is usable: handshake bytes contain ephemeral keys and
  timestamps, so no byte-stable vector exists to assert
  against; the deterministic-key handshake + data round-trip
  IS the proof.
- DNS codec: hand-rolled, RFC 1035 wire format (header + one
  question, A/AAAA answers). No new dependency, no EDNS, no
  CNAME chasing (documented limitation, §M3d.6).
- `Tunn` API facts verified against the 0.7.1 registry source
  on cue (not from docs.rs renderings):
  `Tunn::new(StaticSecret, PublicKey, preshared_key:
  Option<[u8; 32]>, persistent_keepalive: Option<u16>, index:
  u32, rate_limiter: Option<Arc<RateLimiter>>)` (infallible);
  `update_timers(&mut self, dst: &mut [u8]) -> TunnResult`;
  `encapsulate(src, dst)` (queues the packet + returns the
  initiation when no session exists);
  `decapsulate(src_addr: Option<IpAddr>, datagram, dst)`
  (repeat with an empty datagram until `Done`);
  `format_handshake_initiation(dst, force_resend)`;
  `time_since_last_handshake() -> Option<Duration>` (`Some`
  iff a session is established — the D6 signal, so the D6
  fallback was NOT needed);
  `TunnResult = Done | Err(WireGuardError) |
  WriteToNetwork(&mut [u8]) | WriteToTunnelV4(&mut [u8],
  Ipv4Addr) | WriteToTunnelV6(&mut [u8], Ipv6Addr)`.
  boringtun enforces NO AllowedIPs in `Tunn` (only in
  `src/device/`, unused) — the caller enforces them. No
  `set_preshared_key`: the PSK goes through `Tunn::new` only.
  Non-zero reserved bytes are rejected on ingress:
  `parse_incoming_packet` (`noise/mod.rs:128`) reads
  `packet_type = u32::from_le_bytes(src[0..4])` and matches
  `(1,148)/(2,92)/(3,64)/(4,_)`; non-zero reserved bytes 1–3
  make the type match nothing → `Err(InvalidPacket)`.
- smoltcp 0.14.0 API facts verified the same way:
  `Interface::new(Config, device, now)`,
  `poll` / `poll_delay -> Option<Duration>` / `poll_at` /
  `context()` / `update_ip_addrs` / `routes_mut()`;
  `Device` trait (`receive`, `transmit`, `capabilities()`);
  `RxToken::consume(f: FnOnce(&[u8]))`,
  `TxToken::consume(len, f: FnOnce(&mut [u8]))` (no timestamp,
  no Result in 0.14); `Medium::Ip`, `HardwareAddress::Ip`;
  `tcp::Socket::new(rx, tx)` with `SocketBuffer = RingBuffer`;
  `connect(cx, remote, local)`, `close()` (FIN), `abort()`
  (RST), `send_slice` / `recv_slice`, `may_send` / `may_recv`,
  `state()`, `register_recv_waker` / `register_send_waker`
  (`async` feature); `udp::Socket::new(rx, tx: PacketBuffer)`,
  `bind`, `send_slice(data, meta)`, `recv_slice`;
  `SocketSet::new(vec![])`, `add -> SocketHandle`.
  `IFACE_MAX_ADDR_COUNT = 8` (`lib.rs:157`).
  Routing: `route()` returns the destination itself when it
  is in the same network as an interface address, else
  `routes.lookup` (gateway). For `Medium::Ip`, `dispatch_ip`
  never calls `lookup_hardware_addr` (Ethernet/IEEE only), so
  the default-route gateway value is inert — M3d uses the
  first tunnel address as the gateway placeholder.
  `has_neighbor` returns true for any routed address under
  `Medium::Ip`.
- smoltcp 0.14 behaviours that differ from older docs (each
  found by a failing test, §M3d.8):
  `TcpSocket::connect` rejects local port 0
  (`Err(ConnectError::Unaddressable)`, `socket/tcp.rs:1032-1034`)
  — it does NOT assign an ephemeral port; the dialer takes
  ports from a process-wide IANA-range counter
  (`next_ephemeral_port`, 49152–65535).
  UDP `bind` rejects port 0 the same way
  (`BindError::Unaddressable`, `socket/udp.rs:219-221`).
  `SocketSet::get_mut` returns `&mut T` directly and panics
  on a stale handle (not `Option`); the pump guards it with
  its own map membership (a handle in the map always has its
  socket in the set — inserted together, removed together).
  tokio 1.48 has NO `PollSender` / `poll_ready` in mpsc
  (verified in the cue registry source); the write-waker
  slot is a manual `Arc<Mutex<Option<Waker>>>` instead.
- Loop-1 facts verified the same way (each found by a
  failing test, §M3d.8/§M3d.10): boringtun `decapsulate`
  returns `TunnResult::Err` (not a silent drop) for a
  garbage/replayed datagram (`Tunn::parse_incoming_packet`,
  `noise/mod.rs:128`), so the pump drops the datagram and
  the tunnel survives; `encapsulate` returns `Done` only
  when a handshake is already in progress
  (`format_handshake_initiation`, `noise/mod.rs:438-440`) —
  the packet was queued by `queue_packet` (depth-capped)
  and is retried, not lost; `update_timers` returns
  `Err(ConnectionExpired)` only after `set_expired()` +
  `clear_all()` (`timers.rs:168+`), so the `Tunn` is
  terminal and the pump must treat it as fatal + rebuild on
  next dial. smoltcp: `may_recv()` is `Established`, or
  `FinWait1|FinWait2`, else true only if the receive buffer
  is non-empty (`socket/tcp.rs:1197-1205`) — so in
  TimeWait/CloseWait/FinWait2 with an empty buffer a FIN is
  only observed by calling `recv_slice` (which returns
  `Finished` when `rx_fin_received`, `recv_error_check`,
  `:1302-1314`); `CLOSE_DELAY = 10_000 ms` (`:301`),
  `ACK_DELAY_DEFAULT = 10 ms` (`:300`); `close()` only
  moves `Established → FinWait1` (`:1084-1105`) — the FIN
  goes out after the transmit buffer drains, it does not
  discard it; `abort()` moves the socket to `Closed` and
  the NEXT `dispatch` sends exactly one RST and then clears
  the tuple (`:2830-2840`), so the socket must stay in the
  set for one more `poll` after `abort()` or no RST is ever
  sent. boringtun timers: `REKEY_TIMEOUT = 5 s`,
  `KEEPALIVE_TIMEOUT = 10 s` (`timers.rs:22-23`); the
  non-persistent keepalive fires only when data was
  received but nothing sent for 10 s; the persistent
  keepalive fires every `persistent_keepalive` seconds.
  smoltcp's initial retransmit timeout is ~1 s (observed:
  the fake server retransmits an un-ACKed echo at ~1009 ms).

## M3d.4 MTU arithmetic

- Tunnel MTU default 1408 (sing-box default,
  `transport/wireguard/endpoint.go:103-105`: `if options.MTU
  == 0 { options.MTU = 1408 }`); absent/0 → 1408, >65535 →
  `Validation`.
- Inner IP packet ≤ MTU. boringtun adds exactly 32 bytes per
  data packet: 4 (type) + 4 (sender index) + 8 (counter) + 16
  (AEAD tag). Outer UDP datagram ≤ MTU + 32, plus outer IP/UDP
  headers (20 + 8 for IPv4, 40 + 8 for IPv6) on the wire.
- Every `encapsulate` output buffer is at least 148 bytes
  (`WIREGUARD_MIN_DATAGRAM`): with no session yet,
  `encapsulate` formats a 148-byte handshake initiation into
  the SAME buffer (`noise/mod.rs:264-267`), so a smaller
  buffer (e.g. a 40-byte SYN + 32 = 72) fails the first packet
  with `Err` instead of queuing it (found by a failing test,
  §M3d.8). `format_packet_data` PANICS on a too-small buffer
  (`session.rs:196-199`), so the 148-byte floor is also the
  panic guard.
- smoltcp device MTU = tunnel MTU. smoltcp TCP socket buffers
  (64 KiB each way) are independent of the MTU; they bound
  in-flight stream data, not the wire packet size.

## M3d.5 DNS behaviour

- Domain dial targets resolve ONLY through `wireguard_dns`
  servers, inside the tunnel, over a smoltcp UDP socket:
  A query first, then AAAA if the A query answers nothing;
  servers tried in order; one query at a time per dial;
  timeout = the outer `dial_timeout` (no separate DNS
  budget); responses matched by transaction id.
- DNS failover (loop 1): a server that answers with an
  error (or, for a dead server, the dial timeout) does NOT
  end the lookup — the next server in `wireguard_dns` is
  tried. A dead first server still consumes the dial
  timeout (no per-query timeout; deferred, §M3d.10).
- Transaction ids start per pump core/tunnel from a seed
  (wall-clock nanoseconds plus a process-wide counter,
  never 0) and then increment sequentially, one per query,
  within that core — so txids ARE sequential within one
  tunnel and only the starting value differs between
  cores/tunnels; replies are checked for txid, question
  name, question type, AND source address (a reply from an
  address other than the queried server is ignored and the
  query stays pending). The TC (truncated) bit yields no
  answer — there is NO TCP fallback for truncated DNS
  replies (documented limitation).
- A `wireguard_dns` server entry may carry a `:port`
  suffix, but the query ALWAYS goes to port 53: Go's
  `buildWireGuardDNSOptions`
  (`internal/profile/dns.go:392-412`) hardcodes
  `server_port: 53` for every server regardless of the
  entry text, and `validateWireGuardDNS` (`:585+`) accepts
  any non-empty server string with no port validation — so
  ignoring the port IS Go parity, not a deviation. A
  hostname entry with a `:port` suffix has the suffix
  stripped for the bootstrap lookup only (the query port
  is still 53).
- DNS queries are NOT subject to the dial-time allowed-IPs
  check: the server is config-specified, not a dial target
  (S5). The bootstrap cache for hostname servers is
  per-dialer-lifetime; the config is static, so a cached
  bootstrap never goes stale within a dialer's life (NB3).
- No `wireguard_dns` → fail-closed `ConnectionDown`, NEVER a
  system-resolver fallback for the target (Go
  `internal/outbound/dialer.go:127-145` `ErrNoResolver`).
- A `wireguard_dns` SERVER given as a hostname bootstraps
  ONCE via the system resolver (`tokio::net::lookup_host`)
  and is cached — the Go `bootstrap.go` rule, and the ONLY
  system-resolver use in the dialer. Dial targets and the
  peer endpoint never go through it.
- CNAME is NOT chased: a response carrying only a CNAME (no
  address record of the requested type) yields no IP.
- The DNS sockets bind to the tunnel address of the server's
  family, NOT 0.0.0.0: smoltcp's UDP egress uses the BOUND
  address as the packet source, so a 0.0.0.0-bound socket
  emits queries with source 0.0.0.0 and the reply can never
  come back (found by a failing test, §M3d.8). With no tunnel
  address of that family, the query fails fast instead of
  hanging until the dial timeout.

## M3d.6 Deviations from Go (deliberate, with citations)

- Single peer only (parent D1): 0 peers → `Validation`
  (stricter than Go, which accepts 0 peers at creation and
  fails only at dial — a dialer with no peer can never dial);
  2+ peers → `Unsupported` (boringtun `Tunn` is a
  single-peer state machine).
- `system:true` → `Unsupported` with the Go RUNTIME text
  verbatim (`internal/outbound/manager.go:486-488`):
  `"outbound: wireguard endpoint with system:true is
  rejected: userspace WireGuard only"`. The parse-layer text
  (`internal/profile/config.go:296-298`) is a different layer
  and is not used here.
- Domain peer endpoint → `ConnectionDown` at first dial,
  never system-resolved (parent D4; Go probe §M3d.7).
- Domain dial target with no `wireguard_dns` →
  `ConnectionDown` (see §M3d.5).
- Non-zero `reserved` → `Unsupported` (boringtun rejects
  non-zero reserved on ingress, §M3d.3; patching the outgoing
  bytes would break the handshake against any boringtun
  peer, so there is no patch path — the in-process proof the
  parent asked for cannot exist).
- wg-quick spellings in endpoint JSON → `Validation` "did you
  mean …" (parent D2): `preshared_key` → `pre_shared_key`,
  `persistent_keepalive` →
  `persistent_keepalive_interval`, a single `endpoint` string
  → peer `address` + `port`. Never silently ignored.
- Any non-empty `detour` → `Unsupported` (M3 rejects all
  detours; `listen_port` + `detour` also conflict in Go).
- Tunnel `address` required, non-empty (parent D8); a bare IP
  is rejected — sing-box JSON uses `netip.ParsePrefix` ONLY
  (the bare-IP → `/32`/`/128` rule exists only in castctl's
  wg-quick converter,
  `internal/outbound/wireguard_conf.go:247`, not in the JSON
  schema).
- `address` / `allowed_ips` (and any other Listable-typed
  field) accept a bare string as a one-element list
  (sing-box `Listable` shorthand), as well as the array form
  (loop 1 fix: the M3d draft rejected the bare string — that
  rejection was a deviation, now fixed; §M3d.10).
- Wrong-typed JSON fields are `Validation` naming the field,
  never silent defaults (loop 1 fix, §M3d.10): a
  present-but-wrong-typed `mtu` / `keepalive` /
  `listen_port` / `system` / `reserved` / `detour`, or a
  non-string element in a string array, is a hard parse
  error (Go JSON-unmarshals into a typed struct, so a
  wrong-typed field is a hard parse error there too).
- Tunnel address count ≤ 8 (smoltcp `IFACE_MAX_ADDR_COUNT`,
  §M3d.3); smoltcp silently drops a 9th address, so the
  dialer rejects longer lists fail-closed.
- `persistent_keepalive_interval` in seconds, 0 = disabled;
  passed as `Option<u16>` to `Tunn::new` (`None` when 0).
- Allowed-IPs checked by the CALLER at dial time (target IP
  must be inside the union of `allowed_ips`, family-strict,
  before any packet is sent); boringtun `Tunn` enforces
  nothing (§M3d.3).
- Handshake signal: `time_since_last_handshake()` (§M3d.3);
  the D6 fallback (TCP connect immediately under the overall
  timeout) was NOT needed.
- Keys are `[u8; 32]` after strict Std-base64 decode; the
  `Debug` impls for config/dialer print lengths/presence
  only, never key bytes; no key material appears in any
  `Display`/`Debug`/error string (string-catch test).
- Test keys are self-generated from fixed FAKE seeds only
  (repeated-byte patterns); test names carry the `fake_`
  prefix so a grep finds them as test-only.

Loop-1 documented items (not code changes; reasons in the
plan's triage):

- Ingress allowed-IPs are NOT enforced (T-NB2): boringtun
  `Tunn` does not enforce them (§M3d.3); a decryptable
  packet is from the peer by construction, and smoltcp
  drops packets not addressed to the interface.
- Two tunnel addresses (NB6): ALL configured addresses go
  on the smoltcp interface, but the FIRST address of each
  family wins as the default-route gateway placeholder AND
  the DNS socket bind address; a second address of the same
  family is present for inbound matching but never used as
  an egress/DNS source.
- No NAT rebinding (NB11): the peer endpoint is fixed at
  dial time; the pump never re-resolves or re-binds it.
- The outer UDP socket binds the wildcard address (NB16):
  normal for a client; the peer address is fixed per dial.
- No concurrent-stream cap (S12): known limitation — any
  number of streams may share one dialer/tunnel; no
  backpressure exists between streams except the shared
  64 KiB socket buffers and the per-stream 64-message
  channels.
- `poll_read` returning `Ok(0)` on an empty buffer is the
  standard `AsyncRead` shape (T-NB8): it means "no data
  right now, poll again", not EOF; EOF is signalled only by
  the `Eof` message. Latent only.
- A tiny MTU is not rejected (NB5): Go parity — the dial
  times out instead of failing fast at parse time.
- A single bad datagram vs a fatal error (S7): covered by
  the R-B4 fix — a bad datagram is dropped, the tunnel
  survives; only UDP transport (socket) errors stay fatal.
  boringtun returns `TunnResult::Err` for a bad datagram
  (it does not silently drop it), so the drop is the
  pump's decision, documented here.
- `encapsulate` returning `Done` (NB22, measured): the
  packet was queued by boringtun (`queue_packet`,
  depth-capped) and is retried via `send_queued_packet`
  on the empty-datagram drain — queued, not lost.
- Timer expiry (NB23, measured): `update_timers` returns
  `Err(ConnectionExpired)` only after the session is
  terminal (`set_expired()` + `clear_all()`), so fatal +
  rebuild-on-next-dial is correct; there is no
  recover-in-place path.
- Unbounded queues (NB12/S13, deferred — see §M3d.10):
  the per-stream channels are bounded (64 messages); the
  smoltcp socket buffers are 64 KiB each way; the pump
  drains at most 4 chunks per cycle per direction. No
  drop policy for TCP data is invented — a slow reader
  stalls the sender via the TCP window, it does not lose
  data.

## M3d.7 D4 Go probe (domain peer endpoint, on cue)

Scratch test `TestZZD4DomainPeerNoDNSRouter` (tags
`with_utls,with_quic,with_wireguard,with_gvisor`, scratch
copy at `/tmp/d4-probe`, source
`~/workspace/tmp/zz_d4_probe_test.go`, never in the repo
tree): WG endpoint, peer address `"localhost"` (domain), no
DNS router registered, `m.Start()` then direct
`m.Endpoint("wg").DialContext(tcp, 10.0.0.1:80)`. **Go
PANICS** — nil pointer dereference at
`protocol/wireguard/endpoint.go:117` (`ep.dnsRouter.Lookup`
on nil router), via `transport/wireguard/endpoint.go:229`
(`SetEndpointResolverFunc`) ← `device/peer.go:412`
`resolveEndpoints` ← `SendHandshakeInitiation`. Go does NOT
bootstrap a domain peer via the system resolver; it fails
closed (catastrophically). Per parent D4, M3d fails closed
on a domain peer endpoint — `ConnectionDown` at first dial,
never system-resolver bootstrap for the peer. DNS *server*
hostnames (`wireguard_dns` entries) still bootstrap once via
the system resolver (Go `bootstrap.go` rule, distinct from
the peer endpoint).

Side observation (out of scope, NOT probed further):
creating the synthetic `castctl-dialer` outbound as
`runtime.go:500-515` does (`direct` + `Detour = <endpoint
tag>`) fails in the probe with ``outbound: create
direct[via-wg]: `detour` is not supported in direct
context`` — sing-box `protocol/direct/outbound.go:55`
rejects any non-empty Detour in a direct outbound. Whether
the production runtime path hits this was NOT probed; the
D4 probe bypassed it by dialling the endpoint directly.

## M3d.8 Tests + fail-before proofs

Unit tests (`wireguard.rs`, 40 — the M3d draft said 27, the
actual count at the draft commit was 28; loop 1 fixed the
count, T-NB5, and added one more, the S6 hostname-strip
test, I10) + config tests (3 new) + integration tests
(`tests/wireguard.rs`, 16): (a) two-`Tunn` handshake + data
round-trip with deterministic fake keys; (b) REAL data path
— boringtun server + smoltcp server stack + TCP echo,
loopback only, small echo + 64 KiB payload across MTU 1408
intact (max UDP datagram asserted ≤ MTU + 32 + outer
headers; measured max 1440), keepalive PINNED BY COUNT (keepalive=1 emits ≥2
datagrams in a 3 s idle window, keepalive=0 emits 0 — the
old sleep-2.5-s-and-re-dial shape passed with keepalive
disabled and pinned nothing, so it was replaced), slow
reader (1 MiB echo with no reads for 500 ms, byte-exact),
EOF after a full channel (576 KiB + FIN, slow drain of one
8 KiB read per 150 ms — longer than the pump's 100 ms
`PUMP_TICK_CAP`, so the EOF `try_send` hits `Full` and
must be retried via `pending_eof`; a 10 ms drain does not
pin this, see the I2 entry in the fail-before log — byte-exact, no
hang), stream survives its dialer being dropped, bad
datagram (garbage + oversized + spoofed-source) does not
kill the tunnel, both-sides-same-nonstandard-PSK control,
DNS failover to the next server, DNS server port ignored
(Go parity; the hostname-`:port` strip is pinned by a unit
test, `localhost:5353` → loopback, since the `SocketAddr`
arm already handled IP:port before loop 1), IPv6 AAAA + TCP echo end-to-end
(fd00::1 / ::1); (c) `system:true` rejected via `new()` and
via `dispatch_endpoint` with the exact Go text; (d) one test
per required field (private_key, peer public_key, peer
address, peer port, address, allowed_ips) + malformed
base64 + wrong-length key; (e) PSK present vs absent both
echo, plus the negative case (client PSK set, server unset)
FAILS the handshake; (f) no-leakage string-catch test
(base64, decimal, hex, and URL-safe base64 forms of the
fake keys); (g) allowed-IPs dial-time rejection before any
packet (server received zero datagrams). Target: in-tunnel DNS
(`echo.test` → 10.0.0.1 via the fake in-tunnel DNS
responder) + domain-target-without-DNS fail-closed +
domain-peer fail-closed (against a LIVE server on
`localhost`, so a system-resolving dialer would succeed
and fail the test).

Fail-before proofs: every test above has one, in
`~/workspace/tmp/castctl-rust-m3d-notes/writer-fail-before-loop1.log`
(one revert at a time, that test alone; the M3d draft's log
`writer-fail-before.log` had cross-batch contamination and
is superseded for the loop-1 tests).
Bugs found BY the tests while writing M3d (all fixed in the
same commit, each with a fail-before entry proving the test
catches it):

1. `Prefix::contains` shifted `u32::MAX << 32` for a `/0`
   prefix (debug overflow panic) — `0.0.0.0/0` is the
   commonest `allowed_ips` value, so this would have panicked
   on the first real dial.
2. `encapsulate` buffer too small (§M3d.4, 148-byte floor).
3. TCP `connect` with local port 0 (§M3d.3).
4. DNS socket bound to 0.0.0.0 (§M3d.5).
5. The leakage string-catch initially only covered the base64
   form; a derived `Debug` (decimal bytes) slipped through —
   the test now also asserts the decimal forms
   ("170, 170" / "187, 187" / "34, 34"), plus hex and
   URL-safe base64 forms (loop 1, NB21).
6. Deferred shutdown (loop 1, found by the EOF test):
   `ShutdownWrite` processed while data was still queued
   called `close()` immediately, and `may_send()` is false
   after `close()` — so the queued data could never be fed
   into smoltcp and the stream stalled forever. The pump
   now defers the FIN (`shutdown_pending`) until the send
   queue drains (the fake echo server had the same stall
   shape and was fixed the same way).
7. EOF tail loss (loop 1, found by the EOF test — a
   HARNESS bug, not a pump bug): the fake echo server
   closed its socket as soon as `pending_echo` emptied,
   while 1240 bytes still sat unread in its smoltcp
   receive buffer (the close check ran before the receive
   loop in the same cycle); once `LastAck`/`Closed` the
   echo arm never runs again, so the tail was lost and the
   client saw a clean EOF 1240 bytes short. The server now
   closes only when the receive buffer is also drained
   (`!sock.may_recv()`); re-measured with the slow drain
   the loss is 65,488 bytes — ~one full smoltcp receive
   buffer (I4).
8. RST never sent on abort (loop 1, found by the keepalive
   test): `abort()` + immediate removal from the socket
   set meant smoltcp never emitted the RST; the peer only
   learned the connection died via its own ~1 s RTO
   retransmit, and the RST that answered it came from the
   interface (unknown tuple), not the socket. The pump now
   retires aborted sockets one poll later
   (`abort_socket`, `closing_prev`/`closing_next`).
9. Prompt EOF (loop 1, found by the EOF test): the
   receive loop only ran while `may_recv()` was true, so
   after the buffer drained in TimeWait/CloseWait/FinWait2
   `Finished` was never observed and EOF waited for the
   10 s TIME-WAIT close timer (the fast-drain EOF test took
   10.7 s; with the probe 0.67 s). The loop now also probes
   in those states. (The EOF test now takes ~20 s total
   because the slow drain — one 8 KiB read per 150 ms —
   dominates; the EOF itself arrives promptly.)

## M3d.9 Chưa kiểm chứng

- No real WireGuard peer tested outside the process: no
  sing-box peer, no real server, no interop claim. The
  in-process boringtun server is the only peer the dialer
  has ever spoken to.
- IPv6 is end-to-end tested IN-PROCESS only (AAAA + TCP
  echo over fd00::1 / ::1, loop 1): no real v6 peer, no
  v6 DNS server, no v6 traffic outside the process.
- No real DNS server: only the fake in-process responder
  (A → 10.0.0.1, AAAA → fd00::1 on v6). No test against a
  real resolver, no CNAME-chasing need ever exercised.
- Keepalive is proven by PACKET COUNT (loop 1): ≥2
  datagrams in a 3 s idle window with keepalive=1, 0 with
  keepalive=0. The count pins the client pump's
  boringtun keepalive, not the session lifetime.
- No concurrent multi-stream test (two streams on one
  dialer at once); no custom-MTU test (all tests use the
  1408 default); no performance measurement (throughput /
  latency / CPU).
- The D4 side observation (direct + detour rejected by
  sing-box, §M3d.7) was NOT probed further; whether the
  production runtime path hits it is unknown.
- `dial_timeout` is a single overall budget; per-phase
  budgets (handshake vs DNS vs TCP connect) do not exist.
  A dead first DNS server consumes the whole dial timeout
  (no per-query timeout; S10 deferred, §M3d.10).

## M3d.10 Fix loop 1 (2026-11-05, on top of `8f62c68`)

Blocking findings fixed (one line each; file:line is at the
loop-1 commit, test name + isolated fail-before in
`writer-fail-before-loop1.log`):

- T1/R-B1 receive backpressure data loss
  (`wireguard.rs`, `SockState::pending_rx` +
  `flush_pending`): bytes already consumed by `recv_slice`
  are held and retried instead of dropped on a full
  channel. Test: `fake_wireguard_slow_reader_no_data_loss`.
- T2 EOF loss (`wireguard.rs`, `pending_eof` /
  `pending_failed`): EOF/Failed are queued and retried
  until delivered; `eof_sent` is never set before
  delivery. Test: `fake_wireguard_eof_after_full_channel`.
- T3 Listable shorthand (`wg_json_str_array`): a bare
  string is a one-element list for `address` /
  `allowed_ips`. Test:
  `fake_listable_single_string_address_and_allowed_ips`.
- R-B2 dialer drop kills streams (`WgStream` now holds
  `Arc<Tunnel>`; the pump stops only when the last
  `Arc<Tunnel>` drops). Test:
  `fake_wireguard_stream_survives_dialer_drop`.
- R-B3 wrong-typed JSON (`wg_json_*` now return
  `Result`): present-but-wrong-typed fields are
  `Validation` naming the field, never silent defaults.
  Tests: one per field (`fake_wrong_typed_mtu_is_validation`
  et al.).
- R-B4 bad datagram kills tunnel (`handle_udp`): a
  `TunnResult::Err` from decapsulation drops the datagram;
  only UDP transport errors stay fatal. Test:
  `fake_wireguard_bad_datagram_does_not_kill_tunnel`.
- R-B5 keepalive test redesign: the old sleep-and-re-dial
  shape passed with keepalive disabled; the test now
  counts datagrams (≥2 in 3 s idle with keepalive=1, 0
  with keepalive=0). Test:
  `fake_wireguard_keepalive_emits_datagrams_during_idle`.
- R-B6 fail-before hygiene: every fail-before re-run in
  isolation (one revert at a time, that test alone) in
  `writer-fail-before-loop1.log`; the draft log's
  cross-batch contamination does not recur.

Non-blocking fixes in loop 1: S1 (no raw config value in
`parse_prefix` errors); S2/S3/S4 provenance
(`ip_network_table` 0.2.0 BSD-2-Clause, not 0.5.0 MIT;
`portable-atomic` 1.15.0 added; dangling "74 lines in the
writer's notes" pointer removed — `docs/provenance.md`
§14); NB19 (base64 key decode no longer trims
whitespace); NB20 (both-sides-same-nonstandard-PSK
control test); NB21 (leak catch extended to hex + URL-safe
base64); S8 (`Prefix::contains` safe for any
`prefix_len`); NB1/T-NB7 (DNS failover to the next
server); NB2 (random-ish txid seed + txid/qname/qtype/
source checks; TC = no TCP fallback); T-NB6
(ephemeral-port wrap fixed with a CAS transition);
NB13 (server records max UDP datagram length, asserted ≤
MTU + overhead; measured max 1440); NB14 (AAAA end-to-end); S6/T-NB4 (Go
`buildWireGuardDNSOptions` verified to hardcode port 53 —
port ignored by design, Go parity; the hostname-`:port`
strip for the bootstrap lookup is pinned by a unit test,
`localhost:5353` → loopback — the S6 integration test
uses an IP:port entry, which the `SocketAddr` arm already
handled before loop 1, so it cannot pin the strip);
T-NB5 (test counts:
40 unit + 16 integration, §M3d.8).

Documented in loop 1 (no code change): S5 (DNS queries
exempt from the dial-time allowed-IPs check); T-NB2
(ingress allowed-IPs not enforced); NB3 (DNS bootstrap
cache per-dialer-lifetime); NB6 (first tunnel address per
family wins for gateway + DNS bind); NB11 (no NAT
rebinding); NB16 (outer UDP bind wildcard is normal);
S12 (no concurrent-stream cap); T-NB8 (`poll_read` 0-byte
shape); NB5 (tiny MTU not rejected, Go parity); S7
(single bad datagram vs fatal, covered by R-B4); NB22
(`encapsulate` `Done` = queued, measured); NB23
(timer-expiry is terminal, measured) — all in §M3d.6.

Deferred (explicit, not in loop 1): S10 (per-query DNS
timeout beyond the overall `dial_timeout`); NB8
(RST-after-half-close reported as clean EOF); NB10
(write-waker sharing — fix only if a lost wakeup is
demonstrated, otherwise documented as a known limitation);
NB12/S13 (unbounded queues — bounded in practice by the
64-message channels and 64 KiB socket buffers; no drop
policy for TCP data is invented).

Bugs found by the loop-1 tests (fixed in the loop-1
commit, §M3d.8 items 6–9): the deferred-shutdown stall,
the EOF tail loss (harness), the never-sent RST on abort,
and the 10 s delayed EOF (prompt-EOF probe).

## M3d.11 Clippy gate is `--all-targets` (2026-11-05, on top of `16bcbfc`)

The clippy gate from now on is
`cargo clippy --workspace --all-targets -- -D warnings`.
The plain `--workspace` form does NOT cover test targets:
Boss ran the `--all-targets` form and it failed with 10
errors, all in test-only code, that the plain gate had
been passing — 2 in `castctl-rs/tests/parity.rs`
(`chunks_exact` with a constant chunk size, `:131`;
collapsible `if`, `:427`), 3 in
`castctl-transport/tests/common/mod.rs` (dead
`RequestRecord` fields / `FakeServer.records`, and a `loop`
that never loops), 1 in `castctl-transport/tests/rpc.rs`
(`MutexGuard` held across an await), and 4 in
`castctl-transport/tests/wireguard.rs` (redundant
`.max(0) as u64` on an already-`u64` value, a `loop` +
`match` that is a `while let`, and a collapsible `if`).
All 10 were fixed by code (no `#[allow]`): `chunks_exact`
→ `as_chunks::<64>().0` (same chunks — the padded message
length is a multiple of 64 by construction); the two
collapsible `if`s → let-chains; the dead fake-server
fields are now asserted on in the `env_proxy` test
(method/path/empty body of the exact request the client
sent); the dead `loop` removed (every path returned, so
removing it changes nothing); the guard scoped in a block
so it drops before the awaits; the redundant `.max(0) as
u64` dropped; the DNS `loop` + `match` became a `while
let`. The historical gate transcripts in §M3.7, §M3c and
§M3e.4 still show the plain form — that is what was
actually run then, not an error to rewrite.

## M4a — Gateway WS + Noise + protobuf (crate `castctl-gateway`, 2026-11-05)

M4a ports `internal/gateway` (WS dial, Noise handshake,
envelope/framing, Request/CallJSON/Ping/DownloadFile,
streams) and `internal/conn` SharedConn (retry across
reconnects, heartbeat, stale probe, down notice) to Rust,
crate `rust/castctl-gateway`. Base `dev-rust 2c38b3e`;
branch `feat/rust-m4a-gateway`. No Go file is modified;
the only new Go file is the parity harness
`rust/parity/gateway_server/main.go` (serve + client modes,
built on `internal/gateway/gatewaytest.Server`).

## M4a.1 Crate map + pins

- `proto.rs`: prost-generated types from the committed
  `internal/proto/desc0.bin` + `desc1.bin` via `build.rs` +
  `compile_fds` (option (c)); no `protoc` (none on cue; Go
  removed it deliberately). Probe passed BEFORE dependent
  code: empty `json_name` accepted; generated
  `hatch.noise.rs` + `ingress_rev_proxy.rs`.
- `noise.rs`: snow, `Noise_XX_25519_AESGCM_SHA256`, fresh
  static keypair per handshake, empty payloads, no PSK, no
  prologue. **snow has no formal audit** — recorded, not
  claimed otherwise; the handshake is covered by the
  Cacophony vector (`tests/noise_vector.rs`, 3/3) and the
  cross-language parity gate (§M4a.4).
- `framing.rs`: `split_pieces` (60000), `marshal_transport_frame`,
  `Reassembler` with the Go-only hardening caps (64 MiB /
  16 groups / 32768 pieces).
- `gateway.rs`: `Gateway` reader task, stream queues,
  `open`/`next`/`request`/`call_json`/`ping`/`download_file`.
- `shared.rs`: `SharedConn`, `DownTracker`, `Connector`
  trait, heartbeat.
- `dial.rs`: `default_ws_url`, `dial_gateway` (UA
  `Chrome/153.0.0.0`, Origin `https://muse.ai`, 20s
  upgrade bound, 20s handshake steps; the URL carries the
  literal `auth_token=<redacted>` — never the real token —
  see §M4a.2 deviation 12). [SUPERSEDED 2026-11-05 — see §M4c.7:
  Go sends the real token; Rust now does too.] The gateway-dial
  TLS rule (DialTLS forces Enabled=true) lives at the
  gateway-dial call site, NOT folded into `build_tls`.

Pins (`rust/Cargo.toml`, exact; licenses read from each
crate's pinned `Cargo.toml` in the cue registry,
2026-11-05): snow `=0.10.0` (Apache-2.0 OR MIT),
prost / prost-build / prost-types `=0.14.4` (Apache-2.0),
tokio-tungstenite `=0.30.0` (MIT; feature
`rustls-tls-webpki-roots`), rand `=0.10.3` (MIT OR
Apache-2.0), futures-core / futures-sink / futures-util
`=0.3.34` (MIT OR Apache-2.0). `Cargo.lock`: +30 packages,
no pre-existing pin changed (the 14 removed lines are
dependency-list lines re-sorted when new crates joined).
See `docs/provenance.md` §15 and `NOTICE` (b).

## M4a.2 Deviations from Go (deliberate, with citations)

1. Single-Mutex `TransportState`: snow has no
   split-transport API, unlike Go's separate `sendCS` /
   `recvCS` (`gateway.go:241-...`, `noiseHandshake`).
   One `TransportState` sits behind one `Mutex`
   (`noise.rs`). Wire-identical; encrypt/decrypt cannot
   proceed concurrently. API-shape deviation only.
2. ALPN: Go pins `["http/1.1"]` for the WS dial
   (`connector.go`, `dialWebSocket` — gorilla cannot
   upgrade over h2). The rustls client used here sends NO
   ALPN by default, so the server cannot negotiate h2 and
   the upgrade stays HTTP/1.1. Same wire outcome,
   different mechanism. If a peer ever requires an ALPN
   offer, revisit.
3. Dead classification simplified: Go `lost.go`
   `classifyDeadLocked` distinguishes loss
   (EOF/ECONNRESET/close 1006) → `ErrConnectionLost`
   (`NotSent`, `StreamIDs`, `CloseCode`, `CloseReason`) —
   vs clean close vs other errors; the `NotSent` bit
   decides retry safety per in-flight call. Rust `fail()`
   records the first fatal reader error verbatim and
   `next()` wraps it as `ConnectionError` ("gateway
   connection lost: <log_summary>"). Retry safety rests
   on `SharedConn` `safe_to_repeat` + error kind, not on
   a per-call sent/not-sent bit.
4. No Phase: Go errors carry a Phase (`withPhase`,
   `PhaseStreaming`); Rust `TransportError` carries none
   — phase→exit mapping belongs to the CLI layer (M4+),
   per `castctl-transport/src/error.rs` `exit_code` doc.
5. `connects()` counts successful installs only
   (measured: 2 failed + 1 good attempts → `connects()
   == 1`; auth failure → 0). The counter is
   install-based, not attempt-based.
6. `probe_stale` (fix loop 1, 2026-11-05): the PR1
   version used AND against the hardcoded `HEARTBEAT`
   (25s) and claimed "same as Go" — false as implemented.
   Go `probeStale` (`conn.go:445-452`) is two early
   returns, i.e. EITHER axis fresh (OR) against
   `m.heartbeatInterval`. The fix uses `||` and
   `self.heartbeat_interval`; the test proves both
   branches (one axis fresh → no ping; both stale →
   exactly one probe ping).
7. Heartbeat never opens the first connection (same as
   Go): ticks return early while `connects() == 0` and no
   outage is recorded; the first call opens.
8. `start_heartbeat` takes `&Arc<Self>`: a plain `&self`
   cannot spawn a task holding the connection.
9. `write_half` is `tokio::sync::Mutex`, not
   `std::sync::Mutex`: the std guard is `!Send` and is
   held across `send().await`. `live()` decides under
   the std lock, then acts after dropping it
   (`SlotDecision` enum).
10. Gateway 3xx → `Gateway(status)` → exit 3 (Q5
    settled); `RedirectRefused` (M3 HTTP-only) is NOT
    reused for gateway.
11. `Display` for `TransportError` echoes
    caller-supplied messages (truncated to 200 chars) by
    design, for the operator; `Debug` and `log_summary`
    never echo message bytes (lengths only). The library
    never puts a token/cookie into a message itself.
12. WS URL carries the literal `auth_token=<redacted>`
    [SUPERSEDED 2026-11-05 — see §M4c.7: Go sends the real token
    (`auth_token=%s`, 4 verbs, 4 args), not the literal;
    the whole deviation below is wrong.]
    (fix loop 1, Boss decision 2026-11-05 — MIRROR GO
    byte-for-byte, NOT a formal match): Go
    `internal/gateway/connector.go:116` (`defaultWSURL`)
    builds the URL with 3 format verbs and 4 args, so
    the quoted hatch token is computed and silently
    discarded by `Sprintf`; `TestDefaultWSURL` pins the
    literal; and the Go 0.9.0 production binary on 3
    hosts relays real turns through that URL — proven-live
    behaviour. Sending the real token would leak it to
    server/proxy logs with no evidence the gateway needs
    it. The Rust `default_ws_url` returns the identical
    string, and the dial test asserts the literal on the
    string AND that no real token value reaches the wire.
    Wire nuance — [SUPERSEDED 2026-11-05 in M4b, fix loop 1 (R-B1):
    this paragraph as originally written claimed the
    server decodes the encoded form back; that claim was
    WRONG. The live edge returns 401 for the encoded form
    and 502 for the literal (live probe on cue,
    2026-11-05); the M4a test only proved the fake server
    tolerates the encoded form. `dial_gateway` no longer
    percent-encodes: the hand-written `ws_upgrade`
    (`castctl-gateway/src/dial.rs`) sends the literal
    verbatim, and the rewritten dial test asserts the
    query value `== "<redacted>"` with no decode step.
    See §M4b.2 deviation 1 and §M4b.3. A reader
    implementing from the struck sentences would
    reintroduce the 401.] What stays true: `http::Uri`
    (used by tokio-tungstenite's `into_client_request`)
    cannot represent `<`/`>` in a query. (Mechanism
    proven by source, fix loop 2: `http` 1.x
    `src/uri/path.rs:444-462` `build_query_map` — WHATWG
    query-state allows 0x21 / 0x24–0x3B / 0x3D /
    0x3F–0x7E, so `<` = 0x3C and `>` = 0x3E are
    CLASS_INVALID — verified against the 1.5.0 source;
    the lock pins 1.3.1, and the behavioural separator
    against the fake server (raw-literal dial fails with
    URI-PARSE-ERR, encoded dials fine) corroborates the
    mechanism against the locked build — and tungstenite's
    `IntoClientRequest for &str` is `parse::<Uri>()`.)
    The dial test asserts the query value equals
    `<redacted>` with no decode step (rewritten in M4b;
    the fix-loop-2 NB5 two-sequence decode dance is
    gone). If later live proof
    shows the gateway needs the real token, change
    `default_ws_url` in this one place and re-enable the
    token-URL test.
    [SUPERSEDED 2026-11-05 in M4c — see §M4c.7: the condition above
    is now met (Go source proves the token is sent; Rust
    without it gets 502). The "3 verbs, 4 args" premise,
    the "computed and silently discarded" mechanism, and
    the "no evidence the gateway needs it" claim are all
    wrong — the M4a reading mistook test redaction for
    the URL builder, and display redaction hid `%s` as
    `<redacted>` in the evidence. What stays true from
    this deviation: `http::Uri` cannot represent `<`/`>`
    in a query (mechanism proven by source), and the
    hand-written `ws_upgrade` sends the target verbatim.
    The fix is exactly the one place named here:
    `default_ws_url` now renders the real token, quoted.]
13. `TooManyPieces` → exit 1, not 3 (fix loop 1):
    Go `classifyError` (`commands.go:304-311,336`) gives
    exit 3 only to `ReassemblySizeError` and
    `TooManyUnfinishedGroupsError`; `TooManyPiecesError`
    has no branch (and no `ExitCode` method) and falls
    through to the default exit 1. Rust
    `ReassemblyError::into_transport_error` splits the
    mapping accordingly (Size / TooManyGroups →
    `Gateway(-1)` exit 3; TooManyPieces →
    `ConnectionError` exit 1).
    Retry trade-off (fix loop 2, F4/NB2): mapping Pieces
    to `ConnectionError` makes it retried iff the method
    is safe (`should_retry`), where Go never retries a
    reassembly error — bounded by the 30s budget,
    safe-methods only, practically unreachable (the 64
    MiB size cap is checked before the piece-count cap,
    and the real gateway sends 60 kB pieces). The fully
    faithful mapping (a distinct variant with
    `exit_code() == 1` and `should_retry == false`) is
    explicitly deferred to a later touch.
14. `live()` replacement accounting (fix loop 1): when
    `live()` replaces a dead installed gateway it now
    does `drops++` + `mark_down(dead, false)` + `Close()`
    of the old gateway, mirroring Go `Live`
    (`conn.go:500-520`); the PR1 version overwrote the
    slot with none of the three. The stale test asserts
    `drops() == 1` after reconnect.
    (Fix loop 2, F5/NB3: the same detach now also runs
    when the reopen FAILS — Go detaches before opening,
    so the drop is counted and the old gateway closed
    even on open error; the new test asserts `drops() ==
    1` and an empty slot after a failed reopen. The
    `dead` fallback is Go `errGatewayClosed` ("closed",
    `internal/conn/errors.go:313-315`) — fix loop 2,
    NB4; the fix-loop-1 text "gateway connection
    closed" was the wrong fallback for this path. The
    other "gateway connection closed" strings in
    `gateway.rs` are the generic closed-connection error
    on the read/close paths, not this fallback, and are
    unchanged. Residuals, fix loop 3: the RECORDED
    dead-error text still differs from Go's close
    classification — Rust records "gateway connection
    closed" via `fail()` on peer-close/EOF paths where Go
    records receive-failed/`ErrConnectionLost`;
    pre-existing, diagnostic-only. Detach timing on the
    open-failure path: Go detaches before the open
    attempt, Rust detaches after the failed open, so
    `downSince` can start up to one connect-timeout
    later; the end state after `live()` returns is
    identical.)

## M4a.3 Findings while writing (fail-before proofs + fixes)

- `research-noise.md` §5.1 mislabels the msg_3 plaintext
  as `"hellosubmarine"` (14 bytes); the hex in that same
  file decodes to `"yellowsubmarine"` (15 bytes; 15+16 tag
  = 31 = len(msg_3)). The vector test FAILED first; the
  test plaintext was fixed to the hex. The vector itself
  was never edited, and the research file is NOT edited
  in this PR — the correction is recorded here and in the
  test comment.
- The envelope is ASYMMETRIC (Go `gateway.go`
  `sendEnvelope` vs `readFrame`; `gatewaytest/server.go`
  `serveWS`): the client sends
  `ServiceRequest{service, payload: ServiceFrame}` and
  the server answers `ServiceResponse{payload:
  ServiceFrame}`. The first Rust fake server guessed
  symmetric; the client then dropped the connection
  ("gateway connection lost"). Fixed to asymmetric.
- Real route paths come from
  `internal/proto/routes.json`, not `/v1/...` guesses:
  connection.ping POST `/api/ping`; sessions.list GET
  `/api/session/list`; chat.history GET `/chat/history`;
  feed.list GET `/api/feed`; goals.list GET `/goals`.
  The first canned maps used invented paths and returned
  `{}` for every method (caught by the Go client run,
  before the Rust client run).
- The reassembler completes when the number of DISTINCT
  indices reaches `total_chunks` (Go `framing.go`
  `feed`): the first unit test expected completion only
  after a duplicate overwrite post-completion; the test
  was fixed (the overwrite must arrive while the group
  is still incomplete).
- `snow::NoiseParams.name` is a field, not a method.
- `futures-core` / `futures-sink` / `futures-util` must
  be direct deps: tokio-tungstenite does not re-export
  the Stream/Sink traits.
- Go on cue is 1.26.8 but `go.mod` requires >= 1.27.3
  and `GOTOOLCHAIN=local` blocks the download; the
  parity-server binary was built in the sandbox (go
  1.27.3 + warm module cache) and copied to cue — the
  binary runs on cue and the gate itself ran on cue.
- `pkill -f "gateway_server serve"` self-matches the
  SSH session (the pattern appears in the session's own
  command line) and kills it: kill the server by exact
  name (`pkill -x gateway_server`) instead.

## M4a.4 Gates (cue, 2026-11-05)

- `cargo fmt --check`: exit 0 (after `cargo fmt -p
  castctl-gateway` on cue; formatted files copied back).
- `cargo build --workspace`: exit 0.
- `cargo test --workspace`: exit 0. BEFORE 304, AFTER
  337 (+33, all in `castctl-gateway`: lib 13 +
  integration 13 + golden 4 + noise 3).
- `cargo clippy --workspace --all-targets -- -D
  warnings`: exit 0 (after fixes: derivable `Default`
  for `Body`; 2 collapsible `if`s → let-chains; let-else
  → `?`; `live()` fast path via `.filter()`; `Install`
  → `SlotDecision` for enum-variant-names; doc-list
  indent in golden.rs; type aliases for the fake
  server's record types).
- Golden protobuf: 58/58 (`tests/golden.rs`
  `golden_vectors_58_of_58`: encode==`.bin`,
  decode==struct, encode(decode)==`.bin` per case, plus
  presence / oneof / enum-names tests).
- Parity gate (same Go `gatewaytest` server, 5 methods):
  Go client vs Rust client outputs byte-identical
  (`diff` empty; the server binds `127.0.0.1:0`
  (ephemeral) and prints the actual port per run — the
  39345 / 45717 in earlier notes are two runs' ports;
  both clients exit 0).
- Required other tests (all pass in
  `tests/gateway.rs`): heartbeat sends at cadence
  (2..=5 pings in 1.1s at a 300ms injected interval);
  stale probe detects a dead conn and the next call
  reconnects; retry within `RetryFor` (2 failed + 1 good
  attempts); down notice after `DownNotice`/`DownFails`
  (unit: 5th fail notifies; integration: `OnDown`
  fires); no token/cookie leak into logs (`Gateway`
  `Debug`, `TransportError` `Debug`/`log_summary`
  contain no token); cancel mid-handshake does not hang
  (aborted dial finishes < 2s); gateway 404 →
  `Gateway(404)` → exit 3; unknown method →
  `Validation` → exit 2; 200 kB chunked response with
  shuffled pieces reassembles.
- Fix loop 1 (2026-11-05, same gates, all exit 0):
  `cargo fmt --check`, `cargo build --workspace`,
  `cargo test --workspace` (BEFORE 337, AFTER 346, +9,
  all in `castctl-gateway`: lib 14 (+1
  `noise_transport_debug_renders_shape_only`) +
  integration 21 (+8: B1 token-URL, probe_stale both
  branches, unsafe no-retry, 3xx, non-JSON, Reset, msg2,
  request-timeout)), `cargo clippy --workspace
  --all-targets -- -D warnings` (after fixes: named
  `Callback` struct impl instead of a closure —
  `result_large_err` on the 136-byte `ErrorResponse` —
  and scoping the `request_targets` lock guard before
  `gw.close().await` — `await_holding_lock`). Parity
  gate re-run: same Go server, 5 methods, Go client vs
  Rust client byte-identical (`diff` empty; server
  `127.0.0.1:33727` ephemeral; both exit 0). The Rust
  parity client dialed with the literal
  `auth_token=<redacted>` URL (percent-encoded on the
  wire by `dial_gateway`). [SUPERSEDED 2026-11-05 — see §M4c.7:
  the parity client used the wrong URL; Go sends the
  real token. The byte-identical methods still stand —
  they ran over a loopback fake server, not the live
  edge.]
- SPDX header (fix loop 4, 2026-11-05 — CI Go đỏ cả 3 tag vì
  `TestSPDXHeaders` fail): mọi file .go thêm vào repo (kể cả dưới
  `rust/`) phải có header SPDX GPL-3.0-or-later —
  `TestSPDXHeaders` quét toàn repo (repo root, không trừ thư mục
  nào). `rust/parity/gateway_server/main.go` đã sửa từ
  GPL-3.0-only sang GPL-3.0-or-later; các file `.rs` vẫn
  GPL-3.0-only.

## M4a.5 Chưa kiểm chứng

- wss:// dial: only ws:// loopback tested; the rustls +
  webpki-roots path is unexercised.
- No live muse.ai peer; no real VM, cookies or tokens
  (all fake: `hatch_sess=FAKE`, `AT-FAKE`, `HT-FAKE`).
- No real WireGuard/outbound dial: the gateway dialed
  direct loopback; profile-outbound routing is M4b
  wiring, not this crate.
- Go CI state for the new `main.go`: it compiles (`go
  build` exit 0 in the sandbox) and `go vet` + `gofmt -l`
  are clean, but no Go test/CI ran it in this PR.
- snow has no formal audit (see §M4a.1).
- Down-notice timing at production thresholds (60s / 5
  fails) was not waited; covered by threshold injection.
- Heartbeat at the production 25s cadence was not
  waited; covered by the 300ms injection.

## M4a.6 Hạn chế đã ghi nhận (fix loop 1, 2026-11-05 — không sửa)

One line each + reason. Fixed in this loop and NOT
listed here: red-team N3 (unsafe no-retry test — added),
N4 (3xx / non-JSON / Reset / msg2 / timeout tests —
added), N8 (live() accounting — §M4a.2 deviation 14);
technical N10 (lib.rs unwrap claim — narrowed) and N11
(parity port + generation comment — fixed); safety N1–N4
(no-leak strengthening, ws_error routing, hand-written
Debug, lib.rs claim) and N6 (parity temp file —
`os.CreateTemp`).

(Fix loop 2, 2026-11-05: also fixed and not listed
below — F5/NB3 `live()` open-failure detach (drop
counted + old gateway closed even when the reopen
fails, tested) and NB4 `dead` fallback text (now
"closed" as in Go). F4/NB2 (TooManyPieces retry
trade-off) is recorded in §M4a.2 deviation 13, not
fixed.)

- wss:// never exercised; ALPN "same wire outcome" is
  inference, not measurement (red-team N1): only ws://
  loopback tested; rustls+webpki-roots vs Go's uTLS
  Chrome preset are different TLS stacks — a
  fingerprint-filtering real peer could reject Rust.
- Parity gate is narrow: 5 happy-path unary calls only
  (red-team N2): no non-2xx, BodyChunk, Reset, chunked /
  large, subscribe, auth chain, or routes beyond the 5;
  the parity handler ignores `service`, so a Rust bug in
  service selection is invisible to the gate.
- Reset code is dropped from the error (red-team N5 =
  technical N5): Go's reset summary carries `code` +
  `reason_length`; Rust keeps only `body_length =
  reason.len()` in `Gateway(-1)` — exit code same,
  operator diagnostics differ.
- WS-upgrade timeout → exit 4, Go → exit 1; no overall
  connect bound (red-team N6 = technical N1):
  `CONNECT_TIMEOUT` (60s) is a const only, nothing
  enforces it; worst case one `dial_gateway` is ~80s
  (20s upgrade + 3× 20s handshake steps) vs Go's 60s.
- `Gateway::close()` doc overclaims; the reader task can
  leak on a non-cooperative peer (red-team N7 =
  technical N9): dropping the `JoinHandle` detaches
  instead of aborting; closing the write half only sends
  a WS Close frame and does not close the TCP transport,
  so a peer ignoring Close frames leaves the reader
  blocked forever. `close()` can also block
  indefinitely acquiring the write-half lock (Go bounds
  it at 2s).
- Heartbeat has no panic restart and no generation guard
  (red-team N9 = technical N2): a panicking tick leaves
  `heartbeat_running == true` forever (later
  `start_heartbeat` is a no-op); `stop_heartbeat` clears
  the flag before the task exits, so a start in the
  window can create a second loop.
- `Deadline` (absolute) is dropped, undocumented
  (red-team N10): Go's retry budget is
  `min(RetryFor, opts.Deadline, ctx deadline)`; Rust has
  no `Deadline` field and always retries for the full
  policy budget.
- Subscribe/stream not ported in M4a (red-team N11 =
  technical N3): no `SharedConn::subscribe_raw`, no
  public `Gateway::open_stream`, no `SubscribeJSON`;
  only the constants exist.
- GET body→query drops array/object values; Go renders
  them with `%v` (red-team N12 = technical N6): a GET
  body containing a nested value drops the query key in
  Rust but sends `key=[1 2]` / `key=map[…]` in Go.
- `read_bounded` rejects non-Binary WS messages; Go
  accepts any message type as msg2 (red-team N13 =
  technical N7): a Text frame carrying valid msg2 bytes
  succeeds in Go, fails in Rust.
- Golden presence test decodes back only 2 of 4 fields
  (red-team N14): encode pins all four tags, decode-back
  asserts only `chunk_id` / `payload`.
- Heartbeat cadence integration range admits ~1.5× slop
  (red-team N15): 2..=5 pings in 1.1s at 300ms (expect
  ≈3); the formula itself is pinned exactly by the unit
  test.
- `sent_any` is write-only dead state (technical N4):
  set before the first write (for the dropped
  `ErrConnectionLost` classification, deviation 3) but
  never read.
- WS Ping/Pong relies on implicit tungstenite behaviour,
  untested (technical N8): no test sends a WS Ping to
  the Rust client; Go installs explicit ping/pong/close
  handlers.
- No concurrent-request test (technical N12):
  `send_envelope` holds the write mutex per piece, not
  per envelope (Go holds `sendMu` across the whole
  envelope), so concurrent envelopes can interleave
  pieces; the reassembler tolerates it by design, but
  envelope atomicity is untested.
- `new_chunk_id` has no error path (technical N13): Go
  returns an error if the OS RNG fails; Rust uses
  `rand::random()` with no fallible API.
- No logging in the crate at all (technical N14): Go
  `markDown` logs a Warn and the retry loop logs debugs;
  the Rust crate has no logger — the CLI layer owns
  observability.

## M4b — CLI auth + read-only commands (2026-11-05)

M4b ports the gateway auth chain (`internal/gateway/cookies.go`,
`auth.go`, `subscription.go`, `connector.go`, `summary.go`), the
profile credentials API (`internal/profile/credentials.go`), and
the 13 read-only commands from `internal/commands/read.go` plus
the CLI runtime / error taxonomy (`commands.go` `classifyError`,
`runtime.go`), into `rust/castctl-gateway` (new modules) and
`rust/castctl-cli` (new `network.rs` / `runtime.rs`). Base is
`dev-rust` after PR1 merged (96ce485); branch
`feat/rust-m4b-cli-auth`. No Go file is modified. No new crate
enters the lock: chrono 0.4.45, rustls 0.23.46, tokio-rustls
0.26.6, webpki-roots 0.26.11 and base64 0.22.1 were already in
it (promoted to direct deps only), so `NOTICE` /
`docs/provenance.md` are untouched.

## M4b.1 Crate map

- `castctl-shared`: `timefmt.rs` (chrono `Local` + a
  hand-rolled TZif abbreviation reader), `status.rs`,
  `sessions.rs`, `event.rs`, `feed.rs`, `usage.rs`,
  `bridge.rs` (`from_serde`: gateway `serde_json::Value` →
  shared `JsonValue`).
- `castctl-config`: `credential_for_profile` (value read,
  first profile match wins) + `has_credential_for_profile`
  (presence-only) + `LoginCredential` (hand-written `Debug`
  that never prints values).
- `castctl-transport`: `tls.rs` (`tls_client_config`, ALPN
  `["http/1.1"]`), `http.rs` `request_tls` (dial → rustls
  wrap with SNI → hyper http1).
- `castctl-gateway`: `summary.rs` (allowlist summary),
  `cookies.rs` (3 forms), `auth.rs` (hatch chain),
  `subscription.rs` (`FetchSubscription`, `callAction`,
  `ParseRSCResult`, `FindActionID`), `connector.rs`
  (`GatewayConnector`), `dial.rs` (hand-written WS upgrade
  — see deviation 1).
- `castctl-cli`: `runtime.rs` (`build_runtime`,
  `ProfileConnector` adapter, `Runtime::cookies()`),
  `network.rs` (`classify_error`, the 13 handlers,
  `indent_json`).

## M4b.2 Deviations from Go (deliberate, with citations)

1. WS upgrade written by hand. [PARTLY SUPERSEDED 2026-11-05 — see
   §M4c.7: Go `defaultWSURL` (`connector.go:113-120`)
   sends the real token (`auth_token=%s`, 4 verbs, 4
   args), NOT the literal — the 'literal token' premise
   is wrong, and so is '502 (past the token check)': the
   401/502 probe compared two spellings of a placeholder
   (`%3Credacted%3E` → 401, literal → 502); both lack a
   valid token, so 502 is the token-check failure, not a
   pass.] `http::Uri` rejects `<`/`>` in the query, so
   the upgrade request is written as raw HTTP/1.1 bytes
   (`dial.rs` `ws_upgrade`) and the response is validated
   (101 + `Sec-WebSocket-Accept` via tungstenite's
   `derive_accept_key`) before wrapping the stream with
   `from_partially_read`. The direct dial now also pins
   ALPN `["http/1.1"]` via `tls_client_config` (M4b fix
   of the M4a no-ALPN deviation).
2. Q8 (decided by the parent per the decision principles):
   `Unsupported` → exit 2 ONLY for config parse/dispatch
   errors; runtime errors map to exit 1. Evidence: Go
   `defaultBuildRuntime` maps setup errors to `errCode(2)`
   (LoadSingleConfig, ResolveLogSettings, NewManager,
   ResolveProfileDNS, dns.New, dnsClient.Start, mgr.Dialer)
   except `mgr.Start` → 3, while runtime errors go through
   `classifyError`.
3. HTTPS via hyper http1 only: Go negotiates h2, Rust
   cannot speak h2 — same request/response over HTTP/1.1.
4. TLS via rustls, not Go's uTLS Chrome fingerprint: the
   ClientHello differs from Go's. Live evidence (§M4b.5):
   the HTTPS paths pass against the live edge; the gateway path
   got 502 in M4b (missing token, not the fingerprint — see
   §M4c.7) and passes since M4c (live gate 15/15, §M4c.8).
5. `BodySummary` has no Payload text field: the
   VM-unavailable case is carried as `error_code:
   Some("vm_unavailable")`. Go's `GatewayError.Error()`
   (`internal/conn/errors.go`) never prints Payload — the
   payload matters only for `classifyConnError`'s substring
   check, which the marker replaces.
6. `SessionInfo` / `ParseRSCResult` numbers are
   `serde_json::Value`, not Go `json.Number` literals:
   number-literal spelling (e.g. `1.50` → `1.5`) is not
   preserved through shaped outputs; values stay
   numerically identical.
7. `history --download` → exit 1 "not ported yet" BEFORE
   any network call (Go fetches history first; M2 stub
   convention).
8. `invite` stays fully stubbed (exit 1, `STUB_LINE`).
9. [FIXED in fix loop 1 — was a deviation, now matches
   Go.] A `Block` outbound builds into `BlockDialer`
   (`castctl-transport/src/dialer.rs`) and fails at dial
   time with `ConnectionDown` ("dial <host>: operation
   not permitted", mirroring sing-box's `syscall.EPERM`
   — `protocol/block/outbound.go:37-40`), which the CLI
   classifies as exit 1, exactly like Go's dial-time
   failure. Before the fix it failed at dispatch
   (exit 2).
10. No keeper / refresh; no cookie writer
    (`WriteCookiesFile` deferred to M5 keeper).
11. No DNS router is built (M3 system-resolver deviation
    carries over).
12. Cookie / chunk bodies via `String::from_utf8_lossy`
    (Go strings hold arbitrary bytes; invalid UTF-8 is
    replaced, not rejected).
13. `FindActionID` derives the chunk base from the page
    URL's scheme+authority (Go hardcodes
    `https://muse.ai`; identical in production).
14. "could not find fetchSubscriptionAction" /
    "subscription is not an object" `GatewayError`s carry
    no payload text (Go's `Error()` never prints Payload).
15. The CLI renders `GatewayError` via its own Go-exact
    `Error()` builder (`network.rs`
    `gateway_error_text`), NOT `TransportError::log_summary()`
    (whose gateway shape is the M4a `render()` deviation).
16. `ConnectionError`'s `error_length` is the inner
    message's length (loop-6: the CLI never prints the
    message; the length is the only observable).
17. Empty feed / ideas / threads / files / goals rows emit
    `[]`, never `null` (handlers replace nil slices).
    Corrects the Batch A note that said feed/ideas emit
    `null`.
18. `from_serde` number-literal spelling is not preserved
    (see 6).
19. `serde_json` float exponent spelling on passthrough
    outputs (`1e21` vs Go `1e+21`): values numerically
    identical, spelling differs.
20. `\b` / `\f` / U+2028 / U+2029: exact via the CLI
    indenter (Go `json.Marshal` rules); shaped serializers
    were already exact.
21. Local time via chrono `Local` + a hand-rolled TZif
    abbreviation reader: chrono `%Z` gives `"+07:00"`,
    not `"ICT"` — the Asia/Ho_Chi_Minh tzfile has no "ICT"
    abbreviation (verified with `zdump -v` and a Python
    TZif parse on cue, plus a Go probe program).
22. `do_hatch` / `callAction` / `fetch_text` derive TLS
    from the URL scheme (https → `request_tls`, http →
    `request`); no separate tls flag.
23. `dial_gateway_over_stream` takes a generic stream, not
    `Box<dyn AsyncReadWrite>` (avoids a honk-outbound
    dependency in the gateway crate).
24. Oversized upgrade response (> 8192 B before `\r\n\r\n`)
    renders the 28-char `gateway: websocket dial failed`
    (`dial.rs` `ws_upgrade` oversize guard). Deliberate
    DoS guard with NO Go equivalent: gorilla's
    `ReadResponse` has no such cap, so there is no Go
    rendering to match. [Recorded in fix loop 2 — the
    fix-loop-1 report's blanket "inherently unmatchable"
    justification for the `dial_failed()` sites was wrong
    for the other sites (they go through the
    handshake-failure path, `connector.go:292-311`); the
    oversize guard is the ONE site where it is true.]
25. `ws_upgrade` does not validate the `Upgrade: websocket`
    / `Connection: upgrade` response headers (gorilla
    rejects a 101 without them — `client.go:394-405` →
    `ErrBadHandshake`, resp non-nil → Go renders
    `status_code=101`; Rust proceeds if the accept key
    matches, and the Noise handshake then fails later
    with a different error). Leniency, not a
    message-rendering issue. Also not handled: obs-fold
    continuation lines (Go folds them into the previous
    header's value; Rust checks each physical line
    independently). Recorded as a follow-up, not fixed
    in fix loop 2 (it changes acceptance, not just the
    message). NOTE (fix loop 3): the leading-space
    FIRST header line is NOT part of this deviation —
    Go rejects it outright (`malformed MIME header
    initial line`, `textproto/reader.go:538-545`), while
    a leading-space line AFTER the first is a
    continuation (the obs-fold gap above). Fix loop 3
    implements the first-line rejection in
    `check_upgrade_head` (first header line starting
    with SP/HTAB → fixed message); only the obs-fold
    continuation case remains open here. NOTE (docs
    follow-up): obs-fold can also corrupt the accept
    value itself — a continuation line after a correct
    `Sec-WebSocket-Accept` folds into the accept value
    in Go (`Header.Get` returns `"<key> X-Extra: v"`
    → mismatch → `status_code=101`), while Rust treats
    the continuation as its own header line and the
    accept stays matched → proceeds. This flips an
    ACCEPTANCE decision, not just a message. The mirror
    case coincides: a continuation accept line after a
    wrong accept folds to `"wrong Sec-WebSocket-Accept:
    <key>"` in Go → mismatch → `status_code=101`, and
    Rust also renders `status_code=101` (it does not
    count the leading-space name as an accept header).
    Verified by a Go probe in the docs follow-up
    (notes dir: `goprobe-plusdd/`).
26. The tungstenite path (`ws_error`'s non-Http arms)
    renders `dial_failed()` for a bad-accept failure too:
    tungstenite returns a protocol error with no response
    attached, so the status is not available to render
    `status_code=101` (Go renders `status_code=101`
    there as well). Non-blocking: the live dial path uses
    the hand-written `ws_upgrade`, not a tungstenite
    dial; fixing the tungstenite path needs plumbing the
    status through. Recorded so the two paths do not
    drift apart again.
27. Bare-LF header terminator: `ws_upgrade` reads until
    `b"\r\n\r\n"` (`dial.rs` read loop); Go's `ReadLine`
    accepts bare `\n` (verified by a Go probe in fix
    loop 3: a `502` response with bare-LF endings parses
    to resp 502). A bare-LF response never terminates
    the Rust read loop → EOF → fixed 35-char message,
    where Go renders the status. Pre-existing M4b code,
    untouched by fix loops 1–3, never claimed
    Go-faithful. Recorded as a follow-up; fixing it
    means changing the read loop, out of this loop's
    scope.
28. Signed 3-char status tokens (`+DD`, 100 tokens
    `+00`..`+99`): Go's `ReadResponse` accepts a status
    token iff `len==3 && Atoi ok && >= 0`
    (`net/http/response.go:170-186`); `strconv.Atoi`
    accepts a leading `+`, so `+50`/`+01`/`+99`/`+00`
    are VALID codes (resp 50/1/99/0) and gorilla's resp
    branch renders `status_code_length=2` for 10–99
    and `=1` for 0–9 (never `status_code`, never
    `None`, since the code is < 100 and ≠ 101).
    Rust's step-1 gate (`is_three_digit_code`,
    `dial.rs` — "exactly 3 ASCII digits") rejects
    `'+'` → malformed → the fixed 35-char message
    `gateway: websocket handshake failed`. Root cause:
    fix loop 3 (and both fix-loop-2 reviewers, and the
    fix-loop-3 brief) equated "valid code" with
    "exactly 3 ASCII digits", citing Go's
    `isThreeDigitCode`
    (`internal/gateway/handshake_log.go:62-67`) — but
    that function governs what the log extractor emits
    as a token, not what `ReadResponse` accepts as a
    code; the `is_three_digit_code` doc comment in
    `dial.rs` states the false rule as Go-derived.
    The divergence only manifests when the headers
    parse cleanly: `+50` + bad header → fixed in both
    (the header error masks the code difference).
    Recorded as a deviation (final re-review round 3:
    safety PASS, technical PASS, red-team FAIL on this
    one family; loop 3 of max 3 was closed, so no
    loop 4 to land the fix). The fix, fully specified
    for a future change: in step 1, a token is a valid
    code iff `len==3 && Atoi ok && >= 0`, i.e. 3 ASCII
    digits OR `+` + 2 ASCII digits, routed through the
    existing deferred-status-error path (so ordering
    vs proto/headers stays Go-faithful); pin with unit
    tests (`+50` → length 2, `+01` → length 1,
    `+99` → length 2, `+00` → length 1, `+50` + bad
    header → fixed) + an integration test via
    `start_with_response_bytes`. Pathological input
    class: no real server sends signed status codes;
    the live edge sends well-formed responses.
    Evidence: red-team probe
    (`/tmp/goprobe-fl3-rt/out.txt`, md5
    `64d2dac61b5d20c738cc36fb8cd762b4`; 69-case battery
    `/tmp/goprobe-fl3-rt2/out.txt`, md5
    `bb7d86540aa002728dc0aaa2ba404019`), parent probe
    (`/tmp/goprobe-parent/main.go`), docs-follow-up
    probe (saved in the notes dir:
    `goprobe-plusdd/main.go` + `out.txt`). The
    fix-loop-3 report's "22 cases" probe claim is NOT
    cited here (unverifiable: only 17 `==` blocks
    shown; `/tmp/goprobe-fl3/out.txt` exists on
    neither VM).

## M4b.3 Findings

- **The literal token — [SUPERSEDED 2026-11-05 — see §M4c.7].**
  M4a recorded that the live server "decodes
  `%3Credacted%3E` back to `<redacted>`". False: a raw-TLS
  Python probe on cue (identical headers, only the token
  spelling differs, vm_id from the Go status output)
  returned `401 Unauthorized` for the encoded form and
  `502 Bad Gateway` for the literal form, twice each,
  interleaved with Go `status` (exit 0 twice) — not
  backend flapping. The fix is a hand-written WS upgrade
  in `castctl-gateway/src/dial.rs` (`ws_upgrade`): the
  request-target is sent verbatim (plain string split, no
  `http::Uri`), the response must be 101 with a correct
  `Sec-WebSocket-Accept` (via tungstenite's
  `derive_accept_key`), leftover bytes after the header
  block are preserved with
  `WebSocketStream::from_partially_read`. Both
  `dial_gateway` (direct) and `dial_gateway_over_stream`
  use it; the direct dial now also pins ALPN
  `["http/1.1"]`, fixing the M4a no-ALPN deviation.
  [Correction: the 401/502 measurements above stand, but
  the conclusion is withdrawn — both forms lacked a valid
  token, so neither proves anything about the upgrade
  path. The fix is sending the real token (§M4c.7), not
  the literal. The hand-written upgrade itself stays.]
- **CRLF goes through `muse.write` / `muse.edit` only.**
  A Python edit script that rewrote `dial.rs` turned its
  `\r\n` literals into bare LFs (0 literal CR bytes in
  the file), so the upgrade request had no `\r\n` and the
  server waited forever → 20s timeout on all 3 dial
  tests. Fixed with `muse.edit` (`\\r\\n` in JSON);
  verified 12 sequences, 0 literal CR bytes. Never build
  a CRLF-carrying file through a Python edit script.
- **The FakeServer cannot record a literal `<>` upgrade.**
  Tungstenite's server handshake parses the target with
  `http::Uri` (`server.rs:158`), which rejects `<>`, so
  the M4a FakeServer cannot accept or record a
  literal-token upgrade at all. The literal-token tests
  use a new harness, `tests/common/raw_upgrade.rs`
  (`RawUpgradeServer`: records raw request bytes
  verbatim, answers 101, then closes — it does not speak
  Noise, so the dial fails at the Noise step with
  `ConnectionError`, which the tests assert).
- **TLS fingerprint blocks the live gateway (see §M4b.5) — [SUPERSEDED 2026-11-05 — see §M4c.7].**
  rustls + literal token → 502; OpenSSL + literal → 502;
  Go/uTLS-Chrome + literal → 101. ClientHello captures
  (iptables REDIRECT + a Python listener on cue):
  Go WS dial 1748 B, uTLS HelloChrome (GREASE cipher +
  extensions + groups + key share, ECH, ALPN http/1.1
  only); rustls 251 B, no GREASE, no ECH, no MLKEM768,
  11 extensions in rustls order. The edge terminates TLS
  and then 502s at the HTTP proxy (`server_connection_
  error`), so the fingerprint decides upstream routing,
  not the handshake. [CORRECTED in fix loop 1 (F1): the
  original text said "rustls has no API for GREASE / ECH
  / extension order" — that is FALSE on ECH. rustls
  0.23.46 HAS an ECH API (`ClientConfig::with_ech()` /
  `EchGreaseConfig`, including GREASE-ECH — vendored
  source `src/client/builder.rs:27`,
  `src/client/ech.rs:47`) but no cipher/group/keyshare
  GREASE and no extension-order control; ML-KEM768
  exists only via the aws-lc-rs provider, which the
  ring-only rule forecloses — aws-lc-rs is banned from
  the lock (rule in `rust/Cargo.toml:94-100`; this
  paragraph is the PORTING record of the ban). The conclusion stands: rustls
  cannot mimic Chrome. Cheaper control before the
  BoringSSL probe: try an aws-lc-rs-provider rustls dial
  — if the edge keys on size/MLKEM presence it may get
  further than ring-provider rustls; if it keys on
  GREASE/order, it will not. The probe, not the claim,
  decides. [CLARIFIED in fix loop 2 (N1): such a dial is
  only sound as a separate scratch binary OUTSIDE the
  workspace lock — enabling aws-lc-rs alongside ring in
  this workspace makes provider resolution ambiguous and
  panics at runtime (`Cargo.toml:94-100`); running the
  probe here would violate the ban.] BoringSSL (already in the lock via honk,
  `boring` / `tokio-boring` 5.2.0) implements GREASE
  (`ssl/encrypted_client_hello.cc`, `hs->grease_seed`)
  and is the candidate fix — a new TLS-architecture
  decision, not attempted in PR2.
  [SUPERSEDED 2026-11-05 — see §M4c.7: the three-way contrast is
  confounded — rustls + literal and OpenSSL + literal
  both lacked the token, and Go sent the real token, so
  'fingerprint decides upstream routing' was never
  isolated. The ClientHello measurements (1748 B vs 251
  B) stand; the conclusion does not. The M4c fork
  (ClientHello set-identical, still 502) is consistent
  with the token cause. Whether the fingerprint matters
  at all is decided by the step-3 matrix (§M4c.8).]
- **`usage --json`'s one-off `ConnectionError`.** First
  parity run: `usage --json` failed with
  `error_length=36` while `usage` and `usage-raw` passed
  (same `fetch_subscription` path). The re-run passed
  all three (see §M4b.5). Treated as transient (likely a
  blip during the FindActionID chunk fetch). [FIXED in
  fix loop 1 (F3): the 36-char string is hyper's `error
  reading a body from connection`
  (`hyper-1.12.0/src/error.rs:547`, `Kind::Body`),
  pinned by the `mid_body_abort_is_connection_error_
  36_chars` test (`castctl-transport/tests/tls.rs`) — a
  server-side reset mid-body, mapped to
  `ConnectionError` (exit 1). The live recurrence itself
  remains unreproduced; the re-run passed.] The 36-char
  message is a hyper error string from `http.rs`
  (`truncate(..., 200)`).
- **Cue disk filled to 100% mid-task.** `rust/target/
  debug` reached 17 G (2255 files). Freed by deleting
  `target/debug`; the release binary was preserved and
  backed up to `/tmp/castctl-rs-m4b`.
- **Display redaction, third time.** A connector-test
  failure and the probe output both rendered a real
  token as `auth_token=<redacted>` while the bytes were
  different. Byte-level checks (`grep -c`, Python byte
  lists) are the only reliable verification for token
  URLs.
- **Go ghost profiles synthesise defaults.** An explicit
  `--profile nosuch` does NOT error: `LoadProfile`
  synthesises `SourceNone` defaults for a ghost name.
  Only `default_profile` naming a nonexistent profile
  errors. Rust matches (verified by test).
- **Test-harness findings.** The shared FakeServer
  deadlocks on a binary ClientHello (it reads until
  `\r\n\r\n`, which a ClientHello never contains) —
  plain-HTTP fakes live in `tests/http_fake.rs` instead.
  Per-target clippy dead-code forced splitting
  `tests/common/mod.rs` in both gateway and transport
  (a target that never constructs a server trips
  `-D warnings` on its fields). `MutexGuard` held across
  `await` is flagged by clippy 1.99 even with an explicit
  `drop` — scope the lock in a block instead.
- **Fix loop 2: stage-2 handshake errors match Go.**
  The fix-loop-1 report's §1 exclusion ("`dial_failed()`
  stays for TCP-dial / EOF / non-UTF8 / missing-accept
  failures — Go's dial-error text there is the variable
  wrapped transport error (`connector.go:275-277`)") was
  WRONG: `:275-277` is the TCP-dial stage
  (`dialer.WebSocketDial` failing, before any HTTP byte);
  the `ws_upgrade` failures all happen after TCP
  connect, inside gorilla's `DialContext`, and Go renders
  them via `newHandshakeFailureError(resp, err)`
  (`connector.go:292-311`). Fix loop 2 renders them
  Go-faithfully: bad accept on a 101 →
  `status_code=101` (gorilla returns resp non-nil,
  `client.go:394-405`); post-connect write / read / EOF
  failures → the fixed 35-char message (gorilla returns
  `(nil, nil, err)`, `client.go:372-387`); the
  non-UTF-8 arm is now byte-parsed (`check_upgrade_head`
  in `dial.rs`): Go's `ReadResponse` + `textproto`
  work on bytes and never validate UTF-8
  (`net/http/response.go:158-206`,
  `net/textproto/reader.go:521-596`), so a non-UTF-8
  status token → fixed 35-char (Atoi fails →
  malformed-status error → token-shape fails),
  non-UTF-8 in a header VALUE is valid obs-text
  (`validHeaderValueByte`, `reader.go:733`) → the
  status-based rendering, and non-UTF-8 in a header KEY
  fails the whole response (`canonicalMIMEHeaderKey`
  ok=false) → fixed 35-char. Both re-reviewers were
  partly right: the red-team was right that the arm
  diverges (and right for the status-token case) but its
  "always fixed 35-char" fix is wrong for header-value
  garbage; the technical reviewer was right that no
  SINGLE rendering covers the arm, but "do not touch"
  was wrong — the per-position mapping is clean once
  the head is parsed as bytes. The oversized-response
  guard stays `dial_failed()` (deviation 24 — the one
  site with no Go equivalent). The head check also
  validates header well-formedness the way Go does
  (colon present, valid field-name/value bytes, status
  error deferred until the whole head validates
  [CORRECTED in fix loop 3: deferred only for a valid
  3-digit code — Go returns a malformed-status error
  before parsing headers, so a malformed token +
  malformed header renders the token/length form, not
  the fixed message]), and
  the accept value is trimmed of leading SP/HTAB only
  (Go `bytes.TrimLeft`) [CORRECTED in fix loop 3:
  trimmed on BOTH ends — every header line passes
  through `trim()` in `readContinuedLineSlice`
  (`textproto/reader.go:108-119`) before the colon
  split, so a trailing space/tab on a correct accept
  key still matches]. Pinned by 7 integration tests
  + 4 unit tests (13 cases) — see the fix-loop-2
  report.
- **Fix loop 3: `check_upgrade_head` matches Go's
  `ReadResponse` order.** Both fix-loop-2 re-reviewers
  (technical FAIL B1–B4, red-team FAIL B1–B5) found
  the same five divergences in the byte-parser, each
  verified against Go 1.27.3 source AND a probe
  program calling `http.ReadResponse` on exact byte
  inputs (this loop's probe: `/tmp/goprobe-fl3/`,
  22 cases — all five claims re-derived, none taken
  from the reviews): (1) ORDERING — Go returns a
  malformed-status error BEFORE parsing headers
  (`response.go:170-186`), so a malformed token +
  malformed header renders the token/length form
  (`ABC` + no-colon header → `status_token_length=3`,
  `1000` → `status_token_length=4`), not the fixed
  message; fix loop 2's "status error deferred until
  the whole head validates" is true only for a VALID
  code — the fix returns a malformed token's mapping
  immediately. (2) PROTO — Go validates it with
  `ParseHTTPVersion` (`response.go:186`,
  `request.go:827-847`) after the code and before the
  headers: `FOO 502`, `HTTP/1 502`, `HTTP/1.1.1 502`
  → fixed; `HTTP/9.9` and `HTTP/1.0` → resp 502; the
  fix adds a `valid_http_version` mirror (exactly 8
  bytes, `HTTP/` + digit + `.` + digit). Precedence:
  `FOO ABC` still renders `status_token_length=3`
  (status error first). (3) ACCEPT TRIM — Go trims
  BOTH ends (`readContinuedLineSlice`'s `trim` +
  `TrimLeft`): a correct key with a trailing space or
  tab MATCHES and proceeds; fix loop 2's "leading
  only" rule was wrong, and its unit test pinned the
  wrong behaviour — flipped to assert a match. The
  trim is of the VALUE after the colon, not of the
  whole line. (4) DUPLICATE ACCEPT — Go's
  `Header.Get` returns the FIRST value: first-wrong /
  second-right mismatches (`status_code=101`); only
  the first accept header counts now. The
  integration test needs a server that derives the
  correct key from the client's random nonce — a
  fixed response cannot express it (a first draft
  with the RFC example key passed pre-fix for the
  wrong reason: neither header matched the random
  key); the test uses a new local helper,
  `start_duplicate_accept_server` in `connector.rs`.
  (5) FIRST HEADER LINE — Go rejects a first line
  starting with SP/HTAB (`readMIMEHeader`'s `Peek(1)`
  check, `reader.go:538-545` →
  `malformed MIME header initial line`) → fixed; the
  fix rejects it in `check_upgrade_head`. The two
  reviewers differed in detail (red-team: only SP
  needs the new rule, "HTAB already matches";
  technical: reject SP/HTAB) — this loop's probe
  shows Go errors on BOTH, and Rust's key-byte check
  already rejects a HTAB-first line via a different
  rule, so the explicit first-line check covers both
  (harmless duplication, one rule in one place). The
  five fixes compose into one order: malformed token
  → proto → headers (with first-line rejection) →
  accept (both-ends trim, first-only) → deferred
  status error. NOTE (docs follow-up): this paragraph's
  step-1 "malformed token" gate equates "valid code"
  with "exactly 3 ASCII digits" — that premise is wrong
  for signed `+DD` tokens (Go accepts `+00`..`+99` as
  valid codes); see deviation 28 for the exact family,
  both renderings, and the specified fix. Also fixed in
  this loop: the no-colon
  error text is `malformed MIME header: missing
  colon`, not `malformed MIME header line`
  (`dial.rs` comment). Recorded, not fixed: the
  bare-LF terminator (deviation 27, pre-existing).
  The `start_reset_server` / `serve_one` no-stop-handle
  observation stands recorded (client side bounded by
  the 20 s upgrade timeout; tasks die with the test
  binary) — the new duplicate-accept server DOES
  expose `stop()`. Pinned by 4 new integration tests
  + 5 new/renamed unit tests — see the fix-loop-3
  report.

## M4b.4 Gates (cue, 2026-11-05, pre-rebase head 86a2142)

All four exit 0, no `#[allow]`:

- `cargo fmt --check` → 0.
- `cargo build --workspace` → 0.
- `cargo test --workspace` → 0, **440 passed** (baseline
  347 → **+93**).
- `cargo clippy --workspace --all-targets -- -D warnings`
  → 0.

Per-crate final counts (from the gate log):

| crate | tests | new in M4b |
|---|---|---|
| castctl-cli | 68 | +27 |
| castctl-config | 90 | +3 |
| castctl-gateway | 76 (lib 32 + auth 4 + connector 6 + gateway 22 + golden 4 + noise 3 + subscription 5) | +33 (lib +18, integration +15) |
| castctl-shared | 35 | +28 |
| castctl-transport | 111 (lib 80 + env_proxy 1 + rpc 12 + tls 1 + wireguard 17) | +2 (lib +1, tls integration +1) |
| pre-existing (log_redact 46, tg_text 10, tg_files 2, rs parity 2) | 60 | 0 |
| **total** | **440** | **+93** |

New tests by file: `castctl-shared` (`timefmt`, `status`,
`sessions`, `event`, `feed`, `usage`, `bridge`);
`castctl-config` credential tests; `castctl-cli`
`network.rs` / `runtime.rs`; `castctl-gateway`
`summary.rs`, `cookies.rs`, `auth.rs` (unit + `tests/
auth.rs`), `subscription.rs` (unit + `tests/
subscription.rs`), `connector.rs` (unit + `tests/
connector.rs`, incl. the literal-token test against
`RawUpgradeServer`); `castctl-transport` `tls.rs` (unit)
+ `tests/tls.rs`. The M4a gateway test
`dial_url_sends_redacted_literal_not_real_token` was
rewritten (the old wire assert expected
`%3Credacted%3E`); the string-level assert
(`default_ws_url` byte-for-byte == Go URL) and the
value-level assert (query value == literal) are kept.
[SUPERSEDED 2026-11-05 — see §M4c.7: the test is rewritten in M4c
to send the real (fake-in-test) token, quoted.]
Logs: `gate-logs-m4b/gate-{fmt,build,test,clippy}-m4b.log`.
The gates are re-run after the rebase onto dev-rust;
those logs are `gate-{fmt,build,test,clippy}-m4b-
rebased.log` and the result is in the writer report.

## M4b.5 Live test trên cue (2026-11-05)

Binaries: Go 0.9.0 `/usr/local/bin/castctl` (1396697 B);
Rust release `/tmp/castctl-rust-m4/rust/target/release/
castctl-rs` (23204064 B, built 19:46, backed up to
`/tmp/castctl-rs-m4b`). Read-only commands only; no
chat/send, approval, update, login, or keeper. Max 2
runs per command (run 1 on no.0 died mid-run: ssh exit
255 after `status` + `usage`; run 2 completed all 16
labels + `goal`/`idea` separately).

Profiles:

- cue-test: config `/root/castctl-live-test/config.json`
  (600), cookies `.../profiles/cue-test/cookies.txt`
  (0600, `hatch_sess` valid until 2026-12-05T03:11:56Z,
  12 cookies), direct dial (no outbound), vm_id from
  FetchSessionInfo.
- no.0 (Boss's live profile): config `/root/.config/
  castctl/config.json` written by Boss (minimal:
  default_profile + no.0 entry, cookies_file,
  node_id `a4d787ca4a5a87d9`, auto_approve=always).
  Do NOT modify it. Cookies `/root/.config/castctl/
  profiles/no.0/cookies.txt` (2809 B). Boss proved
  authenticated: `castctl --profile no.0 status`
  returns vm_id `72d127a3-2e19-4c84-b073-9ed4b82102b9`,
  sessions=110, exit 0.

### cue-test parity (controlled comparison)

16 labels, Go `--config ... --profile cue-test <cmd>`
vs Rust release (same form). `compare.py` compares
exit code, raw stdout, JSON with keys sorted, stderr.

| command | Go | Rust | raw | normalized | note |
|---|---|---|---|---|---|
| usage | 0 | 0 | MATCH | MATCH | byte-identical text, incl. `resets 2026-11-07 14:52 +07` |
| usage --json | 0 | 0 | MATCH | MATCH | JSON-identical after key sort |
| usage --raw | 0 | 0 | MATCH | MATCH | JSON-identical after key sort |
| status, threads, threads --all, history --limit 3, history --limit 3 --raw, files --limit 3, feed, feed --raw, feed-status, feed-prompt, goals, ideas, unread | 0 | 1 | DIFF | N/A (no Rust output) | Rust stderr `castctl: conn: connection error error_length=45` — the WS upgrade gets HTTP 502 from the live edge (see blocker below); Go would print 45 for the same failure (fix loop 1, T-B1 — was 47 before the fix) |

No fields were dropped for cue-test: the three usage
commands match raw; the gateway commands produce no
Rust output to normalize.

### no.0 live gate

18 labels (16 + `goal goal_62b884f95116` + `idea
idea_0b270d463ca24cc2b863ffdc79b1ea30`, IDs taken from
Go's `goals`/`ideas` outputs). Same pattern:

| command | Go | Rust | raw | after dropping volatile fields | note |
|---|---|---|---|---|---|
| usage | 0 | 0 | MATCH | MATCH | — |
| usage --json | 0 | 0 | DIFF | MATCH after dropping `bonus_tokens.balance_units` | drift (proven below) |
| usage --raw | 0 | 0 | DIFF | MATCH after dropping `topupBalance` | drift (proven below) |
| goal, idea, status, threads, threads --all, history --limit 3, history --limit 3 --raw, files --limit 3, feed, feed --raw, feed-status, feed-prompt, goals, ideas, unread | 0 | 1 | DIFF | N/A (no Rust output) | same 502 blocker |

Dropped fields (exactly these, nothing else):
`bonus_tokens.balance_units` (usage --json) and
`topupBalance` (usage --raw). No other field was
dropped; every other leaf matches.

Drift proof (Go run twice, same field moves, no code
change): `usage --json` Go×2, 4 s apart —
`balance_units` 447188087 → 447186591 (−1496);
`usage --raw` Go run 2 vs a later Go run —
`topupBalance` 447305148 → 447183505 (−121643).
Run-2 Go-vs-Rust gaps are the same direction and
scale: `balance_units` 447329611 → 447318242
(−11369), `topupBalance` 447305148 → 447276676
(−28472). The counters fall continuously because the
Boss's live session consumes tokens; the text `usage`
output still MATCHes raw because it prints rounded
values (`3B tokens left`, `10% used`).

### Blocker: the live gateway is unreachable from Rust

[SUPERSEDED 2026-11-05 — see §M4c.7: the blocker was the missing token in the WS URL, not the TLS fingerprint. The measurements below stand; the root-cause attribution and the BoringSSL-as-candidate-fix framing do not. The gateway path passes since M4c (live gate 15/15, §M4c.8/§M4c.10).]

Root cause as believed in M4b (WRONG — see note above): the Meta edge
was thought to require a Chrome TLS fingerprint. Go dials with
uTLS HelloChrome → 101. Rust (rustls) and Python
(OpenSSL) sent non-Chrome ClientHellos and got HTTP 502
(`server_connection_error`) from the edge proxy — at the time read as
fingerprint-caused routing; M4c proved the 502 was the missing token
(the same dials with the real token get 101). The
ClientHello captures are in `gate-logs-m4b/
live-evidence/` (`ch-go-ws.bin` 1748 B Chrome,
`ch-rustls.bin` 251 B). [CORRECTED in fix loop 1 (F1):
rustls 0.23.46 HAS an ECH API
(`ClientConfig::with_ech()` / `EchGreaseConfig`,
including GREASE-ECH) but no cipher/group/keyshare
GREASE and no extension-order control; ML-KEM768 exists
only via the aws-lc-rs provider, foreclosed by the
ring-only rule (aws-lc-rs banned — see §M4b.3). The
narrow claim stands: rustls cannot mimic Chrome's ClientHello —
that is a fact about rustls, not the cause of the 502.]
BoringSSL (already in the lock via honk, GREASE in its
source) is the candidate fix — a new TLS-architecture
decision for Boss, NOT attempted in PR2. Consequence:
all 13 gateway commands + `goal`/`idea` fail live
with exit 1; the HTTPS path (`usage*`) is the only
live-parity proof in this PR.

### Secrets grep proof

`grep -ri -o` per word over every file in
`gate-logs-m4b/` (fix loop 1 recount, 2026-11-05 — the
writer's counts were one gate-test log short):
`hatch_sess` 4, `auth_token` 2, `cookie` 54,
`bearer` 2, `token` 97. Command: `for w in
hatch_sess auth_token cookie bearer token; do printf
'%s: ' "$w"; grep -ri -o "$w" . | wc -l; done`
(substring, case-insensitive, one line per match).
Every match is
a test name, a script identifier, the literal
`<redacted>` placeholder, public feed article text,
or the words `hatch_sess` / `cookie` inside a chat
message that discusses cookies by name (no value).
Value-carrying patterns are all zero:
`hatch_sess=<value>` 0, `Bearer <value>` 0,
`Cookie:` header 0. No cookie, token, or auth
header value appears in any log or in the PR.

### Unverified (live)

- The entire gateway path (all 13 commands +
  `goal`/`idea`) — blocked in M4b, not merely untested.
  [SUPERSEDED 2026-11-05: unblocked in M4c; live gate 15/15,
  see §M4c.8.]
- Write-path commands (`history --download`,
  `invite`, chat/send, keeper, login, update).
- Transport (socks/vless/...): both live profiles
  dial direct; a command needing transport is
  `chưa kiểm chứng`.
- `goal`/`idea` on cue-test (no IDs were fetched
  there; covered on no.0 instead).
- `wss://` literal-token bytes on the wire (fix loop
  1, N4): unasserted — no TLS-server test harness
  exists in the repo (no `TlsAcceptor` /
  `ServerConfig` / `rcgen` in the lock), so a
  TLS-wrapped upgrade cannot be recorded in-test.
  `ws` and `wss` share `ws_upgrade` and the same URL
  string, so the gap is small, but strictly the
  TLS-wrapped request line is unasserted.
- Python-probe evidence (fix loop 1, N3): the Python
  502-vs-401 probe output has no saved log (report-only;
  the script is in `gate-logs-m4b/probe-ws.py`) and the
  Go auth-call ClientHello (SNI=muse.ai, claimed 1804 B)
  has no file on cue or in `live-evidence/` (searched
  `/tmp/*.bin` on cue, 2026-11-05). The Rust probe log
  (`live-evidence/live-ws-probe.log`) is the surviving
  evidence for the 502/401 contrast. The first-capture
  DERP bin IS preserved
  (`live-evidence/ch-derp-wrong-capture.bin` 1515 B +
  `.log`, md5-verified against cue `/tmp/ch-go.bin`) —
  it proves the first capture caught a Tailscale DERP
  connection, not the gateway; it is NOT Go's
  ClientHello.

Logs: `gate-logs-m4b/parity-cue-test/`,
`gate-logs-m4b/live-parity-no0-run2/` (108 files),
`gate-logs-m4b/live-parity-no0-run2.log`,
`gate-logs-m4b/live-evidence/` (ClientHello bins,
probe log, drift outputs).

## M4b.6 Chưa kiểm chứng

- Write-path commands are NOT live-tested in this PR
  (`history --download`, `invite`, chat/send, keeper,
  login, update): read-only only, by the PR scope.
- No transport (socks/vless/...) live test: the live
  profiles dial direct (no outbound). A command needing
  transport is `chưa kiểm chứng` until a transport is set
  up on cue.
- The live gateway path (all 13 commands + `goal` /
  `idea`): [SUPERSEDED 2026-11-05 — see §M4c.7/§M4c.8: it was
  BLOCKED in M4b by the missing token, not the TLS fingerprint;
  the live gate ran in M4c and is 15/15 byte-identical.] The
  ClientHello capture WAS done (Go 1748 B Chrome vs rustls
  251 B); no BoringSSL/TLS fix was needed.
- `usage --json`'s one-off `ConnectionError`
  (`error_length=36`) in the first parity run: the
  re-run passed (see §M4b.3); root cause unpinned,
  treated as transient. (Fix loop 1: the 36-char string
  is pinned by test as hyper's mid-body error; the live
  recurrence is still unreproduced.)
- Long-run behaviour (reconnect storms, heartbeat at the
  production 25s cadence through the CLI) was not waited;
  covered by threshold injection in M4a tests.


## M4c. Gateway qua honk Chrome TLS — swap xong, fork thử rồi revert: 502 không phải TLS

Mục tiêu: `status` exit 0 + JSON khớp Go sau chuẩn hoá, rồi
bảng 13 lệnh. Kết quả: FLOOR KHÔNG ĐẠT. `status` vẫn exit 1
(`error_length=45`, `status_code=502`) sau khi ClientHello
đã SET-identical với Go và sau fork Chrome-parity. Nguyên
nhân thật: URL WS của Rust thiếu token thật — Go gửi
token thật (`connector.go:113-120`, 4 verbs, 4 args),
Rust gửi literal. Edge 502 vì upgrade không xác thực.
(Câu chuyện `%!(EXTRA string=...)` trong §M4c.5 là SAI
— xem §M4c.7; cả hai câu chuyện cũ đều bị rút lại.)
Fork đã revert trong cùng PR; cây này trỏ lại upstream
honk. Bước tiếp theo: mirror đúng byte URL của Go trong
`default_ws_url` — làm trong task này, xem §M4c.7.

### M4c.1 Thay đổi code (so với `27a0eaf`)

- `rust/castctl-transport/src/tls.rs`: thêm
  `honk_tls_wrap<S>(stream, host) -> Result<Box<dyn TlsStream>,
  TransportError>` — dựng node honk tổng hợp
  (`Node { host, outbound: AnyTls(AnyTlsConfig { tls:
  TlsOptions { enabled: true, sni: Some(host),
  alpn: ["http/1.1"], ..Default } }) }`) → `build_connector`
  → `connect(host, stream)`; MỌI lỗi map về chuỗi cố định
  `gateway: websocket TLS failed` (29 ký tự, xem hiệu
  đính §M4c.2). Thêm `pub trait TlsStream: AsyncRead +
  AsyncWrite + Send + Unpin {}` + blanket impl (cần vì
  `Box<dyn AsyncRead + AsyncWrite>` không compile — E0225,
  một trait object chỉ chứa một non-auto trait; honk's
  `AsyncReadWrite` bị loại vì nó ép bound `Debug` lên
  các chữ ký dial generic của gateway).
  `tls_client_config()` giữ nguyên cho `http.rs` (chuỗi
  HTTPS auth qua rustls đang pass live — KHÔNG swap).
- `rust/castctl-transport/src/lib.rs`: export `TlsStream,
  honk_tls_wrap` cạnh `tls_client_config`.
- `rust/castctl-gateway/src/dial.rs`: `tls_wrap` gọi
  `honk_tls_wrap`, trả `Box<dyn TlsStream>`; `dial_secure`
  trả `WebSocketStream<Box<dyn TlsStream>>`; bỏ import
  `tls_client_config` và mọi dùng `tokio_rustls`; nhánh
  Tls của `ws_error` gọi `tls_failed()` (trước là literal
  trùng lặp). `ws_upgrade` / Noise / `connector.rs` /
  `http.rs` giữ nguyên. URL token literal giữ nguyên
  trong commit này (đó là sai lầm — xem §M4c.7; fix
  trong task tiếp theo).
- `rust/castctl-gateway/Cargo.toml`: bỏ dep `tokio-rustls`
  (chỉ `dial.rs` dùng); feature `rustls-tls-webpki-roots`
  của `tokio-tungstenite` GIỮ (dọn riêng, xem plugpoint
  §9.6).
- Test mới (3): `rust/castctl-transport/tests/honk_tls.rs`
  (`ClientHelloRecorder` + `parse_client_hello`; assert
  SNI=`localhost`, ALPN=`["http/1.1"]`, GREASE cipher,
  ext `fe0d`, group `11ec`, và handshake failure → đúng
  chuỗi `gateway: websocket TLS failed` + exit 1);
  `gateway_tls_connector_builds_for_host` (transport);
  `tls_failed_is_29_chars` (gateway). TDD: RED quan sát
  được trên cue (`E0432: unresolved import
  castctl_transport::honk_tls_wrap`) rồi GREEN.

Bẫy chrome-mode [STATIC]: `dispatch_outbound` return sớm
với `"direct"` (`rust/castctl-transport/src/config.rs:477`)
TRƯỚC khi `build_tls`/`apply_tls_mode` (`:324`) chạy.
Profile `no.0` là direct → chrome mode KHÔNG BAO GIỜ được
bật trong production path. Fix: `honk_tls_wrap` tự bật
`set_tls_mode("utls")` + `set_utls_imitate("chrome")`
(idempotent) trước `build_connector`. Không có fix này,
mọi đo ClientHello sau swap đều vô nghĩa.

### M4c.2 Hiệu đính [CORRECTED M4c]

Đo bằng máy (`len()`): `"gateway: websocket TLS failed"`
= **29** ký tự, `"gateway: websocket dial failed"` = **30**
ký tự. M4b brief/docs nói 28 — sai, chưa từng được pin
bằng test. §M4b.2 dòng 3535 vẫn ghi "28-char" (lịch sử,
không viết lại theo lệ M4b); hiệu đính này là bản ghi
chuẩn. 35-char handshake-failed, 45-char 502, 36-char
hyper body là đúng. Không động deviation 28 (+DD) —
"28" khác.

### M4c.3 Gates (cue, 1.99.1, `CARGO_TARGET_DIR=/tmp/m4c-a/m4c-target`)

- Baseline tại `27a0eaf` (trước đổi): fmt 0, build 0,
  test **467 passed / 0 failed** (29 test binaries),
  clippy `--workspace --all-targets -- -D warnings` 0.
  Log: `/tmp/m4c-a/baseline-gates.log`.
- Sau implement (upstream honk): fmt 0, build 0, test
  **470 passed / 0 failed** (467 + 3 mới), clippy 0.
  (5 lỗi rustfmt + 1 lỗi clippy `chunks_exact(2)` →
  `as_chunks::<2>().0` đã sửa trước lần chạy này.)
  Log: `/tmp/m4c-a/m4c-gates.log`.
- Sau fork (thoitiettxl-cyber/honk `802ccafb`): fmt 0,
  build 0, test **470 passed / 0 failed**, clippy 0;
  `cargo tree -p castctl-transport` vẫn resolve
  `boring-sys 5.2.0`, `quinn 0.11.12`, `quinn-proto
  0.11.19` từ git Glassyiris. Log:
  `/tmp/m4c-a/m4c-gates-fork.log`.
- Sau revert (cây commit cuối, upstream honk): fmt 0,
  build 0, test **470 passed / 0 failed**, clippy 0;
  `cargo tree` trỏ lại `daeuniverse/honk`
  `9e31cc0b`. Log: `/tmp/m4c-a/m4c-gates-final.log`.
- Release build (fork): exit 0 (1m 51s), binary
  23,307,832 B, md5 `2cd009948240cd05fb096dfa44e82907`
  (`/tmp/castctl-rs-m4c`). Release build (revert):
  exit 0 (14.14s, chỉ relink), binary 23,299,248 B,
  md5 `95dc1a101927fd2fc800b8c616a9b790` — trùng binary
  M4c-plain trước fork (cây code giống hệt, chỉ docs
  khác). Log: `/tmp/m4c-a/m4c-release-final.log`.

`Cargo.lock` note: lock commit tại `27a0eaf` đã stale —
thiếu các edge mà manifest khai (vd `castctl-cli` →
`castctl-gateway`/`castctl-shared`/`castctl-transport`/
`chrono`/`serde_json`/`tokio`; `castctl-transport` →
`rustls`/`tokio-rustls`/`webpki-roots`; `rustls` →
`log`). Mọi lần cargo chạy đều tự điền; diff lock của
PR này chỉ còn 17 dòng fill đó (không đổi version crate
nào, 3 dòng `source` honk đã về upstream).

### M4c.4 Fork Chrome-parity — đã thử, KHÔNG phải đáp án

Fork-gate F0–F3 (số đo trên cue, profile `no.0`):

- F0 (đủ điều kiện fork): ClientHello diff honk-plain vs
  Go chỉ chứa đúng 3 mục trong 4 mục cho phép — (a)
  cipher +`c009,c00a`, (b) thiếu ext `0005`/`0012`,
  (c) ALPS: Go `44cd` (payload `0003026832`), honk
  không có trên WS row (gate `alps` đòi h2 trong ALPN,
  WS pin `["http/1.1"]`). Không có mục lạ. (d) REALITY:
  không có server để probe live interop → KHÔNG làm.
- F1 (live trước fork): Go `status` exit 0 3/3 (1909 B,
  md5 `ab159233ad77373bdc1754c948b3fca7`, `vm_id
  72d127a3-2e19-4c84-b073-9ed4b82102b9`, sessions 112);
  Rust honk-plain exit 1 3/3 (`error_length=45`,
  `status_code=502`). Không phải transient.
- F2 (patch (c) tách đôi): patch (c) theo brief
  (codepoint `0`→`1`) là KHÔNG ĐỦ trên WS row vì ALPS
  không bao giờ được gắn ở đó. (c) tách thành (c1)
  codepoint `0`→`1` trong `add_chrome_alps`
  (`tls.rs:274`) + (c2) gate `alps` thành `let alps =
  chrome;` (`tls.rs:608-613`) — uTLS HelloChrome_133
  gửi ALPS vô điều kiện; path REALITY của honk đã gọi
  `add_chrome_alps` vô điều kiện (`reality.rs:125`).
  Không thêm mục mới ngoài diff đã đo.
- F3 (JA4 WS row): xem §M4c.5 — parity đạt theo nghĩa
  duy nhất khả thi (set + cipher-hash + counts); chuỗi
  JA4 đầy đủ không thể bằng nhau vì CẢ HAI phía đều
  permute thứ tự ext mỗi connection.

Fork: `https://github.com/thoitiettxl-cyber/honk`,
nhánh `feat/chrome-tls-parity`, head
`802ccafb00eed5019516911a234cf1c57c653c3a`, base
`9e31cc0bd28825afdc0e384dc989bc3f076e69cf`. 4 commit, đều
trong `crates/honk-outbound/src/tls.rs`, mỗi patch 1
commit, style honk (một dòng imperative, không body;
lý do + dẫn chứng Go ghi ở đây và `docs/provenance.md`
§13, không trong message): (a) `fix(tls): send Chrome
cipher list on plain-TLS connector` (`f64ab28`,
`set_cipher_list(CHROME_CIPHER_LIST)`); (b) `fix(tls):
enable OCSP stapling and SCT on plain-TLS connector`
(`8b8e1b5`, `enable_ocsp_stapling()` +
`enable_signed_cert_timestamps()`); (c1) `fix(tls): use
new ALPS codepoint 0x44cd` (`814b05f`, `0`→`1`);
(c2) `fix(tls): attach ALPS on every Chrome plain-TLS
dial` (`802ccaf`, gate → `chrome`). Không có test
mới trong honk (verify ở castctl: JA4 + live 101, xem
dưới). Không mở PR upstream (quyết định riêng sau).
Nhánh fork vẫn tồn tại trên GitHub làm bằng chứng;
cây castctl KHÔNG phụ thuộc vào nó nữa.

Live sau fork (vẫn 502): Go exit 0 2/2 (1909 B,
md5 `ab159233...` như cũ), Rust exit 1 2/2
(`error_length=45`) + 1 lần isolated (rs-only). Kết
luận fork-gate: **fork KHÔNG phải đáp án** — không
stack thêm patch. Revert `rust/Cargo.toml` +
`Cargo.lock` về upstream trong cùng PR.

### M4c.5 Nguyên nhân thật: token trong URL (không phải TLS)

Ba phát hiện đo được, theo thứ tự:

1. **JA4-permutation.** Capture có kiểm soát (1 lần Go
   riêng + 1 lần Rust riêng, sniffer riêng từng cửa
   sổ): Go cũng permute thứ tự extension mỗi
   connection (bin Go-only thứ tự khác bin Go phase-1,
   cùng set). JA4 hash ext nên chuỗi JA4 đầy đủ không
   bao giờ bằng nhau giữa hai lần chạy bất kỳ — mục
   tiêu F3 "JA4 bằng nhau" như viết ban đầu là không
   khả thi theo thiết kế. Mục tiêu đúng: set + hash
   cipher + counts. Với fork, Rust đạt hết: cipher
   15+GREASE (không `c009/c00a`), ext 18 (gồm `0005`,
   `0012`, `44cd`), groups `{GREASE,11ec,001d,0017,
   0018}`, sigalgs 8 giống hệt, key shares
   GREASE(1 B)+`11ec`(1216 B)+`001d`(32 B); JA4
   std `t13d1514ht_acb858a92679_*`, like
   `t13d1616ht_fdd82fda8608_*` (cipher-hash giống Go,
   ext-hash khác chỉ vì permutation). Per-extension
   lengths cũng giống hệt (vd Go 1716 B vs Rust 1716 B:
   mọi ext cùng length, kể cả `fe0d` 186 B; size
   1716/1748/1780/1812 chỉ là độ dài ECH GREASE
   payload ngẫu nhiên, cả hai phía đều vậy).
   Cùng edge IP `57.144.151.197`: Go 101, Rust 502 —
   loại trừ giả thuyết edge-IP.
2. **Full-flow capture** (`sniff-full.py`, AF_PACKET,
   log từng packet + reassemble 2 chiều; 2 lần Go +
   1 lần Rust, mỗi lần 1 flow Go / 6 flow Rust do
   retry): sau Finished, Go gửi 2 record app-data
   `0x17:1203` + `0x17:106` (wire length), rồi mới
   nhận 101 (172 B); Rust gửi 1 record 403 B rồi nhận
   502 (172 B). Cả hai đều có flight [CCS+Finished]
   64 B giống hệt. Wire length = plaintext + 17
   (overhead AEAD TLS 1.3: 16 tag + 1 inner type;
   kiểm chứng: record Finished 53 B = 36 B plaintext
   (4 header + 32 verify_data SHA-256) + 17) — nên
   plaintext: Go 1186 + 89 = **1275 B**, Rust 386 B;
   chênh lệch **889 B**. [CORRECTED fix loop 1: bản cũ
   ghi "Go 1186 B", "mang thêm 817 B" và "request tĩnh
   cả hai phía đều là 386 B" là sai — 1203/106 là wire
   length, không phải plaintext; 1186 B chỉ là record
   đầu, và 386 B chỉ là request của Rust (probe Go cũ
   dùng format 3-verbs sai nên cũng ra 386). Số đúng:
   1275 − 386 = 889 = len(quoted token) − len(literal
   10 ký tự), suy ra token đã quote dài ≈ 899 ký tự.
   Record thứ hai là đuôi của request — xem "Mở"
   cuối section này (đã giải, fix loop 1).]
3. **Root cause — `%!(EXTRA string=...)`. [SUPERSEDED 2026-11-05 — see §M4c.7: this whole item is wrong.]** Go
   `defaultWSURL` (`internal/gateway/connector.go:
   115-117`): `fmt.Sprintf("%s://%s/v1/noise?vm_id=%s&
   auth_token=<redacted>", scheme, host, quotePython(
   vmID, ""), quotePython(hatchToken, ""))` — **3 verbs,
   4 args**. Go `fmt` render arg thừa thành suffix
   `%!(EXTRA string=<token>)` gắn vào URL. Probe Go
   trên cue chứng minh verbatim: với token giả
   `FAKETOKEN-1234567890`, URL thành
   `...&auth_token=<redacted>%!(EXTRA string=
   FAKETOKEN-1234567890)` (len 135). Suy ra token thật
   dài 783 ký tự (1186 − 386 − 17 wrapper = 783).
   M4a kết luận "Go gửi literal `auth_token=
   <redacted>`" là CHƯA ĐỦ: param `auth_token` đúng
   là literal, nhưng token thật vẫn lên wire trong
   suffix EXTRA — và edge đọc token ở đó để xác thực
   upgrade. Rust chỉ gửi literal → edge 502 upgrade
   không xác thực. Điều này cũng giải thích vì sao
   rustls (M4b), honk-plain và honk-fork đều 502 như
   nhau (cả ba đều thiếu token), và vì sao `usage`
   pass (dùng HTTPS muse.ai bằng cookie, không qua
   URL WS).
   [RETRACTED 2026-11-05 — see §M4c.7: Go sends the token via
   `auth_token=%s` (4 verbs, 4 args); there is no
   `%!(EXTRA...)` suffix. The 800/817 B arithmetic and
   the "token is 783 chars" inference are withdrawn
   with the story. The capture bins stay as
   measurements; the attribution does not. What the
   length gap really is: Go sends the quoted real
   token, Rust sent the literal.]

[RESOLVED fix loop 1 — record app-data thứ hai của
Go, 106 B wire (89 B plaintext), gửi cùng timestamp
5.312 với record đầu, trước 101 (5.409), tái hiện cả
2 lần Go: là ĐUÔI CỦA REQUEST, không phải message
riêng; Rust không cần gửi gì thêm.] Cơ chế: Go
`crypto/tls` dynamic record sizing
(`conn.go::maxPayloadSizeForWrite`): record app-data
đầu tiên bị cap ở `tcpMSSEstimate(1208) − 5 (header)
− 16 (AEAD) − 1 (content-type) = 1186` byte plaintext;
phần còn lại (89 B) sang record thứ hai. Chứng minh:
(a) log `sniff-go-full.log`: `5.312 c2s len=1208
tls=[('0x17', 1203)]` + `5.312 c2s len=111
tls=[('0x17', 106)]`, 101 ở 5.409; (b) đọc stdlib
(`crypto/tls/conn.go`, `tcpMSSEstimate = 1208`,
`maxPayloadSizeForWrite` trừ header + AEAD overhead
+ 1 byte ContentType ở TLS 1.3); (c) probe loopback
chạy lại (`/tmp/rt-probe/main.go`, gorilla v1.5.3 +
stdlib): `Write(1186)` → 1 record `[0x17:1203]`,
`Write(1188)` → 2 record `[0x17:1203][0x17:19]`.
Loại trừ Noise: gorilla `DialContext` chỉ `req.Write`
1 lần rồi đọc; Noise chạy sau 101 theo thứ tự code.
Nó KHÔNG phải nguyên nhân 502: edge trả 502 cho Rust
sau ~107ms mà không chờ record này — quyết định 502
dựa trên request.

### M4c.6 Chưa kiểm chứng / bước tiếp theo

- Bảng 13 lệnh + `goal`/`idea`: KHÔNG CHẠY (floor
  `status` exit 0 chưa đạt; mọi lệnh gateway đều
  502 cùng nguyên nhân). Không chạy lại cho đủ số —
  vô nghĩa cho tới khi URL mang token.
- Bước tiếp theo — LÀM TRONG TASK NÀY (§M4c.7):
  `default_ws_url` (`rust/castctl-gateway/src/dial.rs:105`)
  render đúng byte URL của Go:
  `auth_token={quotePython(hatchToken, "")}` (dùng hatch
  token thật — hiện hàm nhận `_hatch_token` và bỏ qua).
  Đây là đảo ngược quyết định an ninh M4a — nhưng chính
  quyết định M4a đã viết trước điều kiện lật: "if later
  live proof shows the gateway needs the real token,
  change 1 place + re-enable test". Live proof là source
  Go (§M4c.7) + Rust thiếu token thì 502. Thay đổi gồm:
  1 chỗ trong `default_ws_url` + viết lại test URL (3 test
  a/b/c) + ma trận tách biến 4 tổ hợp (§M4c.8) + chạy lại
  4 gates + live probe `status` (nếu 101 thì mới chạy
  bảng 13 lệnh). Record 89 B pre-101 của Go (§M4c.5) đã
  giải ở fix loop 1: đuôi request do dynamic record
  sizing, không cần gửi thêm — live gate 15 label pass
  mà không có nó.
- (d) REALITY: vẫn là deviation mở (như M3e) — không
  có server để probe live interop.
- Upstream PR cho 4 patch fork: chưa mở; fork branch
  còn đó, quyết định sau.
- Disk trên cue: `/` còn ~5.4G sau release build
  fork (đã dọn 1.5G `debug/incremental` + cache build
  cũ 7.8G `/dev/shm/v67-target` + 11G
  `/tmp/castctl-rust-m4/rust/target` — đều là cache
  regenerable của PR đã merge, binary giữ lại;
  xem báo cáo M4c).

### M4c.7 Correction — Go gửi token thật; hai câu chuyện cũ đều SAI (2026-11-05, Boss đọc trực tiếp)

- Sự thật (đọc từ source, không qua rendered text):
  Go `internal/gateway/connector.go:113-120`:
  `fmt.Sprintf("%s://%s/v1/noise?vm_id=%s&auth_token=%s",
  scheme, host, quotePython(vmID, ""),
  quotePython(hatchToken, ""))` — **4 verbs, 4 args**.
  Token thật được URL-quote `safe=""` (comment trên:
  'with the token URL-quoted (safe=""), as in
  gateway.py'). `quotePython`
  (`internal/gateway/media.go:19-38`): byte UTF-8,
  unreserved `A-Za-z0-9_.-~` + safe literal, còn lại
  `%XX` hoa — đúng semantics của Rust
  `quote_path_param` (`castctl-transport/src/routes.rs:
  148-158`). Bằng chứng bằng số (không tin rendered
  text): trong `connector.go`,
  `grep -c 'auth_token=%s'` = 1,
  `grep -c 'auth_token=<redacted>'` = 0. Grep toàn
  repo: mọi chuỗi `<redacted>` / `[redacted]` chỉ nằm
  trong test redaction và `internal/redact/*` — không
  có trong đường dựng URL.
- Vì sao kết luận cũ sai: (a) Bẫy display redaction
  (đã ghi 2 lần trong M4a, lần thứ 3 vẫn ngã): tooling
  render `auth_token=<bất cứ gì>` thành
  `auth_token=<redacted>` trong output exec/read — `sed`
  in ra `<redacted>` ở chỗ file chứa `%s`. Chỉ
  `grep -c` / độ dài / hash mới đáng tin. (b) M4a đọc
  nhầm dòng test redaction thành đường dựng URL, rồi
  ghi thành "3 verbs, 4 args" + "Boss decision: mirror
  Go byte-for-byte" — quyết định đó dựa trên tiền đề
  sai. (c) Câu chuyện `%!(EXTRA string=...)` trong
  §M4c.5: dựng từ số đo capture (800 B chênh) + một
  probe Go mà format string đưa vào là bản 3-verbs từ
  bản ghi M4a sai — với format thật (4 verbs, 4 args)
  Go không bao giờ sinh suffix `%!(EXTRA...)`. Probe
  đó chỉ tái hiện bản ghi sai, không đo Go thật. Số
  học 800/817 B và suy ra "token dài 783 ký tự" đều bị
  rút lại cùng câu chuyện. Các bin capture vẫn là đo
  thật (Go request dài hơn Rust), nhưng attribution
  "800 B = suffix EXTRA" là sai — chênh lệch đúng là
  889 B (Go request 1275 B − Rust 386 B), tức độ dài
  token thật đã quote trừ literal 10 ký tự (Go gửi
  token, Rust gửi literal); token đã quote dài
  ≈ 899 ký tự (fix loop 1, xem §M4c.5).
- Hệ quả: (i) M4a deviation 12, M4b.2 deviation 1,
  M4b.3 "TLS fingerprint blocks the live gateway",
  §M4c.5 item 3 và §M4c.6 "bước tiếp theo" cũ đều
  SUPERSEDED (đánh dấu tại chỗ). (ii) M4b probe
  401/502: cả hai spelling đều thiếu token hợp lệ —
  401 là encoded-placeholder, 502 là
  literal-placeholder; 502 là lỗi xác thực token,
  KHÔNG phải "đã qua token check". (iii) So sánh 3
  chiều M4b (rustls+literal → 502, OpenSSL+literal →
  502, Go+literal → 101) bị confound hoàn toàn: Go
  gửi token thật, hai bên kia không — 'fingerprint
  decides' chưa từng được isolate. Fork M4c
  (ClientHello set-identical, vẫn 502) nhất quán với
  nguyên nhân token. TLS có cần Chrome hay không —
  chỉ ma trận tách biến §M4c.8 mới trả lời được.
  (iv) Điều kiện lật trong M4a ("if later live proof
  shows the gateway needs the real token, change 1
  place + re-enable test") nay đã đủ: live proof là
  source Go + Rust thiếu token thì 502. Fix:
  `default_ws_url` render `auth_token={quote(token)}`
  — 1 chỗ, xem §M4c.7b.
- Cái gì vẫn đúng: hand-written `ws_upgrade` (gửi
  target verbatim); `http::Uri` reject `<>`
  (mechanism); bẫy chrome-mode direct-profile; JA4
  permutation (Go cũng permute); hiệu đính 29/30-char;
  fork không phải đáp án (nhưng vì lý do khác: thiếu
  token, không phải vì parity chưa đủ); bin capture và
  số đo ClientHello.
- An ninh (đảo ngược M4a, ghi rõ): token thật nay đi
  trong URL WS — server/proxy log có thể thấy. Đây là
  hành vi của Go production (0.9.0 relay turn thật qua
  URL này), và edge yêu cầu nó (502 khi thiếu). Giảm
  thiểu giữ nguyên: URL không bao giờ vào log/lỗi của
  Rust — mọi error trên đường dial là chuỗi cố định
  hoặc chỉ độ dài (test (b) bắt chuỗi error-text của
  đường dial; các form 45/35/29-char được pin bằng unit
  test), và workspace không có log macro nào (grep 0
  trong `castctl-gateway/src`, `castctl-transport/src`,
  `castctl-cli/src`, ngoài import `valid_log_level` ở
  `run.rs:34`) nên không có sink log nào cho URL đi
  tới. `redact` KHÔNG được nối dây (`redact_string` 0
  caller, không crate nào depend `castctl-log-redact`)
  — bảo vệ thật là fixed-string, không phải redaction
  (fix loop 1, safety N1; xem cả doc `default_ws_url`
  ở `dial.rs`). Token không lưu trên `Gateway`. Không
  có cách khác đã chứng minh: literal → 502 ở cả 3 TLS
  engine.

### M4c.7b URL fix + test (task này)

- `default_ws_url` dùng `quote_path_param` (đã đúng
  semantics quotePython safe="") cho cả `vm_id` và
  `hatch_token`:
  `{scheme}://{host}/v1/noise?vm_id={quote(vm_id)}&auth_token={quote(token)}`.
- Tests (TDD red trước): (a) byte-exact với hằng tự
  tính tay bằng Python `quote(safe="")` — token giả
  `FAKE+tok/en=1 2é` → quoted
  `FAKE%2Btok%2Fen%3D1%202%C3%A9`, URL dài 88 ký tự
  (fix loop 1 thêm case `% & ? #`, chuỗi rỗng,
  passthrough unreserved, vm_id rỗng); (b) error-text
  của đường dial fail không chứa token giả (raw lẫn
  quoted) — phạm vi đúng của (b) là error-text của
  gateway crate, không phải log output thật (workspace
  không có logger để capture; xem §M4c.7); (c) URL
  chứa token đã quote + request ghi lại bởi
  RawUpgradeServer chứa token đã quote.
- Quote với byte UTF-8 không hợp lệ: Go string có thể
  chứa byte UTF-8 không hợp lệ (quote theo byte), Rust
  `&str` không biểu diễn được — assessed non-issue:
  token đi qua JSON nên luôn là UTF-8 hợp lệ, khác biệt
  này không tới được (fix loop 1, red-team NIT-4).

### M4c.8 Ma trận tách biến + quyết định TLS + live gate 13 lệnh (task này)

Ma trận (cue, profile `no.0`, lệnh `status`, 1 lần/ô;
Go ref exit 0, 1909 B):

| tổ hợp | exit | stdout | kết luận |
|---|---|---|---|
| token + honk-chrome | 0 | 1905 B, md5 `511ca34f…` | 101 |
| token + rustls | 0 | 1905 B, md5 `511ca34f…` (cmp IDENTICAL với ô honk) | 101 |
| literal + honk-chrome | 502 | đã biết ở `851ff99` (3/3), không chạy lại | token thiếu → 502 |
| literal + rustls | 502 | đã biết ở M4b, không chạy lại | token thiếu → 502 |

Quyết định (quy tắc Boss: rustls+token = 101 → giữ
rustls): **GIỮ RUSTLS, gỡ honk khỏi đường gateway.**
Token là biến quyết định; TLS engine không phải. Ô
rustls đo bằng switch tạm `CASTCTL_GATEWAY_TLS_ENGINE`
(env var, chỉ sống trong lúc đo) + `rustls_tls_wrap`
tạm trong `castctl-transport/src/tls.rs`; cả hai đã
xóa. Giới hạn audit trail (fix loop 1, red-team
NIT-2): không log nào trên cue ghi ô nào chạy engine
nào, và switch tạm chưa từng được commit — attribution
ô honk dựa vào record lúc đo. Kết luận giữ rustls
không phụ thuộc ô đó: ô token+rustls → 101 được
corroborate độc lập bởi live gate cuối (release binary
md5 `6a43a62f…`, rustls-only, 15 label, md5 stdout
trùng hệt `matrix-token-rustls.out`). Hai ô literal là
số liệu cũ (đã disclose ở bảng trên), không chạy lại
trong cùng cửa sổ. Code bên thua đã gỡ: `honk_tls_wrap`,
`build_gateway_tls_connector`, test
`gateway_tls_connector_builds_for_host`,
`tests/honk_tls.rs` (3 tokio tests); `honk-outbound` /
`honk-config` ở lại vì outbound dispatch vẫn dùng
(M3). `tls_wrap` trong gateway `dial.rs` gọi
`rustls_tls_wrap` vĩnh viễn. Không còn reference tới
`honk_tls_wrap` / `build_gateway_tls_connector` /
`CASTCTL_GATEWAY_TLS_ENGINE` trong `rust/` (grep 0,
trừ PORTING history).

Live gate (cue, profile `no.0`, binary release cuối
md5 `6a43a62fd6ebe2c9ad64609701f81ac6`; Go 0.9.0;
mỗi lệnh ≤2 lần; stderr cả hai bên đều rỗng):

| lệnh | Go exit | Rust exit | khớp raw? | khớp sau chuẩn hoá? | khác biệt |
|---|---|---|---|---|---|
| status | 0 | 0 | không (1909 vs 1905 B) | giá trị JSON bằng nhau, xem ghi chú | `1.0` → `1`, 2 chỗ, 4 byte |
| threads | 0 | 0 | có | có | — |
| threads --all | 0 | 0 | có | có | — |
| history --limit 3 | 0 | 0 | có | có | — |
| history --limit 3 --raw | 0 | 0 | có | có | — |
| files --limit 3 | 0 | 0 | có | có | — |
| feed | 0 | 0 | có | có | — |
| feed --raw | 0 | 0 | có | có | — |
| feed-status | 0 | 0 | có | có | — |
| feed-prompt | 0 | 0 | có | có | — |
| goals | 0 | 0 | có | có | — |
| ideas | 0 | 0 | có | có | — |
| unread | 0 | 0 | có | có | — |
| goal goal_62b884f95116 | 0 | 0 | có | có | — |
| idea idea_0b270d463ca24cc2b863ffdc79b1ea30 | 0 | 0 | có | có | — |

14/15 khớp raw byte-for-byte; `status` là lệnh duy
nhất lệch, và chỉ lệch cách viết số. Chuẩn hoá trong
bảng này không cần bỏ field nào: không có field thời
gian nào đổi giữa hai lần chạy (cả hai lần chạy
`status` mỗi bên đều byte-identical với lần đầu).

Ghi chú `status` — `1.0` → `1` (đã biết từ M4b, không
phải lỗi M4c): server gửi `size: 1.0` trong
`bookmark_display_crop` (2 chỗ). Go decode bằng
`json.Number` (`internal/gateway/calls.go:182`) nên
giữ nguyên literal `1.0`. Rust qua bridge
`from_serde` thành `JsonValue::Float(1.0)`, rồi
`format_json_float` dùng Rust `Display` (`format!
("{f}")`) nên ra `1`. Đã kiểm chứng: parse JSON hai
bên bằng nhau (`json.load` equal: True), mỗi bên ổn
định qua 2 lần chạy. Đây đúng là hạn chế đã ghi trong
`bridge.rs` ("float-spelled literal is not preserved
character-for-character") và PORTING §M4b — sửa cần
giữ literal số trong model `JsonValue` (thay đổi
shared serializer, ảnh hưởng mọi lệnh shaped), ngoài
phạm vi M4c nên KHÔNG sửa ở đây; follow-up riêng.
[FIXED pre-merge — xem §M4c.10: bridge nay giữ literal
số trong model `JsonValue`, live gate sau fix 15/15
byte-identical raw.]

Gates (cue, 1.99.1, `CARGO_TARGET_DIR=/tmp/m4c-a/m4c-target`):
`cargo fmt --check` 0; `cargo build --workspace` 0;
`cargo test --workspace` **469 passed / 0 failed**
(baseline 470 ở `851ff99`; net −1 = −1 test
`tests/honk_tls.rs` −1 test
`gateway_tls_connector_builds_for_host` (unit trong
`tls.rs`) +1 test `ws_url_is_byte_exact_go_url` —
[CORRECTED fix loop 1: bản cũ ghi −3/+3 là sai;
`honk_tls.rs` ở `851ff99` chỉ có 1 test,
`connector.rs` 20→20, `gateway.rs` 22→23, `tls.rs`
unit 2→1]); `cargo clippy --workspace --all-targets
-- -D warnings` 0; secret-grep 0 value-pattern;
`cargo build --release -p castctl-rs` 0. Sự cố giữa
chừng: `/` trên cue đầy 100% khi link debug
(`ld terminated with signal 7 [Bus error]`) do cây
debug `/tmp/m4c-a/m4c-target/debug` phình 15G + dir
release cũ `/tmp/m4c-a/m4c-target-release` 1.3G (đều
của session này) — đã xóa cả hai, build lại từ đầu,
đĩa hồi ~10–17G.

`Cargo.lock` (+17 dòng) là regeneration, không đổi
version: `castctl-cli` nhận thêm dep
`castctl-gateway`/`castctl-shared`/`castctl-transport`/
`chrono`/`serde_json`/`tokio`; `castctl-gateway` thêm
`base64`/`bytes`/`castctl-config`/`http`/`regex`;
`castctl-shared` thêm `chrono`/`serde_json`;
`castctl-transport` thêm `rustls`/`tokio-rustls`/
`webpki-roots`; `rustls 0.23.46` thêm dep `log`
(checksum không đổi). Không crate mới nào mang secret;
`log` chỉ là facade và workspace không có log macro
nào (fix loop 1, safety N4).

Evidence (cue): ma trận
`/tmp/m4c-a/live/matrix-token-honk.{out,err}`,
`/tmp/m4c-a/live/matrix-token-rustls.{out,err}`; gate
`/tmp/m4c-a/live/gate/go-*.out`, `rs-*.out` (+
`*.err` rỗng, `*.exit`); logs
`/tmp/m4c-a/gates-{fmt,build,test,clippy}.log`,
`/tmp/m4c-a/m4c-release-final2.log`.

GAP (fix loop 1): 4 file `.exit` thiếu trên cue
(`go-goal.exit`, `go-idea.exit`, `go-status2.exit`,
`rs-status2.exit`) — không log nào ghi exit code của
đúng 4 lần chạy đó (grep `go-goal|go-idea|go-status2|
rs-status2` trong `/tmp/m4c-a/*.log` = 0 hit), nên
KHÔNG bịa file. Exit 0 của 4 lần chạy chỉ suy ra được
(`.out` non-empty, cmp-identical với phía bên kia,
`.err` rỗng).

### M4c.9 Fix loop 1 — review round 1 (2026-11-05)

1 commit, xử lý hết 15 NIT trong 13 hàng của 3 review vòng 1
(technical 5, safety 5, red-team 5; 0 BLOCKING).
Gates sau loop: xem §M4c.8 (cập nhật trong commit này).

| # | NIT | Disposition |
|---|---|---|
| 1 | Technical NIT-2: số học test-count sai | fixed — §M4c.8 ghi số đúng: −1 `honk_tls.rs`, −1 `gateway_tls_connector_builds_for_host`, +1 `ws_url_is_byte_exact_go_url` (đếm lại từng file ở 2 head) |
| 2 | Technical NIT-1: test (a) thiếu case | fixed — thêm 4 case (`% & ? #`, chuỗi rỗng, passthrough unreserved, vm_id rỗng) vào `ws_url_is_byte_exact_go_url`, hằng tự tính bằng Python `quote(safe="")` |
| 3 | Technical NIT-4: claim (b) rộng hơn test | fixed — §M4c.7 + §M4c.7b thu hẹp đúng phạm vi: error-text của gateway crate, không phải log output thật |
| 4 | Technical NIT-5 + red-team NIT-3: thiếu 4 file `.exit` | recorded as GAP — không log nào ghi exit code 4 lần chạy đó, KHÔNG bịa file (xem §M4c.8) |
| 5 | Red-team NIT-1: số học request sai + 106 B | fixed — §M4c.5 số đúng (Go 1275 B, chênh 889 B, token ≈ 899 ký tự); 106 B ĐÃ GIẢI: đuôi request do dynamic record sizing (log + stdlib + probe chạy lại) |
| 6 | Red-team NIT-4: quote byte UTF-8 không hợp lệ | recorded — assessed non-issue, 1 dòng trong §M4c.7b (token qua JSON nên luôn UTF-8 hợp lệ) |
| 7 | Red-team NIT-5: `split_ws_url` fallback lặng về default port | recorded, noted — pre-existing, ngoài phạm vi, KHÔNG sửa (`dial.rs` `split_ws_url`: port parse fail → `(authority, default_port)` thay vì lỗi) |
| 8 | Red-team NIT-2: ô literal cũ + ô rustls thiếu audit trail; technical NIT-3: ô token+honk thiếu corroboration độc lập | recorded — literal cells đã disclose; corroboration của ô token+rustls bằng live gate cuối ghi rõ trong §M4c.8; câu corroboration đó cũng bao phủ ô token+honk |
| 9 | Safety N1: doc `redact` sai | fixed — doc `default_ws_url` (`dial.rs`) + §M4c.7 sửa đúng cơ chế (fixed-string + 0 log macro; `redact_string` 0 caller, không crate nào depend `castctl-log-redact`) |
| 10 | Safety N2: `request_url` nhúng URL vào lỗi | fixed — `auth.rs` `request_url` trả chuỗi cố định `"invalid URL"`; red test `request_url_invalid_url_error_is_fixed_string` (TDD: FAIL trước, PASS sau) |
| 11 | Safety N3: thiếu test render CLI | fixed — test `classify_error_connection_variants` (`network.rs`): ConnectionError length-only, ConnectionDown render message (đã truncate 200 ở construction) / bare khi rỗng |
| 12 | Safety N4: lock diff rộng hơn draft | recorded — mô tả đúng 1 dòng trong §M4c.8 (regeneration, `log` cho rustls, checksum không đổi) |
| 13 | Safety N5: thiếu test `wss://` TLS-fail | fixed — test `dial_wss_tls_failure_error_is_fixed_string_without_token` (`tests/gateway.rs`): dial `wss://` tới listener plain 127.0.0.1 → lỗi là chuỗi cố định 29-char, không chứa token |

### M4c.10 Pre-merge fix — bridge giữ literal số, `status` 15/15 (Boss, 2026-11-05)

Boss order trước khi merge PR #69: sửa luôn lệch `1.0`
vs `1` trong PR này, không để thành follow-up — mục tiêu
của port là output khớp Go, và bug ở bridge JSON (drop
float literal) sẽ ảnh hưởng mọi lệnh khác có số thực.

Điểm rơi (đã đo, 2 research độc lập đồng thuận):
`from_serde` (`castctl-shared/src/bridge.rs:38-44`) —
`as_f64()` → `Float(f64)` giết literal; `format_json_float`
(`resources.rs:355`, `format!("{f}")`) chỉ là chỗ mất mát
lộ ra (`1.0f64` → `"1"`). Sửa mỗi `format_json_float`
không cứu được vì thông tin đã mất từ bước parse. Go phía
bên kia: `decodeJSONValue` dùng `dec.UseNumber()`
(`jsonutil.go:25-45`), `writeJSON` Encoder indent 2,
không escape HTML — mọi số là literal string, phát
verbatim.

Quyết định shape — (i) `Float(f64)` → `Float(String)`
literal, GIỮ `Int(i64)`:
- Ít xâm lấn nhất: split Int/Float và semantics
  integer-first của `as_int64` giữ nguyên cấu trúc; chỉ
  payload của `Float` đổi kiểu. Không variant mới, không
  chạm 5 điểm dựng `Int(v)` production, không đổi match
  arm nào ngoài các chỗ dùng payload `Float`.
- Cả hai fixture quyết định đều đúng: `9007199254740993`
  (> 2^53, vừa `i64`) → `Int` (exact, như cũ);
  `18446744073709551615` (> `i64::MAX`) →
  `Float("18446744073709551615")` literal — sửa luôn lỗi
  làm sai chữ số hiện tại (`...52000`).
- Biến thể một variant `Num(String)` thay cả Int/Float
  (research (b) đề xuất): sạch hơn về lý thuyết nhưng
  chạm mọi match arm Int/Float và mọi điểm dựng số —
  xâm lấn hơn mà không giữ đúng thêm case nào so với (i):
  cả hai biến thể đều đọc literal từ
  `Number::to_string()` trong `from_serde`, và literal
  đó đã mất `-0` từ bước parse (xem `-0` dưới đây). (i)
  được chọn vì ít xâm lấn hơn.
- `RawValue` / `arbitrary_precision`: `arbitrary_precision`
  đã bật workspace-wide (`rust/Cargo.toml:58`) — chính nó
  khiến `Number` giữ literal; vấn đề không nằm ở serde mà
  ở bridge vứt literal đi. `RawValue` cần feature mới +
  đường decode riêng (gateway decode ra `Value`, không bao
  giờ chứa `RawValue`) + vẫn phải đổi enum — xâm lấn hơn
  ở mọi chiều, lợi ích 0 (`Number::to_string()` đã trả đúng
  literal, đã đo). Không đổi `Cargo.toml`, không thêm dep.
- `PartialEq` đổi theo literal (`1.0 != 1.00`,
  `1e3 != 1000`), khớp `json.Number` (string type) — đã đo:
  `Value("1.0") == Value("1.00")` → false.
- NaN/Inf: sau đổi này không còn đường production nào dựng
  `Float` từ `f64` (chỉ `from_serde` từ số JSON đã decode,
  mà serde reject literal NaN/Inf) nên rule cũ "render
  NaN/Inf thành `null`" không còn trigger nào tới được.
  Literal parse ra `±Inf` (vd `1e999`) vẫn là token số JSON
  hợp lệ và được emit verbatim, đúng như Go marshal
  `json.Number("1e999")`; `as_int64` của nó trả `None`,
  khớp hành vi cũ (`Float(inf)` → `None`).
- `format_json_float` mất caller duy nhất (arm `Float`) nên
  bị xóa cùng các case float của test
  `probe_json_float_format`; phần pin string-escaping của
  test đó giữ lại thành test riêng. Không còn `f64` nào
  được format trong model này; nếu tương lai cần dựng số
  từ `f64`, dùng `Number::from_f64(f).to_string()` (spelling
  canonical kiểu Go, đã đo).

Blast radius (tự grep toàn workspace trước khi đổi):
chỉ `castctl-shared` match/dựng `JsonValue` shared trực
tiếp. `castctl-telegram` 0 dùng shared `JsonValue`;
`castctl-cli`/`castctl-gateway` chỉ dùng qua `from_serde`
+ helper `as_*`, không match variant (mọi `JsonValue::`
khác trong hai crate đó là `castctl-config::JsonValue` /
`serde_json::Value`). Fixture `event.rs:244`
(`Float(42.0)`) → `Float("42.0")`, `sessions.rs:212`
(`Float(1792821457000.0)`) → `Float("1792821457000.0")`
— cả hai đi qua `as_int64` nên giá trị giữ nguyên.

`as_int64` với literal (giữ đúng semantics Go, đã pin
bằng test `from_serde_float_as_int64_follows_go`):

| literal | kết quả | vì sao |
|---|---|---|
| `"1e3"` | 1000 | parse f64 → truncate |
| `"1.0"`, `"0.0"`, `"-0.5"` | 1, 0, 0 | truncate về 0 |
| `"9007199254740993"` | exact | vừa i64 |
| `"9223372036854775808"`, `"1e100"` | `i64::MIN` | Go `int64(f)`, \|f\| ≥ 2^63 |
| `"1e999"` | `None` | parse ra +Inf |

Fixture test (TDD: đỏ trước trên code cũ — fixture
`1.0` render `"size":1`, rồi xanh sau fix):
`castctl-shared/tests/json_number_literals.rs`,
`status_numbers_keep_go_literal_spelling` — chạy đường
thật `from_serde` → `summarize_status` →
`status_summary_to_json`, assert output text khớp byte
với Go (chuỗi kỳ vọng viết tay, không tính lại bằng code
đang test; output Go đầy đủ dán trong comment của test,
đo bằng probe Go verbatim `decodeJSONValue` + `writeJSON`):

| fixture (server gửi) | Go phát ra | Rust sau fix |
|---|---|---|
| `1.0` | `1.0` | `1.0` |
| `0.0` | `0.0` | `0.0` |
| `1e3` | `1e3` | `1e3` (discriminator: đường `f64` cho `1000`) |
| `1.5` | `1.5` | `1.5` |
| `9007199254740993` | `9007199254740993` | `9007199254740993` |
| `1.50` | `1.50` | `1.50` |
| `1E3` | `1E3` | `1E3` |
| `18446744073709551615` | `18446744073709551615` | `18446744073709551615` |

Known limitation — `-0` (vòng 3, đã chứng minh bằng
probe, không fix được ở bridge): Go phát `-0` (đo bằng
probe Go verbatim: `json.Number("-0")` marshal ra `-0`);
Rust phát `0`. Nguyên nhân nằm ở bước parse, trước
`from_serde`: serde_json 1.0.145 với
`arbitrary_precision`, `parse_any_number` (`de.rs`) quét
literal vào buffer rồi thử `buf.parse::<i64>()` trước —
`"-0"` parse ra `Ok(0)` → `ParserNumber::I64(0)`, literal
bị vứt. Probe Rust đo trực tiếp:
`from_str::<Value>("-0")` cho `to_string() == "0"`,
`as_i64() == Some(0)`, không phân biệt được với input
`"0"`. Vì vậy special-case trong `from_serde` (đã thử:
kiểm `n.to_string() == "-0"`) không bao giờ kích hoạt —
test đỏ vẫn đỏ sau khi thêm code; code đó đã gỡ, không
để lại dead code đánh lừa người sau. Biến thể
`Num(String)` cũng không cứu được qua cùng đường decode
(nó cũng chỉ đọc `to_string()`). Fix thật cần tầng decode
(giữ raw number text bằng `RawValue` / custom number
handling tại các điểm decode của gateway:
`gateway.rs:903`, `auth.rs:188,255,309`,
`subscription.rs:125`) — việc riêng, cần quyết định
thiết kế riêng, không làm trong fix loop này. Không
payload thực nào của server chứa `-0` (counts / sizes /
timestamps đều không âm-zero); hành vi hiện tại được pin
bằng test
`from_serde_neg_zero_collapses_to_int_zero_known_limitation`.

Live gate sau fix (cue, profile `no.0`, release binary
md5 `be0614aa9460d29c3e9a7edbad5c6fe1`, Go 0.9.0; mỗi lệnh 1 lần/bên, đều trong
giới hạn ≤2 lần; stderr cả hai bên đều rỗng, 0 byte):

| lệnh | Go exit | Rust exit | khớp raw? | khác biệt |
|---|---|---|---|---|
| status | 0 | 0 | có (1909 B = 1909 B) | — (`"size": 1.0` cả hai, 2 chỗ) |
| threads | 0 | 0 | có | — |
| threads --all | 0 | 0 | có | — |
| history --limit 3 | 0 | 0 | có | — |
| history --limit 3 --raw | 0 | 0 | có | — |
| files --limit 3 | 0 | 0 | có | — |
| feed | 0 | 0 | có | — |
| feed --raw | 0 | 0 | có | — |
| feed-status | 0 | 0 | có | — |
| feed-prompt | 0 | 0 | có | — |
| goals | 0 | 0 | có | — |
| ideas | 0 | 0 | có | — |
| unread | 0 | 0 | có | — |
| goal goal_62b884f95116 | 0 | 0 | có | — |
| idea idea_0b270d463ca24cc2b863ffdc79b1ea30 | 0 | 0 | có | — |

**15/15 byte-identical raw; không label nào regress.**
Ghi chú `status` trong §M4c.8 ("follow-up riêng") nay đã
lỗi thời — fix này chính là follow-up đó, làm trong cùng
PR theo lệnh Boss. `seen_at_ms` là timestamp server-side
đã lưu, ổn định giữa các lần chạy: giá trị
`1793894108735` giống hệt trong cả 6 output `status` Go
trên cue (gate, gate2, 3 probe cũ, go-full) và cả 2
output Rust. `status` Go gate1 vs gate2 chỉ lệch ở
`"sessions"`: 112 → 114 (live state đổi). Evidence:
`/tmp/m4c-a/live/gate2/` (`go-*.out` / `rs-*.out` +
`*.err` rỗng + `*.exit` đều 0).

Gates (cue, 1.99.1, `CARGO_TARGET_DIR=/tmp/m4c-a/m4c-target`,
ở head cuối sau fix): `cargo fmt --check` 0; `cargo
build --workspace` 0; `cargo test --workspace` **567
passed / 0 failed** (+2 so với 565 ở `2b70a07`: 1
integration test mới + 1 unit test `as_int64` mới; test
float cũ đổi tên/kỳ vọng, không đổi số lượng);
`cargo clippy --workspace --all-targets -- -D warnings`
0; `cargo build --release -p castctl-rs` 0 (binary md5
`be0614aa9460d29c3e9a7edbad5c6fe1`). Flake ghi nhận: lần chạy test đầu fail 1
test `castctl-cli` (`unknown_profile_is_typed_cookies_missing`,
`create_dir_all` → `AlreadyExists`) — race có sẵn trong
`temp_home` (`network.rs`: nhiều test song song dùng chung
đường dẫn theo pid + `remove_dir_all` trong setup), không
liên quan đến đổi này (diff không chạm `network.rs`); chạy
lại không đổi code thì 567/0. Cơ chế (đọc từ code
`network.rs:752-768`): 6 test dùng chung
`temp_home("home")` qua `isolated_env()` — cùng một đường
dẫn trong một process test (cargo chạy test song song nhiều
thread, cùng pid); `remove_dir_all` trong setup của test B
xóa HOME của test A đang chạy giữa chừng, nên A đọc
config/cookies khác đi và fail flaky. (Số 469 trong §M4c.8 là
trước rebase; sau rebase lên `07e1c0d` là 565.)

## M5a — Telegram bot core (crate `castctl-telegram`, 2026-11-05)

M5a ports `internal/telegram` (bot core: long polling,
dispatcher, state file, approvals, claims, files,
inbound media) and the Bot-API-side command handlers of
`internal/commands` (routing, allowlist/owner gates,
callbacks, `/help`, `/start`, `/main`, `/delete` prompt,
`/autoapprove`, `/watch`, `/login` arming) to Rust,
crate `rust/castctl-telegram`. Base `dev-rust
96ce485` (M4a merged); branch
`feat/rust-m5a-bot-core`. No Go file is modified; no
`.go` harness file was added. Go base `main 1396697`.

## M5a.1 Crate map + pins

- `error.rs`: `BotError` (`Transport`, `Api{code,
  description (held, never printed), retry_after}`,
  `Validation`, `State`, `NotWired`, `Cancelled`);
  `Display` never prints the Api description;
  `error_class()` maps structurally;
  `summary()` = `format_summary(error_class,
  rune_count(Display))`.
- `types.rs`: `Update`/`Message`/`CallbackQuery`/
  `MessageContext` (`sender_id()` callback-first,
  `chat_key()`).
- `api.rs`: `BotApi` (`getUpdates` timeout param 25,
  `allowed_updates` message+callback_query only,
  `getMe`, send/edit/delete/answer, `setMyCommands`,
  `getMyCommands`, multipart upload with a fresh body
  per retry attempt, `getFile` + download); 429 retry
  exactly per Go `retryCall` (`bot.go:1527-1546`).
- `send.rs`: `Send` (split >3800 via
  `castctl-tg-text::split_text`, keyboard only on last
  piece), `SendMD`, `sendOne` HTML-then-plain fallback
  (4096 cap), `Edit` (swallows "message is not
  modified"), `EditPlain` (swallows ALL errors — Go
  deviation, mirrored), `Delete`, `answer`,
  `validate_commands` (before any request).
- `state.rs`: `telegram-state.json` v1 (atomic save:
  temp + fsync + chmod 0600 + rename, dir 0700;
  corrupt JSON → fresh + corrupt flag; unknown
  version → refuse startup; non-integer version
  shape → refuse with ≤32-rune echo; toggles as
  pointers; `sent_media` cap 500; offset
  monotonic-max only).
- `dispatcher.rs`: per-chat FIFO workers, dedupe
  window 1024 (in-memory only), queue depth 64 (full
  queue drops the NEWEST, counts it), idle reap 5m,
  shutdown drain bounded 10s, offset-before-handle
  (`onOffset` under lock, before handling, whether or
  not the queue accepted it).
- `registry.rs`: `CallbackRegistry` cap 3000, `c:`
  token, consume-before-RPC, `ApprovalMarkup` /
  `ApproveAllMarkup`.
- `approvals.rs`: `Approval` / `DescribeApproval` /
  `ChooseAutoDecision` / `ApprovalText`.
- `claims.rs`: `ApproveForever` / `awaitClaim` /
  `recordClaim` / `failClaim` / `NotifyPending` /
  `AutoLog` cap 51, `decideOnce` single-flight per id,
  decided cap 1024 oldest-first.
- `files.rs`: `SendFile` / `sendFileKind`,
  `MediaOf` / `InboxName` / `DownloadMedia` (20 MiB,
  TWO gates), `/files` list cap 12, history window
  last 40 events.
- `router.rs`: the 30-command table
  (`COMMAND_MENU`), parse, owner gate, `BotServices`
  seam trait (M5b turn runner + M4b gateway).
- `commands.rs`: `CommandHandler` (full handlers +
  seam dispatch + callbacks, `/help` byte-identical
  to Go).
- `bot.rs`: `Bot` (construction calls `getMe` once;
  poll loop; allowlist BEFORE enqueue; turn
  tracking; shutdown).

Pins: the `Cargo.lock` diff for M5a is exactly the new
member entry (`[[package]] castctl-telegram 0.1.0`
with its 16 dependencies, all already-locked crates)
plus one added edge, rustls → `log` (the `logging`
feature this crate enables, M4b's feature set; `log`
was already in the lock). NO new crate version
entered the lock and NO pin changed — the TLS direct
deps are pinned exactly to the versions already in
the lock: rustls `=0.23.46`, tokio-rustls `=0.26.6`,
webpki-roots `=0.26.11`, ring `=0.17.14`. So no
`NOTICE` / `docs/provenance.md` entry is needed for
M5a (the M3d/M4a pattern applies only when a new
direct dep is added). `rust/Cargo.toml`: exactly one
new member line (`"castctl-telegram"`, after
`"castctl-gateway"`). (Pre-rebase record at
`e25bca9`; the rebase onto merged M4b deleted the
temporary `tls.rs` and its direct deps — see
§M5a.3 deviation 1 and §M5a.9 for the rebased lock
diff.)

## M5a.2 Command table (30 rows)

`full` = Bot-API-side complete in this crate.
`seam` = handler renders/admits/gates, the work goes
through `BotServices` (gateway = M4b wiring, turn
runner = M5b). Never claim a seam-only command is
fully implemented.

| # | Command | full/seam | Reason |
|---|---------|-----------|--------|
| 1 | start | full | fixed reply (`telegram_commands.go:237-240`) |
| 2 | help | full | `telegramBotHelpText` byte-identical (`:40-64`) |
| 3 | stop | seam | `stopTurn` (M5b) |
| 4 | status | seam | sessions + unread + identity + probe (M4b/M5b) |
| 5 | chats | seam | `listChatSessions` gateway read (M4b); picker render full |
| 6 | main | full | state mapping + fixed reply |
| 7 | new | seam | `SessionStart` (M4b/M5b); mapping write full |
| 8 | history | seam | history read (M4b); N clamp [1,50] full |
| 9 | unread | seam | `chat.unread_count` (M4b); 3500-rune truncate full |
| 10 | rename | seam | gateway op (M4b); title write full |
| 11 | pin | seam | gateway op (M4b) |
| 12 | unpin | seam | gateway op (M4b) |
| 13 | archive | seam | gateway op (M4b); mapping reset full |
| 14 | unarchive | seam | gateway op (M4b) |
| 15 | delete | full* | prompt + confirm keyboard full; confirm tap runs `delete_chat` (M4b seam). NO owner gate (see §M5a.3 deviation 9) |
| 16 | approvals | seam | `egress.approvals` read (M4b); render + buttons full |
| 17 | autoapprove | full | state file only, never rewrites `config.json` |
| 18 | watch | full | state-file flag only; forwarding is roadmap step 5b, NOT implemented |
| 19 | files | seam | history read (M4b); reverse/dedupe/cap-12 render full |
| 20 | feed | seam | feed read (M4b); limit sanitise full |
| 21 | goals | seam | goals read (M4b) |
| 22 | goal | seam | `goals.get` (M4b); head + `<pre>` / `goal.json` render full |
| 23 | ideas | seam | list/execute (M4b); first-15 render + `▶️ Execute` button full |
| 24 | usage | seam | usage read (M4b) |
| 25 | wake | seam | wake (M4b) |
| 26 | fs | seam | op runs in service (M4b); text/file/rm-confirm render full |
| 27 | profile | full | local `os.Stat` on the cookies file + format (`telegram_owner.go:87-101`); no gateway call, no service (fix loop 1, tech B9) |
| 28 | update | seam | owner gate full; dry-run check (M4b) |
| 29 | login | full* | arming + instruction full; save + probe is a seam (`save_login_cookies`) |
| 30 | raw | seam | owner gate full; route check in service (M4b seam); gateway call (M4b seam) |

Full 8 / seam 22 (was 7 / 23 before fix loop 1).

There is NO `telegram sync-commands` subcommand in
Go — none was invented. The 30 are verified from
`telegramCommandMenu` + `runCommand`
(`telegram_commands.go:73-118`, `:154-235`) and the
live `getMyCommands` record in
`CASTCTL-CONTEXT.md` (menu "/" live = 30).

## M5a.3 Deviations from Go (deliberate, with citations)

1. TEMPORARY TLS module (`tls.rs`, parent decision
   1): `HttpClient` was plaintext-only and the Bot
   API is HTTPS-only, while the TLS code (`tls.rs` +
   `request_tls`) existed only in uncommitted M4b.
   DONE on the rebase onto merged M4b (`27a0eaf`):
   the module is DELETED (`castctl-telegram/src/
   tls.rs` gone, `mod tls;` gone, direct deps
   rustls / tokio-rustls / webpki-roots / hyper /
   hyper-util / http-body-util removed from the
   crate manifest), `BotApi` now uses M4b's
   `HttpClient::request_tls` (`castctl-transport`,
   ALPN `http/1.1` via `tls_client_config`, pinned
   by M4b's own test `tls_config_pins_http11_alpn`),
   and `telegram_api_target()` moved into `api.rs`.
   `castctl-transport` was NOT touched (Boss rule:
   do not edit M4b's src) — see deviation 21 for
   the one consequence of that (download cap).
2. 5xx bounded backoff in the poll loop [DEVIATION]:
   Go's bot core has NO 5xx retry — a 5xx surfaces
   to `errorsHandler` (log-only) and the library polls
   again. This crate backs off on the ladder 1s, 2s,
   4s, 8s, 16s, 30s (capped), reset on the first
   successful poll, so a sick upstream does not
   hot-loop. Ladder + reset are tested
   (`tests/bot_core.rs`: `backoff_5xx_poll_loop_retries`
   — 2×500 then success, update still handled; the
   429 path has its own test with request count +
   timing).
3. Registry tokens ARE `crypto/rand` parity (fix
   loop 1, safety B1 / tech B7 / red N3): 6 bytes
   from `rand` 0.10.3 (already a workspace dep, used
   by `castctl-gateway`, already in `Cargo.lock` —
   one dep line in `castctl-telegram/Cargo.toml`,
   zero new crates in the lock), base64url, 8 chars,
   `c:` prefix, collision-retry loop. `rand::random`
   panics if the OS RNG is unavailable, mirroring
   Go's panic on `crypto/rand` failure. The earlier
   draft derived tokens from time + counter + pid
   (predictable in principle); that construction is
   gone. Note on exploitability: there is NO API
   injection channel for callback forgery — Telegram
   only emits `callback_query` updates for buttons
   the bot itself sent, so the server already knows
   every token. The CSPRNG is Go parity +
   defence-in-depth, not a fix for a demonstrated
   forgery.
4. `error_class()` mapping (fix loop 1, tech B8):
   decode failures map in-crate to
   `ResponseDecodeFailure` / `UpdateDecodeFailure`
   with the `telegram poll error: ` prefix via
   `format_summary` (from `castctl-log-redact` —
   see §M5a.4 for why the mapping is in-crate);
   `ConnectionDown` / `ConnectionError` classify
   from the message via `fallback_class` (dns /
   timeout / tls / refused / reset / unreachable /
   eof), falling back to `Unclassified` when the
   message matches nothing — `TransportError` drops
   the DNS/TLS/errno distinction Go's
   `transportClass` reads, so the message text is
   the only signal left. `summary()` counts the raw
   error text's RUNES as Go does (`bot.go:764-770`)
   — length only, never the text itself, so no token
   leaks through the count. All 20 `ErrorClass`
   labels are emittable: `Dns` / `Tls` /
   `ConnectionRefused` / `ConnectionReset` /
   `Unreachable` / `Eof` come only via
   `fallback_class(message)` (reachable when the
   transport message matches — pinned by the
   `transport_connection_failures_classify_from_message`
   test); every other label has a direct arm.
   `ContextDeadlineExceeded` has no direct arm (no
   call site in this crate applies a deadline to a
   poll/RPC — Go emits it from
   `context.DeadlineExceeded`; the 429 sleep and the
   poll loop observe shutdown instead, which maps to
   `ContextCanceled`), but it IS emittable via the
   `fallback_class` phrase "context deadline
   exceeded" (fix loop 2, tech N-N2 — the loop-1
   claim "19/20, only `ContextDeadlineExceeded`
   unreachable" was literally wrong).
5. Download cap 16 MiB on BOTH paths [DEVIATION]:
   `HttpClient::request` AND `request_tls` cap at
   16 MiB (`MAX_RESPONSE_BODY`); neither can be
   parameterised from this crate. (Pre-rebase, the
   temporary TLS module honoured the 20 MiB+1 gate
   exactly; the rebase removed that path — see
   deviation 21 for the consequence.)
6. `inbox_name` uses a UTC prefix [DEVIATION]: Go
   uses local time (`inbound.go:146-170`); this
   crate has no tz database, so the
   `<YYYYmmdd-HHMMSS>-` prefix is UTC. The prefix is
   only a filename disambiguator.
7. `EditPlain` swallows ALL errors (Go deviation,
   mirrored, `bot.go:1701-1724`): not "fixed".
8. Claim-storm residual mirrored, NOT fixed
   (`claims.go` takeover semantics): a slow decider
   + short `ClaimWait` lets every concurrent caller
   time out, take over, and decide the same id (20
   goroutines, 150ms decider, 20ms ClaimWait → 20
   decider calls). Gateway-side idempotency is
   REQUIRED in step 5.
9. `/delete` has NO owner gate (documented
   asymmetry, Python parity, Boss-approved
   2026-11-01 — `telegram_commands.go:930-951`).
   Do not add one.
10. `/fs get` refusal wording kept verbatim:
    `Too big for Telegram (50 MB).`
    (`telegram_fs.go:330-334`, gate is 49 MiB) vs
    `downloadFile`'s `Too big for Telegram (49 MB);
    use castctl download.`
    (`telegram_commands.go:711-720`). The
    inconsistency is Go's, copied, not "fixed".
11. `currentThread` side-chat sentence kept
    verbatim: `That works on side chats. Open one
    with /chats or make one with /new.`
    (`telegram_commands.go:853-861`).
12. `setMyCommands` validation: all entries
    validated BEFORE any request (name
    `^[a-z0-9_]{1,32}$`, no dupes, description
    1–256 runes); failure only warns at the caller —
    here the error is returned and zero API calls
    are made (`bot.go:1786-1816`).
13. No CLI wiring (parent decision 2):
    `telegram run` / `status` stays a stub in
    `castctl-cli` — NOT edited here. Follow-up.
14. No `classifyError` port: M4b owns
    `classify_error` in `castctl-cli/network.rs`
    (`internal/commands/commands.go:241-360`); this
    crate must not port a second one. Rebase
    outcome (M4b merged at `27a0eaf`):
    `classify_error` is `pub(crate) fn
    classify_error(err: &TransportError) -> FlowErr`
    (`network.rs:196`), so it is NOT directly
    reusable from `castctl-telegram` — expanding
    M4b's just-merged API is out of scope. The
    in-crate `error_class` mapping is KEPT (tested,
    20/20 labels emittable via `format_summary` /
    `fallback_class` — see §M5a.4). It could be
    reused only if `classify_error` moves to a shared
    crate in a future PR; until then the two
    mappings coexist by design.
15. `WireGuard` dispatch: no `WireGuard(Arc<...>)`
    → `Arc<dyn Dialer>` conversion helper existed on
    `dev-rust` at M5a write time (M4b-only,
    uncommitted then); this crate
    writes its own 5-line match in-crate if needed.
    Rebase outcome: the "if needed" never
    triggered — this crate has ZERO WireGuard
    references, so nothing was written. M4b's
    transport exports `dispatch_endpoint` /
    `dispatch_outbound` publicly if a future need
    arises.
16. Poll offset vs state offset: the in-memory poll
    offset advances past EVERY update received
    (strangers included), mirroring the Go library,
    which advances its offset after handing each
    update to the handler. The STATE offset only
    advances for accepted updates, via the
    dispatcher's `onOffset` hook. A stranger update
    is therefore re-fetched and re-dropped after a
    restart — harmless, and exactly Go's behaviour
    (strangers "never advance the offset hook",
    `bot.go:651-667`).
17. `ApproveForever`'s once-per-id warning log has
    no sink: Go logs a warning when an approval
    offers no forever option (`claims.go:133-221`);
    this crate has no logger, so the warning cannot
    be emitted. The claim is still released exactly
    as Go does; the `warned` set was removed as dead
    state rather than kept unread.
18. Mirrored Go deviations (not introduced here):
    `DownloadMedia` Gate 2 reads through a
    LimitReader at cap+1 although upstream (Python)
    has no second gate (`inbound.go:172-221`);
    `sendDocument` fallback ONLY on `ErrorBadRequest`
    when kind ≠ document, exactly once;
    `opts.Mode` ignored; no size limit enforced in
    `SendFile` itself (`files.go:169-264`); the file
    part Content-Type is `application/octet-stream`
    (the Go library's stdlib multipart default;
    Python sets it from the filename,
    `src/muse_cli/tgapi.py:161-172`); in-memory
    dedupe window 1024 is lost on restart (Go-added
    deviation vs Python, kept).
19. `notify_pending` early-return: when a turn is
    running, pending approvals are NOT notified and
    never notified later for those ids — no reminder
    queue (`claims.go:335-412`). Mirrored as-is.
20. 5xx with an undecodable body takes the 5xx
    ladder [DEVIATION, fix loop 1, red N1]: Go's
    `getUpdates` decode fails the whole call on a
    non-JSON 5xx body (the error surfaces to
    `errorsHandler`, log-only, and the library polls
    again with no backoff). This crate maps an
    undecodable 5xx body to `Api{code: status,
    description: "", retry_after: None}` and backs
    off on the ladder (deviation 2), so an empty
    500 body cannot wedge the poll loop into a
    1s-pause retry storm. Any OTHER undecodable body
    maps to `ResponseDecode` (the Go behaviour).
21. Download cap is 16 MiB on the production TLS
    path too [DEVIATION, rebase onto merged M4b]:
    the deleted temporary TLS module honoured the
    20 MiB+1 gate exactly (`request_with_body_cap`);
    M4b's `request_tls` caps at the fixed
    `MAX_RESPONSE_BODY` (16 MiB,
    `castctl-transport/src/http.rs`, `http_over_stream`)
    with no parameter, and Boss's rule for this
    rebase forbids editing M4b's src — so NO
    parameterised-cap variant was added. A file
    whose real size is in (16 MiB, 20 MiB] now fails
    at the transport with `BotError::Transport`
    (`TransportError::Gateway` + body summary)
    instead of downloading and hitting Gate 2's
    clear `BotError::Validation("file exceeds the
    20 MiB download limit")`; Go ACCEPTS such a
    file. Gate 1 (message-declared size > 20 MiB,
    refused before download) still works — note it
    checks the size declared on the message, NOT
    `getFile`'s reported `file_size` (pre-existing
    divergence from Go, which reads `getFile`;
    see `files.rs` — the two agree for a consistent
    server). Gate 2 is UNREACHABLE while the transport
    caps at 16 MiB (`bytes.len()` can never exceed
    20 MiB); it revives unchanged if the parameterised
    cap lands. The `max_body` parameter is retained on
    `download_file_bytes` / `get_path` / `post_json`
    for the call shape (currently honoured by
    neither path). Follow-up (not this rebase): a
    parameterised cap in `castctl-transport` owned
    by a transport PR. The 3 unit tests of the
    deleted module are gone with it; their coverage
    lives on in M4b's transport tests
    (`tls_config_pins_http11_alpn`,
    `host_header_rules`) already counted in the
    467-test M4b base; the third deleted test
    (`tls_config_builds_without_panic`) is subsumed
    by the ALPN test, which calls the same
    `tls_client_config()` constructor.

## M5a.4 Reuse verification (read, not re-ported)

- `castctl-log-redact::ErrorClass` covers all 20
  labels (verified by reading
  `castctl-log-redact/src/summarize.rs`: TooManyRequests,
  BadRequest, Forbidden, Unauthorized, NotFound,
  Conflict, ResponseDecodeFailure,
  UpdateDecodeFailure, Timeout, Dns, Tls,
  ConnectionRefused, ConnectionReset, Unreachable,
  Eof, ContextCanceled, ContextDeadlineExceeded,
  Http5xx, Http4xx, Unclassified) + `label()`,
  `format_summary` (decode classes get
  `telegram poll error: `, others `telegram error: `),
  `SUMMARIZE_PREFIX_RUNES = 256`, the anchored-decode
  rule (decode classes only via anchored chain check,
  never string fallback) and the scrub-chain-dropping
  behaviour (`bot.go:1125-1200`). This crate USES
  `format_summary` and `fallback_class` from it, but
  NOT `classify_error` / the anchored rule: those
  operate on `ErrorChain` values, which this crate
  never constructs (its errors are typed
  `BotError` variants, not anyhow chains), so the
  decode-class mapping is done in-crate in
  `BotError::error_class` (fix loop 1, tech B8).
  No gap found — the other crate was NOT extended.
- `castctl-tg-text` reused as-is (M1 parity
  complete — `escape_text`, `split_text` CHUNK_SIZE
  3800, `strip_tags`, `button_text` 64 chars).
- `castctl-tg-files` reused (`file_kind_for`,
  `FileKind`, `UPLOAD_LIMIT` 49 MiB, `PHOTO_LIMIT`
  10 MiB).
- `castctl-transport::HttpClient::request` reused
  for plaintext tests (no proxy env, no redirect,
  16 MiB body cap). `RpcClient::call_json` is
  gateway-only and was NOT used for the Bot API
  (route table lookup would fail; envelope decoding
  differs).
- `castctl-config::TelegramConfig` is NOT used
  in-crate (fix loop 1, tech N11 — the M5a draft
  claimed otherwise): the token arrives as a plain
  `String` in `BotApiConfig`, and only the shape
  check `castctl_config::telegram::valid_telegram_token_shape`
  is reused. `config.json` is never re-parsed here.
  M4b did not change `TelegramConfig` (verified by
  grepping the M4b diff — no Telegram hits), so
  this still holds after the rebase.
- Rebase reuse decisions (onto merged M4b,
  `27a0eaf` — see §M5a.9): TLS REUSED
  (`HttpClient::request_tls` + `tls_client_config`,
  ALPN `http/1.1` pinned by M4b's
  `tls_config_pins_http11_alpn`); `classify_error`
  NOT reused — `pub(crate)` in `castctl-cli`, see
  §M5a.3 deviation 14; `credential_for_profile`
  NOT reused — it is M4b's login-credential API
  (`LoginCredential` username/password for
  profiles, `castctl-config/src/config.rs:165`),
  not a bot-token API, and this crate takes the
  token as a `String`; `castctl-gateway/src/
  summary.rs` NOT reused — it is M4b's gateway
  allowlist body summary (port of
  `internal/gateway/summary.go`), a different thing
  from this crate's `BotError::summary()`
  (`summarizeError` port); `dispatch_endpoint` /
  `dispatch_outbound` NOT reused — this crate never
  touches WireGuard (deviation 15). No M4b code was
  duplicated into this crate and no M4b code was
  moved.

## M5a.5 Gates (cue, 2026-11-05; fix loop 1 same day)

All four gates exit 0 on the final code (toolchain
1.99.1 via `rust/rust-toolchain.toml`):

- `cargo fmt --check --all`: exit 0.
- `cargo build --workspace`: exit 0, 0 warnings.
- `cargo test --workspace`: exit 0. Fix loop 1:
  BEFORE 402 (measured on the writer's head,
  `/tmp/castctl-rust-m5a-baseline-fixloop1.log`),
  AFTER 437 (+35, all in `castctl-telegram`: lib
  +23, integration `tests/bot_core.rs` +12). The
  writer's BEFORE 347 was measured with a
  clean-checkout run on cue
  (`/tmp/castctl-rust-m5a-baseline.log`, 347 passed,
  0 failed) — it disagrees by 1 with PORTING
  §M4a.4's "AFTER 346" (fix loop 1); cause not
  established, possibly a test added in a later
  `dev-rust` commit. The comparison here uses the
  measured 347, not the recorded 346.
- `cargo clippy --workspace --all-targets -- -D
  warnings`: exit 0, 0 errors, 0 warnings (after
  the fix loop in §M5a.7 item 5).
- Required tests (all pass in
  `tests/bot_core.rs`): routing 30/30 + unknown
  name + `@botname` + upper-case; offset persists
  across restart (no update handled twice);
  duplicate update in one batch handled once; 429
  backoff (3 `sendMessage` requests, elapsed ≥ 3s
  for two `retry_after=1` + 0.5s sleeps); 5xx poll
  backoff (2×500 then success, update handled
  once); stranger rejection (owner admitted,
  allowed non-owner refused ONLY the 4 owner
  commands with the fixed sentence, stranger
  dropped silently with no state change — offset
  stays at the last accepted id); `/help` sent text
  byte-identical to Go (constant pinned by the
  `help_text_matches_go_verbatim` unit test);
  token never in any `Debug`/`Display`/summary;
  `SetCommands` validation rejects bad names,
  dupes, overlong/empty descriptions with zero
  `setMyCommands` calls (valid menu: exactly 1).

## M5a.6 Chưa kiểm chứng

- Live `getMe` / `getMyCommands`: no bot token exists
  on cue (config has 0 token keys,
  `/root/.secrets` does not exist). Re-run when a
  token becomes lawfully available on cue:
  `castctl telegram run` (once CLI wiring lands) or
  the `get_me` / `get_my_commands` calls against
  `api.telegram.org`. NEVER send a real Telegram
  message to any user; never print/log/commit a token.
- Turn streaming is M5b (seam only, via the
  `BotServices` trait). No turn was run live.
- CLI wiring follow-up (`telegram run` / `status`
  stub in `castctl-cli`, see §M5a.3 deviation 13).
- The 5xx backoff ladder at production thresholds
  (30s cap) was not waited; covered by threshold
  injection in the poll loop (50ms ladder in tests).
- `EditPlain` swallowing all errors, the claim-storm
  residual, and the `/delete` no-owner-gate asymmetry
  are mirrored from Go, not live-proven here.

## M5a.7 Findings while writing (fail-before proofs + fixes)

1. `BotError` derived `Debug` printed the `Api`
   description (server text), contradicting the module
   doc and the `api_display_never_prints_description`
   test. Fixed with a hand-written `Debug` that
   renders the description as `[redacted]`
   (`error.rs`); `Display` already printed only the
   code.
2. Dispatcher channel closed without a processor:
   `enqueue` dropped the `mpsc::Receiver` at the end
   of the queue-creation block when no processor was
   set, so EVERY send failed closed and the queue
   could never fill to its depth of 64
   (`full_queue_drops_newest` failed at the first
   fill assert). Fixed by holding the receiver in
   `ChatQueue` until a worker takes it
   (`dispatcher.rs`). Production always sets the
   processor in `Bot::new` before the first enqueue,
   so this only bit the no-processor test path — the
   test, not the code, was the spec.
3. State-test temp paths collided across runs:
   `tmp_path()` used a per-process counter starting at
   0, so a previous `cargo test` run's saved file
   (toggles written by `set_toggles`) was re-loaded
   and `toggles_nil_means_block_values_win` failed on
   a stale `Some(false)`. Fixed by including the pid
   in the temp name (`state.rs`); `bot_core.rs` test
   dirs already did this.
4. Poll-loop shutdown could hang forever: `Bot::run`
   selected on `Notify::notified()`, but
   `notify_waiters()` wakes only waiters that are
   CURRENTLY waiting — a shutdown requested while the
   loop was between selects was lost, and the loop
   polled forever (`offset_persists_across_restart`
   and `stranger_rejection_three_cases` ran past 60s
   with no progress; the tests that passed had won
   the race). Fixed with a durable `AtomicBool`
   shutdown flag checked at the top of every
   iteration; the `Notify` only wakes a sleeping poll
   early (`bot.rs`).
5. Clippy fix loop (2026-11-05, 38 errors → 0):
   `cargo clippy --fix` on cue applied the
   mechanical fixes (collapsible `if`s, `map_or` →
   `is_some_and` / `unwrap_or`, range `contains`,
   `div_ceil`, `bool_assert_comparison`, needless
   lifetimes, redundant casts); the diff was reviewed
   hunk by hunk after pulling it back. Hand-fixed:
   three `too_many_arguments` (arity mirrors Go's
   `sendFileKind` / `HttpClient::request` signatures
   — `#[allow]` with the reason, same precedent as
   `NotifyPending`); two `match_overlapping_arm`
   (range arms → guards); one `doc_lazy_continuation`
   (reworded `+` list item); two dead test fields
   (`FakeServer.count`, `RequestRecord.path`).

## M5a.8 Fix loop 1 (2026-11-05, after the three Phase 3 reviews)

All 12 BLOCKING items fixed, all cheap NITs fixed.
Per-item fix + test (details in
`~/workspace/tmp/castctl-rust-m5a/fix-loop1-report.md`):

1. `decide_once` (tech B1 / red R1): level-triggered
   wait (`DecideInflight { done, notify }`),
   `DecideInflightGuard` Drop cleanup on EVERY exit
   incl. decider panic, waiter observes shutdown.
   Follow-up found during the loop: a waiter woken
   by the owner's shutdown-cancelled guard drop
   re-elected itself owner and returned `Ok(true)`
   — fixed with a shutdown-flag check at the top of
   the `decide_once` loop. Tests: stress (5 rounds
   × 8 waiters), owner-abort takeover,
   waiter-cancelled-on-shutdown, `set_decided`
   first-wins, claim-storm count (asserts 20, does
   NOT fix the storm).
2. Dispatcher shutdown (tech B2 / red R2):
   `abandoned` checked BEFORE processing each item.
   Test: slow processor, 50ms shutdown timeout,
   buffered items dropped AND never processed.
3. Malformed updates (red R3): `#[serde(default)]`
   on id/chat/from/file_id (Go: absent → zero;
   wrong-type item is skipped per item — CORRECTED
   by fix loop 3, red R6: the loop-1 record said
   "wrong-type still fails the whole batch", which
   was FALSE against the pinned library's per-item
   `decodeUpdate`; see the Fix loop 3 section).
   Tests: missing chat, missing update_id, callback
   missing from, result-not-array, ok:true no
   result, wrong-type item.
4. Offset overflow (red R4): `saturating_add(1)` at
   both offset sites; only other `+ 1` is the
   download-cap `+ 1` (not an update id). Test with
   `i64::MAX` / 0 / -1 / `i64::MIN` + restart
   (polls with offset `MAX`, no replay).
5. State load (tech B3): body type-mismatch →
   fresh + corrupt (Go `state.go:240-242`); unique
   temp per save (`create_new`, 0600 at creation,
   removed on error); dir chmod 0700 only when
   creating; `omitempty` serialisation; unknown-
   version error carries offset + toggle counts;
   `claim/release_sent_media` return the save
   error. Parity fixes, not deviations.
6. `set_decided` first-wins (tech B4, Go
   `bot.go:1310-1324`).
7. Markdown fallback (tech B5): Markdown mode sends
   the ORIGINAL text; only HTML strips tags. Test
   with `**bold**` (send + edit + over-limit).
8. 429 sleep cancellable (tech B6 / red N7): one
   `ShutdownSignal` shared by the poll loop and the
   API client (`call_json_timeout`,
   `send_file_multipart`); tests on both paths.
9. Registry token CSPRNG (safety B1 / tech B7 /
   red N3): `rand` 0.10.3, one dep line, zero new
   crates in the lock; deviation 3 rewritten.
10. `error_class` gaps (tech B8): decode classes
    mapped in-crate (`format_summary` prefix);
    deviation 4 corrected in fix loop 2 (tech N-N2):
    all 20 labels are emittable —
    `ContextDeadlineExceeded` has no direct arm but
    is reachable via the `fallback_class` phrase
    "context deadline exceeded" (the loop-1 "19/20"
    claim was wrong); `summary()` counts
    raw-text runes (test pin fixed 22 → 32).
11. Command table (tech B9): `/profile` FULL, local
    (`os.Stat` + format, Go
    `telegram_owner.go:87-101`); `/raw` = "route
    check in service (M4b seam)". Table 8 full /
    22 seam. `profile_text` removed from
    `BotServices`.
12. `BotApiConfig` Debug (safety B2): hand-written,
    token redacted; `token_never_in_debug_or_display`
    covers it.
NITs fixed in the same loop: safety N1 (ALPN
applied — the doc promised it, the builder did not
set it), N3 (`summary()` drops the token param),
N4 (allowlist in `process_update`), N5 (uid==0
drop), N6 (`/login` save failure → Go's fixed
sentence), N7 (20 MiB hold documented, not
changed), N8 (temp 0600 at creation); red N1 (5xx
empty body → 5xx ladder, deviation 20), N2
(`dropped()` documented as the only
observability), N5 (shutdown re-checked inside
`select!` via `shutdown_wait()`), N6 (single
answer on raced decide tap), N8 (storm count
asserted), N9 (no-worker leftovers counted);
tech N1 (`notify_pending` → struct; clippy
`too_many_arguments` allows now 3, not 4 — the
4th was `notify_pending`'s, removed by the fix),
N2 (claim/release return save errors), N3
(omitempty + unknown-version counts), N4
(`chat_key` edited → sender id), N6 (markup kept
through multipart), N7 (`dl_file_name` Go
semantics), N9 (double-start guard), N10
(`set_processor` spawns workers for pre-existing
queues), N11 (`TelegramConfig` not used in-crate),
N12 (`int_field` truncates float64), N13
(voice/video_note file_name forced `""`), N14
(`download_media` fast-errors on empty file_id),
N15/N16/N17 (router/service contract docs:
`fs_rm` text, `/new` no-session warning,
`files_list` history order), N18 (`catch_unwind`
around the `onOffset` hook).
Deferred: exactly one — red N10 (`is_auth_error`,
`commands.rs:90-95`, only matches
`TransportError::Auth`): whether a real gateway auth
failure surfaces as `TransportError::Auth` through
the M4b seam services is unverified. (Rebase
update: M4b HAS landed — `27a0eaf` — so the seam
services exist in the tree now (`castctl-gateway`);
the mapping itself is still unverified and still
deferred, now to the CLI-wiring follow-up, not to
M4b landing. Pin with a test then; do not guess the
mapping.) (Fix loop 2, tech
N-N3 — the loop-1 section wrongly said "Deferred:
none." while the fix-loop-1 report §3 listed this
same N10 as deferred.) Everything else in the loop
is either fixed or documented-in-place with its
reason (N7 size hold, N2 observability, N15–N17
contracts).
Harness notes from the loop: the fake server
paces empty `getUpdates` by 10ms (a running Bot
otherwise hot-spins and starved a sibling test
past its wait under full parallel runs); the
`offset_persists_across_restart` waits are 10s
(scheduling margin, not a behaviour bound). One
test-authoring mistake was caught and fixed in
the loop: a state test chmod'd the shared `/tmp`
to 0755 (restored to 1777 on cue); state tests
now use dedicated directories.

### Fix loop 2 (re-review of loop 1)

Re-review verdicts on loop 1: technical FAIL (only
the lock edge below), safety FAIL (only the same
lock edge), red-team FAIL (R5 below). Every loop-1
BLOCKING fix was verified as real in code (12/12
technical, B1/B2 safety, R1/R2/R4 red-team); the
failures were one landing defect and one hole in
the R3 fix itself.

1. `Cargo.lock` stale (safety L1 / technical N-B1,
   BLOCKING): `castctl-telegram/Cargo.toml` declared
   `rand = { workspace = true }` but the committed
   `rust/Cargo.lock` had no `"rand"` edge under
   `castctl-telegram` — the loop-1 report checked
   `git diff -- Cargo.lock` at the REPO ROOT, where
   no `Cargo.lock` exists, and claimed "EMPTY". The
   loop-1 gates therefore cannot have run on the
   committed tree (any build rewrites the lock).
   Fixed here: the lock gains exactly the `"rand"`
   edge (no new crate version), committed, and all
   gates re-run on the committed tree with `git
   status` clean afterwards + `cargo build --locked`
   passing. The loop-1 "EMPTY" claim is superseded
   by this record; the loop-1 report file itself is
   not rewritten (history stands, corrected going
   forward).
2. Explicit JSON `null` poisons the batch (red R5,
   BLOCKING, novel): `#[serde(default)]` only fires
   for ABSENT fields; a field present as `null`
   still failed serde for every non-`Option` type
   (`update_id`, `message_id`, `chat`, `date`,
   `Chat.id`/`kind`, `User.id`/`first_name`/`is_bot`,
   `CallbackQuery.id`/`from`, `PhotoSize`/`FileObject`
   `.file_id`, bare `null` array elements, `null`
   elements of nested vecs). Go's `encoding/json`
   treats `null` as not-present (zero value), so Go
   proceeds. Fixed with a `null_as_default`
   `deserialize_with` helper on every non-`Option`
   decode field, a `null_photo_vec` helper for
   `photo` elements, and a `null` → zero-`Update`
   arm in `get_updates`. (The sentence this item
   originally ended with — "Wrong-TYPE fields still
   fail the whole batch (Go parity — unchanged)" —
   was FALSE and is SUPERSEDED by fix loop 3, red
   R6; see the Fix loop 3 section. A wrong-type
   field fails only that item, per the pinned
   library's `decodeUpdate`.)
   Tests: every null shape in one batch with a good
   update (unit + loop-level).
3. Dispatcher residuals (red NITs 1+2, tech N-N1):
   (a) the worker's `abandoned` check and pending
   decrement now share ONE lock (two locks let
   `shutdown()` drain `pending` between them,
   counting an item dropped that was then
   processed); (b) `shutdown()` early-returns when
   already shut down, like Go
   (`dispatcher.go:264-271`). Test: double-shutdown
   with a gated processor (deterministic via a
   probe enqueue proving the first shutdown's flag
   is set).
4. Panicking-decider test (red NIT 3): a decider
   whose first call panics — the waiter still
   resolves and the next `decide_once` retries the
   RPC (calls==2). The panic path was code-verified
   only in loop 1.
5. `decide_once` checks `decided` BEFORE shutdown
   (red NIT 4): Go's `decideOnce` checks the decided
   set before observing ctx cancellation, so an
   already-decided id returns `Ok(false)` even
   during shutdown. One-line reorder, Go-verified
   (`bot.go:1345-1397`); test pins it.
6. Doc corrections (tech N-N2/N-N3/N-N4): deviation
   4 is 20/20 emittable (see item 4 above); this
   section's old "Deferred: none." contradicted the
   loop-1 report — red N10 is the one deferred item
   (M4b seam); the `/raw` comment now says the only
   in-crate part is parsing the method.
7. Deliberate decisions, documented not changed:
   no empty-batch pacing in `run()` (red NIT 5 —
   real Telegram long-polls 25s, Go would spin
   identically on a fast-emptying proxy);
   `download_file_bytes` has no 429 retry (red NIT
   6 — Go's `DownloadMedia` does one `client.Do`,
   non-200 is a plain error; `getFile` keeps the
   normal `call_json` 429 retry); `getMe` runs
   before the shutdown signal is installed (red
   NIT 7 — moot, no `Bot` exists yet to shut down);
   `approve_forever` / `await_claim` never consult
   shutdown and the `Decider` trait has no
   cancellation token (red NIT 8 — Go passes a
   cancellable ctx; fix when the trait gains one,
   M4b/M5b).

CRITICAL PROCESS LESSON (fix loop 2): after ANY
manifest change, always diff `rust/Cargo.lock`
(never repo-root `Cargo.lock` — no such file
exists) and always confirm `git status` is clean
AFTER running the gates on the committed tree. A
build that rewrites the lock means the gated tree
was not the committed tree, and every gate claim
in the report is void until re-run on the
committed tree.

### Fix loop 3 (re-review of loop 2)

Re-review verdicts on loop 2: technical PASS,
safety PASS, red-team FAIL (R6 below, novel). The
R5 fix and both R2 residuals were verified as real
in code; the failure was a pre-existing decode-path
divergence whose "Go parity" justification —
certified in review 2 and baked into a test name —
was FALSE against the pinned library source.

1. Wrong-TYPE field fails the whole batch (red R6,
   BLOCKING, novel — the loop-2 report's "Wrong-TYPE
   fields still fail the whole batch (Go parity)"
   line and this section's loop-1 item 3 wording
   are SUPERSEDED by this record; the loop-2
   report file itself is not rewritten). The Rust
   `get_updates` returned `Err(UpdateDecode)` on
   the FIRST per-item decode failure, discarding
   the whole batch; `run()` re-polled the same
   offset forever, so one malformed update starved
   every update at/after it. Go does not do that:
   the repo's bot polls through the pinned library
   (`go-telegram/bot v1.27.1-0.20261008103508-
   f53bfe55a30b`, `go.mod:8`, no `replace`;
   `internal/telegram/bot.go:519` calls
   `b.api.Start(ctx)`), whose `get_updates.go`
   decodes the envelope into `[]json.RawMessage`
   and then each item separately in `decodeUpdate`
   — "decodes one update on its own, so a single
   undecodable update does not reject the whole
   batch. On failure the id is still read when
   possible, so the offset can move past it. A zero
   id means it could not be read." The loop skips
   an undecodable item and advances `lastUpdateID`
   past any item whose id is readable; only an
   unreadable id leaves the offset stuck (with an
   exponential backoff, capped at 5s). Fixed here
   by mirroring `decodeUpdate` in `get_updates`
   (one spot, `api.rs` — NOT `types.rs`): on a
   per-item decode failure, best-effort read
   `update_id` (`item.get("update_id").and_then
   (Value::as_i64)`); readable → push a skipped
   zero `Update` carrying that id (the run loop's
   `poll_offset.max(id + 1)` advances the offset
   and the allowlist drops it by sender 0);
   unreadable (wrong-type id, float id, non-object
   element, missing id) → push a zero `Update`
   (id 0, dropped, offset unchanged) — and CONTINUE
   decoding the rest of the batch. This is a parity
   fix, NOT a new deviation. Tests: both red-team
   trigger batches at loop level (wrong-type id
   `"six"` + good update id 7; readable id 5 with
   wrong-type nested field `"chat": "oops"` + good
   update id 6), plus edge cases in the same test
   (a non-object element, a float `update_id` 5.5 —
   Go's head-ID read fails on a float too, so the
   Rust `as_i64 → None` matches). Both loop tests
   failed BEFORE the fix (10s `wait_until` timeouts
   — the good updates were never handled, the first
   execution of the R6 triggers). The test
   `wrong_type_fails_the_whole_decode_like_go` is
   renamed to `wrong_type_fails_vec_decode`: the
   `Vec<Update>`-level assertion stays true (serde's
   `Vec` decode IS all-or-nothing), but the old name
   baked the falsified parity claim into the suite
   and must not be reintroduced. The existing
   `malformed_updates_do_not_poison_the_loop` test
   is updated to the new behaviour (its batch 5 now
   expects the good item handled: 6 turns, not 5).
   `BotError::UpdateDecode` is no longer
   constructed by `get_updates`; the variant stays
   (error-class mapping + `error.rs` tests still
   reference it).
2. `FileObject.file_id: null` had no test fixture
   (tech N-N1): the loop-2 report claimed "every
   null shape" but no `document: {"file_id": null}`
   fixture existed in the unit or loop test. The
   code was already correct (the helper is applied
   at `types.rs:197`, the same generic helper as
   every other `String` field); a 4th element with
   a null document `file_id` is added to the unit
   test, asserting `""`.
3. Double-shutdown test used a wall-clock sleep
   (red NIT 3): `sleep(500ms)` before the final
   assert in `double_shutdown_counts_leftovers_once`
   is replaced by a bounded wait-until loop on
   `handled.len() == 10` (5s timeout). No
   `wait_until` helper exists in the dispatcher
   unit-test module (the one in `bot_core.rs` is
   integration-test-only), so the loop is inline.
4. `offsetStuck` backoff vs Rust's fixed 1s pause
   (red NIT 4): DOCUMENTED, not changed. After the
   R6 fix a poison batch produces NO error at all,
   so no backoff is needed: Go re-requests the same
   offset with exponential backoff (≤5s) when the
   id is unreadable; Rust drops the zero-`Update`
   and re-polls at the 25s long-poll cadence.
   Equivalent outcome (no stall, no spin), no
   backoff added.
5. All-`null` batch repolls the same offset (tech
   N-N2): RESOLVED by the library evidence, not a
   gap. Go's `decodeUpdate` returns ID 0 for a
   `null` element (`json.Unmarshal(null, &upd)` is
   a no-op, `errDecode == nil`, then `upd.ID == 0`
   → skip + `offsetStuck`), so Go ALSO does not
   advance the offset past an all-`null` batch —
   Go-identical behaviour. No code change.
6. Owner-election `select!` race (red NIT 5):
   NOT touched, not retrofitted silently. The
   loop-3 diff does not touch `claims.rs`.

Deferred NITs: exactly one — red N10 (`is_auth_error`,
M4b seam), carried from loops 1–2. (Rebase update:
M4b merged at `27a0eaf`; the seam services exist in
the tree, the mapping is still unverified — deferred
to the CLI-wiring follow-up.)

## M5a.9 Rebase onto merged M4b (2026-11-05)

M4b PR #67 merged by Boss himself (`27a0eaf`,
2026-11-05T15:55:49Z; Boss-verified: fmt 0, clippy
`--all-targets` 0, 467 test, release build 0). The
remote moving under this branch is normal (Boss
standing rule, 2026-11-05): rebase onto the new head
and re-run the gates; stop only if a conflict touches
a file that must not be edited, or another crate's
tests fail for a reason outside the rebase scope.

- M4b-base test count, measured on cue in a separate
  clean checkout of `27a0eaf` (NOT the shared M4b
  checkout): **467 passed, 0 failed** (29 suites),
  matching Boss's 467 and M4b's own gate. Run with
  `CARGO_PROFILE_DEV_DEBUG=0` +
  `CARGO_PROFILE_DEV_INCREMENTAL=false` (disk-forced;
  the default-profile build hit 100% disk, see below).
- Rebase: the 6 M5a commits replayed onto `27a0eaf`
  with exactly ONE conflict, `rust/PORTING.md` —
  both sides had appended their section before
  `## Quy tắc quyết định`; resolved by keeping BOTH,
  M4b first, then M5a, no section dropped.
  `rust/Cargo.toml` auto-merged (M4b's workspace dep
  block + M5a's `"castctl-telegram"` member line);
  `rust/Cargo.lock` auto-merged. No M4b src touched.
- TLS swap (commits `192a675` + lock refresh
  `3cf1b23`, head `3cf1b23`): temp `tls.rs` DELETED
  (file + `mod tls;` + 6 direct deps), `BotApi`
  rewired to M4b's `HttpClient::request_tls` (single
  `HttpClient` + `use_tls` flag), `telegram_api_target`
  moved into `api.rs`. ALPN `http/1.1` is M4b's
  `tls_client_config`, pinned by M4b's own test
  `tls_config_pins_http11_alpn` in
  `castctl-transport`. The 3 deleted unit tests are
  gone with the module; their coverage lives on in
  M4b's transport tests (already in the 467).
- LOCK STALE (pre-existing, found by this rebase):
  the lock at `27a0eaf` (`d85537cd...`) does not
  match M4b's manifests — M4b added manifest deps
  without updating it. `cargo build --locked` fails
  exit 101 on the PURE `27a0eaf` tree and on the
  rebased tree before refresh (`cannot update the
  lock file ... because --locked was passed`).
  Commit `3cf1b23` refreshes it: adds M4b's missing
  edges (transport rustls/tokio-rustls/webpki-roots,
  gateway base64/bytes/castctl-config/http/regex/
  tokio-rustls, cli castctl-gateway/castctl-shared/
  castctl-transport/chrono/serde_json/tokio, shared
  chrono/serde_json) AND drops the six edges the
  TLS swap removed from `castctl-telegram`. No new
  crate, no version change (verified by package-list
  comparison). Lock md5 after gates:
  `c5dfca3382a4e6ec40c6ed55087f527d`, identical
  before/after the gates.
- Gates on the committed tree `3cf1b23` (cue,
  rustc/cargo 1.99.1): `cargo fmt --check` 0;
  `cargo build --locked --workspace` 0 (run FIRST,
  on the committed lock); `cargo build --workspace`
  0; `cargo test --workspace` **560 passed,
  0 failed, twice consecutively**; `cargo clippy
  --workspace --all-targets -- -D warnings` 0.
  Test-count math: 467 (M4b base) + 96 (M5a new)
  − 3 (deleted TLS unit tests) = 560
  (`castctl-telegram` lib 70 + `bot_core` 23 = 93).
  Re-verified on the final head `82119e3`
  (PORTING-only delta vs `3cf1b23`): fmt 0,
  `build --locked` 0, test 560/0 (see rebase-report
  §7).
- DISK CAVEAT (environment, not code): the
  default-profile `cargo test --workspace` does NOT
  fit on cue's current disk — it hit 100% (81M free,
  then 24K free) twice, failing at link time with
  `ld terminated with signal 7 [Bus error]` /
  `No space left on device (os error 28)` before any
  test ran. Other sessions hold ~24G in `/tmp`
  (`m4c-a` 15G, `castctl-rust-perf1` 9.4G — never
  touched); only this task's own target dir was
  cleaned. The two passing test runs therefore used
  `CARGO_PROFILE_DEV_DEBUG=0` +
  `CARGO_PROFILE_DEV_INCREMENTAL=false` (target
  1.6G; the count is profile-independent). fmt /
  build / `--locked` / clippy all ran on the
  default profile. Re-run the default-profile test
  when disk allows.
- Reuse decisions and the download-cap consequence
  are in §M5a.3 deviations 1, 5, 14, 15, 21 and
  §M5a.4. Live `getMe` / `getMyCommands`: still
  never verified — no bot token on cue (see §M5a.6).

## M5b — Telegram turn engine + two-way media + approvals (2026-11-05/06)

M5b ports the turn engine of `internal/commands`
(`telegram_turn.go`, `wait.go`, `telegram_preview.go`)
plus the `internal/wait` core (`waiter.go`, `replies.go`,
`reason.go`, `history.go`), the approval decide path
(`telegram_approvals.go`, `internal/telegram/approvals.go`,
`claims.go`), the media delivery path
(`telegram_turn.go:793-1426`, `files.go`, `inbound.go`),
and the production `BotServices` + `Decider` impls that
M5a left as test doubles. Crate `rust/castctl-telegram`;
branch `feat/rust-m5b-turns`; base `dev-rust 07e1c0d`.
No Go production file is modified. One Go harness file
is extended: `rust/parity/gateway_server/main.go`
(`serve-e2e` mode, stateful scripted history). Go base
`main 1396697` (same as M5a).

## M5b.1 Crate map + pins

- `preview.rs`: `StreamPreview` — `PREVIEW_TAIL_RUNES`
  3300, initial status `"⏳ Muse is working…"`,
  `format_elapsed_secs` (<60s `"Ns"`, <3600 `"Mm SSs"`,
  else `"Hh MMm"`), part-key aliasing (first-seen wins),
  `delta.message_start` resets a known key only,
  `delta.presentation` ignored, online suppressed until
  `seenWork`, app status wins over derived tool labels.
- `wait.rs`: `Waiter` (approvals-first feed, F8 re-arm,
  `seenRunning` gate, suspect terminals need history
  proof via `Settle`), `replies_after` (literal
  `message.assistant` + `completed` only), `user_ack`
  (contains either way), `needs_input_reason` (34 wait
  phrases, safety regex, gate regex — all literals from
  `internal/wait/reason.go:24-169`, read verbatim
  2026-11-05), `outcome_of` / `exit_code` (done 0,
  needs_input/needs_approval 4, failed 2, timeout 124).
- `turn.rs`: `TurnRunner` (one turn/chat, spawn gate,
  stop registry, resumed guard), `BubbleEditor` (1s
  ticker, throttle-before-render, text-compare,
  shown/lastEdit written BEFORE the network call,
  `editFinal` calls `finish()` first; the edit attempt
  times out after 15s (`EDIT_FINAL_TIMEOUT`), and the
  fallback send is one `call_json_timeout` call
  (`api.rs:441-479`): up to 3 attempts × 40s
  `CLIENT_TIMEOUT` + 2 × (60s max `retry_after` +
  0.5s `RETRY_AFTER_PAD`) ≈ 241s — so the full
  `edit_final` worst case is ≈ 15s + ≈ 241s ≈ 256s,
  not "detached 15s" (corrected in fix loop 1, Red
  N2). `deliver_send` (baseline 1+20, ack poll
  100ms / 30s), `wait_follow` (see deviation 1),
  `deliver_final` / `deliver_media_turn` /
  `deliver_media_item` / `collect_turn_media` /
  `build_turn_segments`, `outcome_notes`,
  `final_markup`, `question_options` (widget → list →
  generic 👍/👎/▶️), `media_path` (hand-rolled
  `quote_python` + percent-decode), `doc_name`,
  `turn_error_text`, `media_failure_class`.
- `services.rs`: `GatewayBotServices` (production
  `BotServices`: 10 real methods — `start_turn`,
  `stop_turn`, `wait_turns`, `resume_turn`,
  `inbound_media`, `pending_approvals`,
  `decide_approval`, `files_list`, `download_file`,
  `raw_call` — the other 19 return
  `BotError::NotWired("<method>")`, listed here as the
  M4b-gateway follow-up boundary; corrected in fix
  loop 1, Tech N5 — the count was "9" with the same
  10 names listed) and `GatewayDecider`
  (one `egress.approval.decide` call, body exactly
  `{"decision": "<decision>"}`; safe because that
  method is deliberately NOT in `POST_READ_METHODS`,
  so `safe_to_repeat` is false and no post-send retry
  happens — matches Go's no-retry `callDecide`).
- `castctl-gateway/src/gateway.rs`: forced addition
  `Gateway::open_stream` (public, wraps private
  `open(..., track=false)`; Go `stream.go` `open`).
  No other gateway change. `open`/`next` stay private.
- `tests/turn_e2e.rs`: env-gated offline E2E (see
  M5b.6). Fake token literal
  `123456:FAKE-TOKEN-TEST-ONLY-AAAA` only; no real
  Telegram traffic, no token copied from anywhere.
- `files.rs` (M5a file, additive only): pure
  `truncate_caption` extracted from `send_file`
  (identical `.take(CAPTION_LIMIT)` logic) so the
  1023/1024/1025 boundary is unit-testable; no
  behavior change.

## M5b.2 BotServices home decision

The production `BotServices` impl lives in
`services.rs` inside `castctl-telegram` — no new crate,
no workspace edit. Reason (self-decide rule, no
evidence either way in the repo): the seam trait
(`BotServices` in `router.rs`) and its impl stay in one
crate; the impl needs `castctl-gateway`
(`SharedConn`) + `castctl-shared`, and the gateway does
not depend on telegram, so no cycle exists. A separate
crate would add a workspace member + a dependency edge
for no seam benefit.

## M5b.3 Deviations from Go (deliberate, with citations)

1. **No `chat.subscribe`; follow = history poll.**
   Rust has no subscribe implementation anywhere
   (`grep subscribe` in `castctl-gateway`,
   `castctl-transport`, `castctl-cli` is empty;
   `SubscribeRaw` was not ported in M3). Porting the
   full Go Runner (`internal/wait/runner.go` 1295
   lines + `waiter.go` 768 + `replies.go` 366 +
   `history.go` 345, with settle/checkState/endgame)
   is out of scope for one M5b pass. Instead
   `wait_follow` polls `chat.history` (limit 200)
   every 1s, feeds new events (seq order) to the
   ported `Waiter` + `StreamPreview`, tries `Settle`
   on an ignored terminal with a `RepliesAfter` proof,
   and does a final history read at finish. Bubble
   updates therefore land at poll cadence, not on
   push; the final text still comes from the history
   re-read, as in Go.
2. **Runner-owned active set.** `Bot::begin_turn` /
   `end_turn` cannot be called by the runner because
   `Bot::new` requires the services first (circular
   construction); `Bot::new`'s signature is unchanged
   (would break M5a tests). Two sets exist; the
   runner's set drives all M5b decisions. Consequence
   (verified from Go `telegram_turn.go:316-396`): Go's
   `startResume` checks the bot core's second set
   (`HasActiveTurn`) after acquiring the slot — in
   Rust that check collapses into the slot wait.
3. **`/fs get` "50 MB" wording kept verbatim.**
   Go says `"Too big for Telegram (50 MB)."` at
   `telegram_fs.go:334-335` while the gate is 49 MiB
   (`files.go`); the `/files` download button says
   `"Too big for Telegram (49 MB); use castctl
   download."` (`telegram_commands.go:721,733`). Each
   string is ported verbatim per call site, not
   unified — the contradiction is Go's, not Rust's.
4. **Cap 6 counted after dedupe, before claim — and
   the send list IS truncated.** Go
   (`telegram_turn.go:1145-1155`) appends the excess
   note, then `items = items[:maxFilesPerTurn]`. The
   first M5b version computed the note but sent all 7
   files; the cap-6 edge-case test caught it
   (2026-11-06) and the truncation was added. The
   deviation vs Python (Go counts already-sent files
   against the 6) is Go's behaviour, ported as-is.
5. **`inbox_name` uses UTC, not local time** (M5a
   deviation 6, inherited — the E2E fs.write path
   `telegram-inbox/20261105-195242-photo.jpg` shows
   UTC while cue local time was 2026-11-06 02:52+07).
6. **Download Gate 1 checks the message-declared
   size, not getFile `file_size`** (M5a deviation 21,
   inherited); **Gate 2 is unreachable** at the
   16 MiB `request_tls` cap (Go accepts files up to
   20 MiB). No criterion lowered: the gates are
   ported as written; the transport cap is the
   blocker, recorded here for the follow-up.
7. **Claim-storm residual, mirrored.** Go's
   double-decide has 3 layers (registry Consume,
   `decideOnce` single-flight cap 1024, approval
   claim protocol `claimChainMax=3`, `ClaimWait`
   15s); with 20 goroutines + a slow decider (150ms)
   + ClaimWait 20ms, 20 Decide RPCs fire for one id
   — gateway-side idempotency is REQUIRED and
   unproven. Rust mirrors the same 3 layers
   (`CallbackRegistry::consume`, `ClaimManager::
   decide_once`, `approve_forever` claim chain), so
   the same residual applies. [NEEDS-MEASUREMENT]
   on a live gateway.
8. **Decide burns the button.** `consume` happens
   BEFORE the Decide RPC (Go `bot.go:1398-1446`;
   M5a `commands.rs` `cb_decide`), so a failed Decide
   still burns the button; retry needs a fresh
   `/approvals` listing. Ported as-is.
9. **No owner check on decide buttons — verified Go
   behaviour, ported exactly.** Go has NO owner check
   on decide buttons; the owner gate covers only
   `profile`/`update`/`login`/`raw`
   (`internal/commands/telegram_owner.go:65-73`);
   `/approvals`, `/autoapprove` and decide buttons are
   open to every allowlisted user, first tapper wins.
   No owner check was added.
10. **`approve_forever` swallows per-id decide
    errors**, so `WaitResult.auto_approve_errors` is
    always empty from the `ClaimApprover` used by the
    waiter (decisions are still correct). The error
    list is populated only by the waiter's own
    approver path in Go; Rust's `ClaimManager::
    approve_forever` returns just the approved ids.
    Recorded, not fixed: changing the `ClaimManager`
    API is a follow-up, not M5b.
11. **Elapsed timer: the bubble is NOT re-edited
    between deltas.** Go's code comment claims the
    ticker refreshes the elapsed time, but
    `telegram_turn.go:699-728` (`maybeEdit` returns
    early when `!dirty`) means the elapsed timer
    alone never triggers an edit. Rust ports the
    actual behaviour.
12. **`requireRunning` is a dead flag in Go**
    (`internal/wait/waiter.go:151-156`,
    `internal/commands/wait.go:253` "accepted, no live
    effect") — no effect ported.
13. **History-error swallow rule extended to follow
    polls — now bounded (fix loop 1).** Go's ack-poll
    rule (history errors swallowable only if
    GatewayError/TimeoutError) is applied to the follow
    polls too; any other history error fails the turn.
    The follow poll additionally fails the turn after
    `FOLLOW_HISTORY_ERROR_BUDGET` (30s) of continuous
    swallowable errors — deviation 17.
14. **M4c token fix: in base since the rebase onto
    `c7b1d34` (2026-11-06) — OBSOLETE as a limitation.**
    At the M5b base `07e1c0d`, `default_ws_url`
    (`rust/castctl-gateway/src/dial.rs`) still sent the
    literal token string; the real-token fix lived on
    `feat/rust-m4c-chrome-tls` (PR #69). Boss merged
    PR #69 on 2026-11-05 (dev-rust `c7b1d34`,
    independently verified gates + live parity 13/13
    on cue). M5b rebased onto `c7b1d34` on 2026-11-06,
    so the fix is in the base: this is no longer a
    known limitation. The offline E2E is unaffected:
    the fake `gatewaytest.Server` does not validate
    the WS token.
15. **Editor stop flag (Rust-only bug, found by a
    hang).** `BubbleEditor::finish` used a bare
    `Notify::notify_waiters`; when `finish()` ran
    before the loop task first polled, the wakeup was
    lost and the loop waited forever
    (`edit_final_falls_back_to_send_on_error` hung
    >60s in the gates3 run, 2026-11-06). Fixed with
    an `AtomicBool stopped` flag checked at the top
    of each loop iteration; the flag is the authority,
    the `Notify` is only a wakeup. Regression test
    `finish_before_loop_starts_returns_promptly`.
16. **serve-e2e query-string bug (harness, found by
    the first E2E run).** The Rust gateway sends GET
    params as a query string (`/chat/history?limit=10`
    with an empty body); the scripted handler matched
    paths exactly and parsed the limit from the body,
    so every history call fell into the default case
    and returned `{}` — the ack poll looped the full
    30s. Fixed in the harness: strip the query before
    matching, read the limit from the query when the
    body has none.
17. **Follow-poll history-error budget (fix loop 1,
    deliberate deviation).** The follow poll has no
    `chat.subscribe` to resubscribe on (deviation 1),
    so a dead gateway would poll silently to the 6h
    turn timeout with no notice, no backoff, no
    escalation — and `wait_turns` joined without a
    timeout, so shutdown hung too. The fix bounds
    *consecutive* swallowable history errors in
    `wait_follow` at `FOLLOW_HISTORY_ERROR_BUDGET =
    30s`: the turn then fails with the gateway error
    text (`editFinal` reports it, the slot is
    released). The bound is derived from Go, not
    invented — two independent anchors:
    - the ack deadline, 30s
      (`internal/commands/telegram_turn.go:175`);
    - the Runner's `ReconnectBudget = 30s`
      (`internal/wait/runner.go:30-31`) — the duration
      Go tolerates a storm of failed resubscribes
      before escalating to a bounded state check
      (`noteFailure`, `runner.go:701-713`).
    Go's push stream can recover on the next
    resubscribe; the Rust history poll cannot, so at
    the same 30s boundary the poll fails the turn
    instead of escalating to a state check it does not
    have. Backoff between error polls mirrors Go's
    resubscribe pause: base 1s (`DefaultResubPause`,
    `runner.go:33-34`), doubling with the shift capped
    at 5 (max 32s, `runner.go:426-435`); with the 30s
    budget the poll fails after ~31s. The backoff
    sleep watches the stop notify (`select!`), so
    /stop stays prompt. `wait_turns` now signals every
    registered stop before joining, and a turn
    registered after shutdown began is signalled at
    registration — the join is bounded by the same
    turn-cancellation rule as Go's `Wait`
    (`telegram_turn.go:240-249`). Note the honest
    difference: Go itself would wait to the 6h
    deadline and report a timeout outcome
    (`executeWait` catch-all → timeout,
    `internal/commands/wait.go:349-360`); failing at
    30s of continuous gateway errors is a deliberate,
    documented choice to surface a dead gateway
    instead of polling silently for hours.
18. **`notified`/`resumed` are never pruned —
    matching Go (known limitation, fix loop 1, Red
    N4).** Go's `claims.go` `notified` set is only
    ever added to, and the `resumed` map is never
    pruned either. Rust matches both. The `tasks` vec
    IS pruned (finished `JoinHandle`s are dropped
    before pushing a new one); the `decided` set was
    already capped at 1024 with oldest-first
    eviction.
19. **Fixed multipart boundary (Safety N7, NOT
    fixed — follow-up).** The root cause is in M5a
    (`castctl-transport` multipart construction),
    outside the M5b diff; recorded here as a
    follow-up, not fixed in this loop.
20. **`outcome_notes` carries `res.note` (fix loop
    2).** Go's `outcomeNotes`
    (`telegram_turn.go:1391-1429`) never mentions
    `res.Note`: the note surfaces in CLI wait output,
    not the bubble. The bot bubble has no CLI, so
    the note must ride the notes — otherwise a
    final-read failure shows `"(no reply text)"`
    with no explanation. The `"⌛ Still running
    after 6h…"` line is suppressed when
    `final_read_failed`: a final-read timeout is not
    a 6h timeout.
21. **`edit_final` fallback send races the turn
    stop (fix loop 2).** Go runs the fallback send
    on a detached 15s ctx and still attempts the
    `"⏹ Stopped."` confirmation after /stop
    (`telegram_turn.go:755-767`). Rust abandons the
    fallback send on stop: in a 429 storm the
    fallback would otherwise hold the slot ~241s
    (3 attempts × 40s + 2 × 60.5s sleeps). The
    primary edit keeps its 15s attempt, so the stop
    confirmation is attempted once, not twice.
22. **`finish()` stop-win abandons the join (fix
    loop 2).** Go joins unconditionally
    (`telegram_turn.go:728-745`) but is bounded
    because the turn ctx cancels the in-flight
    edit. Rust has no turn ctx; the stop is the
    bound. The trailing edit is skipped on the stop
    win — the in-flight edit already raced the same
    stop in `maybe_edit`, so the loop exits on its
    own.
23. **`history_replies` newest-N assumption (fix
    loop 2).** Widening assumes the gateway returns
    the newest N events for `limit=N` — the same
    assumption Go's `HistoryReplies` makes
    (`history.go:216-257`). If a gateway returned
    oldest-N or unsorted windows instead, widening
    could not recover old replies and the exhaustion
    note could fire spuriously. The E2E harness
    returns all events regardless of limit (no
    `has_more`), so widening is exercised only by
    the unit tests' `WindowPort`.
24. **Lag window stays a single 1s re-read (fix
    loop 2).** Go polls to the lag-window end
    (`runner.go:1023-1250`); Rust re-reads once
    after 1s, as in the first M5b version.
25. **Proof-restore skips the follow-up exclusion
    entirely (fix loop 2; corrected in review round
    3).** Rust never runs Go's `LatestUserSeq` +
    `withinTurn` step (`internal/wait/runner.go:
    1105-1199`): (i) final replies after a newer
    user message are NOT excluded, (ii) proof
    replies restored into the final read pass
    through no filter, (iii) the note `"replies
    after a newer user message were excluded"`
    never appears. User-visible consequence: a
    user follow-up sent mid-turn can make the first
    turn's final text / question / outcome pick up
    the follow-up turn's replies. Known limitation,
    no new loop.
26. **`deliver_final` does not listen to stop (fix
    loop 2, residual; scope corrected in review
    round 3).** Not only media sends — every
    send/edit in `deliver_final` (`turn.rs:2552`,
    media items and long-reply text segments
    alike) runs to completion once started; see
    deviation 29 for the bounds. Known limitation.
27. **Per-window retry is deliberate leniency, not
    Go parity (fix loop 2; corrected in review
    round 3).** Go's `HistoryReplies`
    (`history.go:216-257`) calls `ReadHistory`
    directly — 0 retries. The one-retry
    `readWindow` (`history.go:259-278`) is used
    only by `DeriveBoundary` / `LatestUserSeq`
    (`history.go:95`, `~150`). Rust retries once
    per window on any non-auth error. Consequence:
    a transient error in one window is masked →
    `Done` instead of `Timeout`; the recovered
    replies are real, so the outcome is still
    right — low harm. Known limitation.
28. **`finish()` trailing edit does not listen to
    stop (review round 3, Red B1).** The stop win
    in the join `select!` does skip the trailing
    edit (deviation 22 — that part stands), but
    once the join arm wins, or when `turn_stop` is
    `None`, the trailing `edit_plain` in
    `finish()` (`turn.rs:1199-1202`) runs
    unconditionally: no timeout, no stop race — so
    a 429 storm on that final edit ignores /stop
    for up to ~241s (3 attempts × 40s
    `CLIENT_TIMEOUT` + 2 × 60.5s `retry_after`
    sleeps) while the slot stays held and
    `wait_turns` blocks behind it. The current
    regression test feeds a single delta, so the
    trailing edit is skipped (`text == shown`)
    and this hole has no test coverage. Fix is
    small (skip/race the trailing edit once
    `turn_stop` is set — the flag is already in
    scope) if taken as a follow-up. Known
    limitation.
29. **`deliver_final` is entirely deaf to stop
    (review round 3, Red B2; extends deviation
    26).** Not only media sends — every send/edit
    in `deliver_final` (up to 6 media files,
    multi-segment long text replies) ignores the
    per-turn stop; each `send_file` up to ~481s
    (3 × 120s `UPLOAD_TIMEOUT` + 2 × 60.5s),
    each gateway download 300s, each JSON
    send/edit ~241s; 6 files → ~2h theoretical,
    ~15–25 min in a real storm. Real divergence
    from Go: Go's `stopTurn` calls
    `entry.cancel()` (`telegram_turn.go:437`);
    `deliverFinal` / `deliverMediaSegments` /
    `deliverMediaItem` all take the turn ctx and
    `deliverMediaSegments` returns `ctx.Err()`
    (`telegram_turn.go:1231`) — Go aborts
    mid-delivery on stop, Rust runs to the end.
    Retry sleeps listen only to the process
    shutdown signal, not the per-turn stop. Known
    limitation, follow-up (needs the stop passed
    down into `deliver_final`).

## M5b.9 Fix loop 2 (2026-11-06, review round 2)

Every BLOCKING from review round 2, fixed red-test
first. Red run on cue (`cargo test -p
castctl-telegram --lib`): **128 passed, 14 failed**
— all 14 targeted (the `follow_backoff` test failed
on its timing bound as predicted pre-fix; the three
B3 fixtures were corrected after the red run — the
`Waiter` needs a `running` event before a
`completed` terminal, else the terminal is a suspect
ignored terminal and `wait_follow` times out).

- B1 (`python_float` scientific threshold, Tech
  B-mới-1 = Red N1): decision now by decimal
  exponent from `format!("{f:e}")` — scientific iff
  exponent < -4 or >= 6; mantissa trimmed, form
  `"{mantissa}e{exp:+03}"`; else Rust `{}` display
  + `.0` if integral. Regression test pins 1e6,
  1234567.0, 1e15, 1e20, 1750000000.0, 100000.0,
  0.0001, 1e-5 (incl. negatives, 0.0) to the
  probe-verified Go outputs. §M5b.8 Tech N4 claim
  corrected (deviation: none — this is a bug fix).
- B2 (final-read failure, Red B1): `wait_follow`'s
  final section rewritten to Go
  (`runner.go:1023-1250`): final read = 2 attempts
  of `history_replies` (100ms between); on failure
  replies are forced to `[]` and reconciliation is
  skipped; `final_read_failed && kind == Done` →
  `kind = Timeout`, `detail = waiter.status()`,
  note `"could not read the final replies; run
  \`castctl wait\` again"`; `WaitResult.note` is now
  set (was always empty). `outcome_notes` carries
  the note (deviation 20) and suppresses the 6h
  timeout line on final-read failure, so
  `deliver_final` shows the note instead of
  `"(no reply text)"` when the final text is empty
  but a note exists. Regression test: Done + reply,
  then history Err ×2 → kind Timeout, outcome
  `"timeout"`, exact note, exit 124, replies empty.
- B3 (history widening + proof restore, Red B2):
  `GatewayPort::history` now returns
  `(Vec<Value>, bool)` (events + `has_more`), all
  impls and test ports updated;
  `TurnRunner::history_replies` widens
  `HISTORY_LIMITS = [200, 500, 1000]`
  (`history.go:50,216-257`), merges replies deduped
  by (seq, message_id), sorts oldest-first, per-window
  retry once on non-auth error (deviation 27),
  empty page with `has_more` continues unless it is
  the last window; exhaustion → note `"history window
  exhausted at %d events; older replies may be
  missed; run \`castctl wait\` again"` (largest
  limit). Proof replies collected in the poll loop
  are restored into the final read (final text wins
  on collision), note `"final read missed the settle
  proof reply; reporting the proof reply"`.
  Caveat: newest-N assumption (deviation 23).
  Regression tests: 251-event window recovers the
  oldest reply; 1201-event window notes exhaustion
  and keeps kind Done; proof reply restored.
- B4 (`finish()` join + 429 sleep vs TurnStop, Red
  B3): `TurnStop::wait()` (level-triggered,
  enable-before-check); `BubbleEditor::finish`
  `select!`s the join handle vs the stop — stop win
  returns early, handle dropped (task detached),
  trailing edit skipped (deviation 22);
  `maybe_edit` races the streaming `edit_plain`
  against the stop (dropping the future cancels the
  in-flight Bot API call incl. its 429 retry sleep);
  `edit_final` fallback `send` races the stop
  (deviation 21); primary edit keeps its 15s
  timeout. Regression tests: 60s streaming edit +
  stop → finish returns <5s; 60s fallback send +
  stop → `edit_final` returns <5s.
- Tech N1/N2 = Safety N1 = Red N3 (`media_path`):
  scheme check case-insensitive (`HTTP://` OK);
  `http_escaped_path` validates like Go
  `url.Parse` — control byte anywhere → None, bad
  `%` escape anywhere except the query → None, port
  validated (userinfo stripped, bracketed IPv6 OK,
  unbracketed 0/1 colons only, port empty or
  all-digits); `percent_decode` is bytewise
  (`%FF` → one 0xFF byte, not U+FFFD) and
  `media_path` works on bytes after decode,
  re-quoting via `quote_python_bytes`. Regression
  test pins the probe cases (control char in path,
  bad escape in host/userinfo/fragment, bad escape
  in query OK, `HTTP://`, invalid port, `:8080`,
  empty port, IPv6, `%FF` byte round-trip).
  Correction (review round 3, Safety N4): the
  `HTTP://` acceptance is a deliberate deviation,
  not Go parity — Go's `MediaPath` prefix gate
  (`media.go:47-91`) only accepts lowercase
  `http://` / `https://` and never calls `url.Parse`
  on an uppercase-scheme ref (`HTTP://…` falls
  through to the relative-path branch instead).
  `url.Parse` does lowercase the scheme, but that
  is irrelevant to the gate; the old `is_http_url`
  comment said otherwise and is corrected. The
  behaviour stays safe (full validation, result
  still a `/media/raw/…` path).
- Tech N3 (`collect_turn_media`): restructured to
  Go's merge-then-filter shape
  (`telegram_turn.go:930-1000`): empty page breaks
  the widening (`:947-949`), dedupe key is now
  (seq, event_name, message_id). The key change is
  near-unobservable in Rust (the assistant filter
  ran before the insert in the old shape, so the
  name was constant there); implemented faithfully
  and recorded here. Regression test: empty second
  page stops the widening (no third history call).
- Tech N4 = Safety N2 (spawn/shutdown race):
  `spawn_mu` gate — the stopping check and the
  slot insert hold one lock in `start_turn`, and
  registration holds the same gate in
  `start_turn`/`start_resume`; `wait_turns` sets
  `stopping` and takes the task list under the
  gate (Go `turnsMu`, `telegram_turn.go:240-249`).
  A task spawned after shutdown began is aborted
  and its slot cleared explicitly (an
  aborted-before-first-poll task never creates its
  `TurnSlotGuard`). Bound test: 10 concurrent
  starts racing `wait_turns` → returns <10s
  (passes on old code too — the race window is
  tiny; the fix is structural).
- Tech N5 (backoff cap): `wait_follow` error
  backoff is capped at the remaining error budget
  (`runner.go:426-435`); regression test pins the
  slot freeing <800ms on a 300ms budget.
- Safety N3 (`deliver_send`): checks `stop.stopped`
  and returns `Err(BotError::Cancelled)` after the
  baseline reads, before `open_stream`; regression
  test uses a port whose `open_stream` panics.
- Safety N4 (`edit_final` fallback send): covered
  by B4 above (deviation 21).
- Safety N5 (`.expect()` on Mutex locks in prod):
  converted in `turn.rs` prod paths (`start_turn`
  active, `push_task` tasks, `start_resume` active
  + resumed, `run_text_turn`/`run_resume` stops +
  resumed) and `api.rs` (`set_shutdown_signal`,
  `sleep_or_shutdown` — poisoned = no signal →
  plain sleep). M5a files (`claims.rs` decide-loop
  locks, `dispatcher.rs`, `bot.rs`,
  `registry.rs`) are untouched except the N7
  validation — follow-up, recorded here.
- Safety N6 (`raw_call`): serde error no longer
  echoed; fixed string `"telegram: bad /raw
  params"`; regression test pins the exact Debug.
- Safety N7 (`decide_once`): validates the
  decision at the top — only `allow_always` /
  `allow_once` / `deny`, else `BotError::Validation`
  before any decided-check or RPC (defense in
  depth; Go's `decideOnce` itself does not validate,
  its callers do). Regression test: unknown decision
  → Validation, 0 decider RPCs, not decided.
- Safety N8 (`TurnSlotGuard` in `start_resume`):
  VERIFIED already-satisfied — the guard is created
  immediately after the slot-wait `break`, before
  the stale check (`turn.rs`, `start_resume`); no
  code change, comment added.
- Red N2 (E2E fake too easy): `FakeBotApi` now
  answers the first `editMessageText` 429 +
  `retry_after: 1` and an identical re-edit 400
  `"Bad Request: message is not modified"`; new
  test `m5b_e2e_fake_edit_failures` pins both
  deterministically (3 edit requests: 429 + retry +
  not-modified). The main E2E's first edit hits the
  429 and recovers inside its 30s wait.
- Red N4 (error-budget reset): regression test —
  dead gateway ~2s, recovery, dead again ~2s →
  the turn delivers `"edit:Hello"` and no
  gateway-error edit appears; the budget resets
  after recovery.

Review round 3 follow-ups (recorded here, no code
change in this commit):
- Safety N1 (`oldest_seq` counts seq-less events):
  UNCONFIRMED as a divergence. Direct check of
  Go's `oldestSeq` (`history.go:313-328`) +
  `seqOf` (`events.go:155-…`) shows Go also maps
  a missing/non-numeric seq to 0 and takes the
  min over all events — Rust's `oldest_seq`
  (`turn.rs:271`) matches that exactly. The
  presence-reporting Go function is `historySeq`
  (`telegram_turn.go:1020-1035`), used at a
  different call site. Follow-up: the reviewer to
  name the exact Go call site, or drop the item.
- Safety N2 (echo of `{decision}` / `{method}`):
  no divergence found on direct check. Go's
  `outcomeNotes` (`telegram_turn.go:1391-1426`)
  echoes the same `"✅ auto-approved
  (always/once): …"` line, and Go's `ownerRaw`
  (`telegram_owner.go:202`) passes
  `method+".json"` as the `replyLong` stem, same
  as Rust. If the concern is user input reaching
  a document name, note Go does the same and the
  name is only used when the text exceeds 3800
  runes. Follow-up only.
- Safety N4 (scheme comment): corrected above —
  `HTTP://` acceptance is a deliberate deviation,
  `is_http_url` + test comments fixed.

Gate (cue, fix loop 2, `/tmp/m5b-gate-fl2b.log` on
cue): `cargo fmt --check` 0 (own fmt section,
verbatim), `cargo build --workspace` 0, `cargo test
--workspace` 0 — **643 passed, 0 failed** (627
baseline after the rebase + 16 new: the 14 red
tests + the Tech N4 bound test + the Red N2 fake
test), `cargo clippy --workspace --all-targets -- -D
warnings` 0, SPDX (`go test -run TestSPDXHeaders`,
go 1.27.3 via `/usr/local/go/bin` + GOTOOLCHAIN=auto)
0. The gate needed three runs: run 1 failed fmt (one
`cargo fmt` diff in `api.rs`), 1 test
(`follow_error_budget_resets_after_recovery` — the
fixture's `completed` terminal had no preceding
`running` event, so the `Waiter` stored it as a
suspect ignored terminal and the poll loop never
reached the final section; fixed by adding the
`running` event, same as the B3 fixtures), and 4
clippy findings (`unused_assignments` on the lag
re-read, `type_complexity` on the spelled-out
`history` future type — now the `HistoryFuture`
alias — `collapsible_match` on the timeout arm,
`manual_range_contains` on the exponent check);
run 2 failed clippy only (`dead_code`: the fake's
`last_edit`/`edit_429_done` were struct fields the
struct never read — now locals in `start()`); run 3
green. E2E re-run: §M5b.6, fix loop 2.

## M5b.8 Fix loop 1 (2026-11-06, review round 1)

Every BLOCKING from review round 1, fixed red-test
first (the red run on cue: 111 passed, 17 failed —
all 17 targeted; the two structurally-fixed items,
the concurrent-`start_turn` race and the
`start_resume` acquired guard, passed on old code
too, as expected: the old race has no await between
its two locks, and the old resume test set `stopping`
before the resume started waiting):

- B1 (ack poll swallows transient history errors):
  `deliver_send` now loops on Gateway/Timeout errors
  to the 30s deadline (`wait.go:920-929`,
  `swallowableHistoryError` `wait.go:816-823`);
  baseline reads still fail the send.
- B2 (collect cap `upto`): `deliver_media_turn`
  passes `Some(delivered_top_seq(user_seq, res))`
  (`telegram_turn.go:1133`, filter `:960`). Two
  round-1 tests called it with `user_seq=0` and an
  empty `res` — under Go's cap that collects nothing,
  so the fixtures now carry a covering reply (empty
  text, no text segment).
- B3 (media_path parity): rewritten to Go's order
  (`media.go:47-91`): `variants.original` wins over a
  non-empty path, `sandbox://` strip, http(s) URL →
  `EscapedPath` (query/fragment dropped, bad `%`
  escape fails the parse — probe-verified against
  Go's `net/url`), TrimLeft `/`, strip `media/raw/`
  once, unquote-only-if-valid (`PathUnescape` fails
  on ANY bad escape, so the whole original is kept
  and re-quoted — probe-verified), reject empty / any
  `..` segment, re-quote with `/` safe. One test
  expectation was corrected by the probe: a raw
  space in an http URL parses fine
  (`/a%20b.png`), it is not an error.
- B4 (generic question values): `"Yes"` / `"No"` /
  `"Go ahead"` (`telegram_turn.go:1518-1522`); labels
  keep their emoji.
- Red B1 (collect/final history error → silent lost
  reply): a non-fatal collect error returns
  `Ok(false)` (text-only fallback); a bad per-file
  path is a "fetched" notice and the turn continues;
  a `deliver_final` error is now reported with
  `edit_final` error text in `run_text_turn` and
  `run_resume` (Go returns the error without
  `editFinal`, `telegram_turn.go:529-532`, but the
  spawned task drops that `Err` — the user would see
  nothing).
- Red B3 (wait_follow silent to 6h): deviation 17
  above.
- Red B4 (start_turn TOCTOU): one critical section
  for check+insert (`telegram_turn.go:271-280`).
- Tech N1 (fmt): `cargo fmt` on the tree; the gate
  log now has its own fmt section with verbatim
  output (round 1's log had none).
- Safety N1: file names HTML-escaped in both
  notices (`telegram.EscapeText`,
  `telegram_turn.go:1324-1330,1377-1380`).
- Tech N2: `pending_approvals` empty-list fallback
  → `pending` (`wait.go:1160-1164`, Python `or`
  semantics; `turn.rs`/`wait.rs` event-payload
  extractors are correct as-is — Go
  `waiter.go:386-397` says an explicitly empty list
  does NOT fall back there).
- Tech N3: `widget_options` filters empty labels
  BEFORE the 10-cap (`telegram_turn.go:1532-1548`).
- Tech N4: `python_float` = Go `pythonFloat`
  (`telegram_turn.go:1618-1637`): shortest
  round-trip, `.0` for integral values, Go-style
  `e+XX`/`e-XX` scientific form iff the decimal
  exponent is < -4 or >= 6 (probe-verified against
  Go's `strconv.FormatFloat(f, 'g', -1, 64)` — the
  `[1e-4, 1e21)` claim in the first version of this
  note was wrong; corrected in fix loop 2, §M5b.9).
- Tech N5/N6: counts corrected — 10 real
  `GatewayBotServices` methods (§M5b.1); the E2E
  `/media/raw/e2e.png` GET count corrected in §M5b.6
  (3, re-measured in the fix-loop-1 E2E re-run).
- Tech N8: `safety_re` / `gate_prefix_re`
  precompiled with `OnceLock<Regex>`.
- Safety N5/Red N1: `start_resume` never clears a
  slot it did not acquire (`telegram_turn.go:327-332`
  `acquired` guard).
- Red N2: the "Final edit 15s" claim corrected
  (§M5b.1): worst case ≈ 256s (15s edit attempt +
  ≈ 241s fallback send).
- Red N4: `tasks` pruned; `notified`/`resumed`
  recorded as matching Go (deviation 18).
- Safety N3: `TurnSlotGuard` clears the slot on
  Drop, including panic unwind (Go defers
  `clearActive`, `telegram_turn.go:187-197,281-284`).
- Safety N4: `ApproveClaimGuard` in
  `approve_forever`'s todo loop releases the claim on
  Drop unless it settled (mirrors the `decide_once`
  guard; `fail_claim`/`record_claim` settle, so no
  explicit disarm is needed).
- Safety N8: `decide_approval` and
  `GatewayDecider::decide` reject any decision
  outside `allow_always`/`allow_once`/`deny`
  (`approvals.go:21-33`, `wait.go:1277-1293`) before
  any RPC.

Not fixed (kept as known limitation): the M4c token
fix is merged now (deviation 14) — the rebase onto
dev-rust `c7b1d34` is pending the coordinator's
decision, not done in this loop; Safety N7 multipart
boundary (deviation 19, M5a follow-up).

## M5b.4 classifyError

No new mapping was written. The CLI side is M4b
(`castctl-cli/src/network.rs:196` `classify_error`,
`pub(crate)`, with tests pinning auth 2 / gateway 3 /
timeout 4 / cancelled 130 empty / validation 2 /
unsupported 1) and the bot side is M5a
(`castctl-telegram/src/error.rs` `error_class` /
`summary`, 20 labels). M5b pins the main classes
byte-for-byte with additional tests (`turn_error_text`
literals, `media_failure_class` literals, the
too-big/failure notice literals) — it does not open
M4b's `pub(crate)` and does not duplicate the
mapping. Exit codes: AuthError 2, GatewayError 3,
Timeout/DeadlineExceeded 4, Canceled 130 with empty
text, ValidationError 2, ExportError 1, everything
else 1; wait timeout 124, no-delivery-ack 5.

## M5b.5 Gates (cue, 2026-11-06)

Baseline (before any edit, `07e1c0d`): `cargo test
--workspace` 560 passed, 0 failed
(`/tmp/m5b-baseline.log`, 32 `test result: ok` lines).

After (final, `/tmp/m5b-gates6.log`):

- `cargo fmt --check`: 0 (FMT-OK; `cargo fmt` run on
  cue before the gates).
- `cargo build --workspace`: 0 (BUILD-EXIT:0).
- `cargo test --workspace`: 0 (TEST-EXIT:0) — **601
  passed, 0 failed**: 560 baseline + 35 M5b unit tests
  (preview 10, wait 10, turn 13, services 2) + 5
  edge-case tests added in fix loop 1 (cap-6, 49 MiB
  pre-check ×2, busy reply, caption boundary) + 1
  env-gated E2E test (skips without `M5B_E2E=1`).
- `cargo clippy --workspace --all-targets -- -D
  warnings`: 0 (CLIPPY-EXIT:0).

All runs with `CARGO_TARGET_DIR=/root/v68-target`
`CARGO_PROFILE_DEV_DEBUG=0`
`CARGO_PROFILE_DEV_INCREMENTAL=false`
(1.99.1 via `rust-toolchain.toml`).

Fix loop 1 (after gates3-5): the `edit_final` hang
(deviation 15), one `unnecessary_map_or` clippy
finding, the cap-6 truncation bug (found by the
edge-case test), the serve-e2e query-string bug
(deviation 16), and the E2E phase-3 slot race
(fresh chats + per-turn final-edit assertion).

Fix loop 1 (review round 1, 2026-11-06,
`/root/m5b-gate-fl1.log` on cue): `cargo fmt` 0,
`cargo fmt --check` 0 (own fmt section, verbatim),
`cargo build --workspace` 0, `cargo test
--workspace` 0 — **619 passed, 0 failed** (601
baseline + 18 new regression tests), `cargo clippy
--workspace --all-targets -- -D warnings` 0 after
two findings (a `collapsible_if` in the new claim
guard, `approx_constant` on the `3.14159` float-test
literal — both fixed, literal changed to `123.456`).
Red run before the fixes: 111 passed, 17 failed
(all 17 targeted). Same env as above.

Fix loop 2 (review round 2, 2026-11-06,
`/tmp/m5b-gate-fl2b.log` on cue): `cargo fmt
--check` 0 (own fmt section, verbatim), `cargo
build --workspace` 0, `cargo test --workspace` 0 —
**643 passed, 0 failed** (627 baseline after the
rebase onto `c7b1d34` + 16 new regression tests: the
14 red tests + the Tech N4 spawn/shutdown bound test
+ the Red N2 fake-edit-failures test), `cargo clippy
--workspace --all-targets -- -D warnings` 0, SPDX
(`go test -run TestSPDXHeaders`, go 1.27.3 via
`/usr/local/go/bin` + GOTOOLCHAIN=auto) 0. Red run
before the fixes (`cargo test -p castctl-telegram
--lib`): 128 passed, 14 failed (all 14 targeted).
Three gate runs were needed: run 1 failed fmt (one
`cargo fmt` diff in `api.rs`), 1 test (Red N4
fixture: `completed` without a preceding `running`
event — the `Waiter` treats it as a suspect ignored
terminal, so the poll loop never reaches the final
section), and 4 clippy findings (`unused_assignments`
lag re-read, `type_complexity` on the `history`
future type, `collapsible_match` timeout arm,
`manual_range_contains` exponent check); run 2 failed
clippy only (`dead_code` on two `FakeBotApi` struct
fields). Same env as above.

## M5b.6 Offline E2E (cue, 2026-11-06)

Fake Bot API server (loopback, plaintext, in
`tests/turn_e2e.rs`) + real Go gateway
(`gateway_server serve-e2e`). One test, three
sequential phases, 5.18s, `E2E-EXIT:0`:

- Phase 1 (text turn): streaming edits (partial
  `"Hel"` edit, then the full `"Hello from Muse"`
  edit), 1 media sent (`sendPhoto`, `e2e.png`),
  1 approval decided (`POST /approvals/a1/decide`,
  body `{"decision":"allow_always"}`, exactly 1 RPC
  in the server log).
- Phase 2 (inbound media): `getFile` + file
  download (4 bytes `FAKE`) + `fs.write`
  `telegram-inbox/20261105-195242-photo.jpg`
  (`data_base64 "RkFLRQ=="`) + follow turn.
- Phase 3 (two parallel turns, fresh chats 333/444):
  both delivered their final edits.

Server-log counts for the run: decide RPC 1,
fs.write 1, `/media/raw/e2e.png` gets 3, streams 4
(corrected in fix loop 1, Tech N6 — the section said
"gets 2"; the fix-loop-1 E2E re-run's `E2E SUMMARY`
lists `mediaGets` with 3 entries, 4.27s,
`E2E-EXIT:0`; the first run had 3: the phase-3 chats
reused 111,
whose slot had not been released yet after the
phase-2 final edit, so "parallel one" got the busy
reply instead of opening a stream — correct Go
behaviour, wrong test setup; fixed by using fresh
chats and asserting two final edits, one per turn).

Verbatim trace: `/tmp/m5b-e2e-server.log` and
`/tmp/m5b-e2e.log` on cue (copied to the report).

Fix loop 2 re-run (2026-11-06,
`/root/m5b-e2e-fl2.log` + `/root/m5b-e2e-server-fl2.log`
on cue): gateway `127.0.0.1:33241`, 2 tests passed in
4.77s, `E2E-EXIT:0` — `m5b_offline_turn_e2e` (same
3 phases as above) and the new
`m5b_e2e_fake_edit_failures` (429-once + identical
re-edit, 3 edit requests). Server SUMMARY:
`streams=4 decided=[a1:{"decision":"allow_always"}]
fsWrites=[telegram-inbox/20261105-220804-photo.jpg]
mediaGets=[/media/raw/e2e.png ×3]` — same counts as
fix loop 1. The main E2E's first edit hits the
fake's 429 and recovers inside its 30s wait.

## M5b.7 Chưa kiểm chứng

- Live Bot API thật: no bot token on cue; never
  copied one; never sent a real message. The fake
  server proves the turn logic against the Bot API
  surface, not against Telegram.
- Live gateway `chat.subscribe` (does not exist in
  Rust yet — deviation 1) and live 429 retry on
  `sendMessage`/`sendFile` (the 429 path is ported
  from `bot.go:1534-1535` but never observed live).
  The E2E fake now covers the 429-once + "message is
  not modified" cases (Red N2, fix loop 2); the real
  429-storm wall-time is still [NEEDS-MEASUREMENT].
- Claim storm / gateway idempotency (deviation 7).
- `goal`/`idea` and the other ~20 `NotWired`
  service methods (M4b-gateway follow-up boundary).
- `auto_approve_errors` population (deviation 10).

## Quy tắc quyết định (Boss, 2026-11-05 — standing)

Applies to the whole Rust port, not just M4a. Decide
everything and own it; if evidence is missing, decide
by principle and record the reason:

1. Live/production evidence → follow production.
2. No evidence → match Go byte-for-byte (Go is the
   ground truth of this project), unless matching Go
   creates a clear security hole → choose the safer
   option and record the deviation with evidence.
3. Never lower gate criteria; never claim "match"
   without output.
