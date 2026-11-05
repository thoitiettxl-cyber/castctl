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
