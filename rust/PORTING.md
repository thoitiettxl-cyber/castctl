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
test result: ok. 41 passed; 0 failed  (castctl-log-redact)
test result: ok. 7 passed; 0 failed   (castctl-shared)
test result: ok. 2 passed; 0 failed   (castctl-tg-files)
test result: ok. 8 passed; 0 failed   (castctl-tg-text)
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
