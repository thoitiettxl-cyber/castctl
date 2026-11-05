# M-perf-0 — Go vs Rust performance baseline (measurement only)

Baseline hiệu năng Go `castctl` 0.9.0 vs Rust `castctl-rs` (M2 CLI surface),
đo trên cue ngày 2026-11-05. **Không tối ưu code** — chỉ đo; mọi đề xuất
tối ưu nằm ở mục Hotspot bên dưới và đều kèm số.

## Cách chạy lại toàn bộ (1 lệnh, trên cue, từ repo root)

```sh
sh rust/perf/run.sh [--skip-build] [--skip-item5]
```

- `--skip-build`: dùng lại binary `rust/target/release/castctl-rs` đã build
  (bỏ qua 2 lần build release; dùng khi chỉ muốn đo lại).
- Không `--skip-build`: build release thường (ghi kích thước chưa strip),
  rồi build lại với `RUSTFLAGS="-C strip=symbols"` (số chính).
- Yêu cầu: `cargo +1.99.1` (pin `rust/rust-toolchain.toml`), Go qua
  `PATH=/usr/local/go/bin:$PATH GOTOOLCHAIN=auto`, `python3`, `ss`.
  `hyperfine` (1.18.0) và GNU `time` (1.9) nếu có thì chạy thêm để đối
  chiếu; số chính vẫn là loop Python `measure.py` (không phụ thuộc tool ngoài).
- Output: `rust/perf/data/*.json` (số thô từng lần chạy) + `summary.json`
  (tổng hợp). Script in toàn bộ `summary.json` ra stdout.
- **Bẫy thứ tự gate (đã gặp 2026-11-05):** `TestSPDXHeaders` quét MỌI
  file `.go` dưới repo root (chỉ trừ thư mục dot) — kể cả file sinh ra
  dưới `rust/target/debug/build/boring-sys-*/out/` (322 file BoringSSL
  không có header SPDX) sau một lần `cargo build/test --workspace`.
  Chạy SPDX **trước** build workspace, hoặc xóa
  `rust/target/debug/build/boring-sys-*/out/` trước khi chạy SPDX
  (chỉ xóa `out/`, đừng xóa cả thư mục build — xóa `out/` mà giữ
  fingerprint làm lần build sau fail `couldn't find .../bindings.rs`;
  muốn build lại thì `cargo clean -p boring-sys`). File `.go` của PR
  này (`rust/perf/go-bench/`) có header đầy đủ và không nằm trong danh
  sách thiếu. CI Go (checkout sạch, không build Rust) không gặp bẫy này.

## Điều kiện đo (run4, 2026-11-05T10:52:05Z)

- Máy: cue, `Linux 6.18.38+ x86_64`, 8 × Intel Xeon @ 2.50GHz, 23 Gi RAM,
  no swap, `loadavg` 0.96–1.60 trong lúc đo.
- Go: `/usr/local/bin/castctl` 0.9.0 (`1396697 2026-11-04T21:38:36Z`),
  48,100,296 B, build `-s -w`, tags
  `with_utls,with_quic,with_wireguard,with_gvisor`, `CGO_ENABLED=1`,
  `-trimpath -buildvcs=false`. Go toolchain 1.27.3.
- Rust: `castctl-rs` build từ `dev-rust` 96ce485 trên nhánh này,
  `cargo +1.99.1 build --release --locked -p castctl-rs`,
  `RUSTFLAGS="-C strip=symbols"` (số chính); build thường 2.4 s,
  build strip 2.1 s (chỉ build closure `castctl-rs` + `castctl-cli` +
  `castctl-config` + `regex`, không build toàn workspace).
- Env chuẩn mỗi lần chạy: `LC_ALL=C TZ=UTC`, HOME/XDG cô lập (tempdir),
  stdin `/dev/null`, `CASTCTL_CONFIG`/`CASTCTL_PROFILE` unset, timeout 10 s.
- Phương pháp wall+RSS: Python stdlib `os.wait4` (`measure.py`) — lấy
  `ru_maxrss` của đúng child. Sampler `/proc` đã probe và LOẠI (nhiễu 3×
  trên tiến trình ~10 ms). Cold cache: KHÔNG drop_caches (VM dùng chung,
  M4b đang chạy) — chỉ ghi first-run sau build làm cold proxy, N=1, ghi rõ.
- Thống kê: median + min/max, N=20 (startup/RSS), N=5 lần chạy process
  (pure-logic, item 5). Tỉ lệ Rust/Go < 1 = Rust tốt hơn (time/RAM/size).
  Chênh < ~10% với khoảng min/max giao nhau = "nằm trong sai số".

## Bảng số (run4)

### 1. Kích thước binary

| | Go 0.9.0 | Rust release | Rust/Go |
|---|---|---|---|
| Stripped | 48,100,296 B (45.87 MiB) | **620,968 B (0.59 MiB)** | **0.0129 (77.5× nhỏ hơn)** |
| Chưa strip (Rust) | — | 778,936 B | 0.0162 |
| GNU strip (đối chiếu) | — | 620,960 B (chênh 8 B so với `-C strip=symbols`) | — |
| `.text` | 21,017,769 B | 434,883 B | 0.021 |
| `.rodata` | 2,644,352 B | 74,708 B | 0.028 |

`sha256`: Go `c8ea009e…`, Rust stripped `6f270890…` (full trong
`data/summary.json`). **Caveat lớn nhất của bảng này:** Go binary chứa
TOÀN BỘ castctl (Telegram bot, sing-box, gateway, keeper, webui…;
`.gopclntab` 17.9 MB + `.go.type` 5.6 MB riêng), còn Rust M2 mới chỉ có
CLI surface + config + tg-text. Khoảng cách 77× sẽ thu hẹp khi Rust port
thêm. Đừng trích số này mà không kèm caveat.

### 2. Startup (wall-clock, N=20, warmup 5)

| Lệnh | Go median (min–max) ms | Rust median (min–max) ms | Rust/Go |
|---|---|---|---|
| `--version` | 8.321 (7.644–10.023) | 0.731 (0.686–0.831) | **0.088 (11.4× nhanh hơn)** |
| `--help` | 7.936 (7.569–9.125) | 0.744 (0.662–1.000) | **0.094 (10.7× nhanh hơn)** |
| First-run sau build ("cold proxy", N=1) `--version` | 10.814 | 1.274 | 0.118 (8.5×) |

Đối chiếu hyperfine 1.18.0 (N=20): `--version` Go median 8.57 ms vs Rust
0.699 ms (12.3×); `--help` Go 8.70 ms vs Rust 0.726 ms (12.0×). Khớp loop.
Phần lớn 8 ms của Go là Go runtime init (hyperfine: user 5.6 ms +
system 4.2 ms); Rust user 0.60 ms + system 0.15 ms.

### 3. Peak RSS (os.wait4, N=20)

| Lệnh | Go median (min–max) MiB | Rust median (min–max) MiB | Rust/Go | Exit |
|---|---|---|---|---|
| `--version` | 43.5 (42.5–43.9) | 13.2 (13.2–13.2) | **0.30 (70% ít hơn)** | 0 / 0 |
| `--help` | 43.5 (42.5–43.6) | 13.2 (13.2–13.2) | **0.30** | 0 / 0 |
| `status --config min` | 45.5 (44.7–45.9) | 13.2 (13.2–13.2) | 0.29 | 2 / 1 |
| `status --config large` | 48.5 (47.1–49.4) | 13.2 (13.2–13.2) | 0.27 | 2 / 1 |
| `status --config bad-JSON` | 43.6 (42.5–44.0) | 13.1 (13.1–13.1) | 0.30 | 2 / 2 |

Ghi chú: Go `status` với config tốt KHÔNG offline-sạch — nó parse +
validate rồi fail nhanh vì thiếu session (`{"error":"conn:
auth_failed","type":"cookies_missing"}`) và, với config large, fail ở
tạo outbound (`create vless[vless-1-r0]: invalid public_key` — Go validate
REALITY key ở tầng outbound-creation, còn `ParseSingleConfig` thì chấp
nhận FAKE-PUB). Đường so sánh sạch nhất cho parse là bad-JSON gate
(cả hai đều dừng ở parse, exit 2). RSS Rust phẳng 13.2 MiB ở mọi lệnh
(kể cả config large); RSS Go tăng +5 MiB từ min → large.

### 4. Logic thuần: parse config + render text Telegram (N=5 lần chạy process)

| Tác vụ | Go ns/iter median (min–max) | Rust ns/iter median (min–max) | Rust/Go |
|---|---|---|---|
| Parse config min (42 B) | 5,882 (4,349–6,748) | 2,517 (2,515–2,536) | **0.43 (2.3× nhanh hơn)** |
| Parse config large (25,657 B, 50 profiles + 140 outbounds) | 5,109,444 (4,955,411–5,181,402) | 933,791 (927,131–941,493) | **0.18 (5.5× nhanh hơn)** |
| Decode JSON large, Rust-only (`decode_ordered_object`) | — | 293,392 (290,478–301,111) | — |
| `MDToHTML` (message 51,560 B) | 4,615,838 (4,491,082–4,774,714) | 873,318 (872,076–932,134) | **0.19 (5.3× nhanh hơn)** |
| `SplitText` (51,560 B) | 517,752 (509,399–526,929) | 266,445 (265,129–274,988) | **0.51 (1.9× nhanh hơn)** |
| Render chain (`MDToHTML` + `SplitText`) | 5,239,473 (5,167,113–5,443,152) | 1,085,378 (1,065,200–1,111,932) | **0.21 (4.8× nhanh hơn)** |

Harness khác nhau nên đây là **so sánh thực dụng, không phải cùng một bộ
đếm**: Go dùng `testing.B` (`-benchtime=100x -count=5`,
`rust/perf/go-bench/bench_test.go`); Rust dùng loop `Instant` tự thích
ứng K (≥ ~200 ms/lần, `rust/perf/bench/src/main.rs`, standalone crate,
không chạm `rust/Cargo.toml`). Cả hai đọc cùng fixture từ
`rust/perf/fixtures/` (config-large: 10× bộ outbound mọi protocol từ
Go `TestParseSingleConfigEveryProtocolValid`, tag làm duy nhất;
message-long: Markdown tổng hợp ~50 KB, deterministic, seed 20261105).

**Bất đối xứng phải đọc kèm:** cùng tên hàm nhưng khác khối lượng việc.
Go `ParseSingleConfig` validate sâu toàn bộ outbound (sing-box); Rust
defer sing-box option validation (deviation D-M2-1) nên parse-large của
Rust làm ít việc hơn. Bằng chứng: Go parse-large 1,735,099 B/op +
41,734 allocs/op; Rust decode chỉ 293 µs trong tổng parse 934 µs
(validation+build struct chiếm 69%). Khi Rust bổ sung validation, lợi
thế parse-large sẽ thu hẹp — đo lại sau bước đó (hotspot H5).
Tương tự `MDToHTML`: Go 4,857,863 B/op + 8,390 allocs/op (churn chuỗi
lớn); Rust dùng `regex` crate + `String` building, chưa đếm alloc
(không có tool tương đương `ReportAllocs` cho Rust ở đây).

### 5. Độ trễ 1 request qua transport loopback (SOCKS5 local)

Định nghĩa: 1 × TCP CONNECT tới SOCKS5 `127.0.0.1:1080` (no-auth) →
CONNECT tới HTTP origin `127.0.0.1:<ephemeral>` → `GET /body-1024.bin`
→ đọc đủ body 1024 B → đóng. N=5 lần chạy process × 20 request/lần.

| | Go ms/req median (min–max) | Rust ms/req median (min–max) | Rust/Go |
|---|---|---|---|
| SOCKS5 GET loopback | 0.813 (0.784–0.970) | 0.756 (0.745–0.897) | **0.93 (7% nhanh hơn — nằm trong sai số, khoảng giao nhau)** |

**Hạn chế, ghi rõ:** cả hai client đều hand-roll stdlib (Go
`rust/perf/go-bench/socks5_test.go`, Rust `bench/src/main.rs`
`socks5-get`), đo code harness chứ KHÔNG phải outbound thật của castctl
(sing-box/honk). Độ trễ loopback bị chi phối bởi TCP localhost + proxy
Python + `http.server` Python, không phải code client. Setup hết 1.6 s
(trong hạn 20 phút). Hai bẫy đã gặp và sửa trong lúc đo: (a) port cố định
18080 thuộc server `echo.py` của session khác (pid 1666878) trả `b"ok"`
cho mọi path — driver nay chọn port ephemeral bằng bind-0 và verify body
trước khi đo; (b) Go client fail toàn bộ ở lần chạy driver đầu vì
isolated HOME làm `go test` (GOTOOLCHAIN=auto) tìm toolchain cache sai
chỗ — Go item 5 nay chạy với HOME thật (ghi trong `measure_all.py`).

## Kết luận

- Rust **nhanh hơn Go rõ rệt, ngoài sai số**, ở: kích thước binary
  (77× nhỏ hơn — kèm caveat scope M2), startup (10–11×), RSS (70% ít
  hơn), logic thuần parse/render (1.9–5.5×). Các khoảng min/max không
  giao nhau ở những mục này.
- Rust **không hơn đáng kể** ở độ trễ 1 request loopback qua SOCKS5
  hand-roll: nhanh hơn 7%, khoảng giao nhau → trong sai số; và số này
  đo harness, không phải outbound thật.
- Lợi thế parse-large (5.5×) và render (5.3×) một phần là do Go làm
  nhiều việc hơn (validate sâu, alloc churn) và Rust defer validation —
  không phải toàn bộ là "Rust nhanh hơn". Đo lại sau khi Rust bổ sung
  validation.
- Không có mục nào Rust chậm hơn Go ngoài sai số trong baseline này.

## Hotspot ưu tiên (tối đa 7, sắp theo lợi ích/chi phí)

1. **Rust parse-large: validation chiếm 69% thời gian parse.**
   Bằng chứng số: parse-large 934 µs vs decode-alone 293 µs cùng input
   (25,657 B) — validation + build struct ≈ 641 µs. Lợi ích ước lượng:
   đưa validation về gần tốc độ decode → parse-large ~400–500 µs (~2×).
   Chi phí sửa: trung bình (code trong `castctl-config/src/config.rs`,
   validation order + error message bị test parity ghim). Rủi ro: phá
   parity byte-for-byte của thông báo lỗi. Chỉ làm sau khi có profile
   chi tiết hơn (hiện không có `perf` trên cue).
2. **Rust `md_to_html` chiếm 80% render chain.** Bằng chứng số:
   `md_to_html` 873 µs vs `split_text` 266 µs cùng input 51,560 B;
   render-chain 1,085 µs ≈ tổng hai hàm. Go tương ứng 4,616 µs với
   8,390 allocs/op — phía Rust chưa đếm được alloc. Lợi ích: giảm số
   pass regex / allocation trong `inline_html` (`castctl-tg-text`,
   stash + `replace_all` nhiều lượt). Chi phí: trung bình. Rủi ro:
   parity `MDToHTML` (test M1 ghim output từng case).
3. **`split_text_limit` collect toàn bộ input thành `Vec<char>` trước.**
   Bằng chứng cấu trúc (không phải profile): `lib.rs` collect
   `text.chars()` rồi mới cắt; số đo: 266 µs cho 51,560 B (Go 518 µs).
   Lợi ích: nhỏ–vừa (bỏ 1 alloc lớn + pass char). Chi phí: trung bình
   (ngữ nghĩa cắt/fence-carry bị test ghim chặt). Rủi ro: đổi hành vi
   cắt ở biên. Đo alloc trước khi sửa.
4. **Lợi thế parse-large sẽ thu hẹp khi Rust bổ sung sing-box validation
   (D-M2-1) — đo lại, đừng tối ưu trước.** Bằng chứng số: Go parse-large
   5.11 ms vs Rust 0.93 ms nhưng Go validate 140 outbound sâu (41,734
   allocs/op); Rust defer. Lợi ích: tránh tối ưu sai chỗ + tránh ngạc
   nhiên khi validation hạ cánh. Chi phí: thấp (chỉ đo lại). Rủi ro:
   không có — đây là follow-up đo, không phải sửa code.
5. **Startup: không đáng tối ưu thêm lúc này.** Bằng chứng số: Rust
   `--version` 0.731 ms, hyperfine user 0.60 ms + system 0.15 ms; phần
   lớn là spawn process + dynamic loader (`.rela.dyn` 22 KB). Lợi ích
   tối đa ~0.2 ms tuyệt đối. Chi phí: thấp–trung bình (`-C
   target-cpu=native` bị CẤM ở PR này; static musl đổi cả toolchain).
   Rủi ro: đổi ABI/link. Để sau, khi binary lớn hơn.
6. **Kích thước binary: đã thắng, đừng tối ưu thêm.** Bằng chứng số:
   620,968 B stripped (`.text` 435 KB, `.gcc_except_table` 24 KB,
   `.eh_frame` 36 KB) vs Go 48.1 MB. Lợi ích thêm (LTO /
   `codegen-units=1` / `panic=abort`): vài chục KB, không đáng kể so với
   77× hiện tại. Chi phí: thấp nhưng `panic=abort` đổi hành vi crash.
   Rủi ro: thấp. Chỉ xem lại khi Rust port thêm crate nặng.
7. **Transport thật chưa đo — đừng micro-tối ưu client hand-roll.**
   Bằng chứng số: item 5 Rust 0.756 ms vs Go 0.813 ms, trong sai số,
   và cả hai đều qua proxy Python + `http.server` Python. Lợi ích của
   việc tối ưu client hand-roll: ~0. Đo lại bằng outbound thật
   (honk/sing-box, M3) + gateway thật (M4a) trước khi đụng tới. Chi phí:
   thấp (chỉ đo). Rủi ro: tối ưu sai tầng.

## Output lần chạy thật (run4, dán nguyên văn, rút gọn)

```
$ sh rust/perf/run.sh --skip-build   # trên cue, repo root
... (build skipped) ...
hyperfine --version:  Go median 8.57 ms vs Rust 0.699 ms (12.3x)
hyperfine --help:     Go median 8.70 ms vs Rust 0.726 ms (12.0x)
summary.json: date 2026-11-05T10:52:05Z, machine cue 8x Xeon 2.50GHz 23Gi,
  go 0.9.0 (1396697), rust 0.9.0, cargo 1.99.1, go 1.27.3
item5: status measured, rust 0.756 ms/req (0.745-0.897),
  go 0.813 ms/req (0.784-0.970)
```

Số thô đầy đủ: `rust/perf/data/*.json` (mỗi file ghi từng lần chạy,
median/min/max/mean, exit code). Tái lập: chạy lại lệnh trên rồi diff
`data/summary.json` với file đã commit — các median startup/RSS/logic
thuần dao động < ~10% giữa các lần chạy trên cùng máy.

## File trong `rust/perf/`

- `run.sh` — 1 lệnh rerun (gọi `measure_all.py`).
- `measure_all.py` — driver items 1–5, ghi `data/*.json` + `summary.json`.
- `measure.py` — timing wall + peak RSS bằng `os.wait4` (stdlib).
- `socks5.py` — SOCKS5 proxy tối thiểu (asyncio, no-auth, CONNECT only).
- `bench/` — standalone Rust crate (`[workspace]` riêng, path deps tới
  `castctl-config`/`castctl-tg-text`, stdlib-only, không chạm
  `rust/Cargo.toml`): timing loop pure-logic + client SOCKS5.
  `Cargo.lock` của nó được commit để tái lập.
- `go-bench/` — Go `testing.B` bench (`ParseSingleConfig`, `MDToHTML`,
  `SplitText`, render chain) + client SOCKS5 (`TestSocks5Get`).
  File `.go` mang header SPDX GPL-3.0-or-later (bắt buộc:
  `TestSPDXHeaders` quét toàn repo).
- `fixtures/` — `config-min.json` (42 B), `config-large.json` (25,657 B,
  tổng hợp, xem `gen_fixtures.py`), `message-long.md` (51,560 B, tổng
  hợp, seed 20261105), `body-1024.bin` (1024 B), `gen_fixtures.py`
  (generator deterministic — chạy lại để tái tạo fixture).
- `data/` — số thô các lần chạy (run4 là số trong bảng trên).

## Chưa kiểm chứng / giới hạn (ghi rõ, không giấu)

- Cold cache thật (drop_caches): không đo — VM dùng chung, M4b đang chạy
  trên cue; chỉ có cold proxy N=1 (first-run sau build).
- `perf` không có trên cue (không có `linux-tools` cho kernel 6.18.38+);
  hotspot 1–3 dựa trên breakdown số đo (decode vs parse, hàm vs hàm)
  và lý do cấu trúc, KHÔNG dựa trên CPU profile.
- Rust chưa có số allocation/op tương đương Go `ReportAllocs`.
- Item 5 đo harness hand-roll, không phải outbound/gateway thật.
- So sánh kích thước binary mang caveat scope M2 (xem §1).
