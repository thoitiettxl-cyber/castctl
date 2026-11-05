# M-perf-0 — Go vs Rust performance baseline (measurement only)

Baseline hiệu năng Go `castctl` 0.9.0 vs Rust `castctl-rs` (M2 CLI surface),
đo trên cue ngày 2026-11-05. **Không tối ưu code** — chỉ đo; mọi đề xuất
tối ưu nằm ở mục Hotspot bên dưới và đều kèm số.

Số trong tài liệu này là **run7** (`2026-11-05T12:15:19Z`, full rerun, xem
mục Drift bên dưới). Số RSS Rust của run4 (commit `7f46964`, 13.2 MiB)
là SAI — đó là floor của tiến trình Python cha (`ru_maxrss` từ `wait4`
kế thừa qua fork, đã chứng minh bằng probe) — nên toàn bộ số RSS run4
đã bị thay bằng run7. Wall-clock của run4 thì ĐÚNG: driver run4 dùng
`os.wait4` blocking (không có vòng poll nào), và Rust `--version`
0.686–0.831 ms không thể ra từ lưới 5 ms — wall drift run4→run7 (+34%
Go / +23% Rust) là drift theo tải, tỉ lệ ổn định 0.081–0.088. Vòng poll
WNOHANG gây lượng tử hoá 5 ms chỉ xuất hiện ở driver trung gian của fix
loop 1 (run5, Rust `--version` median 5.448 ms), không phải phương pháp
của run4; các vấn đề phương pháp do probe trong fix loop 1 phát hiện,
không phải review vòng 1 (review vòng 1 đã kiểm chứng số run4 là đúng).
Run6 dùng target dir còn ấm nên thời gian build của nó không phải full
build. Run7 là lần chạy đầy đủ đầu tiên sau khi sửa lỗi RSS (backend
GNU time) và loại vòng poll WNOHANG.

## Cách chạy lại toàn bộ (1 lệnh, trên cue, từ repo root)

```sh
sh rust/perf/run.sh [--skip-build] [--skip-item5]
```

- `--skip-build`: dùng lại binary `rust/target/release/castctl-rs` đã build
  (bỏ qua 2 lần build release; dùng khi chỉ muốn đo lại).
- `--skip-item5`: bỏ qua item 5 thật (ghi `status: "skipped"` vào
  `summary.json`; không dựng server nào).
- Không `--skip-build`: build release thường (ghi kích thước chưa strip),
  rồi build lại với `RUSTFLAGS="-C strip=symbols"` (số chính).
- `CARGO_TARGET_DIR`: driver tôn trọng biến này của cargo (xem
  `measure_all.py`). Mặc định là `rust/target`. Run7 dùng
  `CARGO_TARGET_DIR=/dev/shm/perf0-target` vì đĩa `/` của cue lúc đó đã
  99% đầy (850 MB trống theo `df_root` trong `summary.json`, session M4b
  đang build song song); target dir ~41 MiB (delta trống trên /dev/shm:
  7.82→7.78 GiB), dọn sau khi chạy xong.
- Yêu cầu: `cargo +1.99.1` (pin `rust/rust-toolchain.toml`), Go qua
  `PATH=/usr/local/go/bin:$PATH GOTOOLCHAIN=auto`, `python3`,
  `/usr/bin/time` (BẮT BUỘC — đo RSS, xem phương pháp bên dưới).
  `hyperfine` (1.18.0) nếu có thì chạy thêm để đối chiếu startup; số
  chính vẫn là loop Python `measure.py` (không phụ thuộc tool ngoài).
  Lưu ý: `summary.json: hyperfine.version` ở run7 vẫn là dict kết quả
  benchmark `--version` (key này từng bị ghi đè bởi label benchmark —
  driver đã đổi label thành `version_bench` cho lần chạy sau); version
  của tool ghi ở `machine.hyperfine_version` mới là authoritative.
  Tooling trên cue: `apt-get install -y hyperfine time`, 2026-11-05
  (apt history End-Date 17:41:28 giờ địa phương): hyperfine
  1.18.0-2build1, GNU time 1.9-0.2build1. GNU `time` KHÔNG được dùng làm
  cross-check startup (không có code path nào gọi nó cho việc đó) — nó
  là backend đo RSS.
- Output: `rust/perf/data/*.json` (số thô từng lần chạy) + `summary.json`
  (tổng hợp). Script in toàn bộ `summary.json` ra stdout; stdout thật
  của run7 được commit ở `data/run7-stdout.txt`.
- **Bẫy thứ tự gate (đã gặp 2026-11-05):** `TestSPDXHeaders` quét MỌI
  file `.go` dưới repo root (chỉ trừ thư mục dot) — kể cả file sinh ra
  dưới `rust/target/debug/build/boring-sys-*/out/` (322 file BoringSSL
  không có header SPDX) sau một lần `cargo build/test --workspace`.
  Bẫy này CHỈ xảy ra sau workspace build, KHÔNG bao giờ xảy ra với
  `run.sh` (nó chỉ build `-p castctl-rs` + bench crate, không sinh file
  `.go` nào). Chạy SPDX **trước** build workspace, hoặc xóa
  `rust/target/debug/build/boring-sys-*/out/` trước khi chạy SPDX
  (chỉ xóa `out/`, đừng xóa cả thư mục build — xóa `out/` mà giữ
  fingerprint làm lần build sau fail `couldn't find .../bindings.rs`;
  muốn build lại thì `cargo clean -p boring-sys`). File `.go` của PR
  này (`rust/perf/go-bench/`) có header đầy đủ và không nằm trong danh
  sách thiếu. CI Go (checkout sạch, không build Rust) không gặp bẫy này.
  `run.sh` kết thúc bằng một bước SPDX chỉ-đọc (advisory, không làm
  fail run): run7 in `SPDX check: PASS`.

## Điều kiện đo (run7, 2026-11-05T12:15:19Z)

- Máy: cue, `Linux 6.18.38+ x86_64`, 8 × Intel Xeon @ 2.50GHz,
  MemTotal 24,788,940 kB (23.6 GiB), SwapTotal 0 kB (ghi trong
  `summary.json: machine.meminfo`), loadavg 1-phút 0.48–1.00 trong lúc
  đo (4 snapshot: start 0.48, mid 0.53, after_item4 1.00, end 1.00;
  cộng 33 mark loadavg + timestamp trước/sau từng item và từng phía
  trong `summary.json: marks`). Đĩa `/` 850 MB trống lúc chạy (99%
  đầy, theo `df_root` trong `summary.json`); build outputs đặt trên
  `/dev/shm` (7.82 GiB trống trước, 7.78 GiB sau).
- Go: `/usr/local/bin/castctl` 0.9.0 (`1396697 2026-11-04T21:38:36Z`),
  48,100,296 B. `go version -m` (ghi đầy đủ trong `summary.json`):
  `-buildmode=exe`, tags `with_utls,with_quic,with_wireguard,
  with_gvisor`, `-trimpath=true`, `CGO_ENABLED=1`, `GOARCH=amd64`.
  Output `go version -m` KHÔNG có dòng `-ldflags` nào nên tài liệu này
  không claim `-s -w` (claim đó ở run4 không có nguồn trong data).
  Go toolchain 1.27.3. Lưu ý về độ đầy đủ của dữ liệu: trường
  `go_binary_build_info` trong `summary.json` bị cắt ngắn (ở run7, hàm
  `sh()` chỉ giữ 4000 ký tự cuối của stdout, nên phần đầu — đường dẫn
  binary và vài dep đầu — bị mất; mọi field trích dẫn ở trên đều nằm
  trong phần còn lại; driver đã đổi sang giữ đầu 2000 + cuối 2000 kèm
  marker `[...truncated...]` cho lần chạy sau). Tương tự, `machine.gnu_time_version`
  ghi self-report của binary GNU time (`time (GNU Time) UNKNOWN…`) còn
  "1.9-0.2build1" là version gói apt — hai cách ghi version khác nhau,
  không mâu thuẫn.
- Rust: `castctl-rs` build từ `dev-rust` 96ce485 trên nhánh này,
  `cargo +1.99.1 build --release --locked -p castctl-rs`,
  `RUSTFLAGS="-C strip=symbols"` (số chính); build thường 2.3 s,
  build strip 2.0 s (full build, target dir lạnh; chỉ build closure
  `castctl-rs` + `castctl-cli` + `castctl-config`, stdlib-only, không
  build toàn workspace).
- Env chuẩn mỗi lần chạy: `LC_ALL=C TZ=UTC`, HOME/XDG cô lập (tempdir,
  dọn trong `finally` sau mỗi lần đo), stdin `/dev/null`,
  `CASTCTL_CONFIG`/`CASTCTL_PROFILE` unset, timeout 10 s (ép bằng
  SIGALRM — xem `measure.py`).
- Phương pháp wall+RSS (`measure.py`, đã sửa ở fix loop 1 sau khi probe
  chứng minh phương pháp đo RSS cũ sai — chỉ RSS, wall-clock không sai):
  - Wall-clock + exit code: spawn trực tiếp, `os.wait4` blocking ở
    main thread — cùng phương pháp với run4, và wall-clock của run4 là
    đúng (xem phần mở đầu). Trong fix loop 1, một vòng poll WNOHANG
    đã được THỬ làm phương án thay thế rồi LOẠI bằng probe: với sleep
    5 ms nó lượng tử hoá mọi wall time theo lưới 5 ms — bằng chứng là
    run5 (driver trung gian dùng vòng poll đó) đo Rust `--version`
    median 5.448 ms, mọi run cụm ngay trên 5 ms (xem
    `data/run5-summary.json`). Vòng poll đó không bao giờ là phương
    pháp của run4.
  - Peak RSS: spawn RIÊNG dưới `/usr/bin/time -v -o <report>` (cha
    mỏng ~1–2 MB RSS nên floor ~1.3 MB). `ru_maxrss` từ `wait4` của
    tiến trình Python KHÔNG dùng được cho tiến trình nhỏ: probe
    2026-11-05 — parent Python có self maxrss 114,072 KiB fork ra
    `/bin/true`, `wait4` báo child đúng 114,072 KiB; cùng `/bin/true`
    dưới GNU time báo 1,260 KB, `castctl-rs --version` báo 2,104 KB
    dưới GNU time so với 13,656 KiB dưới `wait4`-từ-Python. Quy luật
    (đã chứng minh): `ru_maxrss` báo cáo = max(RSS của parent lúc
    spawn, peak thật của child). Floor ~13 MB của Python đã làm sai
    toàn bộ số RSS Rust ở run4/run5 (báo 13.2 MiB thay vì 2.1 MiB).
    Peak thật của Go (~30 MB) vượt floor nên số RSS Go không bị ảnh
    hưởng. Giá trị `wait4` thô vẫn được giữ trong data
    (`maxrss_kib_raw`) để đối chiếu.
  - Cold cache: KHÔNG drop_caches (VM dùng chung, M4b đang chạy) —
    chỉ ghi first measured run, warmup=0, sau một lần probe
    `--version` (KHÔNG phải cold, KHÔNG phải first-run sau build),
    N=1, ghi rõ.
  - Thứ tự chạy: KHÔNG interleave — mỗi item đo theo adjacent batch
    (hết Go rồi tới Rust; item 5 chạy Rust trước rồi Go). Loadavg +
    timestamp trước/sau từng phía nằm trong `summary.json: marks`;
    ở run7 loadavg 1-phút phẳng 1.00 trong suốt item 5 nên thứ tự
    batch không làm lệch item 5.
- Thống kê: median + min/max, N=20 (startup/RSS), N=5 lần chạy process
  (pure-logic, item 5 — xem chi tiết replicate ở §4). Tỉ lệ Rust/Go < 1
  = Rust tốt hơn (time/RAM/size). Chênh < ~10% với khoảng min/max giao
  nhau = "nằm trong sai số". Dao động giữa các lần chạy: xem mục Drift.

## Bảng số (run7)

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
| `--version` | 11.169 (9.790–13.090) | 0.901 (0.814–1.335) | **0.081 (12.4× nhanh hơn)** |
| `--help` | 10.771 (9.545–13.707) | 0.867 (0.765–1.146) | **0.080 (12.4× nhanh hơn)** |
| First measured run, warmup=0, sau probe `--version` (KHÔNG cold, KHÔNG sau build), N=1 `--version` | 12.616 | 1.676 | 0.133 (7.5×) |

Đối chiếu hyperfine 1.18.0 (N=20, median): `--version` Go 11.128 ms vs
Rust 0.882 ms (12.6×); `--help` Go 11.091 ms vs Rust 0.981 ms (11.3×).
Khớp loop. Phần lớn thời gian của Go là Go runtime init (hyperfine:
`--version` user 4.29 ms + system 7.97 ms); Rust user 0.71 ms + system
0.21 ms.
Lưu ý thống kê: hyperfine tự báo "times faster" theo **mean**, khác
median README dùng: `--version` 12.7× (mean) vs 12.6× (median);
`--help` 9.4× (mean) vs 11.3× (median) — mean của Rust ở `--help`
(1.195 ms) bị kéo lên bởi một outlier (max 3.647 ms) so với median
0.981 ms.

### 3. Peak RSS (GNU time, N=20)

| Lệnh | Go median (min–max) MiB | Rust median (min–max) MiB | Rust/Go | Exit |
|---|---|---|---|---|
| `--version` | 30.36 (29.80–30.98) | 2.14 (2.00–2.38) | **0.071 (93% ít hơn)** | 0 / 0 |
| `--help` | 30.30 (29.74–31.17) | 2.21 (2.04–2.36) | **0.073** | 0 / 0 |
| `status --config min` | 32.74 (32.11–33.73) | 2.32 (2.22–2.39) | 0.071 | 2 / 1 |
| `status --config large` | 37.67 (37.01–38.41) | 2.83 (2.71–2.88) | 0.075 | 2 / 1 |
| `status --config bad-JSON` | 30.77 (30.29–31.74) | 2.33 (2.27–2.38) | 0.076 | 2 / 2 |

Ghi chú: Go `status` với config tốt KHÔNG offline-sạch — nó parse +
validate rồi fail nhanh vì thiếu session (`{"error":"conn:
auth_failed message_length=152","type":"cookies_missing"}` — stderr
verbatim từ `go_status_probe` trong `summary.json`) và, với config
large, fail ở tạo endpoint, stderr verbatim 1 lần chạy (ghi ở
`data/item3-status-large-go-stderr.txt`, 114 B, exit 2):

```
castctl: outbound: create endpoint wireguard[wg-home-r0]: decode private key: illegal base64 data at input byte 4
```

Go validate key của wireguard endpoint ở tầng outbound/endpoint-creation,
còn `ParseSingleConfig` thì chấp nhận `FAKE-PRIVKEY` (bench parse-large
pass). Đường so sánh sạch nhất cho parse là bad-JSON gate (cả hai đều
dừng ở parse, exit 2). RSS Rust tăng nhẹ theo config (min 2.32 →
large 2.83 MiB, +0.51 MiB — chi phí parse thật, giờ đo được vì RSS
đã đúng); RSS Go tăng +4.9 MiB từ min → large (+7.3 MiB so với
`--version`). Wall-clock cũng thấy chi phí parse của Rust: `status`
large 2.681 ms so với min 0.877 ms.

**Lịch sử số RSS (đọc kỹ trước khi trích):** số RSS Rust ở run4/run5
(13.2 MiB) là SAI — đó là floor của Python cha (xem phương pháp đo);
số đúng là ~2.1 MiB. Số RSS Go `--version` ở run4 (43.5 MiB) cũng
không tái lập được: run5/run6/run7 đều đo 30.4 MiB (GNU time đối chiếu
trực tiếp 30.1–30.9 MiB) với cùng binary (cùng sha256). Nguyên nhân
chênh lệch run4 chưa rõ — giả thuyết (chưa kiểm chứng): Go 1.27 xin
transparent huge page cho heap arena, RSS hạch toán cả page 2 MB dù
chỉ dùng một phần; tuỳ trạng thái THP/fragmentation mà số hạch toán
dao động. Tài liệu này dùng 30.4 MiB (3 run liên tiếp khớp nhau).

### 4. Logic thuần: parse config + render text Telegram

Replicate khác nhau nên đây là **so sánh thực dụng, không phải cùng một
bộ đếm**: Go item 4 là 1 process × 5 counts × 100 iters (`go test
-benchtime=100x -count=5`, `rust/perf/go-bench/bench_test.go`); Rust
item 4 là 5 process runs, adaptive K (≥ ~200 ms/lần,
`rust/perf/bench/src/main.rs`, standalone crate, không chạm
`rust/Cargo.toml`). JSON thô của Rust bench (K, total_ms, output_len)
được lưu đủ trong `summary.json: items.pure_logic.rust_bench_raw`.
Cả hai đọc cùng fixture từ `rust/perf/fixtures/` (config-large: 10× bộ
19 protocol type từ Go `TestParseSingleConfigEveryProtocolValid` —
18 outbound + 1 wireguard endpoint, tag làm duy nhất; message-long:
Markdown tổng hợp ~50 KB, deterministic, seed 20261105).

| Tác vụ | Go ns/iter median (min–max) | Rust ns/iter median (min–max) | Rust/Go | K median (Rust) |
|---|---|---|---|---|
| Parse config min (42 B) | 4,511 (3,736–7,066) | 2,553 (2,523–2,582) | **0.57 (1.8× nhanh hơn)** | 131,072 |
| Parse config large (32,246 B, 50 profiles + 180 outbounds + 10 endpoints) | 7,146,253 (7,058,437–7,368,679) | 1,162,514 (1,150,233–1,233,601) | **0.16 (6.1× nhanh hơn)** | 256 |
| Decode JSON large, Rust-only (`decode_ordered_object`) | — | 392,479 (383,715–397,645) | — | 1,024 |
| `MDToHTML` (message 51,560 B) | 5,405,424 (5,294,002–5,591,805) | 872,425 (864,204–962,577) | **0.16 (6.2× nhanh hơn)** | 256 |
| `SplitText` (51,560 B) | 550,978 (533,314–555,317) | 281,451 (276,157–321,615) | **0.51 (2.0× nhanh hơn)** | 1,024 |
| Render chain (`MDToHTML` + `SplitText`) | 5,619,489 (5,342,446–6,167,847) | 1,114,199 (1,091,979–1,157,389) | **0.20 (5.0× nhanh hơn)** | 256 |

`output_len` đã kiểm chứng trong raw: parse-large 50 profiles,
decode-large 4 keys, `md-to-html` 58,259 chars, `split-text` 15,
render-chain 58,277, parse-min 1. Mọi run Rust đều ≥ 200 ms total
(K dừng ở 131,072 khi total đạt ~335 ms ở parse-min; cap `1<<20`
không chạm tới).

**Bất đối xứng phải đọc kèm:** cùng tên hàm nhưng khác khối lượng việc.
Go `ParseSingleConfig` validate sâu toàn bộ outbound (sing-box); Rust
defer sing-box option validation (deviation D-M2-1) nên parse-large của
Rust làm ít việc hơn. Bằng chứng: Go parse-large 2,195,597 B/op +
52,163 allocs/op (median — xem `go_b_op_allocs` trong `summary.json`);
Rust decode chỉ 392 µs trong tổng parse 1,163 µs (validation+build
struct chiếm 66%). Khi Rust bổ sung validation, lợi thế parse-large sẽ
thu hẹp — đo lại sau bước đó (hotspot H4). Tương tự `MDToHTML`: Go
4,861,632 B/op + 8,389 allocs/op (median; churn chuỗi lớn); Rust dùng
`regex` crate + `String` building, chưa đếm alloc (không có tool tương
đương `ReportAllocs` cho Rust ở đây).

### 5. Độ trễ 1 request qua transport loopback (SOCKS5 local)

Định nghĩa: 1 × TCP CONNECT tới SOCKS5 `127.0.0.1:<ephemeral>` (no-auth)
→ CONNECT tới HTTP origin `127.0.0.1:<ephemeral>` → `GET /body-1024.bin`
→ đọc đủ body 1024 B → đóng. N=5 lần chạy process × 20 request/lần.
Cả hai cổng đều ephemeral (bind-0); proxy được verify bằng handshake
SOCKS5 + CONNECT probe thật trước khi đo (`socks_check` trong
`summary.json`: greeting/connect/body đều ok); process server được
check `poll() is None` sau khi spawn. Giới hạn đã biết: `_free_port()`
bind-rồi-đóng có race TOCTOU — tiến trình khác có thể chiếm cổng trước
khi server bind; đã giảm nhẹ bằng `socks_check` (greeting + CONNECT +
verify body) nên proxy lạ sẽ bị phát hiện trước khi đo, không đo nhầm
trong im lặng.

| | Go ms/req median (min–max) | Rust ms/req median (min–max) | Rust/Go |
|---|---|---|---|
| SOCKS5 GET loopback | 0.874 (0.766–1.071) | 0.830 (0.736–0.995) | **0.95 (5% nhanh hơn — nằm trong sai số, khoảng giao nhau)** |

Setup (spawn + verify hai server) hết 1.5 s; đo 10.4 s; tổng 11.9 s
(trong hạn 20 phút). Thứ tự chạy: Rust trước (5 lượt), rồi Go (5 lượt),
adjacent batches — loadavg 1-phút phẳng 1.00 trong suốt item 5 (marks
trong `summary.json`) nên thứ tự batch không làm lệch phía nào ở run7.

**Hạn chế, ghi rõ:** cả hai client đều hand-roll stdlib (Go
`rust/perf/go-bench/socks5_test.go`, Rust `bench/src/main.rs`
`socks5-get`), đo code harness chứ KHÔNG phải outbound thật của castctl
(sing-box/honk). Độ trễ loopback bị chi phối bởi TCP localhost + proxy
Python + `http.server` Python, không phải code client. Hai bẫy đã gặp
và sửa trong lúc đo: (a) port cố định 18080 thuộc server `echo.py` của
session khác (pid 1666878) trả `b"ok"` cho mọi path — driver nay chọn
port ephemeral bằng bind-0 cho CẢ HTTP origin lẫn SOCKS5 và verify body
trước khi đo; (b) Go client fail toàn bộ ở lần chạy driver đầu vì
isolated HOME làm `go test` (GOTOOLCHAIN=auto) tìm toolchain cache sai
chỗ — Go item 5 nay chạy với HOME thật (ghi trong `measure_all.py`).

## Kết luận

- Rust **nhanh hơn Go rõ rệt, ngoài sai số**, ở: kích thước binary
  (77× nhỏ hơn — kèm caveat scope M2), startup (12.4×), RSS (93% ít
  hơn — số đúng sau khi sửa phương pháp đo; run4 báo 70% là sai do
  floor), logic thuần parse/render (1.8–6.2×). Các khoảng min/max không
  giao nhau ở những mục này.
- Rust **không hơn đáng kể** ở độ trễ 1 request loopback qua SOCKS5
  hand-roll: nhanh hơn 5%, khoảng giao nhau → trong sai số; và số này
  đo harness, không phải outbound thật.
- Lợi thế parse-large (6.1×) và render (6.2×) một phần là do Go làm
  nhiều việc hơn (validate sâu, alloc churn) và Rust defer validation —
  không phải toàn bộ là "Rust nhanh hơn". Đo lại sau khi Rust bổ sung
  validation.
- Không có mục nào Rust chậm hơn Go ngoài sai số trong baseline này.

## Hotspot ưu tiên (tối đa 7, sắp theo lợi ích/chi phí)

1. **Rust parse-large: validation chiếm 66% thời gian parse.**
   Bằng chứng số: parse-large 1,163 µs vs decode-alone 392 µs cùng
   input (32,246 B) — validation + build struct ≈ 770 µs. Lợi ích ước
   lượng: đưa validation về gần tốc độ decode → parse-large ~500–600 µs
   (~2×), với giả định validation+build rút về ~100–200 µs (chưa đo)
   và floor là 392 µs decode (không thể nhanh hơn decode). Chi phí sửa:
   trung bình (code trong `castctl-config/src/config.rs`, validation
   order + error message bị test parity ghim). Rủi ro: phá parity
   byte-for-byte của thông báo lỗi. Chỉ làm sau khi có profile chi tiết
   hơn (hiện không có `perf` trên cue).
2. **Rust `md_to_html` chiếm 78% render chain.** Bằng chứng số:
   `md_to_html` 872 µs vs render-chain 1,114 µs cùng input 51,560 B;
   split trong chain suy ra ≈ 242 µs (1,114 − 872) trên HTML, khác với
   281 µs đo split trên markdown thô — hai input khác nhau, không cộng
   trực tiếp được. Go tương ứng 5,405 µs với 8,389 allocs/op — phía Rust
   chưa đếm được alloc. Lợi ích: giảm số pass regex / allocation trong
   `inline_html` (`castctl-tg-text`, stash + `replace_all` nhiều lượt).
   Chi phí: trung bình. Rủi ro: parity `MDToHTML` (test M1 ghim output
   từng case).
3. **`split_text_limit` collect toàn bộ input thành `Vec<char>` trước.**
   Bằng chứng cấu trúc (không phải profile): `lib.rs` collect
   `text.chars()` rồi mới cắt; số đo: 281 µs cho 51,560 B (Go 551 µs).
   Lợi ích: nhỏ–vừa (bỏ 1 alloc lớn + pass char). Chi phí: trung bình
   (ngữ nghĩa cắt/fence-carry bị test ghim chặt). Rủi ro: đổi hành vi
   cắt ở biên. Đo alloc trước khi sửa.
4. **Lợi thế parse-large sẽ thu hẹp khi Rust bổ sung sing-box validation
   (D-M2-1) — đo lại, đừng tối ưu trước.** Bằng chứng số: Go parse-large
   7.15 ms vs Rust 1.16 ms nhưng Go validate 180 outbound + 10 endpoint
   sâu (52,163 allocs/op); Rust defer. Lợi ích: tránh tối ưu sai chỗ +
   tránh ngạc nhiên khi validation hạ cánh. Chi phí: thấp (chỉ đo lại).
   Rủi ro: không có — đây là follow-up đo, không phải sửa code.
5. **Startup: không đáng tối ưu thêm lúc này.** Bằng chứng số: Rust
   `--version` 0.901 ms, hyperfine user 0.71 ms + system 0.21 ms; phần
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
   Bằng chứng số: item 5 Rust 0.830 ms vs Go 0.874 ms, trong sai số,
   và cả hai đều qua proxy Python + `http.server` Python. Lợi ích của
   việc tối ưu client hand-roll: ~0. Đo lại bằng outbound thật
   (honk/sing-box, M3) + gateway thật (M4a) trước khi đụng tới. Chi phí:
   thấp (chỉ đo). Rủi ro: tối ưu sai tầng.

## Output lần chạy thật (run7 — tóm tắt, KHÔNG nguyên văn)

```
$ CARGO_TARGET_DIR=/dev/shm/perf0-target sh rust/perf/run.sh   # trên cue, repo root
... (full build: plain 2.3 s, strip 2.0 s) ...
hyperfine --version:  Go median 11.13 ms vs Rust 0.882 ms (12.6x)
hyperfine --help:     Go median 11.09 ms vs Rust 0.981 ms (11.3x)
summary.json: date 2026-11-05T12:15:19Z, machine cue 8x Xeon 2.50GHz,
  MemTotal 24788940 kB, SwapTotal 0 kB, go 0.9.0 (1396697), cargo 1.99.1,
  go 1.27.3, hyperfine 1.18.0
item5: status measured, rust 0.830 ms/req (0.736-0.995),
  go 0.874 ms/req (0.766-1.071); setup 1.5 s, measure 10.4 s
SPDX check: PASS
```

Stdout thật đầy đủ: `rust/perf/data/run7-stdout.txt` (98,273 B — chính
là JSON dump của `summary.json` cộng dòng SPDX). Số thô đầy đủ:
`rust/perf/data/*.json` (mỗi file ghi từng lần chạy, median/min/max/
mean, exit code). Tái lập: chạy lại lệnh trên rồi diff
`data/summary.json` với file đã commit.

## Dao động giữa các lần chạy (run4 → run5 → run6 → run7, median)

Run5 dùng driver trung gian của fix loop 1 (vòng poll WNOHANG gây lượng
tử hoá wall 5 ms + RSS floor) nên số startup/RSS của nó KHÔNG dùng
được — driver đó không phải phương pháp của run4 (run4 dùng `wait4`
blocking, wall đúng, xem phần mở đầu); run6 dùng target dir còn ấm nên
thời gian build của nó không phải full build. Chỉ item 4/5 (đo bằng
harness nội bộ, không qua `measure.py`) so sánh được xuyên suốt cả
4 run. Summary run5 (`2026-11-05T12:05:39Z`) và run6
(`2026-11-05T12:14:07Z`) được commit ở `data/run5-summary.json` /
`data/run6-summary.json` để đối chiếu từng ô trong bảng này. Fixture parse-large đổi ở run5 (25,657 B / 140 outbounds →
32,246 B / 180 outbounds + 10 endpoints) nên parse-large/decode-large
tăng theo kích thước fixture, không phải drift máy.

| Tác vụ | run4 | run5 | run6 | run7 |
|---|---|---|---|---|
| Parse min Go / Rust (ns) | 5,882 / 2,517 | 4,529 / 2,554 | 4,494 / 2,539 | 4,511 / 2,553 |
| Parse large Go / Rust (ms) | 5.11 / 0.934 | 6.96 / 1.160 | 7.01 / 1.169 | 7.15 / 1.163 |
| MDToHTML Go / Rust (ms) | 4.62 / 0.873 | 5.00 / 0.869 | 5.43 / 0.878 | 5.41 / 0.872 |
| SplitText Go / Rust (µs) | 518 / 266 | 593 / 271 | 606 / 271 | 551 / 281 |
| Render chain Go / Rust (ms) | 5.24 / 1.085 | 6.46 / 1.074 | 5.42 / 1.092 | 5.62 / 1.114 |
| Item 5 Go / Rust (ms/req) | 0.813 / 0.756 | 0.810 / 0.729 | 0.858 / 0.929 | 0.874 / 0.830 |
| Startup `--version` tỉ lệ Rust/Go | 0.088 | (sai: wall lượng tử hoá) | 0.087 | 0.081 |
| RSS `--version` Go / Rust (MiB) | 43.5 / (sai: floor) | 30.5 / (sai: floor) | 30.4 / 2.14 | 30.4 / 2.14 |

Đọc: số Rust ở item 4 ổn định xuyên suốt (dao động ≤6% quanh median 4
run, trừ parse-large tăng theo fixture); số Go dao động nhiều hơn theo
tải máy (MDToHTML +17% run4→run7, parse-min −23%). Tỉ lệ startup
Rust/Go ổn định 0.081–0.088 dù thời gian tuyệt đối drift +34% (Go)
và +23% (Rust) run4→run7 theo tải. Item 5 dao động run-to-run cả hai
phía (Rust 0.729–0.929) và tỉ lệ đổi dấu (0.90–1.08) — khẳng định kết
luận "trong sai số". RSS Go `--version` ổn định 30.4 MiB ở run5–run7;
run4 (43.5 MiB) là outlier chưa rõ nguyên nhân (xem §3).

## File trong `rust/perf/`

- `run.sh` — 1 lệnh rerun (gọi `measure_all.py`, cuối cùng chạy bước
  SPDX chỉ-đọc advisory).
- `measure_all.py` — driver items 1–5, ghi `data/*.json` + `summary.json`.
- `measure.py` — timing wall (wait4 blocking + SIGALRM) + peak RSS bằng
  GNU time (stdlib + `/usr/bin/time`).
- `socks5.py` — SOCKS5 proxy tối thiểu (asyncio, no-auth, CONNECT only,
  chỉ cho target loopback 127.0.0.0/8).
- `bench/` — standalone Rust crate (`[workspace]` riêng, path deps tới
  `castctl-config`/`castctl-tg-text`, stdlib-only, không chạm
  `rust/Cargo.toml`): timing loop pure-logic + client SOCKS5.
  `Cargo.lock` của nó được commit để tái lập.
- `go-bench/` — Go `testing.B` bench (`ParseSingleConfig`, `MDToHTML`,
  `SplitText`, render chain) + client SOCKS5 (`TestSocks5Get`).
  File `.go` mang header SPDX GPL-3.0-or-later (bắt buộc:
  `TestSPDXHeaders` quét toàn repo).
- `fixtures/` — `config-min.json` (42 B), `config-large.json` (32,246 B,
  50 profiles + 180 outbounds + 10 endpoints, 19 protocol type, xem
  `gen_fixtures.py`), `message-long.md` (51,560 B, tổng hợp, seed
  20261105), `body-1024.bin` (1024 B), `gen_fixtures.py` (generator
  deterministic — chạy lại để tái tạo fixture).
- `data/` — số thô các lần chạy (run7 là số trong bảng trên;
  `run7-stdout.txt` là stdout thật của run7; `run5-summary.json` /
  `run6-summary.json` là summary đầy đủ của run5/run6 để đối chiếu
  bảng Drift).

## Chưa kiểm chứng / giới hạn (ghi rõ, không giấu)

- Cold cache thật (drop_caches): không đo — VM dùng chung, M4b đang chạy
  trên cue; chỉ có first measured run N=1 (warmup=0, sau probe).
- `perf` không có trên cue (không có `linux-tools` cho kernel 6.18.38+);
  hotspot 1–3 dựa trên breakdown số đo (decode vs parse, hàm vs hàm)
  và lý do cấu trúc, KHÔNG dựa trên CPU profile.
- Rust chưa có số allocation/op tương đương Go `ReportAllocs`.
- Item 5 đo harness hand-roll, không phải outbound/gateway thật.
- So sánh kích thước binary mang caveat scope M2 (xem §1).
- Số RSS Go `--version` ở run4 (43.5 MiB) không tái lập được và chưa rõ
  nguyên nhân (giả thuyết THP chưa kiểm chứng); số dùng ở đây là 30.4
  MiB (run5–run7 khớp nhau, GNU time đối chiếu).
- Run5/run6 được commit ở `data/run5-summary.json` /
  `data/run6-summary.json` để đối chiếu drift; chỉ run7 là baseline
  chính thức.
