# M-perf-1 — Go vs Rust performance baseline (measurement only)

Baseline hiệu năng Go `castctl` 0.9.0 vs Rust `castctl-rs` (M2 CLI surface)
và Rust `castctl-full` (CLI + config + transport/honk + gateway),
đo trên cue ngày 2026-11-05. **Không tối ưu code** — chỉ đo; mọi đề xuất
tối ưu nằm ở mục Hotspot bên dưới và đều kèm số.

Số trong tài liệu này là **run8** (`2026-11-05T15:23:14Z`, full rerun, xem
mục Drift bên dưới). Run7 (`2026-11-05T12:15:19Z`) đã được archive
byte-identical ở `data/run7-summary.json` (md5 `c449440cb768a629956a8c410ec1e4ae`)
trước khi rerun ghi đè các file per-item; cột Drift trace về file đó.
Số RSS Rust của run4 (commit `7f46964`, 13.2 MiB) là SAI — đó là floor
của tiến trình Python cha (`ru_maxrss` từ `wait4` kế thừa qua fork, đã
chứng minh bằng probe) — nên toàn bộ số RSS run4 đã bị thay bằng run7.
Wall-clock của run4 thì ĐÚNG: driver run4 dùng `os.wait4` blocking
(không có vòng poll nào), và Rust `--version` 0.686–0.831 ms không thể
ra từ lưới 5 ms — wall drift run4→run7 (+34% Go / +23% Rust) là drift
theo tải, tỉ lệ 0.081–0.088 trong cửa sổ run4–run7 (rerun độc lập đo
0.109, xem mục Drift). Vòng poll WNOHANG gây lượng tử hoá 5 ms chỉ
xuất hiện ở driver trung gian của fix loop 1 (run5, Rust `--version`
median 5.448 ms), không phải phương pháp của run4; các vấn đề phương
pháp do probe trong fix loop 1 phát hiện, không phải review vòng 1
(review vòng 1 đã kiểm chứng số run4 là đúng). Run6 dùng target dir
còn ấm nên thời gian build của nó không phải full build. Run7 là lần
chạy đầy đủ đầu tiên sau khi sửa lỗi RSS (backend GNU time) và loại
vòng poll WNOHANG; run8 giữ nguyên phương pháp đó và thêm cột thứ ba
`rust-full` (xem mục `rust-full` bên dưới).

## Vì sao có run8 (M-perf-1): phép so run7 không công bằng

Boss đọc PR #66 ở source và phán phép so run7 **không hợp lệ**: binary
Rust đo ở run7 là M2 CLI shell (`castctl-cli` + `castctl-config`, không
transport/gateway/bot) còn Go là binary full 48,100,296 B
(`-tags=with_utls,with_quic,with_wireguard,with_gvisor`). "Tỉ lệ 77.5×
là số thật nhưng trả lời sai câu hỏi." Run8 sửa đúng chỗ đó: thêm
binary Rust thứ ba, `rust-full(transport+gateway)`, đo cùng mọi item
với Go full — và mọi tỉ lệ headline từ đây trở đi là `rust-full/go`.
Cột `rust-cli-shell` giữ lại nhưng mang nhãn tham chiếu, không bao giờ
xuất hiện trong kết luận.

`rust-full` liên kết toàn bộ stack Rust đã port (CLI + config +
transport/honk + gateway) nhưng vẫn thiếu Telegram bot, keeper/screencast
login và webui, và dùng honk-outbound thay cho sing-box — nên đây là so
sánh "binary Rust đầy đủ nhất hiện có" với "binary Go đầy đủ", không
phải cùng một engine viết bằng hai ngôn ngữ. **Hiệu năng đo trên binary
Rust chưa đủ bề mặt tính năng; sẽ đo lại ở M7 khi `castctl-rs` thay được
binary Go (bot+keeper+webui). Trước đó không dùng số này để khuyến nghị
thay binary.**

Honesty line (đọc kèm mọi bảng 3 cột): rust-full KHÔNG phải "cùng
engine, khác ngôn ngữ" — Go dùng sing-box làm engine, Rust dùng
honk-outbound. So sánh items 1–3 trả lời "binary Rust mang full stack
đã port thì nặng bao nhiêu so với binary Go full", không trả lời "cùng
engine viết bằng Rust thì nhanh hơn bao nhiêu". Câu trả lời thứ hai
chỉ có ở item 4 (pure-logic, cùng thuật toán) — đó là so sánh hợp lệ
giữ nguyên và nhấn mạnh.

## Cách chạy lại toàn bộ (1 lệnh, trên cue, từ repo root)

```sh
sh rust/perf/run.sh [--skip-build] [--skip-item5]
```

- `--skip-build`: dùng lại các binary đã build (bỏ qua mọi lần build
  release; dùng khi chỉ muốn đo lại). Nếu binary `rust-full` không có
  sẵn, các phía rust-full được ghi `{"missing": true}` chứ không fail run.
- `--skip-item5`: bỏ qua item 5 thật (ghi `status: "skipped"` vào
  `summary.json`; không dựng server nào).
- Không `--skip-build`: build shell release thường (ghi kích thước chưa
  strip), rồi build lại với `RUSTFLAGS="-C strip=symbols"` (số chính);
  rồi build `rust-full` theo cùng recipe: plain → GNU-strip đối chiếu →
  no-keep variant (`--no-default-features`, cho A/B linkage) → headline
  (`RUSTFLAGS="-C strip=symbols"`, số chính); LTO build ở cuối, sau mọi
  phép đo, qua profile `release-lto` (xem mục `rust-full`).
- `CARGO_TARGET_DIR`: driver tôn trọng biến này của cargo (xem
  `measure_all.py`). Mặc định là `rust/target` cho shell/bench.
  **Riêng `rust-full` bắt buộc target dir ngoài repo** (cùng biến khi
  set, else `tempfile.gettempdir()/perf-full-target`, ghi trong
  `summary.json: machine.full_target_dir`): build full-bin biên dịch
  boring-sys, sinh file `.go` dưới target dir; `TestSPDXHeaders` walk
  toàn repo chỉ skip thư mục dot nên target dir trong repo sẽ làm FAIL
  check SPDX chạy cuối `run.sh`. Run8 dùng `/tmp/perf-full-target`
  (cold, 2.2 GiB lúc xong) vì `CARGO_TARGET_DIR` không set; shell build
  dùng `rust/target` trong cây cue. Run7 dùng
  `CARGO_TARGET_DIR=/dev/shm/perf0-target` vì đĩa `/` của cue lúc đó đã
  99% đầy (850 MB trống theo `df_root` trong `summary.json`, session M4b
  đang build song song); target dir ~41 MiB (delta trống trên /dev/shm:
  7.82→7.78 GiB), dọn sau khi chạy xong.
- Disk preflight: driver fail sớm nếu `/` (hoặc filesystem của
  `CARGO_TARGET_DIR`) dưới 1.0 GiB trống, và nếu filesystem của
  full-target dưới 2.0 GiB trống (M-perf-1: closure full ~1.1 GiB
  target dir lúc probe, gấp ~40× shell). Run8: `/` 12.6 GiB trước →
  10.35 GiB sau (target full 2.2 GiB + shell target).
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
  của run8 được commit ở `data/run8-stdout.txt` (xem mục Output bên dưới;
  run7 giữ ở `data/run7-stdout.txt`).
- **Bẫy thứ tự gate (đã gặp 2026-11-05):** `TestSPDXHeaders` quét MỌI
  file `.go` dưới repo root (chỉ trừ thư mục dot) — kể cả file sinh ra
  dưới `rust/target/debug/build/boring-sys-*/out/` (322 file BoringSSL
  không có header SPDX) sau một lần `cargo build/test --workspace`.
  Bẫy này CHỈ xảy ra sau workspace build, KHÔNG bao giờ xảy ra với
  `run.sh` (nó chỉ build `-p castctl-rs` + bench crate + full-bin với
  target dir ngoài repo, không sinh file `.go` nào dưới repo). Chạy SPDX
  **trước** build workspace, hoặc xóa
  `rust/target/debug/build/boring-sys-*/out/` trước khi chạy SPDX
  (chỉ xóa `out/`, đừng xóa cả thư mục build — xóa `out/` mà giữ
  fingerprint làm lần build sau fail `couldn't find .../bindings.rs`;
  muốn build lại thì `cargo clean -p boring-sys`). File `.go` của PR
  này (`rust/perf/go-bench/`) có header đầy đủ và không nằm trong danh
  sách thiếu. CI Go (checkout sạch, không build Rust) không gặp bẫy này.
  `run.sh` kết thúc bằng một bước SPDX chỉ-đọc (advisory, không làm
  fail run): run8 in `SPDX check: PASS`.

## Điều kiện đo (run8, 2026-11-05T15:23:14Z)

- Máy: cue, `Linux 6.18.38+ x86_64`, 8 × Intel Xeon @ 2.50GHz,
  MemTotal 24,788,940 kB (23.6 GiB), SwapTotal 0 kB (ghi trong
  `summary.json: machine.meminfo`), loadavg 1-phút 2.24 lúc bắt đầu,
  7.73 giữa chừng, 6.09 lúc kết thúc (cao hơn run7 0.48–1.00 — build
  full-bin biên dịch ~350 crate song song; cộng 33 mark loadavg +
  timestamp trước/sau từng item và từng phía trong
  `summary.json: marks`). Đĩa `/` 12.6 GiB trống lúc chạy; build
  outputs: shell trên `rust/target`, full trên `/tmp/perf-full-target`
  (2.2 GiB lúc xong, cold — `full_target_cold: true` trong summary).
- Go: `/usr/local/bin/castctl` 0.9.0 (`1396697 2026-11-04T21:38:36Z`),
  48,100,296 B, sha256 `c8ea009e…` (cùng binary với run7).
  `go version -m` (ghi đầy đủ trong `summary.json`):
  `-buildmode=exe`, tags `with_utls,with_quic,with_wireguard,
  with_gvisor`, `-trimpath=true`, `CGO_ENABLED=1`, `GOARCH=amd64`.
  Output `go version -m` KHÔNG có dòng `-ldflags` nào nên tài liệu này
  không claim `-s -w` (claim đó ở run4 không có nguồn trong data).
  Go toolchain 1.27.3.
- Rust shell: `castctl-rs` build từ `dev-rust` 96ce485 trên nhánh này,
  `cargo +1.99.1 build --release --locked -p castctl-rs`,
  `RUSTFLAGS="-C strip=symbols"` (số chính); build thường 2.4 s,
  build strip 2.1 s (full build, target dir lạnh; chỉ build closure
  `castctl-rs` + `castctl-cli` + `castctl-config`, stdlib-only, không
  build toàn workspace).
- Rust full: `castctl-full` build từ `rust/perf/full-bin/` (standalone
  crate, `[workspace]` riêng, path deps `castctl-cli` +
  `castctl-config` + `castctl-transport` + `castctl-gateway`,
  `[patch.crates-io]` copy nguyên văn từ workspace chính),
  `cargo +1.99.1 build --release --locked --offline --manifest-path
  rust/perf/full-bin/Cargo.toml`, `RUSTFLAGS="-C strip=symbols"`
  (số chính); build thường 195.8 s, no-keep 193.1 s, strip 1.7 s
  (target dir lạnh `/tmp/perf-full-target`; mỗi lần đổi RUSTFLAGS là
  rebuild lại closure ~3 phút — đo được, không phải ước). Xem chi tiết
  linkage ở mục `rust-full` bên dưới.
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
    N=1, ghi rõ nhãn `n=1, không dùng làm kết luận`.
  - Thứ tự chạy: KHÔNG interleave — mỗi item đo theo adjacent batch
    (hết Go rồi tới shell rồi tới full; item 5 chạy Rust trước rồi Go).
    Loadavg + timestamp trước/sau từng phía nằm trong
    `summary.json: marks`; ở run7 loadavg 1-phút phẳng 1.00 trong suốt
    item 5 nên thứ tự batch không làm lệch item 5 (run8: item 5 chạy
    cuối, sau khi load đã hạ; xem marks).
- Thống kê: median + min/max, N=20 (startup/RSS), N=5 lần chạy process
  (pure-logic, item 5 — xem chi tiết replicate ở §4). Tỉ lệ
  rust-full/Go < 1 = rust-full tốt hơn (time/RAM/size). Chênh < ~10%
  với khoảng min/max giao nhau = "nằm trong sai số". Dao động giữa các
  lần chạy: xem mục Drift.

## `rust-full`: binary gì, và chứng minh nó thật sự chứa transport+gateway

`rust/perf/full-bin/` là crate standalone (package `perf-full`, binary
`castctl-full`, `[workspace]` riêng, edition 2021): `src/main.rs` là
`main` của `castctl-rs` chép nguyên văn (gọi `castctl_cli::run(&args,
None)`), cộng một lời gọi có điều kiện tới `keep::keep_linked()` — chỉ
chạy khi env `PERF_KEEP_LINKED` được set (không bao giờ set lúc đo).
`src/keep.rs` giữ code transport+gateway sống trong binary bằng các
"root" không I/O (xem chi tiết trong file): Tier 1 gọi thật các hàm
public (`dispatch_outbound`/`dispatch_endpoint`,
`HttpClient::new`/`RpcClient::new`, `InitiatorHandshake::new()` +
`.msg1()`, `Reassembler::new()`, `split_pieces`, `marshal_transport_frame`,
`Gateway::decode_call_json`, `DownTracker::new()`, `default_ws_url`,
`uuid_v4()`, build tokio runtime rồi drop) với input dummy đã ghi rõ là
dummy, không bao giờ dial/bind/đọc file/mạng. Tier 2 chỉ lấy ĐỊA CHỈ
hàm (`WireGuardDialer::dial`, `HttpClient::request`), không gọi.

### Chứng minh linkage (probe trên cue, 2026-11-05, trước khi đo)

(a) **Size A/B, stripped** (`RUSTFLAGS="-C strip=symbols"`, GNU strip
đối chiếu trong ngoặc): shell 620,968 B (620,960) → full **không-keep**
(`--no-default-features`) 621,112 B → full **keep** 12,527,080 B
(12,527,072). Chỉ thêm deps vào `Cargo.toml` mà không dùng thì binary
to thêm 144 B; bật `keep-linked` thì to thêm **11,905,968 B**. Nếu
`(c)−(a) ≈ 0` thì cơ chế giữ-link đã fail — ở đây nó to gấp 20.17×,
cơ chế hoạt động. Unstripped: shell 778,936 B, full no-keep 779,096 B,
full keep 16,811,376 B. `.text`/`.rodata` (stripped): shell 434,883 /
74,708 B; full keep 7,979,624 / 1,604,904 B.

(b) **Bảng `nm`** (đếm symbol chứa chuỗi, trên binary **chưa strip**;
`nm` trên binary đã strip trả về rỗng nên không dùng được — lỗi phương
pháp đã gặp một lần trong lúc probe; và pattern phải là chuỗi trần,
không phải `castctl_transport::`, vì symbol Rust đã mangle):

| Chuỗi | shell | full no-keep | full keep (run8) |
|---|---|---|---|
| `castctl_transport` | 0 | 0 | **504** |
| `castctl_gateway` | 0 | 0 | **62** |
| `honk_outbound` | 0 | 0 | **9,264** |
| `boringtun` | 0 | 0 | **98** |
| `smoltcp` | 0 | 0 | **185** |
| `tokio` | 0 | 0 | **3,905** |
| `prost` | 0 | 0 | **2** |
| `tungstenite` | 0 | 0 | **298** |
| `snow` | 0 | 0 | **118** |
| `hyper` | 0 | 0 | **0** |

Symbol riêng lẻ trong full keep: `dispatch_outbound` 2,
`ensure_tunnel` 1, `KEEP_TIER2` 1, `HonkDialer` 1,
`WireGuardDialer` 4. (`HttpClient`/`RpcClient`/`DownTracker` 0 =
constructor nhỏ bị inline, không phải lỗi.)

(c) **Patch check:** `cargo tree -i boring-sys` /
`cargo tree -i quinn` đều trỏ về git Glassyiris
(`boring-sys rev 3beb573…`, `quinn rev 11f1de84…`,
`honk rev 9e31cc0…`); `full-bin/Cargo.lock` (354 package, commit kèm
crate) chứa đúng các rev đó.

(d) **Hành vi:** `castctl-full --version` → `castctl 0.9.0`, exit 0;
`--help` byte-identical với shell (`cmp` pass); `--version=x` →
stderr + exit 2; `PERF_KEEP_LINKED=1 --version` in giống hệt, exit 0.

### Hai điều probe chứng minh là SAI, và một khoảng trống đã công bố

- **Address-taking + `black_box` KHÔNG giữ được code.** Build chỉ có
  Tier 2 dạng này cho ra binary byte-identical về kích thước
  (16,272,088 B) và `nm` không đổi (boringtun 0, hyper 0) — compiler
  loại bỏ. Chỉ `#[used] static` chứa địa chỉ hàm mới giữ được (Tier 2
  hiện tại): boringtun 0→98, smoltcp 2→185, `ensure_tunnel` xuất hiện,
  +543,384 B unstripped. Lịch sử này ghi trong `keep.rs` để lần sau
  khỏi thử lại cách đã fail.
- **LTO qua `RUSTFLAGS -C lto` KHÔNG build được closure này.** Run8
  fail trong 0.5 s (`options '-C embed-bitcode=no' and '-C lto' are
  incompatible`); sửa thêm `-C embed-bitcode=yes` thì fail tiếp
  (`lto cannot be used for 'proc-macro' crate type without
  '-Zdylib-lto'` trên `zeroize_derive`/`serde_derive` — flag áp cho
  mọi crate kể cả proc-macro). LTO đúng phải qua profile
  (`[profile.release-lto]`, `inherits = "release"`, `lto = "fat"`,
  `strip = "symbols"` trong `full-bin/Cargo.toml`) — profile form bỏ
  qua proc-macro. Build tay trên cue sau run8 với profile này:
  exit 0, 4m 32s, 10,065,944 B (xem hàng LTO ở §1). Driver đã đổi sang
  profile form để rerun sau tái lập được; `summary.json` của run8 vẫn
  ghi đúng lần fail gốc (`build_full_lto`, exit 101).
- **Khoảng trống đã công bố: hyper client machinery (0 symbol).**
  Entry `HttpClient::request` trong `#[used]` static KHÔNG giữ được
  hyper: địa chỉ của một `async fn` chỉ giữ constructor của future,
  không giữ code `poll` điều khiển hyper — mà poll nó thì cần I/O
  thật, điều không root nào được làm. Nên rust-full là **lower bound**
  của binary M7 ở đúng một chỗ này: nó chứa `HttpClient::new` +
  type `http::Request/Response` nhưng không chứa state machine client
  của hyper. Không phóng đại, không giấu.

### Build recipe (tái lập)

- Primary (số headline): release mặc định (opt-level 3,
  `debug = false`, codegen-units mặc định, panic unwind, **không
  LTO**), strip qua `RUSTFLAGS="-C strip=symbols"` — giống hệt run7,
  để delta shell→full quy được hoàn toàn cho closure đã link, không
  lẫn co rút do LTO. Go binary cũng không có analogue LTO.
- LTO variant (hàng riêng, không vào tỉ lệ headline):
  `cargo +1.99.1 build --profile release-lto --locked --offline
  --manifest-path rust/perf/full-bin/Cargo.toml` (output ở
  `release-lto/`, không đụng binary headline ở `release/`).
- Kiểm tra nm trên binary LTO **không chạy trực tiếp được** (profile
  strip symbols nên `nm` trả rỗng); bằng chứng giữ-link ở LTO là
  `.text` 6,942,120 B (so với no-keep 434,883 B và primary 7,979,624 B)
  — closure đầy đủ vẫn còn đó, chỉ co lại 13% do LTO — cộng với cơ chế
  `#[used]` static giữ hàm có địa chỉ + các callee truyền của nó sống
  qua LTO theo construction (linker không thể drop hàm mà địa chỉ của
  nó nằm trong static được giữ). Đây là điểm lệch so với kế hoạch gốc
  (kế hoạch đòi nm cả hai variant); ghi rõ ở đây thay vì giả vờ đã nm.

## Bảng số (run8)

Quy ước: mọi ô headline kèm `median (min–max), N=20` (trừ hàng n=1).
Tỉ lệ headline LUÔN là `rust-full/go`. Cột `rust-shell/go` mang nhãn
tham chiếu — không so được với Go full, không bao giờ xuất hiện trong
kết luận.

### 1. Kích thước binary

| | Go (full) | Rust shell (M2, tham chiếu) | Rust full (transport+gateway) | Rust-full/Go | Rust-shell/Go (tham chiếu) |
|---|---|---|---|---|---|
| Stripped (`-C strip=symbols`) | 48,100,296 B (45.87 MiB) | 620,968 B (0.59 MiB) | **12,527,080 B (11.95 MiB)** | **0.260 (3.84× nhỏ hơn)** | 0.013 (77.5×) |
| Chưa strip | — | 778,936 B | 16,811,376 B | 0.350 | 0.016 |
| GNU strip (đối chiếu) | — | 620,960 B (chênh 8 B) | 12,527,072 B (chênh 8 B) | — | — |
| `.text` | 21,017,769 B | 434,883 B | 7,979,624 B | 0.380 | 0.021 |
| `.rodata` | 2,644,352 B | 74,708 B | 1,604,904 B | 0.607 | 0.028 |
| A/B no-keep, stripped | — | — | 621,112 B (delta closure +11,905,968 B) | — | — |
| LTO variant, stripped (`release-lto`) | — | — | 10,065,944 B (nhỏ hơn headline 19.6%) | 0.209 | — |

`sha256`: Go `c8ea009e…`, shell stripped `6f270890…`, full stripped
`b8aee622…`, full no-keep `9cb6d472…`, full LTO `8040a0c6…` (full trong
`data/summary.json`, trừ LTO — xem ghi chú). Hàng LTO: build tay trên
cue sau run8 (`--profile release-lto`, 4m 32s, `--version` exit 0),
cùng source với run8; `summary.json` của run8 ghi lần build LTO gốc
bằng RUSTFLAGS đã fail (exit 101, xem mục `rust-full`); driver đã sửa
sang profile form để rerun sau tái lập được. Hàng LTO không dùng cho
tỉ lệ headline.

### 2. Startup (wall-clock, N=20, warmup 5)

| Lệnh | Go median (min–max) ms | Rust shell median (min–max) ms (tham chiếu) | Rust full median (min–max) ms | Rust-full/Go | Rust-shell/Go (tham chiếu) |
|---|---|---|---|---|---|
| `--version` | 10.628 (9.809–11.611) | 0.866 (0.770–1.271) | **1.904 (1.691–2.908)** | **0.179 (5.6× nhanh hơn)** | 0.081 |
| `--help` | 10.858 (9.710–11.975) | 0.927 (0.820–1.121) | **2.089 (1.789–2.591)** | **0.192 (5.2× nhanh hơn)** | 0.085 |
| First measured run, warmup=0, sau probe `--version` (KHÔNG cold, KHÔNG sau build), N=1 `--version` — **n=1, không dùng làm kết luận** | 51.909 | 2.863 | 3.393 | 0.065 | 0.055 |

Đối chiếu hyperfine 1.18.0 (N=20, median, 3 lệnh trong MỘT invocation):
`--version` Go 11.0 ms vs shell 0.7 ms vs **full 1.7 ms**
(full/Go 0.155); `--help` Go 10.8 ms vs shell 0.8 ms vs **full 1.8 ms**
(0.167). Khớp loop Python.
Lưu ý hàng n=1: wall first-run ở run8 cao bất thường ở cả ba phía so
với median (Go 51.909 ms ≈ 4.9× median 10.628 ms; shell 3.3×; full
1.8×) trong khi run7 first-run Go chỉ 12.616 ms ≈ median run7. Cơ chế
có thể là page cache bị build full-bin (~350 crate, 2.2 GiB target)
đẩy ra ngay trước khi đo — suy luận, chưa chứng minh; và vì là n=1
nên nó không dùng làm kết luận, chỉ ghi để khỏi ai trích nhầm.

### 3. Peak RSS (GNU time, N=20) + wall `status`

| Lệnh | Go median (min–max) | Rust shell median (min–max) (tham chiếu) | Rust full median (min–max) | Rust-full/Go | Exit Go / shell / full |
|---|---|---|---|---|---|
| `--version` wall ms | 10.628 (9.809–11.611) | 0.866 (0.770–1.271) | 1.904 (1.691–2.908) | 0.179 | 0 / 0 / 0 |
| `--version` RSS MiB | 30.342 (29.719–30.965) | 2.199 (2.102–2.324) | **5.424 (5.195–5.508)** | **0.179 (82% ít hơn)** | 0 / 0 / 0 |
| `--help` wall ms | 10.858 (9.710–11.975) | 0.927 (0.820–1.121) | 2.089 (1.789–2.591) | 0.192 | 0 / 0 / 0 |
| `--help` RSS MiB | 30.221 (29.594–30.965) | 2.246 (2.184–2.375) | **5.398 (5.203–5.473)** | **0.179** | 0 / 0 / 0 |
| `status --config min` wall ms | 12.369 (11.853–13.629) | 1.000 (0.858–1.449) | 2.124 (1.893–2.382) | 0.172 | 2 / 1 / 1 |
| `status --config min` RSS MiB | 33.096 (32.410–33.715) | 2.322 (2.273–2.438) | **5.557 (5.387–5.723)** | **0.168** | 2 / 1 / 1 |
| `status --config large` wall ms | 46.132 (41.204–51.431) | 2.897 (2.604–3.070) | 4.251 (3.727–5.223) | 0.092 | 2 / 1 / 1 |
| `status --config large` RSS MiB | 37.812 (37.156–38.461) | 2.824 (2.789–2.922) | **6.176 (5.930–6.328)** | **0.163** | 2 / 1 / 1 |
| `status --config bad-JSON` wall ms | 11.135 (10.344–12.078) | 0.928 (0.822–1.206) | 1.983 (1.694–2.347) | 0.178 | 2 / 2 / 2 |
| `status --config bad-JSON` RSS MiB | 30.781 (29.973–32.031) | 2.348 (2.289–2.406) | **5.557 (5.395–5.707)** | **0.181** | 2 / 2 / 2 |

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
pass). Đường so sánh sạch nhất cho parse là bad-JSON gate (cả ba đều
dừng ở parse, exit 2). RSS full tăng nhẹ theo config (min 5.557 →
large 6.176 MiB, +0.62 MiB — chi phí parse thật trên closure lớn);
RSS Go tăng +4.9 MiB từ min → large (+7.3 MiB so với `--version`).
Wall-clock cũng thấy chi phí parse của full: `status` large 4.251 ms
so với min 2.124 ms; Go large 46.132 ms so với min 12.369 ms (Go
large chậm hẳn vì fail ở tạo endpoint sau khi parse+validate).

**Lịch sử số RSS (đọc kỹ trước khi trích):** số RSS Rust ở run4/run5
(13.2 MiB) là SAI — đó là floor của Python cha (xem phương pháp đo);
số đúng là ~2.1 MiB cho shell, ~5.4 MiB cho full. RSS Go `--version` là
**bimodal theo session** (cùng binary, cùng sha256): run4 đo 43.5 MiB,
run5/run6/run7 đều đo 30.4 MiB, còn rerun độc lập (verify,
`2026-11-05T14:26:32Z`, xem mục Drift) đo 47.7 MiB — tức 2/5 session ở
mode cao (43.5, 47.7 MiB), 3/5 ở mode thấp (30.4 MiB). Trong một session
thì số ổn định chặt (verify: 47.61–47.93 MiB trên cả 20 run; run7:
29.80–30.98 MiB; run8: 29.72–30.97 MiB). Hai phương pháp đo độc lập
đồng thuận trong session verify: GNU time 47.74 MiB và `wait4`
`maxrss_kib_raw` median 47.7 MiB, nên mode cao là thật, không phải lỗi
đo. Nguyên nhân chưa rõ — giả thuyết (chưa kiểm chứng): Go 1.27 xin
transparent huge page cho heap arena, RSS hạch toán cả page 2 MB dù
chỉ dùng một phần; tuỳ trạng thái THP/fragmentation mà số hạch toán
dao động; lúc probe `AnonHugePages` là 0 kB nên giả thuyết này không
được xác nhận cũng không bị bác bỏ. Probe với đúng env cô lập của
driver vẫn cho mode thấp (30.5–31.3 MiB, probe của verifier sau rerun,
không nằm trong summary đã commit) nên env không phải nguyên nhân.
**Hệ quả khi trích:** số RSS Go trong bảng trên là số của run8 (mode
thấp, 30.3 MiB); tỉ lệ RSS rust-full/Go dao động theo session (run8:
0.179; nếu Go ở mode cao 47.7 MiB thì tỉ lệ ~0.114), không phải một
số duy nhất. RSS Rust full ổn định ~5.4–5.6 MiB ở `--version` trong
run8; RSS shell ổn định ~2.1–2.3 MiB xuyên suốt mọi session
(run6/run7/verify ở `--version`: 2.14 / 2.14 / 2.22 MiB).

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

**Không có cột thứ ba:** bench đo trực tiếp cùng code
`castctl-config`/`castctl-tg-text` mà cả shell lẫn full đều link — cột
rust-full sẽ đo lại code giống hệt qua một binary khác, không thêm
thông tin. Đây là so sánh hợp lệ giữ nguyên từ run7 (Boss item 4).

| Tác vụ | Go ns/iter median (min–max) | Rust ns/iter median (min–max) | Rust/Go | K median (Rust) |
|---|---|---|---|---|
| Parse config min (42 B) | 4,548 (3,872–7,892) | 2,512 (2,502–2,810) | **0.55 (1.8× nhanh hơn)** | 131,072 |
| Parse config large (32,246 B, 50 profiles + 180 outbounds + 10 endpoints) | 7,346,472 (6,980,382–7,728,631) | 1,178,401 (1,146,312–1,266,471) | **0.16 (6.2× nhanh hơn)** | 256 |
| Decode JSON large, Rust-only (`decode_ordered_object`) | — | 389,107 (385,175–475,732) | — | 1,024 |
| `MDToHTML` (message 51,560 B) | 5,344,879 (4,783,666–6,148,271) | 886,299 (868,879–970,148) | **0.17 (6.0× nhanh hơn)** | 256 |
| `SplitText` (51,560 B) | 554,710 (531,612–611,254) | 270,775 (270,210–287,009) | **0.49 (2.0× nhanh hơn)** | 1,024 |
| Render chain (`MDToHTML` + `SplitText`) | 5,994,828 (5,802,702–7,142,152) | 1,075,627 (1,069,368–1,107,080) | **0.18 (5.6× nhanh hơn)** | 256 |

`output_len` đã kiểm chứng trong raw: parse-large 50 profiles,
decode-large 4 keys, `md-to-html` 58,259 chars, `split-text` 15,
render-chain 58,277, parse-min 1. Mọi run Rust đều ≥ 200 ms total
(K dừng ở 131,072 khi total đạt ~335 ms ở parse-min; cap `1<<20`
không chạm tới).

**Bất đối xứng phải đọc kèm:** cùng tên hàm nhưng khác khối lượng việc.
Go `ParseSingleConfig` validate sâu toàn bộ outbound (sing-box); Rust
defer sing-box option validation (deviation D-M2-1) nên parse-large của
Rust làm ít việc hơn. Bằng chứng: Go parse-large 2,195,517 B/op +
52,163 allocs/op (median — xem `go_b_op_allocs` trong `summary.json`);
Rust decode chỉ 389 µs trong tổng parse 1,178 µs (validation+build
struct chiếm 67%). Khi Rust bổ sung validation, lợi thế parse-large sẽ
thu hẹp — đo lại sau bước đó (hotspot H4). Tương tự `MDToHTML`: Go
4,853,245 B/op + 8,387 allocs/op (median; churn chuỗi lớn); Rust dùng
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

**Không có cột rust-full:** phía Rust chạy client `socks5-get` của
bench crate (cùng code honk dialer mà full binary link), không phải
binary `castctl-full` — không có đường CLI nào drive một request qua
transport; thêm đường đó là product surface mới, ngoài scope PR đo
lường.

| | Go ms/req median (min–max) | Rust ms/req median (min–max) | Rust/Go |
|---|---|---|---|
| SOCKS5 GET loopback | 0.885 (0.818–0.919) | 0.872 (0.797–0.921) | **0.99 (1% nhanh hơn — nằm trong sai số, khoảng giao nhau)** |

Setup (spawn + verify hai server) hết 1.5 s; đo 11.0 s; tổng 12.5 s
(trong hạn 20 phút). Thứ tự chạy: Rust trước (5 lượt), rồi Go (5 lượt),
adjacent batches.

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

## Kết luận (chỉ nói về rust-full — cột shell là tham chiếu, không kết luận)

- Rust full **nhanh hơn Go rõ rệt, ngoài sai số**, ở: kích thước binary
  (12.53 MB vs 48.10 MB — 0.260×, nhỏ hơn 3.84×), startup `--version`
  1.904 ms vs 10.628 ms (0.179×, 5.6× nhanh hơn), `--help` 2.089 ms vs
  10.858 ms (0.192×), RSS `--version` 5.424 MiB vs 30.342 MiB (0.179×,
  82% ít hơn), parse config min/large/bad (wall 0.092–0.178×, RSS
  0.163–0.181×). Các khoảng min/max không giao nhau ở những mục này.
- Rust full **không hơn đáng kể** ở độ trễ 1 request loopback qua SOCKS5
  hand-roll: nhanh hơn 1%, khoảng giao nhau → trong sai số; và số này
  đo harness, không phải outbound thật (item 5 không có cột full).
- Lợi thế parse-large (6.2×) và render (6.0×) một phần là do Go làm
  nhiều việc hơn (validate sâu, alloc churn) và Rust defer validation —
  không phải toàn bộ là "Rust nhanh hơn". Đo lại sau khi Rust bổ sung
  validation.
- Không có mục nào rust-full chậm hơn Go ngoài sai số trong baseline
  này.
- Con số cũ "77.5× nhỏ hơn" (run7, shell vs Go full) vẫn đúng về mặt
  số học nhưng **không còn là headline** — nó so hai thứ khác nhau.
  Headline từ run8 là 0.260× (3.84×) của rust-full.

## Hotspot ưu tiên (tối đa 7, sắp theo lợi ích/chi phí)

1. **Rust parse-large: validation chiếm 67% thời gian parse.**
   Bằng chứng số: parse-large 1,178 µs vs decode-alone 389 µs cùng
   input (32,246 B) — validation + build struct ≈ 789 µs. Lợi ích ước
   lượng: đưa validation về gần tốc độ decode → parse-large ~500–600 µs
   (~2×), với giả định validation+build rút về ~100–200 µs (chưa đo)
   và floor là 389 µs decode (không thể nhanh hơn decode). Chi phí sửa:
   trung bình (code trong `castctl-config/src/config.rs`, validation
   order + error message bị test parity ghim). Rủi ro: phá parity
   byte-for-byte của thông báo lỗi. Chỉ làm sau khi có profile chi tiết
   hơn (hiện không có `perf` trên cue).
2. **Rust `md_to_html` chiếm 82% render chain.** Bằng chứng số:
   `md_to_html` 886 µs vs render-chain 1,076 µs cùng input 51,560 B;
   split trong chain suy ra ≈ 190 µs (1,076 − 886) trên HTML, khác với
   271 µs đo split trên markdown thô — hai input khác nhau, không cộng
   trực tiếp được. Go tương ứng 5,345 µs với 8,387 allocs/op — phía Rust
   chưa đếm được alloc. Lợi ích: giảm số pass regex / allocation trong
   `inline_html` (`castctl-tg-text`, stash + `replace_all` nhiều lượt).
   Chi phí: trung bình. Rủi ro: parity `MDToHTML` (test M1 ghim output
   từng case).
3. **`split_text_limit` collect toàn bộ input thành `Vec<char>` trước.**
   Bằng chứng cấu trúc (không phải profile): `lib.rs` collect
   `text.chars()` rồi mới cắt; số đo: 271 µs cho 51,560 B (Go 555 µs).
   Lợi ích: nhỏ–vừa (bỏ 1 alloc lớn + pass char). Chi phí: trung bình
   (ngữ nghĩa cắt/fence-carry bị test ghim chặt). Rủi ro: đổi hành vi
   cắt ở biên. Đo alloc trước khi sửa.
4. **Lợi thế parse-large sẽ thu hẹp khi Rust bổ sung sing-box validation
   (D-M2-1) — đo lại, đừng tối ưu trước.** Bằng chứng số: Go parse-large
   7.35 ms vs Rust 1.18 ms nhưng Go validate 180 outbound + 10 endpoint
   sâu (52,163 allocs/op); Rust defer. Lợi ích: tránh tối ưu sai chỗ +
   tránh ngạc nhiên khi validation hạ cánh. Chi phí: thấp (chỉ đo lại).
   Rủi ro: không có — đây là follow-up đo, không phải sửa code.
5. **Startup của rust-full: 1.9 ms, không đáng tối ưu thêm lúc này.**
   Bằng chứng số: full `--version` 1.904 ms (shell 0.866 ms — closure
   lớn hơn tốn ~1 ms init/reloc: `.rela.dyn` 576 KB so với shell 22 KB);
   phần lớn còn lại là spawn process + dynamic loader. Lợi ích tối đa
   ~1 ms tuyệt đối. Chi phí: thấp–trung bình (`-C
   target-cpu=native` bị CẤM ở PR này; static musl đổi cả toolchain).
   Rủi ro: đổi ABI/link. Để sau, khi binary lớn hơn.
6. **Kích thước binary: LTO co thêm 19.6% nhưng không đổi headline.**
   Bằng chứng số: full headline 12,527,080 B, LTO 10,065,944 B
   (`.text` 7,979,624 → 6,942,120 B); shell 620,968 B. Lợi ích thêm
   (`codegen-units=1` / `panic=abort`): vài chục KB, không đáng kể so
   với 0.260× hiện tại. Chi phí: thấp nhưng `panic=abort` đổi hành vi
   crash. Rủi ro: thấp. Chỉ xem lại khi Rust port thêm crate nặng
   (bot/keeper/webui ở M7 sẽ làm binary lớn hơn nhiều — đo lại ở đó).
7. **Transport thật chưa đo — đừng micro-tối ưu client hand-roll.**
   Bằng chứng số: item 5 Rust 0.872 ms vs Go 0.885 ms, trong sai số,
   và cả hai đều qua proxy Python + `http.server` Python. Lợi ích của
   việc tối ưu client hand-roll: ~0. Đo lại bằng outbound thật
   (honk/sing-box, M3) + gateway thật (M4a) trước khi đụng tới. Chi phí:
   thấp (chỉ đo). Rủi ro: tối ưu sai tầng.

## Output lần chạy thật (run8 — tóm tắt, KHÔNG nguyên văn)

```
$ sh rust/perf/run.sh   # trên cue, repo root, không flag
... (shell build: plain 2.4 s, strip 2.1 s; full build: plain 195.8 s, nokeep 193.1 s, strip 1.7 s) ...
hyperfine --version:  Go median 11.0 ms vs shell 0.7 ms vs full 1.7 ms
hyperfine --help:     Go median 10.8 ms vs shell 0.8 ms vs full 1.8 ms
summary.json: date 2026-11-05T15:23:14Z, machine cue 8x Xeon 2.50GHz,
  MemTotal 24788940 kB, SwapTotal 0 kB, go 0.9.0 (1396697), cargo 1.99.1,
  go 1.27.3, hyperfine 1.18.0, loadavg start 2.24 / mid 7.73 / end 6.09,
  disk / 12.6 -> 10.35 GiB
item5: status measured, rust 0.872 ms/req (0.797-0.921),
  go 0.885 ms/req (0.818-0.919); setup 1.5 s, measure 11.0 s
full-bin LTO build FAILED (RUSTFLAGS); see build_full_lto (secondary row only)
SPDX check: PASS
```

Stdout thật đầy đủ: `rust/perf/data/run8-stdout.txt` (147,054 B — chính
là JSON dump của `summary.json` cộng dòng LTO-fail và dòng SPDX; JSON
trong log khớp byte với `summary.json` đã commit). Số thô đầy đủ:
`rust/perf/data/*.json` (mỗi file ghi từng lần chạy, median/min/max/
mean, exit code). Tái lập: chạy lại lệnh trên rồi diff
`data/summary.json` với file đã commit. Lưu ý: lần chạy này có một
note duy nhất trong summary — LTO build gốc fail (xem mục `rust-full`);
mọi phép đo khác exit như kỳ vọng.

## Dao động giữa các lần chạy (run4 → run5 → run6 → run7 → run8, median)

Run5 dùng driver trung gian của fix loop 1 (vòng poll WNOHANG gây lượng
tử hoá wall 5 ms + RSS floor) nên số startup/RSS của nó KHÔNG dùng
được — driver đó không phải phương pháp của run4 (run4 dùng `wait4`
blocking, wall đúng, xem phần mở đầu); run6 dùng target dir còn ấm nên
thời gian build của nó không phải full build. Chỉ item 4/5 (đo bằng
harness nội bộ, không qua `measure.py`) so sánh được xuyên suốt cả
5 run. Summary run5 (`2026-11-05T12:05:39Z`) và run6
(`2026-11-05T12:14:07Z`) được commit ở `data/run5-summary.json` /
`data/run6-summary.json` để đối chiếu từng ô trong bảng này; run7 ở
`data/run7-summary.json`. Fixture parse-large đổi ở run5 (25,657 B /
140 outbounds → 32,246 B / 180 outbounds + 10 endpoints) nên
parse-large/decode-large tăng theo kích thước fixture, không phải drift
máy.

| Tác vụ | run4 | run5 | run6 | run7 | run8 |
|---|---|---|---|---|---|
| Parse min Go / Rust (ns) | 5,882 / 2,517 | 4,529 / 2,554 | 4,494 / 2,539 | 4,511 / 2,553 | 4,548 / 2,512 |
| Parse large Go / Rust (ms) | 5.11 / 0.934 | 6.96 / 1.160 | 7.01 / 1.169 | 7.15 / 1.163 | 7.35 / 1.178 |
| MDToHTML Go / Rust (ms) | 4.62 / 0.873 | 5.00 / 0.869 | 5.43 / 0.878 | 5.41 / 0.872 | 5.34 / 0.886 |
| SplitText Go / Rust (µs) | 518 / 266 | 593 / 271 | 606 / 271 | 551 / 281 | 555 / 271 |
| Render chain Go / Rust (ms) | 5.24 / 1.085 | 6.46 / 1.074 | 5.42 / 1.092 | 5.62 / 1.114 | 5.99 / 1.076 |
| Item 5 Go / Rust (ms/req) | 0.813 / 0.756 | 0.810 / 0.729 | 0.858 / 0.929 | 0.874 / 0.830 | 0.885 / 0.872 |
| Startup `--version` tỉ lệ shell/Go | 0.088 | (sai: wall lượng tử hoá) | 0.087 | 0.081 | 0.081 |
| Startup `--version` tỉ lệ full/Go | — | — | — | — | **0.179** |
| RSS `--version` Go / shell / full (MiB) | 43.5 / (sai: floor) / — | 30.5 / (sai: floor) / — | 30.4 / 2.14 / — | 30.4 / 2.14 / — | 30.3 / 2.20 / **5.42** |
| Binary stripped Go / shell / full (MB) | — | — | — | 48.10 / 0.62 / — | 48.10 / 0.62 / **12.53** |

Đọc: số Rust ở item 4 ổn định xuyên suốt (dao động ≤6% quanh median 5
run, trừ parse-large tăng theo fixture); số Go dao động nhiều hơn theo
tải máy (MDToHTML +17% run4→run7, parse-min −23%). Tỉ lệ startup
shell/Go 0.081–0.088 ở run4–run8, nhưng rerun độc lập đo 0.109 (wall Go
nhanh hơn 23–27% dù tải cao hơn — chưa giải thích được, xem bên dưới);
thời gian tuyệt đối drift +34% (Go) và +23% (Rust) run4→run7 theo tải.
Item 5 dao động run-to-run cả hai phía (Rust 0.729–0.929) và tỉ lệ đổi
dấu (0.90–1.08) — khẳng định kết luận "trong sai số". RSS Go
`--version` **không** ổn định: bimodal theo session — 30.4 MiB ở
run5–run7, 43.5 MiB ở run4, 47.7 MiB ở rerun độc lập; tỉ lệ RSS
shell/Go dao động 0.046–0.073 theo session (xem §3). Run8 khớp run7 ở
mọi headline trong ~5% (shell `--version` wall 0.901→0.866 ms, RSS
2.14→2.20 MiB; Go 11.169→10.628 ms, 30.36→30.34 MiB) — trừ first
measured run n=1 (Go wall 12.616→51.909 ms, xem §2).

**Verify độc lập (rerun từ checkout sạch, `data/verify-rerun-summary.json`):**
ngày 2026-11-05T14:26:32Z, `sh rust/perf/run.sh` không flag, exit 0, từ
checkout sạch của head này trên cue; cùng binary hai phía (sha256 Go
`c8ea009e…`, Rust `6f270890…` giống hệt run7); loadavg 1-phút 3.47–4.05
(33 marks; run7: 0.48–1.00). Logic thuần drift trong ~10% so với run7
(Go −3.1%…+7.4%, Rust −5.4%…−0.8%), item 5 Go +0.3% / Rust −0.4%,
build 2.3 / 2.1 s, allocs <0.2%. Ngoài băng ~10%: wall startup Go nhanh
hơn 23–27% (11.169→8.192 ms `--version`, 10.771→8.306 ms `--help`) dù
tải cao gấp ~7× — ngược hướng mong đợi, chưa giải thích được; RSS Go
`--version` 30.36→47.74 MiB (+57%), status-min 32.74→48.30 MiB,
status-large 37.67→52.17 MiB, trong khi RSS Rust dao động vài %
(2.14→2.22 MiB ở `--version`, 2.83→2.85 MiB ở status-large). Tỉ lệ
startup 0.081→0.109, tỉ lệ RSS 0.071→0.046. Hướng kết luận không đổi
(Rust vẫn nhanh hơn nhiều ở mọi headline), nhưng số tuyệt đối của Go
không ổn định qua các session — xem §3.

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
- `full-bin/` — standalone Rust crate (`[workspace]` riêng, package
  `perf-full`, binary `castctl-full`): `main.rs` chép `castctl-rs`
  + `keep.rs` giữ transport+gateway sống trong binary (Tier 1 gọi
  thật + Tier 2 `#[used]` static giữ địa chỉ hàm; xem mục `rust-full`).
  Path deps `castctl-cli`/`castctl-config`/`castctl-transport`/
  `castctl-gateway`; `[patch.crates-io]` copy nguyên văn từ workspace
  chính; `[profile.release] debug = false`; `[profile.release-lto]`
  cho variant LTO. `Cargo.lock` của nó được commit để tái lập.
  Target dir của nó BẮT BUỘC ngoài repo (xem Cách chạy lại).
- `go-bench/` — Go `testing.B` bench (`ParseSingleConfig`, `MDToHTML`,
  `SplitText`, render chain) + client SOCKS5 (`TestSocks5Get`).
  File `.go` mang header SPDX GPL-3.0-or-later (bắt buộc:
  `TestSPDXHeaders` quét toàn repo).
- `fixtures/` — `config-min.json` (42 B), `config-large.json` (32,246 B,
  50 profiles + 180 outbounds + 10 endpoints, 19 protocol type, xem
  `gen_fixtures.py`), `message-long.md` (51,560 B, tổng hợp, seed
  20261105), `body-1024.bin` (1024 B), `gen_fixtures.py` (generator
  deterministic — chạy lại để tái tạo fixture).
- `data/` — số thô các lần chạy (run8 là số trong bảng trên;
  `run8-stdout.txt` là stdout thật của run8; `run7-summary.json` là
  summary đầy đủ của run7 để đối chiếu bảng Drift;
  `run5-summary.json` / `run6-summary.json` là summary đầy đủ của
  run5/run6; `verify-rerun-summary.json` là summary đầy đủ của rerun
  độc lập (2026-11-05T14:26:32Z) để đối chiếu drift).

## Chưa kiểm chứng / giới hạn (ghi rõ, không giấu)

- Cold cache thật (drop_caches): không đo — VM dùng chung, M4b đang chạy
  trên cue; chỉ có first measured run N=1 (warmup=0, sau probe).
- `perf` không có trên cue (không có `linux-tools` cho kernel 6.18.38+);
  hotspot 1–3 dựa trên breakdown số đo (decode vs parse, hàm vs hàm)
  và lý do cấu trúc, KHÔNG dựa trên CPU profile.
- Rust chưa có số allocation/op tương đương Go `ReportAllocs`.
- Item 5 đo harness hand-roll, không phải outbound/gateway thật.
- So sánh kích thước binary mang caveat M7 (xem đầu tài liệu):
  rust-full vẫn thiếu bot+keeper+webui, dùng honk thay sing-box.
- Số RSS Go `--version` bimodal theo session: 30.4 MiB (run5–run8) vs
  43.5 MiB (run4) vs 47.7 MiB (rerun độc lập,
  `data/verify-rerun-summary.json`); nguyên nhân chưa rõ (giả thuyết
  THP chưa kiểm chứng — `AnonHugePages` 0 kB lúc probe; env cô lập
  không phải nguyên nhân theo probe của verifier). Số RSS Go trong
  bảng là số run8 (mode thấp); tỉ lệ RSS rust-full/Go theo session
  dao động (run8: 0.179; mode cao Go 47.7 MiB → ~0.114). Wall startup
  Go cũng drift −23…−27% ở rerun độc lập dưới tải cao hơn — chưa giải
  thích được.
- First measured run run8 (n=1): wall cao bất thường ở cả ba phía so
  với median (Go 4.9×, shell 3.3×, full 1.8×) — cơ chế có thể là page
  cache bị build full-bin đẩy ra, chưa chứng minh; không dùng làm kết
  luận.
- Hyper client machinery: rust-full KHÔNG chứa state machine client
  của hyper (0 symbol trong `nm` — xem mục `rust-full`); binary là
  lower bound của binary M7 ở đúng chỗ này.
- Kiểm tra `nm` trên binary LTO không chạy trực tiếp được (profile
  strip symbols); giữ-link ở LTO chỉ được chứng minh gián tiếp qua
  `.text` + cơ chế `#[used]` static (xem mục `rust-full`).
- Run5/run6 được commit ở `data/run5-summary.json` /
  `data/run6-summary.json` để đối chiếu drift; run7 ở
  `data/run7-summary.json`; rerun độc lập được commit ở
  `data/verify-rerun-summary.json`; chỉ run8 là baseline chính thức.
