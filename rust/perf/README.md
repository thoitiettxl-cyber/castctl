# M-perf-2 — Go vs Rust performance baseline (measurement only)

Baseline hiệu năng Go `castctl` 0.9.0 vs Rust `castctl-rs`
(M4b CLI surface: auth + 13 commands, link cả transport/honk +
gateway) và Rust `castctl-full` (CLI + config + transport/honk +
gateway), đo trên cue ngày 2026-11-05. **Không tối ưu code** — chỉ
đo; mọi đề xuất tối ưu nằm ở mục Hotspot bên dưới và đều kèm số.

Số trong tài liệu này là **run9** (`2026-11-05T18:19:48Z`, full rerun,
commit `740e2dc`, xem mục Drift bên dưới). Run8
(`2026-11-05T15:23:14Z`, commit `3c45bfe`, trước rebase lên `dev-rust`
`27a0eaf`) đã được archive byte-identical ở `data/run8-summary.json`
(md5 `90730fd5a0b1265097c27d54d1eefe88`) trước khi rerun ghi đè các
file per-item; cột Drift trace về file đó. Run7
(`2026-11-05T12:15:19Z`) ở `data/run7-summary.json` (md5
`c449440cb768a629956a8c410ec1e4ae`). Số RSS Rust của run4 (commit
`7f46964`, 13.2 MiB) là SAI — đó là floor của tiến trình Python cha
(`ru_maxrss` từ `wait4` kế thừa qua fork, đã chứng minh bằng probe)
— nên toàn bộ số RSS run4 đã bị thay bằng run7. Wall-clock của run4
thì ĐÚNG: driver run4 dùng `os.wait4` blocking (không có vòng poll
nào), và Rust `--version` 0.686–0.831 ms không thể ra từ lưới 5 ms —
wall drift run4→run7 (+34% Go / +23% Rust) là drift theo tải, tỉ lệ
0.081–0.088 trong cửa sổ run4–run7 (rerun độc lập đo 0.109, xem mục
Drift). Vòng poll WNOHANG gây lượng tử hoá 5 ms chỉ xuất hiện ở
driver trung gian của fix loop 1 (run5, Rust `--version` median
5.448 ms), không phải phương pháp của run4; các vấn đề phương pháp do
probe trong fix loop 1 phát hiện, không phải review vòng 1 (review
vòng 1 đã kiểm chứng số run4 là đúng). Run6 dùng target dir còn ấm
nên thời gian build của nó không phải full build. Run7 là lần chạy
đầy đủ đầu tiên sau khi sửa lỗi RSS (backend GNU time) và loại vòng
poll WNOHANG; run8 giữ nguyên phương pháp đó và thêm cột thứ ba
`rust-full` (xem mục `rust-full` bên dưới); run9 giữ nguyên phương
pháp đó, chỉ khác cây source (sau rebase M4b) và tải máy lúc đo
(loadavg ~10–11, xem mục Drift — wall-clock run9 bị thổi phồng, RSS
và logic thuần ổn định).

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

## Vì sao có run9 (M-perf-2): số run8 mô tả cây source cũ

Boss rebuild PR #66 ở head `3ba3d6a` trên cue, đúng lệnh README, và
headline size KHÔNG tái lập: ông đo được 17,481,032 B (sha
`7f816189…`) trong khi README ghi 12,527,080 B (sha `b8aee622…`) —
lệch +4,954 KB (+39%). Chẩn đoán của Boss đúng: run8 đo ở commit
`3c45bfe`, tức TRƯỚC khi rebase lên `dev-rust` `27a0eaf` (M4b merge:
CLI auth + 13 commands, ~11k dòng). Rebase nằm trong `3ba3d6a` nên
bảng run8 mô tả cây cũ. Đây là lần thứ hai lỗi "số cũ, cây mới" xảy
ra (lần đầu Boss bắt ở run7) — run9 sửa bằng cách đo lại TOÀN BỘ ở
head mới và ghi commit sha vào `summary.json` (driver nay ghi
`summary["commit"]` = `git rev-parse HEAD` lúc bắt đầu chạy, và
`summary["items"]["pure_logic"]["rust_bench_binary"]` = size+sha256
của binary bench — hai field này trước đây không có ở đâu).

Run9 xác nhận chẩn đoán: shell stripped 17,446,696 B (run8: 620,968 B
— lớn hơn 28.1×, vì M4b link cả auth + transport/honk/boring-sys
vào `castctl-rs`), full stripped 17,481,032 B — SIZE BẰNG CHÍNH XÁC
số Boss đo, sha `b12911a5…` (khác sha của Boss vì target dir khác:
`/tmp/perf-full-target` so với `/root/v66b-target` của ông — xem mục
`rust-full`, phần tái lập sha). Tỉ lệ headline từ run9 là 0.363×
(2.75× nhỏ hơn), KHÔNG phải 0.260× (3.84×) của run8. Số run8 giữ
nguyên trong mục Drift (commit `3c45bfe`, lý do pre-rebase) — không
xoá, không sửa tay.

Hai thay đổi driver khác ở run9 (cùng commit `740e2dc`): (1) lock
commit riêng `c5b1dd9` trước đó — regenerate cả hai `Cargo.lock` bằng
cargo (mechanical, +18/+25 dòng, 0 removals) vì cả hai lock commit
đều stale sau M4b (driver truyền `--locked` nên `run.sh` fail ở b1
nếu không regen; full-bin lock regen byte-identical với lock Boss đã
tự regen lúc rebuild — md5 `f3d74ba6…` cả hai); (2) `summary.json`
của run9 KHÔNG còn key `rust_full_binary_after_lto_restore` (key này
có trong summary run8, cùng size+sha với `rust_full_binary`, mà
driver code không sinh ra được — artifact của driver lúc chạy run8;
ghi ở đây để khỏi ai tưởng run9 làm mất dữ liệu).

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
  `summary.json: machine.full_target_dir`) — driver từ chối target dir
  trong repo ngay lúc khởi động (`_check_full_target_outside_repo`
  trong `measure_all.py`), không chỉ ghi trong tài liệu: build full-bin
  biên dịch boring-sys, sinh file `.go` dưới target dir; `TestSPDXHeaders` walk
  toàn repo chỉ skip thư mục dot nên target dir trong repo sẽ làm FAIL
  check SPDX chạy cuối `run.sh`. Run9 dùng `/tmp/perf-full-target`
  (cold, 1.1 GiB lúc xong cho một lần build strip; 2.2 GiB sau cả dãy
  b3→b4→b5+LTO) vì `CARGO_TARGET_DIR` không set; shell build
  dùng `rust/target` trong cây cue. Run7 dùng
  `CARGO_TARGET_DIR=/dev/shm/perf0-target` vì đĩa `/` của cue lúc đó đã
  99% đầy (850 MB trống theo `df_root` trong `summary.json`, session M4b
  đang build song song); target dir ~41 MiB (delta trống trên /dev/shm:
  7.82→7.78 GiB), dọn sau khi chạy xong.
- Disk preflight: driver fail sớm nếu `/` (hoặc filesystem của
  `CARGO_TARGET_DIR`) dưới 1.0 GiB trống, và nếu filesystem của
  full-target dưới 2.0 GiB trống (M-perf-1: closure full ~1.1 GiB
  target dir lúc probe, gấp ~40× shell). Run9: `/` 9.69 GiB trước →
  8.73 GiB sau (target full + shell target). Giữa run9 và lúc viết
  lại bảng này, đĩa cue dao động mạnh (96% rồi 76% — các session khác
  build/dọn song song; Boss đã tự dọn các target dir cũ một lần, xem
  mục Drift) — luôn `df` trước khi rerun.
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
  của run9 được commit ở `data/run9-stdout.txt` (xem mục Output bên dưới;
  run8 giữ ở `data/run8-stdout.txt`).
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
  fail run): run8 in `SPDX check: PASS`; **run9 in `SPDX check: FAIL`
  (644 file `.go` thiếu header — 322 dưới `rust/target/release/`
  do rerun b1/b2 tạo + 322 dưới `rust/target/debug/` do session khác
  tạo; workspace closure giờ chứa boring-sys sau M4b nên bẫy này là
  mặc định, không phải ngoại lệ)**. Không file `.go` nào trong số đó
  được track (`git ls-files | grep '\.go$'` = 481 file repo, tất cả có
  header) — gate SPDX chính thức phải chạy trên checkout sạch TRƯỚC
  mọi workspace build.

## Điều kiện đo (run9, 2026-11-05T18:19:48Z, commit `740e2dc`)

- Máy: cue, `Linux 6.18.38+ x86_64`, 8 × Intel Xeon @ 2.50GHz,
  MemTotal 24,788,940 kB (23.6 GiB), SwapTotal 0 kB (ghi trong
  `summary.json: machine.meminfo`), loadavg 1-phút 4.79 lúc bắt đầu,
  7.21 giữa chừng, 18.05 lúc kết thúc (cao hơn run8 2.24–7.73 — build
  full-bin biên dịch ~350 crate song song CỘNG các session khác đang
  build/test song song trên cue, trong đó có một test binary M5a chạy
  196% CPU / 15.8G RSS; cộng 45 mark loadavg + timestamp trước/sau
  từng item và từng phía trong `summary.json: marks`). Đĩa `/` 9.69 GiB
  trống lúc bắt đầu, 8.73 GiB lúc kết thúc; build outputs: shell trên
  `rust/target`, full trên `/tmp/perf-full-target` (cold —
  `full_target_cold: true` trong summary). **Tải này làm wall-clock
  run9 phồng lên so với run8 (xem mục Drift); RSS và logic thuần
  không bị ảnh hưởng đáng kể.**
- Go: `/usr/local/bin/castctl` 0.9.0 (`1396697 2026-11-04T21:38:36Z`),
  48,100,296 B, sha256 `c8ea009e…` (cùng binary với run7/run8).
  `go version -m` (ghi đầy đủ trong `summary.json:
  machine.go_binary_build_info`):
  `-buildmode=exe`, tags `with_utls,with_quic,with_wireguard,
  with_gvisor`, `-trimpath=true`, `CGO_ENABLED=1`, `GOARCH=amd64`.
  Output `go version -m` KHÔNG có dòng `-ldflags` nào nên tài liệu này
  không claim `-s -w` (claim đó ở run4 không có nguồn trong data).
  Go toolchain 1.27.3.
- Rust shell: `castctl-rs` build từ head `740e2dc` trên nhánh này
  (sau rebase lên `dev-rust` `27a0eaf`, M4b đã merge),
  `cargo +1.99.1 build --release --locked -p castctl-rs`,
  `RUSTFLAGS="-C strip=symbols"` (số chính); build thường 187.4 s,
  build strip 189.4 s (full build, target dir lạnh — chậm hơn run8
  2.4/2.1 s vì closure giờ chứa cả transport/honk/boring-sys, không
  còn stdlib-only, và vì tải máy lúc build).
- Rust full: `castctl-full` build từ `rust/perf/full-bin/` (standalone
  crate, `[workspace]` riêng, path deps `castctl-cli` +
  `castctl-config` + `castctl-transport` + `castctl-gateway`,
  `[patch.crates-io]` copy nguyên văn từ workspace chính),
  `cargo +1.99.1 build --release --locked --offline --manifest-path
  rust/perf/full-bin/Cargo.toml`, `RUSTFLAGS="-C strip=symbols"`
  (số chính); build thường 191.2 s, no-keep 217.8 s, strip 1.2 s
  (target dir lạnh `/tmp/perf-full-target`; mỗi lần đổi RUSTFLAGS là
  rebuild lại closure ~3 phút — đo được, không phải ước). Xem chi tiết
  linkage ở mục `rust-full` bên dưới. LTO build của driver ở run9
  exit 101 sau 207.3 s — KHÔNG phải lỗi build: `/tmp/perf-full-target`
  bị Boss xoá giữa lúc build đang chạy (dọn disk lúc cue lên 95%;
  stderr ghi rõ lỗi `.o.d` của boring-sys cmake — xem
  `summary.json: build_full_lto`); retry tay sau đó exit 0, xem mục
  `rust-full`.
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
Lưu ý: `HonkDialer::new` gọi `ProxyRegistry::default_resolver()` trong
crate honk (source ngoài, không đọc trực tiếp) và `tokio::runtime::Builder`
chỉ build rồi drop sau env guard — hai hành vi này được kiểm chứng gián
tiếp (unit test offline của transport crate gọi `HonkDialer::new`, và
`keep_linked()` không bao giờ chạy lúc đo), không phải bằng đọc source.

### Chứng minh linkage (run9, trên cue, 2026-11-05 — sau rebase M4b)

(a) **Size A/B, stripped** (`RUSTFLAGS="-C strip=symbols"`, GNU strip
đối chiếu trong ngoặc): shell 17,446,696 B (17,446,688) → full
**không-keep** (`--no-default-features`) 17,446,536 B → full **keep**
17,481,032 B (17,481,024). **A/B nay đo khác run8:** shell M4b đã
link sẵn toàn bộ closure (auth + transport/honk + gateway) nên thêm
deps mà không keep chỉ đổi −160 B (full no-keep NHỎ hơn shell 160 B —
hai `main` khác nhau, mức nhiễu); bật `keep-linked` thì to thêm
**34,496 B** so với no-keep. Cơ chế giữ-link vẫn hoạt động (xem (b):
các root Tier 1/2 có mặt trong binary keep, vắng trong no-keep), nhưng
con số 20.17× của run8 không còn ý nghĩa — nó đo "shell M2 chưa link
gì" so với "full keep", còn run9 đo "keep root giữ thêm bao nhiêu"
trên nền closure đã link sẵn. Unstripped: shell 23,210,896 B, full
no-keep 23,210,528 B, full keep 23,255,696 B (kích thước + sha256 của
cả ba ghi trong `data/nm-counts.json`). `.text`/`.rodata` (stripped):
shell 11,104,060 / 2,251,952 B; full keep 11,129,372 / 2,251,944 B.

(b) **Bảng `nm`** (đếm symbol chứa chuỗi, trên binary **chưa strip**;
`nm` trên binary đã strip trả về rỗng nên không dùng được — lỗi phương
pháp đã gặp một lần trong lúc probe; và pattern phải là chuỗi trần,
không phải `castctl_transport::`, vì symbol Rust đã mangle). Số đếm đầy
đủ, kèm binary size/sha và lệnh build, ghi trong
`data/nm-counts.json` (run9, trên cue, 2026-11-05); bảng dưới đây trích
từ file đó. Chú ý: shell run9 CHỨA transport/gateway (M4b) nên cột
shell không còn là 0 — so sánh đúng là keep vs no-keep (delta nhỏ:
transport +8, gateway +2, honk +2, tokio +7, snow +5):

| Chuỗi | shell (M4b) | full no-keep | full keep (run9) |
|---|---|---|---|
| `castctl_transport` | 760 | 760 | **768** |
| `castctl_gateway` | 725 | 725 | **727** |
| `honk_outbound` | 9,538 | 9,538 | **9,540** |
| `boringtun` | 98 | 98 | **98** |
| `smoltcp` | 185 | 185 | **185** |
| `tokio` | 4,466 | 4,466 | **4,473** |
| `prost` | 46 | 46 | **46** |
| `tungstenite` | 510 | 510 | **510** |
| `snow` | 129 | 129 | **134** |
| `hyper` | 537 | 537 | **537** |

Tổng dòng `nm`: keep 50,917; shell 50,835; no-keep 50,834.
No-keep đếm Y HỆT shell (mọi chuỗi) — đúng như kỳ vọng: no-keep là
shell qua một `main` khác, cùng closure. Keep hơn no-keep ở đúng các
root Tier 1/2 (xem dưới).

Symbol riêng lẻ trong full keep (cùng phương pháp đếm chuỗi như bảng):
`dispatch_outbound` 2, `ensure_tunnel` 1, `KEEP_TIER2` 1, `HonkDialer` 7,
`WireGuardDialer` 16 (gồm cả symbol global và local — monomorphization
của `dial`/`dial_inner` và drop-glue),
`HttpClient` 114 (constructor `new` nay KHÔNG bị inline hết như run8 —
M4b đổi codegen; 113 trong shell/no-keep, 114 trong keep: root Tier-2
giữ thêm đúng 1),
`RpcClient` 1 (0 trong shell/no-keep — root Tier-2 giữ thêm),
`DownTracker` 1 (1 trong shell/no-keep).

(c) **Patch check:** `cargo tree -i boring-sys` /
`cargo tree -i quinn` đều trỏ về git Glassyiris
(`boring-sys rev 3beb573…`, `quinn rev 11f1de84…`,
`honk rev 9e31cc0…`); `full-bin/Cargo.lock` (355 package, lock
regenerate ở commit `c5b1dd9`, chứa đúng các rev đó).

(d) **Hành vi** (ghi trong `data/behaviour-checks.json`, run9, binary
mới): `castctl-full --version` → `castctl 0.9.0`, exit 0;
`--help` byte-identical với shell (`cmp` pass — cùng sha256
`cc65698a…`, GIỐNG run8: M4b thêm 13 subcommand nhưng top-level help
không đổi); `--version=x` → stderr + exit 2;
`PERF_KEEP_LINKED=1 --version` in giống hệt, exit 0.

### Hai điều probe chứng minh là SAI, và một khoảng trống đã công bố

- **Address-taking + `black_box` KHÔNG giữ được code.** Probe trên
  cue: build chỉ có Tier 2 dạng này cho ra binary không đổi kích
  thước/nm — compiler loại bỏ (số trung gian của probe này không được
  giữ lại nên không trích con số ở đây; hai con số trung gian từng ghi
  ở bản trước — 16,272,088 B và +543,384 B — đã bị gỡ vì cộng lại lệch
  4,096 B so với kích thước unstripped đã commit). Chỉ `#[used]` static
  chứa địa chỉ hàm mới giữ được (Tier 2 hiện tại) — số đếm `nm` đầy đủ
  của binary keep ghi trong `data/nm-counts.json` (xem (b)). Lịch sử
  này ghi trong `keep.rs` để lần sau khỏi thử lại cách đã fail.
- **LTO qua `RUSTFLAGS -C lto` KHÔNG build được closure này.** Run8
  fail trong 0.5 s (`options '-C embed-bitcode=no' and '-C lto' are
  incompatible`); sửa thêm `-C embed-bitcode=yes` thì fail tiếp
  (`lto cannot be used for 'proc-macro' crate type without
  '-Zdylib-lto'` trên `zeroize_derive`/`serde_derive` — flag áp cho
  mọi crate kể cả proc-macro). LTO đúng phải qua profile
  (`[profile.release-lto]`, `inherits = "release"`, `lto = "fat"`,
  `strip = "symbols"` trong `full-bin/Cargo.toml`) — profile form bỏ
  qua proc-macro. Build tay trên cue sau run8 với profile này:
  exit 0, 4m 32s, 10,065,944 B (xem hàng LTO ở §1). Fix loop 1 rebuild
  lại variant này bằng đúng lệnh profile-form (record đầy đủ trong
  `data/lto-build-record.json`): size 10,065,944 B và `.text`
  6,942,120 B khớp y prose. Driver đã đổi sang profile form để rerun
  sau tái lập được; `summary.json` của run8 vẫn ghi đúng lần fail gốc
  (`build_full_lto`, exit 101). **Run9:** driver LTO exit 101 sau
  207.3 s — không phải lỗi RUSTFLAGS mà do target dir bị xoá giữa
  build (xem Điều kiện đo); retry tay bằng đúng lệnh profile-form
  exit 0 sau 315 s: 14,197,080 B, sha `c985a9aa…`, `.text` 9,695,132 B
  (record đầy đủ trong `data/lto-build-record.json` — đã viết lại cho
  run9). Hàng LTO run9 ở §1 là số retry tay, không phải phép đo
  driver; `summary.json` của run9 vẫn ghi đúng lần fail gốc
  (`build_full_lto`, exit 101).
- **Khoảng trống đã công bố ở run8 nay ĐÃ ĐÓNG: hyper client machinery.**
  Run8: hyper 0 symbol trong `nm` — entry `HttpClient::request`
  trong `#[used]` static không giữ được hyper (địa chỉ của một `async
  fn` chỉ giữ constructor của future, không giữ code `poll`). Run9:
  hyper **537 symbol** trong CẢ BA binary (keep/shell/no-keep) —
  M4b link hyper vào `castctl-cli` qua transport/gateway deps nên
  closure đã chứa hyper machinery mà không cần root nào giữ. Rust-full
  KHÔNG còn là lower bound của binary M7 ở chỗ này; câu "lower bound"
  của run8 bị thu hồi cho run9. (Phần còn lại của phân tích run8 vẫn
  đúng: root Tier-2 giữ địa chỉ `async fn` chỉ giữ constructor —
  nhưng ở head mới, hyper đã vào binary bằng đường khác.)
- **Khoảng trống đã công bố: hyper client machinery (0 symbol).**
  Entry `HttpClient::request` trong `#[used]` static KHÔNG giữ được
  hyper: địa chỉ của một `async fn` chỉ giữ constructor của future,
  không giữ code `poll` điều khiển hyper — mà poll nó thì cần I/O
  thật, điều không root nào được làm. Nên rust-full là **lower bound**
  của binary M7 ở đúng một chỗ này: nó chứa `HttpClient::new` +
  type `http::Request/Response` nhưng không chứa state machine client
  của hyper. Không phóng đại, không giấu.

### Tái lập sha (run9 — 5 check thực nghiệm, R1 §6)

Sha của binary keep phụ thuộc vào **cả hai path**: target dir và
checkout (source path). Kích thước thì KHÔNG phụ thuộc vào path nào
trong hai — 17,481,032 B ở mọi lần build dưới đây, mọi section size
đều giống hệt nhau (so `size -A` keep vs build target-dir khác: chỉ
khác dòng tên file).

- **(4e) Reproduce check (pinned path):** 4 dòng trong mục Reproduce
  check bên dưới, chạy verbatim trên target dir ấm (trạng thái sau
  `run.sh`), tái lập đúng 17,481,032 B + sha `b12911a5…` (chỉ relink
  0.39 s). Đây là check chính thức của bảng.
- **(4d) Cold vs warm, cùng path:** `rm -rf /tmp/perf-full-target`
  rồi single build (`RUSTFLAGS="-C strip=symbols"`, cùng manifest)
  → 17,481,032 B, sha `b12911a5…` (3m47s) — Y HỆT dãy warm b3→b4→b5
  của run9. Cold-vs-warm không ảnh hưởng sha.
- **(4a) Rebuild dãy b3→b4→b5** bằng đúng lệnh driver, sau khi
  `/tmp/perf-full-target` bị xoá → headline 17,481,032 B, sha
  `b12911a5…`; plain 23,255,696 B (`55c4bdae…`), plain-gnu 17,481,024 B
  (`201ff340…`), nokeep 17,446,536 B (`9b6c28ed…`). Ba lần build độc
  lập (run9 b5, rebuild tay, cold single, warm-restore retry) cho cùng
  một sha — sha pinned-path tái lập được 4 lần độc lập.
- **(4c) Checkout khác, cùng target dir:** cold single build từ
  checkout khác `/tmp/perf2-alt-checkout` (cùng source 740e2dc) vào
  cùng `/tmp/perf-full-target` → 17,481,032 B, sha **`f7f898e5…`**
  (3m27s). Size giống, sha khác. Cơ chế đã chứng minh: binary chứa 19
  chuỗi `file!()` là absolute path source
  (`/tmp/<checkout>/rust/<crate>/src/*.rs`) và 1 chuỗi `include!`
  build-script `.../castctl-gateway-<metadata-hash>/out/hatch.noise.rs`
  (hash `1d46a2198ebe64b2` ở checkout chính vs `f025442179c6a57f` ở
  checkout alt — cargo metadata hash ăn theo checkout path cho path
  dep); `cmp` hai binary: 1,316,541 byte khác (7.5%), tập trung ở
  `.text`/`.rodata` (layout/địa chỉ đổi theo hash). Hai checkout có
  prefix dài bằng nhau (23 ký tự) nên size bằng nhau. Ngược lại,
  `boring-sys-<hash>` giống nhau ở cả hai binary (registry dep — hash
  không ăn theo checkout) nên 145 chuỗi `__FILE__` BoringSSL
  byte-identical; `hatch.noise.rs` và `bindings.rs` sinh ra cũng
  byte-identical (so sha256 trực tiếp).
- **(4b) Target dir của Boss, checkout chính:** lệnh y hệt Boss
  (`CARGO_TARGET_DIR=/root/v66b-target`, fresh dir, checkout
  `/tmp/castctl-rust-perf1`) → 17,481,032 B, sha **`7f816189…`** —
  KHỚP CHÍNH XÁC sha Boss đo (build 3m47s). Nhưng: bản copy giữ lại
  sau đó cho sha **`b2961462…`** (size vẫn 17,481,032 B; strings vẫn
  nhất quán: 146× `v66b-target`, 19× `castctl-rust-perf1`, gateway
  hash `1d46a2198ebe64b2`), và rebuild lạnh lặp lại từ cùng inputs cho
  `b2961462…` lần nữa (hai lần độc lập). Source (HEAD 740e2dc,
  working tree sạch ngoài file data run9), toolchain (cargo/rustc
  1.99.1, cùng commit hash như run9 ghi), và output build-script đều
  đã verify giống hệt nhau — **nguyên nhân đổi sha chưa rõ** (ứng
  viên: một session khác rebuild đè vào cùng target dir trong lúc đĩa
  cue ở 99% và tải cao; hoặc một input nondeterministic chưa xác
  định). Hệ quả thực dụng: **sha ở target dir `/root/v66b-target`
  không ổn định theo thời gian, không dùng làm cross-check**; chỉ sha
  ở pinned path `/tmp/perf-full-target` (tái lập 4 lần độc lập: run9
  b5, rebuild tay b3→b4→b5, cold single (4d), warm-restore retry
  b3→b4→b5 sau build (4c) — lần retry này tái lập cả 4 sha: headline
  `b12911a5…`, plain `55c4bdae…`, plain-gnu `201ff340…`, nokeep
  `9b6c28ed…`) mới dùng được. Size 17,481,032 B thì ổn định ở mọi path và mọi lần
  build — đó là cross-check bền. (Dự đoán cũ "+435 B vì path dài hơn
  3 ký tự × 145 chuỗi" là SAI: so `size -A` trực tiếp cho thấy mọi
  section giống hệt nhau giữa hai target dir dù tổng độ dài chuỗi
  target-path chênh 584 B — cơ chế bù trừ chưa rõ, chỉ ghi là quan
  sát.)

Lịch sử run8 (giữ để đối chiếu): rebuild từ source fc250db với tên
target dir khác (`/tmp/perf-fix1-target`) cho cùng size, sha khác
(unstripped `687af3f7…` ≠ run8 `2809a25f…`, stripped `57e48df3…` ≠
`b8aee622…`, LTO `8c737840…` ≠ `8040a0c6…`); rebuild với đúng tên
target dir của run8 (`/tmp/perf-full-target`) khớp cả ba sha. Số liệu
đầy đủ trong `data/nm-counts.json` (`comparison_vs_committed_run8`,
`sha_mismatch_explanation`, `byte_reproduction_check`) và
`data/lto-build-record.json` — các file này nay là record của run8,
record run9 nằm trong cùng file ở mục mới (xem `nm-counts.json`
phiên bản run9).

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
  `.text` 9,695,132 B (so với no-keep 11,103,948 B và primary
  11,129,372 B) — closure đầy đủ vẫn còn đó, chỉ co lại 12.9% do LTO —
  cộng với cơ chế `#[used]` static giữ hàm có địa chỉ + các callee
  truyền của nó sống qua LTO theo construction (linker không thể drop
  hàm mà địa chỉ của nó nằm trong static được giữ). Đây là điểm lệch
  so với kế hoạch gốc (kế hoạch đòi nm cả hai variant); ghi rõ ở đây
  thay vì giả vờ đã nm. `.text` LTO nay có record:
  `data/lto-build-record.json` (run9: 14,197,080 B, `.text`
  9,695,132 B).

### Reproduce check (run9 — đúng 4 dòng, checkout + target dir đều pin)

Chạy 4 dòng dưới đây, verbatim, trên cue, từ checkout đã đo run9
(`/tmp/castctl-rust-perf1`, head `740e2dc`):

```sh
cd /tmp/castctl-rust-perf1 && git rev-parse HEAD
RUSTFLAGS="-C strip=symbols" CARGO_TARGET_DIR=/tmp/perf-full-target cargo +1.99.1 build --release --locked --offline --manifest-path rust/perf/full-bin/Cargo.toml
stat -c "%s %n" /tmp/perf-full-target/release/castctl-full
sha256sum /tmp/perf-full-target/release/castctl-full
```

Kết quả kỳ vọng: commit `740e2dc19322c00c081d5c9dc0d7ca7ad8b762b6`,
size **17,481,032 B**, sha256
`b12911a545f530b837d375a0f07f167580e91e2206c2445b4d7e903ae13e002f`.
Đã verify: 4 dòng này trên target dir ấm tái lập đúng size+sha
(relink 0.39 s lúc đầu, 0.36 s khi chạy lại sau warm restore);
cold single build (`rm -rf` target dir trước) cũng tái lập đúng
size+sha; rebuild dãy b3→b4→b5 cũng vậy, hai lần độc lập (rebuild
tay và warm-restore retry — lần retry tái lập cả 4 sha) (xem "Tái
lập sha" bên trên).

**Nếu sha khác → bảng đã cũ, phải đo lại chứ không được sửa số tay.**
Câu này áp cho đúng 4 dòng trên (checkout `/tmp/castctl-rust-perf1`
+ target dir `/tmp/perf-full-target`). Build từ checkout khác hoặc
target dir khác sẽ ra sha khác dù size vẫn 17,481,032 B — đó là hành
vi đã chứng minh (xem (4b)/(4c) bên trên), không phải dấu hiệu bảng
cũ; size mới là cross-check bền qua mọi path. Ngược lại, nếu 4 dòng
trên cho size khác 17,481,032 B thì bảng chắc chắn đã cũ.

## Bảng số (run9)

Quy ước: mọi ô headline kèm `median (min–max), N=20` (trừ hàng n=1).
Tỉ lệ headline LUÔN là `rust-full/go`. Cột `rust-shell/go` mang nhãn
tham chiếu — shell M4b nay gần như cùng closure với full (chênh
34,336 B stripped) nên cột shell không còn là "binary nhỏ không so
được" như run8, nhưng quy ước giữ nguyên: kết luận chỉ nói về
rust-full. Mọi bảng trong mục này mô tả run9 (commit `740e2dc`,
`2026-11-05T18:19:48Z`); số run8 xem mục Drift.

### 1. Kích thước binary

| | Go (full) | Rust shell (M2, tham chiếu) | Rust full (transport+gateway) | Rust-full/Go | Rust-shell/Go (tham chiếu) |
|---|---|---|---|---|---|
| Stripped (`-C strip=symbols`) | 48,100,296 B (45.87 MiB) | 17,446,696 B (16.64 MiB) | **17,481,032 B (16.67 MiB)** | **0.363 (2.75× nhỏ hơn)** | 0.363 |
| Chưa strip | — | 23,210,896 B | 23,255,696 B | 0.483 | 0.483 |
| GNU strip (đối chiếu) | — | 17,446,688 B (chênh 8 B) | 17,481,024 B (chênh 8 B) | — | — |
| `.text` | 21,017,769 B | 11,104,060 B | 11,129,372 B | 0.529 | 0.528 |
| `.rodata` | 2,644,352 B | 2,251,952 B | 2,251,944 B | 0.852 | 0.852 |
| A/B no-keep, stripped | — | — | 17,446,536 B (delta keep +34,496 B) | — | — |
| LTO variant, stripped (`release-lto`) * | — | — | 14,197,080 B (nhỏ hơn headline 18.8%) | 0.295 | — |

`sha256`: Go `c8ea009e…`, shell stripped `95d9be12…`, full stripped
`b12911a5…`, full no-keep `9b6c28ed…`, full LTO `c985a9aa…`, bench
binary `c8832c18…` (3,178,400 B — ghi trong `summary.json:
items.pure_logic.rust_bench_binary`). Hàng LTO (*): retry tay trên cue
sau run9 (`--profile release-lto`, 315 s, `--version` exit 0), cùng
source với run9; record đầy đủ trong `data/lto-build-record.json`;
`summary.json` của run9 chỉ ghi lần build LTO gốc fail exit 101
(207.3 s, target dir bị xoá giữa build — xem Điều kiện đo). Hàng
"Chưa strip" tính tỉ lệ trên Go stripped (không có Go unstripped).
Hàng LTO không dùng cho tỉ lệ headline.

### 2. Startup (wall-clock, N=20, warmup 5)

| Lệnh | Go median (min–max) ms | Rust shell median (min–max) ms (tham chiếu) | Rust full median (min–max) ms | Rust-full/Go | Rust-shell/Go (tham chiếu) |
|---|---|---|---|---|---|
| `--version` | 23.236 (16.629–29.925) | 5.505 (2.355–7.096) | **5.619 (4.371–8.037)** | **0.242 (4.14× nhanh hơn)** | 0.237 |
| `--help` | 9.201 (8.722–19.879) | 1.912 (1.817–2.446) | **1.889 (1.733–2.072)** | **0.205 (4.87× nhanh hơn)** | 0.208 |
| First measured run, warmup=0, sau probe `--version` (KHÔNG cold, KHÔNG sau build), N=1 `--version` — **n=1, không dùng làm kết luận** | 65.893 | 21.079 | 10.288 | 0.156 | 0.320 |

Đối chiếu hyperfine 1.18.0 (N=20, median, 3 lệnh trong MỘT invocation):
`--version` Go 10.7 ms vs shell 2.31 ms vs **full 7.1 ms**
(full/Go 0.66; full mean 6.1, min 2.43, max 8.97 — phân tán rộng);
`--help` Go 16.42 ms vs shell 4.54 ms vs **full 4.33 ms**
(0.26; full mean 3.48, min 0.0, max 8.87 — min 0.0 là artifact
hyperfine, không phải số thật). **KHÔNG khớp loop Python ở run9**
(run8 khớp: driver 10.628/0.866/1.904 vs hyperfine 11.0/0.7/1.7).
Cả hai phương pháp đều đo dưới tải cao nhưng ở thời điểm khác nhau
(hyperfine chạy sau item 5, loadavg cuối 18.05); wall-clock ở thang
1–20 ms bị scheduling jitter chi phối khi loadavg ~10–18 trên 8 CPU.
Hướng kết luận không đổi (Rust full vẫn nhanh hơn Go nhiều ở cả hai
phương pháp), nhưng **tỉ lệ startup tuyệt đối của run9 là số nhiễu
theo tải** — trích kèm caveat này, và dùng RSS (§3) làm số ổn định.
Lưu ý hàng n=1: wall first-run ở run9 cao ở cả ba phía so với median
(Go 65.893 ms ≈ 2.8× median 23.236 ms; shell 3.8×; full 1.8×).
Cơ chế có thể là page cache bị build full-bin (~350 crate) đẩy ra
ngay trước khi đo — suy luận, chưa chứng minh; và vì là n=1 nên nó
không dùng làm kết luận, chỉ ghi để khỏi ai trích nhầm.

### 3. Peak RSS (GNU time, N=20) + wall `status`

| Lệnh | Go median (min–max) | Rust shell median (min–max) (tham chiếu) | Rust full median (min–max) | Rust-full/Go | Exit Go / shell / full |
|---|---|---|---|---|---|
| `--version` wall ms | 23.236 (16.629–29.925) | 5.505 (2.355–7.096) | 5.619 (4.371–8.037) | 0.242 | 0 / 0 / 0 |
| `--version` RSS MiB | 30.346 (29.660–31.277) | 6.121 (6.035–6.336) | **6.230 (6.105–6.348)** | **0.205 (79% ít hơn)** | 0 / 0 / 0 |
| `--help` wall ms | 9.201 (8.722–19.879) | 1.912 (1.817–2.446) | 1.889 (1.733–2.072) | 0.205 | 0 / 0 / 0 |
| `--help` RSS MiB | 30.314 (29.594–30.969) | 6.047 (5.859–6.168) | **6.129 (6.027–6.273)** | **0.202** | 0 / 0 / 0 |
| `status --config min` wall ms | 10.844 (10.473–12.062) | 3.511 (3.079–4.260) | 3.390 (3.151–3.889) | 0.313 | 2 / 2 / 2 |
| `status --config min` RSS MiB | 32.594 (32.027–33.898) | 8.303 (8.004–8.484) | **8.236 (7.934–8.496)** | **0.253** | 2 / 2 / 2 |
| `status --config large` wall ms | 38.329 (36.403–41.720) | 9.274 (8.891–9.852) | 9.047 (8.760–9.700) | 0.236 | 2 / 2 / 2 |
| `status --config large` RSS MiB | 38.023 (37.266–38.715) | 10.305 (9.965–10.477) | **10.020 (9.867–10.250)** | **0.264** | 2 / 2 / 2 |
| `status --config bad-JSON` wall ms | 10.154 (9.063–10.839) | 2.118 (1.815–2.189) | 2.153 (1.877–4.107) | 0.212 | 2 / 2 / 2 |
| `status --config bad-JSON` RSS MiB | 30.844 (30.031–31.406) | 6.664 (6.426–6.746) | **6.631 (6.504–6.750)** | **0.215** | 2 / 2 / 2 |

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
dừng ở parse, exit 2). **Exit code đổi so với run8:** Rust `status`
min/large ở run8 exit 1 (chạm stub chưa implement); ở run9 exit 2
(M4b đã wire `status` thật, fail như Go). Go vẫn exit 2; bad-JSON vẫn
2/2/2. RSS full tăng theo config (min 8.236 → large 10.020 MiB,
+1.78 MiB — chi phí parse thật trên closure lớn); RSS Go tăng +5.43
MiB từ min → large (32.594 → 38.023 MiB; +7.68 MiB so với `--version`
30.346 MiB). Wall-clock cũng thấy chi phí parse của full: `status`
large 9.047 ms so với min 3.390 ms; Go large 38.329 ms so với min
10.844 ms (Go large chậm hẳn vì fail ở tạo endpoint sau khi
parse+validate).

**Lịch sử số RSS (đọc kỹ trước khi trích):** số RSS Rust ở run4/run5
(13.2 MiB) là SAI — đó là floor của Python cha (xem phương pháp đo);
số đúng ở run9 là ~6.1 MiB cho shell, ~6.2 MiB cho full (run8:
~2.2/~5.4 MiB — tăng theo closure M4b). RSS Go `--version` là
**bimodal theo session** (cùng binary, cùng sha256): run4 đo 43.5 MiB,
run5/run6/run7 đều đo 30.4 MiB, còn rerun độc lập (verify,
`2026-11-05T14:26:32Z`, xem mục Drift) đo 47.7 MiB — tức 2/5 session ở
mode cao (43.5, 47.7 MiB), 3/5 ở mode thấp (30.4 MiB). Trong một session
thì số ổn định chặt (verify: 47.61–47.93 MiB trên cả 20 run; run7:
29.80–30.98 MiB; run8: 29.72–30.97 MiB; run9: 29.66–31.28 MiB). Hai phương pháp đo độc lập
đồng thuận trong session verify: GNU time 47.74 MiB và `wait4`
`maxrss_kib_raw` median 47.7 MiB, nên mode cao là thật, không phải lỗi
đo. Nguyên nhân chưa rõ — giả thuyết (chưa kiểm chứng): Go 1.27 xin
transparent huge page cho heap arena, RSS hạch toán cả page 2 MB dù
chỉ dùng một phần; tuỳ trạng thái THP/fragmentation mà số hạch toán
dao động; lúc probe `AnonHugePages` là 0 kB nên giả thuyết này không
được xác nhận cũng không bị bác bỏ. Probe với đúng env cô lập của
driver vẫn cho mode thấp (30.5–31.3 MiB, probe của verifier sau rerun,
không nằm trong summary đã commit) nên env không phải nguyên nhân.
**Hệ quả khi trích:** số RSS Go trong bảng trên là số của run9 (mode
thấp, 30.3 MiB); tỉ lệ RSS rust-full/Go dao động theo session (run9:
0.205; nếu Go ở mode cao 47.7 MiB thì tỉ lệ ~0.131), không phải một
số duy nhất. RSS Rust full ổn định ~6.2 MiB ở `--version` trong
run9; RSS shell ổn định ~6.1 MiB (run6/run7/verify ở `--version`:
2.14 / 2.14 / 2.22 MiB — số shell cũ, trước M4b).

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
| Parse config min (42 B) | 4,418 (3,842–6,200) | 2,559 (2,529–2,748) | **0.58 (1.7× nhanh hơn)** | 131,072 |
| Parse config large (32,246 B, 50 profiles + 180 outbounds + 10 endpoints) | 12,420,197 (7,007,489–12,846,301) | 1,165,842 (1,135,391–1,225,336) | **0.09 (10.6× nhanh hơn)** | 256 |
| Decode JSON large, Rust-only (`decode_ordered_object`) | — | 392,595 (384,565–424,579) | — | 1,024 |
| `MDToHTML` (message 51,560 B) | 12,111,097 (11,221,351–13,702,028) | 921,148 (876,205–961,488) | **0.08 (13.1× nhanh hơn)** | 256 |
| `SplitText` (51,560 B) | 789,801 (684,533–961,132) | 272,123 (265,070–328,551) | **0.34 (2.9× nhanh hơn)** | 1,024 |
| Render chain (`MDToHTML` + `SplitText`) | 14,411,628 (13,253,767–15,319,609) | 1,133,113 (1,085,442–1,136,528) | **0.08 (12.7× nhanh hơn)** | 256 |

`output_len` đã kiểm chứng trong raw: parse-large 50 profiles,
decode-large 4 keys, `md-to-html` 58,259 chars, `split-text` 15,
render-chain 58,277, parse-min 1. Mọi run Rust đều ≥ 200 ms total
(K dừng ở 131,072 khi total đạt ~331 ms ở parse-min; cap `1<<20`
không chạm tới).

**Cảnh báo khi đọc tỉ lệ §4 run9:** tỉ lệ cải thiện mạnh so với run8
(parse-large 0.16→0.09, MDToHTML 0.17→0.08, render 0.18→0.08) CHỦ
YẾU VÌ GO CHẬM ĐI DƯỚI TẢI, không phải vì Rust nhanh lên. Số Go run9
tăng 1.7–2.4× so với run8 (MDToHTML 5.34M→12.11M ns, render
5.99M→14.41M, parse-large 7.35M→12.42M; min của parse-large Go
7.01M ≈ median run8 — tải tăng dần giữa bench), trong khi số Rust
ổn định trong ±5% (parse-large 1.178M→1.166M, md-to-html 0.886M→
0.921M, render 1.076M→1.133M). Tỉ lệ run9 vẫn là số đo thật của run9,
nhưng đừng trích "Rust nhanh hơn 10.6×" mà không kèm caveat tải này;
so sánh công bằng nhất giữa hai run là phía Rust (ổn định) và phía
Go ở run8 (tải thấp).

**Bất đối xứng phải đọc kèm:** cùng tên hàm nhưng khác khối lượng việc.
Go `ParseSingleConfig` validate sâu toàn bộ outbound (sing-box); Rust
defer sing-box option validation (deviation D-M2-1) nên parse-large của
Rust làm ít việc hơn. Bằng chứng: Go parse-large 2,193,108 B/op +
52,155 allocs/op (median — xem `go_b_op_allocs` trong `summary.json`);
Rust decode chỉ 393 µs trong tổng parse 1,166 µs (validation+build
struct chiếm 66%). Khi Rust bổ sung validation, lợi thế parse-large sẽ
thu hẹp — đo lại sau bước đó (hotspot H4). Tương tự `MDToHTML`: Go
4,796,123 B/op + 8,354 allocs/op (median; churn chuỗi lớn); Rust dùng
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
| SOCKS5 GET loopback | 0.948 (0.816–2.280) | 3.973 (1.317–3.999) | **4.19 (Rust chậm hơn 4.19×)** |

Setup (spawn + verify hai server) hết 1.5 s; đo 13.1 s; tổng 14.6 s
(trong hạn 20 phút). Thứ tự chạy: Rust trước (5 lượt), rồi Go (5 lượt),
adjacent batches. **Đảo chiều so với run8** (khi đó 0.885 vs 0.872,
tỉ lệ 0.99, trong sai số): phía Rust run9 là 3.973 ms/req — lượt đầu
1.317 ms rồi bốn lượt sau plateau ở 3.964–3.999 ms (dao động chỉ
±0.5%). Loadavg lúc đo item 5 là 11.39 cho CẢ hai phía (marks
`before/after_item5_*` cùng một giây cho lượt Rust, 13 s cho lượt
Go) nên tải KHÔNG giải thích được chênh lệch. Nguyên nhân chưa rõ —
chưa kiểm chứng: có thể là hồi quy thật ở phía Rust sau M4b (bench
binary nay link closure lớn hơn), hoặc artifact của harness Rust
(dừng ở ~4 ms plateau gợi ý một độ trễ hệ thống, không phải nhiễu
ngẫu nhiên). Cần probe riêng trước khi kết luận; xem mục Drift và
Chưa kiểm chứng. Số này đo harness, không phải outbound thật (item 5
không có cột full) — nhưng nó là mục duy nhất trong baseline run9 mà
Rust chậm hơn Go ngoài sai số.

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
  (17.48 MB vs 48.10 MB — 0.363×, nhỏ hơn 2.75×), startup `--version`
  5.619 ms vs 23.236 ms (0.242×, 4.14× nhanh hơn — kèm caveat tải ở
  §2: driver và hyperfine lệch nhau tới 2× ở run9), `--help` 1.889 ms vs
  9.201 ms (0.205×), RSS `--version` 6.230 MiB vs 30.346 MiB (0.205×,
  79% ít hơn), parse config min/large/bad (wall 0.313/0.236/0.212×, RSS
  0.253/0.264/0.215×). Các khoảng min/max không giao nhau ở những mục
  này (RSS và size ổn định; wall tuyệt đối nhiễu theo tải — xem §2).
- Rust **chậm hơn Go rõ rệt** ở độ trễ 1 request loopback qua SOCKS5
  hand-roll: 3.973 ms/req vs 0.948 ms/req (4.19×) — ĐẢO CHIỀU so với
  run8 (0.99×, trong sai số). Nguyên nhân chưa rõ (cùng loadavg 11.39
  cho cả hai phía; lượt Rust plateau ở 3.96–4.00 ms). Số này đo
  harness, không phải outbound thật (item 5 không có cột full) — nhưng
  nó là mục duy nhất trong baseline run9 mà Rust chậm hơn Go ngoài sai
  số, và cần probe riêng trước khi kết luận.
- Lợi thế parse-large (10.6×) và render (12.7×) một phần là do Go làm
  nhiều việc hơn (validate sâu, alloc churn) và Rust defer validation —
  và một phần lớn là do Go chậm đi dưới tải ở run9 (số Go tăng
  1.7–2.4× so với run8 trong khi số Rust ổn định ±5%) — không phải
  toàn bộ là "Rust nhanh hơn". Đo lại sau khi Rust bổ sung validation,
  và đừng trích tỉ lệ §4 mà không kèm caveat tải.
- Con số cũ "77.5× nhỏ hơn" (run7, shell vs Go full) vẫn đúng về mặt
  số học nhưng **không còn là headline** — nó so hai thứ khác nhau.
  Headline từ run9 là 0.363× (2.75×) của rust-full; headline run8
  0.260× (3.84×) là số của cây cũ pre-rebase, giữ trong mục Drift.

## Hotspot ưu tiên (tối đa 7, sắp theo lợi ích/chi phí)

1. **Rust parse-large: validation chiếm 66% thời gian parse.**
   Bằng chứng số: parse-large 1,166 µs vs decode-alone 393 µs cùng
   input (32,246 B) — validation + build struct ≈ 773 µs. Lợi ích ước
   lượng: đưa validation về gần tốc độ decode → parse-large ~500–600 µs
   (~2×), với giả định validation+build rút về ~100–200 µs (chưa đo)
   và floor là 393 µs decode (không thể nhanh hơn decode). Chi phí sửa:
   trung bình (code trong `castctl-config/src/config.rs`, validation
   order + error message bị test parity ghim). Rủi ro: phá parity
   byte-for-byte của thông báo lỗi. Chỉ làm sau khi có profile chi tiết
   hơn (hiện không có `perf` trên cue).
2. **Rust `md_to_html` chiếm 81% render chain.** Bằng chứng số:
   `md_to_html` 921 µs vs render-chain 1,133 µs cùng input 51,560 B;
   split trong chain suy ra ≈ 212 µs (1,133 − 921) trên HTML, khác với
   272 µs đo split trên markdown thô — hai input khác nhau, không cộng
   trực tiếp được. Go tương ứng 12,111 µs với 8,354 allocs/op — phía Rust
   chưa đếm được alloc. Lợi ích: giảm số pass regex / allocation trong
   `inline_html` (`castctl-tg-text`, stash + `replace_all` nhiều lượt).
   Chi phí: trung bình. Rủi ro: parity `MDToHTML` (test M1 ghim output
   từng case).
3. **`split_text_limit` collect toàn bộ input thành `Vec<char>` trước.**
   Bằng chứng cấu trúc (không phải profile): `lib.rs` collect
   `text.chars()` rồi mới cắt; số đo: 272 µs cho 51,560 B (Go 790 µs).
   Lợi ích: nhỏ–vừa (bỏ 1 alloc lớn + pass char). Chi phí: trung bình
   (ngữ nghĩa cắt/fence-carry bị test ghim chặt). Rủi ro: đổi hành vi
   cắt ở biên. Đo alloc trước khi sửa.
4. **Lợi thế parse-large sẽ thu hẹp khi Rust bổ sung sing-box validation
   (D-M2-1) — đo lại, đừng tối ưu trước.** Bằng chứng số: Go parse-large
   12.42 ms vs Rust 1.17 ms nhưng Go validate 180 outbound + 10 endpoint
   sâu (52,155 allocs/op); Rust defer. Thêm nữa, tỉ lệ run9 phồng lên
   vì Go chậm đi dưới tải (xem §4). Lợi ích: tránh tối ưu sai chỗ +
   tránh ngạc nhiên khi validation hạ cánh. Chi phí: thấp (chỉ đo lại).
   Rủi ro: không có — đây là follow-up đo, không phải sửa code.
5. **Startup của rust-full: 5.6 ms, không đáng tối ưu thêm lúc này.**
   Bằng chứng số: full `--version` 5.619 ms (shell 5.505 ms — closure
   lớn hơn chỉ tốn ~0.1 ms, không còn ~1 ms như run8); phần lớn còn
   lại là spawn process + dynamic loader + scheduling dưới tải
   (hyperfine đo full `--version` 7.1 ms, shell 2.31 ms — hai phương
   pháp lệch nhau, xem §2). Lợi ích tối đa ~1–2 ms tuyệt đối. Chi phí:
   thấp–trung bình (`-C target-cpu=native` bị CẤM ở PR này; static
   musl đổi cả toolchain). Rủi ro: đổi ABI/link. Để sau, khi binary
   lớn hơn.
6. **Kích thước binary: LTO co thêm 18.8% nhưng không đổi headline.**
   Bằng chứng số: full headline 17,481,032 B, LTO 14,197,080 B
   (`.text` 11,129,372 → 9,695,132 B); shell 17,446,696 B. Lợi ích thêm
   (`codegen-units=1` / `panic=abort`): vài chục KB, không đáng kể so
   với 0.363× hiện tại. Chi phí: thấp nhưng `panic=abort` đổi hành vi
   crash. Rủi ro: thấp. Chỉ xem lại khi Rust port thêm crate nặng
   (bot/keeper/webui ở M7 sẽ làm binary lớn hơn nhiều — đo lại ở đó).
7. **Item 5 đảo chiều — probe nguyên nhân trước, đừng micro-tối ưu
   client hand-roll.** Bằng chứng số: item 5 Rust 3.973 ms vs Go
   0.948 ms (run8: 0.872 vs 0.885, trong sai số), và cả hai đều qua
   proxy Python + `http.server` Python. Lợi ích của việc tối ưu client
   hand-roll khi chưa biết nguyên nhân: ~0 (có thể tối ưu sai chỗ).
   Probe trước: bench binary mới (3,178,400 B) có gì khác, plateau
   ~4 ms từ đâu (lượt đầu 1.317 ms rồi plateau 3.96–4.00 ms). Đo lại
   bằng outbound thật (honk/sing-box, M3) + gateway thật (M4a) trước
   khi đụng tới. Chi phí: thấp (chỉ đo). Rủi ro: tối ưu sai tầng.

## Output lần chạy thật (run9 — tóm tắt, KHÔNG nguyên văn)

```
$ sh rust/perf/run.sh   # trên cue, repo root, không flag
... (shell build: plain 187.4 s, strip 189.4 s; full build: plain 191.2 s, nokeep 217.8 s, strip 1.2 s) ...
hyperfine --version:  Go median 10.7 ms vs shell 2.31 ms vs full 7.1 ms
hyperfine --help:     Go median 16.42 ms vs shell 4.54 ms vs full 4.33 ms
summary.json: date 2026-11-05T18:19:48Z, commit 740e2dc, machine cue 8x Xeon 2.50GHz,
  MemTotal 24788940 kB, SwapTotal 0 kB, go 0.9.0 (1396697), cargo 1.99.1,
  go 1.27.3, hyperfine 1.18.0, loadavg start 4.79 / mid 7.21 / end 18.05,
  disk / 9.69 -> 8.73 GiB
item5: status measured, rust 3.973 ms/req (1.317-3.999),
  go 0.948 ms/req (0.816-2.280); setup 1.5 s, measure 13.1 s
full-bin LTO build FAILED (exit 101, target dir deleted mid-build); see build_full_lto
SPDX check: FAIL (advisory only, rerun unaffected; see /tmp/perf0-spdx-check-VqOXTd.log)
```

Stdout thật đầy đủ: `rust/perf/data/run9-stdout.txt` (157,971 B — chính
là JSON dump của `summary.json` (157,881 B; lần build LTO gốc fail nằm
trong mảng `notes` của JSON, không phải một dòng stdout riêng) cộng
dòng `SPDX check: FAIL …` (90 B); JSON trong log khớp byte với
`summary.json` đã commit, md5 `9d84a70fe125e6fc9652c022146fb56e`). Số thô
đầy đủ: `rust/perf/data/*.json` (mỗi file ghi từng lần chạy,
median/min/max/mean, exit code). Tái lập: chạy lại lệnh trên rồi diff
`data/summary.json` với file đã commit. Lưu ý: lần chạy này có một
note duy nhất trong summary — LTO build gốc fail (xem mục `rust-full`);
mọi phép đo khác exit như kỳ vọng. Lưu ý thêm: `summary.json` của run9
KHÔNG còn key `rust_full_binary_after_lto_restore` (key này có trong
summary run8, cùng size+sha với `rust_full_binary`, mà driver code
không sinh ra được — artifact của driver lúc chạy run8; xem mục "Vì
sao có run9").

## Dao động giữa các lần chạy (run4 → run5 → run6 → run7 → run8 → run9, median)

Run5 dùng driver trung gian của fix loop 1 (vòng poll WNOHANG gây lượng
tử hoá wall 5 ms + RSS floor) nên số startup/RSS của nó KHÔNG dùng
được — driver đó không phải phương pháp của run4 (run4 dùng `wait4`
blocking, wall đúng, xem phần mở đầu); run6 dùng target dir còn ấm nên
thời gian build của nó không phải full build. Chỉ item 4/5 (đo bằng
harness nội bộ, không qua `measure.py`) so sánh được xuyên suốt cả
6 run. Summary run5 (`2026-11-05T12:05:39Z`) và run6
(`2026-11-05T12:14:07Z`) được commit ở `data/run5-summary.json` /
`data/run6-summary.json` để đối chiếu từng ô trong bảng này; run7 ở
`data/run7-summary.json`, run8 ở `data/run8-summary.json`. Fixture parse-large đổi ở run5 (25,657 B /
140 outbounds → 32,246 B / 180 outbounds + 10 endpoints) nên
parse-large/decode-large tăng theo kích thước fixture, không phải drift
máy.

| Tác vụ | run4 | run5 | run6 | run7 | run8 | run9 |
|---|---|---|---|---|---|---|
| Parse min Go / Rust (ns) | 5,882 / 2,517 | 4,529 / 2,554 | 4,494 / 2,539 | 4,511 / 2,553 | 4,548 / 2,512 | 4,418 / 2,559 |
| Parse large Go / Rust (ms) | 5.11 / 0.934 | 6.96 / 1.160 | 7.01 / 1.169 | 7.15 / 1.163 | 7.35 / 1.178 | 12.42 / 1.166 |
| MDToHTML Go / Rust (ms) | 4.62 / 0.873 | 5.00 / 0.869 | 5.43 / 0.878 | 5.41 / 0.872 | 5.34 / 0.886 | 12.11 / 0.921 |
| SplitText Go / Rust (µs) | 518 / 266 | 593 / 271 | 606 / 271 | 551 / 281 | 555 / 271 | 790 / 272 |
| Render chain Go / Rust (ms) | 5.24 / 1.085 | 6.46 / 1.074 | 5.42 / 1.092 | 5.62 / 1.114 | 5.99 / 1.076 | 14.41 / 1.133 |
| Item 5 Go / Rust (ms/req) | 0.813 / 0.756 | 0.810 / 0.729 | 0.858 / 0.929 | 0.874 / 0.830 | 0.885 / 0.872 | 0.948 / **3.973** |
| Startup `--version` tỉ lệ shell/Go | 0.088 | (sai: wall lượng tử hoá) | 0.087 | 0.081 | 0.081 | 0.237 |
| Startup `--version` tỉ lệ full/Go | — | — | — | — | **0.179** | **0.242** |
| RSS `--version` Go / shell / full (MiB) | 43.5 / (sai: floor) / — | 30.5 / (sai: floor) / — | 30.4 / 2.14 / — | 30.4 / 2.14 / — | 30.3 / 2.20 / **5.42** | 30.3 / 6.12 / **6.23** |
| Binary stripped Go / shell / full (MB) | — | — | — | 48.10 / 0.62 / — | 48.10 / 0.62 / **12.53** | 48.10 / 17.45 / **17.48** |

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
shell/Go dao động 0.046–0.073 theo session (xem §3). Run8 khớp run7
trong ±5% ở hầu hết các ô headline (không tính hàng n=1; §3 nói riêng
bên dưới): §2 startup/RSS 7/8 ô N=20 trong ±5% (ngoại lệ duy nhất
`--help` phía shell +7.0%, 0.867→0.927 ms), §4 logic thuần mọi ô trong
±5% trừ render chain Go +6.7% (5.62→5.99 ms) (ngoại lệ thứ hai), item 5 Go +1.3% (item 5
Rust +5.1%, 0.830→0.872 ms/req, là ngoại lệ thứ ba). Wall-clock
`status` ở §3 nhiễu hơn: năm trong sáu ô drift +8–14% trên giá trị
tuyệt đối nhỏ (Rust 0.9–2.9 ms, Go 11–46 ms; ô còn lại Go min −4.6%),
trong khi RSS `status` khớp trong ±1.1% — trừ first
measured run n=1 (Go wall 12.616→51.909 ms, xem §2).

**Run9 so với run8 (đọc kỹ — đây là drift lớn nhất từ trước tới nay,
do hai nguyên nhân khác nhau: M4b và tải):** (a) M4b: shell binary
0.62→17.45 MB (28.1×, closure nay link transport/honk/boring-sys),
full binary 12.53→17.48 MB (+39.5% — đúng số Boss đo tay 17,481,032 B),
RSS shell `--version` 2.20→6.12 MiB (×2.8), RSS full `--version`
5.42→6.23 MiB (+14.9%), RSS full `status` +19–62% (status nay làm
việc thật, exit 2 thay vì stub exit 1 ở run8). (b) Tải: run9 chạy dưới
loadavg 4.79→18.05 (session khác chạy test binary 196% CPU / 15.8G
RSS), run8 chỉ 2.24→6.09. Số Rust §4 ổn định trong ±5% (parse-min
+1.9%, parse-large −1.0%, md-to-html +3.9%, split +0.5%, render
+5.3%), nhưng số Go §4 tăng 1.7–2.4× (parse-large +69%, MDToHTML
+127%, render +141%, split +42%; min của Go parse-large 7.01M ≈
median run8 — tải tăng dần giữa bench). Wall startup: Go `--version`
+119% (10.63→23.24 ms) nhưng `--help` −15% (10.86→9.20 ms) trong
cùng một run; shell `--version` +536% (0.87→5.51 ms), full +195%
(1.90→5.62 ms) — Go `--version` và `--help` lệch hướng nhau chứng tỏ
wall 1–20 ms ở run9 bị scheduling jitter chi phối, không phải tốc độ
thật; hyperfine cũng lệch với driver ở run9 (Go `--version` hyperfine
10.7 ms vs driver 23.2 ms; full 7.1 vs 5.6 ms), ngược với run8 khi hai
phương pháp đồng thuận. RSS Go ổn định ±1% ở mọi ô (mode thấp) —
RSS là metric đáng tin nhất của run9. Item 5 là drift lớn nhất:
Rust 0.872→3.973 ms/req (+356%), tỉ lệ 0.99→4.19, đảo chiều kết
luận; Go chỉ +7.1% (0.885→0.948). **Hướng kết luận đổi ở đúng hai
chỗ so với run8: item 5 (Rust nay chậm hơn) và headline size
(0.260×→0.363×); mọi headline khác giữ hướng (Rust nhanh hơn), chỉ
tỉ lệ wall nhiễu hơn do tải.**

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
- `data/` — số thô các lần chạy (run9 là số trong bảng trên;
  `run9-stdout.txt` là stdout thật của run9, 157,971 B, JSON trong log
  khớp byte với `summary.json` hiện tại, md5
  `9d84a70fe125e6fc9652c022146fb56e`; `run8-summary.json` là summary
  đầy đủ của run8 để đối chiếu bảng Drift (md5
  `90730fd5a0b1265097c27d54d1eefe88`); `run7-summary.json` là summary
  đầy đủ của run7; `run5-summary.json` / `run6-summary.json` là summary
  đầy đủ của run5/run6; `verify-rerun-summary.json` là summary đầy đủ
  của rerun độc lập (2026-11-05T14:26:32Z) để đối chiếu drift;
  `nm-counts.json` / `lto-build-record.json` / `behaviour-checks.json`
  là record của run9 (rebuild + `nm` + behaviour checks trên cue,
  2026-11-05 — xem mục `rust-full`).

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
- Số RSS Go `--version` bimodal theo session: 30.3–30.5 MiB (run5–run9) vs
  43.5 MiB (run4) vs 47.7 MiB (rerun độc lập,
  `data/verify-rerun-summary.json`); nguyên nhân chưa rõ (giả thuyết
  THP chưa kiểm chứng — `AnonHugePages` 0 kB lúc probe; env cô lập
  không phải nguyên nhân theo probe của verifier). Số RSS Go trong
  bảng là số run9 (mode thấp); tỉ lệ RSS rust-full/Go theo session
  dao động (run9: 0.205; mode cao Go 47.7 MiB → ~0.131). Wall startup
  Go cũng drift −23…−27% ở rerun độc lập dưới tải cao hơn — chưa giải
  thích được; ở run9 Go `--version` và `--help` lệch hướng nhau
  trong cùng một run (+119% / −15%), và driver lệch với hyperfine tới
  2× — wall tuyệt đối 1–20 ms dưới tải cao là nhiễu scheduling, xem §2.
- First measured run run9 (n=1): wall cao bất thường ở cả ba phía so
  với median (Go 2.8×, shell 3.8×, full 1.8×) — cơ chế có thể là page
  cache bị build full-bin đẩy ra, chưa chứng minh; không dùng làm kết
  luận.
- Hyper client machinery: gap run8 ĐÃ ĐÓNG — hyper có 537 symbol trong
  cả ba binary run9 (keep/shell/nokeep), xem mục `rust-full`; rust-full
  không còn là lower bound ở chỗ này.
- Item 5 đảo chiều (Rust 0.872→3.973 ms/req, tỉ lệ 0.99→4.19) — nguyên
  nhân chưa rõ: cùng loadavg 11.39 cho cả hai phía, lượt Rust plateau
  ở 3.96–4.00 ms sau lượt đầu 1.317 ms. Chưa probe được (cần bench
  binary mới so với run8, kiểm tra thay đổi harness/M4b). Không dùng
  số này để kết luận về outbound thật — item 5 đo harness, không
  phải honk/sing-box.
- Tái lập sha256 phụ thuộc đường dẫn checkout: rebuild từ checkout khác
  (`/tmp/perf2-alt-checkout`, cùng target dir `/tmp/perf-full-target`)
  cho cùng size 17,481,032 B nhưng sha khác (`f7f898e5…` thay vì
  `b12911a5…`) — 19 đường dẫn nguồn tuyệt đối `file!()` + 1 hash
  cargo metadata trong binary. Reproduce check chỉ tái lập sha khi
  checkout ở cùng path; size 17,481,032 B ổn định mọi path và là
  cross-check bền. Cơ chế bù size khi độ dài path đổi (±584 B string
  mà `.rodata` không đổi) chưa giải thích được — chỉ ghi nhận.
- Anomaly (4b): rebuild lạnh với đúng lệnh của Boss ở
  `/root/v66b-target` cho sha `7f816189…` (đúng sha Boss đo), nhưng
  rebuild lạnh lặp lại cùng lệnh/cùng dir sau đó cho sha
  `b2961462…` (cùng size) — nguyên nhân chưa rõ (đĩa dao động mạnh,
  session khác build song song; không loại trừ input không xác định).
  Sha ở `/root/v66b-target` không ổn định theo thời gian, không dùng
  làm cross-check; chỉ sha ở pinned path `/tmp/perf-full-target`
  (tái lập 3×) được dùng trong Reproduce check.
- Kiểm tra `nm` trên binary LTO không chạy trực tiếp được (profile
  strip symbols); giữ-link ở LTO chỉ được chứng minh gián tiếp qua
  `.text` + cơ chế `#[used]` static (xem mục `rust-full`; record build
  LTO đầy đủ trong `data/lto-build-record.json` — size 14,197,080 B,
  `.text` 9,695,132 B, `--version` exit 0).
- Run5/run6 được commit ở `data/run5-summary.json` /
  `data/run6-summary.json` để đối chiếu drift; run7 ở
  `data/run7-summary.json`; run8 ở `data/run8-summary.json`;
  rerun độc lập được commit ở
  `data/verify-rerun-summary.json`; chỉ run9 là baseline chính thức.
