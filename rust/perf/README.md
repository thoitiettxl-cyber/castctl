# M-perf-3 — Go vs Rust performance baseline (measurement only)

Baseline hiệu năng Go `castctl` 0.9.0 vs Rust `castctl-rs`
(M4b CLI surface: auth + 13 commands, link cả transport/honk +
gateway) và Rust `castctl-full` (CLI + config + transport/honk +
gateway), đo trên cue ngày 2026-11-05. **Không tối ưu code** — chỉ
đo; mọi đề xuất tối ưu nằm ở mục Hotspot bên dưới và đều kèm số.

Số trong tài liệu này là **run10** (`2026-11-05T21:45:03Z`, full rerun,
commit `fbaa0d7`, xem mục Drift bên dưới). Run9
(`2026-11-05T18:19:48Z`, commit `740e2dc`) đã được archive byte-identical ở `data/run9-summary.json`
(md5 `9d84a70fe125e6fc9652c022146fb56e`) trước khi rerun ghi đè các
file per-item; cột Drift trace về file đó. Run8
(`2026-11-05T15:23:14Z`, commit `3c45bfe`, trước rebase lên `dev-rust`
`27a0eaf`) ở `data/run8-summary.json` (md5
`90730fd5a0b1265097c27d54d1eefe88`). Run7
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
và logic thuần ổn định); run10 giữ nguyên phương pháp đó, chỉ khác
cây source (sau rebase lên `dev-rust` `25a124e`: M4c + M5a + docs
sweep PR #70) và tải máy lúc đo thấp hơn nhiều (loadavg 0.98–5.46,
xem mục Drift và "Vì sao có run10" — wall-clock run10 không còn bị
thổi phồng như run9).

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
lệch +4,954 KB (+39.5%). Chẩn đoán của Boss đúng: run8 đo ở commit
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
số Boss đo, sha `b12911a5…` (khác sha của Boss vì cả checkout path
lẫn target dir đều khác: `/tmp/castctl-rust-perf1` +
`/tmp/perf-full-target` so với `/tmp/v66/c` + `/root/v66b-target`
của ông — xem mục `rust-full`, phần tái lập sha). Tỉ lệ headline từ run9 là 0.363×
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

## Vì sao có run10 (M-perf-3): số run9 mô tả cây source cũ

Sau khi PR #66 được push ở head `5ce1c62` (run9), `dev-rust` tiến
thêm ba bước: Boss merge PR #69 (M4c: default_ws_url + JsonValue
bridge, head `c7b1d34`) và PR #68 (M5a: Telegram bot core, head
`07e1c0d`), rồi PR #70 (docs sweep, head `25a124e`). PR #66 ở head cũ
CONFLICT trên `rust/Cargo.lock` với `dev-rust` mới và CI không chạy
được (không có merge commit mới cho head `5ce1c62` — GitHub không tạo
merge ref khi PR conflict). Boss ra lệnh: rebase PR #66 lên
`origin/dev-rust`, đo lại toàn bộ ở head mới, cập nhật bảng + sha,
giữ run9 trong Drift ("Không hỏi lại").

Rebase lên `origin/dev-rust` `25a124e` (không phải `c7b1d34` như kế
hoạch ban đầu — dev-rust đã tiến thêm PR #70, doc-only, trong lúc
làm; rebase lên head mới nhất đúng lệnh "rebase lên origin/dev-rust"):
dừng đúng một lần ở commit lock `c5b1dd9` (1 file `rust/Cargo.lock`,
1 vùng, resolve `--ours` = lock của dev, byte-identical). Full-bin
lock không conflict nhưng stale sau M4c (M4c bỏ dep `tokio-rustls`
khỏi `castctl-gateway/Cargo.toml` nên lock run9 không còn khớp
manifest — `run.sh` fail ở b3, exit 101, `--locked`); regenerate
bằng cargo offline trên cue, đúng 1 dòng xoá (`- "tokio-rustls",`),
`cargo tree --locked --offline` exit 0 sau đó; commit riêng `fbaa0d7`
(mechanical, cargo-generated, disclose đầy đủ trong message).

Run10 xác nhận cây mới chỉ nhỏ hơn run9 một chút: shell stripped
17,440,616 B (run9: 17,446,696 B, −6,080 B), full stripped 17,475,048 B
(run9: 17,481,032 B, −5,984 B) — tỉ lệ headline giữ nguyên 0.363×
(2.75× nhỏ hơn). Bench binary byte-identical với run9 (3,178,400 B,
sha `c8832c18…` — code bench không đổi). LTO driver lần này exit 0
(257.6 s, 14,137,784 B, sha `3ff9948c…`), không cần retry tay như
run9. Hai thay đổi lớn ở run10 so với run9: (1) tải máy thấp
(loadavg 0.98→5.46→1.69, so với run9 4.79→9.40→18.05) nên
wall-clock không còn bị thổi phồng — số Go §4 về gần mức run8 (tải
thấp), và driver khớp hyperfine trong 9–29% thay vì lệch tới 2× như
run9; (2) item 5 ĐẢO CHIỀU LẦN NỮA: Rust 0.713 ms/req vs Go
0.782 ms/req (0.91×, Rust nhanh hơn) — plateau 4 ms của run9 không
tái lập dưới tải thấp (xem §5 và Drift). Số run9 giữ nguyên trong mục
Drift (commit `740e2dc`, lý do pre-rebase) — không xoá, không sửa tay.

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
  check SPDX chạy cuối `run.sh`. Run10 dùng `/tmp/perf-full-target`
  (ấm — artifacts run9 còn trong đó; b4 no-keep chỉ mất 9.0 s thay vì
  217.8 s cold như run9) vì `CARGO_TARGET_DIR` không set; shell build
  dùng `rust/target` trong cây cue. Run9 dùng cùng target dir này
  nhưng cold (1.1 GiB lúc xong cho một lần build strip; 2.2 GiB sau cả
  dãy b3→b4→b5+LTO). Run7 dùng
  `CARGO_TARGET_DIR=/dev/shm/perf0-target` vì đĩa `/` của cue lúc đó đã
  99% đầy (850 MB trống theo `df_root` trong `summary.json`, session M4b
  đang build song song); target dir ~41 MiB (delta trống trên /dev/shm:
  7.82→7.78 GiB), dọn sau khi chạy xong.
- Disk preflight: driver fail sớm nếu `/` (hoặc filesystem của
  `CARGO_TARGET_DIR`) dưới 1.0 GiB trống, và nếu filesystem của
  full-target dưới 2.0 GiB trống (M-perf-1: closure full ~1.1 GiB
  target dir lúc probe, gấp ~40× shell). Run10: `/` 13.05 GiB trước →
  8.48 GiB sau (target full + shell target). Giữa run9 và lúc viết
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
  của run10 được commit ở `data/run10-stdout.txt` (xem mục Output bên dưới;
  run9 giữ ở `data/run9-stdout.txt`, run8 ở `data/run8-stdout.txt`).
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
  tạo); run10 in `SPDX check: FAIL` (322 file — chỉ dưới
  `rust/target/release/`, do rerun b1/b2 tạo; workspace closure giờ
  chứa boring-sys sau M4b nên bẫy này là mặc định, không phải ngoại
  lệ)**. Không file `.go` nào trong số đó
  được track (`git ls-files | grep '\.go$'` = 481 file repo, tất cả có
  header) — gate SPDX chính thức phải chạy trên checkout sạch TRƯỚC
  mọi workspace build.

## Điều kiện đo (run10, 2026-11-05T21:45:03Z, commit `fbaa0d7`)

- Máy: cue, `Linux 6.18.38+ x86_64`, 8 × Intel Xeon @ 2.50GHz,
  MemTotal 24,788,940 kB (23.6 GiB), SwapTotal 0 kB (ghi trong
  `summary.json: machine.meminfo`), loadavg 1-phút 0.98 lúc bắt đầu,
  5.46 giữa chừng, 1.69 lúc kết thúc (thấp hơn run9 ở mọi điểm — run9
  4.79 → 9.40 → 18.05; run8 2.24 → 7.73 → 6.09 — build
  full-bin biên dịch ~350 crate song song; cộng 45 mark loadavg + timestamp trước/sau
  từng item và từng phía trong `summary.json: marks`). Đĩa `/` 13.05 GiB
  trống lúc bắt đầu, 8.48 GiB lúc kết thúc; build outputs: shell trên
  `rust/target`, full trên `/tmp/perf-full-target` (ấm —
  `full_target_cold: false` trong summary, artifacts run9 còn đó).
  **Tải thấp này làm wall-clock run10 về gần mức run8 (tải thấp),
  khác hẳn run9 bị thổi phồng (xem mục Drift); RSS và logic thuần
  ổn định như mọi run.**
- Go: `/usr/local/bin/castctl` 0.9.0 (`1396697 2026-11-04T21:38:36Z`),
  48,100,296 B, sha256 `c8ea009e…` (cùng binary với run7/run8).
  `go version -m` (ghi đầy đủ trong `summary.json:
  machine.go_binary_build_info`):
  `-buildmode=exe`, tags `with_utls,with_quic,with_wireguard,
  with_gvisor`, `-trimpath=true`, `CGO_ENABLED=1`, `GOARCH=amd64`.
  Output `go version -m` KHÔNG có dòng `-ldflags` nào nên tài liệu này
  không claim `-s -w` (claim đó ở run4 không có nguồn trong data).
  Go toolchain 1.27.3.
- Rust shell: `castctl-rs` build từ head `fbaa0d7` trên nhánh này
  (sau rebase lên `dev-rust` `25a124e`, M4c + M5a đã merge),
  `cargo +1.99.1 build --release --locked -p castctl-rs`,
  `RUSTFLAGS="-C strip=symbols"` (số chính); build thường 154.8 s,
  build strip 160.4 s (target dir ấm — castctl-* crates biên dịch lại
  cho cây M4c/M5a, deps còn nguyên từ run9).
- Rust full: `castctl-full` build từ `rust/perf/full-bin/` (standalone
  crate, `[workspace]` riêng, path deps `castctl-cli` +
  `castctl-config` + `castctl-transport` + `castctl-gateway`,
  `[patch.crates-io]` copy nguyên văn từ workspace chính),
  `cargo +1.99.1 build --release --locked --offline --manifest-path
  rust/perf/full-bin/Cargo.toml`, `RUSTFLAGS="-C strip=symbols"`
  (số chính); build thường 155.4 s, no-keep 9.0 s, strip 1.1 s
  (target dir ấm `/tmp/perf-full-target` — no-keep chỉ relink vì
  closure đã build ở b3; run9 cold mất 217.8 s cho no-keep). Xem chi tiết
  linkage ở mục `rust-full` bên dưới. LTO build của driver ở run10
  exit 0 sau 257.6 s (14,137,784 B, sha `3ff9948c…`) — lần đầu driver
  LTO thành công (run9 exit 101 do target dir bị xoá giữa build);
  record đầy đủ trong `data/lto-build-record.json`, xem mục
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

### Chứng minh linkage (run10, trên cue, 2026-11-05 — sau rebase lên dev-rust 25a124e: M4c + M5a)

(a) **Size A/B, stripped** (`RUSTFLAGS="-C strip=symbols"`, GNU strip
đối chiếu trong ngoặc): shell 17,440,616 B (17,440,608) → full
**không-keep** (`--no-default-features`) 17,440,264 B → full **keep**
17,475,048 B (17,475,040). **Shell ≈ full — đọc kỹ:** shell M4b đã
link sẵn toàn bộ closure (auth + transport/honk + gateway) nên hai
binary chỉ khác nhau ở `main` + các root keep: full keep lớn hơn
shell **34,432 B** (0.20% của full — shell bằng 99.80% full), và
full no-keep NHỎ hơn shell 352 B (hai `main` khác nhau, mức nhiễu);
bật `keep-linked` thì to thêm **34,784 B** so với no-keep. Hai delta
này là hai số khác nhau — đừng lẫn: 34,432 B = full keep − shell
(hai binary), 34,784 B = keep − no-keep (cùng binary, bật/tắt root
giữ-link). Cơ chế giữ-link vẫn hoạt động ở nghĩa
hẹp (xem (b): chỉ đúng 2 root Tier 1/2 vắng trong no-keep —
`KEEP_TIER2` 1 vs 0 và `RpcClient` 1 vs 0; 6 root còn lại đã có trong
no-keep vì M4b link cùng closure vào CLI — keep chỉ giữ thêm 85 dòng
`nm` và 34,784 B). Unstripped: shell 23,197,360 B, full
no-keep 23,200,024 B (+2,664 B so với shell), full keep 23,245,712 B
(kích thước + sha256 của cả ba ghi trong `data/nm-counts.json`).
`.text`/`.rodata` (stripped):
shell 11,098,764 / 2,251,856 B; full keep 11,123,948 / 2,251,848 B.

(b) **Bảng `nm`** (đếm symbol chứa chuỗi, trên binary **chưa strip**;
`nm` trên binary đã strip trả về rỗng nên không dùng được — lỗi phương
pháp đã gặp một lần trong lúc probe; và pattern phải là chuỗi trần,
không phải `castctl_transport::`, vì symbol Rust đã mangle). Số đếm đầy
đủ, kèm binary size/sha và lệnh build, ghi trong
`data/nm-counts.json` (run10, trên cue, 2026-11-05); bảng dưới đây trích
từ file đó. Chú ý: shell run10 CHỨA transport/gateway (M4b) nên cột
shell không còn là 0 — so sánh đúng là keep vs no-keep (delta nhỏ:
transport +8, gateway +4, honk +2, tokio +7, snow +5):

| Chuỗi | shell (M4b) | full no-keep | full keep (run10) |
|---|---|---|---|
| `castctl_transport` | 812 | 815 | **823** |
| `castctl_gateway` | 733 | 733 | **737** |
| `honk_outbound` | 9,488 | 9,488 | **9,490** |
| `boringtun` | 98 | 98 | **98** |
| `smoltcp` | 185 | 185 | **185** |
| `tokio` | 4,461 | 4,464 | **4,471** |
| `prost` | 50 | 50 | **50** |
| `tungstenite` | 510 | 510 | **510** |
| `snow` | 129 | 129 | **134** |
| `hyper` | 536 | 536 | **536** |

Tổng dòng `nm`: keep 50,906; shell 50,813; no-keep 50,821.
No-keep GẦN như shell nhưng không y hệt: transport 815 vs 812 (+3),
tokio 4,464 vs 4,461 (+3), tổng 50,821 vs 50,813 (+8) — hai `main`
khác nhau kéo theo vài symbol khác nhau (M4c/M5a đổi codegen; run9
no-keep đếm y hệt shell). Keep hơn no-keep ở đúng các
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
regenerate ở commit `fbaa0d7` — đúng 1 dòng xoá `tokio-rustls` khỏi
gateway sau M4c, chứa đúng các rev đó).

(d) **Hành vi** (ghi trong `data/behaviour-checks.json`, run10, binary
mới): `castctl-full --version` → `castctl 0.9.0`, exit 0;
`--help` byte-identical với shell (`cmp` pass — cùng sha256
`cc65698a…`, GIỐNG run8 VÀ run9: M4c + M5a không đổi top-level help);
`--version=x` → stderr + exit 2;
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
  exit 0, 4m 32s, 10,065,944 B (số run8; hàng LTO ở §1 nay là số run10). Fix loop 1 rebuild
  lại variant này bằng đúng lệnh profile-form (record đầy đủ trong
  `data/lto-build-record.json`): size 10,065,944 B và `.text`
  6,942,120 B khớp y prose. Driver đã đổi sang profile form để rerun
  sau tái lập được; `summary.json` của run8 vẫn ghi đúng lần fail gốc
  (`build_full_lto`, exit 101). **Run10:** driver LTO exit 0 sau
  257.6 s — lần đầu driver LTO thành công: 14,137,784 B, sha
  `3ff9948c…`, `.text` 9,644,252 B (record đầy đủ trong
  `data/lto-build-record.json` — đã viết lại cho run10, kèm second
  build độc lập tái lập đúng sha). Hàng LTO run10 ở §1 là số driver,
  không phải retry tay.
- **Khoảng trống đã công bố ở run8 nay ĐÃ ĐÓNG: hyper client machinery.**
  Run8: hyper 0 symbol trong `nm` — entry `HttpClient::request`
  trong `#[used]` static không giữ được hyper (địa chỉ của một `async
  fn` chỉ giữ constructor của future, không giữ code `poll`). Run10:
  hyper **536 symbol** trong CẢ BA binary (keep/shell/no-keep) —
  run9: 537, chênh 1 symbol (codegen, không điều tra; xem (b)) —
  M4b link hyper vào `castctl-cli` qua transport/gateway deps nên
  closure đã chứa hyper machinery mà không cần root nào giữ. Rust-full
  KHÔNG còn là lower bound của binary M7 ở chỗ này; câu "lower bound"
  của run8 bị thu hồi cho run9/run10. (Phần còn lại của phân tích run8 vẫn
  đúng: root Tier-2 giữ địa chỉ `async fn` chỉ giữ constructor —
  nhưng ở head mới, hyper đã vào binary bằng đường khác.)
- **Run8 (đã thu hồi ở run9): khoảng trống hyper client machinery (0 symbol).**
  Entry `HttpClient::request` trong `#[used]` static KHÔNG giữ được
  hyper: địa chỉ của một `async fn` chỉ giữ constructor của future,
  không giữ code `poll` điều khiển hyper — mà poll nó thì cần I/O
  thật, điều không root nào được làm. Nên ở run8 rust-full là **lower bound**
  của binary M7 ở đúng một chỗ này: nó chứa `HttpClient::new` +
  type `http::Request/Response` nhưng không chứa state machine client
  của hyper. Ở run9 và run10 hyper đã vào binary bằng đường khác (M4b link
  hyper vào `castctl-cli` — xem bullet trên), claim này không còn
  đứng. Không phóng đại, không giấu.

### Tái lập sha (run10 — pinned path, 2 lần chạy độc lập, cùng target dir ấm)

Sha của binary keep phụ thuộc vào **cả hai path**: target dir và
checkout (source path). Kích thước thì KHÔNG phụ thuộc vào path nào
trong hai — 17,475,048 B ở cả hai lần build run10, mọi section size
đều giống hệt nhau.

- **Reproduce check (pinned path):** 4 dòng trong mục Reproduce
  check bên dưới, chạy verbatim trên target dir ấm (trạng thái sau
  `run.sh`), tái lập đúng 17,475,048 B + sha `851bb6b4…` (chỉ relink
  0.30 s). Đây là check chính thức của bảng.
- **Driver b5 + reproduce relink:** run10 driver b5 (stripped keep,
  1.1 s) cho 17,475,048 B, sha `851bb6b4…` — trùng với reproduce
  relink. Giữa hai lần đó, build no-keep plain phụ (cho `nm`) đã ghi
  đè `/tmp/perf-full-target/release/castctl-full`; đúng 4 dòng
  Reproduce check rebuild lại và khôi phục đúng sha `851bb6b4…`. Sha
  pinned-path tái lập được 2 lần chạy độc lập (cùng target dir ấm) ở head này.
- **(4c)/(4d) không đo lại ở run10:** cơ chế đã chứng minh ở run9
  vẫn đứng — checkout path là input của sha (19 chuỗi `file!()`
  absolute path + 1 hash cargo metadata trong `hatch.noise.rs`
  include path; run9 (4c): checkout khác `/tmp/perf2-alt-checkout`
  cho cùng size 17,481,032 B nhưng sha `f7f898e5…` thay vì
  `b12911a5…`); cold-vs-warm không ảnh hưởng sha (run9 (4d): cold
  single build cho cùng sha). Run10 chỉ claim tái lập ở pinned path.
- **(4b) Target dir của Boss — ĐÍNH CHÍNH ở fix loop 1: lần đầu là đo nhiễm, không phải sha bất ổn.** Lần chạy đầu (checkout `/tmp/castctl-rust-perf1`, target dir `/root/v66b-target` KHÔNG xoá trước — chữ "fresh dir" ở bản trước là ghi sai) cho sha `7f816189…`, khớp chính xác sha Boss đo. Điều này KHÔNG THỂ là build lạnh thật: theo (4c), checkout path là input của sha — binary build từ `/tmp/castctl-rust-perf1` phải chứa 19 chuỗi `file!()` với path đó, không thể cho ra sha của binary build từ `/tmp/v66/c`. Lần đầu chỉ có thể là cargo reuse artifact của Boss còn trong target dir chưa xoá (hoặc sha đọc từ binary cũ chưa bị thay) — bằng chứng quyết định (strings của binary lần đầu) đã mất cùng `rm -rf /root/v66b-target` sau đó, nên không phân biệt được hai khả năng này; cả hai đều là nhiễm, không phải tái lập. Bằng chứng sau đó nhất quán với nhiễm: bản copy giữ lại cho sha `b2961462…` (strings: 146× `v66b-target`, 19× `castctl-rust-perf1`, gateway hash `1d46a2198ebe64b2` — đúng inputs của writer), và rebuild lạnh lặp lại từ cùng inputs cho `b2961462…` lần nữa (hai lần độc lập). **Probe quyết định (fix loop 1):** recreate checkout `/tmp/v66/c` ở commit `3ba3d6a` + lock full-bin regenerate (md5 `f3d74ba6…`, byte-identical với lock Boss tự regen), `rm -rf /root/v66b-target`, chạy đúng lệnh Boss → 17,481,032 B, sha **`7f816189…`** (build 3m12s, exit 0; strings của binary probe: 19× `v66/c`, 0× `castctl-rust-perf1`, 146× `v66b-target`; bản copy `/tmp/perf2-4b-probe-stripped` cùng sha; log `/tmp/perf2-4b-probe.log`). Kết luận đúng: **sha là hàm xác định của (checkout path, target dir)** — `7f816189…` tái lập được từ đúng inputs của Boss (2× độc lập: Boss + probe này); `b2961462…` là sha đúng cho (checkout `/tmp/castctl-rust-perf1`, target `/root/v66b-target`) (2×); `b12911a5…` cho (checkout `/tmp/castctl-rust-perf1`, target `/tmp/perf-full-target`) (4×). Câu "sha ở `/root/v66b-target` không ổn định theo thời gian" ở bản trước bị RÚT LẠI — không có bằng chứng nào cho bất ổn; chỉ có một lần đo nhiễm. Hệ quả thực dụng không đổi: chỉ sha ở pinned path `/tmp/perf-full-target` (tái lập 4 lần độc lập: run9 b5, rebuild tay b3→b4→b5, cold single (4d), warm-restore retry b3→b4→b5 (sau build (4c)) — lần retry này tái lập cả 4 sha: headline `b12911a5…`, plain `55c4bdae…`, plain-gnu `201ff340…`, nokeep `9b6c28ed…`) mới dùng được trong Reproduce check. Size 17,481,032 B thì ổn định ở mọi path và mọi lần build — đó là cross-check bền. (Dự đoán cũ "+435 B vì path dài hơn 3 ký tự × 145 chuỗi" là SAI: so `size -A` trực tiếp cho thấy mọi section giống hệt nhau giữa hai target dir dù tổng độ dài chuỗi target-path chênh 584 B — cơ chế bù trừ chưa rõ, chỉ ghi là quan sát.)

Lịch sử run8/run9 (giữ để đối chiếu): run8 rebuild từ source fc250db với tên
target dir khác (`/tmp/perf-fix1-target`) cho cùng size, sha khác
(unstripped `687af3f7…` ≠ run8 `2809a25f…`, stripped `57e48df3…` ≠
`b8aee622…`, LTO `8c737840…` ≠ `8040a0c6…`); rebuild với đúng tên
target dir của run8 (`/tmp/perf-full-target`) khớp cả ba sha. Run9
tái lập sha pinned-path 4 lần độc lập (b5, rebuild tay b3→b4→b5,
cold single (4d), warm-restore retry — lần retry tái lập cả 4 sha:
headline `b12911a5…`, plain `55c4bdae…`, plain-gnu `201ff340…`,
nokeep `9b6c28ed…`). Số liệu đầy đủ trong `data/nm-counts.json`
(`comparison_vs_run9`, `sha_reproduction`, `nm`) và
`data/lto-build-record.json` (`byte_reproduction_check` — sha LTO
tái lập 2× độc lập); record run9 cũ còn trong git history của các
file này (`git show 5ce1c62:rust/perf/data/nm-counts.json`).

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
  `.text` 9,644,252 B (so với no-keep 11,098,332 B và primary
  11,123,948 B) — closure đầy đủ vẫn còn đó, chỉ co lại 13.3% do LTO —
  cộng với cơ chế `#[used]` static giữ hàm có địa chỉ + các callee
  truyền của nó sống qua LTO theo construction (linker không thể drop
  hàm mà địa chỉ của nó nằm trong static được giữ). Đây là điểm lệch
  so với kế hoạch gốc (kế hoạch đòi nm cả hai variant); ghi rõ ở đây
  thay vì giả vờ đã nm. `.text` LTO nay có record:
  `data/lto-build-record.json` (run10: 14,137,784 B, `.text`
  9,644,252 B).

### Reproduce check (run10 — đúng 4 dòng, checkout + target dir đều pin)

Chạy 4 dòng dưới đây, verbatim, trên cue, từ checkout đã đo run10
(`/tmp/castctl-rust-perf1`, head `fbaa0d7`). Nếu checkout này đã bị
dọn khỏi cue (đĩa hay đầy — lúc fix loop 1 nó đã không còn), clone
lại nhánh này ở head `fbaa0d7` vào đúng path `/tmp/castctl-rust-perf1`
rồi mới chạy — path checkout là input của sha nên không được dùng
path khác.

```sh
cd /tmp/castctl-rust-perf1 && git rev-parse HEAD
RUSTFLAGS="-C strip=symbols" CARGO_TARGET_DIR=/tmp/perf-full-target cargo +1.99.1 build --release --locked --offline --manifest-path rust/perf/full-bin/Cargo.toml
stat -c "%s %n" /tmp/perf-full-target/release/castctl-full
sha256sum /tmp/perf-full-target/release/castctl-full
```

Kết quả kỳ vọng: commit `fbaa0d7bff38748470e07e46927aaee62f4c06c7`,
size **17,475,048 B**, sha256
`851bb6b4d28afe9435db0766566ecc67a80e7561775670abc7a0c26d64073eb7`.
Đã verify: 4 dòng này trên target dir ấm tái lập đúng size+sha
(relink 0.30 s, ngay sau khi build no-keep plain phụ ghi đè binary
headline — xem "Tái lập sha" bên trên); driver b5 cũng cho cùng
size+sha (2 lần chạy độc lập, cùng target dir ấm, ở head này). Nếu checkout ở head mới hơn mà
chỉ đổi docs/data (tự verify bằng `git diff --name-only
fbaa0d7..HEAD`: chỉ README/PORTING/data, không chạm .rs/.toml/lock)
thì dòng 1 in head mới đó, size + sha vẫn phải khớp, vì binary chỉ
đổi khi source/lock đổi.

**Nếu sha khác → bảng đã cũ, phải đo lại chứ không được sửa số tay.**
Câu này áp cho đúng 4 dòng trên (checkout `/tmp/castctl-rust-perf1`
+ target dir `/tmp/perf-full-target`). Build từ checkout khác hoặc
target dir khác sẽ ra sha khác dù size vẫn 17,475,048 B — đó là hành
vi đã chứng minh (xem (4b)/(4c) bên trên), không phải dấu hiệu bảng
cũ; size mới là cross-check bền qua mọi path. Ngược lại, nếu 4 dòng
trên cho size khác 17,475,048 B thì bảng chắc chắn đã cũ.

## Bảng số (run10)

Quy ước: mọi ô headline kèm `median (min–max), N=20` (trừ hàng n=1).
Tỉ lệ headline LUÔN là `rust-full/go`. Cột `rust-shell/go` mang nhãn
tham chiếu — shell M4b nay gần như cùng closure với full (chênh
34,432 B stripped — shell bằng 99.80% full, xem mục `rust-full` (a))
nên cột shell không còn là "binary nhỏ không so được" như run8,
nhưng quy ước giữ nguyên: kết luận chỉ nói về rust-full. Mọi bảng
trong mục này mô tả run10 (commit `fbaa0d7`,
`2026-11-05T21:45:03Z`); số run9/run8 xem mục Drift.

### 1. Kích thước binary

**Caption (run10):** commit `fbaa0d7bff38748470e07e46927aaee62f4c06c7` (2026-11-05T21:45:03Z). Lệnh build: shell `RUSTFLAGS="-C strip=symbols" cargo +1.99.1 build --release --locked -p castctl-rs`; full `RUSTFLAGS="-C strip=symbols" CARGO_TARGET_DIR=/tmp/perf-full-target cargo +1.99.1 build --release --locked --offline --manifest-path rust/perf/full-bin/Cargo.toml`; LTO `cargo +1.99.1 build --profile release-lto --locked --offline --manifest-path rust/perf/full-bin/Cargo.toml`; no-keep `RUSTFLAGS="-C strip=symbols" CARGO_TARGET_DIR=/tmp/perf-full-target cargo +1.99.1 build --release --locked --offline --manifest-path rust/perf/full-bin/Cargo.toml --no-default-features`. sha256 (đầy đủ, trong `summary.json` / record files): Go `c8ea009e49c5bffce3c6b971db0f9f86948ab3904f478da33d43b6b60a9bc374`, shell stripped `055263b9d96045e1afb8275f06a7895d0b15528afec2dcc153db7e6a60ae2050`, full stripped `851bb6b4d28afe9435db0766566ecc67a80e7561775670abc7a0c26d64073eb7`, full no-keep `d4c800f91b5021f01d768702984b879210b79ad78ee49aabb5d923817bdf41b8`, full LTO `3ff9948cbe39500dea7d6a065d268f259ed2b5749659aac9625e0c9cc5c1acf7`, bench `c8832c1845d9f9b53936af632053d8abe8400c0366a1f70fd249e4fae0937fc2`.

| | Go (full) | Rust shell (M4b, tham chiếu) | Rust full (transport+gateway) | Rust-full/Go | Rust-shell/Go (tham chiếu) |
|---|---|---|---|---|---|
| Stripped (`-C strip=symbols`) | 48,100,296 B (45.87 MiB) | 17,440,616 B (16.63 MiB) | **17,475,048 B (16.67 MiB)** | **0.363 (2.75× nhỏ hơn)** | 0.363 |
| Chưa strip | — | 23,197,360 B | 23,245,712 B | 0.483 | 0.482 |
| GNU strip (đối chiếu) | — | 17,440,608 B (chênh 8 B) | 17,475,040 B (chênh 8 B) | — | — |
| `.text` | 21,017,769 B | 11,098,764 B | 11,123,948 B | 0.529 | 0.528 |
| `.rodata` | 2,644,352 B | 2,251,856 B | 2,251,848 B | 0.852 | 0.852 |
| A/B no-keep, stripped | — | — | 17,440,264 B (delta keep +34,784 B) | — | — |
| LTO variant, stripped (`release-lto`) * | — | — | 14,137,784 B (nhỏ hơn headline 19.1%) | 0.294 | — |

`sha256`: Go `c8ea009e…`, shell stripped `055263b9…`, full stripped
`851bb6b4…`, full no-keep `d4c800f9…`, full LTO `3ff9948c…`, bench
binary `c8832c18…` (3,178,400 B — byte-identical với run9, ghi trong
`summary.json: items.pure_logic.rust_bench_binary`). Hàng LTO (*):
driver build trên cue trong run10 (`--profile release-lto`, 257.6 s,
exit 0, `--version` exit 0), cùng source với run10; record đầy đủ
trong `data/lto-build-record.json` (kèm second build độc lập tái lập
đúng sha). Hàng "Chưa strip" tính tỉ lệ trên Go stripped (không có Go
unstripped). Hàng LTO không dùng cho tỉ lệ headline.

### 2. Startup (wall-clock, N=20, warmup 5)

**Caption (run10):** commit `fbaa0d7bff38748470e07e46927aaee62f4c06c7` (2026-11-05T21:45:03Z). Binary đo: Go `/usr/local/bin/castctl` 0.9.0 (prebuilt, sha256 `c8ea009e49c5bffce3c6b971db0f9f86948ab3904f478da33d43b6b60a9bc374`); shell build `RUSTFLAGS="-C strip=symbols" cargo +1.99.1 build --release --locked -p castctl-rs` (sha256 stripped `055263b9d96045e1afb8275f06a7895d0b15528afec2dcc153db7e6a60ae2050`); full build `RUSTFLAGS="-C strip=symbols" CARGO_TARGET_DIR=/tmp/perf-full-target cargo +1.99.1 build --release --locked --offline --manifest-path rust/perf/full-bin/Cargo.toml` (sha256 stripped `851bb6b4d28afe9435db0766566ecc67a80e7561775670abc7a0c26d64073eb7`). Lệnh đo: driver loop Python (warmup 5, N=20) — xem `summary.json: items.startup_rss`.

| Lệnh | Go median (min–max) ms | Rust shell median (min–max) ms (tham chiếu) | Rust full median (min–max) ms | Rust-full/Go | Rust-shell/Go (tham chiếu) |
|---|---|---|---|---|---|
| `--version` | 10.051 (8.844–11.779) | 2.405 (2.021–3.565) | **2.391 (2.010–2.841)** | **0.238\* (4.20× nhanh hơn\*)** | 0.239 |
| `--help` | 9.193 (8.347–11.528) | 2.301 (1.954–2.828) | **2.247 (1.852–3.064)** | **0.244\* (4.09× nhanh hơn\*)** | 0.250 |

\* Tỉ lệ startup tuyệt đối là wall-clock (driver vs hyperfine lệch 9–29% ở run10, tốt hơn nhiều so với 2× ở run9) — trích kèm caveat này; dùng RSS (§3) làm số ổn định. Xem prose ngay dưới.
| First measured run, warmup=0, sau probe `--version` (KHÔNG cold, KHÔNG sau build), N=1 `--version` — **n=1, không dùng làm kết luận** | 59.615 | 19.465 | 3.667 | 0.062 | 0.327 |

Đối chiếu hyperfine 1.18.0 (N=20, median, 3 lệnh trong MỘT invocation):
`--version` Go 8.61 ms vs shell 1.86 ms vs **full 1.98 ms**
(full/Go 0.23; full mean 1.99, min 1.84, max 2.20 — phân tán hẹp);
`--help` Go 8.41 ms vs shell 2.00 ms vs **full 1.97 ms**
(0.23; full mean 2.03, min 1.85, max 2.32). **Khớp loop Python ở
run10 trong 9–29%** (driver `--version` Go 10.05 vs hyperfine 8.61 ms;
shell 2.41 vs 1.86; full 2.39 vs 1.98 — driver cao hơn hyperfine một
chút ở cả ba phía, cùng hướng; run9 lệch tới 2×: driver Go 23.24 vs
hyperfine 10.7 ms, full 5.62 vs 7.1 ms ngược hướng). Run10 đo dưới
tải thấp (loadavg 0.98–5.46; hyperfine chạy sau item 5, loadavg cuối
1.69) nên wall-clock 1–10 ms ít nhiễu hơn run9 nhiều. Hướng kết luận
không đổi (Rust full vẫn nhanh hơn Go nhiều ở cả hai phương pháp);
tỉ lệ startup tuyệt đối vẫn là wall-clock — trích kèm caveat này, và
dùng RSS (§3) làm số ổn định. Lưu ý hàng n=1: wall first-run ở run10
cao ở Go và shell so với median (Go 59.615 ms ≈ 5.9× median 10.051 ms;
shell 19.465 ms ≈ 8.1× median 2.405 ms) nhưng full chỉ 1.5×
(3.667 ms so với 2.391 ms). Cơ chế có thể là page cache bị build
full-bin (~350 crate) đẩy ra ngay trước khi đo — suy luận, chưa
chứng minh; và vì là n=1 nên nó không dùng làm kết luận, chỉ ghi để
khỏi ai trích nhầm.

### 3. Peak RSS (GNU time, N=20) + wall `status`

**Caption (run10):** commit `fbaa0d7bff38748470e07e46927aaee62f4c06c7` (2026-11-05T21:45:03Z). Binary đo: Go `/usr/local/bin/castctl` 0.9.0 (sha256 `c8ea009e49c5bffce3c6b971db0f9f86948ab3904f478da33d43b6b60a9bc374`); shell `RUSTFLAGS="-C strip=symbols" cargo +1.99.1 build --release --locked -p castctl-rs` (sha256 stripped `055263b9d96045e1afb8275f06a7895d0b15528afec2dcc153db7e6a60ae2050`); full `RUSTFLAGS="-C strip=symbols" CARGO_TARGET_DIR=/tmp/perf-full-target cargo +1.99.1 build --release --locked --offline --manifest-path rust/perf/full-bin/Cargo.toml` (sha256 stripped `851bb6b4d28afe9435db0766566ecc67a80e7561775670abc7a0c26d64073eb7`). Lệnh đo: driver loop Python + GNU time `-v` (warmup 5, N=20) — xem `summary.json: items.startup_rss` / `items.parse_config_rss`.

| Lệnh | Go median (min–max) | Rust shell median (min–max) (tham chiếu) | Rust full median (min–max) | Rust-full/Go | Exit Go / shell / full |
|---|---|---|---|---|---|
| `--version` wall ms | 10.051 (8.844–11.779) | 2.405 (2.021–3.565) | 2.391 (2.010–2.841) | 0.238\* | 0 / 0 / 0 |
| `--version` RSS MiB | 30.371 (29.719–31.027) | 6.111 (6.047–6.242) | **6.203 (6.043–6.277)** | **0.204 (80% ít hơn)** | 0 / 0 / 0 |
| `--help` wall ms | 9.193 (8.347–11.528) | 2.301 (1.954–2.828) | 2.247 (1.852–3.064) | 0.244\* | 0 / 0 / 0 |
| `--help` RSS MiB | 30.496 (29.906–30.965) | 5.996 (5.934–6.141) | **6.115 (5.961–6.191)** | **0.201** | 0 / 0 / 0 |
| `status --config min` wall ms | 11.072 (9.808–13.326) | 3.807 (3.036–4.267) | 3.319 (2.745–4.053) | 0.300\* | 2 / 2 / 2 |
| `status --config min` RSS MiB | 32.936 (31.723–33.969) | 8.232 (8.039–8.438) | **8.189 (7.965–8.438)** | **0.249** | 2 / 2 / 2 |
| `status --config large` wall ms | 41.172 (37.827–45.569) | 9.017 (8.417–9.711) | 8.873 (8.017–9.873) | 0.216\* | 2 / 2 / 2 |
| `status --config large` RSS MiB | 37.777 (36.965–38.281) | 10.203 (9.953–10.445) | **9.949 (9.738–10.211)** | **0.263** | 2 / 2 / 2 |
| `status --config bad-JSON` wall ms | 10.402 (8.488–12.371) | 2.335 (1.842–2.958) | 2.426 (1.878–3.088) | 0.233\* | 2 / 2 / 2 |
| `status --config bad-JSON` RSS MiB | 30.902 (30.035–31.398) | 6.680 (6.555–6.809) | **6.742 (6.555–6.781)** | **0.218** | 2 / 2 / 2 |

\* Tỉ lệ wall lặp lại số §2 — xem caveat tải ở §2 (tỉ lệ tuyệt đối là wall-clock; dùng RSS làm số ổn định).

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
dừng ở parse, exit 2). **Exit code giữ nguyên so với run9:** Rust `status`
min/large ở run8 exit 1 (chạm stub chưa implement); từ run9 exit 2
(M4b đã wire `status` thật, fail như Go). Go vẫn exit 2; bad-JSON vẫn
2/2/2. RSS full tăng theo config (min 8.189 → large 9.949 MiB,
+1.76 MiB — chi phí parse thật trên closure lớn); RSS Go tăng +4.84
MiB từ min → large (32.936 → 37.777 MiB; +7.41 MiB so với `--version`
30.371 MiB). Wall-clock cũng thấy chi phí parse của full: `status`
large 8.873 ms so với min 3.319 ms; Go large 41.172 ms so với min
11.072 ms (Go large chậm hẳn vì fail ở tạo endpoint sau khi
parse+validate).

**Lịch sử số RSS (đọc kỹ trước khi trích):** số RSS Rust ở run4/run5
(13.2 MiB) là SAI — đó là floor của Python cha (xem phương pháp đo);
số đúng ở run10 là ~6.1 MiB cho shell, ~6.2 MiB cho full (run8:
~2.2/~5.4 MiB — tăng theo closure M4b; run9: 6.12/6.23 MiB, gần như
không đổi sang run10). RSS Go `--version` là
**bimodal theo session** (cùng binary, cùng sha256): run4 đo 43.5 MiB,
run5/run6/run7 đều đo 30.4 MiB, còn rerun độc lập (verify,
`2026-11-05T14:26:32Z`, xem mục Drift) đo 47.7 MiB — tức 2/5 session ở
mode cao (43.5, 47.7 MiB), 3/5 ở mode thấp (30.4 MiB). Trong một session
thì số ổn định chặt (verify: 47.61–47.93 MiB trên cả 20 run; run7:
29.80–30.98 MiB; run8: 29.72–30.97 MiB; run9: 29.66–31.28 MiB; run10:
29.72–31.03 MiB). Hai phương pháp đo độc lập
đồng thuận trong session verify: GNU time 47.74 MiB và `wait4`
`maxrss_kib_raw` median 47.7 MiB, nên mode cao là thật, không phải lỗi
đo. Nguyên nhân chưa rõ — giả thuyết (chưa kiểm chứng): Go 1.27 xin
transparent huge page cho heap arena, RSS hạch toán cả page 2 MB dù
chỉ dùng một phần; tuỳ trạng thái THP/fragmentation mà số hạch toán
dao động; lúc probe `AnonHugePages` là 0 kB nên giả thuyết này không
được xác nhận cũng không bị bác bỏ. Probe với đúng env cô lập của
driver vẫn cho mode thấp (30.5–31.3 MiB, probe của verifier sau rerun,
không nằm trong summary đã commit) nên env không phải nguyên nhân.
**Hệ quả khi trích:** số RSS Go trong bảng trên là số của run10 (mode
thấp, 30.4 MiB); tỉ lệ RSS rust-full/Go dao động theo session (run10:
0.204; nếu Go ở mode cao 47.7 MiB thì tỉ lệ ~0.130), không phải một
số duy nhất. RSS Rust full ổn định ~6.2 MiB ở `--version` trong
run10; RSS shell ổn định ~6.1 MiB (run6/run7/verify ở `--version`:
2.14 / 2.14 / 2.22 MiB — số shell cũ, trước M4b).

### 4. Logic thuần: parse config + render text Telegram

**Caption (run10):** commit `fbaa0d7bff38748470e07e46927aaee62f4c06c7` (2026-11-05T21:45:03Z). Lệnh đo: Go `go test -bench . -benchtime=100x -count=5 -run ^$ ./rust/perf/go-bench/` (test binary ephemeral — không có sha256 binary Go nào được ghi); Rust `cargo +1.99.1 build --release --offline` trong `rust/perf/bench/` → binary `perf-bench` 3,178,400 B, sha256 `c8832c1845d9f9b53936af632053d8abe8400c0366a1f70fd249e4fae0937fc2` (byte-identical với run9 — code bench không đổi; ghi trong `summary.json: items.pure_logic.rust_bench_binary`). Không có cột rust-full (bench đo trực tiếp cùng code cả hai phía đều link).

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
| Parse config min (42 B) | 4,440 (4,181–6,451) | 2,499 (2,463–2,536) | **0.56 (1.8× nhanh hơn)** | 131,072 |
| Parse config large (32,246 B, 50 profiles + 180 outbounds + 10 endpoints) | 7,500,259 (7,355,137–7,639,579) | 1,129,751 (1,127,717–1,132,515) | **0.15 (6.6× nhanh hơn)** | 256 |
| Decode JSON large, Rust-only (`decode_ordered_object`) | — | 382,978 (382,695–390,777) | — | 1,024 |
| `MDToHTML` (message 51,560 B) | 5,727,317 (5,644,217–6,435,432) | 861,757 (858,892–864,188) | **0.15 (6.6× nhanh hơn)** | 256 |
| `SplitText` (51,560 B) | 544,487 (541,323–550,130) | 262,253 (260,717–304,116) | **0.48 (2.1× nhanh hơn)** | 1,024 |
| Render chain (`MDToHTML` + `SplitText`) | 6,527,659 (6,309,284–6,788,391) | 1,068,073 (1,066,299–1,094,400) | **0.16 (6.1× nhanh hơn)** | 256 |

`output_len` đã kiểm chứng trong raw: parse-large 50 profiles,
decode-large 4 keys, `md-to-html` 58,259 chars, `split-text` 15,
render-chain 58,277, parse-min 1. Mọi run Rust đều ≥ 200 ms total
(K dừng ở 131,072 khi total đạt ~327 ms ở parse-min; cap `1<<20`
không chạm tới).

**Cảnh báo khi đọc tỉ lệ §4 run10:** tỉ lệ thu hẹp mạnh so với run9
(parse-large 0.09→0.15, MDToHTML 0.08→0.15, render 0.08→0.16) CHỦ
YẾU VÌ GO NHANH LẠI DƯỚI TẢI THẤP, không phải vì Rust chậm đi. Số Go
run10 ở 4 item lớn giảm 31–55% so với run9 (MDToHTML 12.11M→5.73M ns,
render 14.41M→6.53M, parse-large 12.42M→7.50M, split 790k→544k) —
về gần mức run8 (tải thấp: 5.34M/5.99M/7.35M/555k), trong khi số Rust
ổn định trong ±7% so với run9 (parse-large 1.166M→1.130M, md-to-html
0.921M→0.862M, render 1.133M→1.068M). Tỉ lệ run10 vẫn là số đo thật
của run10 — và vì cả hai phía đều đo dưới tải thấp nên tỉ lệ run10
công bằng hơn run9; so sánh công bằng nhất giữa hai run là phía Rust
(ổn định) và phía Go ở run8/run10 (tải thấp).

**Bất đối xứng phải đọc kèm:** cùng tên hàm nhưng khác khối lượng việc.
Go `ParseSingleConfig` validate sâu toàn bộ outbound (sing-box); Rust
defer sing-box option validation (deviation D-M2-1) nên parse-large của
Rust làm ít việc hơn. Bằng chứng: Go parse-large 2,195,428 B/op +
52,162 allocs/op (median — xem `go_b_op_allocs` trong `summary.json`);
Rust decode chỉ 383 µs trong tổng parse 1,130 µs (validation+build
struct chiếm 66%). Khi Rust bổ sung validation, lợi thế parse-large sẽ
thu hẹp — đo lại sau bước đó (hotspot H4). Tương tự `MDToHTML`: Go
4,860,922 B/op + 8,388 allocs/op (median; churn chuỗi lớn); Rust dùng
`regex` crate + `String` building, chưa đếm alloc (không có tool tương
đương `ReportAllocs` cho Rust ở đây).

### 5. Độ trễ 1 request qua transport loopback (SOCKS5 local)

**Caption (run10):** commit `fbaa0d7bff38748470e07e46927aaee62f4c06c7` (2026-11-05T21:45:03Z). Lệnh đo: Rust `[perf-bench, "socks5-get"]` (binary `perf-bench` 3,178,400 B, sha256 `c8832c1845d9f9b53936af632053d8abe8400c0366a1f70fd249e4fae0937fc2` — byte-identical với run9, build `cargo +1.99.1 build --release --offline` trong `rust/perf/bench/`); Go `go test -run TestSocks5Get -count=1 -v ./rust/perf/go-bench/` (test binary ephemeral — không có sha256 binary Go nào được ghi). N=5 lần chạy process × 20 request/lần. Không có cột rust-full (harness, không phải binary).

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
| SOCKS5 GET loopback | 0.782 (0.754–0.803) | 0.713 (0.705–0.787) | **0.91 (Rust nhanh hơn 1.10×)** |

Setup (spawn + verify hai server) hết 1.5 s; đo 8.7 s; tổng 10.2 s
(trong hạn 20 phút). Thứ tự chạy: Rust trước (5 lượt), rồi Go (5 lượt),
adjacent batches. **Đảo chiều LẦN NỮA so với run9** (khi đó Rust
3.973 vs Go 0.948 ms/req, tỉ lệ 4.19, Rust chậm hơn): phía Rust run10
là 0.713 ms/req — năm lượt 0.705–0.787 ms, không còn plateau 4 ms;
phía Go 0.782 ms/req (0.754–0.803 ms, không còn outlier 2.280 ms như
run9). Loadavg 1-phút lúc đo item 5 là 3.75 trước item 5, 1.69 cuối
run (`loadavg_after_item4` / `loadavg_end` trong `summary.json`) —
tải thấp, khác hẳn run9 (11.39 cho cả hai phía). Kết luận: plateau
4 ms của run9 KHÔNG tái lập dưới tải thấp — nhiều khả năng là
artifact theo tải (contention dưới-phút hoặc scheduling), không phải
hồi quy thật ở phía Rust sau M4b. Cơ chế chính xác vẫn chưa chứng
minh (loadavg 1-phút là metric thô, không loại trừ được contention
dưới-phút) — nhưng hướng đảo chiều đã rõ: run8 0.99× (trong sai số) →
run9 4.19× (Rust chậm hơn, tải cao) → run10 0.91× (Rust nhanh hơn,
tải thấp). Xem mục Drift và Chưa kiểm chứng. Số này đo harness, không
phải outbound thật (item 5 không có cột full) — và ở run10 nó không
còn là mục Rust chậm hơn Go.

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
  2.391 ms vs 10.051 ms (0.238×, 4.20× nhanh hơn — kèm caveat wall-clock ở
  §2: driver và hyperfine lệch 9–29% ở run10, tốt hơn nhiều so với 2×
  ở run9), `--help` 2.247 ms vs 9.193 ms (0.244×), RSS `--version`
  6.203 MiB vs 30.371 MiB (0.204×, 80% ít hơn), parse config min/large/bad
  (wall 0.300/0.216/0.233×, RSS 0.249/0.263/0.218×). Các khoảng min/max
  không giao nhau ở những mục này (RSS và size ổn định; wall tuyệt đối
  vẫn là wall-clock — xem §2).
- Rust **nhanh hơn Go** ở độ trễ 1 request loopback qua SOCKS5
  hand-roll: 0.713 ms/req vs 0.782 ms/req (0.91×, 1.10× nhanh hơn) —
  ĐẢO CHIỀU LẦN NỮA so với run9 (4.19×, Rust chậm hơn, tải cao).
  Plateau 4 ms của run9 không tái lập dưới tải thấp — nhiều khả năng
  là artifact theo tải, không phải hồi quy thật. Số này đo harness,
  không phải outbound thật (item 5 không có cột full).
- Lợi thế parse-large (6.6×) và render (6.1×) một phần là do Go làm
  nhiều việc hơn (validate sâu, alloc churn) và Rust defer validation —
  và tỉ lệ run10 thấp hơn run9 vì Go nhanh lại dưới tải thấp (số Go ở
  4 item lớn giảm 31–55% so với run9 trong khi số Rust ổn định trong
  ±7%) — không phải toàn bộ là "Rust nhanh hơn". Đo lại sau khi Rust
  bổ sung validation, và đừng trích tỉ lệ §4 mà không kèm caveat tải.
- Con số cũ "77.5× nhỏ hơn" (run7, shell vs Go full) vẫn đúng về mặt
  số học nhưng **không còn là headline** — nó so hai thứ khác nhau.
  Headline từ run10 là 0.363× (2.75×) của rust-full (giữ nguyên so
  với run9); headline run8 0.260× (3.84×) là số của cây cũ pre-rebase,
  giữ trong mục Drift.

## Hotspot ưu tiên (tối đa 7, sắp theo lợi ích/chi phí)

1. **Rust parse-large: validation chiếm 66% thời gian parse.**
   Bằng chứng số: parse-large 1,130 µs vs decode-alone 383 µs cùng
   input (32,246 B) — validation + build struct ≈ 747 µs. Lợi ích ước
   lượng: đưa validation về gần tốc độ decode → parse-large ~500–600 µs
   (~2×), với giả định validation+build rút về ~100–200 µs (chưa đo)
   và floor là 383 µs decode (không thể nhanh hơn decode). Chi phí sửa:
   trung bình (code trong `castctl-config/src/config.rs`, validation
   order + error message bị test parity ghim). Rủi ro: phá parity
   byte-for-byte của thông báo lỗi. Chỉ làm sau khi có profile chi tiết
   hơn (hiện không có `perf` trên cue).
2. **Rust `md_to_html` chiếm 81% render chain.** Bằng chứng số:
   `md_to_html` 862 µs vs render-chain 1,068 µs cùng input 51,560 B;
   split trong chain suy ra ≈ 206 µs (1,068 − 862) trên HTML, khác với
   262 µs đo split trên markdown thô — hai input khác nhau, không cộng
   trực tiếp được. Go tương ứng 5,727 µs với 8,388 allocs/op — phía Rust
   chưa đếm được alloc. Lợi ích: giảm số pass regex / allocation trong
   `inline_html` (`castctl-tg-text`, stash + `replace_all` nhiều lượt).
   Chi phí: trung bình. Rủi ro: parity `MDToHTML` (test M1 ghim output
   từng case).
3. **`split_text_limit` collect toàn bộ input thành `Vec<char>` trước.**
   Bằng chứng cấu trúc (không phải profile): `lib.rs` collect
   `text.chars()` rồi mới cắt; số đo: 262 µs cho 51,560 B (Go 544 µs).
   Lợi ích: nhỏ–vừa (bỏ 1 alloc lớn + pass char). Chi phí: trung bình
   (ngữ nghĩa cắt/fence-carry bị test ghim chặt). Rủi ro: đổi hành vi
   cắt ở biên. Đo alloc trước khi sửa.
4. **Lợi thế parse-large sẽ thu hẹp khi Rust bổ sung sing-box validation
   (D-M2-1) — đo lại, đừng tối ưu trước.** Bằng chứng số: Go parse-large
   7.50 ms vs Rust 1.13 ms nhưng Go validate 180 outbound + 10 endpoint
   sâu (52,162 allocs/op); Rust defer. Thêm nữa, tỉ lệ run9 phồng lên
   vì Go chậm đi dưới tải (xem §4) — tỉ lệ run10 (0.15×) đã về gần mức
   run8. Lợi ích: tránh tối ưu sai chỗ +
   tránh ngạc nhiên khi validation hạ cánh. Chi phí: thấp (chỉ đo lại).
   Rủi ro: không có — đây là follow-up đo, không phải sửa code.
5. **Startup của rust-full: 2.4 ms, không đáng tối ưu thêm lúc này.**
   Bằng chứng số: full `--version` 2.391 ms (shell 2.405 ms — full
   NHANH hơn shell 0.014 ms, trong sai số; closure lớn hơn không tốn
   thêm thời gian đo được); phần lớn còn lại là spawn process +
   dynamic loader + scheduling (hyperfine đo full `--version` 1.98 ms,
   shell 1.86 ms — hai phương pháp khớp trong 9–29%, xem §2). Lợi ích
   tối đa ~1 ms tuyệt đối. Chi phí:
   thấp–trung bình (`-C target-cpu=native` bị CẤM ở PR này; static
   musl đổi cả toolchain). Rủi ro: đổi ABI/link. Để sau, khi binary
   lớn hơn.
6. **Kích thước binary: LTO co thêm 19.1% nhưng không đổi headline.**
   Bằng chứng số: full headline 17,475,048 B, LTO 14,137,784 B
   (`.text` 11,123,948 → 9,644,252 B); shell 17,440,616 B. Lợi ích thêm
   (`codegen-units=1` / `panic=abort`): vài chục KB, không đáng kể so
   với 0.363× hiện tại. Chi phí: thấp nhưng `panic=abort` đổi hành vi
   crash. Rủi ro: thấp. Chỉ xem lại khi Rust port thêm crate nặng
   (bot/keeper/webui ở M7 sẽ làm binary lớn hơn nhiều — đo lại ở đó).
7. **Item 5 đảo chiều lần nữa — không còn là hotspot tối ưu, chỉ còn
   là caveat theo tải.** Bằng chứng số: item 5 Rust 0.713 ms vs Go
   0.782 ms ở run10 (run9: 3.973 vs 0.948, tải cao; run8: 0.872 vs
   0.885, trong sai số), và cả hai đều qua proxy Python + `http.server`
   Python. Plateau 4 ms của run9 không tái lập dưới tải thấp — câu
   hỏi probe của run9 đã có đáp án hướng tải, không phải hồi quy Rust.
   Cơ chế chính xác (contention dưới-phút) vẫn chưa chứng minh — ghi
   trong Chưa kiểm chứng, không mở probe mới. Đo lại bằng outbound
   thật (honk/sing-box, M3) + gateway thật (M4a) trước khi đụng tới
   client hand-roll. Chi phí: thấp (chỉ đo). Rủi ro: tối ưu sai tầng.

## Output lần chạy thật (run10 — tóm tắt, KHÔNG nguyên văn)

```
$ sh rust/perf/run.sh   # trên cue, repo root, không flag
... (shell build: plain 154.8 s, strip 160.4 s; full build: plain 155.4 s, nokeep 9.0 s, strip 1.1 s) ...
hyperfine --version:  Go median 8.61 ms vs shell 1.86 ms vs full 1.98 ms
hyperfine --help:     Go median 8.41 ms vs shell 2.00 ms vs full 1.97 ms
summary.json: date 2026-11-05T21:45:03Z, commit fbaa0d7, machine cue 8x Xeon 2.50GHz,
  MemTotal 24788940 kB, SwapTotal 0 kB, go 0.9.0 (1396697), cargo 1.99.1,
  go 1.27.3, hyperfine 1.18.0, loadavg start 0.98 / mid 5.46 / end 1.69,
  disk / 13.05 -> 8.48 GiB
item5: status measured, rust 0.713 ms/req (0.705-0.787),
  go 0.782 ms/req (0.754-0.803); setup 1.5 s, measure 8.7 s
full-bin LTO build exit 0 (257.6 s, 14,137,784 B, sha 3ff9948c...)
SPDX check: FAIL (advisory only, rerun unaffected; see /tmp/perf0-spdx-check-3HTKoV.log)
```

Stdout thật đầy đủ: `rust/perf/data/run10-stdout.txt` (154,616 B — chính
là JSON dump của `summary.json` (154,526 B) cộng
dòng `SPDX check: FAIL …` (90 B); JSON trong log khớp byte với
`summary.json` đã commit, md5 `d42bfe24ca472d1ac80dfbacc1295b72`).
Dòng SPDX FAIL này là check advisory trong `run.sh` lúc rerun
(target dir đã chứa file `.go` của boring-sys sau build — 322 file
dưới `rust/target/release/`); gate SPDX chính thức PASS trên checkout
sạch, chạy TRƯỚC mọi build — xem Điều kiện đo. Đừng đọc dòng cuối file
stdout như gate fail. Số thô đầy đủ: `rust/perf/data/*.json` (mỗi file
ghi từng lần chạy, median/min/max/mean, exit code). Tái lập: chạy lại
lệnh trên rồi diff `data/summary.json` với file đã commit. Lưu ý: lần
chạy này KHÔNG có note nào trong summary (`notes: []`) — mọi phép đo
exit như kỳ vọng, LTO driver exit 0. `summary.json` của run10 KHÔNG
còn key `rust_full_binary_after_lto_restore` (key này có trong summary
run8, cùng size+sha với `rust_full_binary`, mà driver code không sinh
ra được — artifact của driver lúc chạy run8; xem mục "Vì sao có run9").

## Dao động giữa các lần chạy (run4 → run5 → run6 → run7 → run8 → run9 → run10, median)

Run5 dùng driver trung gian của fix loop 1 (vòng poll WNOHANG gây lượng
tử hoá wall 5 ms + RSS floor) nên số startup/RSS của nó KHÔNG dùng
được — driver đó không phải phương pháp của run4 (run4 dùng `wait4`
blocking, wall đúng, xem phần mở đầu); run6 dùng target dir còn ấm nên
thời gian build của nó không phải full build. Chỉ item 4/5 (đo bằng
harness nội bộ, không qua `measure.py`) so sánh được xuyên suốt cả
7 run. Summary run5 (`2026-11-05T12:05:39Z`) và run6
(`2026-11-05T12:14:07Z`) được commit ở `data/run5-summary.json` /
`data/run6-summary.json` để đối chiếu từng ô trong bảng này; run7 ở
`data/run7-summary.json`, run8 ở `data/run8-summary.json`, run9 ở
`data/run9-summary.json`, run10 là `data/summary.json` hiện tại.
Fixture parse-large đổi ở run5 (25,657 B /
140 outbounds → 32,246 B / 180 outbounds + 10 endpoints) nên
parse-large/decode-large tăng theo kích thước fixture, không phải drift
máy.

| Tác vụ | run4 | run5 | run6 | run7 | run8 | run9 | run10 |
|---|---|---|---|---|---|---|---|
| Parse min Go / Rust (ns) | 5,882 / 2,517 | 4,529 / 2,554 | 4,494 / 2,539 | 4,511 / 2,553 | 4,548 / 2,512 | 4,418 / 2,559 | 4,440 / 2,499 |
| Parse large Go / Rust (ms) | 5.11 / 0.934 | 6.96 / 1.160 | 7.01 / 1.169 | 7.15 / 1.163 | 7.35 / 1.178 | 12.42 / 1.166 | 7.50 / 1.130 |
| MDToHTML Go / Rust (ms) | 4.62 / 0.873 | 5.00 / 0.869 | 5.43 / 0.878 | 5.41 / 0.872 | 5.34 / 0.886 | 12.11 / 0.921 | 5.73 / 0.862 |
| SplitText Go / Rust (µs) | 518 / 266 | 593 / 271 | 606 / 271 | 551 / 281 | 555 / 271 | 790 / 272 | 544 / 262 |
| Render chain Go / Rust (ms) | 5.24 / 1.085 | 6.46 / 1.074 | 5.42 / 1.092 | 5.62 / 1.114 | 5.99 / 1.076 | 14.41 / 1.133 | 6.53 / 1.068 |
| Item 5 Go / Rust (ms/req) | 0.813 / 0.756 | 0.810 / 0.729 | 0.858 / 0.929 | 0.874 / 0.830 | 0.885 / 0.872 | 0.948 / **3.973** | 0.782 / **0.713** |
| Startup `--version` tỉ lệ shell/Go | 0.088 | (sai: wall lượng tử hoá) | 0.087 | 0.081 | 0.081 | 0.237 | 0.239 |
| Startup `--version` tỉ lệ full/Go | — | — | — | — | **0.179** | **0.242** | **0.238** |
| RSS `--version` Go / shell / full (MiB) | 43.5 / (sai: floor) / — | 30.5 / (sai: floor) / — | 30.4 / 2.14 / — | 30.4 / 2.14 / — | 30.3 / 2.20 / **5.42** | 30.3 / 6.12 / **6.23** | 30.4 / 6.11 / **6.20** |
| Binary stripped Go / shell / full (MB) | — | — | — | 48.10 / 0.62 / — | 48.10 / 0.62 / **12.53** | 48.10 / 17.45 / **17.48** | 48.10 / 17.44 / **17.48** |

Đọc: số Rust ở item 4 ổn định xuyên suốt (dao động ≤7% quanh median
các run, trừ parse-large tăng theo fixture); số Go dao động nhiều hơn
theo tải máy (MDToHTML +17% run4→run7, parse-min −23%). Tỉ lệ startup
shell/Go 0.081–0.088 ở run4–run8, nhưng rerun độc lập đo 0.109 (wall Go
nhanh hơn 23–27% dù tải cao hơn — chưa giải thích được, xem bên dưới);
thời gian tuyệt đối drift +34% (Go) và +23% (Rust) run4→run7 theo tải.
Item 5 dao động run-to-run cả hai phía và tỉ lệ đổi dấu theo tải
(run4–run8: 0.90–1.08, "trong sai số"; run9: 4.19 dưới tải cao;
run10: 0.91 dưới tải thấp) — xem "Run10 so với run9" bên dưới.
RSS Go `--version` **không** ổn định: bimodal theo session — 30.4 MiB ở
run5–run10, 43.5 MiB ở run4, 47.7 MiB ở rerun độc lập; tỉ lệ RSS
shell/Go dao động 0.046–0.073 theo session với shell tiền-M4b (~2.2 MiB);
với shell run9/run10 (~6.1 MiB) khoảng đó là 0.128–0.202 (xem §3). Run8 khớp run7
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
RSS), run8 chỉ 2.24→7.73→6.09. Số Rust §4 ổn định trong ±6% (parse-min
+1.9%, parse-large −1.1%, md-to-html +3.9%, split +0.5%, render
+5.3%), nhưng số Go §4 ở 4 item lớn tăng 1.4–2.4× (parse-large +69%, MDToHTML
+127%, render +140%, split +42%; min của Go parse-large 7.01M ≈
median run8 — tải tăng dần giữa bench). Wall startup: Go `--version`
+119% (10.63→23.24 ms) nhưng `--help` −15% (10.86→9.20 ms) trong
cùng một run; shell `--version` +535% (0.87→5.51 ms), full +195%
(1.90→5.62 ms) — Go `--version` và `--help` lệch hướng nhau chứng tỏ
wall 1–20 ms ở run9 bị scheduling jitter chi phối, không phải tốc độ
thật; hyperfine cũng lệch với driver ở run9 (Go `--version` hyperfine
10.7 ms vs driver 23.2 ms; full 7.1 vs 5.6 ms), ngược với run8 khi hai
phương pháp đồng thuận. RSS Go ổn định ±1% ở mọi ô trừ status-min
(−1.5%) (mode thấp) — RSS là metric đáng tin nhất của run9. Item 5 là drift lớn nhất:
Rust 0.872→3.973 ms/req (+356%), tỉ lệ 0.99→4.19, đảo chiều kết
luận; Go chỉ +7.1% (0.885→0.948). **Hướng kết luận đổi ở đúng hai
chỗ so với run8: item 5 (Rust nay chậm hơn) và headline size
(0.260×→0.363×); mọi headline khác giữ hướng (Rust nhanh hơn), chỉ
tỉ lệ wall nhiễu hơn do tải.**

**Run10 so với run9 (tải thấp, cây M4c/M5a):** (a) Cây mới: shell
binary 17.45→17.44 MB (−6,080 B), full 17.48→17.48 MB (−5,984 B,
−0.03%); tỉ lệ headline giữ nguyên 0.363× (2.75×). RSS `--version`
ổn định trong ±0.5% ở cả ba phía (Go 30.35→30.37, shell 6.12→6.11,
full 6.23→6.20 MiB); RSS `status` ổn định trong ±2% ở mọi ô. (b) Tải:
run10 chạy dưới loadavg 0.98→5.46→1.69 (run9: 4.79→9.40→18.05). Wall
startup về gần mức run8 (tải thấp): Go `--version` 23.24→10.05 ms
(−57%), full 5.62→2.39 ms (−57%); tỉ lệ gần như giữ nguyên (full/Go
0.242→0.238) — ngoại lệ: `--help` phía Rust 1.889→2.247 ms (+19%)
trong khi Go `--help` đứng yên 9.201→9.193 ms, nên tỉ lệ `--help`
full/Go 0.205→0.244 (+19%); nguyên nhân chưa rõ (phân phối tách rõ:
15/20 lượt run10 nằm trên max run9 2.072 ms; 0/20 lượt run9 nằm trên
median run10 2.247 ms; min–max run10 rộng hơn: 1.852–3.064 ms so với
run9 1.733–2.072 ms — ghi nhận, không giải thích). Driver khớp hyperfine trong 9–29% ở run10 (run9 lệch tới 2×).
(c) §4: số Go ở 4 item lớn giảm 31–55% (parse-large 12.42→7.50 ms,
MDToHTML 12.11→5.73 ms, render 14.41→6.53 ms, split 790→544 µs) — về
gần mức run8; số Rust ổn định trong ±7% (parse-large −3.1%,
md-to-html −6.4%, render −5.7%, split −3.6%, min −2.3%). Tỉ lệ §4 về
gần mức run8 (large 0.15 vs run8 0.16, MDToHTML 0.15 vs 0.17, render
0.16 vs 0.18, split 0.48 vs 0.49, min 0.56 vs 0.55). (d) Item 5 là
drift lớn nhất theo hướng ngược: Rust 3.973→0.713 ms/req (−82%), tỉ
lệ 4.19→0.91, ĐẢO CHIỀU LẦN NỮA; Go 0.948→0.782 (−17.5%). Plateau 4
ms của run9 không tái lập dưới tải thấp. **Hướng kết luận đổi ở đúng
một chỗ so với run9: item 5 (Rust nay nhanh hơn); mọi headline khác
giữ hướng (Rust nhanh hơn), tỉ lệ wall ổn định hơn nhờ tải thấp.**

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
- `data/` — số thô các lần chạy (run10 là số trong bảng trên;
  `run10-stdout.txt` là stdout thật của run10, 154,616 B, JSON trong log
  khớp byte với `summary.json` hiện tại, md5
  `d42bfe24ca472d1ac80dfbacc1295b72`; `run9-summary.json` là summary
  đầy đủ của run9 để đối chiếu bảng Drift (md5
  `9d84a70fe125e6fc9652c022146fb56e`); `run8-summary.json` là summary
  đầy đủ của run8 (md5 `90730fd5a0b1265097c27d54d1eefe88`);
  `run7-summary.json` là summary đầy đủ của run7;
  `run5-summary.json` / `run6-summary.json` là summary
  đầy đủ của run5/run6; `verify-rerun-summary.json` là summary đầy đủ
  của rerun độc lập (2026-11-05T14:26:32Z) để đối chiếu drift;
  `nm-counts.json` / `lto-build-record.json` / `behaviour-checks.json`
  là record của run10 (rebuild + `nm` + behaviour checks trên cue,
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
- Số RSS Go `--version` bimodal theo session: 30.3–30.5 MiB (run5–run10) vs
  43.5 MiB (run4) vs 47.7 MiB (rerun độc lập,
  `data/verify-rerun-summary.json`); nguyên nhân chưa rõ (giả thuyết
  THP chưa kiểm chứng — `AnonHugePages` 0 kB lúc probe; env cô lập
  không phải nguyên nhân theo probe của verifier). Số RSS Go trong
  bảng là số run10 (mode thấp); tỉ lệ RSS rust-full/Go theo session
  dao động (run10: 0.204; mode cao Go 47.7 MiB → ~0.130). Wall startup
  Go cũng drift −23…−27% ở rerun độc lập dưới tải cao hơn — chưa giải
  thích được; ở run10 driver khớp hyperfine trong 9–29% (tốt hơn nhiều
  so với run9 lệch tới 2×) — wall tuyệt đối 1–10 ms vẫn là wall-clock,
  xem §2.
- First measured run run10 (n=1): wall cao bất thường ở Go và shell so
  với median (Go 5.9×, shell 8.1×, full 1.5×) — cơ chế có thể là page
  cache bị build full-bin đẩy ra, chưa chứng minh; không dùng làm kết
  luận.
- Hyper client machinery: gap run8 ĐÃ ĐÓNG — hyper có 536 symbol trong
  cả ba binary run10 (keep/shell/nokeep), xem mục `rust-full`; rust-full
  không còn là lower bound ở chỗ này.
- Item 5 đảo chiều lần nữa (Rust 3.973→0.713 ms/req, tỉ lệ 4.19→0.91) —
  plateau 4 ms của run9 không tái lập dưới tải thấp (run10 loadavg
  0.98–5.46 so với run9 4.79–18.05), nhiều khả năng là artifact theo
  tải; cơ chế chính xác (contention dưới-phút) vẫn chưa chứng minh.
  Không dùng số này để kết luận về outbound thật — item 5 đo harness,
  không phải honk/sing-box.
- Tái lập sha256 phụ thuộc đường dẫn checkout (đã chứng minh ở run9):
  rebuild từ checkout khác (`/tmp/perf2-alt-checkout`, cùng target dir
  `/tmp/perf-full-target`) cho cùng size 17,481,032 B nhưng sha khác
  (`f7f898e5…` thay vì `b12911a5…`) — 19 đường dẫn nguồn tuyệt đối
  `file!()` + 1 hash cargo metadata trong binary. Reproduce check chỉ
  tái lập sha khi checkout ở cùng path; size 17,475,048 B (run10) ổn
  định ở pinned path và là cross-check bền. Cơ chế bù size khi độ dài
  path đổi (±584 B string mà `.rodata` không đổi) chưa giải thích
  được — chỉ ghi nhận.
- Anomaly (4b) — ĐÃ GIẢI QUYẾT ở fix loop 1 (xem mục "Tái lập sha"):
  lần đầu khớp sha Boss `7f816189…` là đo nhiễm — target dir
  `/root/v66b-target` không xoá trước nên cargo reuse artifact của
  Boss (bằng chứng quyết định đã mất cùng `rm -rf` sau đó). Probe
  quyết định (recreate `/tmp/v66/c` ở `3ba3d6a` + lock regenerate,
  `rm -rf` target dir, đúng lệnh Boss) tái lập đúng `7f816189…` — sha
  là hàm xác định của (checkout path, target dir), không bất ổn theo
  thời gian. Câu "không ổn định" ở bản trước bị rút lại. Chỉ sha ở
  pinned path `/tmp/perf-full-target` (tái lập 4×) được dùng trong
  Reproduce check.
- Kiểm tra `nm` trên binary LTO không chạy trực tiếp được (profile
  strip symbols); giữ-link ở LTO chỉ được chứng minh gián tiếp qua
  `.text` + cơ chế `#[used]` static (xem mục `rust-full`; record build
  LTO đầy đủ trong `data/lto-build-record.json` — size 14,137,784 B,
  `.text` 9,644,252 B, `--version` exit 0).
- Run5/run6 được commit ở `data/run5-summary.json` /
  `data/run6-summary.json` để đối chiếu drift; run7 ở
  `data/run7-summary.json`; run8 ở `data/run8-summary.json`; run9 ở
  `data/run9-summary.json`;
  rerun độc lập được commit ở
  `data/verify-rerun-summary.json`; chỉ run10 là baseline chính thức.
