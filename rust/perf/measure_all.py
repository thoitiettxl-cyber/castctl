#!/usr/bin/env python3
"""M-perf-0 driver: run every measurement, write rust/perf/data/*.json.

Run from the repo root:  sh rust/perf/run.sh
or:  python3 rust/perf/measure_all.py [--skip-build] [--skip-item5]
Environment on cue: cargo +1.99.1, Go via PATH=/usr/local/go/bin:$PATH
GOTOOLCHAIN=auto. All numbers are produced by this script; nothing here
is hand-typed. Interleaving: Go/Rust runs alternate within each item
(measure.py runs one binary at a time, so the driver alternates the
invocations run-by-run via --runs 1 loops where it matters — in
practice the two binaries are measured in adjacent batches; loadavg
before/after each item is recorded).
"""
import hashlib, json, os, re, shutil, statistics, subprocess, sys, time

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
PERF = os.path.join(ROOT, "rust", "perf")
DATA = os.path.join(PERF, "data")
FIX = os.path.join(PERF, "fixtures")
GO_BIN = os.environ.get("PERF_GO_BIN", "/usr/local/bin/castctl")
RS_BIN = os.path.join(ROOT, "rust", "target", "release", "castctl-rs")
RS_BENCH = os.path.join(PERF, "bench", "target", "release", "perf-bench")
CARGO = ["cargo", "+1.99.1"]
GO_ENV = dict(os.environ, PATH="/usr/local/go/bin:" + os.environ.get("PATH", ""),
              GOTOOLCHAIN="auto", GOFLAGS="-mod=readonly")

def sh(cmd, env=None, cwd=None, timeout=1800):
    t0 = time.time()
    p = subprocess.run(cmd, env=env, cwd=cwd, capture_output=True, text=True, timeout=timeout)
    return {"cmd": cmd, "exit": p.returncode, "seconds": round(time.time() - t0, 1),
            "stdout": p.stdout[-4000:], "stderr": p.stderr[-4000:]}

def sha8(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

def stats(vals):
    return {"n": len(vals), "median": statistics.median(vals), "min": min(vals),
            "max": max(vals), "mean": statistics.mean(vals)}

def isolated_env():
    # Scratch HOME/XDG under the OS temp dir, NOT under data/: Go writes
    # telemetry caches into XDG and they would pollute the committed data.
    import tempfile
    home = tempfile.mkdtemp(prefix="perf0-home-")
    xdg = tempfile.mkdtemp(prefix="perf0-xdg-")
    os.makedirs(home, exist_ok=True); os.makedirs(xdg, exist_ok=True)
    env = dict(os.environ, LC_ALL="C", TZ="UTC", HOME=home, XDG_CONFIG_HOME=xdg)
    env.pop("CASTCTL_CONFIG", None); env.pop("CASTCTL_PROFILE", None)
    return env

def measure(label, argv, runs=20, warmup=5):
    out = os.path.join(DATA, label + ".json")
    env = isolated_env()
    p = subprocess.run([sys.executable, os.path.join(PERF, "measure.py"),
                        "--runs", str(runs), "--warmup", str(warmup),
                        "--out", out, "--label", label, "--"] + argv,
                       env=env, capture_output=True, text=True, timeout=600)
    try:
        return json.load(open(out))
    except Exception:
        return {"label": label, "error": p.stdout + p.stderr, "exit": p.returncode}

def loadavg():
    return open("/proc/loadavg").read().strip()

def main():
    skip_build = "--skip-build" in sys.argv
    skip_item5 = "--skip-item5" in sys.argv
    os.makedirs(DATA, exist_ok=True)
    summary = {"date": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
               "machine": {}, "items": {}, "notes": []}
    m = sh(["uname", "-a"]); summary["machine"]["uname"] = m["stdout"].strip()
    summary["machine"]["nproc"] = sh(["nproc"])["stdout"].strip()
    summary["machine"]["loadavg_start"] = loadavg()
    summary["machine"]["go_version"] = sh(["go", "version"], env=GO_ENV)["stdout"].strip()
    summary["machine"]["cargo_version"] = sh(CARGO + ["--version"], cwd=os.path.join(ROOT, "rust"))["stdout"].strip()
    summary["machine"]["rustc_version"] = sh(["rustc", "+1.99.1", "--version"])["stdout"].strip()
    summary["machine"]["df_root"] = sh(["df", "-h", "/"])["stdout"].strip()
    summary["machine"]["go_binary"] = {"path": GO_BIN, "size_bytes": os.path.getsize(GO_BIN),
        "sha256": sha8(GO_BIN), "version": sh([GO_BIN, "--version"])["stdout"].strip()}

    # ---- build Rust: plain release (unstripped size), then RUSTFLAGS strip
    if not skip_build:
        b1 = sh(CARGO + ["build", "--release", "--locked", "-p", "castctl-rs"],
                cwd=os.path.join(ROOT, "rust"), timeout=3600)
        summary["build_plain"] = b1
        if b1["exit"] != 0:
            summary["notes"].append("plain release build FAILED; see build_plain")
            json.dump(summary, open(os.path.join(DATA, "summary.json"), "w"), indent=2)
            print(json.dumps(summary, indent=2)); return 2
        plain = RS_BIN + "-plain"
        shutil.copyfile(RS_BIN, plain)
        summary["rust_unstripped"] = {"size_bytes": os.path.getsize(plain), "sha256": sha8(plain)}
        shutil.copyfile(RS_BIN, plain + "-gnu")
        g = sh(["strip", plain + "-gnu"])
        summary["rust_gnu_stripped"] = {"size_bytes": os.path.getsize(plain + "-gnu"),
                                        "sha256": sha8(plain + "-gnu"), "strip": g}
        env = dict(os.environ, RUSTFLAGS="-C strip=symbols")
        b2 = sh(CARGO + ["build", "--release", "--locked", "-p", "castctl-rs"],
                cwd=os.path.join(ROOT, "rust"), env=env, timeout=3600)
        summary["build_stripped"] = b2
        if b2["exit"] != 0:
            summary["notes"].append("RUSTFLAGS strip build FAILED; using GNU-stripped binary as Rust binary")
            shutil.copyfile(plain + "-gnu", RS_BIN)
            summary["rust_strip_method"] = "gnu-strip-fallback"
        else:
            summary["rust_strip_method"] = "RUSTFLAGS=-C strip=symbols"
        summary["rust_binary"] = {"size_bytes": os.path.getsize(RS_BIN), "sha256": sha8(RS_BIN),
            "version": sh([RS_BIN, "--version"])["stdout"].strip()}
        for name, path in (("go", GO_BIN), ("rust", RS_BIN)):
            summary.setdefault("size_breakdown", {})[name] = sh(["size", "-A", path])["stdout"]
    else:
        summary["rust_binary"] = {"size_bytes": os.path.getsize(RS_BIN), "sha256": sha8(RS_BIN),
            "version": sh([RS_BIN, "--version"])["stdout"].strip()}
        plain = RS_BIN + "-plain"
        if os.path.exists(plain):
            summary["rust_unstripped"] = {"size_bytes": os.path.getsize(plain), "sha256": sha8(plain)}
            summary["rust_gnu_stripped"] = {"size_bytes": os.path.getsize(plain + "-gnu"),
                                            "sha256": sha8(plain + "-gnu")}
        summary["rust_strip_method"] = "RUSTFLAGS=-C strip=symbols (binary from earlier full run)"
        for name, path in (("go", GO_BIN), ("rust", RS_BIN)):
            summary.setdefault("size_breakdown", {})[name] = sh(["size", "-A", path])["stdout"]
        summary["notes"].append("build skipped (--skip-build)")

    # cold proxy: first run after build, no warmup (one shot each)
    cold = {}
    for name, path in (("go", GO_BIN), ("rust", RS_BIN)):
        cold[name] = measure("cold-first-run-" + name, [path, "--version"], runs=1, warmup=0)
    summary["items"]["cold_proxy_first_run_after_build"] = cold

    # ---- items 2+3: startup + RSS, interleaved batches
    items23 = {}
    for label, argv_go, argv_rs in [
        ("version", [GO_BIN, "--version"], [RS_BIN, "--version"]),
        ("help", [GO_BIN, "--help"], [RS_BIN, "--help"]),
    ]:
        items23[label] = {"go": measure("item2-" + label + "-go", argv_go),
                          "rust": measure("item2-" + label + "-rust", argv_rs)}
    summary["items"]["startup_rss"] = items23
    summary["machine"]["loadavg_mid"] = loadavg()

    # ---- item 3 parse-config: probe Go status offline first
    import tempfile
    cfgdir_min = tempfile.mkdtemp(prefix="perf0-cfgmin-")
    cfgdir_large = tempfile.mkdtemp(prefix="perf0-cfglarge-")
    cfgdir_bad = tempfile.mkdtemp(prefix="perf0 cfgbad-".replace(" ", ""))
    shutil.copyfile(os.path.join(FIX, "config-min.json"), os.path.join(cfgdir_min, "config.json"))
    shutil.copyfile(os.path.join(FIX, "config-large.json"), os.path.join(cfgdir_large, "config.json"))
    open(os.path.join(cfgdir_bad, "config.json"), "w").write("{invalid")
    try:
        probe = sh([GO_BIN, "--config", os.path.join(cfgdir_min, "config.json"), "status"], env=isolated_env(), timeout=15)
    except Exception as e:
        probe = {"exit": None, "seconds": 15, "stdout": "", "stderr": "probe exception: %s" % e}
    summary["go_status_probe"] = probe
    parse = {}
    if probe["exit"] is not None and probe["seconds"] < 10 and "panic" not in probe["stderr"].lower():
        parse["go_good_config"] = measure("item3-status-min-go", [GO_BIN, "--config", os.path.join(cfgdir_min, "config.json"), "status"])
        parse["go_large_config"] = measure("item3-status-large-go", [GO_BIN, "--config", os.path.join(cfgdir_large, "config.json"), "status"])
        parse["mode"] = ("good-config status: Go exits fast (exit %s, %.1fs) but NOT offline-clean: "
                         "it parses+validates, then fails fast on missing session/outbound "
                         "(see go_status_probe stderr); Rust reaches stub (exit 1). "
                         "Bad-config gate below is the clean apples-to-apples parse path." % (probe["exit"], probe["seconds"]))
    else:
        parse["mode"] = "bad-config parse gate only (Go status probe: exit=%s seconds=%s)" % (probe["exit"], probe["seconds"])
        summary["notes"].append("Go status with good config did not run offline cleanly; parse RSS uses bad-config gate")
    parse["rust_min"] = measure("item3-status-min-rust", [RS_BIN, "--config", os.path.join(cfgdir_min, "config.json"), "status"])
    parse["rust_large"] = measure("item3-status-large-rust", [RS_BIN, "--config", os.path.join(cfgdir_large, "config.json"), "status"])
    parse["rust_bad"] = measure("item3-status-bad-rust", [RS_BIN, "--config", os.path.join(cfgdir_bad, "config.json"), "status"])
    parse["go_bad"] = measure("item3-status-bad-go", [GO_BIN, "--config", os.path.join(cfgdir_bad, "config.json"), "status"])
    summary["items"]["parse_config_rss"] = parse

    # ---- item 4: pure logic
    item4 = {}
    gb = sh(["go", "test", "-bench", ".", "-benchtime=100x", "-count=5", "-run", "^$",
             "./rust/perf/go-bench/"], env=GO_ENV, cwd=ROOT, timeout=1200)
    item4["go_bench_raw"] = gb
    # parse `go test -bench` lines: BenchmarkX-8  100  12345 ns/op
    go_bench = {}
    for line in gb["stdout"].splitlines():
        mm = re.match(r"^(Benchmark\w+)-\d+\s+\d+\s+([\d.]+) ns/op", line.strip())
        if mm:
            go_bench.setdefault(mm.group(1), []).append(float(mm.group(2)))
    item4["go_ns_per_op"] = {k: stats(v) for k, v in go_bench.items()}
    bb = sh(CARGO + ["build", "--release", "--offline"],
            cwd=os.path.join(PERF, "bench"), timeout=1800)
    item4["rust_bench_build"] = bb
    rust_bench = {}
    if bb["exit"] == 0:
        for mode in ("parse-min", "parse-large", "decode-large", "md-to-html", "split-text", "render-chain"):
            vals = []
            for _ in range(5):
                r = sh([RS_BENCH, mode], timeout=300)
                try:
                    vals.append(json.loads(r["stdout"].strip().splitlines()[-1])["ns_per_iter"])
                except Exception:
                    vals.append(None)
            rust_bench[mode] = {"ns_per_iter_runs": vals,
                                "stats": stats([v for v in vals if v is not None]) if any(vals) else None}
    else:
        item4["notes"] = "Rust standalone bench crate FAILED to build; see rust_bench_build"
    item4["rust_ns_per_iter"] = rust_bench
    summary["items"]["pure_logic"] = item4
    summary["machine"]["loadavg_after_item4"] = loadavg()

    # ---- item 5: loopback SOCKS5, hard 20-min setup clock
    t5 = time.time()
    item5 = {"setup_deadline_s": 1200}
    # Pick a actually-free loopback port first: 18080 turned out to belong
    # to another session's server (pid 1666878, answers b"ok" to any path),
    # so a fixed port is unsafe. Bind port 0, take the assigned port.
    import socket as _sock
    _s = _sock.socket(); _s.bind(("127.0.0.1", 0)); http_port = _s.getsockname()[1]; _s.close()
    item5["http_port"] = http_port
    http_proc = subprocess.Popen([sys.executable, "-m", "http.server", str(http_port),
                                  "--bind", "127.0.0.1", "--directory", FIX],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    socks_proc = subprocess.Popen([sys.executable, os.path.join(PERF, "socks5.py"),
                                   "--listen", "127.0.0.1", "--port", "1080"],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        time.sleep(1.5)
        up = sh(["ss", "-ltn"], timeout=30)
        item5["listeners"] = up["stdout"]
        # Verify the HTTP origin really serves OUR 1024-byte body (not a
        # foreign server squatting on the port) before trusting any client.
        import socket as _sock2
        try:
            _c = _sock2.create_connection(("127.0.0.1", http_port), timeout=5)
            _c.sendall(b"GET /body-1024.bin HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            _raw = b""
            while True:
                _chunk = _c.recv(4096)
                if not _chunk:
                    break
                _raw += _chunk
            _c.close()
            _body = _raw.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in _raw else b""
            item5["origin_check"] = {"raw_len": len(_raw), "body_len": len(_body),
                                     "body_ok": _body == b"x" * 1024}
        except Exception as e:
            item5["origin_check"] = {"error": str(e)}
        if "1080" not in up["stdout"] or str(http_port) not in up["stdout"]:
            item5["status"] = "chua kiem chung duoc: listener not up within setup window"
        elif not item5.get("origin_check", {}).get("body_ok"):
            item5["status"] = "chua kiem chung duoc: HTTP origin check failed (see origin_check)"
        elif time.time() - t5 > 1200:
            item5["status"] = "chua kiem chung duoc: 20-min setup budget exceeded"
        else:
            env5 = dict(isolated_env(), PERF_SOCKS5_ADDR="127.0.0.1:1080",
                        PERF_HTTP_ADDR=f"127.0.0.1:{http_port}", PERF_SOCKS5_RUNS="20")
            rust5, go5 = [], []
            for _ in range(5):
                r = sh([RS_BENCH, "socks5-get"], env=env5, timeout=120)
                try:
                    rust5.append(json.loads(r["stdout"].strip().splitlines()[-1])["ms_per_request"]["median"])
                except Exception:
                    rust5.append(None)
            go5_raw = []
            import tempfile as _tf
            for _ in range(5):
                out5 = os.path.join(_tf.gettempdir(), "perf0-item5-go-run.json")
                # NOTE: do NOT use the isolated HOME here: Go with
                # GOTOOLCHAIN=auto resolves its toolchain/module cache
                # under $HOME/go; an isolated HOME makes `go test` try
                # to re-download the toolchain (and fail/slow). The Go
                # SOCKS client reads no castctl config, so real HOME is
                # correct for it (probe 2026-11-05: isolated HOME was
                # why all 5 driver Go runs returned None while the
                # manual run with real HOME passed).
                env_go5 = dict(GO_ENV, PERF_SOCKS5_ADDR="127.0.0.1:1080",
                               PERF_HTTP_ADDR=f"127.0.0.1:{http_port}",
                               PERF_SOCKS5_RUNS="20", PERF_OUT=out5)
                r = sh(["go", "test", "-run", "TestSocks5Get", "-count=1", "-v",
                        "./rust/perf/go-bench/"], env=env_go5, cwd=ROOT, timeout=300)
                go5_raw.append({"exit": r["exit"], "stdout_tail": r["stdout"][-500:],
                                "stderr_tail": r["stderr"][-500:]})
                try:
                    go5.append(json.load(open(out5))["ms_per_request"]["median"])
                except Exception:
                    go5.append(None)
            item5["go_runs_raw"] = go5_raw
            if not any(rust5) and not any(go5):
                item5["status"] = "chua kiem chung duoc: both clients failed (see runs: all None)"
            else:
                item5["status"] = "measured"
            item5["rust_ms_per_request_runs"] = rust5
            item5["go_ms_per_request_runs"] = go5
            item5["rust_stats"] = stats([v for v in rust5 if v is not None]) if any(rust5) else None
            item5["go_stats"] = stats([v for v in go5 if v is not None]) if any(go5) else None
            item5["setup_seconds"] = round(time.time() - t5, 1)
    finally:
        http_proc.terminate(); socks_proc.terminate()
        try: http_proc.wait(timeout=5)
        except Exception: http_proc.kill()
        try: socks_proc.wait(timeout=5)
        except Exception: socks_proc.kill()
    summary["items"]["transport_loopback"] = item5

    # ---- hyperfine cross-check (only if installed)
    hf = shutil.which("hyperfine")
    summary["hyperfine"] = {"present": bool(hf)}
    if hf:
        for label, args in (("version", ["--version"]), ("help", ["--help"])):
            r = sh([hf, "--warmup", "5", "--runs", "20", "--export-json",
                    os.path.join(DATA, f"hyperfine-{label}.json"),
                    f"{GO_BIN} {' '.join(args)}", f"{RS_BIN} {' '.join(args)}"], timeout=600)
            summary["hyperfine"][label] = {"exit": r["exit"], "stdout": r["stdout"][-2000:]}
    summary["machine"]["loadavg_end"] = loadavg()
    json.dump(summary, open(os.path.join(DATA, "summary.json"), "w"), indent=2)
    print(json.dumps(summary, indent=2))
    return 0

if __name__ == "__main__":
    sys.exit(main())
