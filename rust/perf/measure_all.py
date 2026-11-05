#!/usr/bin/env python3
"""M-perf-0 driver: run every measurement, write rust/perf/data/*.json.

Run from the repo root:  sh rust/perf/run.sh
or:  python3 rust/perf/measure_all.py [--skip-build] [--skip-item5]
Environment on cue: cargo +1.99.1, Go via PATH=/usr/local/go/bin:$PATH
GOTOOLCHAIN=auto. All numbers are produced by this script; nothing here
is hand-typed.
Run order (NOT interleaved): within each item the two sides are measured
in adjacent batches (all Go runs, then all Rust runs, or vice versa where
noted). Item 5 runs Rust first, then Go. Loadavg + timestamp are recorded
before/after each item and each side in summary["marks"], so any drift
between batches is visible in the committed data.
"""
import hashlib, json, os, re, shutil, statistics, subprocess, sys, tempfile, time

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
PERF = os.path.join(ROOT, "rust", "perf")
DATA = os.path.join(PERF, "data")
FIX = os.path.join(PERF, "fixtures")
GO_BIN = os.environ.get("PERF_GO_BIN", "/usr/local/bin/castctl")
# Build outputs honour CARGO_TARGET_DIR when set (cargo's own variable):
# with it unset the binary lands in rust/target/release/ as usual; with it
# set (e.g. CARGO_TARGET_DIR=/dev/shm/perf0-target on a full disk) both the
# workspace build and the bench-crate build share that target dir, and the
# driver looks for the binaries there. The value is recorded in the summary.
_TARGET_DIR = os.environ.get("CARGO_TARGET_DIR")
RS_BIN = os.path.join(_TARGET_DIR or os.path.join(ROOT, "rust", "target"),
                      "release", "castctl-rs")
RS_BENCH = os.path.join(_TARGET_DIR or os.path.join(PERF, "bench", "target"),
                        "release", "perf-bench")
# Full-stack binary (M-perf-1): rust/perf/full-bin is a standalone crate
# whose build compiles boring-sys (which generates .go files under its
# target dir). TestSPDXHeaders walks the whole repo, so that target dir
# MUST live outside the repo: it shares CARGO_TARGET_DIR when set (same
# rule as RS_BIN), otherwise a stable path under the system temp dir
# (operator-managed, like CARGO_TARGET_DIR itself — it persists across
# runs so --skip-build works; whether it was cold is recorded in the
# summary as full_target_cold). Never default to
# rust/perf/full-bin/target (inside the repo).
_FULL_TARGET_DIR = _TARGET_DIR or os.path.join(
    tempfile.gettempdir(), "perf-full-target")
RS_FULL_BIN = os.path.join(_FULL_TARGET_DIR, "release", "castctl-full")
FULL_BIN_MANIFEST = os.path.join(PERF, "full-bin", "Cargo.toml")
CARGO = ["cargo", "+1.99.1"]
GO_ENV = dict(os.environ, PATH="/usr/local/go/bin:" + os.environ.get("PATH", ""),
              GOTOOLCHAIN="auto", GOFLAGS="-mod=readonly")

def _trunc(s, head=2000, tail=2000):
    # Keep both ends: the head holds the identifying lines (binary path,
    # version, first records), the tail the summary. A tail-only cut
    # silently lost the head of `go version -m` output in run7 (see README).
    if len(s) <= head + tail:
        return s
    return s[:head] + "\n[...truncated...]\n" + s[-tail:]

def sh(cmd, env=None, cwd=None, timeout=1800):
    t0 = time.time()
    p = subprocess.run(cmd, env=env, cwd=cwd, capture_output=True, text=True, timeout=timeout)
    return {"cmd": cmd, "exit": p.returncode, "seconds": round(time.time() - t0, 1),
            "stdout": _trunc(p.stdout), "stderr": _trunc(p.stderr)}

def sha8(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

def stats(vals):
    return {"n": len(vals), "median": statistics.median(vals), "min": min(vals),
            "max": max(vals), "mean": statistics.mean(vals)}

def loadavg():
    return open("/proc/loadavg").read().strip()

def meminfo():
    out = {}
    for line in open("/proc/meminfo"):
        k, _, v = line.partition(":")
        if k in ("MemTotal", "SwapTotal"):
            out[k] = v.strip()
    return out

def isolated_env():
    # Scratch HOME/XDG under the OS temp dir, NOT under data/: Go writes
    # telemetry caches into XDG and they would pollute the committed data.
    # Returns (env, dirs); the caller must rmtree the dirs (see
    # cleanup_dirs) — a run leaves no perf0-* tempdirs behind.
    import tempfile
    home = tempfile.mkdtemp(prefix="perf0-home-")
    xdg = tempfile.mkdtemp(prefix="perf0-xdg-")
    os.makedirs(home, exist_ok=True); os.makedirs(xdg, exist_ok=True)
    env = dict(os.environ, LC_ALL="C", TZ="UTC", HOME=home, XDG_CONFIG_HOME=xdg)
    env.pop("CASTCTL_CONFIG", None); env.pop("CASTCTL_PROFILE", None)
    return env, [home, xdg]

def cleanup_dirs(dirs):
    for d in dirs:
        shutil.rmtree(d, ignore_errors=True)

def measure(label, argv, runs=20, warmup=5):
    out = os.path.join(DATA, label + ".json")
    env, dirs = isolated_env()
    try:
        p = subprocess.run([sys.executable, os.path.join(PERF, "measure.py"),
                            "--runs", str(runs), "--warmup", str(warmup),
                            "--out", out, "--label", label, "--"] + argv,
                           env=env, capture_output=True, text=True, timeout=600)
        try:
            return json.load(open(out))
        except Exception:
            return {"label": label, "error": p.stdout + p.stderr, "exit": p.returncode}
    finally:
        cleanup_dirs(dirs)

def main():
    skip_build = "--skip-build" in sys.argv
    skip_item5 = "--skip-item5" in sys.argv
    os.makedirs(DATA, exist_ok=True)
    summary = {"date": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
               "machine": {}, "items": {}, "notes": [], "marks": {}}
    def mark(key):
        summary["marks"][key] = {"time_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                                 "loadavg": loadavg()}
    # Disk preflight: a full run builds release binaries; fail loudly
    # instead of dying mid-build on a shared disk. Threshold 1.0 GiB on
    # the filesystem that will hold the build outputs (CARGO_TARGET_DIR
    # when set, else /). Threshold rationale: the -p castctl-rs closure
    # is stdlib-only (castctl-cli + castctl-config, ~4k lines, no
    # third-party deps) plus the small bench crate (regex/aho-corasick/
    # memchr); a probe debug build of castctl-config took 28 MiB of
    # target/. 1.0 GiB leaves ~3x headroom over that, and disk_free
    # before/after is recorded in the summary. NOTE (M-perf-1): the
    # full-bin closure (honk + boringtun + quinn + tokio + snow +
    # prost, ~350 crates) is far larger — its target dir measured
    # ~1.1 GiB on cue (run8 probe) — so the 1.0 GiB threshold above is
    # checked against the FULL target filesystem when CARGO_TARGET_DIR
    # is set (shared dir); with the default tempdir target the full
    # build lands on the system temp filesystem instead, and its
    # before/after free space is recorded separately as
    # full_disk_free_gib_before/after below.
    _preflight_path = _TARGET_DIR or "/"
    while not os.path.isdir(_preflight_path):
        _preflight_path = os.path.dirname(_preflight_path) or "/"
    free_gib = shutil.disk_usage(_preflight_path).free / (1 << 30)
    summary["machine"]["cargo_target_dir"] = _TARGET_DIR or "default (rust/target)"
    summary["machine"]["full_target_dir"] = _FULL_TARGET_DIR
    summary["machine"]["full_target_cold"] = not os.path.isdir(
        os.path.join(_FULL_TARGET_DIR, "release", "deps"))
    summary["machine"]["disk_free_gib_before"] = round(free_gib, 2)
    _full_preflight_path = _FULL_TARGET_DIR
    while not os.path.isdir(_full_preflight_path):
        _full_preflight_path = os.path.dirname(_full_preflight_path) or "/"
    summary["machine"]["full_disk_free_gib_before"] = round(
        shutil.disk_usage(_full_preflight_path).free / (1 << 30), 2)
    if free_gib < 1.0:
        summary["notes"].append("disk preflight FAILED: %.2f GiB free on %s, need >= 1 GiB"
                                % (free_gib, _preflight_path))
        json.dump(summary, open(os.path.join(DATA, "summary.json"), "w"), indent=2)
        print(json.dumps(summary, indent=2)); return 2
    # Full-bin gate (M-perf-1): the full closure's target dir is ~1.1 GiB
    # on cue, so the temp filesystem needs 2.0 GiB headroom, not 1.0.
    _full_free = shutil.disk_usage(_full_preflight_path).free / (1 << 30)
    if _full_free < 2.0:
        summary["notes"].append("disk preflight FAILED: %.2f GiB free on %s, need >= 2 GiB (full-bin target)"
                                % (_full_free, _full_preflight_path))
        json.dump(summary, open(os.path.join(DATA, "summary.json"), "w"), indent=2)
        print(json.dumps(summary, indent=2)); return 2
    m = sh(["uname", "-a"]); summary["machine"]["uname"] = m["stdout"].strip()
    summary["machine"]["nproc"] = sh(["nproc"])["stdout"].strip()
    summary["machine"]["meminfo"] = meminfo()
    summary["machine"]["loadavg_start"] = loadavg()
    summary["machine"]["go_version"] = sh(["go", "version"], env=GO_ENV)["stdout"].strip()
    summary["machine"]["go_binary_build_info"] = sh(["go", "version", "-m", GO_BIN], env=GO_ENV)["stdout"]
    summary["machine"]["cargo_version"] = sh(CARGO + ["--version"], cwd=os.path.join(ROOT, "rust"))["stdout"].strip()
    summary["machine"]["rustc_version"] = sh(["rustc", "+1.99.1", "--version"])["stdout"].strip()
    summary["machine"]["df_root"] = sh(["df", "-h", "/"])["stdout"].strip()
    hf = shutil.which("hyperfine")
    if hf:
        summary["machine"]["hyperfine_version"] = sh([hf, "--version"])["stdout"].strip()
    # GNU time is a hard requirement: measure.py refuses to run without it
    # (wait4 ru_maxrss from Python is floor-biased for small processes).
    if not os.path.isfile("/usr/bin/time"):
        summary["notes"].append("GNU time (/usr/bin/time) missing; RSS cannot be measured without the floor bias")
        json.dump(summary, open(os.path.join(DATA, "summary.json"), "w"), indent=2)
        print(json.dumps(summary, indent=2)); return 2
    summary["machine"]["gnu_time_version"] = sh(["/usr/bin/time", "--version"])["stdout"].strip()
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

    # ---- build Rust full-bin (M-perf-1): same recipe as the shell, plus
    # the no-keep variant (--no-default-features) for the linkage A/B.
    # Build order is chosen to minimise RUSTFLAGS-flip rebuilds (each
    # flip recompiles the ~350-crate closure, ~3 min on cue): plain
    # (no RUSTFLAGS) -> nokeep (RUSTFLAGS strip) -> headline
    # (RUSTFLAGS strip, default features; only a relink after nokeep).
    # The LTO variant is built last, after all measurements, so a slow
    # or failing LTO build cannot block the run. CARGO_TARGET_DIR is
    # forced to _FULL_TARGET_DIR (outside the repo) for every full-bin
    # invocation — see the constants above for why.
    def _full_env(**extra):
        env = dict(os.environ, CARGO_TARGET_DIR=_FULL_TARGET_DIR)
        env.update(extra)
        return env
    _full_cmd = CARGO + ["build", "--release", "--locked", "--offline",
                         "--manifest-path", FULL_BIN_MANIFEST]
    if not skip_build:
        b3 = sh(_full_cmd, cwd=ROOT, env=_full_env(), timeout=3600)
        summary["build_full_plain"] = b3
        if b3["exit"] != 0:
            summary["notes"].append("full-bin plain build FAILED; see build_full_plain")
            json.dump(summary, open(os.path.join(DATA, "summary.json"), "w"), indent=2)
            print(json.dumps(summary, indent=2)); return 2
        full_plain = RS_FULL_BIN + "-plain"
        shutil.copyfile(RS_FULL_BIN, full_plain)
        summary["rust_full_unstripped"] = {"size_bytes": os.path.getsize(full_plain),
                                           "sha256": sha8(full_plain)}
        shutil.copyfile(RS_FULL_BIN, full_plain + "-gnu")
        g3 = sh(["strip", full_plain + "-gnu"])
        summary["rust_full_gnu_stripped"] = {"size_bytes": os.path.getsize(full_plain + "-gnu"),
                                             "sha256": sha8(full_plain + "-gnu"), "strip": g3}
        env3 = _full_env(RUSTFLAGS="-C strip=symbols")
        b4 = sh(_full_cmd + ["--no-default-features"], cwd=ROOT, env=env3, timeout=3600)
        summary["build_full_nokeep"] = b4
        if b4["exit"] != 0:
            summary["notes"].append("full-bin no-keep build FAILED; see build_full_nokeep")
            json.dump(summary, open(os.path.join(DATA, "summary.json"), "w"), indent=2)
            print(json.dumps(summary, indent=2)); return 2
        full_nokeep = RS_FULL_BIN + "-nokeep"
        shutil.copyfile(RS_FULL_BIN, full_nokeep)
        summary["rust_full_nokeep"] = {"size_bytes": os.path.getsize(full_nokeep),
                                       "sha256": sha8(full_nokeep)}
        b5 = sh(_full_cmd, cwd=ROOT, env=env3, timeout=3600)
        summary["build_full_stripped"] = b5
        if b5["exit"] != 0:
            summary["notes"].append("full-bin RUSTFLAGS strip build FAILED; see build_full_stripped")
            json.dump(summary, open(os.path.join(DATA, "summary.json"), "w"), indent=2)
            print(json.dumps(summary, indent=2)); return 2
        summary["rust_full_strip_method"] = "RUSTFLAGS=-C strip=symbols"
        summary["rust_full_binary"] = {"size_bytes": os.path.getsize(RS_FULL_BIN),
                                       "sha256": sha8(RS_FULL_BIN),
                                       "version": sh([RS_FULL_BIN, "--version"])["stdout"].strip()}
        for name, path in (("go", GO_BIN), ("rust", RS_BIN), ("rust-full", RS_FULL_BIN)):
            summary.setdefault("size_breakdown", {})[name] = sh(["size", "-A", path])["stdout"]
    else:
        if os.path.isfile(RS_FULL_BIN):
            summary["rust_full_binary"] = {"size_bytes": os.path.getsize(RS_FULL_BIN),
                                           "sha256": sha8(RS_FULL_BIN),
                                           "version": sh([RS_FULL_BIN, "--version"])["stdout"].strip()}
            full_plain = RS_FULL_BIN + "-plain"
            if os.path.exists(full_plain):
                summary["rust_full_unstripped"] = {"size_bytes": os.path.getsize(full_plain),
                                                   "sha256": sha8(full_plain)}
                summary["rust_full_gnu_stripped"] = {"size_bytes": os.path.getsize(full_plain + "-gnu"),
                                                     "sha256": sha8(full_plain + "-gnu")}
            full_nokeep = RS_FULL_BIN + "-nokeep"
            if os.path.exists(full_nokeep):
                summary["rust_full_nokeep"] = {"size_bytes": os.path.getsize(full_nokeep),
                                               "sha256": sha8(full_nokeep)}
            summary["rust_full_strip_method"] = "RUSTFLAGS=-C strip=symbols (binary from earlier full run)"
        else:
            summary["rust_full_binary"] = {"missing": "no full binary found; run without --skip-build"}
            summary["notes"].append("rust-full binary MISSING in --skip-build mode; rust-full sides skipped")
        for name, path in (("go", GO_BIN), ("rust", RS_BIN), ("rust-full", RS_FULL_BIN)):
            if os.path.isfile(path):
                summary.setdefault("size_breakdown", {})[name] = sh(["size", "-A", path])["stdout"]
        summary["notes"].append("build skipped (--skip-build)")

    # First measured run, warmup=0 (NOT cold, NOT first-run after build):
    # both binaries already executed at least once above (--version probes
    # during machine setup + the strip build), so the page cache is warm.
    # N=1 each; only the warmup=0 first run of this invocation is recorded.
    first = {}
    for name, path in (("go", GO_BIN), ("rust", RS_BIN), ("rust-full", RS_FULL_BIN)):
        if not os.path.isfile(path):
            first[name] = {"missing": True}
            continue
        mark("before_first_measured_run_" + name)
        first[name] = measure("first-measured-run-" + name, [path, "--version"], runs=1, warmup=0)
        mark("after_first_measured_run_" + name)
    summary["items"]["first_measured_run_warmup0"] = first

    # ---- items 2+3: startup + RSS, adjacent batches (Go, then Rust
    # shell, then Rust full — same adjacent-batch order every label).
    # A side whose binary is missing is recorded, not measured.
    items23 = {}
    for label, args in [
        ("version", (("go", [GO_BIN, "--version"]),
                     ("rust", [RS_BIN, "--version"]),
                     ("rust-full", [RS_FULL_BIN, "--version"]))),
        ("help", (("go", [GO_BIN, "--help"]),
                  ("rust", [RS_BIN, "--help"]),
                  ("rust-full", [RS_FULL_BIN, "--help"]))),
    ]:
        items23[label] = {}
        for name, argv in args:
            if not os.path.isfile(argv[0]):
                items23[label][name] = {"missing": True}
                continue
            mark("before_item2_" + label + "_" + name)
            items23[label][name] = measure("item2-" + label + "-" + name, argv)
            mark("after_item2_" + label + "_" + name)
    summary["items"]["startup_rss"] = items23
    summary["machine"]["loadavg_mid"] = loadavg()

    # ---- item 3 parse-config: probe Go status offline first
    import tempfile
    cfgdir_min = tempfile.mkdtemp(prefix="perf0-cfgmin-")
    cfgdir_large = tempfile.mkdtemp(prefix="perf0-cfglarge-")
    cfgdir_bad = tempfile.mkdtemp(prefix="perf0-cfgbad-")
    cfgdirs = [cfgdir_min, cfgdir_large, cfgdir_bad]
    shutil.copyfile(os.path.join(FIX, "config-min.json"), os.path.join(cfgdir_min, "config.json"))
    shutil.copyfile(os.path.join(FIX, "config-large.json"), os.path.join(cfgdir_large, "config.json"))
    open(os.path.join(cfgdir_bad, "config.json"), "w").write("{invalid")
    parse = {}
    try:
        probe_env, probe_dirs = isolated_env()
        try:
            probe = sh([GO_BIN, "--config", os.path.join(cfgdir_min, "config.json"), "status"], env=probe_env, timeout=15)
        except Exception as e:
            probe = {"exit": None, "seconds": 15, "stdout": "", "stderr": "probe exception: %s" % e}
        finally:
            cleanup_dirs(probe_dirs)
        summary["go_status_probe"] = probe
        # One verbatim stderr sample of Go `status --config large` (the
        # config-large failure string is quoted from this file, not memory).
        large_env, large_dirs = isolated_env()
        try:
            lp = subprocess.run([GO_BIN, "--config", os.path.join(cfgdir_large, "config.json"), "status"],
                                env=large_env, capture_output=True, text=True, timeout=15)
            stderr_path = os.path.join(DATA, "item3-status-large-go-stderr.txt")
            open(stderr_path, "w").write(lp.stderr)
            summary["go_status_large_stderr"] = {"file": "item3-status-large-go-stderr.txt",
                                                 "bytes": len(lp.stderr), "exit": lp.returncode}
        except Exception as e:
            summary["go_status_large_stderr"] = {"error": str(e)}
        finally:
            cleanup_dirs(large_dirs)
        if probe["exit"] is not None and probe["seconds"] < 10 and "panic" not in probe["stderr"].lower():
            mark("before_item3_status_min_go")
            parse["go_good_config"] = measure("item3-status-min-go", [GO_BIN, "--config", os.path.join(cfgdir_min, "config.json"), "status"])
            mark("after_item3_status_min_go")
            mark("before_item3_status_large_go")
            parse["go_large_config"] = measure("item3-status-large-go", [GO_BIN, "--config", os.path.join(cfgdir_large, "config.json"), "status"])
            mark("after_item3_status_large_go")
            parse["mode"] = ("good-config status: Go exits fast (exit %s, %.1fs) but NOT offline-clean: "
                             "it parses+validates, then fails fast on missing session/outbound "
                             "(see go_status_probe stderr); Rust reaches stub (exit 1). "
                             "Bad-config gate below is the clean apples-to-apples parse path." % (probe["exit"], probe["seconds"]))
        else:
            parse["mode"] = "bad-config parse gate only (Go status probe: exit=%s seconds=%s)" % (probe["exit"], probe["seconds"])
            summary["notes"].append("Go status with good config did not run offline cleanly; parse RSS uses bad-config gate")
        mark("before_item3_status_min_rust")
        parse["rust_min"] = measure("item3-status-min-rust", [RS_BIN, "--config", os.path.join(cfgdir_min, "config.json"), "status"])
        mark("after_item3_status_min_rust")
        mark("before_item3_status_large_rust")
        parse["rust_large"] = measure("item3-status-large-rust", [RS_BIN, "--config", os.path.join(cfgdir_large, "config.json"), "status"])
        mark("after_item3_status_large_rust")
        mark("before_item3_status_bad_rust")
        parse["rust_bad"] = measure("item3-status-bad-rust", [RS_BIN, "--config", os.path.join(cfgdir_bad, "config.json"), "status"])
        mark("after_item3_status_bad_rust")
        # rust-full runs the same castctl_cli::run on the same configs;
        # the only difference is the bigger linked closure, which is
        # exactly what this item measures for the third column.
        if os.path.isfile(RS_FULL_BIN):
            mark("before_item3_status_min_rust_full")
            parse["rust_full_min"] = measure("item3-status-min-rust-full", [RS_FULL_BIN, "--config", os.path.join(cfgdir_min, "config.json"), "status"])
            mark("after_item3_status_min_rust_full")
            mark("before_item3_status_large_rust_full")
            parse["rust_full_large"] = measure("item3-status-large-rust-full", [RS_FULL_BIN, "--config", os.path.join(cfgdir_large, "config.json"), "status"])
            mark("after_item3_status_large_rust_full")
            mark("before_item3_status_bad_rust_full")
            parse["rust_full_bad"] = measure("item3-status-bad-rust-full", [RS_FULL_BIN, "--config", os.path.join(cfgdir_bad, "config.json"), "status"])
            mark("after_item3_status_bad_rust_full")
        else:
            parse["rust_full_min"] = {"missing": True}
            parse["rust_full_large"] = {"missing": True}
            parse["rust_full_bad"] = {"missing": True}
        mark("before_item3_status_bad_go")
        parse["go_bad"] = measure("item3-status-bad-go", [GO_BIN, "--config", os.path.join(cfgdir_bad, "config.json"), "status"])
        mark("after_item3_status_bad_go")
    finally:
        cleanup_dirs(cfgdirs)
    summary["items"]["parse_config_rss"] = parse

    # ---- item 4: pure logic.
    # Replicates differ by design and are recorded as such: Go is 1 process
    # x 5 counts x 100 iters (`go test -benchtime=100x -count=5`); Rust is
    # 5 separate process runs per mode with an adaptive K (>= ~200 ms/run).
    # The full Rust bench JSON line (iters K, total_ms, output_len) is saved
    # per run in rust_bench_raw so K / output_len are verifiable.
    item4 = {}
    mark("before_item4_go_bench")
    gb = sh(["go", "test", "-bench", ".", "-benchtime=100x", "-count=5", "-run", "^$",
             "./rust/perf/go-bench/"], env=GO_ENV, cwd=ROOT, timeout=1200)
    mark("after_item4_go_bench")
    item4["go_bench_raw"] = gb
    # parse `go test -bench` lines: BenchmarkX-8  100  12345 ns/op
    go_bench = {}
    for line in gb["stdout"].splitlines():
        mm = re.match(r"^(Benchmark\w+)-\d+\s+\d+\s+([\d.]+) ns/op", line.strip())
        if mm:
            go_bench.setdefault(mm.group(1), []).append(float(mm.group(2)))
    item4["go_ns_per_op"] = {k: stats(v) for k, v in go_bench.items()}
    # Also parse B/op + allocs/op medians (reported as medians, not min).
    go_alloc = {}
    for line in gb["stdout"].splitlines():
        mm = re.match(r"^(Benchmark\w+)-\d+\s+\d+\s+[\d.]+ ns/op\s+(\d+) B/op\s+(\d+) allocs/op", line.strip())
        if mm:
            go_alloc.setdefault(mm.group(1), {"b_op": [], "allocs_op": []})
            go_alloc[mm.group(1)]["b_op"].append(int(mm.group(2)))
            go_alloc[mm.group(1)]["allocs_op"].append(int(mm.group(3)))
    item4["go_b_op_allocs"] = {k: {"b_op": stats(v["b_op"]), "allocs_op": stats(v["allocs_op"])}
                               for k, v in go_alloc.items()}
    bb = sh(CARGO + ["build", "--release", "--offline"],
            cwd=os.path.join(PERF, "bench"), timeout=1800)
    item4["rust_bench_build"] = bb
    rust_bench = {}
    rust_raw = {}
    if bb["exit"] == 0:
        mark("before_item4_rust_bench")
        for mode in ("parse-min", "parse-large", "decode-large", "md-to-html", "split-text", "render-chain"):
            vals = []
            raws = []
            for _ in range(5):
                r = sh([RS_BENCH, mode], timeout=300)
                try:
                    raw = json.loads(r["stdout"].strip().splitlines()[-1])
                    raws.append(raw)
                    vals.append(raw["ns_per_iter"])
                except Exception:
                    vals.append(None)
            rust_bench[mode] = {"ns_per_iter_runs": vals,
                                "stats": stats([v for v in vals if v is not None]) if any(vals) else None}
            rust_raw[mode] = raws
        mark("after_item4_rust_bench")
    else:
        item4["notes"] = "Rust standalone bench crate FAILED to build; see rust_bench_build"
    item4["rust_ns_per_iter"] = rust_bench
    item4["rust_bench_raw"] = rust_raw
    # No rust-full column: the bench crate measures the shared
    # castctl-config code (parse/decode/MDToHTML) as pure logic, not a
    # binary — rust-full links the same config code, so a third column
    # would re-measure the same functions.
    item4["no_rust_full_column"] = ("pure-logic benches run the shared castctl-config code, "
                                     "not a binary; rust-full links the same code")
    summary["items"]["pure_logic"] = item4
    summary["machine"]["loadavg_after_item4"] = loadavg()

    # ---- item 5: loopback SOCKS5, hard 20-min setup clock
    if skip_item5:
        summary["items"]["transport_loopback"] = {"status": "skipped",
                                                  "reason": "--skip-item5: item 5 not run"}
    else:
        t5 = time.time()
        item5 = {"setup_deadline_s": 1200}
        # Pick actually-free loopback ports first: 18080 turned out to belong
        # to another session's server (pid 1666878, answers b"ok" to any path),
        # so fixed ports are unsafe. Bind port 0, take the assigned ports —
        # for the HTTP origin AND for the SOCKS5 proxy (the 18080 lesson
        # applies to both).
        import socket as _sock
        def _free_port():
            _s = _sock.socket(); _s.bind(("127.0.0.1", 0))
            _p = _s.getsockname()[1]; _s.close(); return _p
        http_port = _free_port()
        socks_port = _free_port()
        item5["http_port"] = http_port
        item5["socks_port"] = socks_port
        http_proc = subprocess.Popen([sys.executable, "-m", "http.server", str(http_port),
                                      "--bind", "127.0.0.1", "--directory", FIX],
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        socks_proc = subprocess.Popen([sys.executable, os.path.join(PERF, "socks5.py"),
                                       "--listen", "127.0.0.1", "--port", str(socks_port)],
                                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            time.sleep(1.5)
            # Both child processes must still be alive: Popen succeeds even
            # when the bind fails and the child dies immediately.
            item5["servers_alive"] = {"http": http_proc.poll() is None,
                                      "socks": socks_proc.poll() is None}
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
            # Verify the SOCKS5 proxy is OURS with a real handshake + CONNECT
            # probe (same idea as origin_check): greeting, CONNECT to the
            # ephemeral HTTP origin, GET, check the 1024-byte body.
            try:
                _c = _sock2.create_connection(("127.0.0.1", socks_port), timeout=5)
                _c.sendall(bytes([5, 1, 0]))
                _greet = _c.recv(2)
                _ok_greet = _greet == b"\x05\x00"
                _ok_conn = False
                _ok_body = False
                if _ok_greet:
                    _c.sendall(bytes([5, 1, 0, 1, 127, 0, 0, 1]) + http_port.to_bytes(2, "big"))
                    _rep = _c.recv(10)
                    _ok_conn = len(_rep) == 10 and _rep[1] == 0
                    if _ok_conn:
                        _c.sendall(b"GET /body-1024.bin HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
                        _praw = b""
                        while True:
                            _chunk = _c.recv(4096)
                            if not _chunk:
                                break
                            _praw += _chunk
                        _pbody = _praw.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in _praw else b""
                        _ok_body = _pbody == b"x" * 1024
                _c.close()
                item5["socks_check"] = {"greeting_ok": _ok_greet, "connect_ok": _ok_conn,
                                        "body_ok": _ok_body}
            except Exception as e:
                item5["socks_check"] = {"error": str(e)}
            # Listener state as booleans only (no `ss -ltn` dump: it maps
            # other tenants' listeners on a shared VM and is not needed —
            # the two probes above already prove both servers are ours).
            item5["listeners_up"] = {"http": bool(item5.get("origin_check", {}).get("body_ok")),
                                     "socks": bool(item5.get("socks_check", {}).get("body_ok"))}
            # setup_seconds = spawn + verify only; the client loops below
            # are timed separately as measure_seconds.
            item5["setup_seconds"] = round(time.time() - t5, 1)
            mark("after_item5_setup")
            if not all(item5["servers_alive"].values()):
                item5["status"] = "chua kiem chung duoc: a server process died during setup (see servers_alive)"
            elif not item5["listeners_up"]["http"]:
                item5["status"] = "chua kiem chung duoc: HTTP origin check failed (see origin_check)"
            elif not item5["listeners_up"]["socks"]:
                item5["status"] = "chua kiem chung duoc: SOCKS5 proxy check failed (see socks_check)"
            elif time.time() - t5 > 1200:
                item5["status"] = "chua kiem chung duoc: 20-min setup budget exceeded"
            else:
                t_measure = time.time()
                mark("before_item5_rust_runs")
                env5, env5_dirs = isolated_env()
                try:
                    env5.update({"PERF_SOCKS5_ADDR": f"127.0.0.1:{socks_port}",
                                 "PERF_HTTP_ADDR": f"127.0.0.1:{http_port}", "PERF_SOCKS5_RUNS": "20"})
                    rust5, go5 = [], []
                    for _ in range(5):
                        r = sh([RS_BENCH, "socks5-get"], env=env5, timeout=120)
                        try:
                            rust5.append(json.loads(r["stdout"].strip().splitlines()[-1])["ms_per_request"]["median"])
                        except Exception:
                            rust5.append(None)
                    mark("after_item5_rust_runs")
                    mark("before_item5_go_runs")
                    go5_raw = []
                    import tempfile as _tf
                    for _ in range(5):
                        _fd, out5 = _tf.mkstemp(prefix="perf0-item5-go-", suffix=".json")
                        os.close(_fd)
                        try:
                            # NOTE: do NOT use the isolated HOME here: Go with
                            # GOTOOLCHAIN=auto resolves its toolchain/module cache
                            # under $HOME/go; an isolated HOME makes `go test` try
                            # to re-download the toolchain (and fail/slow). The Go
                            # SOCKS client reads no castctl config, so real HOME is
                            # correct for it (probe 2026-11-05: isolated HOME was
                            # why all 5 driver Go runs returned None while the
                            # manual run with real HOME passed).
                            env_go5 = dict(GO_ENV, PERF_SOCKS5_ADDR=f"127.0.0.1:{socks_port}",
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
                        finally:
                            try:
                                os.unlink(out5)
                            except OSError:
                                pass
                    mark("after_item5_go_runs")
                    item5["go_runs_raw"] = go5_raw
                    if not any(rust5) and not any(go5):
                        item5["status"] = "chua kiem chung duoc: both clients failed (see runs: all None)"
                    else:
                        item5["status"] = "measured"
                    item5["rust_ms_per_request_runs"] = rust5
                    item5["go_ms_per_request_runs"] = go5
                    item5["rust_stats"] = stats([v for v in rust5 if v is not None]) if any(rust5) else None
                    item5["go_stats"] = stats([v for v in go5 if v is not None]) if any(go5) else None
                    item5["measure_seconds"] = round(time.time() - t_measure, 1)
                    item5["total_seconds"] = round(time.time() - t5, 1)
                finally:
                    cleanup_dirs(env5_dirs)
        finally:
            http_proc.terminate(); socks_proc.terminate()
            try: http_proc.wait(timeout=5)
            except Exception: http_proc.kill()
            try: socks_proc.wait(timeout=5)
            except Exception: socks_proc.kill()
        summary["items"]["transport_loopback"] = item5
    # No rust-full column: the Rust side runs the standalone bench
    # crate's socks5-get client (same honk dialer code the full binary
    # links), not the castctl-full binary itself — the harness has no
    # way to drive a transport request through the CLI binary.
    summary["items"]["transport_loopback"]["no_rust_full_column"] = (
        "Rust side is the bench crate's socks5-get client, "
        "not the castctl-full binary; no CLI path drives a transport request")

    # ---- hyperfine cross-check (only if installed)
    hf = shutil.which("hyperfine")
    summary["hyperfine"] = {"present": bool(hf)}
    if hf:
        summary["hyperfine"]["version"] = summary["machine"].get("hyperfine_version")
        for key, label, args in (("version_bench", "version", ["--version"]), ("help", "help", ["--help"])):
            cmds = [f"{GO_BIN} {' '.join(args)}", f"{RS_BIN} {' '.join(args)}"]
            if os.path.isfile(RS_FULL_BIN):
                cmds.append(f"{RS_FULL_BIN} {' '.join(args)}")
            r = sh([hf, "--warmup", "5", "--runs", "20", "--export-json",
                    os.path.join(DATA, f"hyperfine-{label}.json")] + cmds, timeout=600)
            summary["hyperfine"][key] = {"exit": r["exit"], "stdout": r["stdout"][-2000:],
                                         "commands": cmds}

    # ---- LTO variant (M-perf-1, secondary row only): fat LTO + strip.
    # Built LAST so a slow or failing LTO build cannot block the
    # measurements above. LTO comes from the `release-lto` profile in
    # full-bin/Cargo.toml — RUSTFLAGS `-C lto` is PROVEN broken for
    # this closure (run8: `-C embed-bitcode=no` / `-C lto`
    # incompatibility; manual probe: "lto cannot be used for
    # `proc-macro` crate type without `-Zdylib-lto`" on zeroize_derive
    # / serde_derive). The profile build writes to release-lto/, so it
    # never touches the headline binary in release/ — no restore step.
    if not skip_build:
        try:
            b6 = sh(CARGO + ["build", "--profile", "release-lto", "--locked", "--offline",
                             "--manifest-path", FULL_BIN_MANIFEST],
                    cwd=ROOT, env=_full_env(), timeout=3600)
            summary["build_full_lto"] = b6
            _lto_bin = os.path.join(_FULL_TARGET_DIR, "release-lto", "castctl-full")
            if b6["exit"] == 0 and os.path.isfile(_lto_bin):
                full_lto = RS_FULL_BIN + "-lto"
                shutil.copyfile(_lto_bin, full_lto)
                summary["rust_full_lto"] = {"size_bytes": os.path.getsize(full_lto),
                                            "sha256": sha8(full_lto)}
            else:
                summary["notes"].append("full-bin LTO build FAILED; see build_full_lto (secondary row only)")
        except Exception as e:
            summary["build_full_lto"] = {"error": str(e)}
            summary["notes"].append("full-bin LTO build FAILED with exception (secondary row only): %s" % e)
    else:
        full_lto = RS_FULL_BIN + "-lto"
        if os.path.exists(full_lto):
            summary["rust_full_lto"] = {"size_bytes": os.path.getsize(full_lto),
                                        "sha256": sha8(full_lto)}
    summary["machine"]["loadavg_end"] = loadavg()
    summary["machine"]["disk_free_gib_after"] = round(shutil.disk_usage(_preflight_path).free / (1 << 30), 2)
    summary["machine"]["full_disk_free_gib_after"] = round(
        shutil.disk_usage(_full_preflight_path).free / (1 << 30), 2)
    json.dump(summary, open(os.path.join(DATA, "summary.json"), "w"), indent=2)
    print(json.dumps(summary, indent=2))
    return 0

if __name__ == "__main__":
    sys.exit(main())
