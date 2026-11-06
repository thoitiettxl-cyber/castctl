#!/usr/bin/env python3
"""Single-process timing + peak-RSS measurement (stdlib + GNU time).

Method (probed 2026-11-05, fix loop 1 — the run4/run5 method was WRONG,
see below):
- Wall clock + exit code: spawn the child directly with subprocess.Popen,
  reap it with BLOCKING os.wait4 in the main thread (SIGALRM timeout).
  A WNOHANG poll loop was tried first and REJECTED by probe: with a 5 ms
  sleep it quantised every wall time to a 5 ms grid (Rust --version
  measured 5.45 ms instead of ~0.75 ms; /bin/true measured 5.35 ms).
- Peak RSS: a SEPARATE spawn under /usr/bin/time -v -o <report file>.
  GNU time is a thin C parent (~1-2 MB RSS), so its floor is ~1.3 MB.
  The wait4 ru_maxrss of a Python-spawned child is UNUSABLE for small
  processes: probe 2026-11-05 — a Python parent with self maxrss
  114,072 KiB forked /bin/true and wait4 reported the child at exactly
  114,072 KiB; the same /bin/true under GNU time reports 1,260 KB, and
  castctl-rs --version reports 2,104 KB under GNU time vs 13,656 KiB
  under wait4-from-Python. Rule (proven): reported ru_maxrss =
  max(parent RSS at spawn, child own peak). Python's ~13 MB floor hid
  Rust's true ~2.1 MB RSS in run4/run5 (reported 13.2 MiB). Go's own
  peak (~30 MB) exceeds the floor, so Go RSS numbers were genuine.
  /usr/bin/time is REQUIRED: this script refuses to run without it
  (a wait4-only fallback would silently reintroduce the floor bias).
- Timeout: SIGALRM (ITIMER_REAL) interrupts the blocking wait4; on
  timeout the child (and, for the time spawn, its process group) is
  SIGKILLed and reaped. No polling loop anywhere.

Usage: measure.py --runs N --warmup W --timeout S --out FILE.json --label L -- cmd...
Prints one JSON object to stdout and (with --out) writes it to FILE.
Exit code: 0 if every run exited 0, else 1 (still writes the JSON).
"""
import argparse, json, os, signal, statistics, subprocess, sys, tempfile, time

GNU_TIME = "/usr/bin/time"

def stats(vals):
    if not vals:
        return {"n": 0, "median": None, "min": None, "max": None, "mean": None}
    return {"n": len(vals), "median": statistics.median(vals),
            "min": min(vals), "max": max(vals), "mean": statistics.mean(vals)}

class _Timeout(Exception):
    pass

def _alarm(signum, frame):
    raise _Timeout()

def _wall_spawn(argv, env, timeout):
    """Direct spawn: precise wall clock + exit code. The ru_maxrss from
    this spawn is floor-biased (see docstring) and is returned only as
    maxrss_kib_raw for audit, never used for the reported RSS."""
    t0 = time.perf_counter_ns()
    p = subprocess.Popen(argv, stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL, env=env)
    old = signal.signal(signal.SIGALRM, _alarm)
    try:
        signal.setitimer(signal.ITIMER_REAL, timeout)
        try:
            _, status, ru = os.wait4(p.pid, 0)
        except _Timeout:
            p.kill()
            _, status, ru = os.wait4(p.pid, 0)
            return {"wall_ms": (time.perf_counter_ns() - t0) / 1e6,
                    "maxrss_kib_raw": ru.ru_maxrss,
                    "exit": None, "wait4": True, "timeout": True}
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
    finally:
        signal.signal(signal.SIGALRM, old)
    t1 = time.perf_counter_ns()
    return {"wall_ms": (t1 - t0) / 1e6, "maxrss_kib_raw": ru.ru_maxrss,
            "exit": os.waitstatus_to_exitcode(status), "wait4": True,
            "timeout": False}

def _rss_spawn(argv, env, timeout):
    """RSS spawn under GNU time (thin parent). Returns (maxrss_kib, exit)
    parsed from the -o report file, or (None, exit) if unparseable."""
    fd, report = tempfile.mkstemp(prefix="perf0-gnutime-", suffix=".txt")
    os.close(fd)
    try:
        p = subprocess.Popen([GNU_TIME, "-v", "-o", report] + argv,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                             stdin=subprocess.DEVNULL, env=env,
                             start_new_session=True)
        try:
            rc = p.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(p.pid, signal.SIGKILL)
            except ProcessLookupError:
                p.kill()
            rc = p.wait()
            return None, rc, True
        rss = None
        try:
            for line in open(report):
                line = line.strip()
                if line.startswith("Maximum resident set size"):
                    rss = int(line.rsplit(":", 1)[1].strip().split()[0])
        except (OSError, ValueError, IndexError):
            rss = None
        return rss, rc, False
    finally:
        try:
            os.unlink(report)
        except OSError:
            pass

def run_once(argv, env, timeout):
    wall = _wall_spawn(argv, env, timeout)
    rss, rss_exit, rss_timeout = _rss_spawn(argv, env, timeout)
    return {"wall_ms": wall["wall_ms"], "maxrss_kib": rss,
            "maxrss_kib_raw": wall["maxrss_kib_raw"],
            "exit": wall["exit"], "rss_exit": rss_exit,
            "wait4": wall["wait4"],
            "timeout": bool(wall.get("timeout") or rss_timeout)}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=int, default=20)
    ap.add_argument("--warmup", type=int, default=5)
    ap.add_argument("--timeout", type=int, default=10)
    ap.add_argument("--out", default=None)
    ap.add_argument("--label", default="")
    ap.add_argument("cmd", nargs=argparse.REMAINDER)
    a = ap.parse_args()
    argv = [c for c in a.cmd if c != "--"]
    if not os.path.isfile(GNU_TIME):
        print(f"{GNU_TIME} is required for RSS (wait4 ru_maxrss from "
              "Python is floor-biased; see measure.py docstring)",
              file=sys.stderr)
        return 2
    env = dict(os.environ)
    for _ in range(a.warmup):
        run_once(argv, env, a.timeout)
    runs = [run_once(argv, env, a.timeout) for _ in range(a.runs)]
    walls = [r["wall_ms"] for r in runs]
    rss = [r["maxrss_kib"] / 1024.0 for r in runs if r["maxrss_kib"] is not None]
    out = {"label": a.label, "argv": argv, "env_note": "inherited (HOME/XDG isolated by caller)",
           "warmup": a.warmup,
           "rss_method": "GNU time -v (thin parent); wait4 ru_maxrss kept as maxrss_kib_raw for audit only",
           "wall_ms": stats(walls),
           "peak_rss_mib": stats(rss),
           "exits": [r["exit"] for r in runs],
           "rss_exits": [r["rss_exit"] for r in runs], "runs": runs}
    if a.out:
        with open(a.out, "w") as f:
            json.dump(out, f, indent=2)
    print(json.dumps({"label": a.label, "wall_ms": out["wall_ms"],
                      "peak_rss_mib": out["peak_rss_mib"], "exits": out["exits"]}))
    return 0 if all(e == 0 for e in out["exits"]) else 1

if __name__ == "__main__":
    sys.exit(main())
