#!/usr/bin/env python3
"""Single-process timing + peak-RSS measurement (stdlib only).

Method (validated in measure-plan.md section 2a): spawn the child with
subprocess.Popen, reap it with os.wait4, take ru_maxrss of exactly that
child (Linux, KiB) and wall time from time.perf_counter_ns. The /proc
sampler was probed and REJECTED (3x noise on ~10-20ms processes).
Usage: measure.py --runs N --warmup W --timeout S --out FILE.json --label L -- cmd...
Prints one JSON object to stdout and (with --out) writes it to FILE.
Exit code: 0 if every run exited 0, else 1 (still writes the JSON).
"""
import argparse, json, os, statistics, subprocess, sys, time

def stats(vals):
    if not vals:
        return {"n": 0, "median": None, "min": None, "max": None, "mean": None}
    return {"n": len(vals), "median": statistics.median(vals),
            "min": min(vals), "max": max(vals), "mean": statistics.mean(vals)}

def run_once(argv, env, timeout):
    t0 = time.perf_counter_ns()
    p = subprocess.Popen(argv, stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL, env=env)
    try:
        _, status, ru = os.wait4(p.pid, 0)
    except ChildProcessError:
        p.wait(timeout=timeout)
        return {"wall_ms": (time.perf_counter_ns() - t0) / 1e6,
                "maxrss_kib": None, "exit": p.returncode, "wait4": False}
    t1 = time.perf_counter_ns()
    return {"wall_ms": (t1 - t0) / 1e6, "maxrss_kib": ru.ru_maxrss,
            "exit": os.waitstatus_to_exitcode(status), "wait4": True}

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
    env = dict(os.environ)
    for _ in range(a.warmup):
        run_once(argv, env, a.timeout)
    runs = [run_once(argv, env, a.timeout) for _ in range(a.runs)]
    walls = [r["wall_ms"] for r in runs]
    rss = [r["maxrss_kib"] / 1024.0 for r in runs if r["maxrss_kib"] is not None]
    out = {"label": a.label, "argv": argv, "env_note": "inherited (HOME/XDG isolated by caller)",
           "warmup": a.warmup, "wall_ms": stats(walls),
           "peak_rss_mib": stats(rss),
           "exits": [r["exit"] for r in runs], "runs": runs}
    if a.out:
        with open(a.out, "w") as f:
            json.dump(out, f, indent=2)
    print(json.dumps({"label": a.label, "wall_ms": out["wall_ms"],
                      "peak_rss_mib": out["peak_rss_mib"], "exits": out["exits"]}))
    return 0 if all(e == 0 for e in out["exits"]) else 1

if __name__ == "__main__":
    sys.exit(main())
