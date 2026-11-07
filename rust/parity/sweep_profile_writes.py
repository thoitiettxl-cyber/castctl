#!/usr/bin/env python3
# Copyright (c) 2026 muse-cli contributors
# SPDX-License-Identifier: GPL-3.0-only
# Licensed under the GNU General Public License v3.0 only.
#
# Differential sweep, Go binary vs Rust binary, over one surface.
# Not part of the crate build: run it from a checkout on a machine that
# has the Go binary (default /usr/local/bin/castctl) and a Rust build:
#
#   python3 rust/parity/<this file> <path-to-castctl-rs>
#
# Prints one DIFF block per mismatch and a TOTAL/DIFFS line; exit 0
# either way so a sweep can be pasted into a report. See
# docs/differential-sweeps.md for the recorded runs.
#!/usr/bin/env python3
"""Differential sweep: profile write commands, resulting config compared."""
import json, os, re, shutil, subprocess, sys

GO = "/usr/local/bin/castctl"
RS = sys.argv[1] if len(sys.argv) > 1 else "/tmp/sc-target/release/castctl-rs"
D = "/tmp/sweep7"
JAR = ".muse.ai\tTRUE\t/\tTRUE\t1893456000\thatch_sess\tFAKE\n"

BASE = {"default_profile": "a",
        "profiles": {"a": {"cookies_file": "profiles/a/cookies.txt", "node_id": "n1", "auto_approve": "always"},
                     "b": {"cookies_file": "profiles/b/cookies.txt", "auto_approve": "off"}},
        "telegram": {"token": "123456789:AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIII", "allowed_user_ids": [42]}}

CASES = [
    ["profile", "add", "c"],
    ["profile", "add", "c", "--json"],
    ["profile", "add", "a"],
    ["profile", "rm", "b"],
    ["profile", "rm", "a"],
    ["profile", "name", "b", "renamed"],
    ["profile", "name", "a", "renamed"],
    ["profile", "set-outbound", "a", "proxy"],
    ["profile", "set-outbound", "a", ""],
    ["profile", "set-fingerprint", "a", "firefox"],
    ["profile", "set-tls-engine", "a", "honk"],
    ["profile", "set-tls-engine", "a", "nope"],
    ["auto-approve", "on"],
    ["auto-approve", "off"],
    ["auto-approve", "always"],
    ["config", "migrate", "--write"],
]

def build(case_idx):
    d = os.path.join(D, "c%d" % case_idx)
    shutil.rmtree(d, ignore_errors=True)
    for side in ("g", "r"):
        sd = os.path.join(d, side)
        os.makedirs(os.path.join(sd, "profiles/a"), exist_ok=True)
        os.makedirs(os.path.join(sd, "profiles/b"), exist_ok=True)
        open(os.path.join(sd, "config.json"), "w").write(json.dumps(BASE, indent=2))
        for p in ("profiles/a/cookies.txt", "profiles/b/cookies.txt"):
            fp = os.path.join(sd, p)
            open(fp, "w").write(JAR)
            os.chmod(fp, 0o600)
    return d

def snapshot(d):
    out = {}
    for root, _dirs, files in os.walk(d):
        for fn in files:
            p = os.path.join(root, fn)
            rel = os.path.relpath(p, d)
            with open(p, "rb") as f:
                data = f.read()
            out[rel] = (data, oct(os.stat(p).st_mode & 0o777))
    return out

def norm(snap, side_dir):
    out = {}
    for k, (data, mode) in snap.items():
        data = data.replace(side_dir.encode(), b"<CFG>")
        data = re.sub(rb'"node_id": "[0-9a-f]{16}"', b'"node_id": "<ID>"', data)
        out[k] = (data, mode)
    return out

def run(binary, d, argv):
    p = subprocess.run([binary, "--config", os.path.join(d, "config.json")] + argv, cwd=d,
                       capture_output=True, text=True, timeout=60,
                       env={**os.environ, "HOME": d, "XDG_CONFIG_HOME": os.path.join(d, ".config")})
    return p.returncode, p.stdout, p.stderr

def main():
    shutil.rmtree(D, ignore_errors=True)
    total = diffs = 0
    for i, argv in enumerate(CASES):
        total += 1
        d = build(i)
        dg, dr = os.path.join(d, "g"), os.path.join(d, "r")
        cg, og, eg = run(GO, dg, argv)
        cr, orr, er = run(RS, dr, argv)
        og = og.replace(dg, "<CFG>").replace(D, "<D>")
        eg = eg.replace(dg, "<CFG>").replace(D, "<D>")
        orr = orr.replace(dr, "<CFG>").replace(D, "<D>")
        er = er.replace(dr, "<CFG>").replace(D, "<D>")
        bad = []
        if (cg, og, eg) != (cr, orr, er):
            bad.append("exit go=%s rs=%s\n out go=%r rs=%r\n err go=%r rs=%r"
                       % (cg, cr, og[:300], orr[:300], eg[:300], er[:300]))
        sg, sr = norm(snapshot(dg), dg), norm(snapshot(dr), dr)
        for rel in sorted(set(sg) | set(sr)):
            if sg.get(rel) != sr.get(rel):
                bad.append("file %s differs (go=%r rs=%r)" % (rel, sg.get(rel), sr.get(rel)))
        if bad:
            diffs += 1
            print("DIFF argv=%s" % " ".join(argv))
            for b in bad:
                print("   " + b.replace("\n", "\n   "))
    print("TOTAL=%d DIFFS=%d" % (total, diffs))

main()
