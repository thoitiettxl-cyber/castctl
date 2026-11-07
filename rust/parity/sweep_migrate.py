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
"""Differential sweep #4: `config migrate --write` byte-for-byte.

Each layout is written into two scratch dirs; both binaries run the same
migrate; the resulting config.json (and any other produced file) must be
byte-identical, plus identical stdout/stderr.
"""
import difflib, json, os, re, shutil, subprocess, sys

GO = "/usr/local/bin/castctl"
RS = sys.argv[1] if len(sys.argv) > 1 else "/tmp/sw-target/release/castctl-rs"
D = "/tmp/sweep4"
JAR = ".muse.ai\tTRUE\t/\tTRUE\t1893456000\thatch_sess\tFAKE\n"

LAYOUTS = {
    "flat_only": {"config.json": json.dumps({"cookies_file": "cookies.txt", "node_id": "n1"}), "cookies.txt": JAR},
    "default_profile_dir": {"profiles/default/config.json": json.dumps({"cookies_file": "cookies.txt"}),
                            "profiles/default/cookies.txt": JAR},
    "named_profile_dirs": {
        "profiles/alpha/config.json": json.dumps({"cookies_file": "cookies.txt", "auto_approve": "always"}),
        "profiles/alpha/cookies.txt": JAR,
        "profiles/beta/config.json": json.dumps({"cookies_file": "cookies.txt"}),
        "profiles/beta/cookies.txt": JAR},
    "mixed_flat_and_dirs": {
        "config.json": json.dumps({"cookies_file": "cookies.txt"}),
        "cookies.txt": JAR,
        "profiles/alpha/config.json": json.dumps({"cookies_file": "cookies.txt"}),
        "profiles/alpha/cookies.txt": JAR},
    "already_migrated": {"config.json": json.dumps({"default_profile": "a", "profiles": {"a": {"cookies_file": "profiles/a/cookies.txt"}}}),
                         "profiles/a/cookies.txt": JAR},
    "legacy_with_blocks": {
        "profiles/default/config.json": json.dumps({"cookies_file": "cookies.txt",
                                                    "log": {"level": "debug"},
                                                    "telegram": {"token": "1:A", "allowed_user_ids": [7]}}),
        "profiles/default/cookies.txt": JAR},
    "legacy_unknown_field": {
        "profiles/default/config.json": json.dumps({"cookies_file": "cookies.txt", "extra_thing": {"keep": True}}),
        "profiles/default/cookies.txt": JAR},
    "legacy_dns_block": {
        "profiles/default/config.json": json.dumps({"cookies_file": "cookies.txt",
                                                    "dns": {"servers": [{"address": "1.1.1.1"}]}}),
        "profiles/default/cookies.txt": JAR},
    "empty_dir": {},
    "only_empty_profiles_dir": {"profiles/x/.keep": ""},
}

def setup():
    shutil.rmtree(D, ignore_errors=True)
    for name, files in LAYOUTS.items():
        for side in ("g", "r"):
            d = os.path.join(D, name, side)
            os.makedirs(d, exist_ok=True)
            for rel, content in files.items():
                p = os.path.join(d, rel)
                os.makedirs(os.path.dirname(p), exist_ok=True)
                with open(p, "w") as f:
                    f.write(content)
                if rel.endswith("cookies.txt"):
                    os.chmod(p, 0o600)

def snapshot(d):
    out = {}
    for root, _dirs, files in os.walk(d):
        for fn in files:
            p = os.path.join(root, fn)
            rel = os.path.relpath(p, d)
            with open(p, "rb") as f:
                out[rel] = f.read()
    return out

def run(binary, d, argv):
    p = subprocess.run([binary, "--config", os.path.join(d, "config.json")] + argv, cwd=d,
                       capture_output=True, text=True, timeout=120,
                       env={**os.environ, "HOME": d, "XDG_CONFIG_HOME": os.path.join(d, ".config")})
    return p.returncode, p.stdout, p.stderr

def main():
    setup()
    total = diffs = 0
    for name in LAYOUTS:
        total += 1
        dg, dr = os.path.join(D, name, "g"), os.path.join(D, name, "r")
        cg, og, eg = run(GO, dg, ["config", "migrate", "--write"])
        cr, orr, er = run(RS, dr, ["config", "migrate", "--write"])
        og, eg = og.replace(dg, "<CFG>"), eg.replace(dg, "<CFG>")
        orr, er = orr.replace(dr, "<CFG>"), er.replace(dr, "<CFG>")
        bad = []
        if (cg, og, eg) != (cr, orr, er):
            bad.append("process: exit go=%s rs=%s\n out go=%r\n out rs=%r\n err go=%r\n err rs=%r"
                       % (cg, cr, og[:400], orr[:400], eg[:400], er[:400]))
        def norm_snap(snap, side_dir):
            # the two sides live in different dirs; node_id is derived
            # from the machine/path and is expected to differ
            return {k: re.sub(rb'"node_id": "[0-9a-f]{16}"', b'"node_id": "<ID>"',
                              v.replace(side_dir.encode(), b"<CFG>"))
                    for k, v in snap.items()}
        sg, sr = norm_snap(snapshot(dg), dg), norm_snap(snapshot(dr), dr)
        for rel in sorted(set(sg) | set(sr)):
            a, b = sg.get(rel), sr.get(rel)
            if a != b:
                if a is None or b is None:
                    bad.append("file %s only on %s side" % (rel, "go" if b is None else "rust"))
                else:
                    try:
                        da = a.decode().splitlines()
                        db = b.decode().splitlines()
                        delta = "\n".join(list(difflib.unified_diff(da, db, "go", "rust", lineterm=""))[:40])
                    except UnicodeDecodeError:
                        delta = "<binary differs>"
                    bad.append("file %s differs:\n%s" % (rel, delta))
        if bad:
            diffs += 1
            print("DIFF layout=%s" % name)
            for b in bad:
                print("   " + b.replace("\n", "\n   "))
    print("TOTAL=%d DIFFS=%d" % (total, diffs))

main()
