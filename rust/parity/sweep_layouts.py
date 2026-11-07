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
"""Differential sweep #2: profile/state/layout reads, Go vs Rust.

Fixtures are static (fixed cookie expiry, fixed state files) so the
outputs are deterministic; only the per-side absolute directory is
normalised away.
"""
import json, os, shutil, subprocess, sys

from dropped import is_dropped

GO = os.environ.get("SWEEP_GO", "/usr/local/bin/castctl")
RS = sys.argv[1] if len(sys.argv) > 1 else "/tmp/sw-target/release/castctl-rs"
ROOT = "/tmp/sweep2"

COOKIE_EXP = 1893456000  # 2030-01-01
JAR = ".muse.ai\tTRUE\t/\tTRUE\t%d\thatch_sess\tFAKE\n.muse.ai\tTRUE\t/\tTRUE\t%d\tother\tV\n" % (COOKIE_EXP, COOKIE_EXP)

LAYOUTS = {}

def layout(name, files, cfg=None):
    LAYOUTS[name] = (cfg, files)

SINGLE_OK = json.dumps({"default_profile": "a",
                        "profiles": {"a": {"cookies_file": "profiles/a/cookies.txt",
                                           "node_id": "n1", "auto_approve": "always"}}})

NOCFG = '{"default_profile":"a","profiles":{"a":{}}}'

layout("single_ok", {"config.json": SINGLE_OK, "profiles/a/cookies.txt": JAR})
layout("single_nocookies", {"config.json": NOCFG})
layout("single_two", {"config.json": json.dumps({"default_profile": "a", "profiles": {
    "a": {"cookies_file": "profiles/a/cookies.txt", "auto_approve": "always"},
    "b": {"cookies_file": "profiles/b/cookies.txt", "auto_approve": "off"}}}),
    "profiles/a/cookies.txt": JAR, "profiles/b/cookies.txt": JAR})
layout("single_pinned", {"config.json": json.dumps({"default_profile": "a", "profiles": {
    "a": {"cookies_file": "profiles/a/cookies.txt", "node_id": "n9", "auto_approve": "allow_once"}}}),
    "profiles/a/cookies.txt": JAR})
layout("single_state", {"config.json": SINGLE_OK, "profiles/a/cookies.txt": JAR,
    "profiles/a/session-state.json": json.dumps({"last_tick_outcome": "ok", "last_checked_at": "2026-11-06T10:00:00Z",
                                                 "cookies_seen": 7, "wrote": True, "cookies_sha256": "d"*64})})
layout("single_state_corrupt", {"config.json": SINGLE_OK, "profiles/a/cookies.txt": JAR,
    "profiles/a/session-state.json": "{not json"})
layout("single_tg", {"config.json": json.dumps({"default_profile": "a", "profiles": {"a": {"cookies_file": "profiles/a/cookies.txt"}},
    "telegram": {"token": "123456789:AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIII", "allowed_user_ids": [42]}}),
    "profiles/a/cookies.txt": JAR})
layout("single_tgstate", {"config.json": json.dumps({"default_profile": "a", "profiles": {"a": {"cookies_file": "profiles/a/cookies.txt"}},
    "telegram": {"token": "123456789:AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIII", "allowed_user_ids": [42]}}),
    "profiles/a/cookies.txt": JAR,
    "profiles/a/telegram-state.json": json.dumps({"offset": 12345, "chat_id": 42})})
layout("single_keeper", {"config.json": json.dumps({"default_profile": "a", "profiles": {"a": {}},
    "keeper": [{"tag": "k1", "profile": "a", "interval": "1h"}]})})
layout("legacy_flat", {"config.json": json.dumps({"cookies_file": "cookies.txt"}), "cookies.txt": JAR})
layout("empty_dir", {})

CMDS = [["profile", "list"], ["profile", "show"], ["profile", "show", "a"], ["auth", "status"],
        ["auth", "list"], ["telegram", "status"], ["keeper", "status"], ["config", "migrate", "--dry-run"],
        ["auto-approve", "status"], ["plugin", "list"]]

def build():
    shutil.rmtree(ROOT, ignore_errors=True)
    for name, (cfg, files) in LAYOUTS.items():
        for side in ("g", "r"):
            d = os.path.join(ROOT, name, side)
            os.makedirs(os.path.join(d, "profiles/a"), exist_ok=True)
            for rel, content in files.items():
                p = os.path.join(d, rel)
                os.makedirs(os.path.dirname(p) or d, exist_ok=True)
                with open(p, "w") as f:
                    f.write(content)
            for p in [os.path.join(d, "profiles/a/cookies.txt"), os.path.join(d, "cookies.txt")]:
                if os.path.exists(p):
                    os.chmod(p, 0o600)

def run(binary, cwd, argv, cfgpath):
    p = subprocess.run([binary, "--config", cfgpath] + argv, cwd=cwd, capture_output=True,
                       text=True, timeout=60,
                       env={**os.environ, "HOME": cwd, "XDG_CONFIG_HOME": os.path.join(cwd, ".config")})
    return p.returncode, p.stdout, p.stderr

def main():
    build()
    total = diffs = 0
    dropped = 0
    for name in LAYOUTS:
        for argv in CMDS:
            if is_dropped(argv):
                dropped += 1
                continue
            total += 1
            dg, dr = os.path.join(ROOT, name, "g"), os.path.join(ROOT, name, "r")
            cfg_g, cfg_r = os.path.join(dg, "config.json"), os.path.join(dr, "config.json")
            if not os.path.exists(cfg_g):
                continue
            cg, og, eg = run(GO, dg, argv, cfg_g)
            cr, orr, er = run(RS, dr, argv, cfg_r)
            og = og.replace(dg, "<CFG>").replace(ROOT, "<ROOT>")
            eg = eg.replace(dg, "<CFG>").replace(ROOT, "<ROOT>")
            orr = orr.replace(dr, "<CFG>").replace(ROOT, "<ROOT>")
            er = er.replace(dr, "<CFG>").replace(ROOT, "<ROOT>")
            if (cg, og, eg) != (cr, orr, er):
                diffs += 1
                print("DIFF layout=%s argv=%s" % (name, " ".join(argv)))
                if cg != cr:
                    print("   exit go=%s rs=%s" % (cg, cr))
                if og != orr:
                    print("   out go=%r" % og[:300])
                    print("   out rs=%r" % orr[:300])
                if eg != er:
                    print("   err go=%r" % eg[:300])
                    print("   err rs=%r" % er[:300])
    print("TOTAL=%d DIFFS=%d skipped_dropped=%d" % (total, diffs, dropped))

main()
