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
"""Differential sweep #3: flag/argument parsing edges, Go vs Rust.

Only argv that must fail before any network I/O (invalid values, missing
values, unknown flags, bad enum choices, extra positionals). A case that
times out counts as a diff unless both sides time out.
"""
import json, os, shutil, subprocess, sys

from dropped import is_dropped

GO = os.environ.get("SWEEP_GO", "/usr/local/bin/castctl")
RS = sys.argv[1] if len(sys.argv) > 1 else "/tmp/sw-target/release/castctl-rs"
D = "/tmp/sweep3"
CFG = json.dumps({"default_profile": "a",
                  "profiles": {"a": {"cookies_file": "profiles/a/cookies.txt",
                                     "node_id": "n1", "auto_approve": "always"}},
                  "telegram": {"token": "123456789:AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIII",
                               "allowed_user_ids": [42]},
                  "webui": {"listen": "127.0.0.1:8398", "token": "t"},
                  "keeper": [{"tag": "k1", "profile": "a"}]})

CASES = [
    ["history", "--limit"], ["history", "--limit", ""], ["history", "--limit", "1e3"],
    ["history", "--limit", "0"], ["history", "--limit", "999999999999999999999"],
    ["wait", "--timeout", "-1"], ["wait", "--timeout", "1x"], ["wait", "--timeout"],
    ["wait", "--after-seq", "-3"], ["wait", "--after-seq"],
    ["send", "--text"], ["send", "--thread"], ["send", "--chat"],
    ["send", "a", "b"], ["send", "--wait", "--no-wait"],
    ["files", "--format", "xml"], ["files", "--format"],
    ["threads", "--limit", "no"],
    ["feed", "--limit", "no"], ["feed", "--since", "nope"],
    ["goals", "--status", "weird"], ["ideas", "--limit", "x"],
    ["approvals", "--status", "weird"],
    ["auto-approve", "--status"], ["auto-approve", "on", "off"],
    ["seen", "--thread"], ["seen", "t", "--seq", "x"],
    ["watch", "--since", "x"], ["watch", "--limit", "x"],
    ["raw", "--method"], ["raw", "--body"], ["raw", "x", "--method", "TRACE"],
    ["fs", "ls", "--long", "--json"], ["fs", "get"], ["fs", "put"],
    ["fs", "rm"], ["fs", "bogus"],
    ["session-start", "--title"], ["session-rename"], ["session-pin", "--state", "x"],
    ["session-delete", "x", "--force", "--no-force"],
    ["stop", "--thread"], ["wake", "--profile"],
    ["invite", "--json"], ["redeem"], ["download"],
    ["feed-react", "x", "y", "z"], ["feed-prompt", "--limit", "x"],
    ["idea-exec", "--bogus"],
    ["update", "--version"], ["update", "--allow-downgrade", "--version", ""],
    ["webui", "serve", "--bogus"],
    ["telegram", "run", "--bogus"], ["telegram", "status", "--bogus"],
    ["keeper", "run", "--bogus"], ["keeper", "check", "--tag", ""],
    ["profile", "set-fingerprint", "nope"], ["profile", "set-fingerprint"],
    ["profile", "test", "--bogus"], ["profile", "create"], ["profile", "create", "a"],
    ["profile", "rename", "a"], ["profile", "rm"],
    ["profile", "import", "--bogus"], ["profile", "export", "--bogus"],
    ["config", "migrate", "--write", "--dry-run"], ["config", "set", "x"],
    ["plugin", "check"], ["plugin", "install"], ["plugin", "remove"],
    ["plugin", "enable", "nope"], ["plugin", "disable"],
    ["auth", "import"], ["auth", "observe-login", "--bogus"], ["auth", "export", "--bogus"],
]

def setup():
    shutil.rmtree(D, ignore_errors=True)
    jar = ".muse.ai\tTRUE\t/\tTRUE\t1893456000\thatch_sess\tFAKE\n"
    for side in ("g", "r"):
        d = os.path.join(D, side)
        os.makedirs(os.path.join(d, "profiles/a"), exist_ok=True)
        with open(os.path.join(d, "config.json"), "w") as f:
            f.write(CFG)
        p = os.path.join(d, "profiles/a/cookies.txt")
        with open(p, "w") as f:
            f.write(jar)
        os.chmod(p, 0o600)

def run(binary, argv, side):
    d = os.path.join(D, side)
    try:
        p = subprocess.run([binary, "--config", os.path.join(d, "config.json")] + argv, cwd=d,
                           capture_output=True, text=True, timeout=20,
                           env={**os.environ, "HOME": d, "XDG_CONFIG_HOME": os.path.join(d, ".config")})
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return "TIMEOUT", "", ""

def main():
    setup()
    total = diffs = 0
    dropped = 0
    for argv in CASES:
        if is_dropped(argv):
            dropped += 1
            continue
        total += 1
        cg, og, eg = run(GO, argv, "g")
        cr, orr, er = run(RS, argv, "r")
        dg, dr = os.path.join(D, "g"), os.path.join(D, "r")
        og, eg = og.replace(dg, "<CFG>"), eg.replace(dg, "<CFG>")
        orr, er = orr.replace(dr, "<CFG>"), er.replace(dr, "<CFG>")
        if (cg, og, eg) != (cr, orr, er):
            diffs += 1
            print("DIFF argv=%s" % " ".join(repr(a) for a in argv))
            if cg != cr:
                print("   exit go=%s rs=%s" % (cg, cr))
            if og != orr:
                print("   out go=%r" % og[:300]); print("   out rs=%r" % orr[:300])
            if eg != er:
                print("   err go=%r" % eg[:300]); print("   err rs=%r" % er[:300])
    print("TOTAL=%d DIFFS=%d skipped_dropped=%d" % (total, diffs, dropped))

main()
