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
"""Differential sweep: secret redaction in CLI error output, Go vs Rust.

Go routes every error line through classifyError -> SummarizeErr ->
SafeString, which replaces secret-bearing fields with [redacted]. A port
that prints the raw message leaks the value. Each case below puts a
secret in an error position and compares stderr byte-for-byte.
"""
import json, os, shutil, subprocess, sys

from dropped import is_dropped

GO = os.environ.get("SWEEP_GO", "/usr/local/bin/castctl")
RS = sys.argv[1] if len(sys.argv) > 1 else "/tmp/sc-target/release/castctl-rs"
D = "/tmp/sweep8"
JAR = ".muse.ai\tTRUE\t/\tTRUE\t1893456000\thatch_sess\tFAKE\n"

def cfg(**over):
    c = {"default_profile": "a", "profiles": {"a": {"cookies_file": "profiles/a/cookies.txt"}}}
    c.update(over)
    return json.dumps(c, indent=2)

CASES = [
    ("wg_private_key_int", cfg(outbounds=[{"type": "wireguard", "tag": "wg", "private_key": 5}]),
     ["profile", "list"]),
    ("wg_private_key_obj", cfg(outbounds=[{"type": "wireguard", "tag": "wg", "private_key": {"k": "SECRETVALUE"}}]),
     ["keeper", "status"]),
    ("ss_password_number", cfg(outbounds=[{"type": "shadowsocks", "tag": "ss", "password": 1234567}]),
     ["profile", "list"]),
    ("trojan_password_obj", cfg(outbounds=[{"type": "trojan", "tag": "t", "password": {"p": "SECRET"}}]),
     ["profile", "list"]),
    ("telegram_token_int", cfg(telegram={"token": 123456789, "allowed_user_ids": [1]}),
     ["telegram", "status"]),
    ("credentials_secret", cfg(credentials=[{"tag": "c", "username": 12, "password": 34}]),
     ["profile", "list"]),
    ("endpoint_wg_key", cfg(endpoints=[{"type": "wireguard", "tag": "e", "private_key": "NOTAKEY"}]),
     ["profile", "list"]),
    ("webui_token_type", cfg(webui={"listen": "127.0.0.1:8390", "token": 42}),
     ["profile", "list"]),
    ("hysteria2_password", cfg(outbounds=[{"type": "hysteria2", "tag": "h", "password": {"x": 1}}]),
     ["keeper", "status"]),
    ("vless_uuid_obj", cfg(outbounds=[{"type": "vless", "tag": "v", "uuid": {"u": "SECRETUUID"}}]),
     ["profile", "list"]),
]

def build(name, text):
    d = os.path.join(D, name)
    shutil.rmtree(d, ignore_errors=True)
    for side in ("g", "r"):
        sd = os.path.join(d, side)
        os.makedirs(os.path.join(sd, "profiles/a"), exist_ok=True)
        open(os.path.join(sd, "config.json"), "w").write(text)
        p = os.path.join(sd, "profiles/a/cookies.txt")
        open(p, "w").write(JAR)
        os.chmod(p, 0o600)
    return d

def run(binary, d, argv):
    p = subprocess.run([binary, "--config", os.path.join(d, "config.json")] + argv, cwd=d,
                       capture_output=True, text=True, timeout=60,
                       env={**os.environ, "HOME": d, "XDG_CONFIG_HOME": os.path.join(d, ".config")})
    return p.returncode, p.stdout, p.stderr

def main():
    shutil.rmtree(D, ignore_errors=True)
    total = diffs = 0
    dropped = 0
    for name, text, argv in CASES:
        if is_dropped(argv):
            dropped += 1
            continue
        total += 1
        d = build(name, text)
        dg, dr = os.path.join(d, "g"), os.path.join(d, "r")
        cg, og, eg = run(GO, dg, argv)
        cr, orr, er = run(RS, dr, argv)
        og, eg = og.replace(dg, "<CFG>"), eg.replace(dg, "<CFG>")
        orr, er = orr.replace(dr, "<CFG>"), er.replace(dr, "<CFG>")
        if (cg, og, eg) != (cr, orr, er):
            diffs += 1
            print("DIFF case=%s argv=%s" % (name, " ".join(argv)))
            if cg != cr:
                print("   exit go=%s rs=%s" % (cg, cr))
            if og != orr:
                print("   out go=%r" % og[:300]); print("   out rs=%r" % orr[:300])
            if eg != er:
                print("   err go=%r" % eg[:300]); print("   err rs=%r" % er[:300])
    print("TOTAL=%d DIFFS=%d skipped_dropped=%d" % (total, diffs, dropped))

main()
