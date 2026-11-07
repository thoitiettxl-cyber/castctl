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
"""Differential sweep #5: config/profile location resolution (env + argv)."""
import json, os, shutil, subprocess, sys

GO = "/usr/local/bin/castctl"
RS = sys.argv[1] if len(sys.argv) > 1 else "/tmp/sw-target/release/castctl-rs"
D = "/tmp/sweep5"
JAR = ".muse.ai\tTRUE\t/\tTRUE\t1893456000\thatch_sess\tFAKE\n"
SINGLE = json.dumps({"default_profile": "a", "profiles": {"a": {"cookies_file": "profiles/a/cookies.txt"}}})

def build():
    shutil.rmtree(D, ignore_errors=True)
    for side in ("g", "r"):
        d = os.path.join(D, side)
        # layout A: single config under .config/castctl
        a = os.path.join(d, "A/.config/castctl")
        os.makedirs(os.path.join(a, "profiles/a"), exist_ok=True)
        open(os.path.join(a, "config.json"), "w").write(SINGLE)
        open(os.path.join(a, "profiles/a/cookies.txt"), "w").write(JAR)
        os.chmod(os.path.join(a, "profiles/a/cookies.txt"), 0o600)
        # layout B: empty home
        os.makedirs(os.path.join(d, "B/.config"), exist_ok=True)
        # layout C: legacy flat dir passed with --config
        c = os.path.join(d, "C")
        os.makedirs(c, exist_ok=True)
        open(os.path.join(c, "config.json"), "w").write(json.dumps({"cookies_file": "cookies.txt"}))
        open(os.path.join(c, "cookies.txt"), "w").write(JAR)
        os.chmod(os.path.join(c, "cookies.txt"), 0o600)

CASES = [
    # (name, env overrides builder, argv)
    ("A_default", lambda d: {"HOME": d + "/A", "XDG_CONFIG_HOME": d + "/A/.config"}, ["profile", "list"]),
    ("A_no_xdg", lambda d: {"HOME": d + "/A", "XDG_CONFIG_HOME": ""}, ["profile", "list"]),
    ("A_relative_xdg", lambda d: {"HOME": d + "/A", "XDG_CONFIG_HOME": ".config"}, ["profile", "list"]),
    ("A_home_only", lambda d: {"HOME": d + "/A", "XDG_CONFIG_HOME": None}, ["profile", "list"]),
    ("A_cfg_flag", lambda d: {"HOME": d + "/B", "XDG_CONFIG_HOME": d + "/B/.config"}, ["--config", "<D>/A/.config/castctl/config.json", "profile", "list"]),
    ("A_cfg_flag_badname", lambda d: {"HOME": d + "/B", "XDG_CONFIG_HOME": d + "/B/.config"}, ["--config", "<D>/A/.config/castctl/other.json", "profile", "list"]),
    ("A_cfg_flag_missing", lambda d: {"HOME": d + "/B", "XDG_CONFIG_HOME": d + "/B/.config"}, ["--config", "<D>/nope/config.json", "profile", "list"]),
    ("A_profile_unknown", lambda d: {"HOME": d + "/A", "XDG_CONFIG_HOME": d + "/A/.config"}, ["--profile", "zzz", "profile", "list"]),
    ("A_profile_empty", lambda d: {"HOME": d + "/A", "XDG_CONFIG_HOME": d + "/A/.config"}, ["--profile", "", "profile", "list"]),
    ("A_profile_eq", lambda d: {"HOME": d + "/A", "XDG_CONFIG_HOME": d + "/A/.config"}, ["--profile=a", "profile", "list"]),
    ("A_profile_eq_empty", lambda d: {"HOME": d + "/A", "XDG_CONFIG_HOME": d + "/A/.config"}, ["--profile=", "profile", "list"]),
    ("A_dashdash", lambda d: {"HOME": d + "/A", "XDG_CONFIG_HOME": d + "/A/.config"}, ["--", "profile", "list"]),
    ("A_flag_after_cmd", lambda d: {"HOME": d + "/A", "XDG_CONFIG_HOME": d + "/A/.config"}, ["profile", "list", "--profile", "a"]),
    ("B_no_config", lambda d: {"HOME": d + "/B", "XDG_CONFIG_HOME": d + "/B/.config"}, ["profile", "list"]),
    ("B_no_config_status", lambda d: {"HOME": d + "/B", "XDG_CONFIG_HOME": d + "/B/.config"}, ["status"]),
    ("C_legacy_flag", lambda d: {"HOME": d + "/B", "XDG_CONFIG_HOME": d + "/B/.config"}, ["--config", "<D>/C/config.json", "profile", "list"]),
    ("C_legacy_flag_show", lambda d: {"HOME": d + "/B", "XDG_CONFIG_HOME": d + "/B/.config"}, ["--config", "<D>/C/config.json", "profile", "show"]),
    ("C_legacy_migrate_dry", lambda d: {"HOME": d + "/B", "XDG_CONFIG_HOME": d + "/B/.config"}, ["--config", "<D>/C/config.json", "config", "migrate", "--dry-run"]),
]

def main():
    build()
    total = diffs = 0
    for name, envf, argv in CASES:
        total += 1
        res = []
        for side, binary in (("g", GO), ("r", RS)):
            d = os.path.join(D, side)
            env = {**os.environ, "PATH": "/usr/local/bin:/usr/bin:/bin"}
            for k, v in envf(d).items():
                if v is None:
                    env.pop(k, None)
                elif v == "":
                    env[k] = ""
                else:
                    env[k] = v.replace("<D>", d)
            cmd = [binary] + [a.replace("<D>", d) for a in argv]
            try:
                p = subprocess.run(cmd, cwd=d, capture_output=True, text=True, timeout=60, env=env)
                res.append((p.returncode, p.stdout.replace(d, "<D>"), p.stderr.replace(d, "<D>")))
            except subprocess.TimeoutExpired:
                res.append(("TIMEOUT", "", ""))
        if res[0] != res[1]:
            diffs += 1
            print("DIFF case=%s argv=%s" % (name, " ".join(argv)))
            for lbl, r in (("go", res[0]), ("rs", res[1])):
                print("   %s exit=%s out=%r err=%r" % (lbl, r[0], r[1][:250], r[2][:250]))
    print("TOTAL=%d DIFFS=%d" % (total, diffs))

main()
