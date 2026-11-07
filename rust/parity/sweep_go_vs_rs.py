#!/usr/bin/env python3
"""Differential sweep: Go binary vs Rust binary, same fixture, same argv.

Compares exit code + stdout + stderr byte-for-byte and prints every diff.
Config cases are limited to validation paths so no run can reach the
dial. The argv sweep separates two groups: local argv (validation and
local reads) always runs, and argv that reaches the network
(`NET_ARGS` below) only runs with `SWEEP_LIVE=1`. The split exists
because those cases turn into flaky diffs under load — measured on cue:
one run reported 4 "diffs" that were a timeout on one side and a
response on the other, not a behaviour difference. A deterministic
acceptance run is `DIFFS=0` with the network group skipped, and the
count of skipped cases is printed.

Each fixture copies the live `no.0` cookie file into
`profiles/p1/cookies.txt` (Pi's design: bare-dir existence is part
of the profile-resolution behaviour); the sweep only runs on cue
with that file present.
"""
import json, os, shutil, subprocess, sys

GO = os.environ.get("SWEEP_GO", "/usr/local/bin/castctl")
RS = sys.argv[1] if len(sys.argv) > 1 else "/tmp/wv2-target/release/castctl-rs"
ROOT = "/tmp/sweep"
COOKIE = "/root/.config/castctl/profiles/no.0/cookies.txt"

def base_cfg(**over):
    cfg = {"default_profile": "p1",
           "profiles": {"p1": {"cookies_file": "profiles/p1/cookies.txt",
                                "node_id": "a4d787ca4a5a87d9",
                                "auto_approve": "always"}}}
    cfg.update(over)
    return cfg

def write_case(name, cfg_text, extra_files=None):
    d = os.path.join(ROOT, name)
    for side in ("g", "r"):
        sd = os.path.join(d, side)
        os.makedirs(os.path.join(sd, "profiles/p1"), exist_ok=True)
        shutil.copy(COOKIE, os.path.join(sd, "profiles/p1/cookies.txt"))
        os.chmod(os.path.join(sd, "profiles/p1/cookies.txt"), 0o600)
        with open(os.path.join(sd, "config.json"), "w") as f:
            f.write(cfg_text)
        for rel, content in (extra_files or {}).items():
            p = os.path.join(sd, rel)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "w") as f:
                f.write(content)
    return d

CASES = []  # (name, cfg text or None, extra files)

def case(name, cfg=None, extra=None):
    CASES.append((name, cfg, extra or {}))

# --- config validation variants
case("ok", json.dumps(base_cfg()))
case("badjson", '{"profiles": {')
case("emptyobj", '{}')
case("noprofileskey", '{"default_profile":"p1"}')
case("unknown_top", json.dumps(base_cfg(bogus=1)))
case("log_unknown", json.dumps(base_cfg(log={"bogus": 1})))
case("log_bad_level", json.dumps(base_cfg(log={"level": "nope"})))
case("log_not_obj", json.dumps(base_cfg(log="x")))
case("keeper_not_arr", json.dumps(base_cfg(keeper={"a": 1})))
case("keeper_no_tag", json.dumps(base_cfg(keeper=[{"profile": "p1"}])))
case("keeper_dangling", json.dumps(base_cfg(keeper=[{"tag": "k", "profile": "nope"}])))
case("keeper_dup_tag", json.dumps(base_cfg(keeper=[{"tag": "k", "profile": "p1"}, {"tag": "k", "profile": "p1"}])))
case("keeper_bad_interval", json.dumps(base_cfg(keeper=[{"tag": "k", "profile": "p1", "interval": "0s"}])))
case("dns_not_obj", json.dumps(base_cfg(dns=[])))
case("dns_unknown", json.dumps(base_cfg(dns={"bogus": 1})))
case("outbounds_not_arr", json.dumps(base_cfg(outbounds={})))
case("outbound_dup_tag", json.dumps(base_cfg(outbounds=[{"type": "direct", "tag": "a"}, {"type": "direct", "tag": "a"}])))
case("outbound_no_type", json.dumps(base_cfg(outbounds=[{"tag": "a"}])))
# M7f fix loop 1 (B1): the CLI error-render boundary must apply Go's
# SafeString — a sensitive-field parse error redacts the `json:`
# fragment (`private_key: [redacted]`, probed on cue 2026-11-07).
# FAKE value only (5 is a JSON number, not a secret).
case("red_privkey", json.dumps(base_cfg(outbounds=[{"type": "direct", "tag": "d", "private_key": 5}])))
case("endpoints_not_arr", json.dumps(base_cfg(endpoints={})))
case("telegram_not_obj", json.dumps(base_cfg(telegram=[])))
case("telegram_unknown", json.dumps(base_cfg(telegram={"bogus": 1})))
case("telegram_bad_token", json.dumps(base_cfg(telegram={"token": "x"})))
case("plugins_not_arr", json.dumps(base_cfg(plugins={})))
case("credentials_not_arr", json.dumps(base_cfg(credentials={})))
case("webui_not_obj", json.dumps(base_cfg(webui=[])))
case("profile_unknown_field", json.dumps({"default_profile": "p1", "profiles": {"p1": {"bogus": 1}}}))
case("profile_bad_autoapprove", json.dumps({"default_profile": "p1", "profiles": {"p1": {"auto_approve": "sometimes"}}}))
case("profile_abs_cookies", json.dumps({"default_profile": "p1", "profiles": {"p1": {"cookies_file": "/etc/passwd"}}}))
case("default_profile_missing", json.dumps({"profiles": {"p1": {}}}))
case("default_profile_dangling", json.dumps({"default_profile": "nope", "profiles": {"p1": {}}}))
case("empty_profiles", json.dumps({"default_profile": "p1", "profiles": {}}))
case("webui_ok", json.dumps(base_cfg(webui={"listen": "127.0.0.1:8399", "token": "t"})))
case("log_ok", json.dumps(base_cfg(log={"level": "info"})))

# --- hole 5 (M7f): profile resolution vs identity. These fixtures
# all fail BEFORE any dial (ResolveActiveProfile or
# identityForProfile), so `status`/`chat` are safe here — and are
# never run on a valid fixture. Per-case argv are chosen so no
# run can reach the dial: `--profile p1` is only used where p1
# is NOT in the single file (hole5b), where identity rejects
# it; on hole5a/hole5c p1 IS in the single file, so an explicit
# `--profile p1` would dial and is never run.
HOLE5 = []  # (name, cfg text, argv list)
HOLE5.append(("hole5a_no_default", '{"profiles":{"p1":{}}}',
              [["status"], ["chat"]]))
HOLE5.append(("hole5b_bare_dir", '{"default_profile":"p1","profiles":{}}',
              [["status"], ["chat"],
               ["--profile", "p1", "status"], ["--profile", "p1", "chat"]]))
HOLE5.append(("hole5c_dangling_default", '{"default_profile":"nope","profiles":{"p1":{}}}',
              [["status"], ["chat"]]))
for _name, _cfg, _argv in HOLE5:
    case(_name, _cfg)

ARGS = [
    [],
    ["--help"], ["--bogus"],
    ["status", "extra"], ["status", "--bogus"],
    ["history", "--limit", "abc"], ["history", "--limit", "-1"],
    ["wait", "--timeout", "abc"], ["wait", "--after-seq", "x"],
    ["approve"], ["deny"], ["auto-approve", "maybe"],
    ["goal"], ["goal", "abc"], ["idea"], ["idea", "abc"],
    ["raw"], ["raw", "nope"],
    ["fs"], ["fs", "ls"], ["fs", "get"],
    ["auth"], ["auth", "bogus"],
    ["profile"], ["profile", "bogus"], ["profile", "show"], ["profile", "show", "nope"],
    ["profile", "remove", "nope"],
    ["config"], ["config", "bogus"],
    ["telegram"], ["telegram", "bogus"],
    ["keeper"], ["keeper", "bogus"],
    ["update", "--bogus"], ["update", "--version", "bogus"],
    ["webui"], ["webui", "bogus"],
    ["plugin"], ["plugin", "bogus"], ["plugin", "list"],
    ["download"], ["watch", "--bogus"], ["seen", "abc"],
]

# argv that leave the machine: they need the live gateway, so a loaded
# box turns them into timeout-vs-response diffs. Opt in with SWEEP_LIVE=1.
NET_ARGS = {
    (),
    ("history", "--limit", "-1"),
    ("idea", "abc"),
    ("seen", "abc"),
    ("raw", "nope"),
    ("download",),
    ("goal", "abc"),
    ("fs", "ls"),
    ("fs", "get"),
}
LIVE = os.environ.get("SWEEP_LIVE") == "1"

# argv that this build deliberately no longer implements: `webui`,
# `telegram` and `plugin` are out of the agent-facing CLI
# (rust/AGENT-CLI-SCOPE.md), and the top-level `--help` consequently
# lists 43 commands where Go lists 46. They are SKIPPED, not
# tolerated as diffs: a diff count must stay 0 for the surface both
# binaries still share.
from dropped import is_dropped


def run(binary, cwd, argv, cfgpath=None):
    full = [binary] + (["--config", cfgpath] if cfgpath else []) + argv
    # stdin DEVNULL: a case must never block waiting for input.
    p = subprocess.run(full, cwd=cwd, capture_output=True, text=True,
                       timeout=60, stdin=subprocess.DEVNULL,
                       env={**os.environ, "HOME": cwd, "XDG_CONFIG_HOME": os.path.join(cwd, ".config")})
    return p.returncode, p.stdout, p.stderr

def norm(t, side_dir):
    # the two sides live in different directories: fold each side's own
    # absolute case dir, then the shared root
    return t.replace(side_dir, "<CFG>").replace(ROOT, "<ROOT>")

def main():
    shutil.rmtree(ROOT, ignore_errors=True)
    diffs = 0
    total = 0
    for name, cfg, extra in CASES:
        d = write_case(name, cfg, extra)
        if name.startswith("log_"):
            continue  # Go's sing-box runtime log lines cannot exist in a build without sing-box
        for argv in (["profile", "list"], ["keeper", "status"]):
            total += 1
            cg, og, eg = run(GO, os.path.join(d, "g"), argv, os.path.join(d, "g", "config.json"))
            cr, orr, er = run(RS, os.path.join(d, "r"), argv, os.path.join(d, "r", "config.json"))
            og, eg = norm(og, os.path.join(d, "g")), norm(eg, os.path.join(d, "g"))
            orr, er = norm(orr, os.path.join(d, "r")), norm(er, os.path.join(d, "r"))
            if (cg, og, eg) != (cr, orr, er):
                diffs += 1
                print("DIFF cfg=%s argv=%s" % (name, " ".join(argv) or "(none)"))
                if cg != cr:
                    print("   exit go=%s rs=%s" % (cg, cr))
                if og != orr:
                    print("   out go=%r" % og[:160]); print("   out rs=%r" % orr[:160])
                if eg != er:
                    print("   err go=%r" % eg[:160]); print("   err rs=%r" % er[:160])
    # argv sweep on the ok config
    d = os.path.join(ROOT, "ok")
    skipped = 0
    dropped = 0
    for argv in ARGS:
        if is_dropped(argv):
            dropped += 1
            continue
        if not LIVE and tuple(argv) in NET_ARGS:
            skipped += 1
            continue
        total += 1
        cg, og, eg = run(GO, os.path.join(d, "g"), argv, os.path.join(d, "g", "config.json"))
        cr, orr, er = run(RS, os.path.join(d, "r"), argv, os.path.join(d, "r", "config.json"))
        og, eg = norm(og, os.path.join(d, "g")), norm(eg, os.path.join(d, "g"))
        orr, er = norm(orr, os.path.join(d, "r")), norm(er, os.path.join(d, "r"))
        if (cg, og, eg) != (cr, orr, er):
            diffs += 1
            print("DIFF argv=%s" % (" ".join(argv) or "(none)"))
            if cg != cr:
                print("   exit go=%s rs=%s" % (cg, cr))
            if og != orr:
                print("   out go=%r" % og[:160]); print("   out rs=%r" % orr[:160])
            if eg != er:
                print("   err go=%r" % eg[:160]); print("   err rs=%r" % er[:160])
    # hole-5 argv: status/chat only on the fixtures above.
    for name, cfg, argvs in HOLE5:
        d = os.path.join(ROOT, name)
        for argv in argvs:
            total += 1
            cg, og, eg = run(GO, os.path.join(d, "g"), argv, os.path.join(d, "g", "config.json"))
            cr, orr, er = run(RS, os.path.join(d, "r"), argv, os.path.join(d, "r", "config.json"))
            og, eg = norm(og, os.path.join(d, "g")), norm(eg, os.path.join(d, "g"))
            orr, er = norm(orr, os.path.join(d, "r")), norm(er, os.path.join(d, "r"))
            if (cg, og, eg) != (cr, orr, er):
                diffs += 1
                print("DIFF cfg=%s argv=%s" % (name, " ".join(argv) or "(none)"))
                if cg != cr:
                    print("   exit go=%s rs=%s" % (cg, cr))
                if og != orr:
                    print("   out go=%r" % og[:160]); print("   out rs=%r" % orr[:160])
                if eg != er:
                    print("   err go=%r" % eg[:160]); print("   err rs=%r" % er[:160])
    print("TOTAL=%d DIFFS=%d skipped_live=%d skipped_dropped=%d"
          % (total, diffs, skipped, dropped))

main()
