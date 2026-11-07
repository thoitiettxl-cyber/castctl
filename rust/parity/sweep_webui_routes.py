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
"""Differential sweep #6: Web UI route surface, Go vs Rust.

Starts both binaries' `webui serve` on scratch configs, then walks the
route table (GET/POST/PUT/DELETE where meaningful) in two auth states and
compares status code + normalised body.
"""
import json, os, re, shutil, signal, subprocess, sys, time, urllib.error, urllib.request

GO = "/usr/local/bin/castctl"
RS = sys.argv[1] if len(sys.argv) > 1 else "/tmp/sw-target/release/castctl-rs"
D = "/tmp/sweep6"
TOKEN = "sweeptoken"
JAR = ".muse.ai\tTRUE\t/\tTRUE\t1893456000\thatch_sess\tFAKE\n"

ROUTES = [
    ("GET", "/"), ("GET", "/index.html"), ("GET", "/api/v1"),
    ("GET", "/api/v1/status"), ("GET", "/api/v1/config"), ("GET", "/api/v1/dns"),
    ("GET", "/api/v1/outbounds"), ("GET", "/api/v1/endpoints"), ("GET", "/api/v1/profiles"),
    ("GET", "/api/v1/keeper"), ("GET", "/api/v1/logs"), ("GET", "/api/v1/plugins"),
    ("GET", "/api/v1/settings/keeper"), ("GET", "/api/v1/settings/telegram"),
    ("GET", "/api/v1/settings/webui"), ("GET", "/api/v1/screencast/status"),
    ("GET", "/api/v1/profiles/a"), ("GET", "/api/v1/profiles/nope"),
    ("GET", "/api/v1/profiles/a/login/status"), ("GET", "/api/v1/profiles/evil/login/status"),
    ("GET", "/api/v1/profiles/a/test"), ("GET", "/api/v1/chats"),
    ("GET", "/api/v1/chats/jobs/does-not-exist"), ("GET", "/api/v1/nope"),
    ("POST", "/api/v1/login"), ("POST", "/api/v1/config/validate"),
    ("POST", "/api/v1/outbounds/validate"), ("POST", "/api/v1/profiles"),
    ("POST", "/api/v1/profiles/a/rename"), ("POST", "/api/v1/profiles/a/set-default"),
    ("POST", "/api/v1/screencast/a/start"), ("POST", "/api/v1/screencast/status"),
    ("POST", "/api/v1/profiles/a/login/import"),
    ("PUT", "/api/v1/settings/webui"), ("PUT", "/api/v1/keeper"), ("PUT", "/api/v1/config"),
    ("DELETE", "/api/v1/profiles/a"), ("DELETE", "/api/v1/plugins/nope"),
    ("HEAD", "/"), ("POST", "/api/v1/status"), ("OPTIONS", "/api/v1/status"),
    ("GET", "/api/v1/../api/v1/status"), ("GET", "//api/v1/status"),
]

def build():
    shutil.rmtree(D, ignore_errors=True)
    for side, port in (("g", 18401), ("r", 18402)):
        d = os.path.join(D, side)
        os.makedirs(os.path.join(d, "profiles/a"), exist_ok=True)
        cfg = {"default_profile": "a", "profiles": {"a": {"cookies_file": "profiles/a/cookies.txt"}},
               "webui": {"listen": "127.0.0.1:%d" % port, "token": TOKEN,
                         "login_rate_limit": {"attempts": 1000, "window": "5m"}}}
        json.dump(cfg, open(os.path.join(d, "config.json"), "w"), indent=2)
        p = os.path.join(d, "profiles/a/cookies.txt")
        open(p, "w").write(JAR)
        os.chmod(p, 0o600)

def start(binary, d, port):
    log = open(os.path.join(d, "serve.log"), "w")
    p = subprocess.Popen([binary, "--config", os.path.join(d, "config.json"), "webui", "serve"],
                         cwd=d, stdout=log, stderr=log,
                         env={**os.environ, "HOME": d, "XDG_CONFIG_HOME": os.path.join(d, ".config")})
    for _ in range(100):
        try:
            urllib.request.urlopen("http://127.0.0.1:%d/" % port, timeout=1).read(10)
            return p
        except urllib.error.HTTPError:
            return p
        except Exception:
            time.sleep(0.1)
    return p

def req(port, method, path, auth):
    url = "http://127.0.0.1:%d%s" % (port, path)
    data = b"{}" if method in ("POST", "PUT") else None
    r = urllib.request.Request(url, data=data, method=method)
    if auth:
        r.add_header("Authorization", "Bearer " + TOKEN)
    if data is not None:
        r.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(r, timeout=10) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except Exception as e:
        return "ERR", str(e).encode()

VOLATILE = [rb'"timestamp":\s*"[^"]*"', rb'"now":\s*\d+', rb'"elapsed[^"]*":\s*[\d.]+',
            rb'"go_version":\s*"[^"]*"', rb'"singbox_version":\s*"[^"]*"',
            rb'"version":\s*"[^"]*"', rb'"sha256":\s*"[0-9a-f]+"', rb'"mtime[^"]*":\s*[\d.]+',
            rb'"size":\s*\d+', rb'"listen_addr":\s*"[^"]*"', rb'"config_path":\s*"[^"]*"',
            rb'"vm_id":\s*"[^"]*"', rb'"sessions":\s*\d+', rb'"seen_at_ms":\s*\d+',
            rb'"expires[^"]*":\s*[^,}]+', rb'"next[^"]*":\s*[^,}]+', rb'"pid":\s*\d+']

def norm(b):
    for pat in VOLATILE:
        b = re.sub(pat, b'"<V>"', b)
    b = re.sub(rb"\d{4}-\d\d-\d\dT[0-9:.]+Z?", b"<TS>", b)
    return b

def main():
    build()
    procs = {"g": start(GO, os.path.join(D, "g"), 18401), "r": start(RS, os.path.join(D, "r"), 18402)}
    total = diffs = 0
    try:
        for method, path in ROUTES:
            for auth in (True, False):
                total += 1
                sg, bg = req(18401, method, path, auth)
                sr, br = req(18402, method, path, auth)
                bg, br = norm(bg), norm(br)
                if (sg, bg) != (sr, br):
                    diffs += 1
                    print("DIFF %s %s auth=%s" % (method, path, auth))
                    print("   go %s %r" % (sg, bg[:200]))
                    print("   rs %s %r" % (sr, br[:200]))
        # login with a wrong token, then the same again (rate-limit shape)
        for _ in range(2):
            total += 1
            sg, bg = req(18401, "POST", "/api/v1/login", True)
            sr, br = req(18402, "POST", "/api/v1/login", True)
            if (sg, norm(bg)) != (sr, norm(br)):
                diffs += 1
                print("DIFF POST /api/v1/login(bad body) go %s %r rs %s %r" % (sg, bg[:120], sr, br[:120]))
    finally:
        for p in procs.values():
            p.send_signal(signal.SIGTERM)
            try:
                p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                p.kill()
    print("TOTAL=%d DIFFS=%d" % (total, diffs))

main()
