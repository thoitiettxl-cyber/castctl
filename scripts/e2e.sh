#!/usr/bin/env bash
# castctl end-to-end test (phase 2, item 3).
#
# Runs the whole castctl core against a caller-supplied config copy and
# prints one PASS/FAIL/SKIP verdict per check. See docs/e2e.md for the
# full plan, the isolation rules, and the [NEEDS-MEASUREMENT] gaps.
#
# Usage:
#   scripts/e2e.sh --config PATH <profile>... [--live-send] [--live-keeper] [--binary PATH] [--help]
#
# Rules this script implements (Boss-decided, 2026-11-01):
# - Every castctl invocation passes --config pointing at a temp copy.
#   The supplied config is never modified; ~/.config/castctl is never
#   read or written. State, logs and ports live under one temp dir
#   (mktemp -d, mode 0700) removed by a trap on EXIT/INT/TERM. On
#   INT/TERM the signal trap ENDS the run: it kills servers, removes
#   the temp dir, and exits without printing a summary or a
#   secret-scan verdict.
# - The Telegram token comes only from the environment
#   (CASTCTL_TELEGRAM_TOKEN). castctl itself reads the Telegram token
#   only from config; the env var is a script-level convenience: the
#   script injects it into the temp config copy only, never into the
#   supplied config, and never prints it. A whitespace-only token
#   counts as unset. After injection the env var is unset so child
#   processes cannot inherit it; a saved shell copy serves only the
#   final scan. The web UI token is generated inside the script and
#   injected into the temp copy's `webui` block (there is no
#   environment token source for the web UI anymore): the generated
#   value is held only for the auth header file and the final scan,
#   and is never printed. A CASTCTL_WEBUI_KEY in the environment is
#   ignored and unset early so no child can inherit it.
# - Real messages are sent only with --live-send. Without it, the
#   send/watch/approval-positive legs SKIP with a reason.
# - Cookies are never copied and never read. The temp copy's
#   cookies_file paths point at the ORIGINAL absolute paths; the
#   script records sha256+mtime of each original (and .bak) before
#   and after the legs and FAILs on any unexpected change. Keeper
#   legs that would rewrite cookies stay dry/SKIP unless
#   --live-keeper is given. --live-send does NOT imply --live-keeper.
# - Exit code is non-zero if any check FAILs. A sandbox SKIP never
#   counts as a PASS; the summary lists every SKIP separately.
# - The final secret scan prints counts only, never a matched value.
#   Bare (unlabelled) secrets cannot be proven absent by scanning;
#   see docs/e2e.md for the honest residual.

umask 077
set -u
set -o pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname -- "$SCRIPT_DIR")"
BUILD_TAGS='with_utls,with_quic,with_wireguard,with_gvisor,with_chromedp'
SANDBOX_STRING='first record does not look like a TLS handshake'
# Fake placeholder key material, used ONLY in crafted config variants
# to prove error text is value-free. Never a real key.
FAKE_WG_KEY='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='
FAKE_WG_PUB='BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB='

CONFIG_PATH=''
LIVE_SEND=0
LIVE_KEEPER=0
BINARY_PATH=''
declare -a PROFILES=()

usage() {
    cat <<'USAGE'
usage: scripts/e2e.sh --config PATH <profile>... [--live-send] [--live-keeper] [--binary PATH] [--help]

  --config PATH   config.json file to test (required, must exist).
                  A temp copy is made; the supplied file is never modified.
  <profile>...    one or more profile names to exercise (required).
  --live-send     opt-in: send one real probe message per profile.
                  Without it, send/watch/approval-positive legs SKIP.
  --live-keeper   opt-in: allow keeper legs that would rewrite cookies
                  to run. Without it, those legs stay dry/SKIP with a
                  reason, and any change to a cookies original FAILs.
                  --live-send does NOT imply --live-keeper.
  --binary PATH   castctl binary to test. Without it, the script builds
                  one from this checkout with the approved build tags.
  --help, -h      print this usage and exit 0.

The Telegram token comes only from the environment:
CASTCTL_TELEGRAM_TOKEN. The web UI token is generated inside the
script and injected into the temp config copy's `webui` block.
See docs/e2e.md.
USAGE
}

# ---- argument parsing -------------------------------------------------
while [ "$#" -gt 0 ]; do
    case "$1" in
        --config)
            [ "$#" -ge 2 ] || { usage >&2; exit 2; }
            CONFIG_PATH="$2"; shift 2 ;;
        --config=*)
            CONFIG_PATH="${1#--config=}"; shift ;;
        --binary)
            [ "$#" -ge 2 ] || { usage >&2; exit 2; }
            BINARY_PATH="$2"; shift 2 ;;
        --binary=*)
            BINARY_PATH="${1#--binary=}"; shift ;;
        --live-send)
            LIVE_SEND=1; shift ;;
        --live-keeper)
            LIVE_KEEPER=1; shift ;;
        --help|-h)
            usage; exit 0 ;;
        --)
            shift
            while [ "$#" -gt 0 ]; do PROFILES+=("$1"); shift; done ;;
        --*)
            printf 'e2e: unrecognized argument: %s\n' "$1" >&2
            usage >&2; exit 2 ;;
        *)
            PROFILES+=("$1"); shift ;;
    esac
done

[ -n "$CONFIG_PATH" ] || { printf 'e2e: --config PATH is required\n' >&2; usage >&2; exit 2; }
[ "${#PROFILES[@]}" -ge 1 ] || { printf 'e2e: at least one profile name is required\n' >&2; usage >&2; exit 2; }
[ -f "$CONFIG_PATH" ] || { printf 'e2e: --config file does not exist: %s\n' "$CONFIG_PATH" >&2; exit 2; }
[ "$(basename -- "$CONFIG_PATH")" = 'config.json' ] || { printf 'e2e: --config path must name a config.json file\n' >&2; exit 2; }
SUPPLIED_CONFIG="$(CDPATH= cd -- "$(dirname -- "$CONFIG_PATH")" && pwd)/config.json"
SUPPLIED_DIR="$(dirname -- "$SUPPLIED_CONFIG")"

# ---- required tools (fail fast) ---------------------------------------
# python3, sha256sum and stat are required by every run (config
# handling, hashing, mode checks). go, curl and ss are
# per-leg: a missing one SKIPs its leg with a reason instead of
# failing the whole run. See docs/e2e.md prerequisites.
for _tool in python3 sha256sum stat; do
    command -v "$_tool" >/dev/null 2>&1 || { printf 'e2e: required tool missing: %s\n' "$_tool" >&2; exit 2; }
done
unset _tool

# ---- temp dir, trap, verdict recording --------------------------------
# The trap is installed immediately after mktemp/chmod, before the
# mode check, so every exit path (including a mode-check failure)
# removes the temp dir. cleanup is idempotent: it guards unset/empty
# variables and dead PIDs, so the EXIT trap and the signal handler
# can both run it.
E2E_TMP="$(mktemp -d)"
chmod 0700 "$E2E_TMP"
CFG_DIR="$E2E_TMP/config"
OUT_DIR="$E2E_TMP/out"
WEBUI_DIR="$E2E_TMP/webui"
LOG_DIR="$E2E_TMP/logfiles"
VERDICTS="$OUT_DIR/verdicts.txt"
PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0
SANDBOX_SKIP_COUNT=0
WEBUI_PID=''
WATCH_JOB=''

# safe_name <raw>: filename component derived from a profile or
# variant name. Raw names may contain '/' (or other path-breaking
# characters), so they must never appear in a path. Sanitised text
# plus 12 hex of the sha256 of the raw name keeps distinct names
# distinct. Verdict check names keep the raw profile name; only
# paths use the slug.
safe_name() {
    local raw="$1" sanitised h
    sanitised="$(printf '%s' "$raw" | tr -c 'A-Za-z0-9_.-' '_')"
    h="$(printf '%s' "$raw" | sha256sum | awk '{print substr($1,1,12)}')"
    printf '%s-%s' "$sanitised" "$h"
}

# kill_descendants <pid>: TERM every descendant of pid (deepest
# first), so a signal cannot leave a background job or server alive.
kill_descendants() {
    local pid="$1" child
    command -v ps >/dev/null 2>&1 || return 0
    for child in $(ps --no-headers -o pid --ppid "$pid" 2>/dev/null); do
        kill_descendants "$child"
        kill -TERM "$child" 2>/dev/null || true
    done
}

cleanup() {
    local rc="$?"
    if [ -n "${WEBUI_PID:-}" ] && kill -0 "$WEBUI_PID" 2>/dev/null; then
        kill "$WEBUI_PID" 2>/dev/null || true
        wait "$WEBUI_PID" 2>/dev/null || true
    fi
    if [ -n "${WATCH_JOB:-}" ] && kill -0 "$WATCH_JOB" 2>/dev/null; then
        kill "$WATCH_JOB" 2>/dev/null || true
        wait "$WATCH_JOB" 2>/dev/null || true
    fi
    kill_descendants "$$"
    rm -rf "${E2E_TMP:-}"
    return "$rc"
}

# on_signal: a signal ENDS the run. Kill servers and descendants,
# remove the temp dir, and exit 130 — never print a summary or a
# secret-scan verdict over deleted files.
on_signal() {
    cleanup
    exit 130
}

trap cleanup EXIT
trap on_signal INT TERM
TMP_STAT="$(stat -c '%a' "$E2E_TMP")"
[ "$TMP_STAT" = '700' ] || { printf 'e2e: temp dir mode is %s, expected 700\n' "$TMP_STAT" >&2; exit 2; }
mkdir -p "$CFG_DIR" "$OUT_DIR" "$WEBUI_DIR" "$LOG_DIR"
CFG="$CFG_DIR/config.json"
: > "$VERDICTS"

# record <leg> <check> <PASS|FAIL|SKIP> <reason>
# Reasons are fixed strings, counts, exit codes, profile names and
# field names only. Never interpolate captured command output here,
# except the single D3 fixed string (see record_sandbox).
record() {
    local leg="$1" check="$2" verdict="$3" reason="$4"
    printf '%s | %s | %s | %s\n' "$leg" "$check" "$verdict" "$reason" | tee -a "$VERDICTS"
    case "$verdict" in
        PASS) PASS_COUNT=$((PASS_COUNT + 1)) ;;
        FAIL) FAIL_COUNT=$((FAIL_COUNT + 1)) ;;
        SKIP) SKIP_COUNT=$((SKIP_COUNT + 1)) ;;
    esac
}

# record_sandbox <leg> <check>: SKIP with ONLY the D3 fixed string.
record_sandbox() {
    local leg="$1" check="$2"
    record "$leg" "$check" 'SKIP' "$SANDBOX_STRING"
    SANDBOX_SKIP_COUNT=$((SANDBOX_SKIP_COUNT + 1))
}

has_sandbox_string() {
    grep -a -q -F -- "$SANDBOX_STRING" "$1" 2>/dev/null
}

# run_cap <base> <timeout-secs> <cmd...>: capture stdout/stderr/exit.
# timeout 0 = no bound. The bound is implemented in shell (background
# + kill), because the external timeout(1) cannot exec shell
# functions such as ccfg. A bound kill records exit 124. On timeout
# the signal escalates TERM -> (brief poll) -> KILL, and a .code
# file is always written (125 if the background subshell died
# before writing one), so a missing .code can never read as PASS.
run_cap() {
    local base="$1" timeout_s="$2"; shift 2
    if [ "$timeout_s" -gt 0 ]; then
        "$@" >"$base.out" 2>"$base.err" &
        local pid="$!"
        local waited=0
        while kill -0 "$pid" 2>/dev/null; do
            if [ "$waited" -ge "$timeout_s" ]; then
                kill "$pid" 2>/dev/null || true
                local esc=0
                while kill -0 "$pid" 2>/dev/null && [ "$esc" -lt 15 ]; do sleep 0.2; esc=$((esc + 1)); done
                if kill -0 "$pid" 2>/dev/null; then kill -KILL "$pid" 2>/dev/null || true; fi
                wait "$pid" 2>/dev/null || true
                printf '124' >"$base.code"
                return 0
            fi
            sleep 1
            waited=$((waited + 1))
        done
        wait "$pid"
        printf '%s' "$?" >"$base.code"
    else
        "$@" >"$base.out" 2>"$base.err"
        printf '%s' "$?" >"$base.code"
    fi
    [ -f "$base.code" ] || printf '125' >"$base.code"
}

# run_cap_int <base> <secs> <cmd...>: like run_cap, but the bound is
# delivered as SIGINT (castctl exits 130 on a cancelled context).
# The wait polls so a fast exit does not cost the full interval, and
# escalates INT -> (brief poll) -> KILL if the child ignores SIGINT.
run_cap_int() {
    local base="$1" secs="$2"; shift 2
    "$@" >"$base.out" 2>"$base.err" &
    local pid="$!"
    local waited=0
    while kill -0 "$pid" 2>/dev/null && [ "$waited" -lt "$((secs * 5))" ]; do
        sleep 0.2
        waited=$((waited + 1))
    done
    if kill -0 "$pid" 2>/dev/null; then
        kill -INT "$pid" 2>/dev/null || true
        local esc=0
        while kill -0 "$pid" 2>/dev/null && [ "$esc" -lt 15 ]; do sleep 0.2; esc=$((esc + 1)); done
        if kill -0 "$pid" 2>/dev/null; then kill -KILL "$pid" 2>/dev/null || true; fi
    fi
    wait "$pid"
    printf '%s' "$?" >"$base.code"
    [ -f "$base.code" ] || printf '125' >"$base.code"
}

# ccfg <config> <args...>: castctl with a clean environment and an
# explicit --config. Ambient CASTCTL_* / MUSE_AUTO_* never leak in.
ccfg() {
    local cfg="$1"; shift
    env -u CASTCTL_CONFIG -u CASTCTL_PROFILE -u CASTCTL_TELEGRAM_TOKEN \
        -u MUSE_AUTO_APPROVE -u MUSE_AUTO_ALLOW_ONCE \
        "$BIN" --config "$cfg" "$@"
}

# webui_exec <config> <args...>: like ccfg, but never inherits a
# web UI key from the environment (there is no environment token
# source for the web UI: the token lives in the config copy's
# `webui` block). Uses exec, so the caller's $! IS the castctl
# PID — never a wrapper subshell. Call only backgrounded or via
# run_cap; a direct call replaces this shell.
webui_exec() {
    local cfg="$1"; shift
    exec env -u CASTCTL_CONFIG -u CASTCTL_PROFILE -u CASTCTL_TELEGRAM_TOKEN \
        -u MUSE_AUTO_APPROVE -u MUSE_AUTO_ALLOW_ONCE -u CASTCTL_WEBUI_KEY \
        "$BIN" --config "$cfg" "$@"
}

# json_field <file> <dotted.path>: print the JSON value, or
# __BADJSON__ / __MISSING__. Dict/list values print as JSON.
json_field() {
    python3 - "$1" "$2" <<'PY'
import json, sys
try:
    with open(sys.argv[1], encoding="utf-8") as fh:
        cur = json.load(fh)
except Exception:
    print("__BADJSON__")
    sys.exit(0)
for key in sys.argv[2].split("."):
    if isinstance(cur, dict) and key in cur:
        cur = cur[key]
    else:
        print("__MISSING__")
        sys.exit(0)
if isinstance(cur, (dict, list)):
    print(json.dumps(cur))
elif isinstance(cur, bool):
    print("true" if cur else "false")
elif cur is None:
    print("null")
else:
    print(cur)
PY
}

json_is_valid() {
    python3 - "$1" <<'PY' >/dev/null 2>&1
import json, sys
json.load(open(sys.argv[1], encoding="utf-8"))
PY
}

# count_fixed <file> <value>: count only, never a matched line.
# grep -c prints 0 and exits 1 on no match; both are handled.
count_fixed() {
    local n
    n="$(grep -a -c -F -- "$2" "$1" 2>/dev/null || true)"
    [ -n "$n" ] || n=0
    printf '%s' "$n"
}

# count_regex <file> <pattern>: count only, never a matched line.
count_regex() {
    local n
    n="$(grep -a -c -E -- "$2" "$1" 2>/dev/null || true)"
    [ -n "$n" ] || n=0
    printf '%s' "$n"
}

# ---- config tool (python3 stdlib; never prints a secret value) --------
# Written into the temp dir and deleted by the trap. It reads config
# JSON and prints only shapes, counts, field names and paths.
TOOLS_DIR="$E2E_TMP/tools"
mkdir -p "$TOOLS_DIR"
CFGTOOL="$TOOLS_DIR/cfgtool.py"
cat > "$CFGTOOL" <<'PYEOF'
"""e2e config tool: shape queries and temp-copy edits only.

Never prints a secret value. All edits write a new file; the input
is never modified. Field values for private_key/public_key/
preshared_key/token are never printed, only presence.
"""
import json
import os
import sys

FAKE_KEY = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
FAKE_PUB = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="


def load(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def save(cfg, path):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(cfg, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def profiles(cfg):
    return cfg.get("profiles") or {}


def cmd_inject(argv):
    src, dst = argv
    cfg = load(src)
    token = os.environ.get("CASTCTL_TELEGRAM_TOKEN", "")
    if not token.strip():
        token = ""
    block = cfg.get("telegram")
    if not token:
        print("unset")
        save(cfg, dst)
        return
    if not isinstance(block, dict):
        print("no-block")
        save(cfg, dst)
        return
    block["token"] = token
    cfg["telegram"] = block
    print("injected")
    save(cfg, dst)


def cmd_inject_webui(argv):
    # Sets the temp copy's webui token to the script-generated
    # value from E2E_WEBUI_TOKEN (passed via the environment of
    # this one python call only, mirroring the telegram inject).
    # Only a config that already has a webui block is touched:
    # a block-less config keeps no block, so the no-token
    # negative probe still tests the block gate.
    src, dst = argv
    cfg = load(src)
    token = os.environ.get("E2E_WEBUI_TOKEN", "")
    if not token.strip():
        print("unset")
        save(cfg, dst)
        return
    block = cfg.get("webui")
    if not isinstance(block, dict):
        print("no-block")
        save(cfg, dst)
        return
    block["token"] = token
    cfg["webui"] = block
    print("injected")
    save(cfg, dst)


def cmd_set_webui_listen(argv):
    # Sets webui.listen on a probe copy (or in place) when a
    # webui block exists; a block-less config is left untouched.
    src, dst, addr = argv
    cfg = load(src)
    block = cfg.get("webui")
    if not isinstance(block, dict):
        print("no-block")
        save(cfg, dst)
        return
    block["listen"] = addr
    cfg["webui"] = block
    print("ok")
    save(cfg, dst)


def cmd_related(argv):
    cfg = load(argv[0])
    names = set(profiles(cfg))
    tg = cfg.get("telegram")
    if isinstance(tg, dict) and isinstance(tg.get("profile"), str):
        names.add(tg["profile"])
    keeper = cfg.get("keeper")
    if isinstance(keeper, list):
        for entry in keeper:
            if isinstance(entry, dict) and isinstance(entry.get("profile"), str):
                names.add(entry["profile"])
    for name in sorted(names):
        print(name)


def cmd_original_paths(argv):
    # Prints: <profile>\t<resolved ORIGINAL cookies path>. Resolution
    # mirrors castctl: absolute as-is, relative under the SUPPLIED
    # config file's dir, absent -> <supplied-dir>/profiles/<name>/
    # cookies.txt. Paths only; cookie content is never read.
    cfg = load(argv[0])
    base = os.path.dirname(os.path.abspath(argv[0]))
    for name in sorted(profiles(cfg)):
        entry = profiles(cfg)[name] or {}
        value = entry.get("cookies_file") if isinstance(entry, dict) else None
        if isinstance(value, str) and value.strip():
            path = value if os.path.isabs(value) else os.path.join(base, value)
        else:
            path = os.path.join(base, "profiles", name, "cookies.txt")
        print(f"{name}\t{os.path.normpath(path)}")


def cmd_point_cookies(argv):
    src, dst, name, abspath = argv
    cfg = load(src)
    entry = profiles(cfg).get(name)
    if isinstance(entry, dict):
        entry["cookies_file"] = abspath
    save(cfg, dst)


def cmd_has_block(argv):
    cfg = load(argv[0])
    block = cfg.get(argv[1])
    if argv[1] == "log":
        print("yes" if isinstance(block, dict) else "no")
    elif argv[1] == "keeper":
        print("yes" if isinstance(block, list) and block else "no")
    else:
        print("yes" if isinstance(block, dict) and block else "no")


def cmd_token_present(argv):
    cfg = load(argv[0])
    block = cfg.get(argv[1])
    ok = isinstance(block, dict) and isinstance(block.get("token"), str) and bool(block["token"].strip())
    print("yes" if ok else "no")


def cmd_detour_for(argv):
    cfg = load(argv[0])
    name = argv[1]
    entry = profiles(cfg).get(name) or {}
    outbound = entry.get("outbound") if isinstance(entry, dict) else None
    if isinstance(outbound, str) and outbound:
        print(outbound)
    elif isinstance(outbound, dict):
        tag = outbound.get("tag")
        print(tag if isinstance(tag, str) and tag else f"profile:{name}")
    else:
        print(f"castctl-direct:{name}")


def cmd_shape(argv):
    cfg = load(argv[0])
    outbounds = cfg.get("outbounds") or []
    endpoints = cfg.get("endpoints") or []
    print(f"outbounds_count={len(outbounds)}")
    print(f"endpoints_count={len(endpoints)}")
    tags = []
    for obj in list(outbounds) + list(endpoints):
        if isinstance(obj, dict):
            tags.append(str(obj.get("tag", "")))
            print(f"entry tag={obj.get('tag', '')} type={obj.get('type', '')}")
    print(f"tags_unique={'yes' if len(tags) == len(set(tags)) else 'no'}")
    for name in sorted(profiles(cfg)):
        entry = profiles(cfg)[name] or {}
        outbound = entry.get("outbound") if isinstance(entry, dict) else None
        if isinstance(outbound, str):
            kind = f"tag:{outbound}" if outbound else "tag-empty"
        elif isinstance(outbound, dict):
            kind = "inline"
        elif outbound is None:
            kind = "direct"
        else:
            kind = "other"
        print(f"profile {name} outbound_kind={kind}")
    for obj in endpoints:
        if isinstance(obj, dict) and obj.get("type") == "wireguard":
            tag = obj.get("tag", "")
            has_key = isinstance(obj.get("private_key"), str) and bool(obj.get("private_key"))
            peers = obj.get("peers")
            peer_count = len(peers) if isinstance(peers, list) else -1
            addr = obj.get("address")
            addr_count = len(addr) if isinstance(addr, list) else -1
            system = obj.get("system")
            print(f"wireguard tag={tag} system={system} private_key={'present' if has_key else 'absent'} "
                  f"address_count={addr_count} peers={peer_count}")
            if isinstance(peers, list):
                for peer in peers:
                    if isinstance(peer, dict):
                        pub = isinstance(peer.get("public_key"), str) and bool(peer.get("public_key"))
                        ips = peer.get("allowed_ips")
                        print(f"  peer public_key={'present' if pub else 'absent'} "
                              f"allowed_ips_count={len(ips) if isinstance(ips, list) else -1}")
    wgdns = cfg.get("wireguard_dns")
    if isinstance(wgdns, dict):
        for key in sorted(wgdns):
            val = wgdns[key]
            print(f"wireguard_dns key={key} servers={len(val) if isinstance(val, list) else -1}")


def cmd_edit(argv):
    src, dst, op = argv[0], argv[1], argv[2]
    rest = argv[3:]
    cfg = load(src)
    if op == "strip-log":
        cfg.pop("log", None)
    elif op == "set-log-file":
        cfg["log"] = {"output": rest[0]}
    elif op == "set-log-level":
        cfg["log"] = {"level": rest[0]}
    elif op == "set-log-disabled":
        cfg["log"] = {"disabled": True, "output": rest[0]}
    elif op == "set-log-output":
        block = cfg.get("log")
        if not isinstance(block, dict):
            block = {}
        block["output"] = rest[0]
        cfg["log"] = block
    elif op == "add-unknown-key":
        cfg["e2e_bogus_key"] = True
    elif op == "no-cookies":
        entry = profiles(cfg).get(rest[0])
        if isinstance(entry, dict):
            entry["cookies_file"] = rest[1]
    elif op == "empty-profile-dns":
        entry = profiles(cfg).get(rest[0])
        if isinstance(entry, dict):
            entry["dns"] = {}
    elif op == "add-profile-dns":
        entry = profiles(cfg).get(rest[0])
        if isinstance(entry, dict):
            entry["dns"] = {"servers": [{"tag": "e2e-dns1", "type": "https",
                                         "server": "1.1.1.1", "server_port": 443,
                                         "detour": rest[1]}]}
    elif op == "add-global-dns":
        cfg["dns"] = {"servers": [{"tag": "e2e-dns1", "type": "https",
                                   "server": "1.1.1.1", "server_port": 443,
                                   "detour": rest[0]}]}
    elif op == "wg-outbound":
        cfg.setdefault("outbounds", []).append(
            {"type": "wireguard", "tag": "e2e-wg-outbound"})
    elif op == "dup-tag":
        outbounds = cfg.get("outbounds") or []
        if outbounds and isinstance(outbounds[0], dict):
            dup = dict(outbounds[0])
            outbounds.append(dup)
            cfg["outbounds"] = outbounds
    elif op == "wg-dup-fake":
        # Duplicate the first wireguard endpoint under a new tag with
        # FAKE key material, and a second profile resolving to it, to
        # prove the key-sharing error names tags but never the value.
        endpoints = cfg.get("endpoints") or []
        src_ep = None
        for obj in endpoints:
            if isinstance(obj, dict) and obj.get("type") == "wireguard":
                src_ep = obj
                break
        if src_ep is None:
            print("no-wg-endpoint")
            save(cfg, dst)
            return
        dup_ep = dict(src_ep)
        dup_ep["tag"] = "e2e-wg-dup"
        dup_ep["private_key"] = FAKE_KEY
        src_ep["private_key"] = FAKE_KEY
        for peer in dup_ep.get("peers", []) if isinstance(dup_ep.get("peers"), list) else []:
            if isinstance(peer, dict):
                peer["public_key"] = FAKE_PUB
        for peer in src_ep.get("peers", []) if isinstance(src_ep.get("peers"), list) else []:
            if isinstance(peer, dict):
                peer["public_key"] = FAKE_PUB
        endpoints.append(dup_ep)
        cfg["endpoints"] = endpoints
        names = sorted(profiles(cfg))
        if names:
            first = profiles(cfg)[names[0]]
            if isinstance(first, dict):
                profiles(cfg)["e2e-second-profile"] = dict(first)
                profiles(cfg)["e2e-second-profile"]["outbound"] = "e2e-wg-dup"
        print("duplicated")
    else:
        print(f"unknown-op:{op}")
        sys.exit(2)
    save(cfg, dst)
    print("ok")


def cmd_logs_expected(argv):
    # Prints the /logs reason the web UI handler must return for
    # this config, or "enabled" when logs are served. Mirrors the
    # handler's logGate: no log block or disabled -> logging_disabled;
    # output ""/stderr/stdout -> log_output_not_file; an output
    # target the handler refuses (the config file itself, a cookies
    # file, or anything under profiles/) -> log_output_refused.
    # Relative outputs are resolved against the config file's dir,
    # the same base the handler's refused-set uses for config paths.
    cfg = load(argv[0])
    base = os.path.dirname(os.path.abspath(argv[0]))
    block = cfg.get("log")
    if not isinstance(block, dict):
        print("logging_disabled")
        return
    if block.get("disabled") is True:
        print("logging_disabled")
        return
    output = block.get("output")
    if not isinstance(output, str) or output in ("", "stderr", "stdout"):
        print("log_output_not_file")
        return
    resolved = output if os.path.isabs(output) else os.path.join(base, output)
    resolved = os.path.normpath(resolved)
    if resolved == os.path.abspath(argv[0]):
        print("log_output_refused")
        return
    refused_roots = [os.path.join(base, "profiles")]
    for name in sorted(profiles(cfg)):
        entry = profiles(cfg)[name] or {}
        value = entry.get("cookies_file") if isinstance(entry, dict) else None
        if isinstance(value, str) and value.strip():
            cpath = value if os.path.isabs(value) else os.path.join(base, value)
            refused_roots.append(os.path.normpath(cpath))
    for root in refused_roots:
        if resolved == root or resolved.startswith(root + os.sep):
            print("log_output_refused")
            return
    print("enabled")


def main():
    if len(sys.argv) < 2:
        print("usage: cfgtool <command> ...")
        sys.exit(2)
    cmd = sys.argv[1]
    argv = sys.argv[2:]
    if cmd == "inject":
        cmd_inject(argv)
    elif cmd == "inject-webui":
        cmd_inject_webui(argv)
    elif cmd == "set-webui-listen":
        cmd_set_webui_listen(argv)
    elif cmd == "related-profiles":
        cmd_related(argv)
    elif cmd == "original-paths":
        cmd_original_paths(argv)
    elif cmd == "point-cookies":
        cmd_point_cookies(argv)
    elif cmd == "logs-expected":
        cmd_logs_expected(argv)
    elif cmd == "has-block":
        cmd_has_block(argv)
    elif cmd == "token-present":
        cmd_token_present(argv)
    elif cmd == "detour-for":
        cmd_detour_for(argv)
    elif cmd == "shape":
        cmd_shape(argv)
    elif cmd == "edit":
        cmd_edit(argv)
    else:
        print(f"unknown-command:{cmd}")
        sys.exit(2)


main()
PYEOF

# ---- supplied config: hash, temp copy, injection, cookies -----------
SUPPLIED_SHA="$(sha256sum -- "$SUPPLIED_CONFIG" | awk '{print $1}')"
cp -- "$SUPPLIED_CONFIG" "$CFG"
chmod 0600 "$CFG"

INJECT_RESULT=''
TELEGRAM_INJECTED=0
TELEGRAM_TOKEN_HELD=0
if [ -n "${CASTCTL_TELEGRAM_TOKEN:-}" ] && [ "$(printf '%s' "${CASTCTL_TELEGRAM_TOKEN}" | tr -d '[:space:]')" != '' ]; then
    TELEGRAM_TOKEN_HELD=1
fi
# Saved copies: the final secret scan (counts only) still needs the
# Telegram value after the env var is unset. A whitespace-only
# token counts as unset and is never injected.
TELEGRAM_TOKEN_VALUE="${CASTCTL_TELEGRAM_TOKEN:-}"
INJECT_RESULT="$(python3 "$CFGTOOL" inject "$CFG" "$CFG" 2>"$OUT_DIR/inject.err" || echo inject-failed)"
[ "$INJECT_RESULT" = 'injected' ] && TELEGRAM_INJECTED=1
# Narrow the scope: after injection, no child process can inherit
# the Telegram token env var. A saved shell copy above serves the
# scan only.
unset CASTCTL_TELEGRAM_TOKEN
# The web UI token is generated here and injected into the temp
# copy's webui block. CASTCTL_WEBUI_KEY is not a token source
# anymore: ignore and unset it before anything can inherit it.
# The generated value is passed to the one cfgtool call only, via
# a narrowly scoped env var, and is never printed.
unset CASTCTL_WEBUI_KEY
WEBUI_KEY_VALUE="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
[ -n "$WEBUI_KEY_VALUE" ] || { printf 'e2e: failed to generate a web UI token\n' >&2; exit 2; }
WEBUI_KEY_HELD=0
WEBUI_INJECT_RESULT="$(E2E_WEBUI_TOKEN="$WEBUI_KEY_VALUE" python3 "$CFGTOOL" inject-webui "$CFG" "$CFG" 2>"$OUT_DIR/inject-webui.err" || echo inject-failed)"
if [ "$WEBUI_INJECT_RESULT" = 'injected' ]; then
    WEBUI_KEY_HELD=1
else
    # No webui block (or generation failed): the script holds no
    # usable value; the negative probes cover this shape.
    WEBUI_KEY_VALUE=''
fi

# point_originals: point the temp copy's cookies_file at the
# ORIGINAL absolute path for every profile. Cookies are never
# copied and their content is never read — path strings only.
# A relative cookies_file resolves against the SUPPLIED config's
# directory; an absolute path is kept as-is; an absent
# cookies_file resolves to the supplied dir's default location.
point_originals() {
    local name src_path
    while IFS="$(printf '\t')" read -r name src_path; do
        [ -n "$name" ] || continue
        python3 "$CFGTOOL" point-cookies "$CFG" "$CFG" "$name" "$src_path" >/dev/null
    done <<EOF
$(python3 "$CFGTOOL" original-paths "$SUPPLIED_CONFIG")
EOF
}
point_originals

# record_originals <outfile>: one line per original cookies file
# (and .bak when the path is checked): name, path, sha256 or
# MISSING, mtime or MISSING. Hashes are never printed; the file
# lives in OUT_DIR with a .txt suffix so the secret scan's
# .out/.err globs never read it.
record_originals() {
    local outfile="$1" name src_path sha mtime
    : > "$outfile"
    while IFS="$(printf '\t')" read -r name src_path; do
        [ -n "$name" ] || continue
        if [ -f "$src_path" ]; then
            sha="$(sha256sum -- "$src_path" | awk '{print $1}')"
            mtime="$(stat -c '%Y' -- "$src_path")"
        else
            sha='MISSING'; mtime='MISSING'
        fi
        printf '%s\t%s\t%s\t%s\n' "$name" "$src_path" "$sha" "$mtime" >> "$outfile"
        if [ -f "$src_path.bak" ]; then
            sha="$(sha256sum -- "$src_path.bak" | awk '{print $1}')"
            mtime="$(stat -c '%Y' -- "$src_path.bak")"
        else
            sha='MISSING'; mtime='MISSING'
        fi
        printf '%s\t%s\t%s\t%s\n' "$name.bak" "$src_path.bak" "$sha" "$mtime" >> "$outfile"
    done <<EOF
$(python3 "$CFGTOOL" original-paths "$SUPPLIED_CONFIG")
EOF
}
ORIGINALS_BEFORE="$OUT_DIR/originals-before.txt"
record_originals "$ORIGINALS_BEFORE"

# verify_originals: re-record and compare. Without --live-keeper
# any change (content, mtime, new or vanished .bak) is a FAIL.
# With --live-keeper a change is expected and records PASS.
verify_originals() {
    local after="$OUT_DIR/originals-after.txt"
    record_originals "$after"
    if cmp -s "$ORIGINALS_BEFORE" "$after"; then
        record 'immutability' 'cookies-originals' 'PASS' 'cookies originals byte- and mtime-identical before/after'
    elif [ "$LIVE_KEEPER" = '1' ]; then
        record 'immutability' 'cookies-originals' 'PASS' 'cookies originals changed as expected with --live-keeper'
    else
        record 'immutability' 'cookies-originals' 'FAIL' 'cookies original changed unexpectedly'
    fi
}

# make_variant <name> <cfgtool-edit-args...>: a fresh config dir under
# $E2E_TMP/variants/<slug> holding an edited copy of the temp config.
# Variant names are slugged (see safe_name) because they may embed a
# profile name. No cookies copies: the variant inherits the temp
# copy's cookies_file paths, which point at the originals.
make_variant() {
    local name="$1"; shift
    local vdir="$E2E_TMP/variants/$(safe_name "$name")"
    mkdir -p "$vdir"
    local vcfg="$vdir/config.json"
    cp -- "$CFG" "$vcfg"
    chmod 0600 "$vcfg"
    if [ "$#" -gt 0 ]; then
        python3 "$CFGTOOL" edit "$vcfg" "$vcfg" "$@" >/dev/null
    fi
    printf '%s' "$vcfg"
}

# ---- binary -----------------------------------------------------------
BIN=''
if [ -n "$BINARY_PATH" ]; then
    [ -x "$BINARY_PATH" ] || { printf 'e2e: --binary is not executable: %s\n' "$BINARY_PATH" >&2; exit 2; }
    BIN="$BINARY_PATH"
else
    command -v go >/dev/null 2>&1 || { printf 'e2e: go is required to build the binary (or pass --binary)\n' >&2; exit 2; }
    mkdir -p "$E2E_TMP/bin" "$E2E_TMP/gotmp"
    BIN="$E2E_TMP/bin/castctl"
    BUILD_BASE="$OUT_DIR/build"
    # Go's build work dir defaults to $TMPDIR; keep it inside the
    # script temp dir so it is removed by the trap. If /tmp is a
    # small tmpfs, run with TMPDIR set to a disk-backed dir
    # (see docs/e2e.md prerequisites).
    GOTMPDIR="$E2E_TMP/gotmp"
    export GOTMPDIR
    (cd "$REPO_ROOT" && go build -tags "$BUILD_TAGS" -o "$BIN" ./cmd/castctl) >"$BUILD_BASE.out" 2>"$BUILD_BASE.err"
    BUILD_RC="$?"
    if [ "$BUILD_RC" -ne 0 ]; then
        record 'build' 'go-build' 'FAIL' "go build exited $BUILD_RC"
        printf 'e2e: go build failed; tail recorded in captured output (fixed notice only)\n' >&2
        tail -n 20 "$BUILD_BASE.err" "$BUILD_BASE.out" >"$OUT_DIR/build-failure-tail.err" 2>/dev/null || true
        exit 1
    fi
    record 'build' 'go-build' 'PASS' "built with tags $BUILD_TAGS"
fi
VERSION_BASE="$OUT_DIR/version"
run_cap "$VERSION_BASE" 0 env -u CASTCTL_CONFIG -u CASTCTL_PROFILE "$BIN" --version
VERSION_RC="$(cat "$VERSION_BASE.code")"
if [ "$VERSION_RC" -ne 0 ]; then
    record 'build' 'version' 'FAIL' "castctl --version exited $VERSION_RC"
else
    record 'build' 'version' 'PASS' 'castctl --version exited 0'
fi
VERSION_TEXT="$(cat "$VERSION_BASE.out")"
case "$VERSION_TEXT" in
    *'('*')'*) STAMPED=1 ;;
    *) STAMPED=0 ;;
esac

# ---- helpers for legs -------------------------------------------------
# cookies_present <profile>: profile list row field "cookies" (bool).
cookies_present() {
    local base="$OUT_DIR/list-$(safe_name "$1")"
    run_cap "$base" 30 ccfg "$CFG" profile list
    [ "$(cat "$base.code")" = '0' ] || return 1
    local row
    row="$(python3 - "$base.out" "$1" <<'PY'
import json, sys
try:
    d = json.load(open(sys.argv[1], encoding="utf-8"))
except Exception:
    print("badjson"); sys.exit(0)
for row in d.get("profiles", []):
    if row.get("name") == sys.argv[2]:
        print("true" if row.get("cookies") else "false")
        sys.exit(0)
print("absent")
PY
)"
    [ "$row" = 'true' ]
}

# ---- leg 1: profile test ----------------------------------------------
for PROFILE in "${PROFILES[@]}"; do
    SLUG="$(safe_name "$PROFILE")"
    SHOW_BASE="$OUT_DIR/show-$SLUG"
    run_cap "$SHOW_BASE" 30 ccfg "$CFG" profile show "$PROFILE"
    SHOW_RC="$(cat "$SHOW_BASE.code")"
    if [ "$SHOW_RC" -ne 0 ]; then
        if has_sandbox_string "$SHOW_BASE.err"; then record_sandbox 'profile-test' "show-$PROFILE"; else
            record 'profile-test' "show-$PROFILE" 'FAIL' "profile show exited $SHOW_RC"
        fi
        continue
    fi
    record 'profile-test' "show-$PROFILE" 'PASS' 'profile show exited 0'
    if ! cookies_present "$PROFILE"; then
        record 'profile-test' "test-$PROFILE" 'SKIP' 'no cookies file for profile'
        continue
    fi
    TEST_BASE="$OUT_DIR/profile-test-$SLUG"
    run_cap "$TEST_BASE" 180 ccfg "$CFG" profile test "$PROFILE"
    TEST_RC="$(cat "$TEST_BASE.code")"
    if ! json_is_valid "$TEST_BASE.out"; then
        if has_sandbox_string "$TEST_BASE.out" || has_sandbox_string "$TEST_BASE.err"; then
            record_sandbox 'profile-test' "test-$PROFILE"
        else
            record 'profile-test' "test-$PROFILE" 'FAIL' "profile test exited $TEST_RC with unparseable output"
        fi
        continue
    fi
    DNS_OK="$(json_field "$TEST_BASE.out" 'dns.ok')"
    HTTPS_OK="$(json_field "$TEST_BASE.out" 'https.ok')"
    GW_OK="$(json_field "$TEST_BASE.out" 'gateway.ok')"
    DNS_SOURCE="$(json_field "$TEST_BASE.out" 'dns.source')"
    DNS_SERVER="$(json_field "$TEST_BASE.out" 'dns.server')"
    OK_FIELD="$(json_field "$TEST_BASE.out" 'ok')"
    case "$DNS_SOURCE" in
        profile|wireguard|global-compat|default) SOURCE_OK=1 ;;
        *) SOURCE_OK=0 ;;
    esac
    if [ "$DNS_OK" = 'true' ] && [ "$HTTPS_OK" = 'true' ] && [ "$GW_OK" = 'true' ] \
        && [ "$SOURCE_OK" = '1' ] && [ "$DNS_SERVER" != '__MISSING__' ] && [ "$DNS_SERVER" != '' ] \
        && [ "$TEST_RC" = '0' ] && [ "$OK_FIELD" = 'true' ]; then
        record 'profile-test' "test-$PROFILE" 'PASS' 'dns/https/gateway ok, dns.source in closed enum, server tag present'
    elif has_sandbox_string "$TEST_BASE.out" || has_sandbox_string "$TEST_BASE.err"; then
        record_sandbox 'profile-test' "test-$PROFILE"
    else
        record 'profile-test' "test-$PROFILE" 'FAIL' "profile test exited $TEST_RC with fields not all ok"
    fi
    EGRESS="$(json_field "$TEST_BASE.out" 'egress_ip')"
    if [ "$EGRESS" = 'null' ]; then
        record 'profile-test' "egress-$PROFILE" 'PASS' 'egress_ip null with warning is non-fatal by design (recorded, not asserted ok)'
    else
        record 'profile-test' "egress-$PROFILE" 'PASS' 'egress_ip present'
    fi
done

# ---- leg 2: send / wait -----------------------------------------------
# Offline negative control: conflicting toggles are rejected by the
# parser before any network work (exit 2, measured in Phase 1).
for PROFILE in "${PROFILES[@]}"; do
    SLUG="$(safe_name "$PROFILE")"
    CONF_BASE="$OUT_DIR/wait-conflict-$SLUG"
    run_cap "$CONF_BASE" 30 ccfg "$CFG" --profile "$PROFILE" wait --auto-approve --no-auto-approve
    if [ "$(cat "$CONF_BASE.code")" = '2' ]; then
        record 'send-wait' "conflict-$PROFILE" 'PASS' 'conflicting toggles exit 2'
    else
        record 'send-wait' "conflict-$PROFILE" 'FAIL' "conflicting toggles exited $(cat "$CONF_BASE.code"), expected 2"
    fi
done
if [ "$LIVE_SEND" -ne 1 ]; then
    for PROFILE in "${PROFILES[@]}"; do
        SLUG="$(safe_name "$PROFILE")"
        record 'send-wait' "send-$PROFILE" 'SKIP' 'no --live-send flag'
        record 'send-wait' "wait-$PROFILE" 'SKIP' 'no --live-send flag'
    done
else
    for PROFILE in "${PROFILES[@]}"; do
        SLUG="$(safe_name "$PROFILE")"
        if ! cookies_present "$PROFILE"; then
            record 'send-wait' "send-$PROFILE" 'SKIP' 'no cookies file for profile'
            record 'send-wait' "wait-$PROFILE" 'SKIP' 'no cookies file for profile'
            continue
        fi
        SEND_BASE="$OUT_DIR/send-$SLUG"
        run_cap "$SEND_BASE" 120 ccfg "$CFG" --profile "$PROFILE" send 'castctl e2e probe (no action needed)' --wait 30 --ack-timeout 15
        SEND_RC="$(cat "$SEND_BASE.code")"
        if ! json_is_valid "$SEND_BASE.out"; then
            if has_sandbox_string "$SEND_BASE.out" || has_sandbox_string "$SEND_BASE.err"; then
                record_sandbox 'send-wait' "send-$PROFILE"
            else
                record 'send-wait' "send-$PROFILE" 'FAIL' "send exited $SEND_RC with unparseable output"
            fi
            record 'send-wait' "wait-$PROFILE" 'SKIP' 'send did not produce a result to re-wait on'
            continue
        fi
        DELIVERED="$(json_field "$SEND_BASE.out" 'delivered')"
        USER_SEQ="$(json_field "$SEND_BASE.out" 'user_seq')"
        OUTCOME="$(json_field "$SEND_BASE.out" 'outcome')"
        case "$OUTCOME" in
            done|needs_input|needs_approval) OUTCOME_OK=1 ;;
            *) OUTCOME_OK=0 ;;
        esac
        if [ "$DELIVERED" = 'true' ] && [ "$USER_SEQ" != '__MISSING__' ] && [ "$OUTCOME_OK" = '1' ]; then
            record 'send-wait' "send-$PROFILE" 'PASS' 'delivered, outcome in closed set'
        elif has_sandbox_string "$SEND_BASE.out" || has_sandbox_string "$SEND_BASE.err"; then
            record_sandbox 'send-wait' "send-$PROFILE"
        else
            record 'send-wait' "send-$PROFILE" 'FAIL' "send exited $SEND_RC with fields not ok"
        fi
        if [ "$USER_SEQ" = '__MISSING__' ] || [ "$USER_SEQ" = '' ]; then
            record 'send-wait' "wait-$PROFILE" 'SKIP' 'no user_seq from send result'
            continue
        fi
        WAIT_BASE="$OUT_DIR/wait-$SLUG"
        run_cap "$WAIT_BASE" 60 ccfg "$CFG" --profile "$PROFILE" wait --after-seq "$USER_SEQ" --timeout 30 --json
        WAIT_RC="$(cat "$WAIT_BASE.code")"
        if ! json_is_valid "$WAIT_BASE.out"; then
            if has_sandbox_string "$WAIT_BASE.out" || has_sandbox_string "$WAIT_BASE.err"; then
                record_sandbox 'send-wait' "wait-$PROFILE"
            else
                record 'send-wait' "wait-$PROFILE" 'FAIL' "wait exited $WAIT_RC with unparseable output"
            fi
            continue
        fi
        W_OUTCOME="$(json_field "$WAIT_BASE.out" 'outcome')"
        case "$W_OUTCOME" in
            done|needs_input|needs_approval) W_OK=1 ;;
            *) W_OK=0 ;;
        esac
        if [ "$W_OK" = '1' ]; then
            record 'send-wait' "wait-$PROFILE" 'PASS' 'wait outcome in closed set'
        elif has_sandbox_string "$WAIT_BASE.out" || has_sandbox_string "$WAIT_BASE.err"; then
            record_sandbox 'send-wait' "wait-$PROFILE"
        else
            record 'send-wait' "wait-$PROFILE" 'FAIL' "wait exited $WAIT_RC with outcome not in closed set"
        fi
    done
fi

# ---- leg 3: approvals --------------------------------------------------
for PROFILE in "${PROFILES[@]}"; do
    SLUG="$(safe_name "$PROFILE")"
    # Status shape + precedence, offline (no network).
    ST_BASE="$OUT_DIR/autoapprove-status-$SLUG"
    run_cap "$ST_BASE" 30 ccfg "$CFG" --profile "$PROFILE" auto-approve status
    if [ "$(cat "$ST_BASE.code")" = '0' ] && json_is_valid "$ST_BASE.out" \
        && [ "$(json_field "$ST_BASE.out" 'auto_approve')" != '__MISSING__' ]; then
        record 'approvals' "status-$PROFILE" 'PASS' 'auto-approve status JSON shape ok'
    else
        record 'approvals' "status-$PROFILE" 'FAIL' "auto-approve status exited $(cat "$ST_BASE.code")"
    fi
    ENV_BASE="$OUT_DIR/autoapprove-env-$SLUG"
    run_cap "$ENV_BASE" 30 env -u CASTCTL_CONFIG -u CASTCTL_PROFILE MUSE_AUTO_APPROVE=always "$BIN" --config "$CFG" --profile "$PROFILE" auto-approve status
    ENV_AA="$(json_field "$ENV_BASE.out" 'auto_approve')"
    ENV_SRC="$(json_field "$ENV_BASE.out" 'source')"
    if [ "$(cat "$ENV_BASE.code")" = '0' ] && [ "$ENV_AA" = 'always' ]; then
        record 'approvals' "env-wins-$PROFILE" 'PASS' 'env override wins without writing'
    else
        record 'approvals' "env-wins-$PROFILE" 'FAIL' "env override exited $(cat "$ENV_BASE.code") auto_approve=$ENV_AA"
    fi
    BADENV_BASE="$OUT_DIR/autoapprove-badenv-$SLUG"
    run_cap "$BADENV_BASE" 30 env -u CASTCTL_CONFIG -u CASTCTL_PROFILE MUSE_AUTO_APPROVE=bogus "$BIN" --config "$CFG" --profile "$PROFILE" auto-approve status
    if [ "$(cat "$BADENV_BASE.code")" = '2' ]; then
        record 'approvals' "bad-env-$PROFILE" 'PASS' 'invalid MUSE_AUTO_APPROVE exits 2 (probe value only)'
    else
        record 'approvals' "bad-env-$PROFILE" 'FAIL' "invalid env exited $(cat "$BADENV_BASE.code"), expected 2"
    fi
    # Parser negative controls (no network, no invented approval id).
    APP_BASE="$OUT_DIR/approve-noid-$SLUG"
    run_cap "$APP_BASE" 30 ccfg "$CFG" --profile "$PROFILE" approve
    if [ "$(cat "$APP_BASE.code")" = '2' ]; then
        record 'approvals' "approve-noid-$PROFILE" 'PASS' 'approve with no id exits 2'
    else
        record 'approvals' "approve-noid-$PROFILE" 'FAIL' "approve with no id exited $(cat "$APP_BASE.code"), expected 2"
    fi
    # Persistence on a THROWAWAY copy: auto-approve on rewrites the
    # config (mode stays 0600, file is not byte-preserving). Never
    # run this against the main temp copy.
    AA_DIR="$E2E_TMP/aa-$SLUG"
    mkdir -p "$AA_DIR"
    AA_CFG="$AA_DIR/config.json"
    cp -- "$CFG" "$AA_CFG"; chmod 0600 "$AA_CFG"
    AA_BASE="$OUT_DIR/autoapprove-on-$SLUG"
    run_cap "$AA_BASE" 30 ccfg "$AA_CFG" --profile "$PROFILE" auto-approve on
    AA_MODE="$(stat -c '%a' "$AA_CFG" 2>/dev/null || echo missing)"
    AA_ST_BASE="$OUT_DIR/autoapprove-on-status-$SLUG"
    run_cap "$AA_ST_BASE" 30 ccfg "$AA_CFG" --profile "$PROFILE" auto-approve status
    if [ "$(cat "$AA_BASE.code")" = '0' ] && [ "$AA_MODE" = '600' ] \
        && [ "$(json_field "$AA_ST_BASE.out" 'auto_approve')" = 'always' ]; then
        record 'approvals' "persist-$PROFILE" 'PASS' 'auto-approve on persists, mode stays 0600'
    else
        record 'approvals' "persist-$PROFILE" 'FAIL' "auto-approve on exited $(cat "$AA_BASE.code") mode=$AA_MODE"
    fi
    # Live listing: shape only, counts only, never decide anything.
    if [ "$LIVE_SEND" -ne 1 ]; then
        record 'approvals' "list-$PROFILE" 'SKIP' 'live listing needs --live-send context (no approval invented)'
        continue
    fi
    if ! cookies_present "$PROFILE"; then
        record 'approvals' "list-$PROFILE" 'SKIP' 'no cookies file for profile'
        continue
    fi
    LIST_BASE="$OUT_DIR/approvals-list-$SLUG"
    run_cap "$LIST_BASE" 60 ccfg "$CFG" --profile "$PROFILE" approvals
    if [ "$(cat "$LIST_BASE.code")" = '0' ] && json_is_valid "$LIST_BASE.out"; then
        PENDING="$(python3 - "$LIST_BASE.out" <<'PY'
import json, sys
try:
    d = json.load(open(sys.argv[1], encoding="utf-8"))
except Exception:
    print("__BADJSON__"); sys.exit(0)
p = d.get("pending")
print(len(p) if isinstance(p, list) else "__MISSING__")
PY
)"
        if [ "$PENDING" != '__BADJSON__' ] && [ "$PENDING" != '__MISSING__' ]; then
            record 'approvals' "list-$PROFILE" 'PASS' "approvals listed, pending_count=$PENDING (deciding is manual, never automated here)"
        else
            record 'approvals' "list-$PROFILE" 'FAIL' 'approvals output has no pending list'
        fi
    elif has_sandbox_string "$LIST_BASE.out" || has_sandbox_string "$LIST_BASE.err"; then
        record_sandbox 'approvals' "list-$PROFILE"
    else
        record 'approvals' "list-$PROFILE" 'FAIL' "approvals exited $(cat "$LIST_BASE.code")"
    fi
done

# ---- leg 4: watch ------------------------------------------------------
if [ "$LIVE_SEND" -ne 1 ]; then
    for PROFILE in "${PROFILES[@]}"; do
        SLUG="$(safe_name "$PROFILE")"
        record 'watch' "watch-$PROFILE" 'SKIP' 'unseeded window must not PASS; needs --live-send'
    done
else
    for PROFILE in "${PROFILES[@]}"; do
        SLUG="$(safe_name "$PROFILE")"
        if ! cookies_present "$PROFILE"; then
            record 'watch' "watch-$PROFILE" 'SKIP' 'no cookies file for profile'
            continue
        fi
        WATCH_BASE="$OUT_DIR/watch-$SLUG"
        # Start watch, then send during its window, then collect it.
        run_cap "$WATCH_BASE" 30 ccfg "$CFG" --profile "$PROFILE" watch --timeout 20 --n 50 &
        WATCH_JOB="$!"
        sleep 2
        SEND2_BASE="$OUT_DIR/watch-send-$SLUG"
        run_cap "$SEND2_BASE" 60 ccfg "$CFG" --profile "$PROFILE" send 'castctl e2e watch probe (no action needed)' --wait 10 --ack-timeout 10
        wait "$WATCH_JOB" 2>/dev/null || true
        WATCH_RC="$(cat "$WATCH_BASE.code")"
        ROWS="$(python3 - "$WATCH_BASE.out" <<'PY'
import json, sys
n = 0
bad = 0
for line in open(sys.argv[1], encoding="utf-8", errors="replace"):
    line = line.strip()
    if not line:
        continue
    try:
        row = json.loads(line)
    except Exception:
        bad += 1
        continue
    if "event" in row and "seq" in row:
        n += 1
    else:
        bad += 1
print(f"{n} {bad}")
PY
)"
        ROW_COUNT="${ROWS%% *}"
        BAD_COUNT="${ROWS##* }"
        if [ "$WATCH_RC" = '0' ] && [ "$BAD_COUNT" = '0' ] && [ "$ROW_COUNT" -ge 1 ]; then
            record 'watch' "watch-$PROFILE" 'PASS' "watch clean exit 0, rows=$ROW_COUNT"
        elif [ "$WATCH_RC" = '0' ] && [ "$BAD_COUNT" = '0' ]; then
            record 'watch' "watch-$PROFILE" 'SKIP' 'no events observed in the seeded window'
        elif has_sandbox_string "$WATCH_BASE.out" || has_sandbox_string "$WATCH_BASE.err"; then
            record_sandbox 'watch' "watch-$PROFILE"
        else
            record 'watch' "watch-$PROFILE" 'FAIL' "watch exited $WATCH_RC rows=$ROW_COUNT bad_rows=$BAD_COUNT"
        fi
    done
fi

# ---- leg 5: DNS --------------------------------------------------------
# No local resolver is re-implemented: DNS evidence comes from
# profile test Phase 1 fields, config migrate (dry-run, writes
# nothing), and mutated-copy parse checks.
MIG_BASE="$OUT_DIR/config-migrate"
MIG_SHA_BEFORE="$(sha256sum -- "$CFG" | awk '{print $1}')"
run_cap "$MIG_BASE" 30 ccfg "$CFG" config migrate
MIG_SHA_AFTER="$(sha256sum -- "$CFG" | awk '{print $1}')"
if [ "$(cat "$MIG_BASE.code")" = '0' ] && [ "$MIG_SHA_BEFORE" = "$MIG_SHA_AFTER" ]; then
    record 'dns' 'migrate-dry-run' 'PASS' 'config migrate dry-run exited 0, temp config unchanged'
else
    record 'dns' 'migrate-dry-run' 'FAIL' "config migrate exited $(cat "$MIG_BASE.code")"
fi
for PROFILE in "${PROFILES[@]}"; do
    SLUG="$(safe_name "$PROFILE")"
    TEST_OUT="$OUT_DIR/profile-test-$SLUG.out"
    if [ -f "$TEST_OUT" ] && json_is_valid "$TEST_OUT"; then
        DNS_OK="$(json_field "$TEST_OUT" 'dns.ok')"
        DNS_SOURCE="$(json_field "$TEST_OUT" 'dns.source')"
        DNS_SERVER="$(json_field "$TEST_OUT" 'dns.server')"
        case "$DNS_SOURCE" in
            profile|wireguard|global-compat|default) DS_OK=1 ;;
            *) DS_OK=0 ;;
        esac
        if [ "$DNS_OK" = 'true' ] && [ "$DS_OK" = '1' ] && [ "$DNS_SERVER" != '__MISSING__' ]; then
            record 'dns' "phase1-$PROFILE" 'PASS' 'dns.ok, source in closed enum, server tag present'
        elif has_sandbox_string "$TEST_OUT" || has_sandbox_string "$OUT_DIR/profile-test-$SLUG.err"; then
            record_sandbox 'dns' "phase1-$PROFILE"
        else
            record 'dns' "phase1-$PROFILE" 'FAIL' 'dns fields not ok in profile test output'
        fi
    else
        record 'dns' "phase1-$PROFILE" 'SKIP' 'no profile test result to read DNS fields from'
    fi
    # Negative control: empty per-profile dns {} must fail at runtime
    # construction, not parse silently. Only meaningful with cookies.
    if cookies_present "$PROFILE"; then
        EMPTY_VCFG="$(make_variant "empty-dns-$PROFILE" empty-profile-dns "$PROFILE")"
        EMPTY_BASE="$OUT_DIR/empty-dns-$SLUG"
        run_cap "$EMPTY_BASE" 60 ccfg "$EMPTY_VCFG" profile test "$PROFILE"
        if has_sandbox_string "$EMPTY_BASE.out" || has_sandbox_string "$EMPTY_BASE.err"; then
            record_sandbox 'dns' "empty-dns-$PROFILE"
        elif [ "$(cat "$EMPTY_BASE.code")" != '0' ]; then
            record 'dns' "empty-dns-$PROFILE" 'PASS' "empty profile dns fails construction, exit $(cat "$EMPTY_BASE.code")"
        else
            record 'dns' "empty-dns-$PROFILE" 'FAIL' 'empty profile dns unexpectedly passed profile test'
        fi
    else
        record 'dns' "empty-dns-$PROFILE" 'SKIP' 'no cookies file for profile'
    fi
    # G1: profile dns + top-level dns together must be a parse error.
    DETOUR="$(python3 "$CFGTOOL" detour-for "$CFG" "$PROFILE")"
    G1_VCFG="$(make_variant "g1-$PROFILE" add-profile-dns "$PROFILE" "$DETOUR")"
    python3 "$CFGTOOL" edit "$G1_VCFG" "$G1_VCFG" add-global-dns "$DETOUR" >/dev/null
    G1_BASE="$OUT_DIR/g1-$SLUG"
    run_cap "$G1_BASE" 30 ccfg "$G1_VCFG" profile show "$PROFILE"
    if [ "$(cat "$G1_BASE.code")" = '2' ] && grep -a -q -i -F 'dns' "$G1_BASE.err"; then
        record 'dns' "g1-$PROFILE" 'PASS' 'profile dns + top-level dns together exit 2 naming dns'
    else
        record 'dns' "g1-$PROFILE" 'FAIL' "G1 variant exited $(cat "$G1_BASE.code"), expected 2 naming dns"
    fi
done

# ---- leg 6: outbounds / WireGuard (shape only, never values) ---------
SHAPE_BASE="$OUT_DIR/shape"
python3 "$CFGTOOL" shape "$CFG" >"$SHAPE_BASE.out" 2>"$SHAPE_BASE.err"
SHAPE_RC="$?"
if [ "$SHAPE_RC" -ne 0 ]; then
    record 'outbounds' 'shape' 'FAIL' "shape query exited $SHAPE_RC"
elif ! grep -q '^tags_unique=yes$' "$SHAPE_BASE.out"; then
    record 'outbounds' 'shape' 'FAIL' 'shape query did not assert tags_unique=yes'
else
    record 'outbounds' 'shape' 'PASS' 'shape query ok (field names, tags, counts only, tags_unique=yes)'
fi
# Negative control: a wireguard object in outbounds[] must be rejected.
WGOB_VCFG="$(make_variant 'wg-outbound' wg-outbound)"
WGOB_BASE="$OUT_DIR/wg-outbound"
run_cap "$WGOB_BASE" 30 ccfg "$WGOB_VCFG" profile show "${PROFILES[0]}"
if [ "$(cat "$WGOB_BASE.code")" = '2' ] && grep -a -q -i -F 'wireguard' "$WGOB_BASE.err"; then
    record 'outbounds' 'wg-in-outbounds' 'PASS' 'wireguard in outbounds[] rejected, exit 2 naming wireguard'
else
    record 'outbounds' 'wg-in-outbounds' 'FAIL' "wireguard outbound variant exited $(cat "$WGOB_BASE.code"), expected 2 naming wireguard"
fi
# Negative control: duplicate outbound tag must be rejected (only
# when the config has at least one outbound to duplicate).
if grep -q '^outbounds_count=[1-9]' "$SHAPE_BASE.out"; then
    DUP_VCFG="$(make_variant 'dup-tag' dup-tag)"
    DUP_BASE="$OUT_DIR/dup-tag"
    run_cap "$DUP_BASE" 30 ccfg "$DUP_VCFG" profile show "${PROFILES[0]}"
    if [ "$(cat "$DUP_BASE.code")" = '2' ] && grep -a -q -i -F 'duplicate' "$DUP_BASE.err"; then
        record 'outbounds' 'dup-tag' 'PASS' 'duplicate outbound tag rejected, exit 2 naming duplicate'
    else
        record 'outbounds' 'dup-tag' 'FAIL' "duplicate tag variant exited $(cat "$DUP_BASE.code"), expected 2 naming duplicate"
    fi
else
    record 'outbounds' 'dup-tag' 'SKIP' 'config has no outbounds to duplicate'
fi
# WireGuard shape: presence/type/counts only. No key value is ever
# printed, logged, or hashed into output by the shape query.
if grep -q '^wireguard ' "$SHAPE_BASE.out"; then
    WG_SYSTEM_BAD="$(grep -c '^wireguard .* system=True' "$SHAPE_BASE.out" || true)"
    WG_NOKEY="$(grep -c '^wireguard .* private_key=absent' "$SHAPE_BASE.out" || true)"
    if [ "$WG_SYSTEM_BAD" = '0' ] && [ "$WG_NOKEY" = '0' ]; then
        record 'outbounds' 'wg-shape' 'PASS' 'wireguard endpoints: system not true, private_key present (presence only)'
    else
        record 'outbounds' 'wg-shape' 'FAIL' "wireguard shape: system_true=$WG_SYSTEM_BAD missing_key=$WG_NOKEY"
    fi
    # Key-sharing negative control with FAKE key material only.
    WGDUP_VCFG="$(make_variant 'wg-dup-fake' wg-dup-fake)"
    WGDUP_BASE="$OUT_DIR/wg-dup-fake"
    run_cap "$WGDUP_BASE" 30 ccfg "$WGDUP_VCFG" profile show "${PROFILES[0]}"
    if [ "$(cat "$WGDUP_BASE.code")" = '2' ] && [ "$(count_fixed "$WGDUP_BASE.err" "$FAKE_WG_KEY")" = '0' ]; then
        record 'outbounds' 'wg-key-sharing' 'PASS' 'shared fake key rejected, exit 2, fake key absent from error (count 0)'
    else
        record 'outbounds' 'wg-key-sharing' 'FAIL' "key-sharing variant exited $(cat "$WGDUP_BASE.code")"
    fi
    # Liveness is profile test Phase 1/4 only; reuse leg 1's result.
    for PROFILE in "${PROFILES[@]}"; do
        SLUG="$(safe_name "$PROFILE")"
        TEST_OUT="$OUT_DIR/profile-test-$SLUG.out"
        if [ -f "$TEST_OUT" ] && json_is_valid "$TEST_OUT" && [ "$(json_field "$TEST_OUT" 'gateway.ok')" = 'true' ]; then
            record 'outbounds' "wg-liveness-$PROFILE" 'PASS' 'gateway phase ok through the profile outbound (see leg 1)'
        elif [ -f "$TEST_OUT" ] && has_sandbox_string "$TEST_OUT"; then
            record_sandbox 'outbounds' "wg-liveness-$PROFILE"
        else
            record 'outbounds' "wg-liveness-$PROFILE" 'SKIP' 'no live gateway result; no no-dial WG liveness command exists'
        fi
    done
else
    record 'outbounds' 'wg-shape' 'SKIP' 'no wireguard endpoint in config'
    record 'outbounds' 'wg-key-sharing' 'SKIP' 'no wireguard endpoint in config'
    for PROFILE in "${PROFILES[@]}"; do
        SLUG="$(safe_name "$PROFILE")"
        record 'outbounds' "wg-liveness-$PROFILE" 'SKIP' 'no wireguard endpoint in config'
    done
fi

# ---- leg 7: logging ----------------------------------------------------
# All logging probes use a variant config whose profile has NO
# cookies file, so the failing wait path is offline and bounded.
for PROFILE in "${PROFILES[@]}"; do
    SLUG="$(safe_name "$PROFILE")"
    # (a) No log block + no flag: off-gate. stderr = one JSON line.
    NOLOG_VCFG="$(make_variant "nolog2-$PROFILE" no-cookies "$PROFILE" "$E2E_TMP/variants/missing-cookies-$SLUG")"
    python3 "$CFGTOOL" edit "$NOLOG_VCFG" "$NOLOG_VCFG" strip-log >/dev/null
    NL_BASE="$OUT_DIR/log-nolog-$SLUG"
    run_cap "$NL_BASE" 30 ccfg "$NOLOG_VCFG" --profile "$PROFILE" wait --timeout 1 --json
    NL_LINES="$(wc -l < "$NL_BASE.err" | tr -d ' ')"
    if [ "$(cat "$NL_BASE.code")" = '2' ] && [ "$NL_LINES" = '1' ] && [ ! -s "$NL_BASE.out" ]; then
        record 'logging' "nolog-$PROFILE" 'PASS' 'off-gate: single typed JSON stderr line, empty stdout'
    else
        record 'logging' "nolog-$PROFILE" 'FAIL' "off-gate probe exited $(cat "$NL_BASE.code") stderr_lines=$NL_LINES"
    fi
    # (b) Log block to a fresh file: castctl creates it 0600.
    LOGFILE="$LOG_DIR/e2e-$SLUG.log"
    FILE_VCFG="$(make_variant "logfile-$PROFILE" no-cookies "$PROFILE" "$E2E_TMP/variants/missing-cookies-$SLUG")"
    python3 "$CFGTOOL" edit "$FILE_VCFG" "$FILE_VCFG" set-log-file "$LOGFILE" >/dev/null
    LF_BASE="$OUT_DIR/log-file-$SLUG"
    run_cap "$LF_BASE" 30 ccfg "$FILE_VCFG" --profile "$PROFILE" wait --timeout 1 --json
    if [ -f "$LOGFILE" ]; then
        LF_MODE="$(stat -c '%a' "$LOGFILE")"
        if [ "$LF_MODE" = '600' ]; then
            record 'logging' "file-$PROFILE" 'PASS' 'log file created mode 0600 (content not asserted: failing run may emit nothing)'
        else
            record 'logging' "file-$PROFILE" 'FAIL' "log file mode $LF_MODE, expected 600"
        fi
    else
        record 'logging' "file-$PROFILE" 'FAIL' 'log file was not created'
    fi
    # (c) disabled:true creates no file.
    DIS_LOGFILE="$LOG_DIR/disabled-$SLUG.log"
    DIS_VCFG="$(make_variant "logdisabled-$PROFILE" no-cookies "$PROFILE" "$E2E_TMP/variants/missing-cookies-$SLUG")"
    python3 "$CFGTOOL" edit "$DIS_VCFG" "$DIS_VCFG" set-log-disabled "$DIS_LOGFILE" >/dev/null
    DIS_BASE="$OUT_DIR/log-disabled-$SLUG"
    run_cap "$DIS_BASE" 30 ccfg "$DIS_VCFG" --profile "$PROFILE" wait --timeout 1 --json
    if [ ! -f "$DIS_LOGFILE" ] && [ "$(cat "$DIS_BASE.code")" = '2' ]; then
        record 'logging' "disabled-$PROFILE" 'PASS' 'disabled:true creates no log file'
    else
        record 'logging' "disabled-$PROFILE" 'FAIL' 'disabled:true created a log file or unexpected exit'
    fi
    # (d) Trace override: --log-level trace turns logging on; the
    # typed JSON stays the last stderr line. No --trace flag exists.
    TR_BASE="$OUT_DIR/log-trace-$SLUG"
    run_cap "$TR_BASE" 30 ccfg "$NOLOG_VCFG" --log-level trace --profile "$PROFILE" wait --timeout 1 --json
    TR_LAST="$(tail -n 1 "$TR_BASE.err" 2>/dev/null)"
    case "$TR_LAST" in
        *'"type":"cookies_missing"'*) TR_JSON=1 ;;
        *) TR_JSON=0 ;;
    esac
    if [ "$(cat "$TR_BASE.code")" = '2' ] && [ "$TR_JSON" = '1' ]; then
        record 'logging' "trace-$PROFILE" 'PASS' '--log-level trace accepted, typed JSON is the last stderr line'
    else
        record 'logging' "trace-$PROFILE" 'FAIL' "trace override exited $(cat "$TR_BASE.code")"
    fi
    NOTRACE_BASE="$OUT_DIR/log-notrace-$SLUG"
    run_cap "$NOTRACE_BASE" 30 ccfg "$NOLOG_VCFG" --trace --profile "$PROFILE" wait --timeout 1 --json
    if [ "$(cat "$NOTRACE_BASE.code")" = '2' ]; then
        record 'logging' "no-trace-flag-$PROFILE" 'PASS' 'no --trace flag: exit 2'
    else
        record 'logging' "no-trace-flag-$PROFILE" 'FAIL' "unexpected --trace acceptance, exit $(cat "$NOTRACE_BASE.code")"
    fi
    BADLV_BASE="$OUT_DIR/log-badlevel-$SLUG"
    run_cap "$BADLV_BASE" 30 ccfg "$NOLOG_VCFG" --log-level bogus --profile "$PROFILE" wait --timeout 1 --json
    if [ "$(cat "$BADLV_BASE.code")" = '2' ] && [ "$(count_fixed "$BADLV_BASE.err" 'bogus')" = '0' ]; then
        record 'logging' "bad-level-$PROFILE" 'PASS' 'invalid log level exits 2, probe value never echoed (count 0)'
    else
        record 'logging' "bad-level-$PROFILE" 'FAIL' "bad log level exited $(cat "$BADLV_BASE.code")"
    fi
    # (e) Refused log target: output = the config file itself.
    REF_VCFG="$(make_variant "logrefused-$PROFILE" no-cookies "$PROFILE" "$E2E_TMP/variants/missing-cookies-$SLUG")"
    python3 "$CFGTOOL" edit "$REF_VCFG" "$REF_VCFG" set-log-output "$REF_VCFG" >/dev/null
    REF_BASE="$OUT_DIR/log-refused-$SLUG"
    run_cap "$REF_BASE" 30 ccfg "$REF_VCFG" --profile "$PROFILE" wait --timeout 1 --json
    if [ "$(cat "$REF_BASE.code")" = '2' ]; then
        record 'logging' "refused-$PROFILE" 'PASS' 'log output = config file refused, exit 2'
    else
        record 'logging' "refused-$PROFILE" 'FAIL' "refused log target exited $(cat "$REF_BASE.code"), expected 2"
    fi
    record 'logging' "live-content-$PROFILE" 'SKIP' 'log content on a live successful run [NEEDS-MEASUREMENT]'
done

# ---- leg 8: Telegram ---------------------------------------------------
# castctl reads the Telegram token ONLY from the config block. The
# CASTCTL_TELEGRAM_TOKEN env var is a script-level convenience: it
# was injected into the temp config copy only (see the setup above).
# No env support was added to castctl.
if [ -s "$OUT_DIR/inject.err" ]; then
    record 'telegram' 'inject' 'FAIL' 'telegram token injection failed'
fi
HAS_TG_BLOCK="$(python3 "$CFGTOOL" has-block "$CFG" telegram)"
TG_TOKEN_PRESENT="$(python3 "$CFGTOOL" token-present "$CFG" telegram)"
TG_STATUS_BASE="$OUT_DIR/telegram-status"
run_cap "$TG_STATUS_BASE" 30 ccfg "$CFG" telegram status
TG_STATUS_RC="$(cat "$TG_STATUS_BASE.code")"
if [ "$HAS_TG_BLOCK" = 'no' ]; then
    if [ "$TG_STATUS_RC" = '2' ]; then
        record 'telegram' 'status-absent' 'PASS' 'no telegram block: telegram status exits 2'
    else
        record 'telegram' 'status-absent' 'FAIL' "no telegram block but status exited $TG_STATUS_RC, expected 2"
    fi
    record 'telegram' 'status' 'SKIP' 'no telegram block in config'
    record 'telegram' 'run' 'SKIP' 'no telegram block in config'
elif [ "$TG_TOKEN_PRESENT" = 'no' ]; then
    record 'telegram' 'status' 'SKIP' 'telegram block has no token'
    record 'telegram' 'run' 'SKIP' 'telegram block has no token'
else
    if [ "$TG_STATUS_RC" = '0' ] && json_is_valid "$TG_STATUS_BASE.out" \
        && [ "$(json_field "$TG_STATUS_BASE.out" 'configured')" = 'true' ] \
        && [ "$(json_field "$TG_STATUS_BASE.out" 'token_valid')" = 'true' ]; then
        record 'telegram' 'status' 'PASS' 'telegram status: configured, token_valid (value never printed)'
    elif has_sandbox_string "$TG_STATUS_BASE.out" || has_sandbox_string "$TG_STATUS_BASE.err"; then
        record_sandbox 'telegram' 'status'
    else
        record 'telegram' 'status' 'FAIL' "telegram status exited $TG_STATUS_RC"
    fi
    # Bounded poll: interrupt with SIGINT; a clean interrupt is 130.
    # Delivery of a real message / placeholder reply is manual and
    # [NEEDS-MEASUREMENT]; it is never claimed here.
    TG_RUN_BASE="$OUT_DIR/telegram-run"
    run_cap_int "$TG_RUN_BASE" 15 ccfg "$CFG" telegram run
    TG_RUN_RC="$(cat "$TG_RUN_BASE.code")"
    if [ "$TG_RUN_RC" = '130' ]; then
        record 'telegram' 'run' 'PASS' 'telegram run polls until SIGINT, exits 130'
    elif has_sandbox_string "$TG_RUN_BASE.out" || has_sandbox_string "$TG_RUN_BASE.err"; then
        record_sandbox 'telegram' 'run'
    else
        record 'telegram' 'run' 'FAIL' "telegram run exited $TG_RUN_RC, expected 130 on SIGINT"
    fi
fi

# ---- leg 9: update ------------------------------------------------------
# Never run a non-dry-run update: it would replace the binary under
# test. On an unstamped build every mode refuses before any network
# access; that refusal is the PASS-able check. A stamped dry-run is
# SKIP with reason (needs network to the release API).
UPD_BASE="$OUT_DIR/update-dryrun"
UPD_SHA_BEFORE="$(sha256sum -- "$BIN" 2>/dev/null | awk '{print $1}')"
run_cap "$UPD_BASE" 60 env -u CASTCTL_CONFIG -u CASTCTL_PROFILE "$BIN" update --dry-run
UPD_RC="$(cat "$UPD_BASE.code")"
if [ "$STAMPED" = '0' ]; then
    if [ "$UPD_RC" = '2' ] && grep -a -q -F -- 'cannot determine running version' "$UPD_BASE.err"; then
        record 'update' 'unstamped-refusal' 'PASS' 'unstamped build refuses update in every mode, exit 2, fixed message'
    else
        record 'update' 'unstamped-refusal' 'FAIL' "unstamped update --dry-run exited $UPD_RC"
    fi
    record 'update' 'dry-run' 'SKIP' 'binary is unstamped; stamped dry-run needs a stamped binary'
else
    if [ "$UPD_RC" = '0' ]; then
        record 'update' 'dry-run' 'PASS' 'stamped dry-run report exited 0 (no replace)'
    elif has_sandbox_string "$UPD_BASE.out" || has_sandbox_string "$UPD_BASE.err"; then
        record_sandbox 'update' 'dry-run'
    else
        record 'update' 'dry-run' 'FAIL' "stamped update --dry-run exited $UPD_RC"
    fi
fi
UPD_SHA_AFTER="$(sha256sum -- "$BIN" 2>/dev/null | awk '{print $1}')"
if [ "$UPD_SHA_BEFORE" = "$UPD_SHA_AFTER" ]; then
    record 'update' 'binary-unchanged' 'PASS' 'binary hash unchanged after the update leg'
else
    record 'update' 'binary-unchanged' 'FAIL' 'binary changed during the update leg'
fi

# ---- leg 10: keeper -----------------------------------------------------
HAS_KEEPER_BLOCK="$(python3 "$CFGTOOL" has-block "$CFG" keeper)"
KEEPER_STATUS_BASE="$OUT_DIR/keeper-status"
run_cap "$KEEPER_STATUS_BASE" 60 ccfg "$CFG" keeper status
KEEPER_STATUS_RC="$(cat "$KEEPER_STATUS_BASE.code")"
if [ "$HAS_KEEPER_BLOCK" = 'no' ]; then
    if [ "$KEEPER_STATUS_RC" = '2' ]; then
        record 'keeper' 'status-absent' 'PASS' 'no keeper block: keeper status exits 2'
    else
        record 'keeper' 'status-absent' 'FAIL' "no keeper block but keeper status exited $KEEPER_STATUS_RC, expected 2"
    fi
    record 'keeper' 'status' 'SKIP' 'no keeper block in config'
    record 'keeper' 'check' 'SKIP' 'no keeper block in config'
else
    if [ "$KEEPER_STATUS_RC" = '0' ] && json_is_valid "$KEEPER_STATUS_BASE.out"; then
        record 'keeper' 'status' 'PASS' 'keeper status exited 0, JSON parseable (state files only, no network)'
    elif has_sandbox_string "$KEEPER_STATUS_BASE.out" || has_sandbox_string "$KEEPER_STATUS_BASE.err"; then
        record_sandbox 'keeper' 'status'
    else
        record 'keeper' 'status' 'FAIL' "keeper status exited $KEEPER_STATUS_RC"
    fi
    # One tick now — but keeper check can rewrite cookies (tick
    # writes the cookies file), so on real profiles it stays dry
    # unless --live-keeper is given. Exit 3 (entry stopped: auth
    # expired) is a real outcome, recorded as SKIP — never a
    # healthy PASS. Exit 1/4 are failures unless the sandbox
    # string is present.
    KEEPER_ANY_COOKIES=0
    for PROFILE in "${PROFILES[@]}"; do
        SLUG="$(safe_name "$PROFILE")"
        cookies_present "$PROFILE" && KEEPER_ANY_COOKIES=1
    done
    if [ "$KEEPER_ANY_COOKIES" = '0' ]; then
        record 'keeper' 'check' 'SKIP' 'no cookies file for any profile'
        record 'keeper' 'state-file' 'SKIP' 'no cookies file for any profile; state path not asserted'
    elif [ "$LIVE_KEEPER" != '1' ]; then
        record 'keeper' 'check' 'SKIP' 'dry: keeper check may rewrite cookies; pass --live-keeper to run it'
        record 'keeper' 'state-file' 'SKIP' 'dry: keeper check did not run; state path not asserted'
    else
        CHECK_BASE="$OUT_DIR/keeper-check"
        run_cap "$CHECK_BASE" 120 ccfg "$CFG" keeper check
        CHECK_RC="$(cat "$CHECK_BASE.code")"
        if [ "$CHECK_RC" = '0' ]; then
            record 'keeper' 'check' 'PASS' 'keeper check exited 0 (healthy)'
        elif [ "$CHECK_RC" = '3' ]; then
            record 'keeper' 'check' 'SKIP' 'keeper check exited 3 (entry stopped), recorded outcome, not a healthy PASS'
        elif has_sandbox_string "$CHECK_BASE.out" || has_sandbox_string "$CHECK_BASE.err"; then
            record_sandbox 'keeper' 'check'
        else
            record 'keeper' 'check' 'FAIL' "keeper check exited $CHECK_RC"
        fi
        # The keeper writes state per profile, at
        # <config-dir>/profiles/<name>/session-state.json — never at
        # <config-dir>/session-state.json. Mode must be 0600.
        STATE_FOUND=0
        STATE_BAD=0
        for PROFILE in "${PROFILES[@]}"; do
            SLUG="$(safe_name "$PROFILE")"
            STATE_FILE="$CFG_DIR/profiles/$PROFILE/session-state.json"
            if [ -f "$STATE_FILE" ]; then
                STATE_FOUND=1
                [ "$(stat -c '%a' "$STATE_FILE")" = '600' ] || STATE_BAD=1
            fi
        done
        if [ "$STATE_FOUND" = '1' ] && [ "$STATE_BAD" = '0' ]; then
            record 'keeper' 'state-file' 'PASS' 'session-state.json exists mode 0600 at profiles/<name>/session-state.json'
        elif [ "$STATE_BAD" = '1' ]; then
            record 'keeper' 'state-file' 'FAIL' 'session-state.json mode wrong, expected 600'
        else
            record 'keeper' 'state-file' 'SKIP' 'no session-state.json under profiles/<name>/ (per-profile path checked)'
        fi
    fi
    record 'keeper' 'cdp-reexport' 'SKIP' 'real CDP re-export needs a running browser + expired session [NEEDS-MEASUREMENT]'
    record 'keeper' 'run-single-flight' 'SKIP' 'keeper run single-flight refusal is manual [NEEDS-MEASUREMENT]'
fi

# ---- leg 11: web UI -----------------------------------------------------
# Auth header via a 0600 file, never argv. The key is exported only
# for the server process, then unset.
free_port() {
    python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()'
}

HAS_WEBUI_BLOCK="$(python3 "$CFGTOOL" has-block "$CFG" webui)"
WEBUI_TOKEN_PRESENT="$(python3 "$CFGTOOL" token-present "$CFG" webui)"
WEBUI_TOKEN_AVAILABLE=0
if [ "$WEBUI_KEY_HELD" = '1' ] || [ "$WEBUI_TOKEN_PRESENT" = 'yes' ]; then WEBUI_TOKEN_AVAILABLE=1; fi

if ! command -v curl >/dev/null 2>&1; then
    record 'webui' 'prerequisite' 'SKIP' 'curl is missing'
fi

if [ "$WEBUI_TOKEN_AVAILABLE" = '0' ]; then
    # Negative check: no token anywhere -> serve fails closed, exit 2.
    # Bare serve: the failure is pre-bind, no port is needed.
    NEG_BASE="$OUT_DIR/webui-no-token"
    run_cap "$NEG_BASE" 15 ccfg "$CFG" webui serve
    if [ "$(cat "$NEG_BASE.code")" = '2' ]; then
        record 'webui' 'no-token' 'PASS' 'webui serve with no token exits 2, never starts unauthenticated'
    else
        record 'webui' 'no-token' 'FAIL' "webui serve with no token exited $(cat "$NEG_BASE.code"), expected 2"
    fi
    # The non-loopback probe needs a webui block: without one,
    # serve fails on the block gate before the listen check, so
    # the listen rule is unreachable and the probe SKIP, never
    # PASS for the wrong reason. With a block, the listen check
    # is parse-time and runs before the token check (measured).
    # The probe uses a copy of the config with a non-loopback
    # listen key; the shared copy is never mutated.
    if [ "$HAS_WEBUI_BLOCK" != 'yes' ]; then
        record 'webui' 'nonloopback-refusal' 'SKIP' 'no webui block: listen check unreachable behind the block gate'
    else
        NL_PORT="$(free_port)"
        NL_BASE="$OUT_DIR/webui-nonloopback"
        NL_CFG="$E2E_TMP/nl-config.json"
        cp -- "$CFG" "$NL_CFG"
        chmod 0600 "$NL_CFG"
        python3 "$CFGTOOL" set-webui-listen "$NL_CFG" "$NL_CFG" "0.0.0.0:$NL_PORT" >/dev/null
        run_cap "$NL_BASE" 15 ccfg "$NL_CFG" webui serve
        if [ "$(cat "$NL_BASE.code")" = '2' ] && grep -a -q -F -- 'host must be loopback' "$NL_BASE.err" \
            && [ "$(count_fixed "$NL_BASE.err" "0.0.0.0")" = '0' ]; then
            record 'webui' 'nonloopback-refusal' 'PASS' 'non-loopback listen key exits 2 naming the loopback rule, address never echoed (count 0)'
        else
            record 'webui' 'nonloopback-refusal' 'FAIL' "non-loopback listen key exited $(cat "$NL_BASE.code"), expected 2 naming the loopback rule"
        fi
    fi
    record 'webui' 'auth' 'SKIP' 'no webui token (env unset, no block token)'
    record 'webui' 'bind' 'SKIP' 'no webui token (env unset, no block token)'
    record 'webui' 'secrets-write-only' 'SKIP' 'no webui token (env unset, no block token)'
    record 'webui' 'logs' 'SKIP' 'no webui token (env unset, no block token)'
else
    if ! command -v curl >/dev/null 2>&1; then
        record 'webui' 'auth' 'SKIP' 'curl is missing'
        record 'webui' 'bind' 'SKIP' 'curl is missing'
        record 'webui' 'secrets-write-only' 'SKIP' 'curl is missing'
        record 'webui' 'logs' 'SKIP' 'curl is missing'
    else
        PORT="$(free_port)"
        HDR_GOOD="$E2E_TMP/headers-good"
        HDR_BAD="$E2E_TMP/headers-bad"
        printf 'Authorization: Bearer %s\n' "$WEBUI_KEY_VALUE" > "$HDR_GOOD"
        chmod 0600 "$HDR_GOOD"
        printf 'Authorization: Bearer e2e-wrong-token\n' > "$HDR_BAD"
        chmod 0600 "$HDR_BAD"
        # The good token is always known: the script generated it
        # and injected it into the temp copy's webui block.
        WEBUI_LOG="$OUT_DIR/webui-serve"
        # Bind address via the config listen key (the only listen
        # source): inject the ephemeral port into the temp copy.
        python3 "$CFGTOOL" set-webui-listen "$CFG" "$CFG" "127.0.0.1:$PORT" >/dev/null
        # webui_exec uses exec, so $! IS the castctl PID itself —
        # never a wrapper subshell (see the helper definition).
        webui_exec "$CFG" webui serve >"$WEBUI_LOG.out" 2>"$WEBUI_LOG.err" &
        WEBUI_PID="$!"
        # Poll until the API answers 401 unauthenticated (server up)
        # or the process exits.
        UP=0
        for _ in $(seq 1 20); do
            if ! kill -0 "$WEBUI_PID" 2>/dev/null; then break; fi
            CODE="$(curl -s -m 5 -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT/api/v1/status" 2>/dev/null || echo 000)"
            if [ "$CODE" = '401' ]; then UP=1; break; fi
            sleep 0.5
        done
        if [ "$UP" != '1' ]; then
            record 'webui' 'startup' 'FAIL' 'webui server did not answer 401 unauthenticated within the poll window'
        else
            record 'webui' 'startup' 'PASS' 'webui server answers on the loopback port'
            # Hash write-back: serve start hashes the plaintext
            # block token into the temp copy (atomic, 0600).
            # The stored value must be a bcrypt hash, never the
            # generated plaintext. The hash itself is compared
            # in-shell only, never printed.
            STORED_TOKEN="$(json_field "$CFG" 'webui.token')"
            case "$STORED_TOKEN" in
                '$2a$'*|'$2b$'*|'$2y$'*)
                    if [ "$STORED_TOKEN" != "$WEBUI_KEY_VALUE" ]; then
                        record 'webui' 'token-hash-writeback' 'PASS' 'stored webui token is a bcrypt hash, plaintext never rests on disk'
                    else
                        record 'webui' 'token-hash-writeback' 'FAIL' 'stored webui token equals the plaintext value'
                    fi
                    ;;
                *)
                    record 'webui' 'token-hash-writeback' 'FAIL' 'stored webui token is not a bcrypt hash after serve start'
                    ;;
            esac
            # Bind: loopback only in ss output (if ss exists).
            if command -v ss >/dev/null 2>&1; then
                SS_OUT="$OUT_DIR/webui-ss"
                ss -tln >"$SS_OUT.out" 2>"$SS_OUT.err" || true
                if grep -a -q -F -- "127.0.0.1:$PORT" "$SS_OUT.out" \
                    && ! grep -a -q -F -- "0.0.0.0:$PORT" "$SS_OUT.out"; then
                    record 'webui' 'bind' 'PASS' "ss shows 127.0.0.1:$PORT only, no 0.0.0.0 bind"
                else
                    record 'webui' 'bind' 'FAIL' 'ss bind evidence missing or non-loopback bind present'
                fi
            else
                record 'webui' 'bind' 'SKIP' 'ss is missing; loopback bind not verified'
            fi
            # Auth: no token -> 401, wrong token -> 401, good -> 200.
            STATUS_NOAUTH="$WEBUI_DIR/status-noauth.json"
            CODE_NOAUTH="$(curl -s -m 10 -o "$STATUS_NOAUTH" -w '%{http_code}' "http://127.0.0.1:$PORT/api/v1/status" 2>/dev/null || echo 000)"
            STATUS_BAD="$WEBUI_DIR/status-bad.json"
            CODE_BAD="$(curl -s -m 10 -o "$STATUS_BAD" -w '%{http_code}' -H @"$HDR_BAD" "http://127.0.0.1:$PORT/api/v1/status" 2>/dev/null || echo 000)"
            if [ "$CODE_NOAUTH" = '401' ] && [ "$CODE_BAD" = '401' ]; then
                record 'webui' 'auth' 'PASS' 'no-token and wrong-token both 401'
            else
                record 'webui' 'auth' 'FAIL' "auth codes: no-token=$CODE_NOAUTH wrong-token=$CODE_BAD, expected 401/401"
            fi
            # Good-token checks run when the script holds the
            # token: always, since it generated and injected it.
            if [ -n "$WEBUI_KEY_VALUE" ]; then
                STATUS_GOOD="$WEBUI_DIR/status-good.json"
                CODE_GOOD="$(curl -s -m 10 -o "$STATUS_GOOD" -w '%{http_code}' -H @"$HDR_GOOD" "http://127.0.0.1:$PORT/api/v1/status" 2>/dev/null || echo 000)"
                REMOTE_EXP="$(json_field "$STATUS_GOOD" 'data.remote_exposure')"
                if [ "$CODE_GOOD" = '200' ] && [ "$REMOTE_EXP" = 'false' ]; then
                    record 'webui' 'auth-good' 'PASS' 'good token 200, remote_exposure false'
                else
                    record 'webui' 'auth-good' 'FAIL' "good token did not return 200 with remote_exposure false (code=$CODE_GOOD)"
                fi
                # Secrets write-only: GET /config decoded content must
                # carry <redacted> at secret positions (when the
                # config has secrets) and 0 occurrences of held values.
                CONFIG_BODY="$WEBUI_DIR/config.json"
                CODE_CFG="$(curl -s -m 10 -o "$CONFIG_BODY" -w '%{http_code}' -H @"$HDR_GOOD" "http://127.0.0.1:$PORT/api/v1/config" 2>/dev/null || echo 000)"
                if [ "$CODE_CFG" = '200' ]; then
                    MARKERS="$(python3 - "$CONFIG_BODY" <<'PY'
import json, sys
try:
    d = json.load(open(sys.argv[1], encoding="utf-8"))
except Exception:
    print("__BADJSON__"); sys.exit(0)
data = d.get("data", {})
content = data.get("content", "") if isinstance(data, dict) else ""
print(content.count("<redacted>") if isinstance(content, str) else "__NOCONTENT__")
PY
)"
                    SECRETS_IN_COPY=0
                    if [ "$TELEGRAM_TOKEN_HELD" = '1' ] || [ "$TG_TOKEN_PRESENT" = 'yes' ] || [ "$WEBUI_TOKEN_PRESENT" = 'yes' ]; then
                        SECRETS_IN_COPY=1
                    fi
                    if [ "$SECRETS_IN_COPY" = '1' ] && [ "$MARKERS" != '__BADJSON__' ] && [ "$MARKERS" != '__NOCONTENT__' ] && [ "$MARKERS" -ge 1 ] 2>/dev/null; then
                        record 'webui' 'secrets-write-only' 'PASS' "GET /config decoded content carries <redacted> markers (count=$MARKERS)"
                    elif [ "$SECRETS_IN_COPY" = '0' ]; then
                        record 'webui' 'secrets-write-only' 'SKIP' 'config copy has no secret-bearing fields; marker check would be vacuous'
                    else
                        record 'webui' 'secrets-write-only' 'FAIL' "GET /config markers=$MARKERS"
                    fi
                else
                    record 'webui' 'secrets-write-only' 'FAIL' "GET /config code=$CODE_CFG"
                fi
                # Telegram settings: masked, never the value.
                TG_BODY="$WEBUI_DIR/settings-telegram.json"
                CODE_TG="$(curl -s -m 10 -o "$TG_BODY" -w '%{http_code}' -H @"$HDR_GOOD" "http://127.0.0.1:$PORT/api/v1/settings/telegram" 2>/dev/null || echo 000)"
                if [ "$CODE_TG" = '200' ]; then
                    TG_CONFIGURED="$(json_field "$TG_BODY" 'data.configured')"
                    MASKED="$(json_field "$TG_BODY" 'data.masked')"
                    if [ "$TG_CONFIGURED" != 'true' ]; then
                        record 'webui' 'telegram-masked' 'SKIP' 'telegram not configured on the served config; masked is empty by design'
                    elif [ "$MASKED" = '***' ]; then
                        record 'webui' 'telegram-masked' 'PASS' 'GET /settings/telegram masked exactly ***'
                    else
                        record 'webui' 'telegram-masked' 'FAIL' 'settings/telegram masked value is not exactly ***'
                    fi
                elif [ "$CODE_TG" = '404' ] || [ "$CODE_TG" = '501' ]; then
                    record 'webui' 'telegram-masked' 'SKIP' "settings/telegram code=$CODE_TG (no telegram block served)"
                else
                    record 'webui' 'telegram-masked' 'FAIL' "settings/telegram code=$CODE_TG"
                fi
            else
                record 'webui' 'auth-good' 'SKIP' 'script holds no web UI token value'
                record 'webui' 'secrets-write-only' 'SKIP' 'script holds no web UI token value'
                record 'webui' 'telegram-masked' 'SKIP' 'script holds no web UI token value'
            fi
            # /logs: gate reason must match the config.
            LOGS_BODY="$WEBUI_DIR/logs.json"
            CODE_LOGS="$(curl -s -m 10 -o "$LOGS_BODY" -w '%{http_code}' -H @"$HDR_GOOD" "http://127.0.0.1:$PORT/api/v1/logs" 2>/dev/null || echo 000)"
            if [ "$CODE_LOGS" = '200' ] && json_is_valid "$LOGS_BODY"; then
                LOGS_DISABLED="$(json_field "$LOGS_BODY" 'data.disabled')"
                LOGS_REASON="$(json_field "$LOGS_BODY" 'data.reason')"
                LOGS_ENTRIES="$(json_field "$LOGS_BODY" 'data.entries')"
                EXPECTED_REASON="$(python3 "$CFGTOOL" logs-expected "$CFG")"
                LOGS_REASON_OK=0
                case "$LOGS_REASON" in
                    logging_disabled|log_output_not_file|log_output_refused) LOGS_REASON_OK=1 ;;
                esac
                if [ "$LOGS_DISABLED" = 'true' ] && [ "$LOGS_REASON_OK" = '1' ] && [ "$LOGS_REASON" = "$EXPECTED_REASON" ]; then
                    record 'webui' 'logs' 'PASS' 'GET /logs disabled with the gate reason matching the config'
                elif [ "$LOGS_DISABLED" = 'false' ] && [ "$EXPECTED_REASON" = 'enabled' ] && [ "${LOGS_ENTRIES#[}" != "$LOGS_ENTRIES" ]; then
                    record 'webui' 'logs' 'PASS' 'GET /logs served entries (gate reason not disabled)'
                else
                    record 'webui' 'logs' 'FAIL' "GET /logs gate mismatch: disabled=$LOGS_DISABLED reason-in-closed-enum=$LOGS_REASON_OK"
                fi
            else
                record 'webui' 'logs' 'FAIL' "GET /logs code=$CODE_LOGS"
            fi
        fi
        kill "$WEBUI_PID" 2>/dev/null || true
        wait "$WEBUI_PID" 2>/dev/null || true
        WEBUI_PID=''
        # Verify the port actually closes. The recorded PID is the
        # castctl process itself (webui_exec uses exec), so a
        # lingering answer means the kill missed the real server.
        PORT_CLOSED=0
        for _ in $(seq 1 10); do
            if ! curl -s -m 2 -o /dev/null "http://127.0.0.1:$PORT/api/v1/status" 2>/dev/null; then
                PORT_CLOSED=1; break
            fi
            sleep 0.5
        done
        if [ "$PORT_CLOSED" = '1' ]; then
            record 'webui' 'server-stopped' 'PASS' 'webui server stopped, port closed after the leg'
        else
            record 'webui' 'server-stopped' 'FAIL' 'webui server port still answering after kill'
        fi
        # Non-loopback refusal. The listen check is parse-time
        # and runs before the token check when a webui block
        # exists (measured: exit 2 naming the loopback rule), so
        # this probe needs no token — but without a block the
        # block gate fires first and the probe SKIP, never PASS
        # for the wrong reason. The probe uses a copy of the
        # config with a non-loopback listen key; the probe
        # address is a fixed literal, not a secret.
        if [ "$HAS_WEBUI_BLOCK" != 'yes' ]; then
            record 'webui' 'nonloopback-refusal' 'SKIP' 'no webui block: listen check unreachable behind the block gate'
        else
            NL_PORT="$(free_port)"
            NL_BASE="$OUT_DIR/webui-nonloopback"
            NL_CFG="$E2E_TMP/nl-config.json"
            cp -- "$CFG" "$NL_CFG"
            chmod 0600 "$NL_CFG"
            python3 "$CFGTOOL" set-webui-listen "$NL_CFG" "$NL_CFG" "0.0.0.0:$NL_PORT" >/dev/null
            run_cap "$NL_BASE" 15 ccfg "$NL_CFG" webui serve
            if [ "$(cat "$NL_BASE.code")" = '2' ] && grep -a -q -F -- 'host must be loopback' "$NL_BASE.err" \
                && [ "$(count_fixed "$NL_BASE.err" "0.0.0.0")" = '0' ]; then
                record 'webui' 'nonloopback-refusal' 'PASS' 'non-loopback listen key exits 2 naming the loopback rule, address never echoed (count 0)'
            else
                record 'webui' 'nonloopback-refusal' 'FAIL' "non-loopback listen key exited $(cat "$NL_BASE.code"), expected 2 naming the loopback rule"
            fi
        fi
        record 'webui' 'external-connect' 'SKIP' 'external connect attempt is single-interface [NEEDS-MEASUREMENT]; bind + rejection are the proof'
    fi
fi

# ---- leg 12: final secret scan (counts only) ----------------------------
# Scope A: captured outputs only (.out/.err in OUT_DIR, .json in
# WEBUI_DIR, .log in LOG_DIR), plus verdicts.txt for VALUE patterns
# only (label patterns would self-match on the scan lines' pattern
# names). The scan asserts Scope A is non-empty: an empty scope
# would make a zero-count verdict vacuous.
# Scope B (never content-scanned): the temp config copy, header
# files, and the cookies ORIGINALS (hash/mtime recorded only, never
# read). Scope C: a control file with a FAKE labelled value the
# scanner must detect, proving it can detect.
CONTROL_FILE="$E2E_TMP/control.txt"
printf 'hatch_sess=FAKEPLACEHOLDER123\n' > "$CONTROL_FILE"
CONTROL_COUNT="$(count_regex "$CONTROL_FILE" 'hatch_sess=[^;[:space:]"]+')"
SCAN_FAIL=0
if [ "$CONTROL_COUNT" -lt 1 ]; then
    record 'secret-scan' 'control' 'FAIL' 'scanner control file not detected (count 0)'
    SCAN_FAIL=1
else
    record 'secret-scan' 'control' 'PASS' "scanner control detected (count=$CONTROL_COUNT, fake value)"
fi
SCOPE_A_FILES=0
for f in "$OUT_DIR"/*.out "$OUT_DIR"/*.err "$WEBUI_DIR"/*.json "$LOG_DIR"/*.log; do
    [ -f "$f" ] && SCOPE_A_FILES=$((SCOPE_A_FILES + 1))
done
if [ "$SCOPE_A_FILES" = '0' ]; then
    record 'secret-scan' 'scope' 'FAIL' 'no captured output files to scan; a zero-count verdict would be vacuous'
    SCAN_FAIL=1
fi
# Value patterns: only values the script itself holds from the env.
VALUE_TOTAL=0
if [ "$TELEGRAM_TOKEN_HELD" = '1' ]; then
    for f in "$VERDICTS" "$OUT_DIR"/*.out "$OUT_DIR"/*.err "$WEBUI_DIR"/*.json "$LOG_DIR"/*.log; do
        [ -f "$f" ] || continue
        VALUE_TOTAL=$((VALUE_TOTAL + $(count_fixed "$f" "$TELEGRAM_TOKEN_VALUE")))
    done
    printf 'secret-scan | telegram_token_value | count=%s\n' "$VALUE_TOTAL" | tee -a "$VERDICTS"
    [ "$VALUE_TOTAL" = '0' ] || SCAN_FAIL=1
else
    printf 'secret-scan | telegram_token_value | SKIP (script holds no value: token from supplied config only)\n' | tee -a "$VERDICTS"
fi
WEBUI_VALUE_TOTAL=0
if [ "$WEBUI_KEY_HELD" = '1' ]; then
    for f in "$VERDICTS" "$OUT_DIR"/*.out "$OUT_DIR"/*.err "$WEBUI_DIR"/*.json "$LOG_DIR"/*.log; do
        [ -f "$f" ] || continue
        WEBUI_VALUE_TOTAL=$((WEBUI_VALUE_TOTAL + $(count_fixed "$f" "$WEBUI_KEY_VALUE")))
    done
    printf 'secret-scan | webui_key_value | count=%s\n' "$WEBUI_VALUE_TOTAL" | tee -a "$VERDICTS"
    [ "$WEBUI_VALUE_TOTAL" = '0' ] || SCAN_FAIL=1
else
    printf 'secret-scan | webui_key_value | SKIP (script holds no value)\n' | tee -a "$VERDICTS"
fi
LABEL_TOTAL=0
for pat in 'hatch_sess=[^;[:space:]"]+' 'datr=[^;[:space:]"]+' 'private_key[":=]' 'preshared_key[":=]' 'BEGIN [A-Z ]*PRIVATE KEY' 'Authorization:[[:space:]]*Bearer[[:space:]]+\S+'; do
    PAT_TOTAL=0
    for f in "$OUT_DIR"/*.out "$OUT_DIR"/*.err "$WEBUI_DIR"/*.json "$LOG_DIR"/*.log; do
        [ -f "$f" ] || continue
        PAT_TOTAL=$((PAT_TOTAL + $(count_regex "$f" "$pat")))
    done
    printf 'secret-scan | label:%s | count=%s\n' "$pat" "$PAT_TOTAL" | tee -a "$VERDICTS"
    LABEL_TOTAL=$((LABEL_TOTAL + PAT_TOTAL))
done
[ "$LABEL_TOTAL" = '0' ] || SCAN_FAIL=1
if [ "$SCAN_FAIL" = '1' ]; then
    record 'secret-scan' 'verdict' 'FAIL' 'non-zero secret-pattern count in captured output (counts only, see scan lines above)'
else
    record 'secret-scan' 'verdict' 'PASS' 'all value/label pattern counts are 0 in Scope A (bare secrets remain unprovable by scanning; see docs/e2e.md)'
fi

# ---- negative control + immutability + summary --------------------------
NEG_VCFG="$(make_variant 'negative-control' add-unknown-key)"
NEG_BASE="$OUT_DIR/negative-control"
run_cap "$NEG_BASE" 30 ccfg "$NEG_VCFG" profile show "${PROFILES[0]}"
if [ "$(cat "$NEG_BASE.code")" = '2' ] && { grep -a -q -F -- 'e2e_bogus_key' "$NEG_BASE.err" || grep -a -q -F -- 'unknown top-level config key' "$NEG_BASE.err"; }; then
    record 'negative-control' 'unknown-key' 'PASS' 'unknown top-level key rejected, exit 2, key named in error'
else
    record 'negative-control' 'unknown-key' 'FAIL' "mutated config exited $(cat "$NEG_BASE.code"), expected 2 naming the key"
fi
SUPPLIED_SHA_AFTER="$(sha256sum -- "$SUPPLIED_CONFIG" | awk '{print $1}')"
if [ "$SUPPLIED_SHA" = "$SUPPLIED_SHA_AFTER" ]; then
    record 'immutability' 'supplied-config' 'PASS' 'supplied config byte-identical after the run'
else
    record 'immutability' 'supplied-config' 'FAIL' 'supplied config changed during the run'
fi
# Cookies originals: byte/mtime re-recorded and compared (paths
# only, hashes never printed). See verify_originals above.
verify_originals

printf '\n=== e2e summary ===\n'
printf 'PASS: %s\nFAIL: %s\nSKIP: %s (of which suspected-sandbox: %s)\n' "$PASS_COUNT" "$FAIL_COUNT" "$SKIP_COUNT" "$SANDBOX_SKIP_COUNT"
printf 'SKIPs (each with its reason):\n'
grep -F ' | SKIP | ' "$VERDICTS" || true
if [ "$SANDBOX_SKIP_COUNT" -gt 0 ]; then
    printf 'NOTE: %s suspected-sandbox SKIP(s) are listed above. A sandbox SKIP never counts as PASS toward Floor.\n' "$SANDBOX_SKIP_COUNT"
fi
printf 'Binary: %s\n' "$BIN"
printf 'Temp dir (removed by trap): %s\n' "$E2E_TMP"
if [ "$FAIL_COUNT" -gt 0 ]; then
    exit 1
fi
exit 0
