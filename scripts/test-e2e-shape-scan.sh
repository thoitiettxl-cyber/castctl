#!/usr/bin/env bash
# Test for the leg-12 secret-scan false positive (scripts/e2e.sh).
#
# The shape query in e2e.sh prints WireGuard key *presence* only. It used
# to print `private_key=present`, which matches the leg-12 label pattern
# `private_key[":=]` in the script's own captured shape.out, so the scan
# failed on the script's own diagnostic output. The fix spells presence
# with a space (`private_key present` / `private_key absent`).
#
# This test proves both sides, deterministically, with no live binary
# or network: (1) shape output for configs with and without a key
# matches none of the six label patterns extracted verbatim from
# e2e.sh; (2) a fixture holding a real labelled fake value still
# matches the `private_key` pattern. All key material here is the
# repo's own fake placeholder (FAKE_WG_KEY in e2e.sh); no real secret.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
E2E="$ROOT/scripts/e2e.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

# Extract the embedded cfgtool (between the heredoc markers) verbatim.
python3 - "$E2E" "$TMP/cfgtool.py" <<'PY'
import sys
e2e, out = sys.argv[1], sys.argv[2]
lines = open(e2e, encoding="utf-8").read().splitlines(keepends=True)
start = next(i for i, line in enumerate(lines) if "<<'PYEOF'" in line) + 1
end = next(i for i, line in enumerate(lines) if line.rstrip("\n") == "PYEOF")
open(out, "w", encoding="utf-8").write("".join(lines[start:end]))
PY
[ -s "$TMP/cfgtool.py" ] || fail "cfgtool extraction empty"

# Extract the six label patterns verbatim from the scan loop in e2e.sh,
# so this test fails if the pattern list drifts instead of silently
# testing a stale copy.
mapfile -t PATS < <(python3 - "$E2E" <<'PY'
import shlex
import sys
for line in open(sys.argv[1], encoding="utf-8"):
    stripped = line.strip()
    if stripped.startswith("for pat in "):
        body = stripped[len("for pat in "):]
        body = body[: body.rindex("; do")]
        print("\n".join(shlex.split(body)))
        break
PY
)
[ "${#PATS[@]}" -eq 6 ] || fail "expected 6 label patterns from e2e.sh, got ${#PATS[@]}"

# Same counting semantics as count_regex in e2e.sh: grep -c prints the
# count (exit 1 on zero matches is not a failure here).
count_regex() {
    local n
    n="$(grep -a -c -E -- "$2" "$1" 2>/dev/null || true)"
    [ -n "$n" ] || n=0
    printf '%s' "$n"
}

# Fake placeholder values only (FAKE_WG_KEY in e2e.sh); never real keys.
FAKE_KEY='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='
FAKE_PUB='BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB='

cat > "$TMP/with-key.json" <<JSON
{"outbounds": [], "endpoints": [{"type": "wireguard", "tag": "wg1", "private_key": "$FAKE_KEY", "peers": [{"public_key": "$FAKE_PUB", "allowed_ips": ["10.0.0.0/8"]}], "address": ["10.2.0.2/32"]}]}
JSON
cat > "$TMP/without-key.json" <<JSON
{"outbounds": [], "endpoints": [{"type": "wireguard", "tag": "wg1", "peers": [], "address": ["10.2.0.2/32"]}]}
JSON

python3 "$TMP/cfgtool.py" shape "$TMP/with-key.json" > "$TMP/with-key.out" 2> "$TMP/with-key.err"
python3 "$TMP/cfgtool.py" shape "$TMP/without-key.json" > "$TMP/without-key.out" 2> "$TMP/without-key.err"
[ -s "$TMP/with-key.err" ] && fail "shape with key wrote to stderr: $(cat "$TMP/with-key.err")"
[ -s "$TMP/without-key.err" ] && fail "shape without key wrote to stderr: $(cat "$TMP/without-key.err")"

# 1. No label pattern matches either shape output (the false positive is gone).
# Checked first so a pre-fix run fails here, on the scan count itself.
TOTAL=0
for pat in "${PATS[@]}"; do
    for f in "$TMP/with-key.out" "$TMP/without-key.out"; do
        TOTAL=$((TOTAL + $(count_regex "$f" "$pat")))
    done
done
[ "$TOTAL" = '0' ] || fail "label patterns matched shape output $TOTAL time(s); shape.out: $(cat "$TMP/with-key.out" "$TMP/without-key.out")"

# 2. New presence spelling, and the consumer grep in e2e.sh (:1342) sees it.
grep -Fq 'private_key present' "$TMP/with-key.out" || fail "with-key shape.out lacks 'private_key present': $(cat "$TMP/with-key.out")"
grep -Fq 'private_key absent' "$TMP/without-key.out" || fail "without-key shape.out lacks 'private_key absent': $(cat "$TMP/without-key.out")"
[ "$(grep -c '^wireguard .* private_key absent' "$TMP/without-key.out" || true)" = '1' ] || fail "consumer grep finds no absent line in without-key shape.out"
[ "$(grep -c '^wireguard .* private_key absent' "$TMP/with-key.out" || true)" = '0' ] || fail "consumer grep wrongly finds absent line in with-key shape.out"

# 3. Positive control: a real labelled fake value is still caught.
printf '{"type": "wireguard", "tag": "wg1", "private_key": "%s", "peers": []}\n' "$FAKE_KEY" > "$TMP/real-labelled.json"
printf 'private_key=%s\n' "$FAKE_KEY" >> "$TMP/real-labelled.json"
PRIVATE_COUNT="$(count_regex "$TMP/real-labelled.json" 'private_key[":=]')"
[ "$PRIVATE_COUNT" -ge 1 ] || fail "private_key pattern did not catch a real labelled value (count=$PRIVATE_COUNT)"

printf 'PASS: shape output matches 0/6 label patterns; labelled fake value caught (private_key count=%s)\n' "$PRIVATE_COUNT"
