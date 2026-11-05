#!/usr/bin/env python3
"""Generate the golden files for the M2 parity harness.

One command, overwrites the whole golden dir, fails on timeout,
signal death, or any unexpected output. Reads cases.json (the
single source of truth for the case list, shared with the Rust
parity test). Runs the Go binary (GO_BIN, default
/usr/local/bin/castctl) with an isolated HOME/XDG, a minimal
environment, stdin /dev/null, cwd = a fresh fixture work dir, and
the F1 fixture config installed at $XDG_CONFIG_HOME/castctl/.

Never hand-edit the golden files: re-run gen_golden.sh.
"""

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile

TIMEOUT_SECONDS = 10

# F9(a): the generator only ever runs against this exact golden
# binary. If the installed Go binary differs, generation fails
# loudly instead of silently recording goldens from another build.
EXPECTED_GO_VERSION = "castctl 0.9.0 (1396697 2026-11-04T21:38:36Z)"


def canonical_digest(stdout: bytes, stderr: bytes, exit_code: int) -> str:
    """sha256 over stdout + NUL + stderr + NUL + exit code (F9(b)).

    The Rust parity test recomputes this from the golden records;
    the two sides must agree byte-for-byte on the canonical form.
    """
    h = hashlib.sha256()
    h.update(stdout)
    h.update(b"\x00")
    h.update(stderr)
    h.update(b"\x00")
    h.update(str(exit_code).encode("ascii"))
    return h.hexdigest()


def main() -> int:
    here = os.path.dirname(os.path.abspath(__file__))
    cases_path = os.path.join(here, "cases.json")
    golden_dir = os.path.join(here, "golden")
    go_bin = os.environ.get("GO_BIN", "/usr/local/bin/castctl")

    if not os.path.isfile(go_bin) or not os.access(go_bin, os.X_OK):
        print(f"gen_golden: GO_BIN not executable: {go_bin}", file=sys.stderr)
        return 2
    with open(cases_path, "r", encoding="utf-8") as f:
        cases = json.load(f)
    ids = [c["id"] for c in cases]
    if len(ids) != len(set(ids)):
        print("gen_golden: duplicate case ids", file=sys.stderr)
        return 2

    version_proc = subprocess.run(
        [go_bin, "--version"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=TIMEOUT_SECONDS,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "TZ": "UTC"},
    )
    generated_by = version_proc.stdout.decode("utf-8", "replace").splitlines()
    generated_by = generated_by[0] if generated_by else ""
    if (
        version_proc.returncode != 0
        or version_proc.stderr
        or generated_by != EXPECTED_GO_VERSION
    ):
        print(
            f"gen_golden: GO_BIN --version must be exactly {EXPECTED_GO_VERSION!r}; "
            f"got exit={version_proc.returncode} stdout={generated_by!r} "
            f"stderr={version_proc.stderr!r}",
            file=sys.stderr,
        )
        return 2

    shutil.rmtree(golden_dir, ignore_errors=True)
    os.makedirs(golden_dir, exist_ok=True)

    manifest = {"schema_version": 1, "generated_by": generated_by, "cases": {}}

    for case in cases:
        root = tempfile.mkdtemp(prefix="castctl-golden-")
        try:
            home = os.path.join(root, "home")
            xdg = os.path.join(root, "xdg")
            work = os.path.join(root, "work")
            cfg_dir = os.path.join(xdg, "castctl")
            os.makedirs(home)
            os.makedirs(cfg_dir)
            os.makedirs(work)
            fixture_name = case.get("fixture", "config.json")
            fixture_path = os.path.join(here, "fixtures", fixture_name)
            shutil.copyfile(fixture_path, os.path.join(cfg_dir, "config.json"))
            with open(os.path.join(cfg_dir, "config.json"), "rb") as f:
                config_before = f.read()
            env = {
                "HOME": home,
                "XDG_CONFIG_HOME": xdg,
                "LC_ALL": "C",
                "TZ": "UTC",
                "PATH": "/usr/bin:/bin",
            }
            try:
                proc = subprocess.run(
                    [go_bin] + list(case["argv"]),
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=TIMEOUT_SECONDS,
                    cwd=work,
                    env=env,
                )
            except subprocess.TimeoutExpired:
                print(
                    f"gen_golden: TIMEOUT case {case['id']} argv={case['argv']}",
                    file=sys.stderr,
                )
                return 2
            if proc.returncode < 0:
                print(
                    f"gen_golden: SIGNAL {-proc.returncode} case {case['id']} "
                    f"argv={case['argv']}",
                    file=sys.stderr,
                )
                return 2
            # P-11: no case may write. The fixture config must be
            # byte-identical and the work dir must stay empty.
            with open(os.path.join(cfg_dir, "config.json"), "rb") as f:
                if f.read() != config_before:
                    print(
                        f"gen_golden: WRITE case {case['id']}: fixture config changed",
                        file=sys.stderr,
                    )
                    return 2
            if os.listdir(work):
                print(
                    f"gen_golden: WRITE case {case['id']}: work dir not empty: {os.listdir(work)}",
                    file=sys.stderr,
                )
                return 2
            record = {
                "schema_version": 1,
                "id": case["id"],
                "generated_by": generated_by,
                "fixture": fixture_name,
                "argv": list(case["argv"]),
                "env": dict(env),
                "cwd": work,
                "stdin": "empty",
                "timeout_seconds": TIMEOUT_SECONDS,
                "stdout": proc.stdout.decode("utf-8", "replace"),
                "stderr": proc.stderr.decode("utf-8", "replace"),
                "exit_code": proc.returncode,
            }
            manifest["cases"][case["id"]] = canonical_digest(
                proc.stdout, proc.stderr, proc.returncode
            )
            with open(
                os.path.join(golden_dir, case["id"] + ".json"),
                "w",
                encoding="utf-8",
            ) as f:
                json.dump(record, f, indent=2, ensure_ascii=False)
                f.write("\n")
            print(f"golden {case['id']}: exit={proc.returncode}")
        finally:
            shutil.rmtree(root, ignore_errors=True)

    with open(os.path.join(golden_dir, "manifest.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, ensure_ascii=False, sort_keys=True)
        f.write("\n")

    written = sorted(
        n for n in os.listdir(golden_dir) if n.endswith(".json") and n != "manifest.json"
    )
    if len(written) != len(cases):
        print(
            f"gen_golden: wrote {len(written)} files for {len(cases)} cases",
            file=sys.stderr,
        )
        return 2
    print(f"gen_golden: wrote {len(written)} golden files to {golden_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
