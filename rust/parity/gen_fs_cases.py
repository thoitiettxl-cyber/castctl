#!/usr/bin/env python3
"""Generate the PR-2 fs harness cases (rust/parity/m7b_cases/fs-*.json).

Each case: {"args": [...], "gateway": {path: entry}, ...} where a
gateway entry is {"status", "result", "raw_b64", "body"} (see
gateway_server serve-m7b). Optional keys: "stdin_b64" (bytes fed
to both drivers' stdin, for `fs write`), "seed_files"
{"name": "<base64>"} (decoded once into $OUT/<case>.seed;
"__SEEDDIR__" in argv is replaced with that dir, for `fs put`).

Entry lists reuse one shape: a file, a dotfile (filtered unless
-a), a directory. The `fs.read` result is {"data_base64", "eof"}.
"""
import base64
import json
import os

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "m7b_cases")
os.makedirs(OUT, exist_ok=True)


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


ENTRIES = [
    {"name": "a.txt", "type": "file", "size": 12, "modifiedAt": "2026-10-24T12:57:37"},
    {"name": ".hidden", "type": "file", "size": 3, "modifiedAt": "2026-10-24T12:57:37"},
    {"name": "docs", "type": "directory", "size": 4096, "modifiedAt": "2026-10-24T12:57:37"},
]

LIST = {"result": {"entries": ENTRIES}}
TREE_LIST = {
    "result": {
        "entries": [
            {"name": "d", "type": "directory", "size": 4096, "modifiedAt": "2026-10-24T12:57:37"},
            {"name": "f.txt", "type": "file", "size": 5, "modifiedAt": "2026-10-24T12:57:37"},
        ]
    }
}
READ_HELLO = {"result": {"data_base64": b64(b"hello fs\n"), "eof": True}}


def case(name, args, gateway=None, **extra):
    doc = {"args": args}
    if gateway is not None:
        doc["gateway"] = gateway
    doc.update(extra)
    with open(os.path.join(OUT, name + ".json"), "w") as f:
        json.dump(doc, f, indent=2, ensure_ascii=False)
        f.write("\n")


# --- read-only surface ---
case("fs-ls", ["fs", "ls"], {"/fs/list": LIST})
case("fs-ls-all", ["fs", "ls", "-a"], {"/fs/list": LIST})
case("fs-ls-json", ["fs", "ls", "--json"], {"/fs/list": LIST})
case(
    "fs-ls-json-escapes",
    ["fs", "ls", "--json"],
    {
        "/fs/list": {
            "result": {
                "entries": [
                    {"name": "a\bb", "type": "file", "size": 1},
                    {"name": "c\fd", "type": "file", "size": 2},
                    {"name": "e<f>&g", "type": "file", "size": 3},
                ]
            }
        }
    },
)
case("fs-ls-long", ["fs", "ls", "-l"], {"/fs/list": LIST})
case("fs-ls-path", ["fs", "ls", "sub"], {"/fs/list": LIST})
case("fs-ls-lt-path", ["fs", "ls", "a<b"], {"/fs/list": LIST})
# ^ Fix loop 2, B1 probe: a `<` in a request path. Go's
# encoding/json escapes it (\u003c) in the fs.list body; the
# pre-fix Rust sent it raw. The m7b harness diffs the logged
# request-body bytes, so this case fails until the gateway
# serialisation matches Go.
case("fs-tree", ["fs", "tree"], {"/fs/list": TREE_LIST})
case("fs-tree-json", ["fs", "tree", "--json"], {"/fs/list": TREE_LIST})
case(
    "fs-stat",
    ["fs", "stat", "a.txt"],
    {"/fs/stat": {"result": {"type": "file", "size": 12, "modifiedAt": "2026-10-24T12:57:37"}}},
)
case("fs-cat", ["fs", "cat", "a.txt"], {"/fs/read": READ_HELLO})
case("fs-cat-maxbytes", ["fs", "cat", "--max-bytes", "3", "a.txt"], {"/fs/read": READ_HELLO})
case(
    "fs-cat-binary",
    ["fs", "cat", "b.bin"],
    {"/fs/read": {"result": {"data_base64": b64(b"a\x00b\n"), "eof": True}}},
)
case(
    "fs-cat-binary-flag",
    ["fs", "cat", "--binary", "b.bin"],
    {"/fs/read": {"result": {"data_base64": b64(b"a\x00b\n"), "eof": True}}},
)
case(
    "fs-find",
    ["fs", "find", "memo"],
    {"/fs/search": {"result": {"entries": [{"name": "memo.txt", "type": "file", "size": 9}]}}},
)
case("fs-find-empty", ["fs", "find", "zzz"], {"/fs/search": {"result": {"entries": []}}})

# --- writes ---
case(
    "fs-mkdir",
    ["fs", "mkdir", "newdir"],
    {"/fs/mkdir": {"result": {"path": "newdir", "created": True}}},
)
case(
    "fs-mv",
    ["fs", "mv", "a.txt", "b.txt"],
    {"/fs/rename": {"result": {"ok": True}}},
)
case(
    "fs-rm",
    ["fs", "rm", "--yes", "a.txt"],
    {"/fs/delete": {"result": {"deleted": True}}},
)
case("fs-rm-no-yes", ["fs", "rm", "a.txt"])
case(
    "fs-get",
    ["fs", "get", "file.txt"],
    {
        "/fs/stat": {"result": {"type": "file", "size": 6}},
        "/fs/read": {"result": {"data_base64": b64(b"hello\n"), "eof": True}},
    },
)
case(
    "fs-get-recursive",
    ["fs", "get", "-r", "dir"],
    {
        "/fs/stat": {"result": {"type": "directory"}},
        "/fs/list": {
            "result": {
                "entries": [
                    {"name": "a.txt", "type": "file", "size": 6},
                    {"name": "b.txt", "type": "file", "size": 6},
                ]
            }
        },
        "/fs/read": {"result": {"data_base64": b64(b"hello\n"), "eof": True}},
    },
)
case(
    "fs-put",
    ["fs", "put", "__SEEDDIR__/up.txt", "remote.txt"],
    {"/fs/write": {"result": {}}},
    seed_files={"up.txt": b64(b"hello put\n")},
)
case(
    "fs-write",
    ["fs", "write", "w.txt"],
    {"/fs/write": {"result": {}}},
    stdin_b64=b64(b"hello write\n"),
)
case(
    "fs-write-append",
    ["fs", "write", "--append", "w.txt"],
    {
        "/fs/read": {"result": {"data_base64": b64(b"old"), "eof": True}},
        "/fs/write": {"result": {}},
    },
    stdin_b64=b64(b" more\n"),
)
case(
    "fs-edit-replace",
    ["fs", "edit", "--replace", "old", "new", "e.txt"],
    {
        "/fs/read": {"result": {"data_base64": b64(b"old text\n"), "eof": True}},
        "/fs/write": {"result": {}},
    },
)
case(
    "fs-edit-unchanged",
    ["fs", "edit", "--replace", "old", "old", "e.txt"],
    {"/fs/read": {"result": {"data_base64": b64(b"old text\n"), "eof": True}}},
)
case(
    "fs-edit-replace-missing",
    ["fs", "edit", "--replace", "zzz", "yyy", "e.txt"],
    {"/fs/read": {"result": {"data_base64": b64(b"old text\n"), "eof": True}}},
)

# --- the pre-collapse `..` reject (D-M7b-PR2-6/7): exit 2,
# fixed stderr, ZERO gateway calls (no "gateway" key: the
# servers start, see 0 requests, and both summaries agree).
case("fs-cat-traversal", ["fs", "cat", "../x"])
case("fs-rm-traversal", ["fs", "rm", "--yes", "../x"])
case("fs-mv-traversal", ["fs", "mv", "a", "../b"])
case("fs-put-traversal", ["fs", "put", "local.txt", "../remote.txt"])
case("fs-ls-traversal", ["fs", "ls", "a/../b"])
case(
    "fs-find-traversal-exempt",
    ["fs", "find", ".."],
    {"/fs/search": {"result": {"entries": []}}},
)

# --- gateway error shape ---
case(
    "fs-stat-gateway-error",
    ["fs", "stat", "a.txt"],
    {"/fs/stat": {"status": 500, "body": '{"ok":false,"error":"boom"}'}},
)

print("wrote", len(os.listdir(OUT)), "cases total in", OUT)
