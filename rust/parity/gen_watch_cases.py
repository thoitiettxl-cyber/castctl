#!/usr/bin/env python3
"""Generate rust/parity/watch_cases/*.json (M7b PR-2 watch
Tier A fixtures). Re-running reproduces the files exactly.

Case shape: {"name", "args", "script": {"subscribes": [...]}}.
The serve-wait /chat/subscribe arm serves each entry's
frames as one NDJSON payload (EndBody closes the
subscription cleanly); an empty entry serves silence
(the client's idle timeout ends the batch); Drop closes
the connection after the frames.

Frames for the rows cases cover printWatchRow's whole
surface: a plain message row, all five text keys (input
order scrambled — the row reorders them), agent.status
(dropped without --all), the type fallback, a bad-JSON
line, a non-object line, the {} nulls row, a 301-rune
display_text (truncated to 300), a falsy mix, a big
seq literal + HTML/control escapes, and a list value
(two-layer escaping).
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "watch_cases")

ROWS = [
    '{"event":"agent.message","seq":1,"payload":{"display_text":"hello world"}}',
    '{"event":"agent.message","seq":2,"payload":{"status":"s","text":"t","display_text":"d","activity_text":"a","content":"c"}}',
    '{"event":"agent.status","seq":3,"payload":{"display_text":"working"}}',
    '{"type":"agent.message","seq":4,"payload":{"text":"hi"}}',
    "not-json",
    "[1,2]",
    "{}",
    json.dumps(
        {
            "event": "agent.message",
            "seq": 8,
            "payload": {"display_text": "x" * 301},
        },
        ensure_ascii=False,
    ),
    '{"event":"agent.message","seq":9,"payload":{"display_text":"","content":"c","text":0,"activity_text":false,"status":null}}',
    json.dumps(
        {
            "event": "a<b",
            "seq": 9007199254740993,
            "payload": {"display_text": "<a>&A\x08B\x0cC"},
        },
        ensure_ascii=False,
    ),
    '{"event":"m","seq":11,"payload":{"content":["a<b"]}}',
]

CASES = [
    {
        "name": "watch-rows",
        "args": [],
        "script": {"subscribes": [{"frames": ROWS, "end_body": True}]},
    },
    {
        "name": "watch-all",
        "args": ["--all"],
        "script": {"subscribes": [{"frames": ROWS, "end_body": True}]},
    },
    {
        "name": "watch-n1",
        "args": ["--n", "1"],
        "script": {"subscribes": [{"frames": ROWS, "end_body": True}]},
    },
    {
        "name": "watch-thread",
        "args": ["--thread", "t1"],
        "script": {"subscribes": [{"frames": ROWS[:1], "end_body": True}]},
    },
    {
        "name": "watch-timeout",
        "args": ["--timeout", "1"],
        "script": {"subscribes": [{}]},
    },
    # NOTE: no watch-drop case. A dropped connection is a
    # pinned known deviation (D-watch-drop, see PORTING
    # §M7b.12): rows + exit 1 match, but the stderr text
    # differs — Go surfaces the WS close summary
    # ("gateway: websocket closed (close_code=1006
    # reason_length=14)") while Rust renders the shared
    # length-only form ("conn: connection error
    # error_length=63"). The close code is lost in the
    # shared TransportError layer before watch ever sees
    # it, so no watch-local fix exists; changing the
    # shared rendering is out of this PR's scope. The
    # probe evidence (both drivers, 1 row + exit 1) is in
    # the writer report.
]


def main():
    os.makedirs(OUT, exist_ok=True)
    for case in CASES:
        path = os.path.join(OUT, case["name"] + ".json")
        with open(path, "w") as f:
            json.dump(case, f, indent=2, ensure_ascii=False)
            f.write("\n")
    print("wrote %d cases in %s" % (len(CASES), OUT))


if __name__ == "__main__":
    sys.exit(main())
