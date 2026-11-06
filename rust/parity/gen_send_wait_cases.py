#!/usr/bin/env python3
"""Generate rust/parity/send_wait_cases/*.json (M7b PR-2 send Tier A).

The stage model (proven by the probe run): history calls are
counted globally — calls 1-2 are the deliver baseline
(limit=1, limit=20), call 3+ the ack polls (limit=10), then
the Runner's derive/finish reads continue the count. Stages
switch by from_call: 1 = empty (baseline 0), 3 = the ack
user event, 5 = ack + the assistant reply (the Runner's
finish reads). The download step's limit=30 read is call 7+,
still stage 3.
"""
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "send_wait_cases")
os.makedirs(OUT, exist_ok=True)

USER = {"event_name": "message.user", "payload": {"display_text": "hello"}, "seq": 5}
ASST = {"event_name": "message.assistant", "payload": {"display_text": "Hello", "status": "completed"}, "seq": 6}
ASST_MEDIA = {
    "event_name": "message.assistant",
    "payload": {
        "display_text": "Hello",
        "status": "completed",
        "resources": [{"path": "sandbox://media/raw/pic.jpg", "byte_len": 11}],
    },
    "seq": 6,
}
DONE_FRAMES = [
    '{"event":"task.status","seq":6,"payload":{"status":"running","root_agent_id":"R","agent_id":"R"}}',
    '{"event_name":"message.assistant","seq":6,"payload":{"status":"completed","display_text":"Hello"}}',
    '{"event":"task.status","seq":7,"payload":{"status":"completed","root_agent_id":"R","agent_id":"R"}}',
]


def stages(assistant):
    return [
        {"events": [], "from_call": 1, "has_more": False},
        {"events": [USER], "from_call": 3, "has_more": False},
        {"events": [USER, assistant], "from_call": 5, "has_more": False},
    ]


def done_subscribes():
    return [{"delay_ms": 0, "drop": False, "end_body": True, "frames": DONE_FRAMES}]


def stages_user(text, assistant):
    """Like stages(), but the ack user event carries `text`
    (the sent text) so the deliver ack matches it."""
    user = {"event_name": "message.user", "payload": {"display_text": text}, "seq": 5}
    return [
        {"events": [], "from_call": 1, "has_more": False},
        {"events": [user], "from_call": 3, "has_more": False},
        {"events": [user, assistant], "from_call": 5, "has_more": False},
    ]


def go_escape_text(s):
    """Go encoding/json string escaping (HTML ON) for one string
    value, as json.dumps would emit it, then <>& and U+2028/U+2029
    escaped. Returns the QUOTED string. The literal it builds is
    cross-checked against the REAL Go driver output by the harness
    on every run (go-stream-body-mismatch-expected), so a mistake
    here fails loudly on the Go side, never silently."""
    out = json.dumps(s, ensure_ascii=False)
    out = out.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    out = out.replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")
    return out


def stream_body_for(text, thread=""):
    """Expected chat.stream request-body bytes for `text`
    (and `thread`), computed by the Go escaping rules above."""
    body = ('{"capabilities":{},"items":[{"text":' + go_escape_text(text)
            + ',"type":"text"}],"node_id":"wait-driver"}')
    if thread:
        body = body[:-1] + ',"session_id":' + go_escape_text(thread) + '}'
    return body


# Expected chat.stream request-body bytes, hand-written from the
# Go source (internal/commands/wait.go deliverSend: params map
# capabilities/items/node_id, session_id iff thread != ""; Go
# json.Marshal sorts keys, compact, no spaces). Both drivers
# use node_id "wait-driver". The harness
# (run_send_wait_cases.sh) diffs the serve-wait-logged body
# against this literal on each side. The text is "hello" in
# every case, so HTML escaping (Go on, serde_json off) cannot
# differ here -- the literal pins the bytes, the harness
# proves it (round-1 N-R1).
STREAM_BODY = '{"capabilities":{},"items":[{"text":"hello","type":"text"}],"node_id":"wait-driver"}'
STREAM_BODY_THREAD = '{"capabilities":{},"items":[{"text":"hello","type":"text"}],"node_id":"wait-driver","session_id":"t1"}'

# The helper above must reproduce the hand-written literals
# exactly; if it does not, the generator fails loudly here
# instead of writing wrong expected bodies.
assert stream_body_for("hello") == STREAM_BODY
assert stream_body_for("hello", "t1") == STREAM_BODY_THREAD


def case(name, args, script, stream_body=STREAM_BODY):
    with open(os.path.join(OUT, name + ".json"), "w") as f:
        json.dump({"args": args, "name": name, "script": script, "stream_body": stream_body}, f, indent=1, sort_keys=True)
        f.write("\n")


# 1. Done turn, JSON (the probe shape).
case("send-done", ["--wait", "5", "--ack-timeout", "5", "hello"],
     {"history_stages": stages(ASST), "subscribes": done_subscribes(), "thread": ""})

# 2. Done turn, --text.
case("send-done-text", ["--wait", "5", "--ack-timeout", "5", "--text", "hello"],
     {"history_stages": stages(ASST), "subscribes": done_subscribes(), "thread": ""})

# 3. --wait 0: ack, then JSON + exit 0, no subscribe.
case("send-wait-0", ["--wait", "0", "--ack-timeout", "5", "hello"],
     {"history_stages": stages(ASST), "subscribes": done_subscribes(), "thread": ""})

# 4. No ack within 1s: JSON + silent exit 5. The poll count
# (~10 polls) is timing-shaped; if this case ever flakes,
# drop --ack-timeout to 0 (0 polls, deterministic).
case("send-no-ack", ["--wait", "5", "--ack-timeout", "1", "hello"],
     {"history_stages": [{"events": [], "from_call": 1, "has_more": False}],
      "subscribes": [], "thread": ""})

# 5. Ack, then the turn never finishes within --wait 2s:
# outcome timeout, exit 124, the re-run hint as the note.
case("send-timeout", ["--wait", "2", "--ack-timeout", "5", "hello"],
     {"history_stages": [
         {"events": [], "from_call": 1, "has_more": False},
         {"events": [USER], "from_call": 3, "has_more": False},
     ],
      "subscribes": [{"delay_ms": 0, "drop": False, "end_body": False, "frames": []}],
      "thread": ""})

# 6. Done turn + --download: the assistant event carries one
# media resource (byte_len 11 = len("hello-bytes"), the fixed
# bytes the serve-wait media arm returns).
case("send-download", ["--wait", "5", "--ack-timeout", "5", "--download", "__DLDIR__", "hello"],
     {"history_stages": stages(ASST_MEDIA), "subscribes": done_subscribes(), "thread": ""})

# 7. Done turn + --download, no resources: downloads [] and
# the (empty) download dir is still created.
case("send-download-empty", ["--wait", "5", "--ack-timeout", "5", "--download", "__DLDIR__", "hello"],
     {"history_stages": stages(ASST), "subscribes": done_subscribes(), "thread": ""})

# 8. Threaded send: every history call carries session_id=t1.
case("send-thread", ["--thread", "t1", "--wait", "5", "--ack-timeout", "5", "hello"],
     {"history_stages": stages(ASST), "subscribes": done_subscribes(), "thread": "t1"},
     STREAM_BODY_THREAD)

# 9. Fix loop 2, B1: text with <>& — Go's encoding/json escapes
# them in the chat.stream body (\u003c/\u003e/\u0026); the pre-fix
# Rust sent them raw. The ack event carries the same text so
# the deliver ack matches. (Text from the round-2 red-team
# probe rt-send-weird2.)
TEXT_WEIRD2 = 'a"b <c> d&e ünïcode ✓'
case("send-weird2", ["--wait", "5", "--ack-timeout", "5", TEXT_WEIRD2],
     {"history_stages": stages_user(TEXT_WEIRD2, ASST), "subscribes": done_subscribes(), "thread": ""},
     stream_body_for(TEXT_WEIRD2))

# 10. Fix loop 2, B1: U+2028/U+2029 — Go escapes them even with
# SetEscapeHTML(false); serde_json does not.
TEXT_U2028 = "a\u2028b\u2029c"  # real U+2028/U+2029 chars, written as escapes (invisible in source)
case("send-u2028", ["--wait", "5", "--ack-timeout", "5", TEXT_U2028],
     {"history_stages": stages_user(TEXT_U2028, ASST), "subscribes": done_subscribes(), "thread": ""},
     stream_body_for(TEXT_U2028))

# 11. Fix loop 2, N-R2R1: a real newline in the text — proves the
# runner passes one argv (the old readarray+print split it) and
# the body carries the \n escape on both sides. (Round-1's
# newline claim was vacuous: both sides sent only "line1".)
TEXT_NEWLINE = 'line1\nline2 "quoted" ünïcode ✓'
case("send-newline", ["--wait", "5", "--ack-timeout", "5", TEXT_NEWLINE],
     {"history_stages": stages_user(TEXT_NEWLINE, ASST), "subscribes": done_subscribes(), "thread": ""},
     stream_body_for(TEXT_NEWLINE))

print("wrote", len(os.listdir(OUT)), "cases in", OUT)
