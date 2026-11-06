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

print("wrote", len(os.listdir(OUT)), "cases in", OUT)
