#!/usr/bin/env python3
"""Generate rust/parity/m7b_cases/*.json (M7b Phase A parity gate).

Each case: {"args": [...], "gateway": {path: entry}, "http": {path: entry}}.
Gateway entries: {"status", "result", "raw_b64", "body"} (see
gateway_server serve-m7b). HTTP entries: {"status", "body",
"raw_b64", "stages"} — "result" is NOT supported on the http map
(the Python server serves "body" verbatim; see
m7b_http_server.py).

The rt-*.json cases in m7b_cases/ are NOT generated here:
they are the red-team round-1 attack cases, promoted
verbatim as regression cases in fix loop 1 (B1–B6). The
rt-raw-badbody case is a KNOWN DIFFERENCE (D1): its stderr
is pinned per side in known_diff/ (see run_m7b_cases.sh),
not compared side-to-side. Do not regenerate or delete
the rt-* files; add new regression cases by hand.
"""
import base64
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "m7b_cases")
os.makedirs(OUT, exist_ok=True)

AP1 = {
    "approval_id": "ap1",
    "display": {
        "summary_title": "Network",
        "permission_question": {
            "text": "{assistant} wants net",
            "kind": "network_access",
            "scope": "x.com",
        },
        "detail_rows": [{"label": "Host", "value": "h"}],
    },
    "payload": {"type": "p"},
    "decision_options": [
        {"kind": "allow_once"},
        {"kind": "allow_always"},
        {"kind": "deny"},
    ],
}
# No forever option: approve --all / approvals --approve-all
# must skip it with the "no forever option" stderr line.
AP2 = {
    "approval_id": "ap2",
    "display": {
        "summary_title": "Shell",
        "permission_question": {
            "text": "{assistant} wants shell",
            "kind": "shell",
            "scope": "host",
        },
    },
    "payload": {"type": "p"},
    "decision_options": [{"kind": "allow_once"}, {"kind": "deny"}],
}

PENDING = {"pending_approvals": [AP1, AP2]}
PENDING_ONE = {"pending_approvals": [AP1]}
DECIDE_OK = {"decided": True, "approval_id": "ap1"}

INVITE_FULL = {
    # Raw API field names, as gateway.FetchInvite returns them;
    # shared.SummarizeInvite reads invite_state / invite_link /
    # use_count / subtitle (NOT state / link / used / offer).
    "invite_state": "active",
    "code": "ABC123",
    "invite_link": "https://muse.ai/invite/ABC123",
    "max_uses": 5,
    "use_count": 2,
    "uses_remaining": 3,
    "reward": {"title": "Get Pro", "body": "free month"},
    "subtitle": "Invite friends, get rewards",
}
INVITE_NONE = {"invite_state": "none"}

HISTORY_PIC = {
    "chat_events": [
        {
            "seq": 42,
            "payload": {
                "message_id": "m-42",
                "resources": [
                    {"path": "sandbox://media/raw/pic.jpg", "byte_len": 11}
                ],
            },
        }
    ],
    "has_more": False,
}
HISTORY_PIC_WARN = {
    "chat_events": [
        {
            "seq": 42,
            "payload": {
                "message_id": "m-42",
                "resources": [
                    {"path": "sandbox://media/raw/pic.jpg", "byte_len": 99}
                ],
            },
        }
    ],
    "has_more": False,
}
HISTORY_EMPTY = {"chat_events": [], "has_more": False}

PIC_BYTES = base64.b64encode(b"hello-bytes").decode()


def case(name, args, gateway=None, http=None):
    doc = {"args": args}
    if gateway:
        doc["gateway"] = gateway
    if http:
        doc["http"] = http
    with open(os.path.join(OUT, name + ".json"), "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2, ensure_ascii=False)
        f.write("\n")


def res(result, status=200):
    return {"status": status, "result": result}


# --- session ops (unary call_json) ---
case("session-start", ["session-start", "--title", "hello"],
     {"/session/start": res({"session_id": "s-1", "title": "hello"})})
case("session-rename", ["session-rename", "s-1", "new title"],
     {"/session/rename": res({"ok": True})})
case("session-pin", ["session-pin", "s-1"],
     {"/session/pin": res({"ok": True})})
case("session-unpin", ["session-unpin", "s-1"],
     {"/session/unpin": res({"ok": True})})
case("session-archive", ["session-archive", "s-1"],
     {"/session/archive": res({"ok": True})})
case("session-unarchive", ["session-unarchive", "s-1"],
     {"/session/unarchive": res({"ok": True})})
case("session-delete", ["session-delete", "s-1"],
     {"/session/delete": res({"ok": True})})

# --- stop ---
case("stop", ["stop"], {"/chat/cancel": res({"cancelled": True})})
case("stop-thread", ["stop", "--thread", "s-9"],
     {"/chat/cancel": res({"cancelled": True})})

# --- seen / feed-react / idea-exec ---
case("seen", ["seen", "t-1"],
     {"/api/chat/t-1/seen": res({"ok": True})})
case("feed-react", ["feed-react", "u-1"],
     {"/api/feed/units/u-1/reaction": res({"ok": True})})
case("feed-react-haha", ["feed-react", "u-1", "haha"],
     {"/api/feed/units/u-1/reaction": res({"ok": True})})
case("idea-exec", ["idea-exec", "idea-1"],
     {"/api/idea-cards/idea-1/execute": res({"ok": True})})
case("idea-exec-thread", ["idea-exec", "idea-1", "--thread", "s-2"],
     {"/api/idea-cards/idea-1/execute": res({"ok": True})})

# --- approvals / approve / deny ---
case("approvals", ["approvals"], {"/approvals": res(PENDING)})
case("approvals-recent", ["approvals", "--recent"],
     {"/approvals": res({**PENDING, "recent_approvals": [
         {**AP1, "decision": "allow_once"}]})})
case("approvals-raw", ["approvals", "--raw"],
     {"/approvals": res(PENDING)})
case("approvals-empty", ["approvals"],
     {"/approvals": res({"pending_approvals": []})})
case("approve", ["approve", "ap1"],
     {"/approvals/ap1/decide": res(DECIDE_OK)})
case("approve-always", ["approve", "ap1", "--always"],
     {"/approvals/ap1/decide": res(DECIDE_OK)})
case("approve-all", ["approve", "--all"],
     {"/approvals": res(PENDING),
      "/approvals/ap1/decide": res(DECIDE_OK)})
case("approvals-approve-all", ["approvals", "--approve-all"],
     {"/approvals": res(PENDING),
      "/approvals/ap1/decide": res(DECIDE_OK)})
case("deny", ["deny", "ap1"],
     {"/approvals/ap1/decide": res(DECIDE_OK)})
case("deny-always", ["deny", "ap1", "--always"],
     {"/approvals/ap1/decide": res(DECIDE_OK)})

# --- invite / redeem / wake (plain HTTPS) ---
case("invite", ["invite"], http={
    "/api/hatch/invite": {"status": 200,
                          "body": json.dumps(INVITE_FULL)}})
case("invite-json", ["invite", "--json"], http={
    "/api/hatch/invite": {"status": 200,
                          "body": json.dumps(INVITE_FULL)}})
case("invite-raw", ["invite", "--raw"], http={
    "/api/hatch/invite": {"status": 200,
                          "body": json.dumps(INVITE_FULL)}})
case("invite-create", ["invite", "--create"], http={
    "/api/hatch/invite": {"status": 200, "stages": [
        {"status": 200, "body": json.dumps(INVITE_NONE)},
        {"status": 200, "body": json.dumps(INVITE_FULL)}]}})
case("redeem-success-json", ["redeem", "ABC123", "--json"], http={
    "/api/hatch/invite-code/redeem": {
        "status": 200,
        "body": '{"success":true,"redemptionStatus":"granted"}'}})
case("redeem-success-text", ["redeem", "ABC123"], http={
    "/api/hatch/invite-code/redeem": {
        "status": 200,
        "body": '{"success":true,"redemptionStatus":"granted"}'}})
case("redeem-fail-json", ["redeem", "BAD999", "--json"], http={
    "/api/hatch/invite-code/redeem": {
        "status": 200,
        "body": '{"success":false,"reason":"invalid","detail":"code expired"}'}})
case("redeem-fail-text", ["redeem", "BAD999"], http={
    "/api/hatch/invite-code/redeem": {
        "status": 200,
        "body": '{"success":false,"reason":"invalid","detail":"code expired"}'}})
case("redeem-invalid", ["redeem", "bad!"])
case("wake", ["wake"], http={
    "/api/hatch/vm/wake": {"status": 200,
                           "body": '{"status":"waking","vm_id":"vm-test"}'}})

# --- download ---
case("download-sandbox", ["download", "sandbox://media/raw/pic.jpg"],
     {"/media/raw/pic.jpg": {"status": 200, "raw_b64": PIC_BYTES}})
case("download-history", ["download", "42"],
     {"/chat/history": res(HISTORY_PIC),
      "/media/raw/pic.jpg": {"status": 200, "raw_b64": PIC_BYTES}})
case("download-history-warning", ["download", "42"],
     {"/chat/history": res(HISTORY_PIC_WARN),
      "/media/raw/pic.jpg": {"status": 200, "raw_b64": PIC_BYTES}})
case("download-nofiles", ["download", "zzz"],
     {"/chat/history": res(HISTORY_EMPTY)})

# --- raw ---
case("raw-history", ["raw", "chat.history", "--body", '{"limit":5}'],
     {"/chat/history": res({"messages": [{"role": "user", "text": "hi"}]})})
case("raw-unknown", ["raw", "no.such.method"])
case("raw-nonjson", ["raw", "chat.history"],
     {"/chat/history": {"status": 200,
                        "raw_b64": base64.b64encode(b"plain text\n").decode()}})

# --- gateway error (exit 3, conn summary) ---
case("gateway-error", ["session-start"],
     {"/session/start": {"status": 502,
                         "body": '{"ok":false,"error":"boom"}'}})

print("wrote", len(os.listdir(OUT)), "cases to", OUT)
