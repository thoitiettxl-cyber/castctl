#!/usr/bin/env python3
# Fake muse.ai HTTP server for the M7b Phase A parity gate
# (rust/parity/run_m7b_cases.sh): serves the case script's
# "http" map plus the CannedAuth paths (/api/session,
# /api/auth/check, /api/hatch/token) with the same canned
# values gatewaytest.CannedAuth serves, logging every request
# as `M7B-HTTP <verb> <path> <body>` to stderr — the same
# lines the Go m7b_driver's in-process HTTP handler logs.
#
# Response bytes are verbatim: script entries use "body"
# (exact string) or "raw_b64" (base64 bytes); the server never
# re-serializes JSON, so the bytes match the Go handler's
# exactly. "result" entries are NOT supported on the HTTP map
# (they exist only for the gateway side, which is Go-only).
#
# Usage: m7b_http_server.py <script.json>
# Prints `READY addr=127.0.0.1:PORT` on stdout, serves until
# SIGTERM/SIGINT. All credentials here are fake; nothing real
# is ever read.
import base64
import json
import signal
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CANNED = {
    "/api/session": (200, '{"vm_id":"vm-test"}'),
    "/api/auth/check": (200, '{"access_token":"AT-FAKE"}'),
    "/api/hatch/token": (200, '{"token":"HT-FAKE"}'),
}


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: m7b_http_server.py <script.json>", file=sys.stderr)
        return 2
    with open(sys.argv[1], "r", encoding="utf-8") as f:
        script = json.load(f)
    http_map = script.get("http", {})

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        counts = {}

        def log_message(self, *args):  # silence default logging
            pass

        def _handle(self):
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length > 0 else b""
            sys.stderr.write(
                "M7B-HTTP %s %s %s\n"
                % (self.command, self.path, body.decode("utf-8", "replace"))
            )
            sys.stderr.flush()
            status, payload = self._response(body)
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(payload)

        def _response(self, _body):
            if self.path in CANNED:
                status, text = CANNED[self.path]
                return status, text.encode("utf-8")
            entry = http_map.get(self.path)
            if entry is None:
                return (
                    404,
                    ('{"error":"m7b-http: no canned response for %s"}'
                     % self.path).encode("utf-8"),
                )
            # Stages answer the Nth request to this path with
            # stages[N-1] (the last repeats), mirroring the Go
            # driver's httpHandler.
            stages = entry.get("stages")
            if stages:
                n = Handler.counts.get(self.path, 0)
                Handler.counts[self.path] = n + 1
                entry = stages[min(n, len(stages) - 1)]
            status = entry.get("status") or 200
            if entry.get("raw_b64"):
                return status, base64.b64decode(entry["raw_b64"])
            if entry.get("body") is not None:
                return status, entry["body"].encode("utf-8")
            if entry.get("result") is not None:
                raise SystemExit(
                    "m7b_http_server: 'result' is not supported on "
                    "the http map (use 'body'); path %s" % self.path
                )
            return status, b"{}"

        do_GET = _handle
        do_POST = _handle
        do_PUT = _handle
        do_DELETE = _handle
        do_HEAD = _handle

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True

    def _stop(signum, frame):
        # Raise SystemExit in the main thread: serve_forever
        # unwinds cleanly. (Calling server.shutdown() here
        # deadlocks: it blocks until the serve loop notices,
        # but the loop is the interrupted frame below this
        # handler — the process would ignore SIGTERM forever
        # and pile up as orphans.)
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    print("READY addr=127.0.0.1:%d" % server.server_address[1], flush=True)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
