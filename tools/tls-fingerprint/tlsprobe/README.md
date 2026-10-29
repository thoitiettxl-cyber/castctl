# tlsprobe — PR0 TLS probe for the muse-cli Go port

Scratch-only probe, NOT product code. It answers, per TLS implementation
(stdlib `crypto/tls` vs sing-box uTLS fingerprint `chrome`), whether the
muse-cli gateway path works at the TLS / auth / Noise-handshake layers.
It proves nothing about chat, sessions, or file transfer.

## What it does

- **E1** — TLS handshake only, to `muse.ai:443` and `hatch.metaaivm.com:443`.
  No credentials are read, statted, or touched in any way.
- **E2** — The `gateway.py` HTTPS auth chain, read-only, with cookies from an
  explicitly passed `cookies.txt`:
  `GET /api/session`, `POST /api/auth/check`, `POST /api/hatch/token`.
  Reports only HTTP status codes and booleans (vm_id / access token /
  hatch token obtained). Token values are never printed.
- **E3** — WebSocket upgrade + Noise XX handshake to
  `wss://hatch.metaaivm.com/v1/noise`, then it CLOSES IMMEDIATELY.
  No `ServiceRequest`, no subscription, no `chat.stream`, no chat send,
  no session start, no `fs`/`history`/`unread`/`seen`/`archive`, no
  Telegram, no side-chat creation, no message to Muse.

## What it does NOT do

No messages are sent. No files are written. No cookies, tokens,
`auth_token`, private keys, or passwords are printed, logged, copied,
or embedded anywhere. Every error passes through a scrubber that
replaces secret values and any `auth_token`/`vm_id` query parameter
with `[REDACTED]`. The `-use-proxy` CONNECT code is probe-only and must
NOT be presented as product code: product code models an egress proxy
as an explicit sing-box outbound, never as a hidden env shim on `direct`.

## Build info (delivered binary)

- File: `tlsprobe-linux-amd64`
- SHA-256: `5e0a2daac5e64acac46906e4cc945f58d707933cedb3357d802a97735be3e220`
- Size: 11,427,964 bytes
- `file`: ELF 64-bit LSB executable, x86-64, statically linked, stripped
- `ldd`: not a dynamic executable
- Built with: Go 1.27.3, `GOOS=linux GOARCH=amd64 CGO_ENABLED=0`,
  `-trimpath`, `-ldflags '-s -w -buildid='`, `-tags with_utls`
- Deps (from `go version -m`): sing-box v1.14.4, metacubex/utls v1.8.7,
  flynn/noise v1.1.0, gorilla/websocket v1.5.3
- The build tag `with_utls` is REQUIRED: without it sing-box's uTLS
  client is a stub and the `singbox` implementation cannot run.
- The binary contains no VM paths, no proxy env values, and no secrets
  (verified with `strings`).

## Commands (decisive check: direct dial, no intercepting proxy)

Run on a machine whose egress is NOT TLS-intercepted, with the binary
in the current directory. Direct dial is the default; `-use-proxy` is
off unless explicitly passed.

```sh
# Usage only — dials nothing, exits 0:
./tlsprobe-linux-amd64 -h

# E1, stdlib crypto/tls only (handshake only, no cookie access):
./tlsprobe-linux-amd64 -impl stdlib

# E1, sing-box uTLS (fingerprint chrome) only:
./tlsprobe-linux-amd64 -impl singbox

# E1, both implementations, sequentially:
./tlsprobe-linux-amd64 -impl all
```

E2/E3 only with an explicit cookies-file flag pointing at YOUR OWN
`muse01` `cookies.txt`. There is no default path; without the flag the
probe refuses with exit 2 and reads nothing.

```sh
# Full chain, stdlib:
./tlsprobe-linux-amd64 -impl stdlib -stage all \
  -cookies-file ~/.config/muse-cli/profiles/muse01/cookies.txt

# Full chain, sing-box uTLS:
./tlsprobe-linux-amd64 -impl singbox -stage all \
  -cookies-file ~/.config/muse-cli/profiles/muse01/cookies.txt

# Full chain, both implementations:
./tlsprobe-linux-amd64 -impl all -stage all \
  -cookies-file ~/.config/muse-cli/profiles/muse01/cookies.txt
```

Proxy mode (only for a machine behind a TLS-intercepting egress
proxy, e.g. the hatch VM — NOT the decisive check):

```sh
./tlsprobe-linux-amd64 -impl all -use-proxy
./tlsprobe-linux-amd64 -impl all -stage all -use-proxy \
  -cookies-file ~/.config/muse-cli/profiles/muse01/cookies.txt
```

`-use-proxy` reads the proxy URL from the environment
(`HTTPS_PROXY`/`ALL_PROXY`/`HTTP_PROXY`) and honours `NO_PROXY`/
`no_proxy` exactly: if `NO_PROXY` covers the target host, the probe
reports that and refuses to dial rather than bypassing it. Only the
proxy host:port and the env var NAME are logged — never userinfo,
passwords, or proxy env values. `Proxy-Authorization` is sent only
inside the `CONNECT` request, never logged.

## Expected output

E1 pass, per host (stdlib; sing-box differs only in `negotiated_proto`):

```
IMPL=stdlib STAGES=E1 STAGE_TIMEOUT=20s PROXY=false
STAGE E1 host=muse.ai result=PASS tls_version=0x0304 cipher=0x1301 negotiated_proto="" handshake_complete=true peer_certs=2 verified_chains=1
STAGE E1 host=hatch.metaaivm.com result=PASS tls_version=0x0304 cipher=0x1301 negotiated_proto="" handshake_complete=true peer_certs=2 verified_chains=1
RESULT impl=stdlib E1=PASS
```

E2 pass (status codes and booleans only):

```
STAGE E2 step=api/session status=200 body_len=866 vm_id_obtained=true
STAGE E2 step=api/auth/check status=200 body_len=345 access_token_obtained=true
STAGE E2 step=api/hatch/token status=200 body_len=1518 hatch_token_obtained=true
STAGE E2 result=PASS session=PASS auth_check=PASS hatch_token=<redacted>
```

E3 pass (handshake only, closed immediately):

```
STAGE E3 ws_upgrade=PASS msg1_len=32 (expect 32)
STAGE E3 msg2_len=132 (expect 96)
STAGE E3 msg2_payload_len=36 (content never logged)
STAGE E3 msg3_len=64 (expect 64) handshake_finished=true
STAGE E3 result=PASS ws_url=wss://hatch.metaaivm.com/v1/noise?vm_id=[REDACTED]&auth_token=<redacted> handshake=PASS closed_immediately=true
RESULT PASS impl=stdlib E1=PASS E2=PASS E3=PASS
```

Exit codes: 0 = every stage attempted passed; 1 = a stage failed
(stage name in the output; later stages not attempted for that impl);
2 = usage/safety refusal (e.g. `-stage all` without `-cookies-file`,
cookies file not mode 0600, unknown `-impl`).

Notes on the numbers above (measured via the VM proxy run):

- `negotiated_proto`: stdlib offers no ALPN, so it is empty. The
  sing-box path pins ALPN to `http/1.1` only (the HTTP/WS paths are
  HTTP/1.1 upgrade); the uTLS fingerprint stays `HelloChrome_Auto` —
  only the ALPN list is pinned, because offering `h2` made the
  intercepting proxy negotiate `h2` and then reject HTTP/1.1 bytes.
- `msg2_len=132 (expect 96)`: the gateway sends a 36-byte Noise
  handshake payload in msg2 (96 = empty-payload XX msg2). Python's
  `gateway.py` discards the `read_message` return value, so the probe
  accepts any payload length and reports only its length. The payload
  content is never logged or used.
- `body_len` values are the observed response sizes on the VM run;
  yours may differ slightly. The status codes and booleans are what
  matter.

## Limitation — read this before interpreting results

The VM re-run went through a TLS-intercepting egress proxy, so it
CANNOT decide stdlib vs uTLS fingerprint: the proxy terminates TLS
and the real gateway never sees either ClientHello. Both
implementations passed E1/E2/E3 through the proxy, which proves the
tunnel/auth/Noise path works, but proves nothing about fingerprinting.

The decisive check is the DIRECT run above, on a machine with no
intercepting proxy:

- E1-singbox PASS + E1-stdlib FAIL (direct) → the gateway
  fingerprint-blocks plain Go TLS; the port needs uTLS.
- Both PASS (direct) → no fingerprint block at the TLS layer; stdlib
  would work, uTLS still preferred for parity with the Python client
  (curl_cffi chrome impersonation).
- Both FAIL (direct) → something else blocks the path; record the
  exact redacted error, do not work around it with
  `InsecureSkipVerify`.

## Safety rules for your run

1. ONLY `--profile muse01` cookies — never the default profile, never
   any other profile.
2. Before reading, verify the profile dir and that `cookies.txt` has
   mode 0600. The probe enforces the 0600 check itself and refuses
   (exit 2) otherwise; verify in the shell first anyway:
   `stat -c '%a %n' ~/.config/muse-cli/profiles/muse01/cookies.txt`.
3. Never print, copy, commit, upload, or paste any cookie, token,
   `auth_token`, private key, or password value. The probe never does;
   do not add any such logging.
4. Do not set `InsecureSkipVerify` to work around an
   unknown-authority error: record the exact error instead.
5. Bounded: 20 s stage timeout, monotonic deadlines, max 2 attempts
   per stage. If E1 fails for both implementations, stop — no other
   workaround.

## Source (`tools/tls-fingerprint/tlsprobe/`)

`main.go`, `go.mod`, `go.sum`, plus a copy of this README. Requires
Go >= 1.25.5. Verified to build from a clean copy in `/tmp` with the
default `GOPROXY` (`https://proxy.golang.org,direct`):

```sh
cd tools/tls-fingerprint/tlsprobe
go build -tags with_utls -o tlsprobe .
./tlsprobe -h
# or, without building:
go run -tags with_utls . -impl stdlib
```

The source contains no credential, cookie, or VM-absolute path.

## Echo mode: JA3/JA4 fingerprints (added 2026-10-29)

`-mode echo` prints the JA3/JA4 fingerprints a public TLS echo service
reports for each TLS implementation, with NO cookies, NO auth headers,
and NO Muse traffic. It exists so the operator can compare the stdlib
and uTLS ClientHello values from a direct dial, where the echo sees
this client's real ClientHello.

Default echo endpoint: `https://tls.peet.ws/api/all` (verified live
2026-10-29: response JSON contains `tls.ja3`, `tls.ja3_hash`,
`tls.ja4`, `tls.ja4_r`, `tls_version_negotiated`, offered ciphers and
extensions). Override with `-echo-url` (must be `https`, port 443).
The parser also accepts the flat shape of
`https://tls.browserleaks.com/json` (`ja3_hash`/`ja3_text`/`ja4`/
`ja4_r`). No new dependencies were added; the echo values are parsed
from the response, never computed locally. Direct dial is the default
and never consults proxy env vars in echo mode; `-use-proxy` reuses the
same CONNECT-tunnel code as the stages above.

### Commands (direct dial — the decisive run)

```sh
# Both implementations, direct dial, default echo endpoint:
./tlsprobe-linux-amd64 -mode echo -impl all

# One implementation only:
./tlsprobe-linux-amd64 -mode echo -impl stdlib
./tlsprobe-linux-amd64 -mode echo -impl singbox

# Alternative echo endpoint:
./tlsprobe-linux-amd64 -mode echo -impl all \
  -echo-url https://tls.browserleaks.com/json

# From source, without building (Go >= 1.25.5, from tools/tls-fingerprint/tlsprobe/):
go run -tags with_utls . -mode echo -impl all
go run -tags with_utls . -mode echo -impl singbox \
  -echo-url https://tls.browserleaks.com/json
```

### Commands (via the VM egress proxy — mechanical check only)

```sh
./tlsprobe-linux-amd64 -mode echo -impl all -use-proxy
```

### How to read the output

Per implementation, echo mode prints a handshake-state line (same
format as E1), then the fingerprint lines:

```
WARNING: echo mode reports the ClientHello the echo server saw. ...
IMPL=stdlib MODE=echo STAGE_TIMEOUT=20s PROXY=false
ECHO impl=stdlib handshake host=tls.peet.ws tls_version=0x0304 cipher=0x1301 negotiated_proto="http/1.1" ...
ECHO impl=stdlib ja3=771,...
ECHO impl=stdlib ja3_hash=<md5>
ECHO impl=stdlib ja4=t13d..._..._...
ECHO impl=stdlib ja4_r=t13d..._...
ECHO impl=stdlib tls_version_negotiated=772
ECHO impl=stdlib offered_ciphers=13 offered_extensions=11
ECHO impl=stdlib result=PASS body_len=7972
RESULT impl=stdlib ECHO=PASS
```

Compare `ja3`/`ja3_hash` and `ja4`/`ja4_r` between `impl=stdlib` and
`impl=singbox` from DIRECT runs. If they are identical, the gateway
cannot distinguish the two ClientHellos at the JA3/JA4 layer; if they
differ, the singbox (uTLS chrome) values are the ones to compare
against a real Chrome capture. `ja4_r` is the raw (unsorted, unhashed)
form — the most informative for spotting which extensions/ciphers
differ. ALPN is pinned to `http/1.1` for both implementations in this
probe (same as E1/E2/E3), so ALPN offers do not differ between impls
here.

### Proxy warning — read before interpreting any VM run

Every echo run prints a WARNING line. Through a TLS-intercepting
proxy, the echo server sees the PROXY's ClientHello, not this
client's, so VM echo values prove only that the mode works
mechanically. The decisive values come from the direct run above.
Additionally, the VM's intercepting proxy intermittently truncates
echo responses (observed: `unexpected EOF` / `EOF` on both echo hosts
and both implementations, passing on retry). A failed echo run on the
VM is NOT evidence about either TLS implementation — retry it, or
switch `-echo-url`, before concluding anything.

### Refusals (exit 2)

Echo mode refuses `-stage all` and any `-cookies-file`/`-cookies`
flag: it must never touch credentials. It also refuses non-`https`
echo URLs and non-443 ports. Exit 1 means the echo was unreachable or
returned no JA3/JA4 fields (message names the `-echo-url` fallback).
