# TLS fingerprint probes (scratch measurement tools, NOT shipped code)

These two probes exist so the TLS-engine decision for castctl can be made
from a direct dial on a machine whose egress is NOT TLS-intercepted. They
are measurement scratch, not product code, and must never be imported by
`go/` or shipped in a release. Source only on this branch: no binaries,
no `.so`, no cookies, no secrets.

Decision context (approved 2026-10-29): the castctl default stays `utls`
(chrome preset) on every platform. `cronet` is an opt-in build flavour
(tag `with_cronet` + sidecar `.so` with verified hash) for linux-glibc
and windows only, selected explicitly with `tls_engine: cronet`. The
default changes to platform-aware cronet only after this protocol shows
MATCH/CLOSE against real Chrome of the same version. WebSocket stays on
gorilla + uTLS. `random`/`randomized` presets are rejected. A missing
sidecar means exit 2, no silent fallback. PR3 stays storage-only.

## Contents

- `tlsprobe/` — stdlib `crypto/tls` vs sing-box uTLS (`chrome`) probe:
  E1 handshake, E2 auth chain (needs your own cookies, see its README),
  E3 Noise handshake-then-close, plus `-mode echo` (JA3/JA4 via a public
  echo service, no cookies, no auth, no Muse traffic). Full docs in
  `tlsprobe/README.md`.
- `cronetprobe/` — cronet-go (purego) echo probe: one GET to
  `https://tls.peet.ws/api/all` through `Engine.SetDialer`. As committed,
  its dialer performs a CONNECT tunnel through proxy env vars: that is
  the VM artifact and is PROXY-MASKED. For the decisive run you MUST
  replace it with the direct dialer in step 2 below and unset all proxy
  env vars. No cookies, no auth, no Muse traffic.

## Prerequisites

- Go >= 1.25.5 (tlsprobe was built with Go 1.27.3).
- For `cronetprobe`: a clone of `github.com/sagernet/cronet-go` at
  HEAD `049f2909701ca088c9569f6b303bba5376a2b2ff` (2026-09-12), placed as
  a SIBLING of this checkout (the `replace` in `cronetprobe/go.mod`
  points at `../cronet-go`):

```sh
git clone https://github.com/sagernet/cronet-go.git ../cronet-go
git -C ../cronet-go checkout 049f2909701ca088c9569f6b303bba5376a2b2ff
git -C ../cronet-go rev-parse HEAD   # must print the hash above
```

## Build commands (exact) and expected hashes

```sh
# tlsprobe — reproducible static build:
cd tools/tls-fingerprint/tlsprobe
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath \
  -ldflags '-s -w -buildid=' -tags with_utls -o tlsprobe-linux-amd64 .
sha256sum tlsprobe-linux-amd64
# expect: 5e0a2daac5e64acac46906e4cc945f58d707933cedb3357d802a97735be3e220
# size: 11,427,964 bytes. Go 1.27.3, sing-box v1.14.4, utls v1.8.7.
# The with_utls tag is REQUIRED: without it sing-box's uTLS client is a stub.

# cronetprobe — unmodified rebuild (proxy dialer, VM artifact only):
cd tools/tls-fingerprint/cronetprobe
CGO_ENABLED=0 go build -tags with_purego -trimpath \
  -ldflags '-s -w -buildid=' -o cronetprobe .
sha256sum cronetprobe
# expect: 456b2f1dda38fe398c69d31e5e57dde3f985d629d412404ed350b44256cbcedb
# size: 7,102,691 bytes. (The evaluation scratch build hashed
# f270cdd6d53e0f3b0e5165350b3543ec2827be2121ebd190c71035f758df228e:
# identical code, but its replace directive pointed at an absolute VM
# path; the build-info string differs. `go version -m` on either binary
# shows the only difference is that replace path.)
# NOTE: the DIRECT-dial build in step 2 changes the source, so its hash
# WILL differ. Verify a direct build with `go version -m` (cronet-go pin)
# and a successful echo run, and report the new hash alongside results.
```

## Decisive probe protocol (run on YOUR machine, direct dial, no proxy)

### Step 1 — tlsprobe echo (stdlib vs uTLS)

Verify the hash first (step above), then, with NO proxy env vars set:

```sh
./tlsprobe-linux-amd64 -mode echo -impl stdlib
./tlsprobe-linux-amd64 -mode echo -impl singbox
./tlsprobe-linux-amd64 -mode echo -impl all
# NEVER use -use-proxy here. Each command prints JA3/JA4/Akamai measured direct.
```

### Step 2 — cronet echo (direct dial)

Download the sidecar library and verify its hash (release
`v150.0.7871.63-2`, 2026-08-31):

```sh
gh release download v150.0.7871.63-2 -R sagernet/cronet-go \
  -p 'libcronet-linux-amd64.so' -D /tmp/cronet-eval/lib
sha256sum /tmp/cronet-eval/lib/libcronet-linux-amd64.so
# expect: c3949c6ad64e1d8fcd1e3b1fae4e302b2e553d769665a4bd7576483564c3f026
# size: 11,915,112 bytes
cp /tmp/cronet-eval/lib/libcronet-linux-amd64.so /tmp/cronet-eval/probe/libcronet.so
```

Modify `cronetprobe/main.go` for direct dial: ADD this function, and
change the `engine.SetDialer(connectDialer)` call to
`engine.SetDialer(directDialer)`. Do NOT delete `connectDialer`
(keeping it keeps the imports valid). Record every modification you make.
Unset ALL proxy env vars before building and running.

```go
func directDialer(address string, port uint16) int {
	host, ok := ipToHost[address]
	if !ok {
		fmt.Fprintf(os.Stderr, "DIALER: unknown address %s:%d (no hostname mapping)\n", address, port)
		return -104 // ERR_CONNECTION_FAILED
	}
	d := net.Dialer{Timeout: 20 * time.Second}
	c, err := d.Dial("tcp", net.JoinHostPort(host, fmt.Sprint(port)))
	if err != nil {
		fmt.Fprintln(os.Stderr, "DIALER: direct dial:", err)
		return -104
	}
	tcp, ok := c.(*net.TCPConn)
	if !ok {
		fmt.Fprintln(os.Stderr, "DIALER: conn is not *net.TCPConn")
		c.Close()
		return -104
	}
	f, err := tcp.File()
	if err != nil {
		fmt.Fprintln(os.Stderr, "DIALER: File():", err)
		c.Close()
		return -104
	}
	keptFiles = append(keptFiles, f)
	fmt.Fprintf(os.Stderr, "DIALER: %s:%d -> direct %s fd=%d\n", address, port, net.JoinHostPort(host, fmt.Sprint(port)), f.Fd())
	return int(f.Fd())
}
```

Then build and run (no proxy env), from a directory containing
`libcronet.so` next to the binary (purego loads it from the executable
directory):

```sh
cd tools/tls-fingerprint/cronetprobe
CGO_ENABLED=0 go build -tags with_purego -trimpath \
  -ldflags '-s -w -buildid=' -o cronetprobe .
cp cronetprobe /tmp/cronet-eval/probe/
cd /tmp/cronet-eval/probe && ./cronetprobe
```

### Step 3 — real Chrome, same version

Open `https://tls.peet.ws/api/all` in real Chrome (record the version,
e.g. 150.x), copy JA4 + JA4_r + Akamai + PeetPrint, and compare
field-by-field with steps 1–2.

Reference values (published sources, Chrome 127–148; 152–155 variant
noted): JA4 canonical `t13d1516h2_8daaf6152771_d8a2da3f94cd`;
152–155 variant `t13d1517h2_8daaf6152771_cb7bf5808d99`;
Akamai `1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p`, hash
`52d84b11737d980aef856699f885ca86`; PeetPrint hash
`1d4ffe9b0e34acac0bd883fa7f79d7b5`. Raw JA3 hashes rotate per
connection and are meaningless for comparison — compare JA4/JA4_r only.

Decision rule: JA4-C == Chrome (same version) AND Akamai == Chrome
→ MATCH; A+B ==, Akamai ==, only C differs → CLOSE (acceptable, record
it); anything else → DIFFER.

## Safety rules

1. Echo mode never touches credentials: it refuses `-stage all` and any
   cookies flag. E2/E3 only with YOUR OWN muse01 `cookies.txt`
   (mode 0600, enforced by the probe); never the default profile.
2. Never print, copy, commit, or paste any cookie, token, `auth_token`,
   or password value. These probes never log them; do not add logging
   that does.
3. Do not set `InsecureSkipVerify` to work around an unknown-authority
   error: record the exact error instead.
4. Label every VM/proxy-mediated value PROXY-MASKED. Only direct runs
   decide anything about fingerprinting.

## Report back

Per implementation (stdlib, uTLS, cronet) and real Chrome: JA4,
JA4_r, Akamai fingerprint + hash, PeetPrint hash, Chrome version, the
cronetprobe binary hash after your direct-dial modification, and any
modification you made to the committed sources. Full background,
measurements, and the [UNVERIFIED] list: the TLS-engine evaluation
report (kept outside this repo).
