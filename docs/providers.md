# Providers

## Sources

### Muse

Native login research is parked at `docs/research/native-login-bundle-analysis.md`; the primary phone paths are screencast login + `auth import`.

Session keep-alive is automatic: the keeper ticks the cheap
chain (GET `/api/session` → POST `/api/auth/check`), persists
rotated Set-Cookie values for every cookies-file format, wakes
the VM when the cheap chain is alive but the gateway handshake
fails, and — when a `credentials` entry is configured — re-logs
in headlessly against the versioned login contract
(`internal/keeper/testdata/login-contract.v1.json`, built by
read-only observation via `castctl auth observe-login`, never
by credential submission). Any contract mismatch, captcha, 2FA,
checkpoint, or lock stops the entry with one Telegram alert;
nothing is ever bypassed. **The contract is NOT yet
established**: the embedded fixture is unobserved (no
read-only observation has succeeded — the sandbox transport
intercept blocks the page load), so the driver refuses to run
and no live re-login may be attempted until an observation
from outside the sandbox intercept records the contract. See [The `keeper` section](config.md#the-keeper-section)
and [The `credentials` section](config.md#the-credentials-section).

Release-build note: the release workflow
(`.github/workflows/release.yaml`) builds with
`-tags with_utls,with_quic,with_wireguard,with_gvisor` and
does NOT include `with_chromedp`, so a release binary cannot
CDP re-export or headless re-login — it detects expiry and
alerts only. A local build with the `with_chromedp` tag set
from `scripts/e2e.sh` is required for the full loop.
