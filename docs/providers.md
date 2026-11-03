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
nothing is ever bypassed. **The contract is established**:
the embedded fixture was recorded 2026-11-03 by the
read-only observation `castctl auth observe-login`
(headless, through the S2 profile-routed inbound; nothing
entered or submitted). It covers the first screen only —
the identifier field plus Continue — with structural
selectors (the page exposes no id or name on either
control). The code-challenge screen is not recorded:
reaching it requires submitting, which the observer never
does, so after Continue the driver waits for session
cookies and fails closed at the cookie timeout when the
provider challenges with a code. Re-observe (and update
the fixture and its pinning test) whenever the login page
changes. See [The `keeper` section](config.md#the-keeper-section)
and [The `credentials` section](config.md#the-credentials-section).

Release-build note: the release workflow
(`.github/workflows/release.yaml`) builds with
`-tags with_utls,with_quic,with_wireguard,with_gvisor` and
does NOT include `with_chromedp`, so a release binary cannot
CDP re-export or headless re-login — it detects expiry and
alerts only. A local build with the `with_chromedp` tag set
from `scripts/e2e.sh` is required for the full loop.
