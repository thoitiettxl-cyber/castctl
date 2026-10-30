# AGENTS.md — entry point

Read this first, then only the docs you need.

- Architecture & module layout: docs/architecture.md
- Config (config.json, --config, CASTCTL_CONFIG, XDG): docs/config.md
- Build, test, release (local script, no CI): docs/development.md
- Providers (sources: muse; publishers: facebook, tiktok, youtube): docs/providers.md
- Security rules: docs/security.md
- Provenance & upstream attribution: docs/provenance.md

Hard rules:
1. Never print, log or commit secrets (cookies, tokens, WireGuard keys).
2. All network traffic of a profile goes through that profile's outbound.
3. Never bypass captcha/2FA; the user enters codes.
4. Work on branches, open PRs; main is protected. Tags v* are admin-only.
5. Update the matching docs/* file in the same PR as the code.
6. When porting new behavior from an upstream, update `docs/provenance.md` and `NOTICE` in the same PR.
