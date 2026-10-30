# Development

## Go

Build, test, release: local script only, no CI. From the repo root:

```sh
go build ./...
go vet ./...
go test -race -tags with_utls,with_quic,with_wireguard,with_gvisor ./...
```

The tagged race command above is canonical: an untagged
`go test ./internal/outbound/` fails 4 TLS subtests by design (uTLS
needs `with_utls`). See README.md for the build-tag table, the flake
loop, and the PR3 binary-size measurements. Release builds are a
separate PR (Linux amd64/arm64, `CGO_ENABLED=1`, GLIBC 2.17);
see docs/architecture.md.

## Web UI

Prerequisites: Bun 1.4.3, Node v24.

```sh
cd webui
bun install --frozen-lockfile   # pinned bun.lock is committed
bun run dev                     # Vite dev server, loopback only
bun run dev:mocks               # dev server + mock /api/v1 + flagged Login page
bun run test                    # vitest (i18n parity + diff)
bun run type-check              # tsc --noEmit
bun run lint                    # eslint
bun run build                   # tsc + vite build -> dist/index.html (production, mocks off)
bun run verify                  # test + lint + build
```

Rules:

- The committed `dist/index.html` is always the PRODUCTION build. Never
  commit a mocks-enabled build. Verify with:
  `grep -c CASTCTL_MOCK_FIXTURE webui/dist/index.html` (must be 0) and an
  external-reference audit (no `src=`/`href=`/`fetch(` URLs to other hosts).
- The dev server binds loopback only (`--host 127.0.0.1`). Remote access is
  via the Go server's `--listen` + token + HTTPS/tunnel, never by exposing
  the Vite dev server.
- Mock screenshots: `bun run dev:mocks`, open the printed loopback URL.
  Pages: `#/` (Dashboard), `#/profiles`, `#/profiles/muse01`,
  `#/outbounds`, `#/endpoints`, `#/config`, `#/logs`, `#/system`,
  `#/settings`, `#/login-browser` (flagged Login page — visible only with
  `dev:mocks`), `#/login` (token login). No backend is needed.
- i18n: English + Vietnamese only, key sets must match (`tests/i18n-parity.test.ts`).
  Add strings in both `src/i18n/locales/en.json` and `vi.json` together.
- Branding: `castctl` everywhere user-visible. No upstream branding in
  `src/` or `index.html` (NOTICE/history comments excluded).
- No hard-coded hosts/paths in `webui/src/` (loopback default + `--listen`
  only; no VM paths, no launcher references).
- After editing the fork, update `webui/NOTICE` if the kept/replaced
  balance changes, and this file + docs/architecture.md in the same PR.
