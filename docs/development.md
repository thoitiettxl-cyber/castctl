# Development

## Go

Build and test from the repo root:

```sh
go build ./...
go vet ./...
go test -race -tags with_utls,with_quic,with_wireguard,with_gvisor ./...
```

The tagged race command above is canonical. The untagged suite is
fully green: without `with_utls`, 6 uTLS subtests skip by design
(see README.md for the build-tag table, the flake loop, and the
PR3 binary-size measurements).

CI: `.github/workflows/test.yaml` runs `go test -race` untagged and
with `with_utls` on pull requests and pushes to `main`; it does
not run the full canonical tag set. `.github/workflows/release.yaml`
builds the Linux amd64/arm64 release archives (glibc + `_no-plugin`)
on tag push and on `workflow_dispatch` (default: dry-run — builds
and gates only, publishes nothing). Release assets publish straight
to a public GitHub Release with `gh release upload`; the workflows
never use Actions artifact storage. See docs/architecture.md and
docs/provenance.md §2.

### Local reproduction of the glibc release build

Documented, NOT run here: Docker/podman/buildah are absent on the
VM where this PR was written, so the steps below were not executed
there. On a machine with Docker, from the repo root (Go version
from `go.mod`, currently `1.27.3`):

```sh
docker run --rm -v "$PWD:/src" -w /src \
  -e GO_VERSION="$(sed -n 's/^go \([0-9.]*\)$/\1/p' go.mod)" \
  quay.io/pypa/manylinux2014_x86_64 bash -euo pipefail -c '
    curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -o /tmp/go.tar.gz
    rm -rf /usr/local/go && tar -C /usr/local -xzf /tmp/go.tar.gz
    export PATH="/usr/local/go/bin:${PATH}"
    CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -buildvcs=false -trimpath \
      -tags with_utls,with_quic,with_wireguard,with_gvisor \
      -ldflags="-s -w -X github.com/thoitiettxl-cyber/castctl/internal/commands.Version=0.6.1" \
      -o /tmp/castctl ./cmd/castctl/
    readelf --version-info /tmp/castctl
  '
```

The GLIBC gate in the release workflow fails the build unless the
maximum `GLIBC_x.y` in the binary is 2.17 or older (and fails if no
GLIBC version is found at all). A local compile-only cross-build
without Docker does not prove the gate: the host toolchain's glibc
baseline differs from manylinux2014.

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
