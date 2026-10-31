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
on tag push, on `workflow_dispatch` (default: dry-run — builds
and gates only, publishes nothing), and on pull requests targeting
`main` (builds and gates only, publish forced none). Release assets publish straight
to a public GitHub Release with `gh release upload`; the workflows
never use Actions artifact storage. See docs/architecture.md and
docs/provenance.md §2.

### Local reproduction of the glibc release build

Documented, NOT run here: Docker/podman/buildah are absent on the
VM where this PR was written, so the steps below were not executed
there. On a machine with Docker, from the repo root, the commands
below mirror `.github/workflows/release.yaml` (`build-linux-glibc`,
`linux-amd64` leg): the same environment variables, the same
stamping flags, the same stamping verification, the same `readelf`
guard, and the GLIBC gate copied from the workflow's inner script
— if the workflow gate changes, this block must change with it.
The version stamped here is a local placeholder, not a release
version:

```sh
TARGET="linux-amd64" GOARCH="amd64" \
  RELEASE_VERSION="0.0.0-local-$(git rev-parse --short HEAD)" \
  COMMIT="$(git rev-parse --short HEAD)" \
  BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  SOURCE_DATE_EPOCH="$(git log -1 --format=%ct HEAD)" \
  GO_VERSION="$(sed -n 's/^go \([0-9.]*\)$/\1/p' go.mod)"
rm -rf "dist/${TARGET}"
mkdir -p "dist/${TARGET}/archive"
docker run --rm -v "$PWD:/src" -w /src \
  -e TARGET -e GO_VERSION -e GOARCH -e RELEASE_VERSION -e COMMIT -e BUILD_DATE \
  quay.io/pypa/manylinux2014_x86_64 bash -euo pipefail -c '
    archive_dir="dist/${TARGET}/archive"
    go_archive="go${GO_VERSION}.linux-${GOARCH}.tar.gz"
    curl -fsSL "https://go.dev/dl/${go_archive}" -o "/tmp/${go_archive}"
    rm -rf /usr/local/go
    tar -C /usr/local -xzf "/tmp/${go_archive}"
    export PATH="/usr/local/go/bin:${PATH}"
    CGO_ENABLED=1 GOOS=linux GOARCH="${GOARCH}" go build -buildvcs=false -trimpath \
      -tags with_utls,with_quic,with_wireguard,with_gvisor \
      -ldflags="-s -w -X github.com/thoitiettxl-cyber/castctl/internal/commands.Version=${RELEASE_VERSION} -X github.com/thoitiettxl-cyber/castctl/internal/commands.Commit=${COMMIT} -X github.com/thoitiettxl-cyber/castctl/internal/commands.BuildDate=${BUILD_DATE}" \
      -o "$archive_dir/castctl" ./cmd/castctl/
    version_output="$("$archive_dir/castctl" --version)"
    if ! printf "%s\n" "${version_output}" | grep -Fq "castctl ${RELEASE_VERSION} (${COMMIT} "; then
      echo "stamping verification failed: got ${version_output}, expected castctl ${RELEASE_VERSION} (${COMMIT} ...)" >&2
      exit 1
    fi
    echo "stamping verified: ${version_output}"
    command -v readelf >/dev/null || { echo "readelf not found in container" >&2; exit 1; }
    glibc_versions="$(readelf --version-info "$archive_dir/castctl" | sed -n "s/.*Name: GLIBC_\([0-9.]*\).*/\1/p" | sort -Vu)"
    if [[ -z "${glibc_versions}" ]]; then
      echo "glibc gate: no GLIBC versions found in binary (expected a dynamic glibc link)" >&2
      exit 1
    fi
    printf "GLIBC versions:\n%s\n" "${glibc_versions}"
    max_glibc="$(printf "%s\n" "${glibc_versions}" | sort -V | tail -n 1)"
    if [[ "$(printf "2.17\n%s\n" "${max_glibc}" | sort -V | tail -n 1)" != "2.17" ]]; then
      printf "linux ${GOARCH} binary requires GLIBC_%s, expected GLIBC_2.17 or older\n" "${max_glibc}" >&2
      exit 1
    fi
  '
test -s LICENSE && test -s LICENSE.sing-box && test -s NOTICE && test -s README.md
cp LICENSE LICENSE.sing-box NOTICE README.md "dist/${TARGET}/archive/"
tar --sort=name --mtime="@${SOURCE_DATE_EPOCH}" --owner=0 --group=0 -C "dist/${TARGET}/archive" -czf "dist/castctl_${RELEASE_VERSION}_linux_amd64.tar.gz" castctl LICENSE LICENSE.sing-box NOTICE README.md
```

The GLIBC gate above fails the build unless the maximum `GLIBC_x.y`
in the binary is 2.17 or older (and fails if no GLIBC version is
found at all, or if `readelf` is absent). A local compile-only
cross-build without Docker does not prove the gate: the host
toolchain's glibc baseline differs from manylinux2014.

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
  via the Go server (`castctl webui serve`, loopback-only + token) reached
  through an SSH tunnel, never by exposing the Vite dev server and never
  by binding a non-loopback address.
- Mock screenshots: `bun run dev:mocks`, open the printed loopback URL.
  Pages: `#/` (Dashboard), `#/profiles`, `#/profiles/muse01`,
  `#/outbounds`, `#/endpoints`, `#/config`, `#/logs`, `#/system`,
  `#/settings`, `#/login-browser` (flagged Login page — visible only with
  `dev:mocks`), `#/login` (token login). No backend is needed.
- i18n: English + Vietnamese only, key sets must match (`tests/i18n-parity.test.ts`).
  Add strings in both `src/i18n/locales/en.json` and `vi.json` together.
- Branding: `castctl` everywhere user-visible. No upstream branding in
  `src/` or `index.html` (NOTICE/history comments excluded).
- No hard-coded hosts/paths in `webui/src/` (loopback default only; no VM
  paths, no launcher references).
- Run the real server with `castctl webui serve` (requires a `webui` block
  in config.json; token from `CASTCTL_WEBUI_KEY` or the block). The
  committed dist is built with `VITE_ENABLE_SCREENCAST_LOGIN=true` so the
  screencast page is observable; the page queries the server for
  availability first and reports unavailable without the `with_chromedp`
  build or a keeper entry for the profile.
- After editing the fork, update `webui/NOTICE` if the kept/replaced
  balance changes, and this file + docs/architecture.md in the same PR.
