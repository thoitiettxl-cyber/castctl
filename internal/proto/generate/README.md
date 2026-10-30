# Generation route for internal/proto

## Sources

`noise_transport.proto` and `noise_envelope.proto` are recreated from the
verified `FileDescriptorProto` binaries the Python package loads at runtime
(`desc0.bin` / `desc1.bin`, embedded verbatim in the parent directory).
The original descriptors have no `go_package` option and empty `json_name`
fields; the `.proto` files here add only the `go_package` option (so
`protoc-gen-go` can generate code) and let the compiler fill in the
derived `json_name` values. Names, numbers, types, labels,
`proto3_optional` flags, oneofs, enums, packages, and syntax are otherwise
identical to the originals — see the descriptor-equality test in
`../proto_test.go`, which compares the generated descriptors against the
embedded bins after normalising away exactly those two differences.

Verified descriptor facts (do not reintroduce the planner's shortened
names):

- `noise_transport.proto`, package `ingress_rev_proxy`:
  `NoiseTransportFrame` — `chunk_id` 1 int64, `chunk_index` 2 uint32,
  `total_chunks` 3 uint32, `payload` 4 bytes, all four `optional`
  (four separate oneofs → pointer fields in Go).
- `noise_envelope.proto`, package `hatch.noise`: `ServiceRequest`,
  `ServiceResponse`, `ServiceFrame` (oneof `kind`: `request` /
  `response` / `body_chunk` / `reset`), `Header`, `ApplicationRequest`,
  `ApplicationResponse`, `BodyChunk`, `Reset`. Enum `ServiceType`:
  `SERVICE_DAEMON` 0, `SERVICE_SENTINEL` 1, `SERVICE_VAULT` 2,
  `SERVICE_AUTHD` 3. Nested enum `Reset.Code`: `CODE_UNSPECIFIED` 0,
  `CANCELLED` 1, `TIMEOUT` 2, `PROTOCOL_ERROR` 3, `REFUSED_STREAM` 4,
  `INTERNAL_ERROR` 5, `SERVICE_UNAVAILABLE` 6.

## Toolchain

- `protocompile` v0.14.1 (pure Go; no `protoc` or `buf` binary needed).
- `protoc-gen-go` v1.36.12 (real plugin binary, invoked via the plugin
  protocol by `compile.go`).
- Runtime in the main module: `google.golang.org/protobuf` — the
  generated code was produced with v1.36.12. The main `go.mod` still
  pins v1.36.11 (indirect); promoting it to v1.36.12 as a direct
  dependency is the job of the `go.mod` owner (W-update), not this
  package — see the report for the exact command. The generated code
  compiles and passes the golden tests against v1.36.11 on this VM;
  the promotion is for exact generator/runtime parity, not a
  compile requirement observed here.

## Regenerate

```sh
cd go/internal/proto/generate
./generate.sh [PATH-TO-protoc-gen-go]
```

`generate.sh` copies this directory to a clean directory under `/tmp`,
builds `compile.go` there (this directory is a nested module with its
own `go.mod`/`go.sum`, so the main module's `go.mod`/`go.sum` are never
touched), runs the generation, and copies only the two `.pb.go` files
back. It reuses the PR0 `protoc-gen-go` binary when present, then a
`protoc-gen-go` on `PATH`, and otherwise builds v1.36.12 with
`go install` into a temp dir. The compiled `FileDescriptorProto`
binaries it writes are comparison evidence only and are not committed;
the committed `desc0.bin`/`desc1.bin` in the parent directory are the
original Python copies, byte-identical (sha256-pinned by test).

Never hand-edit the `.pb.go` files: every message and enum must come
from the generator.

## SPDX header on generated files

The committed `.pb.go` files carry the same SPDX header as every other
`.go` file under `go/`:

```text
// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.
```

`protoc-gen-go` does not emit that header, so `generate.sh` injects
it deterministically into the two copied-back files on every
regeneration (idempotently: a file already starting with the header
is left untouched), before the `gofmt` check. `go/spdx_test.go`
enforces the header on every `.go` file including the generated
ones, with no exemption — if a regeneration drops the header, the
suite fails by design. Do not hand-edit a `.pb.go` file to add or
restore the header; re-run `generate.sh` instead.
