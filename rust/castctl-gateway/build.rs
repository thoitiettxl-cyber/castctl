// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Codegen for the gateway protobuf types (M4a, option (c)).
//!
//! The generated Rust types come from the repo's own committed
//! `FileDescriptorProto` binaries — `internal/proto/desc0.bin`
//! (noise_transport.proto) and `internal/proto/desc1.bin`
//! (noise_envelope.proto) — via `prost_build::Config::compile_fds`,
//! which does NOT invoke `protoc` (there is none on cue, and the Go
//! side already removed protoc on purpose: see
//! `internal/proto/generate/README.md`). The descriptors are the
//! single source of truth: the `.proto` files in
//! `internal/proto/generate/` are themselves recreated from these
//! bins, so Rust and Go generate from the same bytes.
//!
//! Regeneration when the proto changes: edit the `.proto` in
//! `internal/proto/generate/`, run its `./generate.sh`
//! (protocompile, pure Go, no protoc), commit the new `desc*.bin`,
//! and the next Rust build regenerates (`cargo:rerun-if-changed`
//! below). No committed generated `.rs` file, no drift check needed.

use std::path::PathBuf;

use prost::Message;
use prost_types::{FileDescriptorProto, FileDescriptorSet};

fn main() {
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    // Crate root rust/castctl-gateway -> repo root is two levels up.
    let repo = manifest
        .parent()
        .and_then(|p| p.parent())
        .unwrap()
        .to_path_buf();
    let desc0_path = repo.join("internal/proto/desc0.bin");
    let desc1_path = repo.join("internal/proto/desc1.bin");
    println!("cargo:rerun-if-changed={}", desc0_path.display());
    println!("cargo:rerun-if-changed={}", desc1_path.display());
    println!("cargo:rerun-if-changed=build.rs");

    let desc0 =
        FileDescriptorProto::decode(std::fs::read(&desc0_path).unwrap().as_slice()).unwrap();
    let desc1 =
        FileDescriptorProto::decode(std::fs::read(&desc1_path).unwrap().as_slice()).unwrap();
    let fds = FileDescriptorSet {
        file: vec![desc0, desc1],
    };
    prost_build::Config::new().compile_fds(fds).unwrap();
}
