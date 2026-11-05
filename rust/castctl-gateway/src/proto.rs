// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Protobuf types for the gateway (M4a).
//!
//! Go sources: `internal/proto/generate/noise_transport.proto`
//! (package `ingress_rev_proxy`: 1 message, 4 proto3-optional
//! fields) and `internal/proto/generate/noise_envelope.proto`
//! (package `hatch.noise`: 8 messages, `ServiceType` + nested
//! `Reset.Code`). The Rust types are generated at build time by
//! `prost-build` from the committed descriptor binaries
//! (`internal/proto/desc0.bin` / `desc1.bin`) — see `build.rs`.
//! No `.proto` file is copied into `rust/`, no `protoc` is
//! needed, and no generated `.rs` file is committed.
//!
//! Naming note (prost 0.14.4, verified from the generated code):
//! `ServiceType` variants keep their `SERVICE_` prefix in
//! shortened form — `ServiceDaemon`, `ServiceSentinel`,
//! `ServiceVault`, `ServiceAuthd` — while `Reset.Code`
//! variants are `Unspecified`, `Cancelled`, … Wire values are
//! unchanged (0–3 / 0–6); only the Rust names differ from Go.
//! `ServiceRequest.service` is a plain `i32` in the generated
//! code, so callers convert through `service_type()` below.
//! `NoiseTransportFrame` fields are all `Option<T>` (proto3
//! optional presence is preserved: `Some(0)` encodes a tag,
//! `None` encodes nothing).

/// Package `hatch.noise` (`noise_envelope.proto`).
pub mod hatch {
    /// The envelope types.
    pub mod noise {
        include!(concat!(env!("OUT_DIR"), "/hatch.noise.rs"));
    }
}

/// Package `ingress_rev_proxy` (`noise_transport.proto`).
pub mod ingress_rev_proxy {
    include!(concat!(env!("OUT_DIR"), "/ingress_rev_proxy.rs"));
}

pub use hatch::noise::reset::Code as ResetCode;
pub use hatch::noise::service_frame::Kind as ServiceFrameKind;
pub use hatch::noise::{
    ApplicationRequest, ApplicationResponse, BodyChunk, Header, Reset, ServiceFrame,
    ServiceRequest, ServiceResponse, ServiceType,
};
pub use ingress_rev_proxy::NoiseTransportFrame;

/// Map a route `Service` (castctl-transport) to the prost
/// `ServiceType` value, mirroring Go
/// `internal/gateway/routes.go:20-32` `serviceID` (unknown or
/// absent → daemon).
pub fn service_type(service: castctl_transport::routes::Service) -> ServiceType {
    use castctl_transport::routes::Service;
    match service {
        Service::Sentinel => ServiceType::ServiceSentinel,
        Service::Vault => ServiceType::ServiceVault,
        Service::Authd => ServiceType::ServiceAuthd,
        Service::Daemon => ServiceType::ServiceDaemon,
    }
}
