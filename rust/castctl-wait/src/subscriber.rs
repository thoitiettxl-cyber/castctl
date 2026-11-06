// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Production [`Subscriber`] implementations over the
//! gateway (Go `conn.Gateway` satisfies `wait.Subscriber`;
//! `SharedConn` wraps it with the 3-attempt subscribe
//! retry). Which one the CLI dials is decided at wiring
//! time against `internal/commands/wait.go` (see
//! `docs/`); both are provided here.
//!
//! The impls are on the bare types (`Gateway`,
//! `SharedConn`), not on `Arc<..>`: the
//! `gateway_subscriber` / `shared_subscriber` helpers
//! coerce `Arc<Gateway>` → `Arc<dyn Subscriber>` by
//! unsize, which requires the INNER type to implement
//! the trait. (An earlier draft implemented the trait
//! for `Arc<..>` and the coercion failed to compile.)

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use castctl_gateway::subscribe::{SubscribeHandler, SubscribeOptions};
use castctl_gateway::{Gateway, SharedConn};
use castctl_transport::TransportError;

use crate::runner::Subscriber;

impl Subscriber for Gateway {
    fn subscribe_raw<'a>(
        &'a self,
        method: &'a str,
        opts: SubscribeOptions,
        handler: &'a mut dyn SubscribeHandler,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Vec<u8>>, TransportError>> + Send + 'a>> {
        // Inherent `Gateway::subscribe_raw` takes
        // precedence over this trait method in
        // resolution; there is no recursion here.
        Box::pin(async move { self.subscribe_raw(method, opts, handler).await })
    }

    fn close(&self) -> Pin<Box<dyn Future<Output = Result<(), TransportError>> + Send + '_>> {
        Box::pin(async move {
            self.close().await;
            Ok(())
        })
    }
}

impl Subscriber for SharedConn {
    fn subscribe_raw<'a>(
        &'a self,
        method: &'a str,
        opts: SubscribeOptions,
        handler: &'a mut dyn SubscribeHandler,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Vec<u8>>, TransportError>> + Send + 'a>> {
        // Inherent `SharedConn::subscribe_raw` takes
        // precedence over this trait method in
        // resolution; there is no recursion here.
        Box::pin(async move { self.subscribe_raw(method, opts, handler).await })
    }

    fn close(&self) -> Pin<Box<dyn Future<Output = Result<(), TransportError>> + Send + '_>> {
        // Go: `SharedConn.Close` is a no-op, so closing a
        // shared connection is safe.
        Box::pin(async move { Ok(()) })
    }
}

/// Wrap a direct gateway as the Runner's [`Subscriber`].
#[must_use]
pub fn gateway_subscriber(gw: Arc<Gateway>) -> Arc<dyn Subscriber> {
    gw as Arc<dyn Subscriber>
}

/// Wrap a shared connection as the Runner's [`Subscriber`].
#[must_use]
pub fn shared_subscriber(conn: Arc<SharedConn>) -> Arc<dyn Subscriber> {
    conn as Arc<dyn Subscriber>
}
