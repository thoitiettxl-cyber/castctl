// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

use std::net::SocketAddr;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::Message as WsMessage;

/// A server that answers the Noise handshake with garbage:
/// it completes the WS upgrade, reads msg1, then sends the
/// given bytes as msg2 and closes. Used to prove a
/// truncated/empty/oversized msg2 is a `ConnectionError`,
/// never a hang or a panic.
pub struct BadMsg2Server {
    pub addr: SocketAddr,
    accept_task: JoinHandle<()>,
}

impl BadMsg2Server {
    pub async fn start(payload: Vec<u8>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accept_task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let payload = payload.clone();
                tokio::spawn(async move {
                    let mut ws = match tokio_tungstenite::accept_async(stream).await {
                        Ok(ws) => ws,
                        Err(_) => return,
                    };
                    let _ = ws.next().await;
                    let _ = ws.send(WsMessage::Binary(payload.into())).await;
                    let _ = ws.close(None).await;
                });
            }
        });
        BadMsg2Server { addr, accept_task }
    }

    pub fn ws_url(&self) -> String {
        format!("ws://{}/v1/noise", self.addr)
    }

    pub fn stop(self) {
        self.accept_task.abort();
    }
}

/// A WS server that accepts the upgrade but never answers
/// the Noise handshake (for the cancel-mid-handshake test).
pub struct BlackholeServer {
    pub addr: SocketAddr,
    accept_task: JoinHandle<()>,
}

impl BlackholeServer {
    pub async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accept_task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let Ok(ws) = tokio_tungstenite::accept_async(stream).await else {
                        return;
                    };
                    let (_w, mut r) = ws.split();
                    // Read msg1, then never reply.
                    let _ = r.next().await;
                    tokio::time::sleep(Duration::from_secs(3600)).await;
                });
            }
        });
        BlackholeServer { addr, accept_task }
    }

    pub fn ws_url(&self) -> String {
        format!(
            "ws://{}/v1/noise?vm_id=vm-test&auth_token=FAKE-TOKEN-123",
            self.addr
        )
    }

    pub fn stop(&self) {
        self.accept_task.abort();
    }
}
