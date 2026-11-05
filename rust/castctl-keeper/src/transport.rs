// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! The frozen screencast transport boundary — port of
//! `internal/keeper/transport.go`.
//!
//! The transport carries JPEG frames (one direction) and
//! input events (the other) between the browser and the
//! caller. It is a thin boundary on purpose: the runner
//! keeps no logic here, only the queue and the phase.
//!
//! The phases are a deliberate vocabulary: there is NO
//! timeout phase. A timeout shows up in the phase's
//! `detail` string, never as its own phase.
//!
//! The `Transport` trait is the frozen seam between the
//! login flow and the two consumers (the `auth login`
//! command's direct screencast and the web UI relay);
//! `wsTransport`/`sessionRegistry` (the relay side) belong
//! to M6b.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::sync::{Mutex, Notify, broadcast};

use crate::clock::CancelFlag;

/// The frame rate the screencast is started with
/// (`screencast.go:26-31`): JPEG quality 60, max 780x1400,
/// every frame.
pub const SCREENCAST_JPEG_QUALITY: i64 = 60;
/// Max screencast width.
pub const SCREENCAST_MAX_WIDTH: i32 = 780;
/// Max screencast height.
pub const SCREENCAST_MAX_HEIGHT: i32 = 1400;
/// Every Nth frame (1 = every frame).
pub const SCREENCAST_EVERY_NTH_FRAME: i32 = 1;

/// A phase in the login flow. The vocabulary is frozen:
/// `loading`, `ready`, `logged_in_detected`, `done`,
/// `failed`, `cancelled` — deliberately NO timeout phase
/// (`transport.go:27-33`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionPhase {
    Loading,
    Ready,
    LoggedInDetected,
    Done,
    Failed,
    Cancelled,
}

impl SessionPhase {
    pub fn as_str(&self) -> &'static str {
        match self {
            SessionPhase::Loading => "loading",
            SessionPhase::Ready => "ready",
            SessionPhase::LoggedInDetected => "logged_in_detected",
            SessionPhase::Done => "done",
            SessionPhase::Failed => "failed",
            SessionPhase::Cancelled => "cancelled",
        }
    }
}

/// One screencast frame: JPEG bytes, the CDP frame number
/// as the session id, and the dimensions the browser
/// reported (`transport.go:37-43`).
#[derive(Clone)]
pub struct Frame {
    /// Raw JPEG bytes.
    pub data: Vec<u8>,
    /// CDP screencast frame id.
    pub session_id: i32,
    /// Frame width in pixels.
    pub width: i32,
    /// Frame height in pixels.
    pub height: i32,
}

impl std::fmt::Debug for Frame {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Frame")
            .field("data_len", &self.data.len())
            .field("session_id", &self.session_id)
            .field("width", &self.width)
            .field("height", &self.height)
            .finish()
    }
}

/// What kind of input an event carries
/// (`transport.go:47-55`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputKind {
    Mouse,
    Key,
    Text,
    Done,
    Cancel,
}

impl InputKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            InputKind::Mouse => "mouse",
            InputKind::Key => "key",
            InputKind::Text => "text",
            InputKind::Done => "done",
            InputKind::Cancel => "cancel",
        }
    }
}

/// Modifier bitmask (`transport.go:60-65`): Alt=1, Ctrl=2,
/// Meta=4, Shift=8.
pub const MOD_ALT: u8 = 1;
/// Ctrl modifier.
pub const MOD_CTRL: u8 = 2;
/// Meta (Command/Windows) modifier.
pub const MOD_META: u8 = 4;
/// Shift modifier.
pub const MOD_SHIFT: u8 = 8;

/// One input event from the viewer (`transport.go:67-82`).
#[derive(Debug, Clone, PartialEq)]
pub struct InputEvent {
    pub kind: InputKind,
    /// Mouse event type (`mousePressed`, `mouseReleased`,
    /// `mouseMoved`, `mouseWheel`) or key event type
    /// (`keyDown`, `keyUp`, `rawKeyDown`, `char`).
    pub event_type: String,
    /// X coordinate in CSS pixels (mouse only).
    pub x: f64,
    /// Y coordinate in CSS pixels (mouse only).
    pub y: f64,
    /// Mouse button: `"left"`, `"middle"`, `"right"`,
    /// `"back"`, `"forward"`, or `"none"`.
    pub button: String,
    /// Click count (mouse only).
    pub click_count: i32,
    /// Scroll delta X (mouseWheel only).
    pub delta_x: f64,
    /// Scroll delta Y (mouseWheel only).
    pub delta_y: f64,
    /// Key code (key only).
    pub code: String,
    /// Key value (key only).
    pub key: String,
    /// Modifier bitmask (Alt=1, Ctrl=2, Meta=4, Shift=8).
    pub modifiers: u8,
    /// Text to insert (text only, from `char` events).
    pub text: String,
}

/// The frozen transport boundary (`transport.go:84-96`).
/// `send_frame` is latest-only: the transport keeps a
/// size-1 slot and overwrites a frame the consumer has not
/// read yet, so the producer never blocks. `send_phase`
/// carries a fixed detail string. `inputs` is the single
/// input stream; `done` closes when the session ends.
#[async_trait::async_trait]
pub trait Transport: Send + Sync {
    /// Send a frame (latest-only, never blocks).
    async fn send_frame(&self, frame: Frame);
    /// Send a phase change with a fixed detail string.
    async fn send_phase(&self, phase: SessionPhase, detail: &str);
    /// The single input stream.
    fn inputs(&self) -> broadcast::Receiver<InputEvent>;
    /// Closes when the session ends.
    fn done(&self) -> Arc<Notify>;
}

/// A fake transport for tests and for headless runs without
/// a viewer (`transport.go:99-159`): a size-1 frame slot,
/// a dropped-frame counter, buffered inputs, and the
/// recorded phase list.
pub struct FakeTransport {
    frame_slot: Mutex<Option<Frame>>,
    dropped: AtomicUsize,
    phases: Mutex<Vec<(SessionPhase, String)>>,
    input_tx: broadcast::Sender<InputEvent>,
    done_notify: Arc<Notify>,
    cancel: CancelFlag,
}

impl FakeTransport {
    pub fn new() -> Self {
        let (input_tx, _) = broadcast::channel(64);
        Self {
            frame_slot: Mutex::new(None),
            dropped: AtomicUsize::new(0),
            phases: Mutex::new(Vec::new()),
            input_tx,
            done_notify: Arc::new(Notify::new()),
            cancel: CancelFlag::new(),
        }
    }

    /// Number of frames dropped by the size-1 slot.
    pub fn dropped_count(&self) -> usize {
        self.dropped.load(Ordering::Relaxed)
    }

    /// The latest frame, if any.
    pub async fn latest_frame(&self) -> Option<Frame> {
        self.frame_slot.lock().await.clone()
    }

    /// The recorded phase list, in order.
    pub async fn phases(&self) -> Vec<(SessionPhase, String)> {
        self.phases.lock().await.clone()
    }

    /// Queue an input event for the runner to consume.
    pub fn push_input(&self, ev: InputEvent) {
        let _ = self.input_tx.send(ev);
    }

    /// The cancel flag the runner watches.
    pub fn cancel_flag(&self) -> CancelFlag {
        self.cancel.clone()
    }

    /// End the session (notify `done`).
    pub fn finish(&self) {
        self.done_notify.notify_waiters();
        self.cancel.cancel();
    }
}

impl Default for FakeTransport {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl Transport for FakeTransport {
    async fn send_frame(&self, frame: Frame) {
        let mut slot = self.frame_slot.lock().await;
        if slot.is_some() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
        *slot = Some(frame);
    }

    async fn send_phase(&self, phase: SessionPhase, detail: &str) {
        self.phases.lock().await.push((phase, detail.to_string()));
    }

    fn inputs(&self) -> broadcast::Receiver<InputEvent> {
        self.input_tx.subscribe()
    }

    fn done(&self) -> Arc<Notify> {
        self.done_notify.clone()
    }
}

/// A transport that refuses every frame (used when the
/// screencast feature is unavailable): frames are dropped
/// and counted, phases are recorded, inputs are empty.
pub struct RefusingTransport {
    inner: FakeTransport,
}

impl RefusingTransport {
    pub fn new() -> Self {
        Self {
            inner: FakeTransport::new(),
        }
    }
}

#[async_trait::async_trait]
impl Transport for RefusingTransport {
    async fn send_frame(&self, _frame: Frame) {
        self.inner.dropped.fetch_add(1, Ordering::Relaxed);
    }

    async fn send_phase(&self, phase: SessionPhase, detail: &str) {
        self.inner.send_phase(phase, detail).await;
    }

    fn inputs(&self) -> broadcast::Receiver<InputEvent> {
        self.inner.inputs()
    }

    fn done(&self) -> Arc<Notify> {
        self.inner.done()
    }
}

/// How long `send_phase` waits before giving up
/// (transport.go uses a bounded send; the exact bound is
/// internal to the runner, not the protocol).
pub const PHASE_SEND_TIMEOUT: Duration = Duration::from_secs(5);

/// Validate an input event against the allowlists
/// (`screencast.go:96-120`): mouse types
/// `{mousePressed, mouseReleased, mouseMoved, mouseWheel}`,
/// key types `{keyDown, keyUp, rawKeyDown, char}`. Returns
/// the normalised event or `None` when the event must be
/// dropped. An empty key is dropped; an empty button
/// becomes `"none"`; text is forwarded only for `char`.
pub fn validate_input_event(mut ev: InputEvent) -> Option<InputEvent> {
    match ev.kind {
        InputKind::Mouse => {
            if !matches!(
                ev.event_type.as_str(),
                "mousePressed" | "mouseReleased" | "mouseMoved" | "mouseWheel"
            ) {
                return None;
            }
            if ev.button.is_empty() {
                ev.button = "none".to_string();
            }
            Some(ev)
        }
        InputKind::Key => {
            if !matches!(
                ev.event_type.as_str(),
                "keyDown" | "keyUp" | "rawKeyDown" | "char"
            ) {
                return None;
            }
            if ev.key.is_empty() {
                return None;
            }
            Some(ev)
        }
        InputKind::Text => {
            if ev.text.is_empty() {
                return None;
            }
            Some(ev)
        }
        InputKind::Done | InputKind::Cancel => Some(ev),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn fake_transport_latest_only_counts_drops() {
        let t = FakeTransport::new();
        let f = |id: i32| Frame {
            data: vec![1, 2, 3],
            session_id: id,
            width: 780,
            height: 1400,
        };
        t.send_frame(f(1)).await;
        t.send_frame(f(2)).await;
        t.send_frame(f(3)).await;
        assert_eq!(t.dropped_count(), 2);
        assert_eq!(t.latest_frame().await.unwrap().session_id, 3);
        t.send_phase(SessionPhase::Ready, "ready").await;
        assert_eq!(
            t.phases().await,
            vec![(SessionPhase::Ready, "ready".to_string())]
        );
    }

    #[test]
    fn validate_input_event_allowlists() {
        let mouse = InputEvent {
            kind: InputKind::Mouse,
            event_type: "mousePressed".to_string(),
            x: 10.0,
            y: 20.0,
            button: String::new(),
            click_count: 1,
            delta_x: 0.0,
            delta_y: 0.0,
            code: String::new(),
            key: String::new(),
            modifiers: 0,
            text: String::new(),
        };
        let out = validate_input_event(mouse).expect("mousePressed allowed");
        assert_eq!(out.button, "none");
        let bad = InputEvent {
            kind: InputKind::Mouse,
            event_type: "mouseDoubleClick".to_string(),
            x: 0.0,
            y: 0.0,
            button: "left".to_string(),
            click_count: 0,
            delta_x: 0.0,
            delta_y: 0.0,
            code: String::new(),
            key: String::new(),
            modifiers: 0,
            text: String::new(),
        };
        assert!(validate_input_event(bad).is_none());
        let empty_key = InputEvent {
            kind: InputKind::Key,
            event_type: "keyDown".to_string(),
            x: 0.0,
            y: 0.0,
            button: String::new(),
            click_count: 0,
            delta_x: 0.0,
            delta_y: 0.0,
            code: "KeyA".to_string(),
            key: String::new(),
            modifiers: 0,
            text: String::new(),
        };
        assert!(validate_input_event(empty_key).is_none());
    }
}
