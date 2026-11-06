// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Live loader tests (M6c-b + fix loops 1–2): the real
//! `.so` loader against REAL plugins built at test time
//! with `go` (`-buildmode=c-shared`). These are the
//! mandated crash-isolation tests plus the fix-loop-1
//! protocol tests (B1–B7, G1–G7) and the fix-loop-2
//! fuse tests (NB1); they run ONLY where a Go toolchain
//! and a C compiler exist (cue). A missing Go toolchain
//! still SKIPs with a loud `eprintln!` (not silent) —
//! but a missing `castctl-rs` binary FAILS the
//! CLI-level tests (fix loop 2, technical N5 /
//! red-team N10): in a full workspace build the binary
//! always exists, so its absence means the test setup
//! is broken, not that the check does not apply.
//!
//! Test plugins live in a scratch dir under the system
//! temp dir, never under `examples/**` (a /tmp plugin
//! cannot import `internal/pluginabi`, so the ABI
//! structs are inlined in the generated Go source).
//! The real `examples/plugin/echo` is built in the
//! worktree for test 1 (the Go comparison) and as the
//! control load for every other test.
//!
//! Every test asserts: the expected Result, the test
//! process exits 0 (a test returning at all), and a
//! follow-up control call (fresh echo load,
//! `provider.call {"input":"ping"}` -> `echo:ping`)
//! succeeds — proving the host survived whatever the
//! plugin did.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use castctl_pluginhost::error::PluginHostError;
use castctl_pluginhost::host::{Desired, Host, Options};

/// Serialises the live tests inside this binary.
/// They share one per-process shadow root
/// (`/tmp/castctl-pluginhost/pid-<pid>/`), and
/// `Host::close` removes that whole directory —
/// so a test closing its host while another test
/// is mid-`shadow_copy` fails the copy with
/// "move shadow plugin" (pre-existing race, R3:
/// shared shadow-root test-isolation race; the
/// same-tag control loads also share one shadow
/// target). The tests still run under plain
/// `cargo test --workspace`; they just do not run
/// concurrently with each other. The assertions
/// are unchanged — this is scheduling, not a
/// weaker test.
static LIVE_LOCK: Mutex<()> = Mutex::new(());
use castctl_pluginhost::loader::WorkerLoader;
use castctl_pluginhost::pluginabi::METHOD_PROVIDER_CALL;

/// The worker binary cargo builds for this package.
fn worker_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_castctl-plugin-worker"))
}

fn go_bin() -> String {
    std::env::var("CASTCTL_TEST_GO").unwrap_or_else(|_| "go".to_string())
}

fn go_available() -> bool {
    std::process::Command::new(go_bin())
        .arg("version")
        .env("GOTOOLCHAIN", "auto")
        .output()
        .is_ok_and(|o| o.status.success())
}

/// Scratch dir for one test's generated sources and
/// built `.so` files (system temp dir, never the repo).
fn scratch_dir(name: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("castctl-loader-live-{}-{name}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    dir
}

static BUILD_LOCK: Mutex<()> = Mutex::new(());

/// Run `go build` for one generated plugin; `None` =
/// skip (go/gcc absent — the build failure names the
/// missing C compiler). Any other build failure is a
/// test failure, never a silent skip.
fn build_plugin(name: &str, source: &str) -> Option<PathBuf> {
    let _guard = BUILD_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let dir = scratch_dir(name);
    let so = dir.join(format!("{name}.so"));
    if so.exists() {
        return Some(so);
    }
    if !go_available() {
        eprintln!(
            "SKIP {name}: no Go toolchain (CASTCTL_TEST_GO={})",
            go_bin()
        );
        return None;
    }
    let src = dir.join("main.go");
    if std::fs::write(&src, source).is_err() {
        panic!("cannot write {src:?}");
    }
    if !dir.join("go.mod").exists()
        && std::fs::write(dir.join("go.mod"), "module loaderlive\n\ngo 1.24\n").is_err()
    {
        panic!("cannot write go.mod in {dir:?}");
    }
    let out = std::process::Command::new(go_bin())
        .args(["build", "-buildmode=c-shared", "-o"])
        .arg(&so)
        .arg(".")
        .current_dir(&dir)
        .env("GOTOOLCHAIN", "auto")
        .env("CGO_ENABLED", "1")
        .output();
    match out {
        Ok(o) if o.status.success() => Some(so),
        Ok(o) => {
            let err = String::from_utf8_lossy(&o.stderr);
            if err.contains("executable file not found")
                || err.contains("gcc: not found")
                || err.contains("C compiler")
            {
                eprintln!("SKIP {name}: no C compiler for cgo: {err}");
                None
            } else {
                panic!("go build {name} failed: {err}");
            }
        }
        Err(e) => panic!("cannot run go: {e}"),
    }
}

/// Build a `.so` from raw Go source that does NOT use
/// the plugin template (e.g. no `castctl_plugin_init`
/// symbol at all). Same skip rules as `build_plugin`.
fn build_raw_plugin(name: &str, source: &str) -> Option<PathBuf> {
    build_plugin(name, source)
}

/// Build the real `examples/plugin/echo` in the
/// worktree (module context required: it imports
/// `internal/pluginabi`); `None` = skip.
fn build_echo() -> Option<PathBuf> {
    let _guard = BUILD_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let dir = scratch_dir("echo");
    let so = dir.join("echo.so");
    if so.exists() {
        return Some(so);
    }
    if !go_available() {
        eprintln!("SKIP echo: no Go toolchain (CASTCTL_TEST_GO={})", go_bin());
        return None;
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let out = std::process::Command::new(go_bin())
        .args([
            "build",
            "-buildmode=c-shared",
            "-o",
            so.to_str().unwrap_or_default(),
            "./examples/plugin/echo",
        ])
        .current_dir(&root)
        .env("GOTOOLCHAIN", "auto")
        .env("CGO_ENABLED", "1")
        .output();
    match out {
        Ok(o) if o.status.success() => Some(so),
        Ok(o) => {
            let err = String::from_utf8_lossy(&o.stderr);
            if err.contains("executable file not found")
                || err.contains("gcc: not found")
                || err.contains("C compiler")
            {
                eprintln!("SKIP echo: no C compiler for cgo: {err}");
                None
            } else {
                panic!("go build echo failed: {err}");
            }
        }
        Err(e) => panic!("cannot run go: {e}"),
    }
}

/// The `castctl-rs` binary cargo builds for the
/// workspace (`target/debug/castctl-rs`, or
/// `$CARGO_TARGET_DIR/debug/castctl-rs`); `None` =
/// the binary is absent, and the CLI-level tests
/// FAIL on that (fix loop 2, technical N5) — the
/// binary is only absent outside a full workspace
/// build, which means the test setup is broken.
fn castctl_rs_bin() -> Option<PathBuf> {
    let target = std::env::var("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target"));
    let bin = target.join("debug/castctl-rs");
    if bin.is_file() {
        Some(bin)
    } else {
        eprintln!("SKIP CLI check: no castctl-rs binary at {}", bin.display());
        None
    }
}

/// The Go `castctl` binary built from this worktree
/// (`./cmd/castctl`); cached in the scratch dir.
/// `None` = skip (no Go toolchain).
fn go_castctl_bin() -> Option<PathBuf> {
    let _guard = BUILD_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let dir = scratch_dir("gocheck");
    let out = dir.join("castctl-go");
    if out.exists() {
        return Some(out);
    }
    if !go_available() {
        eprintln!(
            "SKIP gocheck: no Go toolchain (CASTCTL_TEST_GO={})",
            go_bin()
        );
        return None;
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let built = std::process::Command::new(go_bin())
        .args(["build", "-o"])
        .arg(&out)
        .arg("./cmd/castctl")
        .current_dir(&root)
        .env("GOTOOLCHAIN", "auto")
        .env("CGO_ENABLED", "1")
        .output();
    match built {
        Ok(o) if o.status.success() => Some(out),
        Ok(o) => panic!(
            "go build castctl failed: {}",
            String::from_utf8_lossy(&o.stderr)
        ),
        Err(e) => panic!("cannot run go: {e}"),
    }
}

/// Run `plugin check <so>` with one binary; returns
/// `(exit code, stdout, stderr)`.
fn run_plugin_check(bin: &Path, so: &Path) -> (i32, String, String) {
    let out = std::process::Command::new(bin)
        .args(["plugin", "check"])
        .arg(so)
        .env_remove("CASTCTL_PLUGIN_WORKER_BIN")
        .output()
        .unwrap_or_else(|e| panic!("cannot run {}: {e}", bin.display()));
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Pids of `__plugin-worker` processes parented to
/// this test process (Linux `/proc` scan). Used to
/// prove no worker lingers after a failed load and
/// that a worker dies with its parent (B7).
fn worker_pids() -> Vec<u32> {
    let me = std::process::id();
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return out;
    };
    for e in entries.flatten() {
        let pid: u32 = match e.file_name().to_str().and_then(|s| s.parse().ok()) {
            Some(p) => p,
            None => continue,
        };
        let stat = match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
            Ok(s) => s,
            Err(_) => continue,
        };
        // `comm` is parenthesised and may contain
        // spaces: the ppid follows the last `)`.
        let after = match stat.rfind(')') {
            Some(i) => &stat[i + 2..],
            None => continue,
        };
        let ppid: u32 = match after.split_whitespace().nth(1).and_then(|s| s.parse().ok()) {
            Some(p) => p,
            None => continue,
        };
        if ppid != me {
            continue;
        }
        let cmdline = std::fs::read(format!("/proc/{pid}/cmdline")).unwrap_or_default();
        if cmdline
            .windows(b"__plugin-worker".len())
            .any(|w| w == b"__plugin-worker")
        {
            out.push(pid);
        }
    }
    out
}

/// Pids of `__plugin-worker` processes parented to
/// `parent` (same `/proc` scan as `worker_pids`, for
/// an arbitrary parent pid — the B7 helper parent).
fn worker_pids_of(parent: u32) -> Vec<u32> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return out;
    };
    for e in entries.flatten() {
        let pid: u32 = match e.file_name().to_str().and_then(|s| s.parse().ok()) {
            Some(p) => p,
            None => continue,
        };
        let stat = match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let after = match stat.rfind(')') {
            Some(i) => &stat[i + 2..],
            None => continue,
        };
        let ppid: u32 = match after.split_whitespace().nth(1).and_then(|s| s.parse().ok()) {
            Some(p) => p,
            None => continue,
        };
        if ppid != parent {
            continue;
        }
        let cmdline = std::fs::read(format!("/proc/{pid}/cmdline")).unwrap_or_default();
        if cmdline
            .windows(b"__plugin-worker".len())
            .any(|w| w == b"__plugin-worker")
        {
            out.push(pid);
        }
    }
    out
}

/// One generated test plugin. The ABI structs are
/// inlined (a /tmp plugin cannot import
/// `internal/pluginabi`); `__CALL_BODY__`,
/// `__INIT_BODY__`, `__INIT_TAIL__`,
/// `__SHUTDOWN_BODY__`, `__FREE_BODY__` and
/// `__REGISTER_LOG__` are substituted per behavior.
//
// 9 args is deliberate: one named slot per template
// placeholder; a struct would only rename the same
// list. Test-only builder, never called in prod.
#[allow(clippy::too_many_arguments)]
fn plugin_source_full(
    name: &str,
    abi: u32,
    init_rc: i32,
    call_body: &str,
    init_body: &str,
    init_tail: &str,
    shutdown_body: &str,
    free_body: &str,
    register_log: &str,
) -> String {
    const TEMPLATE: &str = r#"package main

/*
#include <stdint.h>
#include <stdlib.h>

typedef struct { void* ptr; size_t len; } castctl_buffer;
typedef int (*castctl_host_call_fn)(void*, const char*, const uint8_t*, size_t, castctl_buffer*);
typedef void (*castctl_host_free_fn)(void*, size_t);
typedef struct { uint32_t abi_version; void* host_ctx; castctl_host_call_fn call; castctl_host_free_fn free_buffer; } castctl_host_api;
typedef int (*castctl_plugin_call_fn)(const char*, const uint8_t*, size_t, castctl_buffer*);
typedef void (*castctl_plugin_free_fn)(void*, size_t);
typedef void (*castctl_plugin_shutdown_fn)(void);
typedef struct { uint32_t abi_version; castctl_plugin_call_fn call; castctl_plugin_free_fn free_buffer; castctl_plugin_shutdown_fn shutdown; } castctl_plugin_api;

static void crash_now(void) { *(volatile int*)0 = 0; }
static int call_host_fn(castctl_host_call_fn fn, void* ctx, const char* method, const uint8_t* req, size_t len, castctl_buffer* out) { return fn(ctx, method, req, len, out); }
static void free_host_fn(castctl_host_free_fn fn, void* ptr, size_t len) { fn(ptr, len); }
// The //exported Go callbacks, declared so Go code can
// take their addresses as C function pointers (a bare
// C.pluginCall does NOT resolve: cgo only knows names
// declared in the preamble). No `const` qualifiers:
// cgo's generated definitions use plain `char*` /
// `uint8_t*`, and a `const` mismatch is a conflicting
// type.
extern int pluginCall(char*, uint8_t*, size_t, castctl_buffer*);
extern void pluginFree(void*, size_t);
extern void pluginShutdown(void);
*/
import "C"

import (
	"encoding/binary"
	"encoding/json"
	"os"
	"time"
	"unsafe"
)

var _ = os.Args
var _ = time.Second
var _ = binary.BigEndian

var hostAPI *C.castctl_host_api

func allocResp(b []byte) C.castctl_buffer {
	if len(b) == 0 {
		return C.castctl_buffer{ptr: nil, len: 0}
	}
	p := C.malloc(C.size_t(len(b)))
	copy((*[1 << 30]byte)(p)[:len(b)], b)
	return C.castctl_buffer{ptr: p, len: C.size_t(len(b))}
}

func envelope(result json.RawMessage) []byte {
	env, _ := json.Marshal(map[string]json.RawMessage{"ok": json.RawMessage("true"), "result": result})
	return env
}

func errEnvelope(code, msg string) []byte {
	env, _ := json.Marshal(map[string]any{"ok": false, "error": map[string]string{"code": code, "message": msg}})
	return env
}

// logLine calls host.log once; the reply envelope is
// freed via the host's free_buffer. Used by the
// multi-log / background / flood bodies.
func logLine(msg string) C.int {
	logReq := []byte(`{"level":"info","message":"` + msg + `"}`)
	methodC := C.CString("host.log")
	defer C.free(unsafe.Pointer(methodC))
	var out C.castctl_buffer
	rc := C.call_host_fn(hostAPI.call, hostAPI.host_ctx, methodC, (*C.uint8_t)(unsafe.Pointer(&logReq[0])), C.size_t(len(logReq)), &out)
	if out.ptr != nil {
		C.free_host_fn(hostAPI.free_buffer, out.ptr, out.len)
	}
	return rc
}

//export pluginCall
func pluginCall(method *C.char, req *C.uint8_t, reqLen C.size_t, resp *C.castctl_buffer) C.int {
	m := C.GoString(method)
	if m == "plugin.register" {
__REGISTER_LOG__
		reg, _ := json.Marshal(map[string]any{
			"schema_version": 1,
			"metadata":       map[string]string{"name": "__NAME__", "version": "0.1.0", "author": "castctl"},
			"capabilities":   map[string]bool{"provider": true},
		})
		*resp = allocResp(envelope(reg))
		return 0
	}
	if m != "provider.call" {
		*resp = allocResp(errEnvelope("unsupported_method", "unsupported method "+m))
		return 0
	}
__CALL_BODY__
}

//export pluginFree
func pluginFree(ptr unsafe.Pointer, length C.size_t) {
__FREE_BODY__
}

//export pluginShutdown
func pluginShutdown() {
__SHUTDOWN_BODY__
}

//export castctl_plugin_init
func castctl_plugin_init(host *C.castctl_host_api, plugin *C.castctl_plugin_api) C.int {
__INIT_BODY__
	hostAPI = host
	plugin.abi_version = C.uint32_t(__ABI__)
	plugin.call = (C.castctl_plugin_call_fn)(C.pluginCall)
	plugin.free_buffer = (C.castctl_plugin_free_fn)(C.pluginFree)
	plugin.shutdown = (C.castctl_plugin_shutdown_fn)(C.pluginShutdown)
__INIT_TAIL__
	return C.int(__INIT_RC__)
}

func main() {}
"#;
    TEMPLATE
        .replace("__NAME__", name)
        .replace("__ABI__", &abi.to_string())
        .replace("__INIT_RC__", &init_rc.to_string())
        .replace("__CALL_BODY__", call_body)
        .replace("__INIT_BODY__", init_body)
        .replace("__INIT_TAIL__", init_tail)
        .replace("__SHUTDOWN_BODY__", shutdown_body)
        .replace("__FREE_BODY__", free_body)
        .replace("__REGISTER_LOG__", register_log)
}

fn plugin_source(name: &str, abi: u32, init_rc: i32, call_body: &str, init_body: &str) -> String {
    plugin_source_full(
        name,
        abi,
        init_rc,
        call_body,
        init_body,
        "",
        "",
        "C.free(ptr)",
        "",
    )
}

/// `provider.call` body: echo the input back.
const ECHO_BODY: &str = r#"	var in struct {
		Input string `json:"input"`
	}
	_ = json.Unmarshal(C.GoBytes(unsafe.Pointer(req), C.int(reqLen)), &in)
	out, _ := json.Marshal(map[string]string{"payload": "echo:" + in.Input})
	*resp = allocResp(envelope(out))
	return 0"#;

/// `provider.call` body: call `host.log`, then echo.
const HOSTLOG_BODY: &str = r#"	logReq := []byte(`{"level":"info","message":"hello from plugin"}`)
	methodC := C.CString("host.log")
	defer C.free(unsafe.Pointer(methodC))
	var out C.castctl_buffer
	rc := C.call_host_fn(hostAPI.call, hostAPI.host_ctx, methodC, (*C.uint8_t)(unsafe.Pointer(&logReq[0])), C.size_t(len(logReq)), &out)
	if rc != 0 {
		*resp = allocResp(errEnvelope("host_log_failed", "host.log delivery failed"))
		return 0
	}
	if out.ptr != nil {
		C.free_host_fn(hostAPI.free_buffer, out.ptr, out.len)
	}
	var in struct {
		Input string `json:"input"`
	}
	_ = json.Unmarshal(C.GoBytes(unsafe.Pointer(req), C.int(reqLen)), &in)
	rep, _ := json.Marshal(map[string]string{"payload": "echo:" + in.Input})
	*resp = allocResp(envelope(rep))
	return 0"#;

/// `provider.call` body: three `host.log` calls, then echo.
const HOSTLOG3_BODY: &str = r#"	logLine("log one")
	logLine("log two")
	logLine("log three")
	var in struct {
		Input string `json:"input"`
	}
	_ = json.Unmarshal(C.GoBytes(unsafe.Pointer(req), C.int(reqLen)), &in)
	rep, _ := json.Marshal(map[string]string{"payload": "echo:" + in.Input})
	*resp = allocResp(envelope(rep))
	return 0"#;

/// `provider.call` body: `host.log` from a background
/// goroutine (joined before replying), then echo.
const HOSTLOG_BG_BODY: &str = r#"	done := make(chan struct{})
	go func() {
		logLine("from background")
		close(done)
	}()
	<-done
	var in struct {
		Input string `json:"input"`
	}
	_ = json.Unmarshal(C.GoBytes(unsafe.Pointer(req), C.int(reqLen)), &in)
	rep, _ := json.Marshal(map[string]string{"payload": "echo:" + in.Input})
	*resp = allocResp(envelope(rep))
	return 0"#;

/// `provider.call` body: call an unsupported host
/// method (`host.auth.list`); the worker must answer
/// with rc 0 + an `unsupported_host_callback` error
/// envelope, and the call still echoes.
const HOSTLOG_UNSUPPORTED_BODY: &str = r#"	cbReq := []byte(`{}`)
	methodC := C.CString("host.auth.list")
	defer C.free(unsafe.Pointer(methodC))
	var out C.castctl_buffer
	rc := C.call_host_fn(hostAPI.call, hostAPI.host_ctx, methodC, (*C.uint8_t)(unsafe.Pointer(&cbReq[0])), C.size_t(len(cbReq)), &out)
	if rc != 0 {
		*resp = allocResp(errEnvelope("host_auth_failed", "host.auth.list delivery failed"))
		return 0
	}
	var env struct {
		OK bool `json:"ok"`
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if out.ptr != nil {
		_ = json.Unmarshal(C.GoBytes(unsafe.Pointer(out.ptr), C.int(out.len)), &env)
		C.free_host_fn(hostAPI.free_buffer, out.ptr, out.len)
	}
	if env.OK || env.Error.Code != "unsupported_host_callback" {
		*resp = allocResp(errEnvelope("unexpected", "expected unsupported_host_callback"))
		return 0
	}
	var in struct {
		Input string `json:"input"`
	}
	_ = json.Unmarshal(C.GoBytes(unsafe.Pointer(req), C.int(reqLen)), &in)
	rep, _ := json.Marshal(map[string]string{"payload": "echo:" + in.Input})
	*resp = allocResp(envelope(rep))
	return 0"#;

/// `provider.call` body: `host.log` in a tight loop
/// (100k times). The parent must kill the worker at
/// the per-transaction budget (B6), never OOM.
const FLOOD_BODY: &str = r#"	for i := 0; i < 100000; i++ {
		logLine("flood")
	}
	var in struct {
		Input string `json:"input"`
	}
	_ = json.Unmarshal(C.GoBytes(unsafe.Pointer(req), C.int(reqLen)), &in)
	rep, _ := json.Marshal(map[string]string{"payload": "echo:" + in.Input})
	*resp = allocResp(envelope(rep))
	return 0"#;

/// `provider.call` body: ONE `host.log` call carrying
/// a 5 MiB message. The parent must kill the worker at
/// the per-transaction BYTE bound (4 MiB, B6) even
/// though the frame-count bound (1000) is nowhere near
/// tripped — the count and byte bounds are distinct
/// (fix loop 2, technical N9 / red-team N8).
const BIGLOG_BODY: &str = r#"	big := make([]byte, 5*1024*1024)
	for i := range big {
		big[i] = 'x'
	}
	logLine(string(big))
	var in struct {
		Input string `json:"input"`
	}
	_ = json.Unmarshal(C.GoBytes(unsafe.Pointer(req), C.int(reqLen)), &in)
	rep, _ := json.Marshal(map[string]string{"payload": "echo:" + in.Input})
	*resp = allocResp(envelope(rep))
	return 0"#;

/// `provider.call` body: hang forever (never reply).
/// The parent must kill the worker at the 30s transact
/// deadline and fuse the client at the Host level (fix
/// loop 2, NB1).
const HUNG_BODY: &str = r#"	select {}
	var in struct {
		Input string `json:"input"`
	}
	_ = json.Unmarshal(C.GoBytes(unsafe.Pointer(req), C.int(reqLen)), &in)
	rep, _ := json.Marshal(map[string]string{"payload": "echo:" + in.Input})
	*resp = allocResp(envelope(rep))
	return 0"#;

/// `provider.call` body: ignore the input, return a
/// small envelope. Used for the oversize host-request
/// test (B5): only the request frame is large.
const BIGREQ_BODY: &str = r#"	out, _ := json.Marshal(map[string]string{"payload": "big-ok"})
	*resp = allocResp(envelope(out))
	return 0"#;

/// `provider.call` body: valid 16-byte allocation,
/// lying length 1 MiB (inside `i32::MAX`). The host
/// must never accept the bytes as a response (safety
/// N2); the worker may crash or the host may refuse
/// the garbage envelope — both are fail-closed.
const LYING_SMALL_BODY: &str = r#"	p := C.malloc(16)
	*resp = C.castctl_buffer{ptr: p, len: C.size_t(1 << 20)}
	return 0"#;

/// `provider.call` body: write a valid length prefix
/// for a 1 MiB frame to stdout (= the protocol
/// socket), then dribble 1 byte every 25s. The parent
/// must kill the worker at the 30s deadline (B1),
/// not after ~16M x 30s.
const DRIP_BODY: &str = r#"	hdr := []byte{0, 0, 0, 0}
	binary.BigEndian.PutUint32(hdr, 1024*1024)
	os.Stdout.Write(hdr)
	for i := 0; i < 10; i++ {
		os.Stdout.Write([]byte{0x41})
		time.Sleep(25 * time.Second)
	}
	return 0"#;

/// Build a forged-reply call body: a background
/// goroutine writes a forged frame (`op`, `id`,
/// `ok:true`, response = the FORGED envelope) straight
/// to fd 1 while the main call sleeps, then echoes.
/// The parent must reject it as a protocol error
/// (B2), never return the forged bytes.
fn forge_body(op: &str, id: u64) -> String {
    format!(
        r#"	go func() {{
		frame := []byte(`{{"v":2,"id":{id},"op":"{op}","ok":true,"response":"eyJvayI6dHJ1ZSwicmVzdWx0Ijp7InBheWxvYWQiOiJlY2hvOkZPUkdFRCJ9fQ=="}}`)
		hdr := make([]byte, 4)
		binary.BigEndian.PutUint32(hdr, uint32(len(frame)))
		os.Stdout.Write(hdr)
		os.Stdout.Write(frame)
	}}()
	time.Sleep(500 * time.Millisecond)
	var in struct {{
		Input string `json:"input"`
	}}
	_ = json.Unmarshal(C.GoBytes(unsafe.Pointer(req), C.int(reqLen)), &in)
	rep, _ := json.Marshal(map[string]string{{"payload": "echo:" + in.Input}})
	*resp = allocResp(envelope(rep))
	return 0"#,
        id = id,
        op = op
    )
}

/// Build a call body that writes a marker file on
/// entry, then echoes. Used to prove `pluginCall` was
/// (G7/G5) or was not (G5) invoked.
fn marker_call_body(marker: &Path) -> String {
    format!(
        r#"	os.WriteFile({marker:?}, []byte("called"), 0644)
	var in struct {{
		Input string `json:"input"`
	}}
	_ = json.Unmarshal(C.GoBytes(unsafe.Pointer(req), C.int(reqLen)), &in)
	out, _ := json.Marshal(map[string]string{{"payload": "echo:" + in.Input}})
	*resp = allocResp(envelope(out))
	return 0"#,
        marker = marker
    )
}

/// Collected host.log lines: `(level, message)` pairs.
type LogLines = Arc<Mutex<Vec<(String, String)>>>;

/// The `Options.log` sink type (kept local: the
/// crate's `LogFn` is private).
type LogSink = Arc<dyn Fn(&str, &str) + Send + Sync>;

fn make_host(logs: Option<LogLines>) -> Host {
    let loader = WorkerLoader::with_worker_bin(worker_bin());
    let log = logs.map(|logs| {
        // Explicit `dyn Fn` type: the `Options.log`
        // field needs the trait object, not the bare
        // closure type.
        let f: LogSink = Arc::new(move |level: &str, message: &str| {
            logs.lock()
                .unwrap_or_else(|e| e.into_inner())
                .push((level.to_string(), message.to_string()));
        });
        f
    });
    Host::new(Options {
        loader: Some(Box::new(loader)),
        log,
    })
}

fn load(host: &Host, tag: &str, path: &Path) -> castctl_pluginhost::host::ApplyReport {
    let mut d = Desired::new(tag, "check", &path.to_string_lossy());
    d.fragment = b"{}".to_vec();
    host.apply_config(vec![d])
}

/// The follow-up control call every test ends with: a
/// FRESH echo load + `provider.call {"input":"ping"}`
/// must return `echo:ping`. Proves the host process
/// survived whatever the plugin under test did.
fn control_echo_ok() {
    let Some(echo) = build_echo() else {
        eprintln!("SKIP control: go unavailable");
        return;
    };
    let host = make_host(None);
    let report = load(&host, "control", &echo);
    assert!(
        report.skipped.is_empty(),
        "control load skipped: {:?}",
        report.skipped
    );
    let out = host
        .call(
            "control",
            METHOD_PROVIDER_CALL,
            b"{\"input\":\"ping\"}",
            Some(Duration::from_secs(30)),
        )
        .expect("control call");
    let text = String::from_utf8_lossy(&out);
    assert!(text.contains("echo:ping"), "control result: {text}");
    eprintln!("control: fresh echo load provider.call -> {text}");
    host.close();
}

fn is_crash(e: &PluginHostError) -> Option<Option<i32>> {
    match e {
        PluginHostError::PluginCrashed { signal, .. } => Some(*signal),
        _ => None,
    }
}

/// (1) Load the real echo.so, one request: the
/// response must be byte-identical to Go running the
/// same plugin (automated in
/// `live_plugin_check_matches_go`; the manual
/// comparison is also recorded in the PR report).
#[test]
fn live_echo_load_and_call_matches_go() {
    // Serialised: see `LIVE_LOCK`.
    let _live_guard = LIVE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let Some(echo) = build_echo() else { return };
    eprintln!("echo.so: {}", echo.display());
    let host = make_host(None);
    let report = load(&host, "echo", &echo);
    assert!(
        report.skipped.is_empty(),
        "echo load skipped: {:?}",
        report.skipped
    );
    let loaded = host.loaded("echo").expect("echo loaded");
    assert_eq!(loaded.schema_version, 1);
    assert_eq!(loaded.metadata.name, "echo");
    assert_eq!(loaded.metadata.version, "0.1.0");
    assert!(loaded.capabilities.provider);
    eprintln!(
        "register: ok schema={} name={} version={} capabilities=provider",
        loaded.schema_version, loaded.metadata.name, loaded.metadata.version
    );
    let out = host
        .call(
            "echo",
            METHOD_PROVIDER_CALL,
            b"{\"input\":\"ping\"}",
            Some(Duration::from_secs(30)),
        )
        .expect("provider.call");
    let text = String::from_utf8_lossy(&out);
    eprintln!("provider.call: ok {text}");
    assert_eq!(text, "{\"payload\":\"echo:ping\"}");
    host.close();
    control_echo_ok();
}

/// (2) Wrong ABI version (v2 and v0) is refused, no
/// crash, and the plugin call is never invoked (G5:
/// the marker file proves `pluginCall` never ran —
/// the load fails before register).
#[test]
fn live_wrong_abi_version_refused() {
    // Serialised: see `LIVE_LOCK`.
    let _live_guard = LIVE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    for abi in [2u32, 0u32] {
        let name = format!("abi{abi}");
        let marker = scratch_dir(&name).join("called.txt");
        let _ = std::fs::remove_file(&marker);
        let Some(so) = build_plugin(
            &name,
            &plugin_source(&name, abi, 0, &marker_call_body(&marker), ""),
        ) else {
            return;
        };
        let host = make_host(None);
        let report = load(&host, &name, &so);
        assert_eq!(report.loaded.len(), 0, "abi {abi}: unexpectedly loaded");
        assert_eq!(report.skipped.len(), 1);
        let reason = &report.skipped[0].reason;
        eprintln!("abi {abi}: skipped: {reason}");
        assert!(
            reason.contains(&format!("plugin ABI version {abi} is not supported")),
            "abi {abi} reason: {reason}"
        );
        assert!(host.loaded(&name).is_none());
        assert!(
            !marker.exists(),
            "abi {abi}: pluginCall ran during a refused load (marker {marker:?} exists)"
        );
        host.close();
    }
    control_echo_ok();
}

/// (3) init returning an error code is a clear error,
/// no crash.
#[test]
fn live_init_error_is_clear_error() {
    // Serialised: see `LIVE_LOCK`.
    let _live_guard = LIVE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let Some(so) = build_plugin("initerr", &plugin_source("initerr", 1, 7, ECHO_BODY, "")) else {
        return;
    };
    let host = make_host(None);
    let report = load(&host, "initerr", &so);
    assert_eq!(report.loaded.len(), 0);
    assert_eq!(report.skipped.len(), 1);
    let reason = &report.skipped[0].reason;
    eprintln!("initerr: skipped: {reason}");
    assert!(
        reason.contains("castctl_plugin_init returned 7"),
        "initerr reason: {reason}"
    );
    host.close();
    control_echo_ok();
}

/// (G1) init returns 0 but leaves `call` (or
/// `free_buffer`) nil: the completeness check refuses
/// the load with the Go-exact string.
#[test]
fn live_incomplete_table_refused() {
    // Serialised: see `LIVE_LOCK`.
    let _live_guard = LIVE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    for (name, tail) in [
        ("incompletecall", "plugin.call = nil"),
        ("incompletefree", "plugin.free_buffer = nil"),
    ] {
        let Some(so) = build_plugin(
            name,
            &plugin_source_full(name, 1, 0, ECHO_BODY, "", tail, "", "C.free(ptr)", ""),
        ) else {
            return;
        };
        let host = make_host(None);
        let report = load(&host, name, &so);
        assert_eq!(report.loaded.len(), 0, "{name}: unexpectedly loaded");
        assert_eq!(report.skipped.len(), 1);
        let reason = &report.skipped[0].reason;
        eprintln!("{name}: skipped: {reason}");
        assert!(
            reason.contains("plugin function table is incomplete"),
            "{name} reason: {reason}"
        );
        assert!(host.loaded(name).is_none());
        host.close();
    }
    control_echo_ok();
}

/// (G7) init fills `shutdown` (marker file) then
/// returns 7: Go calls `shutdown` after a failed init
/// (`closeAfterOpenFailure`) — the marker proves the
/// Rust worker does too, and the load still fails
/// with the init error.
#[test]
fn live_failed_init_calls_shutdown() {
    // Serialised: see `LIVE_LOCK`.
    let _live_guard = LIVE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let marker = scratch_dir("initshutdown").join("shutdown.txt");
    let _ = std::fs::remove_file(&marker);
    let shutdown_body = format!(
        "os.WriteFile({marker:?}, []byte(\"shutdown\"), 0644)",
        marker = marker
    );
    let Some(so) = build_plugin(
        "initshutdown",
        &plugin_source_full(
            "initshutdown",
            1,
            7,
            ECHO_BODY,
            "",
            "",
            &shutdown_body,
            "C.free(ptr)",
            "",
        ),
    ) else {
        return;
    };
    let host = make_host(None);
    let report = load(&host, "initshutdown", &so);
    assert_eq!(report.loaded.len(), 0);
    assert_eq!(report.skipped.len(), 1);
    let reason = &report.skipped[0].reason;
    eprintln!("initshutdown: skipped: {reason}");
    assert!(
        reason.contains("castctl_plugin_init returned 7"),
        "initshutdown reason: {reason}"
    );
    assert!(
        marker.exists(),
        "shutdown was not invoked after a failed init (marker {marker:?} missing)"
    );
    host.close();
    control_echo_ok();
}

/// (G2) A `.so` without `castctl_plugin_init` and a
/// corrupt (truncated) `.so` both fail at `dlopen`
/// with clear errors, and no worker lingers after the
/// failed load.
#[test]
fn live_missing_symbol_and_corrupt_so() {
    // Serialised: see `LIVE_LOCK`.
    let _live_guard = LIVE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // (a) No entry symbol at all.
    const NO_INIT: &str = r#"package main
import "C"

//export dummy
func dummy() {}

func main() {}
"#;
    let Some(so) = build_raw_plugin("nosymbol", NO_INIT) else {
        return;
    };
    let host = make_host(None);
    let report = load(&host, "nosymbol", &so);
    assert_eq!(report.loaded.len(), 0);
    assert_eq!(report.skipped.len(), 1);
    let reason = &report.skipped[0].reason;
    eprintln!("nosymbol: skipped: {reason}");
    assert!(
        reason.contains("missing castctl_plugin_init"),
        "nosymbol reason: {reason}"
    );
    host.close();
    assert!(
        worker_pids().is_empty(),
        "worker lingers after a missing-symbol load: {:?}",
        worker_pids()
    );
    // (b) Truncated echo.so.
    let Some(echo) = build_echo() else {
        return;
    };
    let dir = scratch_dir("corrupt");
    let corrupt = dir.join("corrupt.so");
    let bytes = std::fs::read(&echo).expect("read echo.so");
    std::fs::write(&corrupt, &bytes[..512]).expect("write corrupt.so");
    let host = make_host(None);
    let report = load(&host, "corrupt", &corrupt);
    assert_eq!(report.loaded.len(), 0);
    assert_eq!(report.skipped.len(), 1);
    let reason = &report.skipped[0].reason;
    eprintln!("corrupt: skipped: {reason}");
    // Pinned exact (fix loop 2, technical N6 /
    // red-team N11): a 512-byte truncation of echo.so
    // fails in the parent's glibc compat gate ("read
    // plugin elf: truncated program header") before
    // any worker is spawned — not at dlopen. The old
    // loose `"dlopen" OR "truncated"` accepted either
    // branch without saying which fires.
    assert!(
        reason.contains("read plugin elf: truncated program header"),
        "corrupt reason: {reason}"
    );
    host.close();
    assert!(
        worker_pids().is_empty(),
        "worker lingers after a corrupt-so load: {:?}",
        worker_pids()
    );
    control_echo_ok();
}

/// (4) Null response and lying length are clean
/// errors; the worker SURVIVES both (a second call on
/// the same client returns the same clean error, not a
/// crash). A garbage pointer (0x1) is the DESIGNED
/// worker death: `PluginCrashed{signal:11}`. A lying
/// length inside `i32::MAX` never yields a successful
/// response (safety N2).
#[test]
fn live_bad_response_pointer() {
    // Serialised: see `LIVE_LOCK`.
    let _live_guard = LIVE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // (a) null pointer, NONZERO length 5 (fix loop 1,
    // G3: the R2-mandated case, not the valid-empty
    // {nil, len 0}). At the loader level this is an
    // empty Ok; the Host refuses the empty response
    // as a decode error. The worker survives.
    let Some(null_so) = build_plugin(
        "nullresp",
        &plugin_source(
            "nullresp",
            1,
            0,
            "\t*resp = C.castctl_buffer{ptr: nil, len: 5}\n\treturn 0",
            "",
        ),
    ) else {
        return;
    };
    let host = make_host(None);
    let report = load(&host, "nullresp", &null_so);
    assert!(
        report.skipped.is_empty(),
        "nullresp load: {:?}",
        report.skipped
    );
    let err = host
        .call(
            "nullresp",
            METHOD_PROVIDER_CALL,
            b"{\"input\":\"ping\"}",
            Some(Duration::from_secs(30)),
        )
        .expect_err("null response must fail");
    eprintln!("nullresp call 1: {err}");
    assert!(
        is_crash(&err).is_none(),
        "null response must not crash: {err}"
    );
    let err2 = host
        .call(
            "nullresp",
            METHOD_PROVIDER_CALL,
            b"{\"input\":\"ping\"}",
            Some(Duration::from_secs(30)),
        )
        .expect_err("null response must fail again");
    eprintln!("nullresp call 2: {err2}");
    assert!(is_crash(&err2).is_none(), "worker must survive: {err2}");
    host.close();

    // (b) lying length: valid pointer, len past i32::MAX.
    // `free_buffer` must run on this path (G3): the
    // counting free body records one free per call —
    // register (1) + two provider calls (2) = 3.
    let free_dir = scratch_dir("lyinglenfree");
    let free_marker = free_dir.join("frees.txt");
    let _ = std::fs::remove_file(&free_marker);
    let free_body = format!(
        "f, _ := os.OpenFile({marker:?}, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)\n\tif f != nil {{ f.Write([]byte(\"f\\n\")); f.Close() }}\n\tC.free(ptr)",
        marker = free_marker
    );
    let Some(lying_so) = build_plugin(
        "lyinglenfree",
        &plugin_source_full(
            "lyinglenfree",
            1,
            0,
            "\tp := C.malloc(4)\n\t*resp = C.castctl_buffer{ptr: p, len: C.size_t(1 << 31)}\n\treturn 0",
            "",
            "",
            "",
            &free_body,
            "",
        ),
    ) else {
        return;
    };
    let host = make_host(None);
    let report = load(&host, "lyinglenfree", &lying_so);
    assert!(
        report.skipped.is_empty(),
        "lyinglenfree load: {:?}",
        report.skipped
    );
    for i in 1..=2 {
        let err = host
            .call(
                "lyinglenfree",
                METHOD_PROVIDER_CALL,
                b"{\"input\":\"ping\"}",
                Some(Duration::from_secs(30)),
            )
            .expect_err("lying length must fail");
        eprintln!("lyinglenfree call {i}: {err}");
        assert!(
            err.to_string().contains("returned an oversize response"),
            "lyinglenfree error: {err}"
        );
        assert!(
            is_crash(&err).is_none(),
            "lying length must not crash: {err}"
        );
    }
    let frees = std::fs::read_to_string(&free_marker).unwrap_or_default();
    let count = frees.lines().count();
    assert_eq!(
        count, 3,
        "free_buffer must run on the oversize path (register + 2 calls): got {count} frees in {frees:?}"
    );
    host.close();

    // (c) garbage pointer 0x1: the worker dies by
    // SIGSEGV — the designed outcome.
    let Some(garbage_so) = build_plugin(
        "garbageptr",
        &plugin_source(
            "garbageptr",
            1,
            0,
            "\t*resp = C.castctl_buffer{ptr: unsafe.Pointer(uintptr(0x1)), len: 16}\n\treturn 0",
            "",
        ),
    ) else {
        return;
    };
    let host = make_host(None);
    let report = load(&host, "garbageptr", &garbage_so);
    assert!(
        report.skipped.is_empty(),
        "garbageptr load: {:?}",
        report.skipped
    );
    let err = host
        .call(
            "garbageptr",
            METHOD_PROVIDER_CALL,
            b"{\"input\":\"ping\"}",
            Some(Duration::from_secs(30)),
        )
        .expect_err("garbage pointer must fail");
    eprintln!("garbageptr call: {err}");
    assert_eq!(is_crash(&err), Some(Some(11)), "garbage pointer: {err}");
    host.close();

    // (d) lying length INSIDE i32::MAX (valid 16-byte
    // allocation, len 1 MiB): the copy reads adjacent
    // worker heap. The guarantee is only that the host
    // never accepts the bytes as a successful response
    // — the worker may segfault (crash) or the garbage
    // may fail envelope decoding (clean error). Either
    // way the host survives (control call below).
    let Some(small_so) = build_plugin(
        "lyingsmall",
        &plugin_source("lyingsmall", 1, 0, LYING_SMALL_BODY, ""),
    ) else {
        return;
    };
    let host = make_host(None);
    let report = load(&host, "lyingsmall", &small_so);
    assert!(
        report.skipped.is_empty(),
        "lyingsmall load: {:?}",
        report.skipped
    );
    let err = host
        .call(
            "lyingsmall",
            METHOD_PROVIDER_CALL,
            b"{\"input\":\"ping\"}",
            Some(Duration::from_secs(30)),
        )
        .expect_err("lying small length must fail");
    eprintln!("lyingsmall call: {err}");
    assert!(
        !err.to_string().contains("echo:ping"),
        "lying length bytes must never be a successful response: {err}"
    );
    host.close();

    control_echo_ok();
}

/// (5) A plugin calling `host.log` mid-call works:
/// the parent multiplexes the callback frame while
/// the call is outstanding (the deadlock rule), the
/// log line arrives, and the call still returns.
#[test]
fn live_host_callback_mid_call() {
    // Serialised: see `LIVE_LOCK`.
    let _live_guard = LIVE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let Some(so) = build_plugin("hostlog", &plugin_source("hostlog", 1, 0, HOSTLOG_BODY, ""))
    else {
        return;
    };
    let logs: LogLines = Arc::new(Mutex::new(Vec::new()));
    let host = make_host(Some(Arc::clone(&logs)));
    let report = load(&host, "hostlog", &so);
    assert!(
        report.skipped.is_empty(),
        "hostlog load: {:?}",
        report.skipped
    );
    let out = host
        .call(
            "hostlog",
            METHOD_PROVIDER_CALL,
            b"{\"input\":\"ping\"}",
            Some(Duration::from_secs(30)),
        )
        .expect("host.log call");
    let text = String::from_utf8_lossy(&out);
    eprintln!("hostlog provider.call: ok {text}");
    assert_eq!(text, "{\"payload\":\"echo:ping\"}");
    let got = logs.lock().unwrap_or_else(|e| e.into_inner()).clone();
    eprintln!("hostlog logs: {got:?}");
    assert!(
        got.iter()
            .any(|(level, msg)| level == "info" && msg == "hello from plugin"),
        "host.log line missing: {got:?}"
    );
    host.close();
    control_echo_ok();
}

/// (G6) Test 5's multiplexing, in the shapes it did
/// not cover: three `host.log` calls in one
/// `provider.call`, one from a plugin background
/// goroutine, and one during `open`/`register` (the
/// open transact multiplexes too).
#[test]
fn live_host_callback_multi_background_register() {
    // Serialised: see `LIVE_LOCK`.
    let _live_guard = LIVE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // (a) Three logs in one call, in order.
    let Some(so) = build_plugin(
        "hostlog3",
        &plugin_source("hostlog3", 1, 0, HOSTLOG3_BODY, ""),
    ) else {
        return;
    };
    let logs: LogLines = Arc::new(Mutex::new(Vec::new()));
    let host = make_host(Some(Arc::clone(&logs)));
    let report = load(&host, "hostlog3", &so);
    assert!(
        report.skipped.is_empty(),
        "hostlog3 load: {:?}",
        report.skipped
    );
    let out = host
        .call(
            "hostlog3",
            METHOD_PROVIDER_CALL,
            b"{\"input\":\"ping\"}",
            Some(Duration::from_secs(30)),
        )
        .expect("host.log x3 call");
    assert_eq!(String::from_utf8_lossy(&out), "{\"payload\":\"echo:ping\"}");
    let got = logs.lock().unwrap_or_else(|e| e.into_inner()).clone();
    eprintln!("hostlog3 logs: {got:?}");
    assert_eq!(
        got,
        vec![
            ("info".to_string(), "log one".to_string()),
            ("info".to_string(), "log two".to_string()),
            ("info".to_string(), "log three".to_string()),
        ],
        "three host.log lines in order"
    );
    host.close();
    // (b) One log from a background goroutine.
    let Some(so) = build_plugin(
        "hostlogbg",
        &plugin_source("hostlogbg", 1, 0, HOSTLOG_BG_BODY, ""),
    ) else {
        return;
    };
    let logs: LogLines = Arc::new(Mutex::new(Vec::new()));
    let host = make_host(Some(Arc::clone(&logs)));
    let report = load(&host, "hostlogbg", &so);
    assert!(
        report.skipped.is_empty(),
        "hostlogbg load: {:?}",
        report.skipped
    );
    let out = host
        .call(
            "hostlogbg",
            METHOD_PROVIDER_CALL,
            b"{\"input\":\"ping\"}",
            Some(Duration::from_secs(30)),
        )
        .expect("background host.log call");
    assert_eq!(String::from_utf8_lossy(&out), "{\"payload\":\"echo:ping\"}");
    let got = logs.lock().unwrap_or_else(|e| e.into_inner()).clone();
    eprintln!("hostlogbg logs: {got:?}");
    assert!(
        got.iter()
            .any(|(level, msg)| level == "info" && msg == "from background"),
        "background host.log line missing: {got:?}"
    );
    host.close();
    // (c) One log during register (the open transact).
    let Some(so) = build_plugin(
        "hostlogreg",
        &plugin_source_full(
            "hostlogreg",
            1,
            0,
            ECHO_BODY,
            "",
            "",
            "",
            "C.free(ptr)",
            "logLine(\"hello from register\")",
        ),
    ) else {
        return;
    };
    let logs: LogLines = Arc::new(Mutex::new(Vec::new()));
    let host = make_host(Some(Arc::clone(&logs)));
    let report = load(&host, "hostlogreg", &so);
    assert!(
        report.skipped.is_empty(),
        "hostlogreg load: {:?}",
        report.skipped
    );
    let got = logs.lock().unwrap_or_else(|e| e.into_inner()).clone();
    eprintln!("hostlogreg logs: {got:?}");
    assert!(
        got.iter()
            .any(|(level, msg)| level == "info" && msg == "hello from register"),
        "register-time host.log line missing: {got:?}"
    );
    let out = host
        .call(
            "hostlogreg",
            METHOD_PROVIDER_CALL,
            b"{\"input\":\"ping\"}",
            Some(Duration::from_secs(30)),
        )
        .expect("hostlogreg call");
    assert_eq!(String::from_utf8_lossy(&out), "{\"payload\":\"echo:ping\"}");
    host.close();
    control_echo_ok();
}

/// (tech N8) A plugin calling an unsupported host
/// method gets rc 0 + an `unsupported_host_callback`
/// error envelope back through the worker (the
/// round-trip of an error envelope, not just the
/// happy-path log delivery), and the call still
/// echoes.
#[test]
fn live_host_callback_unsupported_method() {
    // Serialised: see `LIVE_LOCK`.
    let _live_guard = LIVE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let Some(so) = build_plugin(
        "hostlogunsup",
        &plugin_source("hostlogunsup", 1, 0, HOSTLOG_UNSUPPORTED_BODY, ""),
    ) else {
        return;
    };
    let host = make_host(None);
    let report = load(&host, "hostlogunsup", &so);
    assert!(
        report.skipped.is_empty(),
        "hostlogunsup load: {:?}",
        report.skipped
    );
    let out = host
        .call(
            "hostlogunsup",
            METHOD_PROVIDER_CALL,
            b"{\"input\":\"ping\"}",
            Some(Duration::from_secs(30)),
        )
        .expect("unsupported host method call");
    let text = String::from_utf8_lossy(&out);
    eprintln!("hostlogunsup provider.call: ok {text}");
    assert_eq!(text, "{\"payload\":\"echo:ping\"}");
    host.close();
    control_echo_ok();
}

/// (6) A plugin that deliberately segfaults — in the
/// call AND in init — leaves the host alive with a
/// clear error carrying the signal number (11).
#[test]
fn live_segfault_in_call_and_init() {
    // Serialised: see `LIVE_LOCK`.
    let _live_guard = LIVE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // (a) segfault in the call.
    let Some(crash_so) = build_plugin(
        "crashcall",
        &plugin_source("crashcall", 1, 0, "\tC.crash_now()\n\treturn 0", ""),
    ) else {
        return;
    };
    let host = make_host(None);
    let report = load(&host, "crashcall", &crash_so);
    assert!(
        report.skipped.is_empty(),
        "crashcall load: {:?}",
        report.skipped
    );
    let err = host
        .call(
            "crashcall",
            METHOD_PROVIDER_CALL,
            b"{\"input\":\"ping\"}",
            Some(Duration::from_secs(30)),
        )
        .expect_err("segfaulting call must fail");
    eprintln!("crashcall call: {err}");
    assert_eq!(is_crash(&err), Some(Some(11)), "crashcall: {err}");
    // The client is fused after the crash: a second
    // call replays the same crash error — it never
    // silently restarts or spawns a new worker.
    let err2 = host
        .call(
            "crashcall",
            METHOD_PROVIDER_CALL,
            b"{\"input\":\"ping\"}",
            Some(Duration::from_secs(30)),
        )
        .expect_err("fused client must fail");
    eprintln!("crashcall call 2 (fused): {err2}");
    // The fused replay is a `Failed` error carrying
    // the crash text (not a fresh `PluginCrashed`):
    // it must name the fuse and the signal, and must
    // never silently restart the worker.
    let fused = err2.to_string();
    assert!(
        fused.contains("fused") && fused.contains("signal 11"),
        "fused call must replay the crash, not restart: {err2}"
    );
    host.close();

    // (b) segfault in init.
    let Some(init_so) = build_plugin(
        "crashinit",
        &plugin_source("crashinit", 1, 0, ECHO_BODY, "\tC.crash_now()"),
    ) else {
        return;
    };
    let host = make_host(None);
    let report = load(&host, "crashinit", &init_so);
    assert_eq!(report.loaded.len(), 0);
    assert_eq!(report.skipped.len(), 1);
    let reason = &report.skipped[0].reason;
    eprintln!("crashinit: skipped: {reason}");
    assert!(reason.contains("signal 11"), "crashinit reason: {reason}");
    host.close();

    control_echo_ok();
}

/// (B3) A crash fuses at the HOST level too: after a
/// segfaulting call, `host.fused(tag)` carries
/// "signal 11", `host.loaded(tag)` is gone, and the
/// next `apply_config` with the same tag+path reports
/// `skipped: "fused: …signal 11…"` — without burning
/// a reconfigure + rollback against the dead client.
#[test]
fn live_crash_fuses_host() {
    // Serialised: see `LIVE_LOCK`.
    let _live_guard = LIVE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let Some(crash_so) = build_plugin(
        "crashfuse",
        &plugin_source("crashfuse", 1, 0, "\tC.crash_now()\n\treturn 0", ""),
    ) else {
        return;
    };
    let host = make_host(None);
    let report = load(&host, "crashfuse", &crash_so);
    assert!(
        report.skipped.is_empty(),
        "crashfuse load: {:?}",
        report.skipped
    );
    let err = host
        .call(
            "crashfuse",
            METHOD_PROVIDER_CALL,
            b"{\"input\":\"ping\"}",
            Some(Duration::from_secs(30)),
        )
        .expect_err("segfaulting call must fail");
    eprintln!("crashfuse call: {err}");
    assert_eq!(is_crash(&err), Some(Some(11)), "crashfuse: {err}");
    let fused = host.fused("crashfuse").expect("crash must fuse the host");
    eprintln!("crashfuse fused: {fused}");
    assert!(
        fused.contains("signal 11"),
        "host fuse reason must carry the crash: {fused}"
    );
    assert!(
        host.loaded("crashfuse").is_none(),
        "crashed plugin must not stay loaded"
    );
    let report = load(&host, "crashfuse", &crash_so);
    assert_eq!(report.loaded.len(), 0);
    assert_eq!(report.skipped.len(), 1);
    let reason = &report.skipped[0].reason;
    eprintln!("crashfuse re-apply: skipped: {reason}");
    assert!(
        reason.contains("fused:") && reason.contains("signal 11"),
        "re-apply must skip as fused with the crash reason, not reconfigure: {reason}"
    );
    host.close();
    control_echo_ok();
}

/// (NB1, fix loop 2) A transact-timeout kill fuses at
/// the Host level, exactly like a crash: a hung plugin
/// called with NO Host deadline (`Host::call(...,
/// None)` — the path used by registration /
/// reconfigure / quiesce via `call_envelope`, `plugin
/// check`, and `check_plugin`) must leave
/// `host.fused(tag)` carrying the timeout reason and
/// `host.loaded(tag)` gone, and a re-apply with the
/// same tag+path must skip as fused — never a doomed
/// reconfigure + rollback fused with the wrong reason
/// (`"reconfigure failed and rollback failed"`).
/// The `None` deadline is the point of this test: with
/// `Some(d)` the Host-level `RecvTimeout` arm fires
/// first and masks the bug.
#[test]
fn live_timeout_kill_fuses_host() {
    // Serialised: see `LIVE_LOCK`.
    let _live_guard = LIVE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let Some(so) = build_plugin("hungfuse", &plugin_source("hungfuse", 1, 0, HUNG_BODY, "")) else {
        return;
    };
    let host = Arc::new(make_host(None));
    let report = load(&host, "hungfuse", &so);
    assert!(
        report.skipped.is_empty(),
        "hungfuse load: {:?}",
        report.skipped
    );
    // Run the `None`-deadline call on a detached
    // thread with a 60s join bound: the worker's 30s
    // transact must kill it at ~30s, and a regression
    // there must fail this test in 60s instead of
    // hanging the suite forever. (The detached thread
    // is abandoned on a join timeout; the test process
    // exit kills it with the worker via PDEATHSIG.)
    let (tx, rx) = std::sync::mpsc::channel();
    let host_call = Arc::clone(&host);
    std::thread::spawn(move || {
        let r = host_call.call(
            "hungfuse",
            METHOD_PROVIDER_CALL,
            b"{\"input\":\"ping\"}",
            None,
        );
        let _ = tx.send(r);
    });
    let start = Instant::now();
    let err = rx
        .recv_timeout(Duration::from_secs(60))
        .expect("hungfuse call never returned (worker deadline did not fire?)")
        .expect_err("hung call must fail");
    let elapsed = start.elapsed();
    eprintln!("hungfuse call: {err} after {elapsed:?}");
    assert!(
        err.to_string().contains("timed out"),
        "hung call must fail as a timeout: {err}"
    );
    assert!(
        !err.is_crash(),
        "a timeout kill is ClientDead, not a crash: {err:?}"
    );
    assert!(
        err.is_fatal_client_death(),
        "a timeout kill must be a fatal client death: {err:?}"
    );
    assert!(
        elapsed >= Duration::from_secs(25),
        "hung call took {elapsed:?}, want the 30s worker deadline to actually bound it"
    );
    assert!(
        elapsed < Duration::from_secs(40),
        "hung call took {elapsed:?}, want ~30s, not a hang"
    );
    let fused = host
        .fused("hungfuse")
        .expect("timeout kill must fuse the host");
    eprintln!("hungfuse fused: {fused}");
    assert!(
        fused.contains("timed out"),
        "host fuse reason must carry the timeout: {fused}"
    );
    assert!(
        host.loaded("hungfuse").is_none(),
        "timeout-killed plugin must not stay loaded"
    );
    assert!(
        worker_pids().is_empty(),
        "hungfuse worker lingers after the timeout kill: {:?}",
        worker_pids()
    );
    let report = load(&host, "hungfuse", &so);
    assert_eq!(report.loaded.len(), 0);
    assert_eq!(report.skipped.len(), 1);
    let reason = &report.skipped[0].reason;
    eprintln!("hungfuse re-apply: skipped: {reason}");
    assert!(
        reason.contains("fused:") && reason.contains("timed out"),
        "re-apply must skip as fused with the timeout reason, not reconfigure: {reason}"
    );
    assert!(
        worker_pids().is_empty(),
        "re-apply spawned a worker for a fused plugin: {:?}",
        worker_pids()
    );
    host.close();
    control_echo_ok();
}

/// (B1) A plugin that trickles a frame (valid 1 MiB
/// length prefix, then 1 byte every 25s) must be
/// killed at the 30s transact deadline — the call
/// returns a timeout error in ~30s, never after
/// ~16M x 30s, and the worker is reaped.
#[test]
fn live_slow_drip_timeout() {
    // Serialised: see `LIVE_LOCK`.
    let _live_guard = LIVE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let Some(so) = build_plugin("drip", &plugin_source("drip", 1, 0, DRIP_BODY, "")) else {
        return;
    };
    let host = make_host(None);
    let report = load(&host, "drip", &so);
    assert!(report.skipped.is_empty(), "drip load: {:?}", report.skipped);
    // The 45s Host deadline is only a backstop so a
    // regression hangs the test for 45s instead of
    // forever; the 30s worker transact must fire first.
    let start = Instant::now();
    let err = host
        .call(
            "drip",
            METHOD_PROVIDER_CALL,
            b"{\"input\":\"ping\"}",
            Some(Duration::from_secs(45)),
        )
        .expect_err("drip call must fail");
    let elapsed = start.elapsed();
    eprintln!("drip call: {err} after {elapsed:?}");
    assert!(
        err.to_string().contains("timed out"),
        "drip must fail as a timeout, not a hang or crash: {err}"
    );
    assert!(
        elapsed < Duration::from_secs(40),
        "drip call took {elapsed:?}, want ~30s (deadline enforced inside the frame read)"
    );
    assert!(
        elapsed >= Duration::from_secs(25),
        "drip call took {elapsed:?}, want the deadline to actually bound the trickle"
    );
    host.close();
    assert!(
        worker_pids().is_empty(),
        "drip worker lingers after the timeout kill: {:?}",
        worker_pids()
    );
    control_echo_ok();
}

/// (B2) A plugin background thread forging a reply
/// frame onto fd 1 must never stand in for the real
/// reply: the parent rejects any frame whose op is
/// not exactly `"reply"` or whose id does not match
/// the outstanding call, with a protocol error —
/// never the forged bytes, never the real reply.
#[test]
fn live_forged_reply_rejected() {
    // Serialised: see `LIVE_LOCK`.
    let _live_guard = LIVE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // The two variants must fail with DISTINCT
    // messages (fix loop 2, technical N1): the op
    // check and the id check are separate gates, and
    // the old test asserted only their shared
    // "plugin worker sent" prefix, so deleting the op
    // check would still have passed it. (A correct-id
    // forgery is not constructible from the plugin
    // side — the id is a random 64-bit value the
    // plugin cannot observe — so the op check is
    // pinned by the message, not by a live forgery.)
    // Both kills must also fuse the host (NB1).
    for (name, op, expected) in [
        ("forgereply", "reply", "unexpected frame"),
        ("forgebogus", "bogus", "non-reply frame"),
    ] {
        let Some(so) = build_plugin(name, &plugin_source(name, 1, 0, &forge_body(op, 12345), ""))
        else {
            return;
        };
        let host = make_host(None);
        let report = load(&host, name, &so);
        assert!(
            report.skipped.is_empty(),
            "{name} load: {:?}",
            report.skipped
        );
        let err = host
            .call(
                name,
                METHOD_PROVIDER_CALL,
                b"{\"input\":\"ping\"}",
                Some(Duration::from_secs(30)),
            )
            .expect_err("forged reply must fail");
        eprintln!("{name} call: {err}");
        assert!(
            err.to_string().contains(expected),
            "{name} must fail with the {expected:?} message (op check vs id check): {err}"
        );
        assert!(
            !err.to_string().contains("FORGED"),
            "{name}: forged bytes were accepted: {err}"
        );
        let fused = host
            .fused(name)
            .unwrap_or_else(|| panic!("{name} protocol kill must fuse the host"));
        eprintln!("{name} fused: {fused}");
        assert!(
            fused.contains("plugin worker sent"),
            "host fuse reason must carry the protocol kill: {fused}"
        );
        assert!(
            host.loaded(name).is_none(),
            "{name}: protocol-killed plugin must not stay loaded"
        );
        host.close();
    }
    control_echo_ok();
}

/// (B5) An oversized HOST request is a clean size
/// error, not a crash: a 13 MiB `provider.call`
/// input is refused with "plugin worker frame too
/// large", the worker stays alive, and the next
/// small call succeeds. A 12.5 MiB input (below the
/// effective ~12.58 MiB decoded cap) succeeds.
/// The cap is base64-driven: a 16 MiB frame holds
/// at most (16 MiB - 64..83 bytes of JSON overhead)
/// of base64, i.e. 12,582,849..12,582,864 decoded
/// bytes depending on the call-id digit count
/// (worker.rs `call_frame_overhead_is_pinned`).
#[test]
fn live_oversize_host_request() {
    // Serialised: see `LIVE_LOCK`.
    let _live_guard = LIVE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let Some(so) = build_plugin("bigreq", &plugin_source("bigreq", 1, 0, BIGREQ_BODY, "")) else {
        return;
    };
    let host = make_host(None);
    let report = load(&host, "bigreq", &so);
    assert!(
        report.skipped.is_empty(),
        "bigreq load: {:?}",
        report.skipped
    );
    // 12.5 MiB: below the cap, must succeed.
    let big_ok = vec![b'x'; 12_500_000];
    let out = host
        .call(
            "bigreq",
            METHOD_PROVIDER_CALL,
            &big_ok,
            Some(Duration::from_secs(30)),
        )
        .expect("12.5 MiB request must succeed");
    assert!(
        String::from_utf8_lossy(&out).contains("big-ok"),
        "12.5 MiB result: {}",
        String::from_utf8_lossy(&out)
    );
    eprintln!("bigreq 12.5 MiB: ok");
    // 13 MiB: over the cap, must fail cleanly.
    let big_bad = vec![b'x'; 13_000_000];
    let err = host
        .call(
            "bigreq",
            METHOD_PROVIDER_CALL,
            &big_bad,
            Some(Duration::from_secs(30)),
        )
        .expect_err("13 MiB request must fail");
    eprintln!("bigreq 13 MiB: {err}");
    assert!(
        err.to_string().contains("plugin worker frame too large"),
        "13 MiB must fail as a size error: {err}"
    );
    assert!(
        is_crash(&err).is_none(),
        "oversize request must not be reported as a crash: {err}"
    );
    assert!(
        host.fused("bigreq").is_none(),
        "oversize request must not fuse the client"
    );
    assert!(
        !err.is_fatal_client_death(),
        "oversize request must not be a fatal client death (worker alive): {err:?}"
    );
    // The worker is alive: the next small call works.
    let out = host
        .call(
            "bigreq",
            METHOD_PROVIDER_CALL,
            b"{\"input\":\"ping\"}",
            Some(Duration::from_secs(30)),
        )
        .expect("small call after an oversize request");
    assert!(
        String::from_utf8_lossy(&out).contains("big-ok"),
        "small call after oversize: {}",
        String::from_utf8_lossy(&out)
    );
    host.close();
    control_echo_ok();
}

/// (B5 mirror) An oversized WORKER reply is a clean
/// `oversize_response` error frame, not a 30s timeout
/// and not a signal-9 kill of a healthy worker: a
/// plugin returning a ~13 MiB payload fails fast with
/// the oversize error and stays alive for the next
/// call.
#[test]
fn live_oversize_worker_reply() {
    // Serialised: see `LIVE_LOCK`.
    let _live_guard = LIVE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // A small input returns a small envelope (so the
    // survival check below has a call that can
    // succeed); anything else returns a ~13 MiB
    // payload.
    let big_body = r#"	var in struct {
		Input string `json:"input"`
	}
	_ = json.Unmarshal(C.GoBytes(unsafe.Pointer(req), C.int(reqLen)), &in)
	if in.Input == "small" {
		out, _ := json.Marshal(map[string]string{"payload": "small-ok"})
		*resp = allocResp(envelope(out))
		return 0
	}
	big, _ := json.Marshal(map[string]string{"payload": ""})
	// Build a ~13 MiB payload string.
	pad := make([]byte, 13*1024*1024)
	for i := range pad {
		pad[i] = 'x'
	}
	_ = big
	out, _ := json.Marshal(map[string]string{"payload": string(pad)})
	*resp = allocResp(envelope(out))
	return 0"#;
    let Some(so) = build_plugin("bigresp", &plugin_source("bigresp", 1, 0, big_body, "")) else {
        return;
    };
    let host = make_host(None);
    let report = load(&host, "bigresp", &so);
    assert!(
        report.skipped.is_empty(),
        "bigresp load: {:?}",
        report.skipped
    );
    let start = Instant::now();
    let err = host
        .call(
            "bigresp",
            METHOD_PROVIDER_CALL,
            b"{\"input\":\"ping\"}",
            Some(Duration::from_secs(30)),
        )
        .expect_err("13 MiB response must fail");
    let elapsed = start.elapsed();
    eprintln!("bigresp call: {err} after {elapsed:?}");
    assert!(
        err.to_string().contains("oversize response"),
        "oversize reply must fail as an oversize error: {err}"
    );
    assert!(
        is_crash(&err).is_none(),
        "oversize reply must not be reported as a crash: {err}"
    );
    assert!(
        elapsed < Duration::from_secs(10),
        "oversize reply must fail fast, not after a 30s timeout: {elapsed:?}"
    );
    assert!(
        !err.is_fatal_client_death(),
        "oversize reply must not fuse the client (worker alive): {err:?}"
    );
    // The worker survives (fix loop 2, technical N4):
    // a follow-up small call on the same client works.
    let out = host
        .call(
            "bigresp",
            METHOD_PROVIDER_CALL,
            b"{\"input\":\"small\"}",
            Some(Duration::from_secs(30)),
        )
        .expect("small call after an oversize reply");
    assert!(
        String::from_utf8_lossy(&out).contains("small-ok"),
        "small call after oversize reply: {}",
        String::from_utf8_lossy(&out)
    );
    eprintln!("bigresp small follow-up: ok");
    host.close();
    control_echo_ok();
}

/// (B6) A plugin flooding `host.log` (100k calls in
/// one `provider.call`) is killed at the
/// per-transaction budget with a clear flood error;
/// the parent survives with bounded memory (no
/// accumulating sink is even attached here) and the
/// host stays usable afterwards.
#[test]
fn live_host_call_flood() {
    // Serialised: see `LIVE_LOCK`.
    let _live_guard = LIVE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let Some(so) = build_plugin("flood", &plugin_source("flood", 1, 0, FLOOD_BODY, "")) else {
        return;
    };
    let host = make_host(None);
    let report = load(&host, "flood", &so);
    assert!(
        report.skipped.is_empty(),
        "flood load: {:?}",
        report.skipped
    );
    let start = Instant::now();
    let err = host
        .call(
            "flood",
            METHOD_PROVIDER_CALL,
            b"{\"input\":\"ping\"}",
            Some(Duration::from_secs(30)),
        )
        .expect_err("host.log flood must fail");
    let elapsed = start.elapsed();
    eprintln!("flood call: {err} after {elapsed:?}");
    assert!(
        err.to_string().contains("host callback flood"),
        "flood must fail as a flood error: {err}"
    );
    assert!(
        elapsed < Duration::from_secs(30),
        "flood call took {elapsed:?}, want the budget to cut it off promptly"
    );
    // The flood kill must fuse the host (NB1), not
    // just return the flood error: the worker is dead.
    let fused = host.fused("flood").expect("flood kill must fuse the host");
    eprintln!("flood fused: {fused}");
    assert!(
        fused.contains("host callback flood"),
        "host fuse reason must carry the flood: {fused}"
    );
    assert!(
        host.loaded("flood").is_none(),
        "flood-killed plugin must not stay loaded"
    );
    host.close();
    control_echo_ok();
}

/// (B6 byte bound, fix loop 2) The 4 MiB
/// per-transaction byte bound is distinct from the
/// 1000-frame count bound: ONE `host.log` call
/// carrying a 5 MiB message must trip the flood kill
/// (count = 1, bytes > 4 MiB) and fuse the host with
/// the flood reason — the count bound never fires
/// here.
#[test]
fn live_host_call_byte_bound() {
    // Serialised: see `LIVE_LOCK`.
    let _live_guard = LIVE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let Some(so) = build_plugin("biglog", &plugin_source("biglog", 1, 0, BIGLOG_BODY, "")) else {
        return;
    };
    let host = make_host(None);
    let report = load(&host, "biglog", &so);
    assert!(
        report.skipped.is_empty(),
        "biglog load: {:?}",
        report.skipped
    );
    let start = Instant::now();
    let err = host
        .call(
            "biglog",
            METHOD_PROVIDER_CALL,
            b"{\"input\":\"ping\"}",
            Some(Duration::from_secs(30)),
        )
        .expect_err("5 MiB host.log must fail");
    let elapsed = start.elapsed();
    eprintln!("biglog call: {err} after {elapsed:?}");
    assert!(
        err.to_string().contains("host callback flood"),
        "one 5 MiB host.log must fail as a flood error: {err}"
    );
    assert!(
        elapsed < Duration::from_secs(30),
        "biglog call took {elapsed:?}, want the byte bound to cut it off promptly"
    );
    let fused = host
        .fused("biglog")
        .expect("byte-bound flood kill must fuse the host");
    eprintln!("biglog fused: {fused}");
    assert!(
        fused.contains("host callback flood"),
        "host fuse reason must carry the flood: {fused}"
    );
    assert!(
        host.loaded("biglog").is_none(),
        "flood-killed plugin must not stay loaded"
    );
    host.close();
    control_echo_ok();
}

/// (B4) A crash inside plugin `shutdown` is reported,
/// not swallowed: at the Host level
/// `shutdown_errors()` carries signal 11, and at the
/// CLI level `plugin check` exits non-zero, prints
/// `shutdown: crashed (signal 11)`, and never prints
/// `shutdown: ok`.
#[test]
fn live_shutdown_crash() {
    // Serialised: see `LIVE_LOCK`.
    let _live_guard = LIVE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let Some(so) = build_plugin(
        "shutdowncrash",
        &plugin_source_full(
            "shutdowncrash",
            1,
            0,
            ECHO_BODY,
            "",
            "",
            "C.crash_now()",
            "C.free(ptr)",
            "",
        ),
    ) else {
        return;
    };
    // Host level: the call works, the close reports
    // the shutdown crash.
    let host = make_host(None);
    let report = load(&host, "shutdowncrash", &so);
    assert!(
        report.skipped.is_empty(),
        "shutdowncrash load: {:?}",
        report.skipped
    );
    let out = host
        .call(
            "shutdowncrash",
            METHOD_PROVIDER_CALL,
            b"{\"input\":\"ping\"}",
            Some(Duration::from_secs(30)),
        )
        .expect("shutdowncrash call");
    assert_eq!(String::from_utf8_lossy(&out), "{\"payload\":\"echo:ping\"}");
    host.close();
    let errs = host.shutdown_errors();
    eprintln!("shutdowncrash shutdown_errors: {errs:?}");
    assert_eq!(errs.len(), 1, "one shutdown crash must be recorded");
    assert_eq!(errs[0].0, "shutdowncrash");
    assert_eq!(
        is_crash(&errs[0].1),
        Some(Some(11)),
        "shutdown crash must carry signal 11: {:?}",
        errs[0].1
    );
    // CLI level: `plugin check` must fail it.
    // A missing binary FAILS this test (fix loop 2,
    // technical N5 / red-team N10): in a full
    // workspace build it always exists, so its
    // absence means the test setup is broken — never
    // a silent skip.
    let Some(rs_bin) = castctl_rs_bin() else {
        panic!("no castctl-rs binary: run the full workspace build first (cargo test --workspace)");
    };
    let (code, stdout, stderr) = run_plugin_check(&rs_bin, &so);
    eprintln!("shutdowncrash plugin check: exit {code}\nstdout:\n{stdout}stderr:\n{stderr}");
    assert_ne!(code, 0, "plugin check must fail on a shutdown crash");
    assert!(
        stdout.contains("shutdown: crashed (signal 11)"),
        "plugin check must print the crash line: {stdout}"
    );
    assert!(
        !stdout.contains("shutdown: ok"),
        "plugin check must not print shutdown: ok for a crashing shutdown: {stdout}"
    );
    control_echo_ok();
}

/// (B7) Orphan worker on parent death: a helper parent
/// loads a hung plugin and starts a call; SIGKILLing
/// the parent mid-call must kill the worker within a
/// few seconds (`PR_SET_PDEATHSIG`), never leave it
/// orphaned.
#[test]
fn live_parent_death_kills_worker() {
    // Serialised: see `LIVE_LOCK`.
    let _live_guard = LIVE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let marker = scratch_dir("hung").join("called.txt");
    let _ = std::fs::remove_file(&marker);
    let hung_body = format!(
        r#"	os.WriteFile({marker:?}, []byte("called"), 0644)
	time.Sleep(120 * time.Second)
	var in struct {{
		Input string `json:"input"`
	}}
	_ = json.Unmarshal(C.GoBytes(unsafe.Pointer(req), C.int(reqLen)), &in)
	rep, _ := json.Marshal(map[string]string{{"payload": "echo:" + in.Input}})
	*resp = allocResp(envelope(rep))
	return 0"#,
        marker = marker
    );
    let Some(so) = build_plugin("hung", &plugin_source("hung", 1, 0, &hung_body, "")) else {
        return;
    };
    let mut helper = std::process::Command::new(worker_bin())
        .arg("__pdeath-test-parent")
        .arg(&so)
        .env_remove("CASTCTL_PLUGIN_WORKER_BIN")
        .spawn()
        .expect("spawn pdeath helper parent");
    let helper_pid = helper.id();
    // Wait for the hung call to start (marker written
    // by the plugin on call entry).
    let start = Instant::now();
    while !marker.exists() {
        if start.elapsed() > Duration::from_secs(30) {
            let _ = helper.kill();
            panic!("hung call never started (no marker after 30s)");
        }
        if let Ok(Some(status)) = helper.try_wait() {
            panic!("helper parent exited early with {status} (marker missing)");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    eprintln!(
        "hung call started after {elapsed:?}",
        elapsed = start.elapsed()
    );
    let workers = worker_pids_of(helper_pid);
    eprintln!("helper {helper_pid} workers: {workers:?}");
    assert_eq!(
        workers.len(),
        1,
        "helper must have exactly one worker child"
    );
    let worker_pid = workers[0];
    // SIGKILL the parent mid-call.
    let killed = std::process::Command::new("kill")
        .args(["-9", &helper_pid.to_string()])
        .status()
        .expect("run kill");
    assert!(killed.success(), "kill -9 helper failed");
    let _ = helper.wait();
    // The worker must die with the parent, promptly.
    let start = Instant::now();
    loop {
        if !std::path::Path::new(&format!("/proc/{worker_pid}")).exists() {
            break;
        }
        if start.elapsed() > Duration::from_secs(10) {
            // Do not leave an orphan behind on failure.
            let _ = std::process::Command::new("kill")
                .args(["-9", &worker_pid.to_string()])
                .status();
            panic!("worker {worker_pid} survived its parent's death for 10s (orphan)");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    eprintln!(
        "worker {worker_pid} died with its parent after {:?}",
        start.elapsed()
    );
    control_echo_ok();
}

/// (G4) The Go byte-parity claim, automated: the Go
/// and Rust `plugin check` on the same echo.so must
/// produce identical stdout, identical stderr, and
/// the same exit code. (Covers echo only — a plugin
/// that never calls `host.log` and has no
/// command-only branch; that limit stays recorded in
/// PORTING.)
#[test]
fn live_plugin_check_matches_go() {
    // Serialised: see `LIVE_LOCK`.
    let _live_guard = LIVE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let Some(echo) = build_echo() else { return };
    // A missing binary FAILS this test (fix loop 2,
    // technical N5 / red-team N10): in a full
    // workspace build it always exists, so its
    // absence means the test setup is broken — never
    // a silent skip.
    let Some(rs_bin) = castctl_rs_bin() else {
        panic!("no castctl-rs binary: run the full workspace build first (cargo test --workspace)");
    };
    let Some(go_bin_path) = go_castctl_bin() else {
        return;
    };
    let (rs_code, rs_out, rs_err) = run_plugin_check(&rs_bin, &echo);
    let (go_code, go_out, go_err) = run_plugin_check(&go_bin_path, &echo);
    eprintln!("rust plugin check: exit {rs_code}\n{rs_out}stderr:\n{rs_err}");
    eprintln!("go plugin check: exit {go_code}\n{go_out}stderr:\n{go_err}");
    assert_eq!(
        rs_code, go_code,
        "exit codes differ (rust {rs_code}, go {go_code})"
    );
    assert_eq!(rs_out, go_out, "plugin check stdout differs");
    assert_eq!(rs_err, go_err, "plugin check stderr differs");
    control_echo_ok();
}
