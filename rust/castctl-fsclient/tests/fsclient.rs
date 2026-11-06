// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Port of Go `internal/fsclient/fsclient_test.go` (14
//! test fns). One sub-assertion is not portable:
//! `TestFSGatewayErrorPropagates`' cancelled-context case
//! has no Rust equivalent (cancellation is by dropping
//! the future); it is recorded in PORTING.md §M7a, not
//! ported.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::error::Error;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine;
use castctl_fsclient::{
    Entry, Fs, FsError, FsGateway, WriteResult, decode_entries, go_json_string, norm,
    number_value,
};
use serde_json::{Value, json};

fn temp_dir(tag: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir =
        std::env::temp_dir().join(format!("castctl-fsclient-{tag}-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// One recorded `CallJSON` invocation.
#[derive(Debug, Clone)]
struct FakeCall {
    method: String,
    body: Value,
    timeout: Duration,
}

/// A sentinel error for the gateway-failure test (Go's
/// `errors.New("gateway down")` + `errors.Is`).
#[derive(Debug)]
struct SentinelError;

impl fmt::Display for SentinelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("gateway down")
    }
}

impl Error for SentinelError {}

struct FakeState {
    files: HashMap<String, Vec<u8>>,
    dirs: HashSet<String>,
    dir_kind: String,
    calls: Vec<FakeCall>,
    fail_method: Option<String>,
}

/// In-memory stand-in for `FsGateway` over `fs.*` routes
/// (Go `fakeGateway`, mirroring the `FakeGW` in
/// `test_fs.py`). Files map a normalized relative path to
/// bytes; dirs holds normalized directory paths (`""` is
/// the root).
struct FakeGateway {
    state: Mutex<FakeState>,
}

fn dir_of(p: &str) -> &str {
    match p.rfind('/') {
        Some(i) => &p[..i],
        None => "",
    }
}

fn base_of(p: &str) -> &str {
    match p.rfind('/') {
        Some(i) => &p[i + 1..],
        None => p,
    }
}

fn num_arg(body: &Value, key: &str) -> i64 {
    body.get(key).and_then(number_value).unwrap_or(0)
}

impl FakeGateway {
    fn new(files: &[(&str, &[u8])]) -> Arc<Self> {
        let mut state = FakeState {
            files: HashMap::new(),
            dirs: HashSet::new(),
            dir_kind: String::new(),
            calls: Vec::new(),
            fail_method: None,
        };
        state.dirs.insert(String::new());
        for (p, data) in files {
            state.files.insert(p.to_string(), data.to_vec());
            let parts: Vec<&str> = p.split('/').collect();
            for i in 1..parts.len() {
                state.dirs.insert(parts[..i].join("/"));
            }
        }
        Arc::new(FakeGateway {
            state: Mutex::new(state),
        })
    }

    fn dir_kind_of(state: &FakeState) -> String {
        if state.dir_kind.is_empty() {
            "dir".to_string()
        } else {
            state.dir_kind.clone()
        }
    }

    fn set_dir_kind(&self, kind: &str) {
        self.state.lock().unwrap().dir_kind = kind.to_string();
    }

    fn set_fail(&self, method: &str) {
        self.state.lock().unwrap().fail_method = Some(method.to_string());
    }

    fn calls(&self) -> Vec<FakeCall> {
        self.state.lock().unwrap().calls.clone()
    }

    fn clear_calls(&self) {
        self.state.lock().unwrap().calls.clear();
    }

    fn file(&self, path: &str) -> Option<Vec<u8>> {
        self.state.lock().unwrap().files.get(path).cloned()
    }
}

impl FsGateway for FakeGateway {
    fn call_json(
        &self,
        method: &str,
        body: Value,
        timeout: Duration,
    ) -> Pin<Box<dyn Future<Output = Result<Value, FsError>> + Send + '_>> {
        let method = method.to_string();
        Box::pin(async move {
            let mut state = self.state.lock().unwrap();
            state.calls.push(FakeCall {
                method: method.clone(),
                body: body.clone(),
                timeout,
            });
            if state.fail_method.as_deref() == Some(method.as_str()) {
                return Err(FsError::Other(Arc::new(SentinelError)));
            }
            let p = body
                .get("path")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            match method.as_str() {
                "fs.list" => {
                    let mut names: BTreeMap<String, Value> = BTreeMap::new();
                    for (file, data) in &state.files {
                        if dir_of(file) == p {
                            names.insert(
                                base_of(file).to_string(),
                                json!({"name": base_of(file), "type": "file", "size": data.len() as i64}),
                            );
                        }
                    }
                    for d in &state.dirs {
                        if !d.is_empty() && dir_of(d) == p {
                            names.insert(
                                base_of(d).to_string(),
                                json!({"name": base_of(d), "type": "directory"}),
                            );
                        }
                    }
                    let entries: Vec<Value> = names.into_values().collect();
                    Ok(json!({"path": p, "entries": entries}))
                }
                "fs.stat" => {
                    let kind = if state.dirs.contains(&p) {
                        Self::dir_kind_of(&state)
                    } else {
                        "file".to_string()
                    };
                    Ok(json!({"path": format!("/{p}"), "kind": kind}))
                }
                "fs.read" => {
                    let data = state.files.get(&p).cloned().unwrap_or_default();
                    let mut off = num_arg(&body, "offset");
                    let length = num_arg(&body, "len");
                    if off < 0 {
                        off = 0;
                    }
                    if off > data.len() as i64 {
                        off = data.len() as i64;
                    }
                    let end = std::cmp::min(off + length, data.len() as i64);
                    let chunk = &data[off as usize..end as usize];
                    Ok(json!({
                        "data_base64": base64::engine::general_purpose::STANDARD.encode(chunk),
                        "eof": end >= data.len() as i64,
                    }))
                }
                "fs.write" => {
                    let encoded = body
                        .get("data_base64")
                        .and_then(Value::as_str)
                        .unwrap_or("");
                    let data = base64::engine::general_purpose::STANDARD
                        .decode(encoded)
                        .map_err(|e| FsError::msg(e.to_string()))?;
                    let append = body.get("append").and_then(Value::as_bool).unwrap_or(false);
                    if append {
                        state
                            .files
                            .entry(p.clone())
                            .or_default()
                            .extend_from_slice(&data);
                    } else {
                        state.files.insert(p.clone(), data.clone());
                    }
                    let mut d = dir_of(&p).to_string();
                    while !d.is_empty() {
                        state.dirs.insert(d.clone());
                        d = dir_of(&d).to_string();
                    }
                    Ok(json!({"path": format!("/{p}"), "bytes_written": data.len() as i64}))
                }
                "fs.mkdir" => {
                    state.dirs.insert(p.clone());
                    Ok(json!({"path": format!("/{p}"), "created": true}))
                }
                "fs.rename" => {
                    let src = body
                        .get("source")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string();
                    let dst = body
                        .get("destination")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string();
                    if let Some(data) = state.files.remove(&src) {
                        state.files.insert(dst.clone(), data);
                        return Ok(json!({"path": format!("/{dst}")}));
                    }
                    if state.dirs.contains(&src) {
                        state.dirs.remove(&src);
                        state.dirs.insert(dst.clone());
                        let moved: Vec<(String, Vec<u8>)> = state
                            .files
                            .iter()
                            .filter(|(f, _)| f.starts_with(&format!("{src}/")))
                            .map(|(f, d)| (format!("{dst}{}", &f[src.len()..]), d.clone()))
                            .collect();
                        for old in state
                            .files
                            .keys()
                            .filter(|f| f.starts_with(&format!("{src}/")))
                            .cloned()
                            .collect::<Vec<_>>()
                        {
                            state.files.remove(&old);
                        }
                        for (path, data) in moved {
                            state.files.insert(path, data);
                        }
                        return Ok(json!({"path": format!("/{dst}")}));
                    }
                    Err(FsError::msg(format!("no such path: {src}")))
                }
                "fs.delete" => {
                    let recursive = body
                        .get("recursive")
                        .and_then(Value::as_bool)
                        .unwrap_or(false);
                    if state.files.remove(&p).is_some() {
                        return Ok(json!({"path": format!("/{p}")}));
                    }
                    if state.dirs.contains(&p) {
                        if !recursive {
                            let has_child =
                                state.files.keys().any(|f| f.starts_with(&format!("{p}/")));
                            if has_child {
                                return Err(FsError::msg(format!("directory not empty: {p}")));
                            }
                        }
                        state.files.retain(|f, _| !f.starts_with(&format!("{p}/")));
                        state.dirs.remove(&p);
                        return Ok(json!({"path": format!("/{p}")}));
                    }
                    Err(FsError::msg(format!("no such path: {p}")))
                }
                "fs.search" => {
                    let contains = body
                        .get("name")
                        .and_then(|n| n.get("contains"))
                        .and_then(Value::as_str)
                        .unwrap_or("");
                    let limit = num_arg(&body, "limit");
                    let mut paths: Vec<String> = Vec::new();
                    for file in state.files.keys() {
                        if base_of(file).contains(contains) {
                            paths.push(file.clone());
                        }
                    }
                    for d in &state.dirs {
                        if !d.is_empty() && base_of(d).contains(contains) {
                            paths.push(d.clone());
                        }
                    }
                    paths.sort();
                    if limit > 0 && paths.len() as i64 > limit {
                        paths.truncate(limit as usize);
                    }
                    let entries: Vec<Value> = paths
                        .iter()
                        .map(|pth| {
                            let typ = if state.dirs.contains(pth) {
                                "directory"
                            } else {
                                "file"
                            };
                            json!({"name": base_of(pth), "type": typ, "path": pth})
                        })
                        .collect();
                    Ok(json!({"entries": entries}))
                }
                _ => Err(FsError::msg(format!("unexpected method {method}"))),
            }
        })
    }
}

/// A gateway that strips the `eof` flag from `fs.read`
/// results (Go `eofStrippingGateway`).
struct EofStrippingGateway {
    inner: Arc<FakeGateway>,
}

impl FsGateway for EofStrippingGateway {
    fn call_json(
        &self,
        method: &str,
        body: Value,
        timeout: Duration,
    ) -> Pin<Box<dyn Future<Output = Result<Value, FsError>> + Send + '_>> {
        let method = method.to_string();
        let inner = Arc::clone(&self.inner);
        Box::pin(async move {
            let mut res = inner.call_json(&method, body, timeout).await?;
            if let Some(obj) = res.as_object_mut() {
                obj.remove("eof");
            }
            Ok(res)
        })
    }
}

/// A gateway that always answers `fs.read` with invalid
/// base64 (Go `badBase64Gateway`).
struct BadBase64Gateway;

impl FsGateway for BadBase64Gateway {
    fn call_json(
        &self,
        _method: &str,
        _body: Value,
        _timeout: Duration,
    ) -> Pin<Box<dyn Future<Output = Result<Value, FsError>> + Send + '_>> {
        Box::pin(async move { Ok(json!({"data_base64": "!!!not-base64!!!", "eof": true})) })
    }
}

fn new_fs(gw: Arc<FakeGateway>) -> Fs<FakeGateway> {
    Fs::new(Some(gw))
}

#[test]
fn norm_cases() {
    let cases = [
        ("/", ""),
        ("", ""),
        ("/config/home.yaml", "config/home.yaml"),
        ("sandbox://workspace/a.txt", "workspace/a.txt"),
        ("a//b/./c/", "a/b/c"),
        ("  /a/b  ", "a/b"),
        (r"a\b\c", "a/b/c"),
        (r"sandbox://workspace\a.txt", "workspace/a.txt"),
        (".", ""),
        ("./a", "a"),
        ("a/./b/../c", "a/c"),
    ];
    for (input, want) in cases {
        let got = norm(input).unwrap();
        assert_eq!(got, want, "norm({input:?})");
    }
}

#[test]
fn norm_traversal_is_clamped() {
    // Port of test_fs.py NormTest.test_traversal_is_clamped:
    // normpath on a rooted path clamps ".." away, so
    // "../etc" becomes "etc" instead of erroring.
    for (input, want) in [
        ("../etc", "etc"),
        ("a/../../etc", "etc"),
        ("..", ""),
        ("a/..", ""),
    ] {
        let got = norm(input).unwrap();
        assert_eq!(got, want, "norm({input:?})");
    }
}

#[tokio::test]
async fn fs_method_names_match_routes() {
    // The method names FS uses must be the routes.json
    // names: fs.rename, not fs.move. Verified through the
    // real route table, not a hardcoded copy.
    let tbl = castctl_transport::routes::RouteTable::default_routes().unwrap();
    let want: [(&str, &str, &str); 8] = [
        ("fs.list", "POST", "/fs/list"),
        ("fs.read", "POST", "/fs/read"),
        ("fs.stat", "POST", "/fs/stat"),
        ("fs.search", "POST", "/fs/search"),
        ("fs.write", "POST", "/fs/write"),
        ("fs.mkdir", "POST", "/fs/mkdir"),
        ("fs.rename", "POST", "/fs/rename"),
        ("fs.delete", "POST", "/fs/delete"),
    ];
    for (method, http, path) in want {
        let r = tbl
            .lookup_route(method)
            .unwrap_or_else(|| panic!("LookupRoute({method:?}) = false, want a route"));
        assert_eq!((r.http.as_str(), r.path.as_str()), (http, path));
    }
    assert!(
        tbl.lookup_route("fs.move").is_none(),
        "LookupRoute(fs.move) must be false: the move operation calls fs.rename"
    );
    // And FS must actually call those names: drive each
    // method once through the fake and check the recorded
    // methods.
    let gw = FakeGateway::new(&[("a.txt", b"x")]);
    let f = new_fs(Arc::clone(&gw));
    let _ = f.list_dir("").await;
    let _ = f.stat("a.txt").await;
    let _ = f.read_chunk("a.txt", 0, 1).await;
    let _ = f.search("a", 0).await;
    let _ = f.write_file("b.txt", b"y", true, true).await;
    let _ = f.mkdir("d", true).await;
    let _ = f.move_path("a.txt", "c.txt", false, true).await;
    let _ = f.delete("c.txt", false).await;
    let methods: Vec<String> = gw.calls().iter().map(|c| c.method.clone()).collect();
    assert_eq!(
        methods,
        vec![
            "fs.list",
            "fs.stat",
            "fs.read",
            "fs.search",
            "fs.write",
            "fs.mkdir",
            "fs.rename",
            "fs.delete"
        ]
    );
}

#[tokio::test]
async fn fs_list_and_walk() {
    let gw = FakeGateway::new(&[("config/home.yaml", b"x"), ("memory/a/b.md", b"y")]);
    let f = new_fs(Arc::clone(&gw));
    let entries = f.list_dir("/").await.unwrap();
    let names: Vec<String> = entries.iter().map(|e| e.name.clone()).collect();
    assert_eq!(names, vec!["config".to_string(), "memory".to_string()]);
    let all = f.walk("", -1).await.unwrap();
    let rels: Vec<&str> = all.iter().map(|we| we.rel.as_str()).collect();
    assert!(rels.contains(&"memory/a/b.md"), "walk rels = {rels:?}");
    let shallow = f.walk("", 2).await.unwrap();
    let shallow_rels: Vec<&str> = shallow.iter().map(|we| we.rel.as_str()).collect();
    assert!(
        !shallow_rels.contains(&"memory/a/b.md"),
        "walk depth=2 rels = {shallow_rels:?}"
    );
    // Depth 1 yields only top-level children.
    let one = f.walk("", 1).await.unwrap();
    for we in &one {
        assert_eq!(we.level, 0, "walk depth=1 level for {}", we.rel);
    }
}

#[tokio::test]
async fn fs_chunked_read_and_write() {
    let gw = FakeGateway::new(&[("f.bin", b"0123456789")]);
    let f = Fs::with_chunk_sizes(Some(Arc::clone(&gw)), 3, 3);
    let got = f.read_file("f.bin", None).await.unwrap();
    assert_eq!(got, b"0123456789");
    let got = f.read_file("f.bin", Some(4)).await.unwrap();
    assert_eq!(got, b"0123");
    let res = f
        .write_file("g.bin", b"abcdefgh", true, true)
        .await
        .unwrap();
    assert_eq!(gw.file("g.bin").unwrap(), b"abcdefgh");
    assert_eq!(res.path, "/g.bin");
    assert_eq!(res.bytes_written, 8);
    let mut appends = Vec::new();
    let mut overwrites = Vec::new();
    let mut timeouts = Vec::new();
    for c in gw.calls() {
        if c.method == "fs.write" {
            appends.push(c.body.get("append").and_then(Value::as_bool).unwrap());
            overwrites.push(c.body.get("overwrite").and_then(Value::as_bool).unwrap());
            timeouts.push(c.timeout);
        }
    }
    assert_eq!(appends, vec![false, true, true]);
    assert_eq!(overwrites, vec![true, true, true]);
    for to in &timeouts {
        assert_eq!(*to, Duration::from_secs(120));
    }
    // First-chunk overwrite=false is honoured only on the first chunk.
    let gw2 = FakeGateway::new(&[]);
    let f2 = Fs::with_chunk_sizes(Some(Arc::clone(&gw2)), 3, 3);
    f2.write_file("h.bin", b"abcdef", false, false)
        .await
        .unwrap();
    let mut ow2 = Vec::new();
    let mut cp2 = Vec::new();
    for c in gw2.calls() {
        if c.method == "fs.write" {
            ow2.push(c.body.get("overwrite").and_then(Value::as_bool).unwrap());
            cp2.push(
                c.body
                    .get("create_parent")
                    .and_then(Value::as_bool)
                    .unwrap(),
            );
        }
    }
    assert_eq!(ow2, vec![false, true]);
    assert_eq!(cp2, vec![false, false]);
    // Empty data still makes exactly one (empty) call.
    let gw3 = FakeGateway::new(&[]);
    let f3 = new_fs(Arc::clone(&gw3));
    let res = f3.write_file("e.bin", &[], true, true).await.unwrap();
    assert_eq!(res.bytes_written, 0);
    assert_eq!(res.path, "/e.bin");
    assert_eq!(gw3.calls().len(), 1);
    // Read timeout is 120s; other calls use 60s.
    for c in gw.calls() {
        if c.method == "fs.read" {
            assert_eq!(c.timeout, Duration::from_secs(120));
        }
        if c.method == "fs.list" {
            assert_eq!(c.timeout, Duration::from_secs(60));
        }
    }
}

#[tokio::test]
async fn fs_read_file_max_bytes_edges() {
    let gw = FakeGateway::new(&[("f.bin", b"0123")]);
    let f = new_fs(Arc::clone(&gw));
    let got = f.read_file("f.bin", Some(0)).await.unwrap();
    assert!(got.is_empty());
    assert_eq!(gw.calls().len(), 0, "max_bytes=0 must make 0 calls");
    let got = f.read_file("f.bin", Some(-5)).await.unwrap();
    assert!(got.is_empty());
    assert_eq!(gw.calls().len(), 0, "max_bytes=-5 must make 0 calls");
}

#[tokio::test]
async fn fs_read_chunk_eof_default_and_bad_base64() {
    let gw = FakeGateway::new(&[("f.bin", b"abc")]);
    // The fake always sends eof; strip it via a wrapper
    // gateway to prove the default-true rule.
    let stripping = EofStrippingGateway {
        inner: Arc::clone(&gw),
    };
    let f2 = Fs::new(Some(Arc::new(stripping)));
    let (data, eof) = f2.read_chunk("f.bin", 0, 3).await.unwrap();
    assert_eq!(data, b"abc");
    assert!(eof, "ReadChunk without eof must default to true");
    let f3 = Fs::new(Some(Arc::new(BadBase64Gateway)));
    assert!(f3.read_chunk("f.bin", 0, 3).await.is_err());
}

#[tokio::test]
#[cfg(unix)]
async fn fs_put_symlink_to_dir_root_uploads_nothing() {
    // Red-team F2: Go's `filepath.WalkDir` Lstats the
    // root, so a symlink-to-directory root is skipped
    // and nothing is uploaded (`fsclient.go:707-738`).
    let gw = FakeGateway::new(&[]);
    let f = new_fs(Arc::clone(&gw));
    let root = temp_dir("put-symlink-root");
    let real_dir = root.join("real");
    std::fs::create_dir_all(&real_dir).unwrap();
    std::fs::write(real_dir.join("a.txt"), b"A").unwrap();
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&real_dir, root.join("linkdir")).unwrap();
    }
    let res = f
        .put(&root.join("linkdir"), "remote/up", true, true)
        .await
        .unwrap();
    assert!(
        res.is_empty(),
        "symlink-to-dir root must upload nothing, got {res:?}"
    );
    assert!(
        gw.calls().is_empty(),
        "symlink-to-dir root must make zero remote writes, got {:?}",
        gw.calls()
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn fs_put_skips_symlink_to_dir() {
    let gw = FakeGateway::new(&[]);
    let f = new_fs(Arc::clone(&gw));
    let root = temp_dir("put-symlink");
    let real_dir = root.join("real");
    std::fs::create_dir_all(&real_dir).unwrap();
    std::fs::write(real_dir.join("a.txt"), b"A").unwrap();
    std::fs::write(root.join("target.txt"), b"T").unwrap();
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&real_dir, root.join("linkdir")).unwrap();
        std::os::unix::fs::symlink(root.join("target.txt"), root.join("linkfile.txt")).unwrap();
    }
    let _res = f.put(&root, "remote/up", true, true).await.unwrap();
    assert_eq!(gw.file("remote/up/real/a.txt").unwrap(), b"A");
    assert!(
        gw.file("remote/up/linkdir").is_none(),
        "symlink-to-dir uploaded as a file"
    );
    assert!(
        gw.file("remote/up/linkdir/a.txt").is_none(),
        "symlink-to-dir descended: remote/up/linkdir/a.txt exists, want it skipped"
    );
    assert_eq!(gw.file("remote/up/linkfile.txt").unwrap(), b"T");
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn fs_get_and_put_recursive() {
    let gw = FakeGateway::new(&[("memory/a.md", b"A"), ("memory/sub/b.md", b"B")]);
    let f = new_fs(Arc::clone(&gw));
    let dir = temp_dir("get-put");
    let got = f.get("memory", &dir, true).await.unwrap();
    assert_eq!(got.len(), 2, "get returned {got:?}, want 2 paths");
    let content = std::fs::read(dir.join("memory").join("sub").join("b.md")).unwrap();
    assert_eq!(content, b"B");
    let err = f.get("memory", &dir, false).await.unwrap_err();
    assert!(
        err.to_string().contains("is a folder; use -r"),
        "get folder error = {err}"
    );
    f.put(&dir.join("memory"), "data/copy", true, true)
        .await
        .unwrap();
    assert_eq!(gw.file("data/copy/sub/b.md").unwrap(), b"B");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn fs_get_file_and_put_file() {
    let gw = FakeGateway::new(&[("a.txt", b"hello")]);
    let f = new_fs(Arc::clone(&gw));
    let dir = temp_dir("get-file");
    // Destination is an existing directory: file lands inside it.
    let got = f.get("a.txt", &dir, false).await.unwrap();
    assert_eq!(got, vec![dir.join("a.txt")]);
    // Destination is an exact file path.
    let exact = dir.join("renamed.txt");
    let got = f.get("a.txt", &exact, false).await.unwrap();
    assert_eq!(got, vec![exact.clone()]);
    // Put a single file; "directory" kind spelling is also accepted.
    gw.set_dir_kind("directory");
    let res = f.put(&exact, "remote/copy.txt", false, true).await.unwrap();
    assert_eq!(res.len(), 1);
    assert_eq!(res[0].path, "/remote/copy.txt");
    assert_eq!(res[0].bytes_written, 5);
    // Put a folder without -r errors naming the local path.
    let err = f.put(&dir, "remote/x", false, true).await.unwrap_err();
    assert!(
        err.to_string().contains("is a folder; use -r"),
        "put folder error = {err}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn fs_move_delete_mkdir_stat_search() {
    let gw = FakeGateway::new(&[("a.txt", b"x"), ("b.log", b"y")]);
    let f = new_fs(Arc::clone(&gw));
    let st = f.stat("a.txt").await.unwrap();
    assert_eq!(st.get("kind").and_then(Value::as_str), Some("file"));
    f.mkdir("newdir", true).await.unwrap();
    f.move_path("a.txt", "newdir/a.txt", false, true)
        .await
        .unwrap();
    assert!(
        gw.file("newdir/a.txt").is_some(),
        "move did not create newdir/a.txt"
    );
    assert!(gw.file("a.txt").is_none(), "move left a.txt in fake");
    // Verify the move call body used fs.rename with source/destination.
    let rename_body = gw
        .calls()
        .into_iter()
        .find(|c| c.method == "fs.rename")
        .map(|c| c.body)
        .unwrap();
    assert_eq!(
        rename_body.get("source").and_then(Value::as_str),
        Some("a.txt")
    );
    assert_eq!(
        rename_body.get("destination").and_then(Value::as_str),
        Some("newdir/a.txt")
    );
    f.delete("b.log", false).await.unwrap();
    assert!(gw.file("b.log").is_none(), "delete left b.log in fake");
    let results = f.search("a.txt", 0).await.unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].name, "a.txt");
    // Search limit is sent only when positive.
    gw.clear_calls();
    let _ = f.search("a", 1).await;
    assert!(
        gw.calls()[0].body.get("limit").is_some(),
        "search limit=1 body must have limit key"
    );
    gw.clear_calls();
    let _ = f.search("a", 0).await;
    assert!(
        gw.calls()[0].body.get("limit").is_none(),
        "search limit=0 body must have no limit key"
    );
}

#[tokio::test]
async fn fs_gateway_error_propagates() {
    let gw = FakeGateway::new(&[]);
    gw.set_fail("fs.list");
    let f = new_fs(Arc::clone(&gw));
    let err = f.list_dir("").await.unwrap_err();
    assert!(
        err.other_as::<SentinelError>().is_some(),
        "ListDir error = {err}, want the sentinel"
    );
    let err = Fs::<FakeGateway>::new(None).list_dir("").await.unwrap_err();
    assert!(
        err.to_string().contains("nil gateway"),
        "nil gateway ListDir error = {err}"
    );
    // NOTE (not ported): Go also asserts a cancelled
    // context errors. Rust has no context: cancellation
    // is by dropping the future. See PORTING.md §M7a.
}

#[test]
fn entry_marshal_json() {
    let mut extra = std::collections::BTreeMap::new();
    extra.insert("owner".to_string(), json!("boss"));
    let e = Entry {
        name: "a.txt".to_string(),
        entry_type: "file".to_string(),
        size: Some(12),
        modified_at: "2026-10-24T12:57:37".to_string(),
        extra,
    };
    assert_eq!(
        e.to_json(),
        r#"{"name":"a.txt","type":"file","size":12,"modifiedAt":"2026-10-24T12:57:37","owner":"boss"}"#
    );
    // Absent optionals are omitted, as Python's missing keys are.
    assert_eq!(
        Entry {
            name: "d".to_string(),
            ..Default::default()
        }
        .to_json(),
        r#"{"name":"d"}"#
    );
}

#[test]
fn write_result_json() {
    let r = WriteResult {
        path: "/g.bin".to_string(),
        bytes_written: 8,
    };
    assert_eq!(r.to_json(), r#"{"path":"/g.bin","bytes_written":8}"#);
}

/// Go `encoding/json` short escapes (PR-2: the R3-B1 bug
/// class — `go_json_string` rendered `\u0008`/`\u000c`
/// where Go emits `\b`/`\f`). Expected values are Go
/// `json.Marshal` literals, not recomputed here.
#[test]
fn go_json_string_backspace_formfeed() {
    assert_eq!(go_json_string("\u{8}"), "\"\\b\"");
    assert_eq!(go_json_string("\u{c}"), "\"\\f\"");
    // The other short escapes were already correct.
    assert_eq!(go_json_string("\n\r\t"), "\"\\n\\r\\t\"");
    // An entry name carrying a control char renders
    // through the same escaper (server-controlled names).
    assert_eq!(
        Entry {
            name: "a\u{8}b".to_string(),
            ..Default::default()
        }
        .to_json(),
        r#"{"name":"a\bb"}"#
    );
}

#[test]
fn decode_entries_shapes() {
    // Missing entries key yields no entries.
    assert!(
        decode_entries(&json!({"path": "/"}), "fs.list")
            .unwrap()
            .is_empty()
    );
    // A non-object result is an error.
    assert!(decode_entries(&json!("junk"), "fs.list").is_err());
    // A non-object entry is an error.
    assert!(decode_entries(&json!({"entries": ["junk"]}), "fs.list").is_err());
}
