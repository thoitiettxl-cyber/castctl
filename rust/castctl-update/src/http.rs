// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Synchronous HTTP fetcher for the update flow.
//!
//! Go source: `newUpdateClient` / `fetchBytes` / `downloadAsset`
//! (`internal/update/update.go:383-570`). The Go client is the
//! stdlib `http.Client` with a cloned default transport (dial
//! 10s, keepalive 30s, TLS handshake 10s, response-header 30s,
//! expect-continue 1s), no proxy env, no credentials, no jar,
//! and the `checkRedirectPolicy` redirect policy.
//!
//! This port is a small synchronous HTTP/1.1 client over
//! `TcpStream` (+ `rustls` for `https`), because the update
//! flow is synchronous and no async HTTP client crate is in
//! the workspace for blocking use. It implements exactly the
//! behaviours the flow depends on: GET with `User-Agent:
//! castctl/<version>` and `Accept: application/vnd.github+json`
//! (removed on the download leg), redirect following under
//! `check_redirect_policy`, `Content-Length` and chunked
//! bodies, per-request timeouts, and the `classifyTransportError`
//! vocabulary. It never sends credentials and never consults
//! proxy environment variables.
//!
//! [DEVIATION] — TCP keepalive (Go: 30s) is not set: std's
//! `TcpStream` has no keepalive API and `socket2` is not in
//! the lock. Keepalive only affects idle-connection reuse;
//! this client sends `Connection: close` and opens a fresh
//! connection per request, so the observable behaviour is
//! unchanged.
//!
//! [DEVIATION] — the TLS handshake timeout (Go: 10s) is
//! enforced by the socket read timeout, not by a separate
//! handshake timer: a stalled handshake fails when the read
//! times out, with the same `"tls"` class.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use crate::error::{HttpError, UpdateError};
use crate::select::{
    ParsedUrl, TransportErrorKind, check_redirect_policy, classify_transport_error, parse_url,
};

/// Dial timeout. Source: `update.go:391` (10s).
pub const DIAL_TIMEOUT: Duration = Duration::from_secs(10);
/// Response-header timeout. Source: `update.go:393` (30s).
pub const RESPONSE_HEADER_TIMEOUT: Duration = Duration::from_secs(30);
/// Metadata request timeout. Source: `metadataTimeout = 60s`
/// (`update.go:50`).
pub const METADATA_TIMEOUT: Duration = Duration::from_secs(60);
/// Whole-asset download timeout. Source: `assetTimeout = 10m`
/// (`update.go:51`).
pub const ASSET_TIMEOUT: Duration = Duration::from_secs(600);
/// Maximum release-JSON bytes. Source: `maxReleaseJSONBytes`
/// (`update.go:34`).
pub const MAX_RELEASE_JSON_BYTES: usize = 1 << 20;
/// Maximum asset bytes. Source: `maxAssetBytes`
/// (`update.go:35`).
pub const MAX_ASSET_BYTES: u64 = 256 << 20;
/// Maximum checksums bytes. Source: `maxChecksumsBytes`
/// (`checksums.go:41`).
pub const MAX_CHECKSUMS_BYTES: usize = 64 * 1024;

/// One HTTP response: status, content length (when the server
/// sent one), and a streaming body. The body must be read to
/// completion (or dropped) before the next request.
pub struct Response {
    /// HTTP status code.
    pub status: u16,
    /// `Content-Length` when present and parseable.
    pub content_length: Option<u64>,
    /// The final URL after redirects (raw string).
    pub final_url: String,
    /// Streaming body reader.
    pub body: Box<dyn Read>,
}

/// The `Fetcher` seam: one GET with the update redirect
/// policy. Production uses [`StdFetcher`]; tests use the
/// real fetcher against a local loopback server (see
/// `tests/fetch.rs`), never a fake — the redirect policy,
/// userinfo refusal, and status mapping are all exercised
/// through real sockets.
pub trait Fetcher: Send {
    /// GET `url` with the update headers and redirect policy.
    /// `accept_api` selects the `Accept:
    /// application/vnd.github+json` header (metadata legs);
    /// the download leg passes `false`.
    fn get(
        &mut self,
        url: &str,
        user_agent: &str,
        accept_api: bool,
        timeout: Duration,
    ) -> Result<Response, HttpError>;

    /// GET `url` once, WITHOUT following redirects. Returns
    /// `(status, Location)`; the body is dropped. Used only
    /// by the `fallbackTag` probe (`update.go:855-908`),
    /// which must see the redirect response itself.
    fn get_no_follow(
        &mut self,
        url: &str,
        user_agent: &str,
        timeout: Duration,
    ) -> Result<(u16, Option<String>), HttpError>;
}

/// Build the shared rustls client config: Mozilla roots, no
/// client auth, ALPN `http/1.1`. Mirrors
/// `castctl_transport::tls_client_config` (same roots, same
/// ALPN); duplicated here because `castctl-update` must not
/// depend on the transport crate (different Go package).
fn tls_client_config() -> Arc<rustls::ClientConfig> {
    static CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let mut roots = rustls::RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let mut config = rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            config.alpn_protocols = vec![b"http/1.1".to_vec()];
            Arc::new(config)
        })
        .clone()
}

/// Synchronous fetcher over `TcpStream` (+ rustls for https).
/// No direct Go type counterpart: Go's `*http.Client` is the
/// stdlib; this is the Rust-side equivalent built from the
/// same parameters (`newUpdateClient`, `update.go:383-409`).
/// One response head: (status, content_length, chunked,
/// location, body).
type ResponseHead = (u16, Option<u64>, bool, Option<String>, Box<dyn Read>);

pub struct StdFetcher;

impl StdFetcher {
    /// Perform exactly one request (no redirect following).
    /// Returns `(status, content_length, chunked, location, body)`.
    fn request_once(
        url: &ParsedUrl,
        user_agent: &str,
        accept_api: bool,
        timeout: Duration,
    ) -> Result<ResponseHead, HttpError> {
        let mut stream = Self::connect(url, timeout)?;
        let path = if url.path.is_empty() {
            "/".to_string()
        } else {
            url.path.clone()
        };
        let mut req = format!(
            "GET {path} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {user_agent}\r\nConnection: close\r\n",
            url.authority()
        );
        if accept_api {
            req.push_str("Accept: application/vnd.github+json\r\n");
        }
        req.push_str("\r\n");
        stream
            .write_all(req.as_bytes())
            .and_then(|()| stream.flush())
            .map_err(|_| http_error_for(url, TransportErrorKind::Transport))?;
        let (status, content_length, chunked, location) = read_response_head(stream.as_mut(), url)?;
        let body: Box<dyn Read> = Box::new(BodyReader {
            inner: stream,
            state: if chunked {
                BodyState::Chunked {
                    remaining: 0,
                    done: false,
                }
            } else if let Some(len) = content_length {
                BodyState::Length(len)
            } else {
                BodyState::Close
            },
        });
        Ok((status, content_length, chunked, location, body))
    }

    fn connect(url: &ParsedUrl, timeout: Duration) -> Result<Box<dyn ReadWrite>, HttpError> {
        let host = url.host.clone();
        let port: u16 = if url.port.is_empty() {
            if url.scheme == "https" { 443 } else { 80 }
        } else {
            url.port.parse().unwrap_or(0)
        };
        let addrs: Vec<std::net::SocketAddr> = (host.as_str(), port)
            .to_socket_addrs()
            .map_err(|_| http_error_for(url, TransportErrorKind::Dns))?
            .collect();
        if addrs.is_empty() {
            return Err(http_error_for(url, TransportErrorKind::Dns));
        }
        let mut last_err: Option<std::io::Error> = None;
        for addr in addrs {
            match TcpStream::connect_timeout(&addr, DIAL_TIMEOUT) {
                Ok(stream) => {
                    let _ = stream.set_read_timeout(Some(timeout));
                    let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));
                    let _ = stream.set_nodelay(true);
                    if url.scheme == "https" {
                        let name = rustls::pki_types::ServerName::try_from(host.clone())
                            .map_err(|_| http_error_for(url, TransportErrorKind::Tls))?;
                        let conn = rustls::ClientConnection::new(tls_client_config(), name)
                            .map_err(|_| http_error_for(url, TransportErrorKind::Tls))?;
                        let mut tls = rustls::StreamOwned::new(conn, stream);
                        // Complete the handshake eagerly so a
                        // failure classifies as TLS, not as a
                        // read error on the first response byte.
                        tls.conn
                            .complete_io(&mut tls.sock)
                            .map_err(|_| http_error_for(url, TransportErrorKind::Tls))?;
                        return Ok(Box::new(TlsStream(tls)));
                    }
                    return Ok(Box::new(stream));
                }
                Err(e) => {
                    last_err = Some(e);
                }
            }
        }
        let kind = match last_err.and_then(|e| e.raw_os_error()) {
            Some(errno) if errno == libc::ECONNREFUSED => TransportErrorKind::ConnectionRefused,
            Some(errno) if errno == libc::ECONNRESET => TransportErrorKind::ConnectionReset,
            _ => TransportErrorKind::Dial,
        };
        Err(http_error_for(url, kind))
    }
}

/// `Read + Write` in one trait object (a `Box<dyn Read + Write>`
/// does not compile as a single object type alias without a
/// trait, same shape as `castctl_transport::TlsStream`).
trait ReadWrite: Read + Write + Send {}
impl ReadWrite for TcpStream {}
impl ReadWrite for TlsStream {}

/// TLS stream wrapper so it can sit behind `ReadWrite`.
struct TlsStream(rustls::StreamOwned<rustls::ClientConnection, TcpStream>);

impl Read for TlsStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(buf)
    }
}

impl Write for TlsStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

fn http_error_for(url: &ParsedUrl, kind: TransportErrorKind) -> HttpError {
    HttpError {
        op: "GET",
        host: url.host.clone(),
        path: url.path.clone(),
        status: 0,
        class: classify_transport_error(kind),
        body_len: 0,
    }
}

fn http_error_status(
    url: &ParsedUrl,
    status: u16,
    class: &'static str,
    body_len: i64,
) -> HttpError {
    HttpError {
        op: "GET",
        host: url.host.clone(),
        path: url.path.clone(),
        status,
        class,
        body_len,
    }
}

/// Resolve a `Location` value against the current URL.
/// Absolute URLs pass through; absolute paths keep the
/// current scheme+authority; relative paths merge with the
/// current path's directory. No direct Go function
/// counterpart: Go's `http.Client` resolves redirects
/// internally (`net/http`); this is the Rust-side equivalent
/// for the shapes a GitHub redirect can take.
fn resolve_redirect(current: &ParsedUrl, location: &str) -> Option<ParsedUrl> {
    let location = location.trim();
    if location.is_empty() {
        return None;
    }
    if let Some(abs) = parse_url(location)
        && !abs.scheme.is_empty()
    {
        return Some(abs);
    }
    let base = format!("{}://{}", current.scheme, current.authority());
    if let Some(path) = location.strip_prefix('/') {
        let _ = path;
        return parse_url(&format!("{base}{location}"));
    }
    // Relative: merge with the current directory.
    let dir = match current.path.rfind('/') {
        Some(i) => &current.path[..i + 1],
        None => "/",
    };
    parse_url(&format!("{base}{dir}{location}"))
}

/// Read one HTTP response (status line + headers) from the
/// stream. Returns `(status, content_length, chunked, location)`.
fn read_response_head(
    stream: &mut dyn ReadWrite,
    url: &ParsedUrl,
) -> Result<(u16, Option<u64>, bool, Option<String>), HttpError> {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        if head.len() > 65536 {
            return Err(http_error_for(url, TransportErrorKind::Transport));
        }
        match stream.read(&mut byte) {
            Ok(0) => {
                return Err(http_error_for(url, TransportErrorKind::Transport));
            }
            Ok(_) => {
                head.push(byte[0]);
                if head.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            Err(e) => {
                let kind = match e.kind() {
                    std::io::ErrorKind::TimedOut => TransportErrorKind::Timeout,
                    _ => TransportErrorKind::Transport,
                };
                return Err(http_error_for(url, kind));
            }
        }
    }
    let text = String::from_utf8_lossy(&head);
    let mut lines = text.lines();
    let status_line = lines.next().unwrap_or("");
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    if status == 0 {
        return Err(http_error_for(url, TransportErrorKind::Transport));
    }
    let mut content_length = None;
    let mut chunked = false;
    let mut location = None;
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim().to_ascii_lowercase();
            let value = value.trim();
            match name.as_str() {
                "content-length" => {
                    content_length = value.parse().ok();
                }
                "transfer-encoding" => {
                    if value.to_ascii_lowercase().contains("chunked") {
                        chunked = true;
                    }
                }
                "location" => {
                    location = Some(value.to_string());
                }
                _ => {}
            }
        }
    }
    Ok((status, content_length, chunked, location))
}

/// A body reader honouring `Content-Length`, chunked
/// encoding, or close-delimited bodies.
struct BodyReader {
    inner: Box<dyn ReadWrite>,
    state: BodyState,
}

enum BodyState {
    Length(u64),
    Chunked { remaining: u64, done: bool },
    Close,
}

impl Read for BodyReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match &mut self.state {
            BodyState::Length(remaining) => {
                if *remaining == 0 {
                    return Ok(0);
                }
                let want = (*remaining).min(buf.len() as u64) as usize;
                let n = self.inner.read(&mut buf[..want])?;
                *remaining -= n as u64;
                Ok(n)
            }
            BodyState::Close => self.inner.read(buf),
            BodyState::Chunked { remaining, done } => {
                if *done {
                    return Ok(0);
                }
                if *remaining == 0 {
                    // Read the next chunk-size line.
                    let size = read_chunk_size(&mut self.inner)?;
                    if size == 0 {
                        // Consume trailers until the blank line.
                        read_line(&mut self.inner)?;
                        *done = true;
                        return Ok(0);
                    }
                    *remaining = size;
                }
                let want = (*remaining).min(buf.len() as u64) as usize;
                let n = self.inner.read(&mut buf[..want])?;
                *remaining -= n as u64;
                if *remaining == 0 {
                    // Consume the trailing CRLF.
                    let mut crlf = [0u8; 2];
                    let _ = self.inner.read_exact(&mut crlf);
                }
                Ok(n)
            }
        }
    }
}

fn read_line(reader: &mut dyn Read) -> std::io::Result<String> {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match reader.read(&mut byte) {
            Ok(0) => break,
            Ok(_) => {
                line.push(byte[0]);
                if line.ends_with(b"\n") {
                    break;
                }
            }
            Err(e) => return Err(e),
        }
        if line.len() > 8192 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "line too long",
            ));
        }
    }
    Ok(String::from_utf8_lossy(&line).trim_end().to_string())
}

fn read_chunk_size(reader: &mut dyn Read) -> std::io::Result<u64> {
    let line = read_line(reader)?;
    let size_str = line.split(';').next().unwrap_or("").trim();
    u64::from_str_radix(size_str, 16)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "bad chunk size"))
}

impl Fetcher for StdFetcher {
    fn get(
        &mut self,
        url: &str,
        user_agent: &str,
        accept_api: bool,
        timeout: Duration,
    ) -> Result<Response, HttpError> {
        let origin = parse_url(url).ok_or_else(|| HttpError {
            op: "GET",
            host: String::new(),
            path: String::new(),
            status: 0,
            class: "request",
            body_len: 0,
        })?;
        let mut current = origin.clone();
        let mut via: Vec<ParsedUrl> = Vec::new();
        loop {
            let (status, content_length, _chunked, location, mut body) =
                Self::request_once(&current, user_agent, accept_api, timeout)?;
            let is_redirect = matches!(status, 301 | 302 | 303 | 307 | 308);
            if is_redirect {
                // Drain the body so the connection can close
                // cleanly, then follow the redirect under the
                // policy (Go's client follows it internally).
                let _ = std::io::copy(&mut body, &mut std::io::sink());
                let Some(loc) = location else {
                    return Err(http_error_status(
                        &current,
                        status,
                        crate::select::http_status_class(status),
                        0,
                    ));
                };
                let Some(next) = resolve_redirect(&current, &loc) else {
                    return Err(http_error_for(&current, TransportErrorKind::Redirect));
                };
                // The policy sees the chain so far INCLUDING
                // the current request as the latest `via`
                // entry: Go's `via` holds the requests
                // already made, so on the first redirect
                // `via.len() == 1`.
                via.push(current.clone());
                if let Err(refusal) = check_redirect_policy(&next, &via) {
                    let _ = refusal;
                    return Err(http_error_for(&next, TransportErrorKind::Redirect));
                }
                current = next;
                continue;
            }
            return Ok(Response {
                status,
                content_length,
                final_url: current.raw.clone(),
                body,
            });
        }
    }

    fn get_no_follow(
        &mut self,
        url: &str,
        user_agent: &str,
        timeout: Duration,
    ) -> Result<(u16, Option<String>), HttpError> {
        let parsed = parse_url(url).ok_or_else(|| HttpError {
            op: "GET",
            host: String::new(),
            path: String::new(),
            status: 0,
            class: "request",
            body_len: 0,
        })?;
        let (status, _len, _chunked, location, _body) =
            Self::request_once(&parsed, user_agent, true, timeout)?;
        Ok((status, location))
    }
}

/// GET `url` and return the body capped at `cap` bytes.
/// Non-200 returns an `HttpError` (status + class + body
/// length, body read at most 4096 bytes to count it).
/// Source: `fetchBytes` (`internal/update/update.go:460-510`).
pub fn fetch_bytes(
    fetcher: &mut dyn Fetcher,
    url: &str,
    user_agent: &str,
    cap: usize,
    timeout: Duration,
) -> Result<Vec<u8>, HttpError> {
    let parsed = parse_url(url).unwrap_or(ParsedUrl {
        scheme: String::new(),
        has_userinfo: false,
        host: String::new(),
        port: String::new(),
        path: String::new(),
        raw: url.to_string(),
    });
    let mut resp = fetcher.get(url, user_agent, true, timeout)?;
    if resp.status != 200 {
        let mut counted = [0u8; 4096];
        let mut n = 0usize;
        loop {
            match resp.body.read(&mut counted[n..]) {
                Ok(0) => break,
                Ok(m) => {
                    n += m;
                    if n >= counted.len() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        return Err(http_error_status(
            &parsed,
            resp.status,
            crate::select::http_status_class(resp.status),
            n as i64,
        ));
    }
    let mut body = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        match resp.body.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                body.extend_from_slice(&chunk[..n]);
                if body.len() > cap {
                    // Go reads through a LimitReader(cap+1), so
                    // the reported length is exactly cap+1.
                    return Err(http_error_status(
                        &parsed,
                        resp.status,
                        "too_large",
                        cap as i64 + 1,
                    ));
                }
            }
            Err(e) => {
                let kind = match e.kind() {
                    std::io::ErrorKind::TimedOut => TransportErrorKind::Timeout,
                    _ => TransportErrorKind::Transport,
                };
                return Err(HttpError {
                    op: "GET",
                    host: parsed.host.clone(),
                    path: parsed.path.clone(),
                    status: resp.status,
                    class: classify_transport_error(kind),
                    body_len: body.len() as i64,
                });
            }
        }
    }
    Ok(body)
}

/// Stream `url` to `w`, hashing as it goes, enforcing the
/// size cap and (when known) the expected byte count.
/// Returns the SHA-256 digest of the exact bytes written.
/// Source: `downloadAsset` (`internal/update/update.go:513-570`).
pub fn download_asset<W: std::io::Write>(
    fetcher: &mut dyn Fetcher,
    url: &str,
    user_agent: &str,
    expected_size: i64,
    w: &mut W,
) -> Result<[u8; 32], UpdateError> {
    use sha2::{Digest, Sha256};
    let mut resp = fetcher
        .get(url, user_agent, false, ASSET_TIMEOUT)
        .map_err(|_| {
            // Go: `wrapError(1, "update: download failed", httpError)` —
            // the message is the fixed string; the httpError summary
            // is the cause, not part of the message.
            UpdateError::failure("update: download failed")
        })?;
    if resp.status != 200 {
        let mut counted = [0u8; 4096];
        let mut n = 0usize;
        loop {
            match resp.body.read(&mut counted[n..]) {
                Ok(0) => break,
                Ok(m) => {
                    n += m;
                    if n >= counted.len() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        // The body is counted-and-dropped like Go's
        // `io.Copy(io.Discard, io.LimitReader(body, 4096))`;
        // the httpError summary is the cause, not the message.
        let _ = n;
        return Err(UpdateError::failure("update: download failed"));
    }
    if expected_size > 0
        && let Some(len) = resp.content_length
        && len as i64 != expected_size
    {
        return Err(UpdateError::failure(
            "update: download size does not match the release metadata",
        ));
    }
    let mut hash = Sha256::new();
    let mut total: u64 = 0;
    let mut chunk = [0u8; 8192];
    loop {
        match resp.body.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                total += n as u64;
                if total > MAX_ASSET_BYTES {
                    return Err(UpdateError::failure(
                        "update: download exceeds the size limit",
                    ));
                }
                hash.update(&chunk[..n]);
                w.write_all(&chunk[..n])
                    .map_err(|_| UpdateError::failure("update: download failed"))?;
            }
            Err(_e) => {
                // Go: `wrapError(1, "update: download failed",
                // httpError)` — fixed message, cause not rendered.
                return Err(UpdateError::failure("update: download failed"));
            }
        }
    }
    if total > MAX_ASSET_BYTES {
        return Err(UpdateError::failure(
            "update: download exceeds the size limit",
        ));
    }
    if expected_size > 0 && total as i64 != expected_size {
        return Err(UpdateError::failure(
            "update: download size does not match the release metadata",
        ));
    }
    Ok(hash.finalize().into())
}
