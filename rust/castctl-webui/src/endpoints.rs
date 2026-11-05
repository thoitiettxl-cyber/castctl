// SPDX-License-Identifier: GPL-3.0-only
// WireGuard endpoint import: parse a wg-quick .conf,
// preview the redacted endpoint object, and optionally
// save it. Port of Go internal/webui/endpoints.go; the
// parser is the shared converter
// internal/outbound/wireguard_conf.go (never a second
// parser): it starts no device, dials nothing, and never
// validates key material, so the fixture placeholder
// "<redacted>" parses. On save, the endpoint object is
// appended to "endpoints" and a captured DNS= list is
// stored as wireguard_dns[tag]; the full merged document
// is validated before any write, like every other config
// save.
//
// The endpoint object is built with keys in SORTED order:
// Go builds it as a map[string]any (json.Marshal of the
// struct, then decodeGeneric, then type/tag added), and
// both the preview (MarshalIndent of a map) and the saved
// document (marshalOrdered renders a brand-new subtree
// sorted) emit map keys sorted.

use crate::go_json::encode_go_json_indent;
use crate::redact::redact_value;
use castctl_config::jsonvalue::{JsonValue, OrderedObject};
use std::net::IpAddr;

/// The parsed conf: the endpoint object (sorted keys,
/// WITHOUT type/tag — the caller adds those) plus the
/// captured DNS= server list (empty when the conf has no
/// DNS= line).
#[derive(Debug)]
pub struct WgParsed {
    pub endpoint: JsonValue,
    pub dns_servers: Vec<String>,
}

/// A parse failure. `line` is the 1-based line number when
/// the error names one (all errors from the line loop do);
/// the final structural checks (no [Interface], missing
/// PrivateKey, peer missing a field) carry no line, so no
/// hint is echoed for them.
#[derive(Debug)]
pub struct WgError {
    pub line: Option<usize>,
}

impl WgError {
    /// The fixed web UI message: only the line number is
    /// kept, because the parser echoes pasted input
    /// verbatim in several error shapes (addresses,
    /// endpoints, numbers). `importLineHint` (Go
    /// endpoints.go) extracts `line N` the same way.
    pub fn message(&self) -> String {
        match self.line {
            Some(n) => format!("wireguard conf is invalid at line {}", n),
            None => "wireguard conf is invalid".to_string(),
        }
    }
}

fn err_line(line: usize) -> WgError {
    WgError { line: Some(line) }
}

fn err_no_line() -> WgError {
    WgError { line: None }
}

/// Parse one `addr/bits` prefix with Go netip semantics:
/// a bare IP becomes /32 (v4) or /128 (v6); the address
/// is canonicalised (lowercase + compressed IPv6, no
/// leading-zero IPv4 octets); a prefix with host bits is
/// kept as written (`192.168.1.5/24` stays); zones are
/// rejected in prefixes; bits out of range are rejected.
/// Returns the canonical `addr/bits` string.
pub fn parse_prefix(item: &str) -> Result<String, WgError> {
    if let Some((addr_s, bits_s)) = item.split_once('/') {
        if addr_s.contains('%') {
            return Err(err_no_line());
        }
        let addr: IpAddr = addr_s.parse().map_err(|_| err_no_line())?;
        let bits: u32 = bits_s.parse().map_err(|_| err_no_line())?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        if bits > max {
            return Err(err_no_line());
        }
        Ok(format!("{}/{}", addr, bits))
    } else {
        let addr: IpAddr = item.parse().map_err(|_| err_no_line())?;
        let bits = if addr.is_ipv4() { 32 } else { 128 };
        Ok(format!("{}/{}", addr, bits))
    }
}

/// A comma-separated prefix list; empty items are skipped;
/// an empty result is an error.
fn parse_prefix_list(value: &str) -> Result<Vec<String>, WgError> {
    let mut out: Vec<String> = Vec::new();
    for item in value.split(',') {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        out.push(parse_prefix(item)?);
    }
    if out.is_empty() {
        return Err(err_no_line());
    }
    Ok(out)
}

/// Split a wg-quick Endpoint value (host:port). IPv6 hosts
/// must be bracketed; an unbracketed IPv6 literal is an
/// error because the port would be ambiguous. Port must be
/// 1..65535.
fn split_endpoint(value: &str) -> Result<(String, u16), WgError> {
    if value.matches(':').count() > 1 && !value.starts_with('[') {
        return Err(err_no_line());
    }
    let (host, port_s) = if let Some(rest) = value.strip_prefix('[') {
        let Some(end) = rest.find(']') else {
            return Err(err_no_line());
        };
        let host = &rest[..end];
        let after = &rest[end + 1..];
        let Some(port_s) = after.strip_prefix(':') else {
            return Err(err_no_line());
        };
        (host, port_s)
    } else {
        let Some((host, port_s)) = value.split_once(':') else {
            return Err(err_no_line());
        };
        (host, port_s)
    };
    if host.is_empty() {
        return Err(err_no_line());
    }
    let port: u32 = port_s.parse().map_err(|_| err_no_line())?;
    if !(1..=65535).contains(&port) {
        return Err(err_no_line());
    }
    Ok((host.to_string(), port as u16))
}

/// Parse a uint field (ListenPort/MTU/PersistentKeepalive),
/// base 10, at most `max`.
fn parse_uint(value: &str, max: u64) -> Result<u64, WgError> {
    let n: u64 = value.trim().parse().map_err(|_| err_no_line())?;
    if n > max {
        return Err(err_no_line());
    }
    Ok(n)
}

struct WgPeer {
    address: String,
    port: u16,
    public_key: String,
    pre_shared_key: String,
    allowed_ips: Vec<String>,
    persistent_keepalive: u16,
}

struct WgOpts {
    private_key: String,
    address: Vec<String>,
    listen_port: u16,
    mtu: u32,
    peers: Vec<WgPeer>,
}

/// `ParseWireGuardConfWithDNS` (Go
/// internal/outbound/wireguard_conf.go): parse a wg-quick
/// .conf into sing-box
/// `option.WireGuardEndpointOptions` JSON plus the captured
/// DNS= list. Unknown keys (PostUp, SaveConfig, ...) are
/// ignored. Key strings are NOT validated as key material.
pub fn parse_wireguard_conf(data: &[u8]) -> Result<WgParsed, WgError> {
    let text = String::from_utf8_lossy(data).into_owned();
    let mut opts = WgOpts {
        private_key: String::new(),
        address: Vec::new(),
        listen_port: 0,
        mtu: 0,
        peers: Vec::new(),
    };
    let mut dns_servers: Vec<String> = Vec::new();
    let mut current_peer: Option<WgPeer> = None;
    let mut seen_interface = false;
    let mut unknown_section = false;

    for (lineno, raw_line) in text.split('\n').enumerate() {
        let line_no = lineno + 1;
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(rest) = line.strip_prefix('[') {
            if !rest.ends_with(']') {
                return Err(err_line(line_no));
            }
            let section = rest[..rest.len() - 1].trim().to_lowercase();
            match section.as_str() {
                "interface" => {
                    if let Some(p) = current_peer.take() {
                        opts.peers.push(p);
                    }
                    seen_interface = true;
                    unknown_section = false;
                }
                "peer" => {
                    if let Some(p) = current_peer.take() {
                        opts.peers.push(p);
                    }
                    current_peer = Some(WgPeer {
                        address: String::new(),
                        port: 0,
                        public_key: String::new(),
                        pre_shared_key: String::new(),
                        allowed_ips: Vec::new(),
                        persistent_keepalive: 0,
                    });
                    unknown_section = false;
                }
                _ => {
                    // Keys under an unknown section must not
                    // silently fall through into [Interface]
                    // parsing (and possibly overwrite
                    // PrivateKey): fail closed.
                    if let Some(p) = current_peer.take() {
                        opts.peers.push(p);
                    }
                    unknown_section = true;
                }
            }
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            return Err(err_line(line_no));
        };
        if unknown_section {
            return Err(err_line(line_no));
        }
        let key = key.trim().to_lowercase();
        let value = value.trim();
        if let Some(peer) = current_peer.as_mut() {
            parse_peer_field(peer, &key, value).map_err(|mut e| {
                if e.line.is_none() {
                    e.line = Some(line_no);
                }
                e
            })?;
            continue;
        }
        if !seen_interface {
            return Err(err_line(line_no));
        }
        parse_interface_field(&mut opts, &mut dns_servers, &key, value).map_err(|mut e| {
            if e.line.is_none() {
                e.line = Some(line_no);
            }
            e
        })?;
    }
    if let Some(p) = current_peer.take() {
        opts.peers.push(p);
    }

    if !seen_interface {
        return Err(err_no_line());
    }
    if opts.private_key.is_empty() {
        return Err(err_no_line());
    }
    for peer in &opts.peers {
        if peer.public_key.is_empty() {
            return Err(err_no_line());
        }
        if peer.address.is_empty() {
            return Err(err_no_line());
        }
    }
    Ok(WgParsed {
        endpoint: build_endpoint_object(&opts),
        dns_servers,
    })
}

fn parse_interface_field(
    opts: &mut WgOpts,
    dns_servers: &mut Vec<String>,
    key: &str,
    value: &str,
) -> Result<(), WgError> {
    match key {
        "privatekey" => opts.private_key = value.to_string(),
        "address" => {
            let prefixes = parse_prefix_list(value)?;
            opts.address.extend(prefixes);
        }
        "listenport" => {
            opts.listen_port = parse_uint(value, 65535)? as u16;
        }
        "mtu" => {
            opts.mtu = parse_uint(value, 65535)? as u32;
        }
        "dns" => {
            // No field in the schema: captured into
            // dns_servers instead. Comma-separated; empty
            // items are skipped; whitespace-separated items
            // inside one entry split further (Fields).
            for item in value.split(',') {
                let item = item.trim();
                if item.is_empty() {
                    continue;
                }
                for field in item.split_whitespace() {
                    dns_servers.push(field.to_string());
                }
            }
        }
        _ => {}
    }
    Ok(())
}

fn parse_peer_field(peer: &mut WgPeer, key: &str, value: &str) -> Result<(), WgError> {
    match key {
        "publickey" => peer.public_key = value.to_string(),
        "presharedkey" => peer.pre_shared_key = value.to_string(),
        "allowedips" => {
            let prefixes = parse_prefix_list(value)?;
            peer.allowed_ips.extend(prefixes);
        }
        "endpoint" => {
            let (host, port) = split_endpoint(value)?;
            peer.address = host;
            peer.port = port;
        }
        "persistentkeepalive" => {
            peer.persistent_keepalive = parse_uint(value, 65535)? as u16;
        }
        _ => {}
    }
    Ok(())
}

/// A `badoption.Listable` marshals a single element as the
/// bare value and several as an array (never `null` for a
/// non-empty list).
fn listable_value(items: &[String]) -> JsonValue {
    if items.len() == 1 {
        JsonValue::Str(items[0].clone())
    } else {
        JsonValue::Array(items.iter().map(|s| JsonValue::Str(s.clone())).collect())
    }
}

/// Build the endpoint object in the exact shape Go's
/// `json.Marshal(option.WireGuardEndpointOptions)` emits
/// (struct order, omitempty): `system` false and `name`
/// empty are omitted, `address` and `private_key` are
/// always present, `listen_port`/`mtu`/`peers` only when
/// set, the embedded DialerOptions are all zero (omitted).
/// Keys are then stored SORTED (the Go value is a map by
/// the time it is rendered or saved).
fn build_endpoint_object(opts: &WgOpts) -> JsonValue {
    let mut obj = OrderedObject::new();
    obj.set("address", listable_value(&opts.address));
    if opts.listen_port != 0 {
        obj.set(
            "listen_port",
            JsonValue::Number(opts.listen_port.to_string()),
        );
    }
    if opts.mtu != 0 {
        obj.set("mtu", JsonValue::Number(opts.mtu.to_string()));
    }
    if !opts.peers.is_empty() {
        let peers: Vec<JsonValue> = opts.peers.iter().map(build_peer_object).collect();
        obj.set("peers", JsonValue::Array(peers));
    }
    obj.set("private_key", JsonValue::Str(opts.private_key.clone()));
    JsonValue::Object(obj)
}

fn build_peer_object(peer: &WgPeer) -> JsonValue {
    let mut obj = OrderedObject::new();
    obj.set("address", JsonValue::Str(peer.address.clone()));
    if !peer.allowed_ips.is_empty() {
        obj.set("allowed_ips", listable_value(&peer.allowed_ips));
    }
    if peer.persistent_keepalive != 0 {
        obj.set(
            "persistent_keepalive_interval",
            JsonValue::Number(peer.persistent_keepalive.to_string()),
        );
    }
    obj.set("port", JsonValue::Number(peer.port.to_string()));
    if !peer.pre_shared_key.is_empty() {
        obj.set(
            "pre_shared_key",
            JsonValue::Str(peer.pre_shared_key.clone()),
        );
    }
    obj.set("public_key", JsonValue::Str(peer.public_key.clone()));
    JsonValue::Object(obj)
}

/// Add the flat `type` + `tag` to an endpoint object
/// (Go endpoints.go adds them to the map after Marshal).
/// Keys stay sorted: `tag` sorts after `private_key`,
/// `type` sorts last.
pub fn with_type_and_tag(endpoint: &mut JsonValue, tag: &str) {
    if let JsonValue::Object(obj) = endpoint {
        obj.set("tag", JsonValue::Str(tag.to_string()));
        obj.set("type", JsonValue::Str("wireguard".to_string()));
    }
}

/// Preview: the redacted endpoint object as JSON text
/// (MarshalIndent, 2-space, HTML escaping ON — so the
/// marker renders as `\u003credacted\u003e`, exactly as
/// Go's `json.MarshalIndent` emits it).
pub fn preview_endpoint(endpoint: &JsonValue) -> String {
    let redacted = redact_value(endpoint);
    encode_go_json_indent(&redacted)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONF: &str = "[Interface]\nPrivateKey = FAKE-KEY\nAddress = 10.0.0.2/32, 2001:db8::1/128\nListenPort = 51820\nMTU = 1420\nDNS = 1.1.1.1, 8.8.8.8\n\n[Peer]\nPublicKey = FAKE-PUB\nAllowedIPs = 0.0.0.0/0\nEndpoint = 203.0.113.10:51820\nPersistentKeepalive = 25\n";

    #[test]
    fn parse_full_conf() {
        let parsed = parse_wireguard_conf(CONF.as_bytes()).unwrap();
        assert_eq!(parsed.dns_servers, vec!["1.1.1.1", "8.8.8.8"]);
        let JsonValue::Object(obj) = &parsed.endpoint else {
            panic!("expected object");
        };
        assert_eq!(
            obj.get("private_key"),
            Some(&JsonValue::Str("FAKE-KEY".to_string()))
        );
        assert_eq!(
            obj.get("listen_port"),
            Some(&JsonValue::Number("51820".to_string()))
        );
        assert_eq!(obj.get("mtu"), Some(&JsonValue::Number("1420".to_string())));
        // Two addresses marshal as an array (Listable rule).
        let JsonValue::Array(addrs) = obj.get("address").unwrap() else {
            panic!("expected array");
        };
        assert_eq!(addrs.len(), 2);
        let JsonValue::Array(peers) = obj.get("peers").unwrap() else {
            panic!("expected peers array");
        };
        assert_eq!(peers.len(), 1);
        let JsonValue::Object(peer) = &peers[0] else {
            panic!("expected peer object");
        };
        assert_eq!(
            peer.get("address"),
            Some(&JsonValue::Str("203.0.113.10".to_string()))
        );
        assert_eq!(
            peer.get("port"),
            Some(&JsonValue::Number("51820".to_string()))
        );
        assert_eq!(
            peer.get("public_key"),
            Some(&JsonValue::Str("FAKE-PUB".to_string()))
        );
        assert_eq!(
            peer.get("persistent_keepalive_interval"),
            Some(&JsonValue::Number("25".to_string()))
        );
    }

    #[test]
    fn parse_bare_ip_gets_host_bits() {
        let parsed = parse_wireguard_conf(
            b"[Interface]\nPrivateKey = k\nAddress = 10.0.0.2\n[Peer]\nPublicKey = p\nEndpoint = example.com:51820\n",
        )
        .unwrap();
        let JsonValue::Object(obj) = &parsed.endpoint else {
            panic!("expected object");
        };
        assert_eq!(
            obj.get("address"),
            Some(&JsonValue::Str("10.0.0.2/32".to_string()))
        );
    }

    #[test]
    fn parse_bracketed_ipv6_endpoint() {
        let parsed = parse_wireguard_conf(
            b"[Interface]\nPrivateKey = k\nAddress = 2001:db8::1\n[Peer]\nPublicKey = p\nEndpoint = [2001:db8::2]:51820\n",
        )
        .unwrap();
        let JsonValue::Object(obj) = &parsed.endpoint else {
            panic!("expected object");
        };
        let JsonValue::Array(peers) = obj.get("peers").unwrap() else {
            panic!("expected peers");
        };
        let JsonValue::Object(peer) = &peers[0] else {
            panic!("expected peer");
        };
        assert_eq!(
            peer.get("address"),
            Some(&JsonValue::Str("2001:db8::2".to_string()))
        );
    }

    #[test]
    fn parse_errors_carry_line_numbers() {
        // Malformed section header, line 1.
        let e = parse_wireguard_conf(b"[Interface\nPrivateKey = k\n").unwrap_err();
        assert_eq!(e.line, Some(1));
        assert!(e.message().contains("at line 1"));
        // Key outside [Interface], line 1.
        let e = parse_wireguard_conf(b"PrivateKey = k\n").unwrap_err();
        assert_eq!(e.line, Some(1));
        // Key in unknown section, line 2.
        let e = parse_wireguard_conf(b"[Bogus]\nPrivateKey = k\n").unwrap_err();
        assert_eq!(e.line, Some(2));
        // No [Interface] section: no line, no hint.
        let e = parse_wireguard_conf(b"[Peer]\nPublicKey = p\n").unwrap_err();
        assert_eq!(e.line, None);
        assert_eq!(e.message(), "wireguard conf is invalid");
        // Missing PrivateKey: no line.
        let e = parse_wireguard_conf(b"[Interface]\nAddress = 10.0.0.2\n").unwrap_err();
        assert_eq!(e.line, None);
        // Unbracketed IPv6 endpoint: line 4.
        let e = parse_wireguard_conf(
            b"[Interface]\nPrivateKey = k\n[Peer]\nPublicKey = p\nEndpoint = 2001:db8::2:51820\n",
        )
        .unwrap_err();
        assert_eq!(e.line, Some(5));
    }

    #[test]
    fn preview_redacts_private_key() {
        let mut parsed = parse_wireguard_conf(CONF.as_bytes()).unwrap();
        with_type_and_tag(&mut parsed.endpoint, "wg-home");
        let preview = preview_endpoint(&parsed.endpoint);
        assert!(preview.contains("wireguard"));
        assert!(preview.contains("wg-home"));
        // Go's MarshalIndent escapes HTML: the marker is
        // "\u003credacted\u003e" in the preview text.
        assert!(preview.contains("\\u003credacted\\u003e"));
        assert!(!preview.contains("FAKE-KEY"));
        // Keys sorted (map rendering).
        let addr_pos = preview.find("\"address\"").unwrap();
        let tag_pos = preview.find("\"tag\"").unwrap();
        assert!(addr_pos < tag_pos);
    }
}
