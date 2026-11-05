#!/usr/bin/env python3
"""Generate synthetic perf fixtures (deterministic, fake values only).

Outputs (same dir):
  config-min.json   - copy of rust/parity/fixtures/config.json (minimal)
  config-large.json - 50 profiles + 140 outbounds (10x every-protocol set
                      from internal/profile/config_test.go validOutbounds,
                      tags made unique). Synthetic, labelled as such.
  message-long.md   - ~50KB Markdown corpus (headings/bold/links/fences).
  body-1024.bin     - 1024-byte body served by the item-5 HTTP origin.
No secrets: all tokens/passwords are the literal FAKE-* placeholders
already used in Go tests.
"""
import json, os, random
HERE = os.path.dirname(os.path.abspath(__file__))
random.seed(20261105)

# --- config-large.json ---
base_outbounds = [
    {"type": "socks", "tag": "proxy-sg", "server": "127.0.0.1", "server_port": 1080, "version": "5", "username": "FAKE-USER", "password": "FAKE-PW"},
    {"type": "http", "tag": "http-1", "server": "127.0.0.1", "server_port": 8080, "username": "FAKE-USER", "password": "FAKE-PW"},
    {"type": "shadowsocks", "tag": "ss-1", "server": "203.0.113.10", "server_port": 8388, "method": "aes-256-gcm", "password": "FAKE-PW"},
    {"type": "vmess", "tag": "vmess-1", "server": "203.0.113.11", "server_port": 443, "uuid": "FAKE-UUID", "security": "auto"},
    {"type": "vless", "tag": "vless-1", "server": "203.0.113.20", "server_port": 443, "uuid": "FAKE-UUID", "flow": "xtls-rprx-vision", "tls": {"enabled": True, "server_name": "example.com", "utls": {"enabled": True, "fingerprint": "chrome"}, "reality": {"enabled": True, "public_key": "FAKE-PUB", "short_id": "FAKE-SHORT"}}},
    {"type": "trojan", "tag": "trojan-1", "server": "203.0.113.12", "server_port": 443, "password": "FAKE-PW"},
    {"type": "hysteria2", "tag": "hy2-1", "server": "203.0.113.13", "server_port": 443, "password": "FAKE-PW", "obfs": {"type": "salamander", "password": "FAKE-OBFS"}},
    {"type": "tuic", "tag": "tuic-1", "server": "203.0.113.14", "server_port": 443, "uuid": "FAKE-UUID", "password": "FAKE-PW"},
    {"type": "anytls", "tag": "anytls-1", "server": "203.0.113.15", "server_port": 443, "password": "FAKE-PW"},
    {"type": "ssh", "tag": "ssh-1", "server": "203.0.113.16", "server_port": 22, "user": "FAKE-USER", "password": "FAKE-PW"},
    {"type": "snell", "tag": "snell-1", "server": "203.0.113.17", "server_port": 8388, "version": 4, "psk": "FAKE-PSK"},
    {"type": "shadowtls", "tag": "stls-1", "server": "203.0.113.18", "server_port": 443, "version": 3, "password": "FAKE-PW"},
    {"type": "naive", "tag": "naive-1", "server": "203.0.113.19", "server_port": 443, "username": "FAKE-USER", "password": "FAKE-PW"},
    {"type": "direct", "tag": "direct-1"},
]
outbounds = []
for rep in range(10):
    for ob in base_outbounds:
        o = dict(ob)
        o["tag"] = f"{ob['tag']}-r{rep}"
        outbounds.append(o)
profiles = {}
for i in range(50):
    profiles[f"p{i:03d}"] = {"outbound": f"proxy-sg-r{i % 10}"}
cfg = {"default_profile": "p000", "profiles": profiles, "outbounds": outbounds}
with open(os.path.join(HERE, "config-large.json"), "w") as f:
    json.dump(cfg, f, indent=1, sort_keys=False)
with open(os.path.join(HERE, "config-min.json"), "w") as f:
    f.write('{\n  "profiles": {\n    "default": {}\n  }\n}\n')

# --- message-long.md (~50KB) ---
words = ["alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel"]
parts = []
i = 0
while sum(len(p) for p in parts) < 50 * 1024:
    i += 1
    para = " ".join(random.choice(words) for _ in range(60))
    parts.append(f"## Section {i}\n\nThis is **bold text {i}** with a [link](https://example.com/{i}) and `inline code {i}`. {para}.\n\n")
    parts.append(f"```go\nfunc example{i}() {{\n\treturn {i}\n}}\n```\n\n")
    parts.append(f"- item {i} a\n- item {i} b with **bold** and [link](https://example.org/{i})\n\n")
with open(os.path.join(HERE, "message-long.md"), "w") as f:
    f.write("".join(parts))
with open(os.path.join(HERE, "body-1024.bin"), "wb") as f:
    f.write(b"x" * 1024)
for name in ("config-min.json", "config-large.json", "message-long.md", "body-1024.bin"):
    p = os.path.join(HERE, name)
    print(name, os.path.getsize(p))
