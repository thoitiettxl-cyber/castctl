# castctl

Browser-free content pipeline CLI: generate content with AI agents (starting with muse.ai), then publish it to social platforms (Facebook, TikTok, YouTube — planned).

Each profile has its own account session, outbound proxy (WireGuard, VLESS, SOCKS… via sing-box) and TLS fingerprint, all kept in one `config.json`.

Status: early development. The Go port of [muse-cli](https://github.com/thoitiettxl-cyber/muse-cli) (v0.6.1 is the behavioral reference) is being migrated here.

- Contributors and coding agents: start at [AGENTS.md](AGENTS.md).
- Docs: [docs/](docs/).

License: MIT.
