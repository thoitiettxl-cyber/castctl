# Architecture

## Profile isolation (hard invariant)

Profiles must never interfere with each other through the sing-box
stack. This is a HARD invariant: a violation is a bug, and enforcement
is by test, not by convention. It applies from PR3 on (in the `go/`
tree pre-migration) and in castctl after migration, to every command,
the Telegram bot, the web UI, the session keeper, and the screencast
login flow.

1. **One outbound stack per profile.** Either one sing-box box instance
   per profile, or unique tags per profile, namespaced as
   `<profile>/<tag>`. Never share MUTABLE state between profiles:
   registries, outbound/endpoint managers, routers, DNS clients, and
   dialers are built per profile. Shared data across profiles must be
   immutable configuration only, proven read-only by test. Two profiles
   built concurrently must have independent lifecycles (start/stop of
   one never affects the other).

2. **Local inbounds are per profile and per session, with auth.** A
   local inbound created for the login browser (or any other local
   consumer) binds `127.0.0.1` on an OS-assigned port (`:0`), belongs to
   exactly one profile and one session, requires authentication with a
   random username/password generated for that session, and is closed
   when the session ends. Never a fixed port, never `0.0.0.0`, never
   shared across profiles or sessions, never without auth — so another
   profile or process cannot use it.

3. **Per-profile network state, no cross-profile routing.** The DNS
   cache/client, connection pools, TLS session cache, and cookie jar are
   all per profile. Profile A's traffic must NEVER leave through profile
   B's outbound. Required test: run two profiles concurrently through
   DIFFERENT outbounds backed by fake servers, and assert each egress
   hit only the right upstream (each fake records arrivals; profile A's
   requests appear only at fake A, B's only at fake B), with DNS and
   cookie-jar activity staying inside the owning profile. The TLS session
   cache is OFF by default; if it is ever enabled, it is per profile —
   a global cache must not exist.

4. **No shared WireGuard private key across profiles.** Two profiles
   may not share a WireGuard endpoint config with the same private key
   at the same time — including via a shared endpoint tag referenced by
   both profiles. Validate at config load: the load FAILS with exit 2
   and a clear error naming both profiles. Never print the key in the
   error, a log, or a fixture. Different keys, or a key used by a single
   profile, load normally.

5. **No environment proxy, no system proxy, ever.** No
   `ProxyFromEnvironment`, no reads of `HTTP_PROXY` / `HTTPS_PROXY` /
   `ALL_PROXY` / `NO_PROXY` anywhere in product code, no OS/system-proxy
   detection, and sing-box `SetSystemProxy` is `false` everywhere. A
   test must prove dialling is unaffected by hostile proxy environment
   variables. The only proxy a profile uses is the explicit `http`
   outbound in its own configuration, if any; `direct` stays truly
   direct.

Related invariants (already decided, restated here because this
section is the single reference): every network call of a profile
goes through that profile's one outbound dialer (fail closed, no
system-resolver fallback); cookies live in separate `0600` files, never
inline in `config.json`; secrets are never printed, logged, or
committed (see `docs/security.md`).

