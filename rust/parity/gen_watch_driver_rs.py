"""Build rust/castctl-cli/examples/watch_driver.rs on cue
by copying send_wait_driver.rs (bytes) and editing the
send-specific parts. Never retypes the WS URL line.
"""
SRC = "/tmp/m7b-rb-castctl/rust/castctl-cli/examples/send_wait_driver.rs"
DST = "/tmp/m7b-rb-castctl/rust/castctl-cli/examples/watch_driver.rs"

s = open(SRC).read()

# 1. Doc comment: replace the whole //! block span.
start = s.index("//! Rust side of the M7b PR-2 send Tier A")
end_marker = "//! All credentials here are fake.\n"
end = s.index(end_marker) + len(end_marker)
new_doc = """//! Rust side of the M7b PR-2 watch Tier A parity gate:
//! run the Rust `watch` implementation (the PRODUCTION
//! code under test, via `castctl_cli::watch::run_driver_watch`)
//! against a scripted gateway_server (`serve-wait` mode),
//! printing the CLI row shape + exit code, so the gate
//! can diff it byte-for-byte against the Go watch_driver
//! run with the same script and argv.
//!
//! The connection mirrors the real CLI: a `SharedConn` over
//! a fake connector that dials the scripted server with the
//! canned fake token (HT-FAKE, as the Go driver does).
//!
//! Rows are already exact bytes (one compact JSON row per
//! record line); the example prints the production stdout
//! as-is, with no JSON round-trip.
//!
//! Usage:
//!   cargo run -p castctl-cli --example watch_driver -- \\
//!     --addr 127.0.0.1:PORT [--timeout SECONDS] [--n N]
//!     [--all] [--thread ID]
//!
//! All credentials here are fake.
"""
s = s[:start] + new_doc + s[end:]

# 2. Imports: watch entry instead of send; drop the
# JSON round-trip (watch rows print as-is).
old = "use castctl_cli::send::run_driver_send;\n"
assert s.count(old) == 1
s = s.replace(old, "use castctl_cli::watch::run_driver_watch;\n", 1)
old = "use castctl_config::jsonvalue::{decode_ordered_json, encode_ordered_json};\n"
assert s.count(old) == 1
s = s.replace(old, "", 1)

# 3. Names: driver, cookies prefix, node id, spec.
assert "send_wait_driver" in s and "send-wait-driver-cookies-" in s
s = s.replace("send_wait_driver", "watch_driver")
s = s.replace("send-wait-driver-cookies-", "watch-driver-cookies-")
old = 'node_id: "wait-driver".to_string(),'
assert s.count(old) == 1
s = s.replace(old, 'node_id: "watch-driver".to_string(),', 1)
old = 'match command_spec("send")'
assert s.count(old) == 1
s = s.replace(old, 'match command_spec("watch")', 1)
old = '"watch_driver: no send spec"'
assert s.count(old) == 1
s = s.replace(old, '"watch_driver: no watch spec"', 1)

# 4. Watch takes no positionals: drop the rest-non-empty check.
old = """    if args.rest.is_empty() {
        return Err("send text is required".to_string());
    }
"""
assert s.count(old) == 1
s = s.replace(old, "", 1)

# 5. Run call + output: raw bytes, no JSON round-trip.
start = s.index("    let (stdout, stderr, code) = run_driver_send")
end = s.index('    eprint!("{stderr}");', start)
new_out = """    let (stdout, stderr, code) = run_driver_watch(&rt, &parsed).await;
    // Rows are already exact bytes (one JSON row per line);
    // print them as-is — no JSON round-trip.
    let _ = std::io::stdout().write_all(&stdout);
"""
s = s[:start] + new_out + s[end:]

assert "send_wait_driver" not in s
assert "send-wait-driver" not in s
assert "run_driver_send" not in s
assert "decode_ordered_json" not in s
assert "auth_token=" in s, "WS URL line must survive the copy"
open(DST, "w").write(s)
print("wrote %s (%d bytes)" % (DST, len(s)))
