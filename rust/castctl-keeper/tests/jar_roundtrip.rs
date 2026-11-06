// Jar round-trip + concurrent-write tests — mirrors
// Go `TestTickConcurrentSerialised` and the jar
// round-trip cases in `internal/profile/cookies_test.go`
// and `internal/keeper/jar_test.go`.

use std::time::Duration;

use castctl_keeper::jar::{StoredCookie, parse_jar, serialize_jar};

fn cookie(name: &str, domain: &str, value: &str, expires: i64) -> StoredCookie {
    StoredCookie {
        name: name.to_string(),
        value: value.to_string(),
        domain: domain.to_string(),
        path: "/".to_string(),
        secure: true,
        http_only: false,
        expires,
    }
}

#[test]
fn jar_round_trip_literal() {
    // Literal Netscape jar (Go fixture shape): parse,
    // serialise, parse again — byte-identical second
    // serialisation, and the same cookie set.
    let input = "# Netscape HTTP Cookie File\n\
.muse.ai\tTRUE\t/\tTRUE\t1792000000\thatch_sess\tAAA\n\
.auth.muse.ai\tTRUE\t/\tTRUE\t1792000000\thatch_sess\tBBB\n\
.muse.ai\tTRUE\t/\tFALSE\t0\tdatr\tCCC\n";
    let cookies = parse_jar(input.as_bytes()).unwrap();
    assert_eq!(cookies.len(), 3);
    let out1 = serialize_jar(&cookies).unwrap();
    let cookies2 = parse_jar(&out1).unwrap();
    assert_eq!(cookies2.len(), 3);
    let out2 = serialize_jar(&cookies2).unwrap();
    assert_eq!(out1, out2);
    // Sorted (domain, path, name): .auth.muse.ai first.
    assert!(out1.starts_with(b"# Netscape HTTP Cookie File\n.auth.muse.ai"));
    // HttpOnly does not survive a jar round-trip.
    assert!(!cookies.iter().any(|c| c.http_only));
}

#[test]
fn jar_strict_rejects_short_rows() {
    let bad = "# Netscape HTTP Cookie File\n.muse.ai\tTRUE\t/\tTRUE\t1792000000\thatch_sess\n";
    let err = parse_jar(bad.as_bytes()).unwrap_err();
    assert!(err.to_string().contains("line 2"));
}

#[test]
fn concurrent_writes_serialised_no_loss() {
    // 8 threads x 25 appends through the locked atomic
    // writer: every write lands, no torn file, no lost
    // cookie. Mirrors Go TestTickConcurrentSerialised.
    let base = std::env::temp_dir().join(format!("castctl-keeper-jar-conc-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).unwrap();
    let path = base.join("cookies.txt");
    std::fs::write(&path, "# Netscape HTTP Cookie File\n").unwrap();
    let path = path.to_str().unwrap().to_string();
    let base_s = base.to_str().unwrap().to_string();
    let mut handles = Vec::new();
    for t in 0..8 {
        let path = path.clone();
        let base_s = base_s.clone();
        handles.push(std::thread::spawn(move || {
            for i in 0..25 {
                let guard = castctl_keeper::lockfile::lock_cookies_file(
                    &base_s,
                    "no.0",
                    &path,
                    Duration::from_secs(10),
                )
                .unwrap();
                let raw = std::fs::read_to_string(&path).unwrap();
                let mut cookies = parse_jar(raw.as_bytes()).unwrap_or_default();
                cookies.push(cookie(&format!("c{t}_{i}"), ".muse.ai", "v", 1_792_000_000));
                let data = serialize_jar(&cookies).unwrap();
                castctl_keeper::lockfile::write_cookies_file(&base_s, "no.0", &path, &data)
                    .unwrap();
                drop(guard);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    let raw = std::fs::read_to_string(&path).unwrap();
    let cookies = parse_jar(raw.as_bytes()).unwrap();
    assert_eq!(cookies.len(), 200);
    let _ = std::fs::remove_dir_all(&base);
}
