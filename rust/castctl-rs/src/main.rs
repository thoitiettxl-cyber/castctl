//! `castctl` Rust port binary (M2): wires only the offline CLI
//! surface from `castctl-cli`. `main` mirrors `cmd/castctl/main.go`
//! (`os.Exit(commands.Run(...))`); signal handling (exit 130 on
//! SIGINT) is NOT ported in M2 and is recorded in PORTING.md.

use std::io::Write;

fn main() {
    // argv[1..], lossy-converted: Go receives UTF-8 argv from the
    // OS on Unix; non-UTF8 bytes are a documented approximation
    // (PORTING.md).
    let args: Vec<String> = std::env::args_os()
        .skip(1)
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    let outcome = castctl_cli::run(&args, None);
    let stdout = std::io::stdout();
    let mut stdout = stdout.lock();
    let _ = stdout.write_all(outcome.stdout.as_bytes());
    let _ = stdout.flush();
    let stderr = std::io::stderr();
    let mut stderr = stderr.lock();
    let _ = stderr.write_all(outcome.stderr.as_bytes());
    let _ = stderr.flush();
    std::process::exit(outcome.code);
}
