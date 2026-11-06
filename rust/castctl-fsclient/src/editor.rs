// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Editor helpers (M7a): port of Go
//! `internal/fsclient/editor.go` (`ApplyReplace`,
//! `EditInEditor`, `SplitEditorCommand`, `FmtSize`).
//!
//! Adaptation: Go reads the editor from `os.Getenv`
//! directly. `edit_in_editor` does the same; tests use
//! `edit_in_editor_with_env` with an injected lookup
//! instead of mutating the process environment (Rust
//! tests run in parallel in one process, so a shared
//! `VISUAL`/`EDITOR` would race; Go's `t.Setenv` is
//! per-test scoped and has no Rust equivalent).
//!
//! No `unsafe`, no `unwrap()`/`expect()` on external input.

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::process::{Command, Stdio};

use crate::{FsError, python_repr};

/// Replace occurrences of `old` with `new` in `text`
/// (Go `ApplyReplace`, from `fs.py` `apply_replace`).
/// When `old` is absent it is an error naming the missing
/// text, Python-style. `count` selects how many
/// occurrences to replace: a negative count replaces all,
/// zero replaces none (but still errors when `old` is
/// absent), and a positive count replaces at most that
/// many, from the left.
pub fn apply_replace(text: &str, old: &str, new: &str, count: i64) -> Result<String, FsError> {
    if !text.contains(old) {
        return Err(FsError::msg(format!(
            "--replace: text not found: {}",
            python_repr(old)
        )));
    }
    if count < 0 {
        Ok(text.replace(old, new))
    } else {
        Ok(text.replacen(old, new, count as usize))
    }
}

/// Split an editor command line the way POSIX
/// `shlex.split` does (Go `SplitEditorCommand`):
/// whitespace separates words, single quotes protect
/// everything inside them, double quotes protect
/// everything except the backslash escapes for `$`, `` ` ``,
/// `"`, `\` and newline, and a backslash outside quotes
/// escapes the next character. An empty quoted string
/// yields an empty word; an unbalanced quote is an error,
/// as `shlex.split` raises `ValueError` for one.
pub fn split_editor_command(command: &str) -> Result<Vec<String>, FsError> {
    let mut words: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut token_started = false;
    #[derive(PartialEq)]
    enum State {
        Normal,
        InSingle,
        InDouble,
    }
    let mut state = State::Normal;
    let runes: Vec<char> = command.chars().collect();
    let mut i = 0usize;
    // Flush the current word, if one was started.
    // `mem::replace` reads and clears the flag in one
    // step, so there is no dead store on the final flush
    // (after the loop nothing reads the flag again).
    macro_rules! flush {
        () => {
            if std::mem::replace(&mut token_started, false) {
                words.push(std::mem::take(&mut cur));
            }
        };
    }
    while i < runes.len() {
        let r = runes[i];
        match state {
            State::Normal => match r {
                ' ' | '\t' | '\n' | '\r' => {
                    flush!();
                }
                '\\' => {
                    token_started = true;
                    if i + 1 < runes.len() {
                        i += 1;
                        // A backslash-newline is a line
                        // continuation: both vanish.
                        if runes[i] != '\n' {
                            cur.push(runes[i]);
                        }
                    } else {
                        // A trailing backslash has no
                        // escaped character: shlex raises
                        // ValueError.
                        return Err(FsError::msg("no escaped character"));
                    }
                }
                '\'' => {
                    token_started = true;
                    state = State::InSingle;
                }
                '"' => {
                    token_started = true;
                    state = State::InDouble;
                }
                _ => {
                    token_started = true;
                    cur.push(r);
                }
            },
            State::InSingle => {
                // Inside single quotes every character is
                // literal, including backslashes.
                if r == '\'' {
                    state = State::Normal;
                } else {
                    cur.push(r);
                }
            }
            State::InDouble => match r {
                '"' => {
                    state = State::Normal;
                }
                '\\' => {
                    if i + 1 < runes.len() {
                        let next = runes[i + 1];
                        match next {
                            '$' | '`' | '"' | '\\' | '\n' => {
                                i += 1;
                                if next != '\n' {
                                    cur.push(next);
                                }
                            }
                            _ => {
                                cur.push('\\');
                            }
                        }
                    } else {
                        cur.push('\\');
                    }
                }
                _ => {
                    cur.push(r);
                }
            },
        }
        i += 1;
    }
    if state != State::Normal {
        return Err(FsError::msg("no closing quotation"));
    }
    flush!();
    Ok(words)
}

/// Render a byte count (Go `FmtSize`, from `fs.py`
/// `fmt_size`): B with no decimal, K/M/G with one decimal
/// (`"1023B"`, `"1.0K"`, `"2.5M"`). A `None` size renders
/// `"-"`. Sizes are compared against 1024 at each step
/// exactly as Python's loop does, so 1048575 renders
/// `"1024.0K"`, not `"1.0M"`.
pub fn fmt_size(n: Option<i64>) -> String {
    let n = match n {
        Some(n) => n,
        None => return "-".to_string(),
    };
    let mut f = n as f64;
    for u in ["B", "K", "M", "G"] {
        if f < 1024.0 || u == "G" {
            if u == "B" {
                return format!("{f:.0}{u}");
            }
            return format!("{f:.1}{u}");
        }
        f /= 1024.0;
    }
    String::new()
}

/// Open `data` in the user's editor and return the file's
/// contents afterwards (Go `EditInEditor`, from `fs.py`
/// `edit_in_editor`). The editor is `VISUAL`, else
/// `EDITOR`, else `"vi"`; an empty `VISUAL` falls through
/// to `EDITOR`, as Python's `or` chain does. The data is
/// written to a temporary file (with suffix appended to
/// its name, e.g. `".md"`), the editor runs with the
/// terminal attached, and the temporary file is removed
/// afterwards even when reading it back fails.
///
/// The one intentional difference from Python: the editor
/// command is split shlex-style by `split_editor_command`
/// and executed directly, with the temporary file appended
/// as the last argument. Python runs `editor + " " +
/// shlex.quote(file)` through a shell. The editor's argv,
/// the file it edits, and the ignored exit status are the
/// same; no shell interprets the command. An editor that
/// cannot be started (or exits non-zero) is ignored
/// exactly as Python ignores `subprocess.call`'s return
/// value: the file is read back either way.
pub fn edit_in_editor(data: &[u8], suffix: &str) -> Result<Vec<u8>, FsError> {
    edit_in_editor_with_env(data, suffix, &|k: &str| std::env::var(k).ok())
}

/// `edit_in_editor` with an injected environment lookup
/// (test seam; see the module docs).
pub fn edit_in_editor_with_env(
    data: &[u8],
    suffix: &str,
    getenv: &dyn Fn(&str) -> Option<String>,
) -> Result<Vec<u8>, FsError> {
    let mut editor = getenv("VISUAL").unwrap_or_default();
    if editor.is_empty() {
        editor = getenv("EDITOR").unwrap_or_default();
    }
    if editor.is_empty() {
        editor = "vi".to_string();
    }
    let argv = split_editor_command(&editor)
        .map_err(|e| FsError::msg(format!("fsclient: split editor command: {e}")))?;
    if argv.is_empty() {
        return Err(FsError::msg("fsclient: empty editor command"));
    }
    let tmp_path = create_temp_file(data, suffix)?;
    // The temporary file is removed afterwards even when
    // reading it back fails (Go's `defer os.Remove`).
    let result = run_editor(&argv, &tmp_path);
    let _ = std::fs::remove_file(&tmp_path);
    result
}

fn run_editor(argv: &[String], tmp_path: &std::path::Path) -> Result<Vec<u8>, FsError> {
    let mut cmd = Command::new(&argv[0]);
    cmd.args(&argv[1..]);
    cmd.arg(tmp_path);
    cmd.stdin(Stdio::inherit());
    cmd.stdout(Stdio::inherit());
    cmd.stderr(Stdio::inherit());
    // The editor's exit status is ignored, as in Python: a
    // non-zero exit (or a missing editor binary) still
    // yields whatever the file holds afterwards.
    let _ = cmd.status();
    std::fs::read(tmp_path).map_err(|e| FsError::msg(format!("fsclient: read temp file: {e}")))
}

/// Create a `castctl-edit-*<suffix>` temporary file
/// (0600) holding `data`, returning its path. The name
/// carries a per-process counter plus the nanosecond
/// clock, so concurrent calls never collide (Go's
/// `os.CreateTemp` uses randomness for the same reason).
fn create_temp_file(data: &[u8], suffix: &str) -> Result<std::path::PathBuf, FsError> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir();
    for _ in 0..100 {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let name = format!("castctl-edit-{n}-{now}{suffix}");
        let path = dir.join(name);
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
        {
            Ok(mut file) => {
                if let Err(e) = file.write_all(data) {
                    let _ = std::fs::remove_file(&path);
                    return Err(FsError::msg(format!("fsclient: write temp file: {e}")));
                }
                if let Err(e) = file.flush() {
                    let _ = std::fs::remove_file(&path);
                    return Err(FsError::msg(format!("fsclient: close temp file: {e}")));
                }
                drop(file);
                return Ok(path);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => {
                return Err(FsError::msg(format!("fsclient: create temp file: {e}")));
            }
        }
    }
    Err(FsError::msg(
        "fsclient: create temp file: could not allocate a name",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn apply_replace_cases() {
        assert_eq!(apply_replace("a b a", "a", "c", -1).unwrap(), "c b c");
        assert_eq!(apply_replace("a b a", "a", "c", 1).unwrap(), "c b a");
        assert_eq!(apply_replace("a b a", "a", "c", 0).unwrap(), "a b a");
        let err = apply_replace("abc", "z", "y", -1).unwrap_err();
        assert_eq!(err.to_string(), "--replace: text not found: 'z'");
        // count=0 still errors when old is absent: Python
        // checks membership before replacing.
        assert!(apply_replace("abc", "z", "y", 0).is_err());
        assert_eq!(apply_replace("aaa", "a", "b", 2).unwrap(), "bba");
    }

    #[test]
    fn split_editor_command_cases() {
        let cases: Vec<(&str, Vec<&str>)> = vec![
            ("plain", vec!["vi"]),
            ("with args", vec!["code", "--wait"]),
            ("multiple args", vec!["code", "--wait", "--new-window"]),
            ("single quotes", vec!["my editor", "--flag"]),
            ("double quotes", vec!["my editor", "--flag"]),
            ("escaped space", vec!["my editor", "--flag"]),
            ("empty quoted word", vec!["", "x"]),
            ("single quote keeps backslash", vec![r"a\b"]),
            ("double quote escape", vec![r#"a"b"#]),
            ("double quote backslash before other", vec![r"a\nb"]),
            ("empty", vec![]),
            ("whitespace only", vec![]),
            ("tabs and newlines", vec!["a", "b", "c"]),
            ("quoted empty in middle", vec!["a", "", "b"]),
            ("equals and dashes", vec!["editor", "--opt=value"]),
        ];
        let inputs = [
            "vi",
            "code --wait",
            "code --wait --new-window",
            "'my editor' --flag",
            "\"my editor\" --flag",
            "my\\ editor --flag",
            "\"\" x",
            "'a\\b'",
            "\"a\\\"b\"",
            "\"a\\nb\"",
            "",
            "   ",
            "a\tb\nc",
            "a \"\" b",
            "editor --opt=value",
        ];
        for ((name, want), input) in cases.iter().zip(inputs.iter()) {
            let got = split_editor_command(input).unwrap();
            let want: Vec<String> = want.iter().map(|s| s.to_string()).collect();
            assert_eq!(got, want, "case {name} ({input:?})");
        }
        for input in ["'unbalanced", "\"unbalanced", "a 'b", "a\\"] {
            assert!(
                split_editor_command(input).is_err(),
                "input {input:?}: want unbalanced-quote/escape error"
            );
        }
    }

    fn env_map(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    fn edit_with(
        data: &[u8],
        suffix: &str,
        env: &HashMap<String, String>,
    ) -> Result<Vec<u8>, FsError> {
        edit_in_editor_with_env(data, suffix, &|k: &str| env.get(k).cloned())
    }

    /// Write an executable shell script that appends
    /// "EDITED" to its last argument and records that
    /// argument's path in a sidecar (Go `editorScript`).
    fn editor_script(dir: &std::path::Path, sidecar: &std::path::Path) -> std::path::PathBuf {
        let script = dir.join("fake-editor.sh");
        let content = format!(
            "#!/bin/sh\nfor last; do :; done\nprintf 'EDITED' >> \"$last\"\nprintf '%s' \"$last\" > {}\n",
            sidecar.display()
        );
        std::fs::write(&script, content).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        script
    }

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "castctl-fsclient-editor-{tag}-{}-{n}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn edit_in_editor_cases() {
        let dir = temp_dir("edit");
        let sidecar = dir.join("lastarg.txt");
        let script = editor_script(&dir, &sidecar);

        // editor true leaves data unchanged.
        let env = env_map(&[("VISUAL", ""), ("EDITOR", "true")]);
        assert_eq!(edit_with(b"hello", "", &env).unwrap(), b"hello");

        // editor false leaves data unchanged.
        let env = env_map(&[("VISUAL", ""), ("EDITOR", "false")]);
        assert_eq!(edit_with(b"hello", "", &env).unwrap(), b"hello");

        // editor with args edits last argument.
        let env = env_map(&[
            ("VISUAL", ""),
            ("EDITOR", &format!("{} --wait --extra", script.display())),
        ]);
        assert_eq!(edit_with(b"hello", ".md", &env).unwrap(), b"helloEDITED");
        let recorded = std::fs::read_to_string(&sidecar).unwrap();
        assert!(
            recorded.ends_with(".md"),
            "edited file = {recorded:?}, want .md suffix"
        );
        // The temporary file is removed afterwards.
        assert!(
            std::fs::metadata(&recorded).is_err(),
            "temp file still exists: {recorded:?}"
        );

        // VISUAL beats EDITOR.
        let env = env_map(&[
            ("VISUAL", "true"),
            ("EDITOR", &script.display().to_string()),
        ]);
        assert_eq!(edit_with(b"hello", "", &env).unwrap(), b"hello");

        // quoted editor path with spaces.
        let spaced = dir.join("my editor.sh");
        let content = std::fs::read(&script).unwrap();
        std::fs::write(&spaced, content).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&spaced, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let env = env_map(&[
            ("VISUAL", ""),
            ("EDITOR", &format!("'{}'", spaced.display())),
        ]);
        assert_eq!(edit_with(b"hi", "", &env).unwrap(), b"hiEDITED");

        // unbalanced quote errors.
        let env = env_map(&[("VISUAL", ""), ("EDITOR", "'unbalanced")]);
        assert!(edit_with(b"hi", "", &env).is_err());

        // missing editor binary is ignored like a shell 127.
        let env = env_map(&[("VISUAL", ""), ("EDITOR", "/nonexistent/editor-xyz")]);
        assert_eq!(edit_with(b"hello", "", &env).unwrap(), b"hello");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn fmt_size_cases() {
        let cases: Vec<(Option<i64>, &str)> = vec![
            (None, "-"),
            (Some(0), "0B"),
            (Some(1023), "1023B"),
            (Some(1024), "1.0K"),
            (Some(1536), "1.5K"),
            (Some(1048575), "1024.0K"),
            (Some(1048576), "1.0M"),
            (Some(5 * 1024 * 1024 * 1024), "5.0G"),
            (Some(1500 * 1024 * 1024 * 1024), "1500.0G"),
            (Some(-5), "-5B"),
        ];
        for (input, want) in cases {
            assert_eq!(fmt_size(input), want, "input {input:?}");
        }
    }
}
