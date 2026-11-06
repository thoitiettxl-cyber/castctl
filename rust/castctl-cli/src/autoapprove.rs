// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! The `auto-approve` command: no network, only the
//! single-file config and the environment.
//!
//! Go source: `internal/commands/wait.go:1365-1450`
//! (`cmdAutoApprove`, `autoApproveStatusJSON`) with
//! `internal/profile/profilecmd.go:552,590`
//! (`SetAutoApprove`, `SetAutoAllowOnce`) and
//! `internal/profile/autoapprove.go:37,66`
//! (`ResolveAutoApprove`, `ResolveAutoAllowOnce`).
//!
//! Flow: resolve config + active profile, apply the
//! mutating state through the guarded writer, re-read
//! the profile so the status reflects the just-written
//! toggles (and any env override, which wins for
//! display), then render the status JSON in Go struct
//! field order: auto_approve, source, config, env,
//! auto_allow_once, once_source, once_config, once_env.
//! The `env` / `once_env` fields carry the RAW env value
//! when the variable is set (even to an empty string),
//! else null.

use castctl_config::config::{load_profile, resolve_active_profile};
use castctl_config::{resolve_auto_allow_once, resolve_auto_approve};
use castctl_config::{set_auto_allow_once, set_auto_approve};

use crate::network::{escape_go_marshal_string, write_json_text};
use crate::parser::Parsed;
use crate::run::{Ctx, FlowErr, GlobalOpts, config_err, resolve_config};

/// `cmdAutoApprove` (`wait.go:1365`). Positional
/// validation already happened in `check_spec_positionals`
/// (state/once_state choices, the `once` pairing rule),
/// so this handler only resolves, writes, re-reads, and
/// renders.
pub(crate) fn run_auto_approve(
    ctx: &mut Ctx<'_>,
    g: &GlobalOpts,
    p: &Parsed,
) -> Result<(), FlowErr> {
    let state = if p.positionals.is_empty() {
        "status"
    } else {
        p.positionals[0].as_str()
    };
    let once_state = if p.positionals.len() == 2 {
        p.positionals[1].as_str()
    } else {
        ""
    };
    let loc = resolve_config(ctx, g, false)?;
    let profile_flag = if g.profile_set {
        Some(g.profile_flag.as_str())
    } else {
        None
    };
    let prof =
        resolve_active_profile(&loc.config_dir, profile_flag, ctx.getenv).map_err(config_err)?;
    match state {
        "on" | "always" => {
            set_auto_approve(&loc.config_dir, &prof.name, "always").map_err(config_err)?;
        }
        "off" => {
            set_auto_approve(&loc.config_dir, &prof.name, "off").map_err(config_err)?;
        }
        "once" if once_state == "on" || once_state == "off" => {
            set_auto_allow_once(&loc.config_dir, &prof.name, once_state == "on")
                .map_err(config_err)?;
        }
        _ => {}
    }
    // Re-read the profile so the status reflects the
    // just-written toggles (and any env override, which
    // wins for display).
    let prof = load_profile(&loc.config_dir, &prof.name, ctx.getenv).map_err(config_err)?;
    // Same lookup as `Ctx::getenv` (private to run.rs):
    // the injected getter when present, else the process
    // environment.
    let lookup_env = |key: &str| -> Option<String> {
        match ctx.getenv {
            Some(getenv) => getenv(key),
            None => std::env::var_os(key).map(|v| v.to_string_lossy().into_owned()),
        }
    };
    let env_approve = lookup_env("MUSE_AUTO_APPROVE");
    let env_once = lookup_env("MUSE_AUTO_ALLOW_ONCE");
    let enabled =
        resolve_auto_approve(None, env_approve.as_deref(), Some(&prof)).map_err(config_err)?;
    let once_enabled =
        resolve_auto_allow_once(None, env_once.as_deref(), Some(&prof)).map_err(config_err)?;
    let display = if enabled.enabled { "always" } else { "off" };
    let config_val = if prof.auto_approve.is_empty() {
        "off"
    } else {
        prof.auto_approve.as_str()
    };
    let mut out = String::from("{");
    out.push_str("\"auto_approve\":");
    out.push_str(&escape_go_marshal_string(display));
    out.push_str(",\"source\":");
    out.push_str(&escape_go_marshal_string(&enabled.source));
    out.push_str(",\"config\":");
    out.push_str(&escape_go_marshal_string(config_val));
    out.push_str(",\"env\":");
    match &env_approve {
        Some(v) => out.push_str(&escape_go_marshal_string(v)),
        None => out.push_str("null"),
    }
    out.push_str(",\"auto_allow_once\":");
    out.push_str(if once_enabled.enabled {
        "true"
    } else {
        "false"
    });
    out.push_str(",\"once_source\":");
    out.push_str(&escape_go_marshal_string(&once_enabled.source));
    out.push_str(",\"once_config\":");
    out.push_str(if prof.auto_allow_once {
        "true"
    } else {
        "false"
    });
    out.push_str(",\"once_env\":");
    match &env_once {
        Some(v) => out.push_str(&escape_go_marshal_string(v)),
        None => out.push_str("null"),
    }
    out.push('}');
    ctx.out.stdout.push_str(&write_json_text(&out));
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::run::{Outcome, run};
    use std::collections::HashMap;

    fn temp_home(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "castctl-cli-autoapprove-{tag}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn run_env(args: &[&str], map: HashMap<String, String>) -> Outcome {
        let argv: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        let g = move |k: &str| map.get(k).cloned();
        run(&argv, Some(&g))
    }

    fn isolated_env(home: &std::path::Path) -> HashMap<String, String> {
        let mut map = HashMap::new();
        map.insert("HOME".to_string(), home.to_str().unwrap().to_string());
        map.insert(
            "XDG_CONFIG_HOME".to_string(),
            home.join(".config").to_str().unwrap().to_string(),
        );
        map
    }

    fn write_config(dir: &std::path::Path, text: &str) {
        std::fs::write(dir.join("config.json"), text).unwrap();
    }

    #[test]
    fn status_renders_config_source() {
        let dir = temp_home("status");
        write_config(
            &dir,
            "{\"default_profile\": \"no1\", \"profiles\": {\"no1\": {\"auto_approve\": \"off\", \"auto_allow_once\": false}}}",
        );
        let map = isolated_env(&temp_home("home-status"));
        let out = run_env(
            &[
                "--config",
                dir.join("config.json").to_str().unwrap(),
                "auto-approve",
            ],
            map,
        );
        assert_eq!(out.code, 0, "stderr: {}", out.stderr);
        // Source is "config <path>" — the config file path.
        assert!(
            out.stdout.contains("\"auto_approve\": \"off\""),
            "{}",
            out.stdout
        );
        assert!(out.stdout.contains("\"config\": \"off\""), "{}", out.stdout);
        assert!(out.stdout.contains("\"env\": null"), "{}", out.stdout);
        assert!(
            out.stdout.contains("\"auto_allow_once\": false"),
            "{}",
            out.stdout
        );
        assert!(
            out.stdout.contains("\"once_config\": false"),
            "{}",
            out.stdout
        );
        assert!(out.stdout.contains("\"once_env\": null"), "{}", out.stdout);
        assert!(
            out.stdout.contains("\"source\": \"config "),
            "{}",
            out.stdout
        );
    }

    #[test]
    fn on_off_round_trip_writes_the_file() {
        let dir = temp_home("roundtrip");
        write_config(
            &dir,
            "{\"default_profile\": \"no1\", \"profiles\": {\"no1\": {\"auto_approve\": \"off\"}}}",
        );
        let map = isolated_env(&temp_home("home-roundtrip"));
        let cfg = dir.join("config.json").to_str().unwrap().to_string();
        let out = run_env(&["--config", &cfg, "auto-approve", "on"], map.clone());
        assert_eq!(out.code, 0, "stderr: {}", out.stderr);
        assert!(
            out.stdout.contains("\"auto_approve\": \"always\""),
            "{}",
            out.stdout
        );
        assert!(
            std::fs::read_to_string(dir.join("config.json"))
                .unwrap()
                .contains("\"auto_approve\": \"always\""),
            "file was written"
        );
        let out = run_env(
            &["--config", &cfg, "auto-approve", "once", "on"],
            map.clone(),
        );
        assert_eq!(out.code, 0, "stderr: {}", out.stderr);
        assert!(
            out.stdout.contains("\"auto_allow_once\": true"),
            "{}",
            out.stdout
        );
        let out = run_env(&["--config", &cfg, "auto-approve", "off"], map);
        assert_eq!(out.code, 0, "stderr: {}", out.stderr);
        assert!(
            out.stdout.contains("\"auto_approve\": \"off\""),
            "{}",
            out.stdout
        );
    }

    #[test]
    fn env_overrides_config_for_display() {
        let dir = temp_home("env");
        write_config(
            &dir,
            "{\"default_profile\": \"no1\", \"profiles\": {\"no1\": {\"auto_approve\": \"off\"}}}",
        );
        let mut map = isolated_env(&temp_home("home-env"));
        map.insert("MUSE_AUTO_APPROVE".to_string(), "on".to_string());
        let out = run_env(
            &[
                "--config",
                dir.join("config.json").to_str().unwrap(),
                "auto-approve",
            ],
            map,
        );
        assert_eq!(out.code, 0, "stderr: {}", out.stderr);
        assert!(
            out.stdout.contains("\"auto_approve\": \"always\""),
            "{}",
            out.stdout
        );
        assert!(
            out.stdout.contains("\"source\": \"env MUSE_AUTO_APPROVE\""),
            "{}",
            out.stdout
        );
        assert!(out.stdout.contains("\"env\": \"on\""), "{}", out.stdout);
        // The file is untouched by a status read.
        assert!(
            std::fs::read_to_string(dir.join("config.json"))
                .unwrap()
                .contains("\"auto_approve\": \"off\"")
        );
    }

    #[test]
    fn invalid_env_word_is_exit_2() {
        let dir = temp_home("badenv");
        write_config(
            &dir,
            "{\"default_profile\": \"no1\", \"profiles\": {\"no1\": {\"auto_approve\": \"off\"}}}",
        );
        let mut map = isolated_env(&temp_home("home-badenv"));
        map.insert("MUSE_AUTO_APPROVE".to_string(), "sometimes".to_string());
        let out = run_env(
            &[
                "--config",
                dir.join("config.json").to_str().unwrap(),
                "auto-approve",
            ],
            map,
        );
        assert_eq!(out.code, 2);
        assert!(
            out.stderr
                .contains("MUSE_AUTO_APPROVE must be always or off, not \"sometimes\""),
            "{}",
            out.stderr
        );
    }

    #[test]
    fn no_single_file_is_exit_2() {
        // Empty object: parses fine but has no profiles
        // marker. Go's LoadProfile refuses it as a legacy
        // layout (the flat base file counts when no single
        // file was found), so the CLI exits 2 with the
        // legacy error — resolveActive fails before the
        // writer's "no single config file" branch is ever
        // reached. That branch is covered at the unit level
        // in castctl-config (toggle::tests).
        let dir = temp_home("legacy");
        write_config(&dir, "{}");
        let map = isolated_env(&temp_home("home-legacy"));
        let out = run_env(
            &[
                "--config",
                dir.join("config.json").to_str().unwrap(),
                "auto-approve",
                "on",
            ],
            map,
        );
        assert_eq!(out.code, 2);
        assert!(
            out.stderr.contains("legacy layout found at"),
            "{}",
            out.stderr
        );
    }
}
