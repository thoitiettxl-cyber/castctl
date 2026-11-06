// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! `config migrate`: `MigrateFrom` / `Migrate`.
//!
//! Go sources: `internal/profile/migrate.go`
//! (`MigrateFrom`, `Migrate`, `MigrateResult`,
//! `MigrateProfile`, `readExistingSingle`,
//! `singleFormatKeys`, `refuseSingleFormatBaseFile`,
//! `migrateLegacyProfile`, `legacyProfileSettingsEqual`,
//! `migrateWarnings`, `generateNodeID`, `configsEqual`,
//! `singleDNSDetour`, `detourTagForProfile`,
//! `detourNodeCanDial`, `authorInterimDNS`, `stripDNS`,
//! `cloneSingleConfig`, `singleFirstNames`, `sameDir`),
//! `internal/profile/dns_distribute.go`
//! (`distributeTopLevelDNS`, `stripErrorPrefix`,
//! `carriesDetour`), `internal/profile/config.go`
//! (`parseLegacyConfig`, `applyLegacy`,
//! `strayDefaultLegacyPath`, `HasProfilesMarker`,
//! `readRegularFile`, `configPathExists`).
//!
//! Behaviour, in Go's own words (migrate.go header):
//! dry-run writes nothing; `--write` writes the single
//! file atomically (0600) and never deletes or modifies
//! any old file. A second run over identical parsed
//! content returns already-migrated. A different existing
//! single file is a refuse-overwrite error (no
//! --overwrite). Fingerprint/tls_engine values are
//! preserved verbatim. A missing node_id is generated
//! with crypto/rand (16 hex) only in write mode, only
//! when no single file exists. Any profile error is an
//! overall error, but the result still lists the good
//! profiles; in write mode nothing is written when any
//! profile error exists. The interim global dns section
//! is authored only onto an otherwise already-migrated
//! config when every profile shares one detour; a fresh
//! legacy migration is always direct-only, so it always
//! records a refusal. A refused DNS distribution is an
//! error: exit 2, nothing written.
//!
//! The result JSON is printed on stdout EVEN on error
//! (the caller prints it, then returns the error) —
//! hence `migrate_from` returns `(MigrateResult,
//! Option<ConfigError>)`, not a `Result`.
//!
//! [DEVIATION] sing-box parsing is not ported (D-M2-1):
//! the top-level and per-profile dns sections are
//! handled as raw JSON. `distributeTopLevelDNS` and
//! `authorInterimDNS` therefore validate shape with the
//! light `validate_top_level_dns_shape` check instead of
//! `parseDNS`, and a dns section Go's parser would reject
//! for a sing-box reason (unknown server type, bad
//! `rules`) is carried where Go would refuse it at load.
//! The tag-graph, per-profile DNS, WireGuard DNS and
//! WireGuard key-sharing checks DO run, exactly as in
//! Go, as does the full canonical re-parse after a
//! distribution. The legacy parser's malformed-JSON inner
//! text is the Rust tokenizer's (`invalid json: ...`),
//! not Go's `encoding/json` text (same M2 deviation
//! family); the `parse legacy config: ...` shape matches.

use std::collections::{BTreeMap, HashSet};

use crate::config::{SingleConfig, encode_single_config, has_profiles_marker, parse_single_config};
use crate::dnsvalidate::{
    default_detour_for_profile, parse_dns_block, reachable_tags_for_profile, validate_profile_dns,
    validate_single_config, validate_wireguard_dns, validate_wireguard_private_keys,
    wireguard_dns_for_profile,
};
use crate::errors::{ConfigError, config_error, refuse_error};
use crate::fingerprint::{
    DEFAULT_FINGERPRINT, DEFAULT_TLS_ENGINE, validate_fingerprint_value, validate_tls_engine_value,
};
use crate::gopath::{go_clean, go_is_abs, go_join};
use crate::gostr::{go_lower, go_quote, go_trim_space};
use crate::jsonvalue::{
    JsonValue, OrderedObject, decode_ordered_object, encode_ordered_json_indent,
};
use crate::oserr::{is_not_exist, open_error_text, stat_error_text};
use crate::profile::{
    DEFAULT_PROFILE_NAME, OutboundKind, OutboundRef, Paths, Profile, Source,
    discover_profile_names, parse_auto_allow_once_value, profile_paths, resolve_cookies_file,
};
use crate::taggraph::{detour_of, validate_tag_graph};
use crate::toggle::{generate_node_id, lock_config_dir, write_single_config_locked};

/// One profile in a `MigrateResult`
/// (`migrate.go`, `MigrateProfile`).
#[derive(Debug, Clone, Default)]
pub struct MigrateProfile {
    /// Profile name.
    pub name: String,
    /// `"legacy"` or `"single"`.
    pub source: String,
    /// Resolved cookies file path.
    pub cookies_file: String,
    /// Non-fatal observations (never secret values).
    pub warnings: Vec<String>,
    /// A node_id was generated for this profile (write
    /// mode only; dry-run never invents one).
    pub node_id_generated: bool,
}

/// The JSON-marshalable result of `migrate_from`
/// (`migrate.go`, `MigrateResult`). Field order is the
/// Go struct order; rendering honours Go's `omitempty`.
#[derive(Debug, Clone, Default)]
pub struct MigrateResult {
    /// Directory legacy profiles were read from.
    pub source_dir: String,
    /// Directory the single config was (or would be)
    /// written to.
    pub destination_dir: String,
    /// Whether a dry-run would write a file.
    pub would_write: bool,
    /// Whether this call wrote the single file.
    pub migrated: bool,
    /// `"already-migrated"`, `"refuse-overwrite"`,
    /// `"dns-authored"`, `"dns-distributed"`, or `""`.
    pub reason: String,
    /// Effective default profile (`"default"` when the
    /// file carries none).
    pub default_profile: String,
    /// Profiles, single-file entries first (in
    /// single-first order), then legacy-only profiles.
    pub profiles: Vec<MigrateProfile>,
    /// Whether a single file already existed.
    pub existing_single_config: bool,
    /// Per-profile error messages (no secret values).
    pub errors: Vec<String>,
    /// Names whose node_id was generated by this write.
    /// Never populated by a dry-run.
    pub generated: Vec<String>,
    /// This run authored the interim global dns section.
    pub dns_authored: bool,
    /// Why no dns section was authored (informational;
    /// the migration itself still succeeds).
    pub dns_refusal: String,
    /// This run distributed the top-level dns section
    /// into profile entries and removed it.
    pub dns_distributed: bool,
    /// Why distribution refused (accompanies an error:
    /// a refused distribution writes nothing).
    pub dns_distribution_refusal: String,
}

/// Render a `MigrateResult` as Go's `writeJSON` does:
/// 2-space indent, HTML unescaped, no trailing newline
/// (the caller adds it).
pub fn render_migrate_result(result: &MigrateResult) -> Result<String, ConfigError> {
    let mut obj = OrderedObject::new();
    obj.set(
        "source_dir".to_string(),
        JsonValue::Str(result.source_dir.clone()),
    );
    obj.set(
        "destination_dir".to_string(),
        JsonValue::Str(result.destination_dir.clone()),
    );
    obj.set(
        "would_write".to_string(),
        JsonValue::Bool(result.would_write),
    );
    obj.set("migrated".to_string(), JsonValue::Bool(result.migrated));
    if !result.reason.is_empty() {
        obj.set("reason".to_string(), JsonValue::Str(result.reason.clone()));
    }
    obj.set(
        "default_profile".to_string(),
        JsonValue::Str(result.default_profile.clone()),
    );
    let mut profiles = Vec::new();
    for p in &result.profiles {
        let mut po = OrderedObject::new();
        po.set("name".to_string(), JsonValue::Str(p.name.clone()));
        po.set("source".to_string(), JsonValue::Str(p.source.clone()));
        po.set(
            "cookies_file".to_string(),
            JsonValue::Str(p.cookies_file.clone()),
        );
        // Migration never invents an outbound.
        po.set("outbound".to_string(), JsonValue::Null);
        let warnings: Vec<JsonValue> = p
            .warnings
            .iter()
            .map(|w| JsonValue::Str(w.clone()))
            .collect();
        po.set("warnings".to_string(), JsonValue::Array(warnings));
        if p.node_id_generated {
            po.set("node_id_generated".to_string(), JsonValue::Bool(true));
        }
        profiles.push(JsonValue::Object(po));
    }
    obj.set("profiles".to_string(), JsonValue::Array(profiles));
    obj.set(
        "existing_single_config".to_string(),
        JsonValue::Bool(result.existing_single_config),
    );
    let errors: Vec<JsonValue> = result
        .errors
        .iter()
        .map(|e| JsonValue::Str(e.clone()))
        .collect();
    obj.set("errors".to_string(), JsonValue::Array(errors));
    if !result.generated.is_empty() {
        let generated: Vec<JsonValue> = result
            .generated
            .iter()
            .map(|g| JsonValue::Str(g.clone()))
            .collect();
        obj.set("generated".to_string(), JsonValue::Array(generated));
    }
    if result.dns_authored {
        obj.set("dns_authored".to_string(), JsonValue::Bool(true));
    }
    if !result.dns_refusal.is_empty() {
        obj.set(
            "dns_refusal".to_string(),
            JsonValue::Str(result.dns_refusal.clone()),
        );
    }
    if result.dns_distributed {
        obj.set("dns_distributed".to_string(), JsonValue::Bool(true));
    }
    if !result.dns_distribution_refusal.is_empty() {
        obj.set(
            "dns_distribution_refusal".to_string(),
            JsonValue::Str(result.dns_distribution_refusal.clone()),
        );
    }
    encode_ordered_json_indent(&JsonValue::Object(obj), 2)
}

/// `Migrate` (`migrate.go:100`): migrate the legacy
/// layout in `base_dir` into its own single config.
pub fn migrate(base_dir: &str, write: bool) -> (MigrateResult, Option<ConfigError>) {
    migrate_from(base_dir, base_dir, write)
}

/// `MigrateFrom` (`migrate.go:171`): migrate legacy
/// profiles from `source_dir` into the single config in
/// `dest_dir`. The source directory is read-only: never
/// written, locked, or modified; legacy files there keep
/// serving as the backup. Write mode holds the
/// DESTINATION's config lock across the whole
/// decide+write; dry-run takes no lock (reads only).
/// Cookies files stay where they are: migrated entries
/// point at the source cookies files by absolute path.
pub fn migrate_from(
    source_dir_in: &str,
    dest_dir: &str,
    write: bool,
) -> (MigrateResult, Option<ConfigError>) {
    let mut result = MigrateResult {
        source_dir: source_dir_in.to_string(),
        destination_dir: dest_dir.to_string(),
        profiles: Vec::new(),
        errors: Vec::new(),
        ..Default::default()
    };
    if dest_dir.is_empty() {
        return (
            result,
            Some(config_error(
                "migrate: destination directory must not be empty",
            )),
        );
    }
    let mut source_dir = source_dir_in.to_string();
    if source_dir.is_empty() {
        source_dir = dest_dir.to_string();
        result.source_dir = dest_dir.to_string();
    }
    let same = same_dir(&source_dir, dest_dir);
    if same {
        // An alias spelling of the destination takes
        // same-dir behaviour exactly: every later path
        // uses the destination spelling.
        source_dir = dest_dir.to_string();
        result.source_dir = dest_dir.to_string();
    }
    if !same {
        match std::fs::metadata(&source_dir) {
            Err(e) => {
                if is_not_exist(&e) {
                    return (
                        result,
                        Some(config_error(format!(
                            "migrate: source directory {} does not exist",
                            go_quote(&source_dir)
                        ))),
                    );
                }
                return (
                    result,
                    Some(config_error(format!(
                        "migrate: cannot stat source directory {}: {}",
                        go_quote(&source_dir),
                        stat_error_text(&source_dir, &e)
                    ))),
                );
            }
            Ok(m) => {
                if !m.is_dir() {
                    return (
                        result,
                        Some(config_error(format!(
                            "migrate: source {} is not a directory",
                            go_quote(&source_dir)
                        ))),
                    );
                }
            }
        }
    }

    // Write mode holds the config lock across the WHOLE
    // decide+write (RT-2). Dry-run takes no lock. The
    // guard lives until the end of this function; the
    // write below uses write_single_config_locked
    // directly (SaveSingleConfig would re-acquire the
    // lock and deadlock).
    let _lock_guard = if write {
        match lock_config_dir(dest_dir) {
            Ok(g) => Some(g),
            Err(e) => return (result, Some(e)),
        }
    } else {
        None
    };

    let existing = match read_existing_single(dest_dir) {
        Ok(e) => e,
        Err(e) => return (result, Some(e)),
    };
    if existing.malformed.is_some() && !same {
        // A malformed destination file is not a legacy
        // source profile error: refuse to overwrite it
        // blindly.
        return (result, existing.malformed);
    }
    let existing_is_single = existing.is_single;
    result.existing_single_config = existing_is_single;
    let existing_cfg = existing.cfg;

    // Discover legacy profiles: default first, then
    // sorted dir names.
    let mut names = match discover_profile_names(&source_dir) {
        Ok(n) => n,
        Err(e) => return (result, Some(e)),
    };
    if names.len() > 1 {
        names[1..].sort();
    }

    // profiles/default/config.json is a legacy file for
    // the default profile (R4): directory discovery skips
    // a directory named "default", so its presence is
    // detected explicitly (Stat only).
    let stray_path = stray_default_legacy_path(&source_dir);
    let stray_present = std::fs::metadata(&stray_path).is_ok();

    // NB4: when a single file already exists it wins
    // wholly. Its entries are carried over verbatim
    // first; legacy files are then consulted only for
    // profiles absent from the single file — except
    // cross-dir: a source legacy file for a name already
    // in the single file is still read and compared.
    let mut candidate_profiles: Vec<Profile> = Vec::new();
    let mut from_single: HashSet<String> = HashSet::new();
    if existing_is_single && let Some(existing) = &existing_cfg {
        for name in single_first_names(&existing.profile_names()) {
            if let Some(p) = existing.profiles.get(&name) {
                candidate_profiles.push(p.clone());
                from_single.insert(name);
            }
        }
    }
    let mut profile_errors: Vec<String> = Vec::new();
    // A symlinked profile directory whose target cannot
    // be resolved holds no readable legacy file, but it
    // must not vanish silently: fail the run naming the
    // path. (Discovery above skips it; only the
    // migration step fails loudly.)
    if let Ok(entries) = std::fs::read_dir(go_join(&[&source_dir, "profiles"])) {
        for entry in entries.flatten() {
            let is_symlink = entry.file_type().map(|ft| ft.is_symlink()).unwrap_or(false);
            if !is_symlink {
                continue;
            }
            let link_path = go_join(&[
                &source_dir,
                "profiles",
                &entry.file_name().to_string_lossy(),
            ]);
            match std::fs::metadata(&link_path) {
                Err(e) => profile_errors.push(format!(
                    "symlinked profile dir {} cannot be resolved: {}; migrate cannot read it (remove it or restore its target)",
                    go_quote(&link_path),
                    stat_error_text(&link_path, &e)
                )),
                Ok(m) => {
                    if !m.is_dir() {
                        profile_errors.push(format!(
                            "symlinked profile dir {} is not a directory (it resolves to a non-directory); migrate cannot read it as a profile directory (remove it or restore it to a directory)",
                            go_quote(&link_path)
                        ));
                    }
                }
            }
        }
    }
    for name in &names {
        let paths = match profile_paths(&source_dir, name) {
            Ok(p) => p,
            Err(e) => {
                profile_errors.push(e.message);
                continue;
            }
        };
        if existing.malformed.is_some() && same && name == DEFAULT_PROFILE_NAME {
            // The base config.json is malformed JSON:
            // record it once as the default profile's
            // error; do not re-read it as a legacy file.
            // (Only when source == destination.)
            if let Some(malformed) = &existing.malformed {
                profile_errors.push(malformed.message.clone());
            }
            continue;
        }
        if name == DEFAULT_PROFILE_NAME && stray_present {
            // The stray default legacy file migrates like
            // any named legacy file: its settings become
            // the default entry. It is never silently
            // dropped.
            let stray_dir = go_join(&[&source_dir, "profiles", "default"]);
            let stray_paths = Paths {
                dir: stray_dir.clone(),
                config: stray_path.clone(),
                cookies: go_join(&[&stray_dir, "cookies.txt"]),
                chat: go_join(&[&stray_dir, "chat.json"]),
            };
            let stray_profile = match migrate_legacy_profile(&source_dir, name, &stray_paths) {
                Ok(p) => p,
                Err(e) => {
                    profile_errors.push(e.message);
                    continue;
                }
            };
            // A legacy base file as well means two legacy
            // files claim the default profile: refuse
            // naming both instead of choosing one. (When
            // source == destination and a single file
            // exists, the base file IS the single file,
            // so it does not count here.)
            let mut base_legacy = false;
            if !(same && existing_is_single)
                && config_path_exists(&go_join(&[&source_dir, "config.json"]))
            {
                base_legacy = true;
            }
            if base_legacy {
                profile_errors.push(format!(
                    "profile {} has two legacy config files: {} and {}; refusing to choose between them (remove one, or migrate one by hand)",
                    go_quote(name),
                    go_quote(&go_join(&[&source_dir, "config.json"])),
                    go_quote(&stray_path)
                ));
                continue;
            }
            if existing_is_single && from_single.contains(name) {
                // The destination already has a default
                // entry: identical settings stand as
                // already-migrated; differing settings are
                // a collision naming both locations.
                if let Some(existing) = &existing_cfg
                    && let Some(dest_p) = existing.profiles.get(name)
                    && legacy_profile_settings_equal(&stray_profile, dest_p)
                {
                    continue;
                }
                profile_errors.push(format!(
                    "profile {} differs between source legacy file {} and destination config {}; refusing to overwrite",
                    go_quote(name),
                    go_quote(&stray_path),
                    go_quote(&go_join(&[dest_dir, "config.json"]))
                ));
                continue;
            }
            candidate_profiles.push(stray_profile);
            continue;
        }
        if existing_is_single {
            if from_single.contains(name) {
                if !same && config_path_exists(&paths.config) {
                    // Cross-dir collision: the source
                    // holds a legacy file for a name the
                    // destination already has. Identical
                    // settings stand as already-migrated;
                    // differing settings refuse, naming
                    // the profile and both locations.
                    match migrate_legacy_profile(&source_dir, name, &paths) {
                        Err(e) => {
                            profile_errors.push(e.message);
                            continue;
                        }
                        Ok(src_profile) => {
                            let equal = existing_cfg
                                .as_ref()
                                .and_then(|c| c.profiles.get(name))
                                .is_some_and(|dest_p| {
                                    legacy_profile_settings_equal(&src_profile, dest_p)
                                });
                            if !equal {
                                profile_errors.push(format!(
                                    "profile {} differs between source legacy file {} and destination config {}; refusing to overwrite",
                                    go_quote(name),
                                    go_quote(&paths.config),
                                    go_quote(&go_join(&[dest_dir, "config.json"]))
                                ));
                                continue;
                            }
                        }
                    }
                }
                continue;
            }
            if name == DEFAULT_PROFILE_NAME && same {
                // The base config.json IS the single file;
                // the default profile has no separate
                // legacy file, and it is absent from the
                // single file, so there is no default entry
                // to carry over.
                continue;
            }
        }
        match migrate_legacy_profile(&source_dir, name, &paths) {
            Ok(p) => candidate_profiles.push(p),
            Err(e) => profile_errors.push(e.message),
        }
    }

    // Generate missing node_ids only in write mode and
    // only when there is no existing single file: an
    // already-migrated file is compared verbatim (NB4)
    // before any generation, so a second run never
    // invents an id for a profile already in the single
    // file, and a refused run never reports ids it did
    // not write.
    let mut generated: Vec<String> = Vec::new();
    if write && !existing_is_single {
        for p in &mut candidate_profiles {
            if !p.node_id_present || p.node_id.is_empty() {
                match generate_node_id() {
                    Ok(id) => {
                        p.node_id = id;
                        p.node_id_present = true;
                        generated.push(p.name.clone());
                    }
                    Err(e) => return (result, Some(e)),
                }
            }
        }
    }

    // The effective default_profile reported in the
    // result; the candidate file itself reuses the
    // existing value verbatim (even when absent) so
    // comparison against an existing file is exact.
    let mut effective_default = DEFAULT_PROFILE_NAME.to_string();
    if existing_is_single
        && let Some(existing) = &existing_cfg
        && !existing.default_profile.is_empty()
    {
        effective_default = existing.default_profile.clone();
    }
    result.default_profile = effective_default;
    let generated_set: HashSet<String> = generated.iter().cloned().collect();
    for p in &candidate_profiles {
        let source = if from_single.contains(&p.name) {
            "single"
        } else {
            "legacy"
        };
        result.profiles.push(MigrateProfile {
            name: p.name.clone(),
            source: source.to_string(),
            cookies_file: p.cookies_file.clone(),
            warnings: migrate_warnings(p, write, &generated_set),
            node_id_generated: generated_set.contains(&p.name),
        });
    }
    result.generated = generated;
    if !profile_errors.is_empty() {
        let n = profile_errors.len();
        result.errors.extend(profile_errors);
        return (
            result,
            Some(config_error(format!("migrate: {n} profile error(s)"))),
        );
    }

    let mut candidate: SingleConfig;
    if existing_is_single {
        // Carry the existing file's outbounds, endpoints,
        // dns, and default_profile verbatim (NB4); only
        // legacy-only profiles are added.
        candidate = match &existing_cfg {
            Some(c) => c.clone(),
            None => SingleConfig::default(),
        };
        for p in &candidate_profiles {
            if !from_single.contains(&p.name) {
                candidate.profiles.insert(p.name.clone(), p.clone());
            }
        }
    } else {
        candidate = SingleConfig::default();
        candidate.default_profile = DEFAULT_PROFILE_NAME.to_string();
        for p in &candidate_profiles {
            candidate.profiles.insert(p.name.clone(), p.clone());
        }
    }

    if existing_is_single {
        // `read_existing_single` guarantees `cfg` is `Some`
        // exactly when `is_single` is true; fail closed if
        // that invariant ever breaks instead of panicking.
        let Some(existing) = &existing_cfg else {
            return (
                result,
                Some(config_error("migrate: existing single config is missing")),
            );
        };
        // G4 distribution: when the existing file carries
        // a top-level dns section, distribute it verbatim
        // into every profile's own dns block and remove
        // the top-level key in the same atomic write —
        // but only onto a config that is otherwise
        // already-migrated. A distribution refusal is an
        // error: the whole run refuses, exit 2, nothing
        // is written.
        if candidate.dns_raw.is_some() {
            let otherwise_migrated =
                match configs_equal(&strip_dns(existing), &strip_dns(&candidate)) {
                    Ok(v) => v,
                    Err(e) => return (result, Some(e)),
                };
            if otherwise_migrated {
                let (distributed, dist_refusal, dist_err) =
                    distribute_top_level_dns(&mut candidate, dest_dir);
                if let Some(err) = dist_err {
                    result.dns_distribution_refusal = dist_refusal;
                    return (result, Some(err));
                }
                if distributed {
                    result.dns_distributed = true;
                    if !write {
                        result.would_write = true;
                        return (result, None);
                    }
                    if let Err(e) = write_single_config_locked(dest_dir, &candidate) {
                        return (result, Some(e));
                    }
                    result.migrated = true;
                    result.reason = "dns-distributed".to_string();
                    return (result, None);
                }
            }
        }
        // DNS extension: author the interim global section
        // only onto an otherwise already-migrated config.
        let (dns_authored, dns_refusal) = author_interim_dns(&mut candidate, existing);
        result.dns_authored = dns_authored;
        result.dns_refusal = dns_refusal;
        if dns_authored {
            if !write {
                result.would_write = true;
                return (result, None);
            }
            if let Err(e) = write_single_config_locked(dest_dir, &candidate) {
                return (result, Some(e));
            }
            result.migrated = true;
            result.reason = "dns-authored".to_string();
            return (result, None);
        }
        let equal = match configs_equal(existing, &candidate) {
            Ok(v) => v,
            Err(e) => return (result, Some(e)),
        };
        if equal {
            result.reason = "already-migrated".to_string();
            return (result, None);
        }
        result.reason = "refuse-overwrite".to_string();
        return (
            result,
            Some(refuse_error(
                "existing single config differs from what migrate would write; refusing to overwrite (no --overwrite in this design)",
            )),
        );
    }

    // No existing single file: a fresh migration. A
    // profiles-absent destination file carrying
    // single-format sections is refused first (R1 guard):
    // overwriting it would silently delete those
    // sections, and no later step re-reads them. Its
    // profiles are always direct-only (legacy files carry
    // no outbound), so no dns section can be authored;
    // record the refusal and write the migration without
    // one.
    let (refusal, gerr) = refuse_single_format_base_file(dest_dir);
    if let Some(err) = gerr {
        result.errors.push(refusal);
        // The node_id generation above ran in memory only
        // and nothing is written on this refusal: never
        // report an id as generated (the RT-2 rule — a
        // reported id must be a persisted id).
        result.generated = Vec::new();
        for mp in &mut result.profiles {
            mp.node_id_generated = false;
            mp.warnings.retain(|w| w != "node_id generated");
        }
        return (result, Some(err));
    }
    let (_, refusing, ok) = single_dns_detour(&candidate);
    if !ok && !refusing.is_empty() {
        result.dns_refusal = format!(
            "dns section not authored: profile {} has no outbound tag for a dns detour (direct-only); add an outbound and re-run config migrate, or add a dns section by hand (see docs/config.md)",
            go_quote(&refusing)
        );
    }

    if !write {
        result.would_write = true;
        return (result, None);
    }
    if let Err(e) = write_single_config_locked(dest_dir, &candidate) {
        return (result, Some(e));
    }
    result.migrated = true;
    (result, None)
}

// ---------------------------------------------------------------------
// File reading
// ---------------------------------------------------------------------

/// Whether `path` exists and is not a directory
/// (`configPathExists`, `config.go:1070`): stat only,
/// never opened.
fn config_path_exists(path: &str) -> bool {
    match std::fs::metadata(path) {
        Ok(meta) => !meta.is_dir(),
        Err(_) => false,
    }
}

/// The failure modes of `read_regular_file`: absent
/// (Go `os.IsNotExist`) versus any other failure, whose
/// text is already Go-shaped (`stat ...` / `config path
/// ...` / `open ...`).
enum ReadRegularError {
    NotExist,
    Other(String),
}

/// `readRegularFile` (`config.go:827`): stat first (a
/// FIFO, socket, device or directory is an error naming
/// the path without ever opening it, so a read can never
/// block on a FIFO), then read.
fn read_regular_file(path: &str) -> Result<Vec<u8>, ReadRegularError> {
    match std::fs::metadata(path) {
        Err(e) => {
            if is_not_exist(&e) {
                return Err(ReadRegularError::NotExist);
            }
            Err(ReadRegularError::Other(stat_error_text(path, &e)))
        }
        Ok(m) => {
            if m.is_dir() {
                return Err(ReadRegularError::Other(format!(
                    "config path {} is a directory, not a file",
                    go_quote(path)
                )));
            }
            if !m.is_file() {
                return Err(ReadRegularError::Other(format!(
                    "config path {} is not a regular file",
                    go_quote(path)
                )));
            }
            match std::fs::read(path) {
                Ok(data) => Ok(data),
                Err(e) => {
                    if is_not_exist(&e) {
                        Err(ReadRegularError::NotExist)
                    } else {
                        Err(ReadRegularError::Other(open_error_text(path, &e)))
                    }
                }
            }
        }
    }
}

/// The outcome of `read_existing_single`: the parsed
/// single file (`cfg`, when `is_single`), whether the
/// destination file parses as a single file, and the
/// malformed-JSON error (a legacy-flat file that is not
/// valid JSON at all) when present.
struct ExistingSingle {
    cfg: Option<SingleConfig>,
    is_single: bool,
    malformed: Option<ConfigError>,
}

/// `readExistingSingle` (`migrate.go:653`): absent or
/// legacy-flat → no single file; single file →
/// parsed (with Go's full parse-time validation chain:
/// Rust's parse runs only the tail, so the tag-graph /
/// DNS / WireGuard checks run here too); unparseable
/// single file → error; malformed JSON → the
/// `malformed` slot (reported as the default profile's
/// error by the caller, never a silent fallback).
fn read_existing_single(base_dir: &str) -> Result<ExistingSingle, ConfigError> {
    let path = go_join(&[base_dir, "config.json"]);
    let data = match read_regular_file(&path) {
        Err(ReadRegularError::NotExist) => {
            return Ok(ExistingSingle {
                cfg: None,
                is_single: false,
                malformed: None,
            });
        }
        Err(ReadRegularError::Other(inner)) => {
            return Err(config_error(format!("read config: {inner}")));
        }
        Ok(data) => data,
    };
    let marker = match has_profiles_marker(&data) {
        Ok(m) => m,
        // Go wraps the marker error (itself a profile
        // error, prefix included) with `parse legacy
        // config: %v` — the double `profile: ` prefix
        // is real Go behaviour, reproduced here.
        Err(e) => {
            return Ok(ExistingSingle {
                cfg: None,
                is_single: false,
                malformed: Some(config_error(format!("parse legacy config: {}", e.message))),
            });
        }
    };
    if !marker {
        return Ok(ExistingSingle {
            cfg: None,
            is_single: false,
            malformed: None,
        });
    }
    let mut cfg = parse_single_config(&data, base_dir)?;
    validate_single_config(&mut cfg)?;
    validate_top_level_dns_shape(&cfg)?;
    Ok(ExistingSingle {
        cfg: Some(cfg),
        is_single: true,
        malformed: None,
    })
}

/// Light shape check for a top-level dns section
/// ([DEVIATION], D-M2-1): Go's `parseDNS` validates the
/// full sing-box DNS options; Rust keeps the section raw,
/// so this checks only the shape distribution relies on
/// (object; `servers` an array of objects with non-empty
/// string `tag`/`type`; `final` a string when present).
/// The error text is shaped like Go's
/// `parse dns: ...` so distribution refusals quoting it
/// read correctly after `stripErrorPrefix`.
fn validate_top_level_dns_shape(cfg: &SingleConfig) -> Result<(), ConfigError> {
    let Some(raw) = &cfg.dns_raw else {
        return Ok(());
    };
    let JsonValue::Object(obj) = raw else {
        return Err(config_error("parse dns: dns section is not a JSON object"));
    };
    if let Some(servers) = obj.get("servers") {
        let JsonValue::Array(list) = servers else {
            return Err(config_error("parse dns: dns servers is not an array"));
        };
        for (i, srv) in list.iter().enumerate() {
            let JsonValue::Object(o) = srv else {
                return Err(config_error(format!(
                    "parse dns: dns server {i} is not a JSON object"
                )));
            };
            match o.get("tag") {
                Some(JsonValue::Str(t)) if !t.is_empty() => {}
                _ => {
                    return Err(config_error(format!(
                        "parse dns: dns server {i} has no tag"
                    )));
                }
            }
            match o.get("type") {
                Some(JsonValue::Str(t)) if !t.is_empty() => {}
                _ => {
                    return Err(config_error(format!(
                        "parse dns: dns server {i} has no type"
                    )));
                }
            }
        }
    }
    if let Some(f) = obj.get("final")
        && !matches!(f, JsonValue::Str(_))
    {
        return Err(config_error("parse dns: dns final must be a string"));
    }
    Ok(())
}

/// `singleFormatKeys` (`migrate.go:675`): the top-level
/// keys in `data` whose values have the single-config
/// shape for that key, in canonical order. Shape, not
/// key presence alone, triggers.
fn single_format_keys(data: &[u8]) -> Vec<String> {
    let Ok(obj) = decode_ordered_object(data) else {
        return Vec::new();
    };
    let mut keys = Vec::new();
    if let Some(JsonValue::Object(_)) = obj.get("dns") {
        keys.push("dns".to_string());
    }
    for key in ["outbounds", "endpoints"] {
        if let Some(JsonValue::Array(arr)) = obj.get(key)
            && !arr.is_empty()
            && arr.iter().any(|elem| match elem {
                JsonValue::Object(o) => matches!(
                    o.get("type"),
                    Some(JsonValue::Str(t)) if !t.is_empty()
                ),
                _ => false,
            })
        {
            keys.push(key.to_string());
        }
    }
    if let Some(JsonValue::Object(m)) = obj.get("wireguard_dns")
        && !m.is_empty()
        && m.iter().any(|(_, v)| match v {
            JsonValue::Array(arr) => arr.iter().any(|e| matches!(e, JsonValue::Str(_))),
            _ => false,
        })
    {
        keys.push("wireguard_dns".to_string());
    }
    if let Some(JsonValue::Object(m)) = obj.get("log")
        && !m.is_empty()
        && m.keys()
            .iter()
            .any(|k| matches!(k.as_str(), "disabled" | "level" | "output" | "timestamp"))
    {
        keys.push("log".to_string());
    }
    if let Some(JsonValue::Str(_)) = obj.get("default_profile") {
        keys.push("default_profile".to_string());
    }
    keys
}

/// `refuseSingleFormatBaseFile` (`migrate.go:775`):
/// refuse a fresh migration when the destination
/// config.json is a profiles-absent file carrying
/// single-format sections: a fresh migration would
/// overwrite it with a synthetic profile set, silently
/// deleting those sections. Returns the refusal text
/// and the error, or `("", None)` when there is nothing
/// to refuse.
fn refuse_single_format_base_file(dest_dir: &str) -> (String, Option<ConfigError>) {
    let path = go_join(&[dest_dir, "config.json"]);
    let Ok(data) = read_regular_file(&path) else {
        return (String::new(), None);
    };
    let Ok(marker) = has_profiles_marker(&data) else {
        return (String::new(), None);
    };
    if marker {
        return (String::new(), None);
    }
    let keys = single_format_keys(&data);
    if keys.is_empty() {
        return (String::new(), None);
    }
    let quoted: Vec<String> = keys.iter().map(|k| go_quote(k)).collect();
    let refusal = format!(
        "migrate: destination config file {} carries single-format section(s) {} but no \"profiles\" key; refusing to overwrite it with a fresh migration (add a \"profiles\" object so the file parses as a single config, or remove the sections by hand first, see docs/config.md)",
        go_quote(&path),
        quoted.join(", ")
    );
    let err = config_error(refusal.clone());
    (refusal, Some(err))
}

/// `sameDir` (`migrate.go:625`): whether two directory
/// paths name the same directory, compared by absolute
/// path after resolving symlinks. When either path
/// cannot be resolved, its cleaned absolute path is
/// compared instead (fail-open to cross-dir logic).
fn same_dir(a: &str, b: &str) -> bool {
    fn resolved(p: &str) -> String {
        let abs = if go_is_abs(p) {
            p.to_string()
        } else {
            match std::env::current_dir() {
                Ok(cwd) => go_join(&[&cwd.to_string_lossy(), p]),
                Err(_) => p.to_string(),
            }
        };
        let cleaned = go_clean(&abs);
        match std::fs::canonicalize(&cleaned) {
            Ok(c) => c.to_string_lossy().into_owned(),
            Err(_) => cleaned,
        }
    }
    resolved(a) == resolved(b)
}

/// `configsEqual` (`migrate.go:911`): compare two
/// configs by their canonical saved encoding
/// (parsed-equal, ignoring file formatting).
fn configs_equal(a: &SingleConfig, b: &SingleConfig) -> Result<bool, ConfigError> {
    let ab = encode_single_config(a)?;
    let bb = encode_single_config(b)?;
    Ok(ab == bb)
}

/// `stripDNS` (`migrate.go:1060`): a copy of `cfg`
/// with no dns section, so `configs_equal` can compare
/// two configs ignoring dns.
fn strip_dns(cfg: &SingleConfig) -> SingleConfig {
    let mut cp = cfg.clone();
    cp.dns_raw = None;
    cp
}

/// `singleFirstNames` (`migrate.go:1097`): names with
/// `"default"` first and the rest in their given
/// (sorted) order.
fn single_first_names(names: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for n in names {
        if n == DEFAULT_PROFILE_NAME {
            out.push(n.clone());
        }
    }
    for n in names {
        if n != DEFAULT_PROFILE_NAME {
            out.push(n.clone());
        }
    }
    out
}

/// `strayDefaultLegacyPath` (`config.go:1081`):
/// `profiles/default/config.json` — the default
/// profile's stray legacy file.
fn stray_default_legacy_path(base_dir: &str) -> String {
    go_join(&[base_dir, "profiles", DEFAULT_PROFILE_NAME, "config.json"])
}

// ---------------------------------------------------------------------
// Legacy parsing
// ---------------------------------------------------------------------

/// The flat per-profile config shape from cli.py
/// (`config.go`, `legacySettings`). MIGRATE-ONLY.
#[derive(Debug, Clone, Default)]
struct LegacySettings {
    cookies_file: String,
    cookies_file_present: bool,
    vm_id: String,
    vm_id_present: bool,
    node_id: String,
    node_id_present: bool,
    auto_approve: String,
    auto_allow_once: bool,
    subscription_action_id: String,
    fingerprint: String,
    fingerprint_present: bool,
    tls_engine: String,
    tls_engine_present: bool,
}

/// `parseLegacyConfig` (`config.go:901`), strict mode
/// only (used by Migrate, which must not silently
/// reinterpret a corrupt file): wrong-typed settings
/// are errors, not silent coercions. Fingerprint /
/// tls_engine are validated strictly in both modes.
/// Unknown keys are ignored.
fn parse_legacy_config(data: &[u8]) -> Result<LegacySettings, ConfigError> {
    let obj = decode_ordered_object(data).map_err(|e| {
        // Go reports the encoding/json error text here;
        // the Rust tokenizer text differs (pre-existing
        // M2 deviation). The shape is preserved by
        // stripping the one `profile: ` prefix the
        // decoder adds.
        config_error(format!(
            "parse legacy config: {}",
            strip_error_prefix(&e.message)
        ))
    })?;
    if obj.has("profiles") {
        return Err(config_error(
            "\"profiles\" key does not belong in a legacy per-profile config",
        ));
    }
    let mut s = LegacySettings {
        auto_approve: "off".to_string(),
        ..Default::default()
    };
    let get_string = |key: &str| -> Result<(String, bool), ConfigError> {
        match obj.get(key) {
            None => Ok((String::new(), false)),
            Some(JsonValue::Str(v)) => Ok((v.clone(), true)),
            Some(_) => Err(config_error(format!("{key} must be a string"))),
        }
    };
    (s.cookies_file, s.cookies_file_present) = get_string("cookies_file")?;
    (s.vm_id, s.vm_id_present) = get_string("vm_id")?;
    (s.node_id, s.node_id_present) = get_string("node_id")?;
    (s.subscription_action_id, _) = get_string("subscription_action_id")?;
    if let Some(v) = obj.get("fingerprint") {
        match v {
            JsonValue::Str(str_v) => {
                validate_fingerprint_value(str_v).map_err(config_error)?;
                s.fingerprint = str_v.clone();
                s.fingerprint_present = true;
            }
            _ => return Err(config_error("fingerprint must be a string")),
        }
    }
    if let Some(v) = obj.get("tls_engine") {
        match v {
            JsonValue::Str(str_v) => {
                validate_tls_engine_value(str_v).map_err(config_error)?;
                s.tls_engine = str_v.clone();
                s.tls_engine_present = true;
            }
            _ => return Err(config_error("tls_engine must be a string")),
        }
    }
    if let Some(v) = obj.get("auto_approve") {
        match v {
            JsonValue::Str(str_v) => {
                if go_lower(go_trim_space(str_v)) == "always" {
                    s.auto_approve = "always".to_string();
                } else {
                    s.auto_approve = "off".to_string();
                }
            }
            _ => return Err(config_error("auto_approve must be a string")),
        }
    }
    if let Some(v) = obj.get("auto_allow_once") {
        s.auto_allow_once = parse_auto_allow_once_value(v)
            .map_err(|_| config_error("auto_allow_once must be a boolean or an on/off word"))?;
    }
    Ok(s)
}

/// `applyLegacy` (`config.go:1005`): build a `Profile`
/// from legacy settings for the given paths.
fn apply_legacy(
    name: &str,
    paths: &Paths,
    s: &LegacySettings,
    base_dir: &str,
) -> Result<Profile, ConfigError> {
    let mut p = Profile {
        name: name.to_string(),
        dir: paths.dir.clone(),
        config_file: paths.config.clone(),
        cookies_file: paths.cookies.clone(),
        chat_file: paths.chat.clone(),
        auto_approve: s.auto_approve.clone(),
        auto_allow_once: s.auto_allow_once,
        subscription_action_id: s.subscription_action_id.clone(),
        fingerprint: DEFAULT_FINGERPRINT.to_string(),
        tls_engine: DEFAULT_TLS_ENGINE.to_string(),
        source: Source::Legacy,
        config_found: true,
        outbound: OutboundRef {
            kind: OutboundKind::Direct,
            tag: String::new(),
            typ: "direct".to_string(),
            from: String::new(),
            raw: None,
        },
        ..Default::default()
    };
    if s.cookies_file_present {
        p.cookies_file = resolve_cookies_file(base_dir, paths, &s.cookies_file, name)?;
    }
    if s.vm_id_present {
        p.vm_id = s.vm_id.clone();
        p.vm_id_present = true;
    }
    if s.node_id_present {
        p.node_id = s.node_id.clone();
        p.node_id_present = true;
    }
    if s.fingerprint_present {
        p.fingerprint = s.fingerprint.clone();
        p.fingerprint_present = true;
    }
    if s.tls_engine_present {
        p.tls_engine = s.tls_engine.clone();
        p.tls_engine_present = true;
    }
    Ok(p)
}

/// `defaultProfile` (`migrate.go:810`): the defaults
/// for a profile with no legacy file. Note
/// `config_found` stays false here (unlike
/// `apply_legacy`): a missing file yields defaults, not
/// a file-backed entry.
fn default_profile(paths: &Paths, name: &str) -> Profile {
    Profile {
        name: name.to_string(),
        dir: paths.dir.clone(),
        config_file: paths.config.clone(),
        cookies_file: paths.cookies.clone(),
        chat_file: paths.chat.clone(),
        auto_approve: "off".to_string(),
        fingerprint: DEFAULT_FINGERPRINT.to_string(),
        tls_engine: DEFAULT_TLS_ENGINE.to_string(),
        source: Source::Legacy,
        outbound: OutboundRef {
            kind: OutboundKind::Direct,
            tag: String::new(),
            typ: "direct".to_string(),
            from: String::new(),
            raw: None,
        },
        ..Default::default()
    }
}

/// `migrateLegacyProfile` (`migrate.go:821`): load one
/// legacy profile strictly. A missing config file yields
/// defaults. It never writes.
fn migrate_legacy_profile(
    base_dir: &str,
    name: &str,
    paths: &Paths,
) -> Result<Profile, ConfigError> {
    match read_regular_file(&paths.config) {
        Err(ReadRegularError::NotExist) => Ok(default_profile(paths, name)),
        Err(ReadRegularError::Other(inner)) => Err(config_error(format!(
            "profile {}: read config: {}",
            go_quote(name),
            inner
        ))),
        Ok(data) => {
            let s = parse_legacy_config(&data)?;
            apply_legacy(name, paths, &s, base_dir)
        }
    }
}

/// `legacyProfileSettingsEqual` (`migrate.go:839`):
/// compare the settings a legacy file carries
/// (cookies_file, vm_id, node_id, auto_approve,
/// auto_allow_once, subscription_action_id,
/// fingerprint, tls_engine). The outbound is excluded:
/// a legacy file never carries one. Cookies files
/// compare equal when literally equal, or when both are
/// the profile's own default cookies path.
fn legacy_profile_settings_equal(a: &Profile, b: &Profile) -> bool {
    let cookies_equal = a.cookies_file == b.cookies_file
        || (a.cookies_file == go_join(&[&a.dir, "cookies.txt"])
            && b.cookies_file == go_join(&[&b.dir, "cookies.txt"]));
    cookies_equal
        && a.vm_id == b.vm_id
        && a.node_id == b.node_id
        && a.auto_approve == b.auto_approve
        && a.auto_allow_once == b.auto_allow_once
        && a.subscription_action_id == b.subscription_action_id
        && a.fingerprint == b.fingerprint
        && a.tls_engine == b.tls_engine
}

/// `migrateWarnings` (`migrate.go:872`): `missing
/// cookies file`, `node_id generated`, else (dry-run
/// only) `node_id will be generated on --write`.
fn migrate_warnings(p: &Profile, write: bool, generated_set: &HashSet<String>) -> Vec<String> {
    let mut warnings = Vec::new();
    if std::fs::metadata(&p.cookies_file).is_err() {
        warnings.push("missing cookies file".to_string());
    }
    if generated_set.contains(&p.name) {
        warnings.push("node_id generated".to_string());
    } else if (!p.node_id_present || p.node_id.is_empty()) && !write {
        warnings.push("node_id will be generated on --write".to_string());
    }
    warnings
}

// ---------------------------------------------------------------------
// DNS detour walk (authorInterimDNS / singleDNSDetour)
// ---------------------------------------------------------------------

/// One outbound/endpoint/inline node in the tag graph,
/// resolved by tag for detour-chain walking
/// (`migrate.go`, `detourNode`).
struct DetourNode<'a> {
    tag: String,
    typ: String,
    options: &'a JsonValue,
}

/// `lookupDetourNode` (`migrate.go:998`): resolve a tag
/// to its node — an outbound, an endpoint, or another
/// profile's inline outbound. A tag that resolves to
/// nothing is not found; the caller decides whether that
/// is a dangling reference (left for validateTagGraph)
/// or an unusable path.
fn lookup_detour_node<'a>(cfg: &'a SingleConfig, tag: &str) -> Option<DetourNode<'a>> {
    for raw in &cfg.outbounds_raw {
        if let JsonValue::Object(obj) = raw
            && let Some(JsonValue::Str(t)) = obj.get("tag")
            && t == tag
        {
            let typ = match obj.get("type") {
                Some(JsonValue::Str(t)) => t.clone(),
                _ => String::new(),
            };
            return Some(DetourNode {
                tag: tag.to_string(),
                typ,
                options: raw,
            });
        }
    }
    for raw in &cfg.endpoints_raw {
        if let JsonValue::Object(obj) = raw
            && let Some(JsonValue::Str(t)) = obj.get("tag")
            && t == tag
        {
            let typ = match obj.get("type") {
                Some(JsonValue::Str(t)) => t.clone(),
                _ => String::new(),
            };
            return Some(DetourNode {
                tag: tag.to_string(),
                typ,
                options: raw,
            });
        }
    }
    for p in cfg.profiles.values() {
        if p.outbound.kind == OutboundKind::Inline && p.outbound.tag == tag {
            let Some(raw) = &p.outbound.raw else {
                return None;
            };
            let typ = match raw {
                JsonValue::Object(obj) => match obj.get("type") {
                    Some(JsonValue::Str(t)) => t.clone(),
                    _ => String::new(),
                },
                _ => String::new(),
            };
            return Some(DetourNode {
                tag: tag.to_string(),
                typ,
                options: raw,
            });
        }
    }
    None
}

/// `selectorSelected` (`migrate.go:1030`): the one
/// member upstream dials for a selector — its Default
/// when set and a member, else its first member. A
/// Default naming a non-member, or an empty member
/// list, selects nothing.
fn selector_selected(options: &JsonValue) -> Option<String> {
    let JsonValue::Object(obj) = options else {
        return None;
    };
    let members: Vec<String> = match obj.get("outbounds") {
        Some(JsonValue::Array(list)) => list
            .iter()
            .filter_map(|m| match m {
                JsonValue::Str(s) => Some(s.clone()),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    };
    if members.is_empty() {
        return None;
    }
    if let Some(JsonValue::Str(d)) = obj.get("default")
        && !d.is_empty()
    {
        if members.contains(d) {
            return Some(d.clone());
        }
        return None;
    }
    Some(members[0].clone())
}

/// Whether a direct outbound carries any non-zero
/// DialerOptions field (sing-box v1.14.4
/// `option/outbound.go`, `DialerOptions` + the
/// `AbstractDialerOptions` it embeds; `detour` is
/// handled by the caller before the switch, and
/// `override_address` / `override_port` /
/// `proxy_protocol` are NOT DialerOptions, so they do
/// not count — Go compares `TakeDialerOptions()` only,
/// after forcing `UDPFragmentDefault` true, a field no
/// parsed config can set, `json:"-"`).
///
/// Zero values: empty strings, `0` numbers, `false`
/// bools, `"0s"`/`"0"`/`""` durations, `null`. The
/// pointer fields (`udp_fragment`, `domain_resolver`,
/// `network_strategy`) count when present and non-null,
/// even when `false` for `udp_fragment` (a non-nil
/// pointer differs from the zero value). An empty
/// `network_type` / `fallback_network_type` list counts
/// as zero (documented approximation: Go's
/// `reflect.DeepEqual` distinguishes an empty slice
/// from nil, but an empty list is pathological input).
fn direct_dialer_options_nonempty(options: &JsonValue) -> bool {
    let JsonValue::Object(obj) = options else {
        return false;
    };
    let non_empty_string =
        |v: &JsonValue| -> bool { matches!(v, JsonValue::Str(s) if !s.is_empty()) };
    let non_zero_duration = |v: &JsonValue| -> bool {
        match v {
            JsonValue::Str(s) => !(s.is_empty() || s == "0s" || s == "0"),
            _ => false,
        }
    };
    for key in [
        "bind_interface",
        "inet4_bind_address",
        "inet6_bind_address",
        "protect_path",
        "netns",
        "domain_strategy",
    ] {
        if let Some(v) = obj.get(key)
            && non_empty_string(v)
        {
            return true;
        }
    }
    for key in [
        "bind_address_no_port",
        "reuse_addr",
        "tcp_fast_open",
        "tcp_multi_path",
        "disable_tcp_keep_alive",
    ] {
        if let Some(JsonValue::Bool(true)) = obj.get(key) {
            return true;
        }
    }
    if let Some(JsonValue::Number(lit)) = obj.get("routing_mark")
        && lit.parse::<i64>().unwrap_or(0) != 0
    {
        return true;
    }
    for key in [
        "connect_timeout",
        "tcp_keep_alive",
        "tcp_keep_alive_interval",
        "fallback_delay",
    ] {
        if let Some(v) = obj.get(key)
            && non_zero_duration(v)
        {
            return true;
        }
    }
    for key in ["udp_fragment", "domain_resolver", "network_strategy"] {
        if let Some(v) = obj.get(key)
            && !matches!(v, JsonValue::Null)
        {
            return true;
        }
    }
    for key in ["network_type", "fallback_network_type"] {
        if let Some(JsonValue::Array(list)) = obj.get(key)
            && !list.is_empty()
        {
            return true;
        }
    }
    false
}

/// `detourNodeCanDial` (`migrate.go:1063`): whether
/// dialing through `node` can ever succeed, walking
/// detour fields and selector selected members
/// recursively (visiting guards detour cycles).
/// `as_detour_target` distinguishes the two ways a node
/// is reached: as a DETOUR target (an empty direct
/// outbound is refused) or as a node dialed through
/// directly (a direct member dials fine even though it
/// cannot itself serve as a detour target).
fn detour_node_can_dial(
    cfg: &SingleConfig,
    node: &DetourNode,
    visiting: &mut HashSet<String>,
    as_detour_target: bool,
) -> bool {
    if !node.tag.is_empty() {
        if visiting.contains(&node.tag) {
            return false;
        }
        visiting.insert(node.tag.clone());
    }
    let result = detour_node_can_dial_inner(cfg, node, visiting, as_detour_target);
    if !node.tag.is_empty() {
        visiting.remove(&node.tag);
    }
    result
}

fn detour_node_can_dial_inner(
    cfg: &SingleConfig,
    node: &DetourNode,
    visiting: &mut HashSet<String>,
    as_detour_target: bool,
) -> bool {
    // A detour field takes precedence: dialing goes
    // through the detour target first, and the detour
    // target is always reached as a detour target.
    if !detour_of(node.options).is_empty() {
        let target_tag = detour_of(node.options).to_string();
        let Some(target) = lookup_detour_node(cfg, &target_tag) else {
            return false;
        };
        return detour_node_can_dial(cfg, &target, visiting, true);
    }
    match node.typ.as_str() {
        "direct" => {
            if as_detour_target {
                direct_dialer_options_nonempty(node.options)
            } else {
                true
            }
        }
        "selector" => {
            let Some(selected) = selector_selected(node.options) else {
                return false;
            };
            let Some(target) = lookup_detour_node(cfg, &selected) else {
                return false;
            };
            detour_node_can_dial(cfg, &target, visiting, false)
        }
        // Unusable in castctl runtime regardless of
        // members (urltest needs a URL test history
        // storage service the manager context never
        // registers); block/bridge never dial, upstream.
        "urltest" | "block" | "bridge" => false,
        // Any other outbound/endpoint type dials through
        // its own transport.
        _ => true,
    }
}

/// `detourTagForProfile` (`migrate.go:1156`): the tag a
/// dns detour for `p` would name, or `""` when `p` is
/// direct-only or every detour chain from `p`
/// terminates unusably. A tag that resolves to nothing
/// is returned as-is and left for validateTagGraph to
/// reject as dangling.
fn detour_tag_for_profile(cfg: &SingleConfig, p: &Profile) -> String {
    match p.outbound.kind {
        OutboundKind::Tag => {
            let Some(node) = lookup_detour_node(cfg, &p.outbound.tag) else {
                return p.outbound.tag.clone();
            };
            if detour_node_can_dial(cfg, &node, &mut HashSet::new(), true) {
                p.outbound.tag.clone()
            } else {
                String::new()
            }
        }
        OutboundKind::Inline => {
            let Some(raw) = &p.outbound.raw else {
                return p.outbound.tag.clone();
            };
            let typ = match raw {
                JsonValue::Object(obj) => match obj.get("type") {
                    Some(JsonValue::Str(t)) => t.clone(),
                    _ => return p.outbound.tag.clone(),
                },
                _ => return p.outbound.tag.clone(),
            };
            let node = DetourNode {
                tag: p.outbound.tag.clone(),
                typ,
                options: raw,
            };
            if detour_node_can_dial(cfg, &node, &mut HashSet::new(), true) {
                p.outbound.tag.clone()
            } else {
                String::new()
            }
        }
        OutboundKind::Direct => String::new(),
    }
}

/// `singleDNSDetour` (`migrate.go:944`): the one detour
/// tag every profile in `cfg` routes through. When no
/// single detour exists, the second return names the
/// first profile in sorted order that has no detour tag
/// or a different one, and ok is false. With no profiles
/// at all: `("", "", false)`.
fn single_dns_detour(cfg: &SingleConfig) -> (String, String, bool) {
    if cfg.profiles.is_empty() {
        return (String::new(), String::new(), false);
    }
    let mut detour = String::new();
    for (name, p) in &cfg.profiles {
        let tag = detour_tag_for_profile(cfg, p);
        if detour.is_empty() {
            if tag.is_empty() {
                return (String::new(), name.clone(), false);
            }
            detour = tag;
            continue;
        }
        if tag != detour {
            return (String::new(), name.clone(), false);
        }
    }
    (detour, String::new(), true)
}

// ---------------------------------------------------------------------
// DNS authoring / distribution
// ---------------------------------------------------------------------

/// The tag of the single server in the interim global
/// dns section (`migrate.go`, `interimDNSServerTag`).
const INTERIM_DNS_SERVER_TAG: &str = "castctl-doh";

/// `stripErrorPrefix` (`dns_distribute.go:249`):
/// remove the standard `"profile: "` error prefix from
/// an embedded validation or parse error, so a
/// distribution refusal quoting it does not read
/// `"profile: profile ..."`. Only one leading prefix
/// is removed, and only when present.
fn strip_error_prefix(s: &str) -> &str {
    s.strip_prefix("profile: ").unwrap_or(s)
}

/// `authorInterimDNS` (`migrate.go:1179`): author the
/// INTERIM global dns section onto `candidate` when it
/// has no dns section, the existing single file (when
/// one exists) is otherwise identical to the candidate,
/// and a single detour serves every profile. The
/// authored section is the gated default only: one DoH
/// server (https, IP-literal 1.1.1.1, no bootstrap
/// hostname, path /dns-query) through the shared
/// detour. Authoring is validated with the same checks
/// a hand-written section faces; a validation failure
/// falls back to no section with the refusal recorded.
/// Returns `(authored, refusal)`; `refusal` is `""`
/// when authoring was not applicable (a section already
/// exists, or the config differs).
fn author_interim_dns(candidate: &mut SingleConfig, existing: &SingleConfig) -> (bool, String) {
    if candidate.dns_raw.is_some() {
        return (false, String::new());
    }
    // Per-profile DNS (G1 coexistence): authoring a
    // global section onto a config where any profile
    // already carries its own dns block would produce a
    // file the loader rejects.
    for (name, p) in &candidate.profiles {
        if p.dns_present {
            return (
                false,
                format!(
                    "dns section not authored: profile {} already has a per-profile dns block; a top-level dns section would conflict (see docs/config.md)",
                    go_quote(name)
                ),
            );
        }
    }
    match configs_equal(&strip_dns(existing), &strip_dns(candidate)) {
        Ok(true) => {}
        _ => return (false, String::new()),
    }
    let (detour, refusing, ok) = single_dns_detour(candidate);
    if !ok {
        if refusing.is_empty() {
            return (false, String::new());
        }
        return (
            false,
            format!(
                "dns section not authored: profile {} does not share one detour tag with every other profile (direct-only, or a different outbound tag); add a shared outbound and re-run config migrate, or add a dns section by hand (see docs/config.md)",
                go_quote(&refusing)
            ),
        );
    }
    // The authored server's key order is tag first
    // (unlike a hand-written section, where type comes
    // first).
    let mut server = OrderedObject::new();
    server.set(
        "tag".to_string(),
        JsonValue::Str(INTERIM_DNS_SERVER_TAG.to_string()),
    );
    server.set("type".to_string(), JsonValue::Str("https".to_string()));
    server.set("server".to_string(), JsonValue::Str("1.1.1.1".to_string()));
    server.set(
        "server_port".to_string(),
        JsonValue::Number("443".to_string()),
    );
    server.set("path".to_string(), JsonValue::Str("/dns-query".to_string()));
    server.set("detour".to_string(), JsonValue::Str(detour));
    let mut dns = OrderedObject::new();
    dns.set(
        "servers".to_string(),
        JsonValue::Array(vec![JsonValue::Object(server)]),
    );
    dns.set(
        "final".to_string(),
        JsonValue::Str(INTERIM_DNS_SERVER_TAG.to_string()),
    );
    candidate.dns_raw = Some(JsonValue::Object(dns));
    if let Err(e) = validate_tag_graph(candidate) {
        candidate.dns_raw = None;
        return (false, format!("dns section not authored: {}", e.message));
    }
    if let Err(e) = validate_wireguard_private_keys(candidate) {
        candidate.dns_raw = None;
        return (false, format!("dns section not authored: {}", e.message));
    }
    (true, String::new())
}

/// Whether a parsed DNS server object carries a detour
/// field (`dns_distribute.go`, `carriesDetour`): every
/// type except `hosts` and `fakeip`.
fn dns_server_carries_detour(typ: &str) -> bool {
    typ != "hosts" && typ != "fakeip"
}

/// `distributeTopLevelDNS` (`dns_distribute.go:59`):
/// copy the candidate's top-level dns section verbatim
/// into every profile's own dns block and remove the
/// top-level key, in memory only. Returns
/// `(distributed, refusal, error)`; any refusal is
/// all-or-nothing — the candidate is left unmutated —
/// and the refusal names the profile and the field/tag
/// that failed. Detour mapping per profile: empty /
/// missing detour → filled with the profile's own
/// detour tag; equal to the own tag → kept; reachable
/// but different → kept; unreachable → the whole run
/// refuses.
fn distribute_top_level_dns(
    candidate: &mut SingleConfig,
    base_dir: &str,
) -> (bool, String, Option<ConfigError>) {
    let Some(dns_raw) = candidate.dns_raw.clone() else {
        return (false, String::new(), None);
    };
    // No-recipient guard (F1): distribution that would
    // delete the top-level section while no profile
    // receives a copy is a silent deletion, not a
    // distribution.
    if candidate.profiles.is_empty() {
        let refusal = "dns distribution refused: top-level dns section is present but no profile would receive a distributed dns block (no non-nil profile entries); refusing to delete the section without distributing it (see docs/config.md)".to_string();
        return (false, refusal.clone(), Some(config_error(refusal)));
    }
    let (parsed_servers, _, _) = parse_dns_block(&dns_raw);
    if parsed_servers.is_empty() {
        let first = candidate
            .profiles
            .keys()
            .next()
            .cloned()
            .unwrap_or_default();
        let refusal = format!(
            "dns distribution refused: profile {}: top-level dns section has no servers; refusing to distribute an empty dns section (see docs/config.md)",
            go_quote(&first)
        );
        return (false, refusal.clone(), Some(config_error(refusal)));
    }
    // Guards that read state before any mutation.
    for (name, p) in &candidate.profiles {
        if p.dns_present {
            let refusal = format!(
                "dns distribution refused: profile {} already has a per-profile dns block; distribution would overwrite it (see docs/config.md)",
                go_quote(name)
            );
            return (false, refusal.clone(), Some(config_error(refusal)));
        }
    }
    for (name, p) in &candidate.profiles {
        if let Some((tag, _)) = wireguard_dns_for_profile(p, candidate) {
            let refusal = format!(
                "dns distribution refused: profile {} resolves WireGuard DNS through endpoint {}; distributing the top-level dns section would shadow it with a per-profile dns block (see docs/config.md)",
                go_quote(name),
                go_quote(&tag)
            );
            return (false, refusal.clone(), Some(config_error(refusal)));
        }
    }

    // Phase 1: compute every per-profile block without
    // mutating the candidate, so a refusal in any profile
    // leaves the whole candidate untouched.
    let mut pending: BTreeMap<String, JsonValue> = BTreeMap::new();
    for (name, p) in &candidate.profiles {
        let (own_detour, _) = default_detour_for_profile(p);
        let reachable = reachable_tags_for_profile(candidate, p);
        let JsonValue::Object(mut obj) = dns_raw.clone() else {
            let refusal = format!(
                "dns distribution refused: profile {}: top-level dns section is not a JSON object",
                go_quote(name)
            );
            return (false, refusal.clone(), Some(config_error(refusal)));
        };
        if let Some(servers_val) = obj.get("servers").cloned() {
            let JsonValue::Array(servers) = &servers_val else {
                let refusal = format!(
                    "dns distribution refused: profile {}: top-level dns servers do not match the parsed dns section",
                    go_quote(name)
                );
                return (false, refusal.clone(), Some(config_error(refusal)));
            };
            if servers.len() != parsed_servers.len() {
                let refusal = format!(
                    "dns distribution refused: profile {}: top-level dns servers do not match the parsed dns section",
                    go_quote(name)
                );
                return (false, refusal.clone(), Some(config_error(refusal)));
            }
            let mut edited: Vec<JsonValue> = Vec::new();
            for (i, elem) in servers.iter().enumerate() {
                let JsonValue::Object(_) = elem else {
                    let refusal = format!(
                        "dns distribution refused: profile {}: dns server {} is not a JSON object",
                        go_quote(name),
                        i
                    );
                    return (false, refusal.clone(), Some(config_error(refusal)));
                };
                let parsed_srv = &parsed_servers[i];
                if !dns_server_carries_detour(&parsed_srv.typ) {
                    // hosts/fakeip: no detour field exists;
                    // copy untouched (per-profile validation
                    // below refuses the candidate, since a
                    // detour-less server cannot satisfy G2).
                    edited.push(elem.clone());
                    continue;
                }
                let current = parsed_srv.detour.clone();
                if current.is_empty() {
                    let mut srv = match elem {
                        JsonValue::Object(o) => o.clone(),
                        _ => unreachable!(),
                    };
                    srv.set("detour".to_string(), JsonValue::Str(own_detour.clone()));
                    edited.push(JsonValue::Object(srv));
                } else if current == own_detour || reachable.contains(&current) {
                    // Keep verbatim: rewriting a reachable
                    // detour would silently reroute DNS.
                    edited.push(elem.clone());
                } else {
                    let refusal = format!(
                        "dns distribution refused: profile {}: dns server {} detour {} is not reachable from this profile's outbound (see docs/config.md)",
                        go_quote(name),
                        go_quote(&parsed_srv.tag),
                        go_quote(&current)
                    );
                    return (false, refusal.clone(), Some(config_error(refusal)));
                }
            }
            obj.set("servers".to_string(), JsonValue::Array(edited));
        }
        let block = JsonValue::Object(obj);
        // The distributed block must parse: run the
        // same light shape check the top-level section
        // faces at load.
        let shape_cfg = SingleConfig {
            dns_raw: Some(block.clone()),
            ..Default::default()
        };
        if let Err(e) = validate_top_level_dns_shape(&shape_cfg) {
            let refusal = format!(
                "dns distribution refused: profile {}: distributed dns block does not parse: {}",
                go_quote(name),
                strip_error_prefix(&e.message)
            );
            return (false, refusal.clone(), Some(config_error(refusal)));
        }
        pending.insert(name.clone(), block);
    }

    // Phase 2: apply, then validate the whole candidate
    // exactly as a hand-written file is validated. On
    // any failure restore the pre-distribution state.
    let saved_dns_raw = candidate.dns_raw.clone();
    let mut saved_profiles: Vec<(String, Option<JsonValue>, bool)> = Vec::new();
    for (name, p) in &candidate.profiles {
        saved_profiles.push((name.clone(), p.dns.clone(), p.dns_present));
    }
    for (name, p) in candidate.profiles.iter_mut() {
        if let Some(block) = pending.get(name) {
            p.dns = Some(block.clone());
            p.dns_present = true;
        }
    }
    candidate.dns_raw = None;

    let validate = |candidate: &mut SingleConfig| -> Result<(), ConfigError> {
        validate_tag_graph(candidate)?;
        validate_profile_dns(candidate)?;
        validate_wireguard_dns(candidate)?;
        validate_wireguard_private_keys(candidate)?;
        // Full re-parse of the canonical encoding: the
        // distributed file must load exactly as written.
        let encoded = encode_single_config(candidate)?;
        let mut reparsed = parse_single_config(encoded.as_bytes(), base_dir)?;
        validate_single_config(&mut reparsed)?;
        Ok(())
    };
    if let Err(e) = validate(candidate) {
        candidate.dns_raw = saved_dns_raw;
        for (name, dns, dns_present) in saved_profiles {
            if let Some(p) = candidate.profiles.get_mut(&name) {
                p.dns = dns;
                p.dns_present = dns_present;
            }
        }
        let refusal = format!(
            "dns distribution refused: {}",
            strip_error_prefix(&e.message)
        );
        return (false, refusal.clone(), Some(config_error(refusal)));
    }
    (true, String::new(), None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "castctl-config-migrate-{tag}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn fixture_dir() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("m7d-migrate")
    }

    fn fixture_text(name: &str) -> String {
        std::fs::read_to_string(fixture_dir().join(name)).unwrap()
    }

    fn copy_dir_recursive(src: &std::path::Path, dst: &std::path::Path) {
        std::fs::create_dir_all(dst).unwrap();
        for entry in std::fs::read_dir(src).unwrap() {
            let entry = entry.unwrap();
            let to = dst.join(entry.file_name());
            if entry.file_type().unwrap().is_dir() {
                copy_dir_recursive(&entry.path(), &to);
            } else {
                std::fs::copy(entry.path(), to).unwrap();
            }
        }
    }

    fn mode_of(path: &std::path::Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    const DNS_REFUSAL_FIRST: &str = "dns section not authored: profile \"default\" has no outbound tag for a dns detour (direct-only); add an outbound and re-run config migrate, or add a dns section by hand (see docs/config.md)";
    const DNS_REFUSAL_SECOND: &str = "dns section not authored: profile \"default\" does not share one detour tag with every other profile (direct-only, or a different outbound tag); add a shared outbound and re-run config migrate, or add a dns section by hand (see docs/config.md)";

    #[test]
    fn migrate_cross_dir_dry_run_write_and_idempotent_match_go() {
        let root = temp_dir("crossdir");
        let src = root.join("legacy-src");
        copy_dir_recursive(&fixture_dir().join("legacy-src"), &src);
        let dest = root.join("legacy-dest");
        std::fs::create_dir_all(&dest).unwrap();
        let src_s = src.to_string_lossy().into_owned();
        let dest_s = dest.to_string_lossy().into_owned();
        // Collect every file under src with its bytes, so the
        // test can prove the source is untouched.
        let mut src_before: Vec<(std::path::PathBuf, Vec<u8>)> = Vec::new();
        fn collect(dir: &std::path::Path, out: &mut Vec<(std::path::PathBuf, Vec<u8>)>) {
            for e in std::fs::read_dir(dir).unwrap() {
                let e = e.unwrap();
                let p = e.path();
                if e.file_type().unwrap().is_dir() {
                    collect(&p, out);
                } else {
                    out.push((p.clone(), std::fs::read(&p).unwrap()));
                }
            }
        }
        collect(&src, &mut src_before);

        // Dry-run: byte-exact result JSON against the R3
        // verbatim output (paths substituted).
        let (result, err) = migrate_from(&src_s, &dest_s, false);
        assert!(err.is_none(), "err: {err:?}");
        assert!(result.would_write);
        assert!(!result.migrated);
        assert_eq!(result.reason, "");
        assert_eq!(result.default_profile, "default");
        assert!(!result.existing_single_config);
        assert!(result.errors.is_empty());
        assert_eq!(result.dns_refusal, DNS_REFUSAL_FIRST);
        assert_eq!(result.profiles.len(), 2);
        assert_eq!(result.profiles[0].name, "default");
        assert_eq!(result.profiles[0].source, "legacy");
        assert_eq!(
            result.profiles[0].cookies_file,
            format!("{src_s}/cookies.txt")
        );
        assert!(result.profiles[0].warnings.is_empty());
        assert_eq!(result.profiles[1].name, "muse01");
        let rendered = render_migrate_result(&result).unwrap();
        let expected = r#"{
  "source_dir": "__SRC__",
  "destination_dir": "__DEST__",
  "would_write": true,
  "migrated": false,
  "default_profile": "default",
  "profiles": [
    {
      "name": "default",
      "source": "legacy",
      "cookies_file": "__SRC__/cookies.txt",
      "outbound": null,
      "warnings": []
    },
    {
      "name": "muse01",
      "source": "legacy",
      "cookies_file": "__SRC__/profiles/muse01/cookies.txt",
      "outbound": null,
      "warnings": []
    }
  ],
  "existing_single_config": false,
  "errors": [],
  "dns_refusal": "dns section not authored: profile \"default\" has no outbound tag for a dns detour (direct-only); add an outbound and re-run config migrate, or add a dns section by hand (see docs/config.md)"
}"#
        .replace("__SRC__", &src_s)
        .replace("__DEST__", &dest_s);
        assert_eq!(rendered, expected, "rendered:\n{rendered}");
        // Dry-run writes NOTHING: the destination stays empty.
        assert!(std::fs::read_dir(&dest).unwrap().next().is_none());

        // --write: same result except would_write/migrated,
        // and the written bytes match Go's output exactly.
        let (result, err) = migrate_from(&src_s, &dest_s, true);
        assert!(err.is_none(), "err: {err:?}");
        assert!(!result.would_write);
        assert!(result.migrated);
        assert!(result.generated.is_empty());
        let written = std::fs::read_to_string(dest.join("config.json")).unwrap();
        let expected_file = fixture_text("migrate-crossdir-written-config.json")
            .replace("/tmp/m7d-probes/legacy-src", &src_s);
        assert_eq!(written, expected_file, "written:\n{written}");
        assert_eq!(mode_of(&dest.join("config.json")), 0o600);
        assert!(dest.join("config.json.lock").exists());
        // Source untouched byte-for-byte.
        for (path, bytes) in &src_before {
            assert_eq!(&std::fs::read(path).unwrap(), bytes, "changed: {path:?}");
        }

        // Second run: already-migrated, profiles now single,
        // dns_refusal switches to the second wording (D5).
        let (result, err) = migrate_from(&src_s, &dest_s, false);
        assert!(err.is_none(), "err: {err:?}");
        assert_eq!(result.reason, "already-migrated");
        assert!(!result.would_write);
        assert!(result.existing_single_config);
        assert_eq!(result.profiles[0].source, "single");
        assert_eq!(result.profiles[1].source, "single");
        assert_eq!(result.dns_refusal, DNS_REFUSAL_SECOND);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn migrate_same_dir_matches_go_and_keeps_legacy_files() {
        let root = temp_dir("samedir");
        let dir = root.join("mig-same");
        copy_dir_recursive(&fixture_dir().join("legacy-src"), &dir);
        let dir_s = dir.to_string_lossy().into_owned();
        let (result, err) = migrate_from(&dir_s, &dir_s, true);
        assert!(err.is_none(), "err: {err:?}");
        assert!(result.migrated);
        let written = std::fs::read_to_string(dir.join("config.json")).unwrap();
        let expected_file = fixture_text("migrate-samedir-written-config.json")
            .replace("/tmp/m7d-probes/mig-same", &dir_s);
        assert_eq!(written, expected_file, "written:\n{written}");
        // Legacy files are KEPT (plus a 0-byte lock file).
        assert!(dir.join("cookies.txt").exists());
        assert!(
            dir.join("profiles")
                .join("muse01")
                .join("config.json")
                .exists()
        );
        assert!(dir.join("config.json.lock").exists());
        // Re-run: already-migrated.
        let (result, err) = migrate_from(&dir_s, &dir_s, true);
        assert!(err.is_none(), "err: {err:?}");
        assert_eq!(result.reason, "already-migrated");
        assert!(!result.migrated);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn migrate_dns_distribution_matches_go() {
        let root = temp_dir("dnsdist");
        let dest = root.join("mig-dns");
        std::fs::create_dir_all(&dest).unwrap();
        let dest_s = dest.to_string_lossy().into_owned();
        let input =
            fixture_text("mig-dns-config-input.json").replace("/tmp/m7d-probes/mig-dns", &dest_s);
        std::fs::write(dest.join("config.json"), &input).unwrap();
        let (result, err) = migrate_from(&dest_s, &dest_s, false);
        assert!(err.is_none(), "err: {err:?}");
        assert!(result.would_write);
        assert!(result.dns_distributed);
        assert!(result.dns_refusal.is_empty());
        assert_eq!(result.reason, "");
        let (result, err) = migrate_from(&dest_s, &dest_s, true);
        assert!(err.is_none(), "err: {err:?}");
        assert!(result.migrated);
        assert_eq!(result.reason, "dns-distributed");
        assert!(result.dns_distributed);
        let written = std::fs::read_to_string(dest.join("config.json")).unwrap();
        let expected_file = fixture_text("migrate-dns-distributed-config.json")
            .replace("/tmp/m7d-probes/mig-dns", &dest_s);
        assert_eq!(written, expected_file, "written:\n{written}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn migrate_dns_authoring_matches_go() {
        let root = temp_dir("dnsauth");
        let dest = root.join("mig-auth");
        std::fs::create_dir_all(&dest).unwrap();
        let dest_s = dest.to_string_lossy().into_owned();
        std::fs::write(
            dest.join("config.json"),
            fixture_text("mig-auth-config-input.json"),
        )
        .unwrap();
        let (result, err) = migrate_from(&dest_s, &dest_s, false);
        assert!(err.is_none(), "err: {err:?}");
        assert!(result.would_write);
        assert!(result.dns_authored);
        assert!(result.dns_refusal.is_empty());
        let (result, err) = migrate_from(&dest_s, &dest_s, true);
        assert!(err.is_none(), "err: {err:?}");
        assert!(result.migrated);
        assert_eq!(result.reason, "dns-authored");
        assert!(result.dns_authored);
        let written = std::fs::read_to_string(dest.join("config.json")).unwrap();
        let expected_file = fixture_text("migrate-dns-authored-config.json")
            .replace("/tmp/m7d-probes/mig-auth", &dest_s);
        assert_eq!(written, expected_file, "written:\n{written}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn migrate_refuse_overwrite_keeps_destination_bytes() {
        let root = temp_dir("refuse");
        let src = root.join("legacy-src");
        copy_dir_recursive(&fixture_dir().join("legacy-src"), &src);
        let dest = root.join("dest");
        std::fs::create_dir_all(&dest).unwrap();
        let before = "{\"default_profile\":\"other\",\"profiles\":{\"other\":{}}}\n";
        std::fs::write(dest.join("config.json"), before).unwrap();
        let (result, err) = migrate_from(&src.to_string_lossy(), &dest.to_string_lossy(), true);
        let err = err.expect("must refuse");
        assert_eq!(
            err.message,
            "profile: existing single config differs from what migrate would write; refusing to overwrite (no --overwrite in this design)"
        );
        assert_eq!(result.reason, "refuse-overwrite");
        assert!(!result.would_write);
        assert!(!result.migrated);
        assert!(result.existing_single_config);
        assert!(result.dns_refusal.is_empty());
        assert_eq!(result.profiles[0].name, "other");
        assert_eq!(result.profiles[0].source, "single");
        assert_eq!(result.profiles[0].warnings, vec!["missing cookies file"]);
        assert_eq!(
            std::fs::read_to_string(dest.join("config.json")).unwrap(),
            before
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn migrate_missing_source_dir_and_not_a_directory() {
        let root = temp_dir("badsrc");
        let dest = root.join("dest");
        std::fs::create_dir_all(&dest).unwrap();
        let dest_s = dest.to_string_lossy().into_owned();
        let (result, err) = migrate_from("/tmp/definitely-no-such-castctl-dir", &dest_s, true);
        let err = err.expect("must fail");
        assert_eq!(
            err.message,
            "profile: migrate: source directory \"/tmp/definitely-no-such-castctl-dir\" does not exist"
        );
        // D6: the result reports existing_single_config
        // false even though the destination HAS a config
        // file — the source check returns before the
        // destination is read.
        assert_eq!(result.default_profile, "");
        assert!(result.profiles.is_empty());
        assert!(!result.existing_single_config);
        let file = dest.join("ob-direct.json");
        std::fs::write(&file, "{}\n").unwrap();
        let (_, err) = migrate_from(&file.to_string_lossy(), &dest_s, true);
        assert_eq!(
            err.expect("must fail").message,
            format!(
                "profile: migrate: source {} is not a directory",
                go_quote(&file.to_string_lossy())
            )
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn migrate_bad_legacy_json_is_a_profile_error() {
        let root = temp_dir("badlegacy");
        let src = root.join("src");
        let bad = src.join("profiles").join("bad");
        std::fs::create_dir_all(&bad).unwrap();
        std::fs::write(bad.join("config.json"), "{invalid json").unwrap();
        let dest = root.join("dest");
        std::fs::create_dir_all(&dest).unwrap();
        let (result, err) = migrate_from(&src.to_string_lossy(), &dest.to_string_lossy(), true);
        let err = err.expect("must fail");
        assert_eq!(err.message, "profile: migrate: 1 profile error(s)");
        assert_eq!(result.errors.len(), 1);
        assert!(
            result.errors[0].contains("parse legacy config:"),
            "error: {}",
            result.errors[0]
        );
        assert!(!dest.join("config.json").exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn migrate_node_id_generated_only_on_write() {
        let root = temp_dir("nodeid");
        let src = root.join("src");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("config.json"), "{\"auto_approve\":\"off\"}").unwrap();
        let dest = root.join("dest");
        std::fs::create_dir_all(&dest).unwrap();
        let (result, err) = migrate_from(&src.to_string_lossy(), &dest.to_string_lossy(), false);
        assert!(err.is_none(), "err: {err:?}");
        assert!(result.generated.is_empty());
        assert_eq!(
            result.profiles[0].warnings,
            vec![
                "missing cookies file",
                "node_id will be generated on --write"
            ]
        );
        let (result, err) = migrate_from(&src.to_string_lossy(), &dest.to_string_lossy(), true);
        assert!(err.is_none(), "err: {err:?}");
        assert!(result.migrated);
        assert_eq!(result.generated, vec!["default"]);
        assert_eq!(
            result.profiles[0].warnings,
            vec!["missing cookies file", "node_id generated"]
        );
        let written = std::fs::read_to_string(dest.join("config.json")).unwrap();
        assert!(written.contains("\"node_id\": "), "written:\n{written}");
        // The generated id is 16 lowercase hex chars.
        let marker = "\"node_id\": \"";
        let start = written.find(marker).expect("node_id in written file") + marker.len();
        let id = &written[start..start + 16];
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()), "id: {id}");
        assert_eq!(&written[start + 16..start + 17], "\"");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn migrate_refuses_single_format_base_file_and_scrubs_generated() {
        let root = temp_dir("singlefmt");
        let src = root.join("src");
        std::fs::create_dir_all(&src).unwrap();
        // A profile WITHOUT a node_id, so generation would
        // claim it — the refusal must scrub that claim.
        std::fs::write(src.join("config.json"), "{\"auto_approve\":\"off\"}").unwrap();
        let dest = root.join("dest");
        std::fs::create_dir_all(&dest).unwrap();
        let dest_config = "{\"outbounds\":[{\"type\":\"socks\",\"tag\":\"x\",\"server\":\"127.0.0.1\",\"server_port\":1080}]}\n";
        std::fs::write(dest.join("config.json"), dest_config).unwrap();
        let (result, err) = migrate_from(&src.to_string_lossy(), &dest.to_string_lossy(), true);
        let err = err.expect("must refuse");
        assert!(
            err.message
                .contains("carries single-format section(s) \"outbounds\""),
            "message: {}",
            err.message
        );
        assert_eq!(result.errors.len(), 1);
        // RT-2 scrub: never report an id that was not
        // persisted.
        assert!(result.generated.is_empty());
        assert!(!result.profiles[0].node_id_generated);
        assert!(
            !result.profiles[0]
                .warnings
                .contains(&"node_id generated".to_string()),
            "warnings: {:?}",
            result.profiles[0].warnings
        );
        assert_eq!(
            std::fs::read_to_string(dest.join("config.json")).unwrap(),
            dest_config
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn migrate_already_migrated_without_legacy_files() {
        let root = temp_dir("alreadymig");
        let dest = root.join("dest");
        std::fs::create_dir_all(&dest).unwrap();
        let dest_s = dest.to_string_lossy().into_owned();
        // cfgA shape: no default_profile key; alpha's cookies
        // file exists, beta's default one does not. Alpha's
        // cookies file MUST live outside the config dir:
        // Go's `readExistingSingle` parses the existing
        // file with `ParseSingleConfig`, which rejects a
        // cookies_file inside the config dir that is not
        // the profile cookies file (config.go:808) — the
        // same refusal migrate would hit in Go.
        let alpha_cookies = root.join("alpha-cookies.txt");
        std::fs::write(&alpha_cookies, "hatch_sess=FAKE\n").unwrap();
        let config = format!(
            "{{\"profiles\":{{\"alpha\":{{\"cookies_file\":{},\"node_id\":\"A1\",\"auto_approve\":\"off\",\"auto_allow_once\":false}},\"beta\":{{\"node_id\":\"B1\",\"auto_approve\":\"off\",\"auto_allow_once\":false}}}}}}\n",
            go_quote(&alpha_cookies.to_string_lossy())
        );
        std::fs::write(dest.join("config.json"), config).unwrap();
        let before = std::fs::read_to_string(dest.join("config.json")).unwrap();
        let (result, err) = migrate_from(&dest_s, &dest_s, false);
        assert!(err.is_none(), "err: {err:?}");
        assert_eq!(result.reason, "already-migrated");
        assert!(!result.would_write);
        assert_eq!(result.default_profile, "default");
        assert_eq!(result.profiles[0].name, "alpha");
        assert_eq!(result.profiles[0].source, "single");
        assert!(result.profiles[0].warnings.is_empty());
        assert_eq!(result.profiles[1].name, "beta");
        assert_eq!(result.profiles[1].warnings, vec!["missing cookies file"]);
        // Second wording (already-migrated re-run), but the
        // profile named is the first sorted profile without
        // a shared detour — "alpha" here, not the "default"
        // baked into DNS_REFUSAL_SECOND (that constant comes
        // from the legacy-src fixture, whose first profile
        // is "default").
        assert_eq!(
            result.dns_refusal,
            "dns section not authored: profile \"alpha\" does not share one detour tag with every other profile (direct-only, or a different outbound tag); add a shared outbound and re-run config migrate, or add a dns section by hand (see docs/config.md)"
        );
        let (result, err) = migrate_from(&dest_s, &dest_s, true);
        assert!(err.is_none(), "err: {err:?}");
        assert_eq!(result.reason, "already-migrated");
        assert_eq!(
            std::fs::read_to_string(dest.join("config.json")).unwrap(),
            before
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn migrate_legacy_parse_strict_shapes() {
        // Unknown "profiles" key is refused.
        let e = parse_legacy_config(b"{\"profiles\":{}}").unwrap_err();
        assert_eq!(
            e.message,
            "profile: \"profiles\" key does not belong in a legacy per-profile config"
        );
        // Wrong-typed string field.
        let e = parse_legacy_config(b"{\"vm_id\": 42}").unwrap_err();
        assert_eq!(e.message, "profile: vm_id must be a string");
        // Invalid fingerprint value.
        let e = parse_legacy_config(b"{\"fingerprint\":\"opera\"}").unwrap_err();
        assert_eq!(
            e.message,
            "profile: fingerprint must be one of chrome, firefox, ios, safari"
        );
        // auto_approve: non-"always" string coerces to off.
        let s = parse_legacy_config(b"{\"auto_approve\":\"sometimes\"}").unwrap();
        assert_eq!(s.auto_approve, "off");
        // auto_allow_once: on-word, bool, bad value.
        let s = parse_legacy_config(b"{\"auto_allow_once\":\"on\"}").unwrap();
        assert!(s.auto_allow_once);
        let s = parse_legacy_config(b"{\"auto_allow_once\":true}").unwrap();
        assert!(s.auto_allow_once);
        let e = parse_legacy_config(b"{\"auto_allow_once\":\"maybe\"}").unwrap_err();
        assert_eq!(
            e.message,
            "profile: auto_allow_once must be a boolean or an on/off word"
        );
        // Unknown keys ignored.
        let s = parse_legacy_config(b"{\"weird_key\": 1}").unwrap();
        assert_eq!(s.auto_approve, "off");
    }

    #[test]
    fn migrate_single_format_keys_shapes() {
        assert!(single_format_keys(b"{\"dns\":{}}").contains(&"dns".to_string()));
        assert!(single_format_keys(b"{\"dns\":\"x\"}").is_empty());
        assert!(
            single_format_keys(b"{\"outbounds\":[{\"type\":\"socks\"},{\"server\":\"x\"}]}")
                .contains(&"outbounds".to_string())
        );
        assert!(single_format_keys(b"{\"outbounds\":[]}").is_empty());
        assert!(
            single_format_keys(b"{\"wireguard_dns\":{\"wg\":[\"1.1.1.1\"]}}")
                .contains(&"wireguard_dns".to_string())
        );
        assert!(single_format_keys(b"{\"wireguard_dns\":{}}").is_empty());
        assert!(single_format_keys(b"{\"log\":{\"level\":\"info\"}}").contains(&"log".to_string()));
        assert!(single_format_keys(b"{\"log\":{}}").is_empty());
        assert!(
            single_format_keys(b"{\"default_profile\":\"x\"}")
                .contains(&"default_profile".to_string())
        );
        assert!(single_format_keys(b"{bad json").is_empty());
    }

    #[test]
    fn migrate_detour_walk_shapes() {
        // Two profiles on the same socks tag: one detour.
        let cfg = crate::config::parse_single_config(
            br#"{"profiles":{"a":{"outbound":"proxy"},"b":{"outbound":"proxy"}},"outbounds":[{"type":"socks","tag":"proxy","server":"127.0.0.1","server_port":1080}]}"#,
            "/tmp",
        )
        .unwrap();
        let mut cfg = cfg;
        crate::dnsvalidate::validate_single_config(&mut cfg).unwrap();
        let (detour, refusing, ok) = single_dns_detour(&cfg);
        assert!(ok, "refusing={refusing}");
        assert_eq!(detour, "proxy");
        // Two profiles on the SAME selector: the selector
        // tag itself is the shared detour (Go
        // `detourTagForProfile` returns the profile's own
        // tag when its node can dial — it does NOT resolve
        // through the selector to the member). A profile on
        // "proxy" and another on "sel" therefore have NO
        // single detour, even though the selector's member
        // is "proxy": the tags differ.
        let cfg = crate::config::parse_single_config(
            br#"{"profiles":{"a":{"outbound":"sel"},"b":{"outbound":"sel"}},"outbounds":[{"type":"socks","tag":"proxy","server":"127.0.0.1","server_port":1080},{"type":"selector","tag":"sel","outbounds":["proxy"],"default":"proxy"}]}"#,
            "/tmp",
        )
        .unwrap();
        let mut cfg = cfg;
        crate::dnsvalidate::validate_single_config(&mut cfg).unwrap();
        let (detour, refusing, ok) = single_dns_detour(&cfg);
        assert!(ok, "refusing={refusing}");
        assert_eq!(detour, "sel");
        let cfg = crate::config::parse_single_config(
            br#"{"profiles":{"a":{"outbound":"proxy"},"b":{"outbound":"sel"}},"outbounds":[{"type":"socks","tag":"proxy","server":"127.0.0.1","server_port":1080},{"type":"selector","tag":"sel","outbounds":["proxy"],"default":"proxy"}]}"#,
            "/tmp",
        )
        .unwrap();
        let (_, refusing, ok) = single_dns_detour(&cfg);
        assert!(!ok);
        assert_eq!(refusing, "b");
        // Direct-only profiles share no detour.
        let cfg = crate::config::parse_single_config(br#"{"profiles":{"a":{}}}"#, "/tmp").unwrap();
        let (_, refusing, ok) = single_dns_detour(&cfg);
        assert!(!ok);
        assert_eq!(refusing, "a");
        // A selector whose member is a urltest is unusable.
        let cfg = crate::config::parse_single_config(
            br#"{"profiles":{"a":{"outbound":"sel"}},"outbounds":[{"type":"selector","tag":"sel","outbounds":["u"]},{"type":"urltest","tag":"u","outbounds":["proxy"],"url":"https://example.invalid/"},{"type":"socks","tag":"proxy","server":"127.0.0.1","server_port":1080}]}"#,
            "/tmp",
        )
        .unwrap();
        let (_, refusing, ok) = single_dns_detour(&cfg);
        assert!(!ok);
        assert_eq!(refusing, "a");
    }
}
