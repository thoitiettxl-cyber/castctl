// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Hand-rolled argument parser mirroring Go's `argParser`
//! (`internal/commands/commands.go:455-726` at base `dev-rust`
//! `85a8d5e`): long abbreviations, `--flag=value`, bundled short
//! flags, exit-2 parser errors, `--help` short-circuit.

use castctl_config::gostr::{go_parse_int64, go_quote};

/// A flag's value kind (`commands.go`, `flagKind`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlagKind {
    /// Boolean flag; `--name=value` is an error.
    Bool,
    /// One string value.
    Str,
    /// One integer value (base-10, 64-bit).
    Int,
    /// Repeatable, one value per occurrence (`raw --param`).
    StringList,
    /// Repeatable, two values per occurrence (`fs edit --replace`).
    PairList,
}

/// One flag definition (`commands.go`, `flagDef`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlagDef {
    /// Long name without `--`.
    pub name: &'static str,
    /// Short letter, 0 when none.
    pub short: u8,
    /// Value kind.
    pub kind: FlagKind,
    /// argparse default applied when an int flag was never set.
    pub def_int: Option<i64>,
}

/// Boolean flag definition helper (`commands.go`, `boolFlag`).
pub const fn bool_flag(name: &'static str) -> FlagDef {
    FlagDef {
        name,
        short: 0,
        kind: FlagKind::Bool,
        def_int: None,
    }
}

/// String flag definition helper (`commands.go`, `strFlag`).
pub const fn str_flag(name: &'static str) -> FlagDef {
    FlagDef {
        name,
        short: 0,
        kind: FlagKind::Str,
        def_int: None,
    }
}

/// Int flag with an argparse default (`commands.go`, `intFlag`).
pub const fn int_flag(name: &'static str, short: u8, def: i64) -> FlagDef {
    FlagDef {
        name,
        short,
        kind: FlagKind::Int,
        def_int: Some(def),
    }
}

/// Int flag with no default (0 when absent; `commands.go` flags
/// declared directly as `flagDef{name, kind: flagInt}`).
pub const fn int_flag_no_def(name: &'static str) -> FlagDef {
    FlagDef {
        name,
        short: 0,
        kind: FlagKind::Int,
        def_int: None,
    }
}

/// Parsed flag values and positionals (`commands.go`, `parsed`).
#[derive(Debug, Clone, Default)]
pub struct Parsed {
    /// Boolean flags set on the command line.
    pub bools: Vec<(String, bool)>,
    /// String flag values (last wins).
    pub strs: Vec<(String, String)>,
    /// String flags present on the command line (even with an empty
    /// value: `--from=` counts as set).
    pub str_set: Vec<String>,
    /// Int flag values (last wins).
    pub ints: Vec<(String, i64)>,
    /// Int flags present on the command line.
    pub int_set: Vec<String>,
    /// String-list values, in occurrence order.
    pub lists: Vec<(String, Vec<String>)>,
    /// Pair-list values, in occurrence order.
    pub pairs: Vec<(String, Vec<(String, String)>)>,
    /// Positional arguments, in order.
    pub positionals: Vec<String>,
}

fn get<'a>(map: &'a [(String, String)], key: &str) -> Option<&'a str> {
    map.iter()
        .rev()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

fn get_int(map: &[(String, i64)], key: &str) -> Option<i64> {
    map.iter().rev().find(|(k, _)| k == key).map(|(_, v)| *v)
}

fn get_list<'a>(map: &'a [(String, Vec<String>)], key: &str) -> Option<&'a [String]> {
    map.iter()
        .rev()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_slice())
}

impl Parsed {
    /// `p.bool(name)` (`commands.go`).
    pub fn bool(&self, name: &str) -> bool {
        self.bools
            .iter()
            .rev()
            .find(|(k, _)| k == name)
            .map(|(_, v)| *v)
            .unwrap_or(false)
    }

    /// `p.str(name)` (`commands.go`): `""` when absent.
    pub fn str(&self, name: &str) -> String {
        get(&self.strs, name).unwrap_or("").to_string()
    }

    /// `p.strIsSet(name)` (`commands.go`).
    pub fn str_is_set(&self, name: &str) -> bool {
        self.str_set.iter().any(|k| k == name)
    }

    /// `p.intVal(name)` (`commands.go`): 0 when absent.
    pub fn int_val(&self, name: &str) -> i64 {
        get_int(&self.ints, name).unwrap_or(0)
    }

    /// `p.intIsSet(name)` (`commands.go`).
    pub fn int_is_set(&self, name: &str) -> bool {
        self.int_set.iter().any(|k| k == name)
    }

    /// String-list values for `name` (`commands.go`, `p.lists`).
    pub fn list(&self, name: &str) -> Vec<String> {
        get_list(&self.lists, name)
            .map(|v| v.to_vec())
            .unwrap_or_default()
    }

    /// Pair-list values for `name` (`commands.go`, `p.pairs`).
    pub fn pairs(&self, name: &str) -> Vec<(String, String)> {
        self.pairs
            .iter()
            .rev()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.clone())
            .unwrap_or_default()
    }

    fn set_bool(&mut self, name: &str) {
        if let Some(slot) = self.bools.iter_mut().find(|(k, _)| k == name) {
            slot.1 = true;
        } else {
            self.bools.push((name.to_string(), true));
        }
    }

    fn set_str(&mut self, name: &str, val: String) {
        if let Some(slot) = self.strs.iter_mut().find(|(k, _)| k == name) {
            slot.1 = val;
        } else {
            self.strs.push((name.to_string(), val));
        }
        if !self.str_set.iter().any(|k| k == name) {
            self.str_set.push(name.to_string());
        }
    }

    fn set_int(&mut self, name: &str, val: i64) {
        if let Some(slot) = self.ints.iter_mut().find(|(k, _)| k == name) {
            slot.1 = val;
        } else {
            self.ints.push((name.to_string(), val));
        }
        if !self.int_set.iter().any(|k| k == name) {
            self.int_set.push(name.to_string());
        }
    }

    /// Record an int flag's default value without marking it set
    /// (Go `parse`: defaults only write `p.ints`, never `intSet`;
    /// handlers use `intIsSet` to tell "user passed the flag"
    /// from "default applied").
    fn set_int_default(&mut self, name: &str, val: i64) {
        if let Some(slot) = self.ints.iter_mut().find(|(k, _)| k == name) {
            slot.1 = val;
        } else {
            self.ints.push((name.to_string(), val));
        }
    }

    fn push_list(&mut self, name: &str, val: String) {
        if let Some(slot) = self.lists.iter_mut().find(|(k, _)| k == name) {
            slot.1.push(val);
        } else {
            self.lists.push((name.to_string(), vec![val]));
        }
    }

    fn push_pair(&mut self, name: &str, pair: (String, String)) {
        if let Some(slot) = self.pairs.iter_mut().find(|(k, _)| k == name) {
            slot.1.push(pair);
        } else {
            self.pairs.push((name.to_string(), vec![pair]));
        }
    }
}

/// A usage error: exit 2 with usage + message (`commands.go`,
/// `parserError`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParserError(pub String);

/// The parser result: `help_shown` means `--help` was seen and the
/// help text was already appended to stdout (`commands.go`,
/// `parseResult`).
#[derive(Debug)]
pub struct ParseOutcome {
    /// Parsed values (partial on help; empty on error).
    pub parsed: Parsed,
    /// Whether help was shown.
    pub help_shown: bool,
}

/// `argParser` (`commands.go:455`).
pub struct ArgParser {
    /// Flag definitions for this command.
    pub defs: Vec<FlagDef>,
    /// Help text printed on `--help`.
    pub help_text: &'static str,
}

impl ArgParser {
    /// `findLong` (`commands.go`): exact match, else a unique
    /// prefix; `help` is implicit on every command.
    fn find_long(&self, name: &str) -> Option<FlagDef> {
        for d in &self.defs {
            if d.name == name {
                return Some(d.clone());
            }
        }
        let mut found: Option<FlagDef> = None;
        for d in &self.defs {
            if d.name.starts_with(name) {
                if found.is_some() {
                    return None; // ambiguous
                }
                found = Some(d.clone());
            }
        }
        if found.is_none() && "help".starts_with(name) {
            return Some(FlagDef {
                name: "help",
                short: 0,
                kind: FlagKind::Bool,
                def_int: None,
            });
        }
        found
    }

    /// `findShort` (`commands.go`): `h` is implicit on every
    /// command.
    fn find_short(&self, c: u8) -> Option<FlagDef> {
        for d in &self.defs {
            if d.short != 0 && d.short == c {
                return Some(d.clone());
            }
        }
        if c == b'h' {
            return Some(FlagDef {
                name: "help",
                short: b'h',
                kind: FlagKind::Bool,
                def_int: None,
            });
        }
        None
    }

    /// `parse` (`commands.go`): appends help text to `stdout` on
    /// help; returns the first error, or the first help, whichever
    /// comes first.
    pub fn parse(&self, args: &[String], stdout: &mut String) -> Result<ParseOutcome, ParserError> {
        let mut p = Parsed::default();
        let mut i = 0usize;
        let mut seen_dashdash = false;
        while i < args.len() {
            let tok = args[i].clone();
            i += 1;
            if seen_dashdash {
                p.positionals.push(tok);
                continue;
            }
            if tok == "--" {
                seen_dashdash = true;
            } else if tok.starts_with("--") && tok.len() > 2 {
                let name_val = &tok[2..];
                let (name, inline_val, has_inline) = match name_val.find('=') {
                    Some(j) => (&name_val[..j], &name_val[j + 1..], true),
                    None => (name_val, "", false),
                };
                let def = match self.find_long(name) {
                    Some(def) => def,
                    None => {
                        return Err(ParserError(format!("unrecognized argument: --{name}")));
                    }
                };
                if def.name == "help" {
                    stdout.push_str(self.help_text);
                    return Ok(ParseOutcome {
                        parsed: p,
                        help_shown: true,
                    });
                }
                i = self.consume_long(&mut p, args, i, &def, inline_val, has_inline)?;
            } else if tok.starts_with('-') && tok.len() > 1 && tok != "-" {
                // Short flags, possibly bundled: -la, -oDIR, -o DIR.
                // Go indexes bytes (rest[0]); a non-ASCII byte is
                // reported as a single byte, mirroring %c on a byte.
                let rest = tok.as_bytes()[1..].to_vec();
                let mut rest_idx = 0usize;
                while rest_idx < rest.len() {
                    let c = rest[rest_idx];
                    let def = match self.find_short(c) {
                        Some(def) => def,
                        None => {
                            return Err(ParserError(format!(
                                "unrecognized argument: -{}",
                                c as char
                            )));
                        }
                    };
                    if def.name == "help" {
                        stdout.push_str(self.help_text);
                        return Ok(ParseOutcome {
                            parsed: p,
                            help_shown: true,
                        });
                    }
                    if def.kind == FlagKind::Bool {
                        p.set_bool(def.name);
                        rest_idx += 1;
                        continue;
                    }
                    // Value-taking short: rest after the letter is
                    // the value, else the next token whole.
                    let val: String;
                    if rest_idx + 1 < rest.len() {
                        val = String::from_utf8_lossy(&rest[rest_idx + 1..]).into_owned();
                        rest_idx = rest.len();
                    } else {
                        if i >= args.len() {
                            return Err(ParserError(format!(
                                "argument -{}: expected one argument",
                                def.short as char
                            )));
                        }
                        val = args[i].clone();
                        i += 1;
                        rest_idx = rest.len();
                    }
                    self.set_value(&mut p, &def, val)?;
                }
            } else {
                p.positionals.push(tok);
            }
        }
        // Int-flag defaults for flags never set on the command line.
        // Defaults must not mark the flag set (see set_int_default).
        for def in &self.defs {
            if def.kind == FlagKind::Int
                && let Some(d) = def.def_int
                && !p.int_is_set(def.name)
            {
                p.set_int_default(def.name, d);
            }
        }
        Ok(ParseOutcome {
            parsed: p,
            help_shown: false,
        })
    }

    /// `consumeLong` (`commands.go`).
    fn consume_long(
        &self,
        p: &mut Parsed,
        args: &[String],
        mut i: usize,
        def: &FlagDef,
        inline_val: &str,
        has_inline: bool,
    ) -> Result<usize, ParserError> {
        let flag_display = format!("--{}", def.name);
        if def.kind == FlagKind::Bool {
            if has_inline {
                return Err(ParserError(format!(
                    "argument {flag_display}: ignored explicit argument {}",
                    go_quote(inline_val)
                )));
            }
            p.set_bool(def.name);
            return Ok(i);
        }
        let mut values: Vec<String> = Vec::new();
        if has_inline {
            values.push(inline_val.to_string());
        }
        let need = if def.kind == FlagKind::PairList { 2 } else { 1 };
        while values.len() < need {
            if i >= args.len() {
                return Err(ParserError(format!(
                    "argument {flag_display}: expected {need} argument(s)"
                )));
            }
            let next = &args[i];
            if next.starts_with('-') && next != "-" && !looks_like_negative_number(next, def.kind) {
                return Err(ParserError(format!(
                    "argument {flag_display}: expected {need} argument(s)"
                )));
            }
            values.push(next.clone());
            i += 1;
        }
        // INVARIANT: the loop above fills `values` to exactly
        // `need` elements; PairList means need == 2, so both
        // indexes exist. (No expect/unwrap on argv/config/file
        // data: the length is established by this function's own
        // loop, not by external input.)
        if def.kind == FlagKind::PairList {
            p.push_pair(def.name, (values[0].clone(), values[1].clone()));
            return Ok(i);
        }
        // INVARIANT: same loop; need >= 1, so the first element
        // exists.
        self.set_value(p, def, values.into_iter().next().expect("need >= 1"))?;
        Ok(i)
    }

    /// `setValue` (`commands.go`).
    fn set_value(&self, p: &mut Parsed, def: &FlagDef, val: String) -> Result<(), ParserError> {
        match def.kind {
            FlagKind::Bool => p.set_bool(def.name),
            FlagKind::Str => p.set_str(def.name, val),
            FlagKind::Int => match go_parse_int64(&val) {
                Ok(n) => p.set_int(def.name, n),
                Err(_) => {
                    return Err(ParserError(format!(
                        "argument --{}: invalid int value: {}",
                        def.name,
                        go_quote(&val)
                    )));
                }
            },
            FlagKind::StringList => p.push_list(def.name, val),
            FlagKind::PairList => {
                // PairList values only arrive via consumeLong.
                // Go's setValue has no PairList case, so a short
                // form would silently DROP the value; the arm is
                // unreachable in practice because no PairList
                // def has a short flag (the only one is fs
                // --replace). Kept as debug_assert, no behaviour
                // change.
                debug_assert!(false, "pair list must go through consumeLong");
            }
        }
        Ok(())
    }
}

/// `looksLikeNegativeNumber` (`commands.go`): only for int flags; a
/// token that parses as an int64 counts.
fn looks_like_negative_number(tok: &str, kind: FlagKind) -> bool {
    if kind != FlagKind::Int {
        return false;
    }
    go_parse_int64(tok).is_ok()
}

/// `checkPositionals` (`commands.go:715`): missing → required list;
/// extra → unrecognized list. The `prog` parameter is unused by Go
/// (kept for signature parity).
pub fn check_positionals(p: &Parsed, names: &[&str]) -> Result<(), ParserError> {
    if p.positionals.len() < names.len() {
        let missing = &names[p.positionals.len()..];
        return Err(ParserError(format!(
            "the following arguments are required: {}",
            missing.join(", ")
        )));
    }
    if p.positionals.len() > names.len() {
        let extra = &p.positionals[names.len()..];
        return Err(ParserError(format!(
            "unrecognized arguments: {}",
            extra.join(" ")
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parser(defs: Vec<FlagDef>, help: &'static str) -> ArgParser {
        ArgParser {
            defs,
            help_text: help,
        }
    }

    fn parse_ok(ap: &ArgParser, args: &[&str]) -> Parsed {
        let argv: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        let mut out = String::new();
        let outcome = ap.parse(&argv, &mut out).unwrap();
        assert!(!outcome.help_shown);
        assert!(out.is_empty());
        outcome.parsed
    }

    fn parse_err(ap: &ArgParser, args: &[&str]) -> String {
        let argv: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        let mut out = String::new();
        ap.parse(&argv, &mut out).unwrap_err().0
    }

    #[test]
    fn test_long_forms_and_abbreviations() {
        let ap = parser(vec![str_flag("thread"), int_flag("limit", 0, 10)], "HELP\n");
        let p = parse_ok(&ap, &["--thread", "t1", "--limit=5"]);
        assert_eq!(p.str("thread"), "t1");
        assert_eq!(p.int_val("limit"), 5);
        let p = parse_ok(&ap, &["--thr", "t2", "--lim", "7"]);
        assert_eq!(p.str("thread"), "t2");
        assert_eq!(p.int_val("limit"), 7);
        // Ambiguous prefix: --t could be thread only here (limit
        // does not start with t), so it resolves.
        let p = parse_ok(&ap, &["--t", "t3"]);
        assert_eq!(p.str("thread"), "t3");
        assert_eq!(
            parse_err(&ap, &["--bogus"]),
            "unrecognized argument: --bogus"
        );
    }

    #[test]
    fn test_ambiguous_prefix_rejected() {
        let ap = parser(vec![bool_flag("raw"), bool_flag("recent")], "HELP\n");
        assert_eq!(parse_err(&ap, &["--r"]), "unrecognized argument: --r");
        // "--ra" is a UNIQUE prefix of "raw" only: it resolves.
        let p = parse_ok(&ap, &["--ra"]);
        assert!(p.bool("raw"));
        let p = parse_ok(&ap, &["--re"]);
        assert!(p.bool("recent"));
    }

    #[test]
    fn test_bool_inline_value_rejected() {
        let ap = parser(vec![bool_flag("json")], "HELP\n");
        assert_eq!(
            parse_err(&ap, &["--json=true"]),
            "argument --json: ignored explicit argument \"true\""
        );
    }

    #[test]
    fn test_missing_value_and_flag_look() {
        let ap = parser(vec![str_flag("thread")], "HELP\n");
        assert_eq!(
            parse_err(&ap, &["--thread"]),
            "argument --thread: expected 1 argument(s)"
        );
        assert_eq!(
            parse_err(&ap, &["--thread", "--json"]),
            "argument --thread: expected 1 argument(s)"
        );
        // A lone "-" IS accepted as a value.
        let p = parse_ok(&ap, &["--thread", "-"]);
        assert_eq!(p.str("thread"), "-");
        // Empty inline value is accepted.
        let p = parse_ok(&ap, &["--thread="]);
        assert_eq!(p.str("thread"), "");
        assert!(p.str_is_set("thread"));
    }

    #[test]
    fn test_negative_number_only_for_int() {
        let ap = parser(vec![int_flag("limit", 0, 10), str_flag("thread")], "HELP\n");
        let p = parse_ok(&ap, &["--limit", "-5"]);
        assert_eq!(p.int_val("limit"), -5);
        assert_eq!(
            parse_err(&ap, &["--thread", "-5"]),
            "argument --thread: expected 1 argument(s)"
        );
        // "-5x" does not parse as int: rejected as a flag look.
        assert_eq!(
            parse_err(&ap, &["--limit", "-5x"]),
            "argument --limit: expected 1 argument(s)"
        );
        // Int overflow: same invalid-int message.
        assert_eq!(
            parse_err(&ap, &["--limit", "99999999999999999999"]),
            "argument --limit: invalid int value: \"99999999999999999999\""
        );
        assert_eq!(
            parse_err(&ap, &["--limit", "12x"]),
            "argument --limit: invalid int value: \"12x\""
        );
    }

    #[test]
    fn test_short_bundling_and_attached_values() {
        let ap = parser(
            vec![
                FlagDef {
                    name: "long",
                    short: b'l',
                    kind: FlagKind::Bool,
                    def_int: None,
                },
                FlagDef {
                    name: "all",
                    short: b'a',
                    kind: FlagKind::Bool,
                    def_int: None,
                },
                FlagDef {
                    name: "output",
                    short: b'o',
                    kind: FlagKind::Str,
                    def_int: None,
                },
            ],
            "HELP\n",
        );
        let p = parse_ok(&ap, &["-la"]);
        assert!(p.bool("long") && p.bool("all"));
        let p = parse_ok(&ap, &["-oDIR"]);
        assert_eq!(p.str("output"), "DIR");
        let p = parse_ok(&ap, &["-o", "DIR"]);
        assert_eq!(p.str("output"), "DIR");
        // Short value consumes the next token whole, even a flag.
        let p = parse_ok(&ap, &["-o", "--json"]);
        assert_eq!(p.str("output"), "--json");
        assert_eq!(parse_err(&ap, &["-x"]), "unrecognized argument: -x");
        assert_eq!(
            parse_err(&ap, &["-o"]),
            "argument -o: expected one argument"
        );
        // Lone "-" is a positional.
        let p = parse_ok(&ap, &["-"]);
        assert_eq!(p.positionals, vec!["-".to_string()]);
    }

    #[test]
    fn test_help_short_circuit_rules() {
        let ap = parser(vec![str_flag("thread")], "HELP\n");
        let argv: Vec<String> = vec!["--bogus".to_string(), "--help".to_string()];
        let mut out = String::new();
        assert!(ap.parse(&argv, &mut out).is_err());
        assert!(out.is_empty());
        // Earlier help beats everything later.
        let argv: Vec<String> = vec!["--help".to_string(), "--bogus".to_string()];
        let mut out = String::new();
        let outcome = ap.parse(&argv, &mut out).unwrap();
        assert!(outcome.help_shown);
        assert_eq!(out, "HELP\n");
        // Help after a positional is still help.
        let argv: Vec<String> = vec!["pos".to_string(), "--he".to_string()];
        let mut out = String::new();
        let outcome = ap.parse(&argv, &mut out).unwrap();
        assert!(outcome.help_shown);
        // Help after -- is not help.
        let p = parse_ok(&ap, &["--", "--help"]);
        assert_eq!(p.positionals, vec!["--help".to_string()]);
        // -h inside a bundle shows help immediately.
        let argv: Vec<String> = vec!["-lh".to_string()];
        let ap2 = parser(
            vec![FlagDef {
                name: "long",
                short: b'l',
                kind: FlagKind::Bool,
                def_int: None,
            }],
            "HELP\n",
        );
        let mut out = String::new();
        let outcome = ap2.parse(&argv, &mut out).unwrap();
        assert!(outcome.help_shown);
        assert_eq!(out, "HELP\n");
    }

    #[test]
    fn test_int_defaults_applied_only_when_unset() {
        let ap = parser(
            vec![int_flag("limit", 0, 10), int_flag_no_def("after-seq")],
            "HELP\n",
        );
        let p = parse_ok(&ap, &[]);
        assert_eq!(p.int_val("limit"), 10);
        assert_eq!(p.int_val("after-seq"), 0);
        assert!(!p.int_is_set("after-seq"));
        // A defaulted flag holds its default value but is NOT set:
        // handlers must be able to tell it from an explicit flag.
        assert!(!p.int_is_set("limit"));
        let p = parse_ok(&ap, &["--limit", "3"]);
        assert_eq!(p.int_val("limit"), 3);
        assert!(p.int_is_set("limit"));
    }

    #[test]
    fn test_string_list_and_pair_list() {
        let ap = parser(
            vec![
                FlagDef {
                    name: "param",
                    short: 0,
                    kind: FlagKind::StringList,
                    def_int: None,
                },
                FlagDef {
                    name: "replace",
                    short: 0,
                    kind: FlagKind::PairList,
                    def_int: None,
                },
            ],
            "HELP\n",
        );
        let p = parse_ok(
            &ap,
            &["--param", "a=1", "--param=b=2", "--replace", "x", "y"],
        );
        assert_eq!(p.list("param"), vec!["a=1".to_string(), "b=2".to_string()]);
        assert_eq!(p.pairs("replace"), vec![("x".to_string(), "y".to_string())]);
        assert_eq!(
            parse_err(&ap, &["--replace", "only-one"]),
            "argument --replace: expected 2 argument(s)"
        );
    }

    #[test]
    fn test_check_positionals_messages() {
        let p = Parsed {
            positionals: vec!["a".to_string()],
            ..Default::default()
        };
        assert_eq!(
            check_positionals(&p, &["code", "extra"]).unwrap_err().0,
            "the following arguments are required: extra"
        );
        let p = Parsed {
            positionals: vec!["a".to_string(), "b".to_string(), "c".to_string()],
            ..Default::default()
        };
        assert_eq!(
            check_positionals(&p, &["code"]).unwrap_err().0,
            "unrecognized arguments: b c"
        );
        assert!(check_positionals(&p, &["a", "b", "c"]).is_ok());
    }

    #[test]
    fn test_empty_inline_thread_value_accepted() {
        // Regression guard: "--thread=" must not be treated as an
        // error (the earlier draft of this test asserted "").
        let ap = parser(vec![str_flag("thread")], "HELP\n");
        let p = parse_ok(&ap, &["--thread="]);
        assert_eq!(p.str("thread"), "");
    }
}
