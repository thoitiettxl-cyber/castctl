// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! The versioned login-form contract — port of
//! `internal/keeper/contract.go`.
//!
//! The contract is built ONLY from automated, read-only
//! observation of the live login page. A contract with
//! `observed == false` is NOT established: the driver must
//! refuse to run (`ContractNotEstablished`), never guess a
//! form. The embedded fixture is
//! `testdata/login-contract.v1.json`, verbatim from Go.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::{KeeperError, ReloginBlocker};
use crate::notify::NoticeKind;

/// The embedded recorded contract (Go `//go:embed
/// testdata/login-contract.v1.json`).
pub const LOGIN_CONTRACT_JSON: &str = include_str!("../testdata/login-contract.v1.json");

/// Returned when no observed login-form contract exists for
/// this build: the driver must not guess a form
/// (`contract.go:33`).
pub fn err_contract_not_established() -> KeeperError {
    KeeperError::ContractNotEstablished
}

/// One recorded flow step: fill a field or activate a
/// control (`contract.go:40-48`). `field` names the
/// credential slot (`"username"` or `"password"`) for fill
/// steps, `""` otherwise. No values are recorded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginContractStep {
    /// `"fill"` or `"click"`.
    pub action: String,
    /// CSS selector recorded from the observed page.
    pub selector: String,
    /// Credential slot for fill steps; omitted otherwise.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub field: String,
}

/// One recorded blocker signal (`contract.go:50-58`): a CSS
/// selector whose presence means the page is blocked, or a
/// page-text keyword (lowercase substring) with the same
/// meaning. `kind` is the closed [`NoticeKind`] for the alert.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginBlockerSignal {
    /// Selector signal, if any.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub selector: String,
    /// Keyword signal, if any.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub keyword: String,
    /// Closed notice kind for the alert.
    pub kind: NoticeKind,
}

/// The recorded login-form contract for one provider login
/// page (`contract.go:60-68`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginContract {
    /// Contract version; must be 1.
    pub version: i32,
    /// Whether the contract was established by observation.
    pub observed: bool,
    /// Login page URL.
    pub login_url: String,
    /// Recorded flow steps.
    #[serde(default)]
    pub steps: Vec<LoginContractStep>,
    /// Recorded blocker signals.
    #[serde(default)]
    pub blockers: Vec<LoginBlockerSignal>,
    /// Observation notes.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub notes: String,
}

/// The embedded recorded contract. Callers must check
/// `observed` before using it (`contract.go:71-79`).
pub fn default_login_contract() -> Result<LoginContract, KeeperError> {
    serde_json::from_str(LOGIN_CONTRACT_JSON)
        .map_err(|e| KeeperError::Other(format!("embedded login contract is corrupt: {e}")))
}

/// The redacted, driver-supplied view of the live login page
/// (`contract.go:81-93`): how many elements each recorded
/// selector matches, and the page's visible text (lowercased
/// by the driver) for keyword signals. It carries no values,
/// no HTML, and no screenshot bytes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PageSnapshot {
    /// Match count per selector.
    pub counts: HashMap<String, i32>,
    /// Visible text, lowercased by the driver.
    pub visible_text: String,
}

/// The driver's count-only snapshot (`contract.go:95-112`):
/// match counts, blocker hits (value names the signal class
/// only, never page text), and the selectors whose
/// evaluation threw in the browser.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotResult {
    /// Match count per selector.
    #[serde(default)]
    pub counts: HashMap<String, i32>,
    /// Blocker hit per kind: `"selector"` or `"keyword"`.
    #[serde(default)]
    pub hits: HashMap<String, String>,
    /// Selectors the browser could not evaluate.
    #[serde(default, rename = "badSelectors")]
    pub bad_selectors: Vec<String>,
}

/// The two outcomes of [`snapshot_decision`]: Go returns
/// `ErrContractNotEstablished` (a plain error, NOT a
/// blocker) for an unobserved contract, and a
/// `*ReloginBlocker` otherwise (`contract.go:114-145`). The
/// distinction matters to the wait loops: a non-blocker
/// error is transient and polls to the deadline, a blocker
/// stops immediately.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnapshotDecisionError {
    /// No observed contract exists.
    NotEstablished,
    /// A blocker (hit, mismatch, or bad selector).
    Blocker(ReloginBlocker),
}

impl fmt::Display for SnapshotDecisionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SnapshotDecisionError::NotEstablished => {
                write!(f, "login-form contract not established")
            }
            SnapshotDecisionError::Blocker(b) => write!(f, "{b}"),
        }
    }
}

impl std::error::Error for SnapshotDecisionError {}

/// Map a count snapshot onto the contract through the SAME
/// decision as [`match_contract`], plus one driver-only stop:
/// a selector the browser could not evaluate
/// (`bad_selectors` non-empty) outranks a blocker hit and
/// the step checks (`contract.go:114-145`). Precedence:
/// unobserved refuses outright; then bad selector; then
/// blocker signals; then the step-selector exactly-one
/// count. The two paths must agree on every input without
/// bad selectors.
pub fn snapshot_decision(
    contract: &LoginContract,
    res: &SnapshotResult,
) -> Result<(), SnapshotDecisionError> {
    if !contract.observed {
        return Err(SnapshotDecisionError::NotEstablished);
    }
    if !res.bad_selectors.is_empty() {
        return Err(SnapshotDecisionError::Blocker(ReloginBlocker::new(
            NoticeKind::Blocked,
            "contract_bad_selector",
        )));
    }
    let mut blocked_kind = NoticeKind::Blocked;
    let mut blocked_detail = String::new();
    let mut have_block = false;
    for sig in &contract.blockers {
        if let Some(detail) = res.hits.get(sig.kind.as_str()) {
            blocked_kind = sig.kind;
            blocked_detail = format!("blocker_{detail}");
            have_block = true;
            break;
        }
    }
    // No special case for an empty-kind signal: a hit with
    // an empty kind falls through to the step checks, exactly
    // like Go (an empty kind in the contract is a malformed
    // entry; both paths treat it the same).
    match_decision(
        contract,
        if have_block { Some(blocked_kind) } else { None },
        &blocked_detail,
        &res.counts,
    )
    .map_err(|b| match b {
        // Unobserved is unreachable here (checked above);
        // map it to NotEstablished rather than inventing a
        // blocker.
        DecisionError::NotEstablished => SnapshotDecisionError::NotEstablished,
        DecisionError::Blocker(b) => SnapshotDecisionError::Blocker(b),
    })
}

/// Whether a blocker was produced by a recorded blocker
/// signal (selector or keyword hit), as opposed to a
/// contract mismatch (`contract.go:147-170`). Wait loops stop
/// immediately on a signal but poll to the deadline on a
/// mismatch.
pub fn is_blocker_signal(b: &ReloginBlocker) -> bool {
    matches!(
        b.detail.as_str(),
        "blocker_signal" | "blocker_selector" | "blocker_keyword" | "contract_bad_selector"
    )
}

enum DecisionError {
    NotEstablished,
    Blocker(ReloginBlocker),
}

/// The ONE blocker/mismatch decision shared by
/// [`match_contract`] and [`snapshot_decision`]
/// (`contract.go:172-210`). `blocked_kind` is `None` when no
/// blocker signal hit; `blocked_detail` names the signal
/// class that hit. Every contract step selector must match
/// exactly one element.
fn match_decision(
    contract: &LoginContract,
    blocked_kind: Option<NoticeKind>,
    blocked_detail: &str,
    counts: &HashMap<String, i32>,
) -> Result<(), DecisionError> {
    if !contract.observed {
        return Err(DecisionError::NotEstablished);
    }
    if let Some(kind) = blocked_kind {
        let kind = if crate::notify::valid_notice_kind(kind) {
            kind
        } else {
            NoticeKind::Blocked
        };
        return Err(DecisionError::Blocker(ReloginBlocker::new(
            kind,
            blocked_detail,
        )));
    }
    for step in &contract.steps {
        if step.selector.is_empty() {
            return Err(DecisionError::Blocker(ReloginBlocker::new(
                NoticeKind::Blocked,
                "contract_step_no_selector",
            )));
        }
        if counts.get(&step.selector).copied().unwrap_or(0) != 1 {
            return Err(DecisionError::Blocker(ReloginBlocker::new(
                NoticeKind::Blocked,
                "contract_mismatch",
            )));
        }
    }
    Ok(())
}

/// Check a page snapshot against the contract
/// (`contract.go:212-240`). Blocker signals are checked
/// FIRST (a blocked page may also lack the form); then every
/// contract step selector must match exactly one element.
/// An unobserved contract refuses outright with
/// [`KeeperError::ContractNotEstablished`].
pub fn match_contract(contract: &LoginContract, snap: &PageSnapshot) -> Result<(), KeeperError> {
    if !contract.observed {
        return Err(KeeperError::ContractNotEstablished);
    }
    let mut blocked_kind: Option<NoticeKind> = None;
    let mut blocked_detail = String::new();
    for sig in &contract.blockers {
        if !sig.selector.is_empty() && snap.counts.get(&sig.selector).copied().unwrap_or(0) > 0 {
            blocked_kind = Some(sig.kind);
            blocked_detail = "blocker_selector".to_string();
            break;
        }
        if !sig.keyword.is_empty()
            && snap
                .visible_text
                .to_lowercase()
                .contains(&sig.keyword.to_lowercase())
        {
            blocked_kind = Some(sig.kind);
            blocked_detail = "blocker_keyword".to_string();
            break;
        }
    }
    match match_decision(contract, blocked_kind, &blocked_detail, &snap.counts) {
        Ok(()) => Ok(()),
        Err(DecisionError::NotEstablished) => Err(KeeperError::ContractNotEstablished),
        Err(DecisionError::Blocker(b)) => Err(KeeperError::Blocked(b)),
    }
}

/// Validate the recorded contract's steps BEFORE any browser
/// is launched or any credential typed (`contract.go:242-262`):
/// the version, and every step's action, field, and selector.
/// A violation returns a blocker with a fixed-enum detail.
/// Blocker signals are NOT checked here.
pub fn validate_contract(contract: &LoginContract) -> Option<ReloginBlocker> {
    if contract.version != 1 {
        return Some(ReloginBlocker::new(
            NoticeKind::Blocked,
            "contract_bad_version",
        ));
    }
    for step in &contract.steps {
        if step.selector.is_empty() {
            return Some(ReloginBlocker::new(
                NoticeKind::Blocked,
                "contract_step_no_selector",
            ));
        }
        match step.action.as_str() {
            "fill" => match step.field.as_str() {
                "username" | "password" => {}
                _ => {
                    return Some(ReloginBlocker::new(
                        NoticeKind::Blocked,
                        "contract_unknown_field",
                    ));
                }
            },
            "click" => {
                if !step.field.is_empty() {
                    return Some(ReloginBlocker::new(
                        NoticeKind::Blocked,
                        "contract_click_field",
                    ));
                }
            }
            _ => {
                return Some(ReloginBlocker::new(
                    NoticeKind::Blocked,
                    "contract_unknown_action",
                ));
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observed_contract() -> LoginContract {
        default_login_contract().expect("embedded fixture parses")
    }

    #[test]
    fn embedded_fixture_shape() {
        let c = observed_contract();
        assert!(c.observed);
        assert_eq!(c.version, 1);
        assert_eq!(c.login_url, "https://muse.ai/");
        assert_eq!(c.steps.len(), 2);
        assert_eq!(c.steps[0].action, "fill");
        assert_eq!(c.steps[0].field, "username");
        assert_eq!(c.steps[0].selector, "form input[aria-label]");
        assert_eq!(c.steps[1].action, "click");
        assert_eq!(c.steps[1].selector, "form button[type=\"submit\"]");
        assert!(c.blockers.is_empty());
        assert!(validate_contract(&c).is_none());
    }

    #[test]
    fn match_contract_requires_exactly_one() {
        let c = observed_contract();
        let mut snap = PageSnapshot::default();
        snap.counts.insert("form input[aria-label]".to_string(), 1);
        snap.counts
            .insert("form button[type=\"submit\"]".to_string(), 1);
        assert!(match_contract(&c, &snap).is_ok());
        snap.counts
            .insert("form button[type=\"submit\"]".to_string(), 0);
        let err = match_contract(&c, &snap).unwrap_err();
        // Go `ReloginBlocker.Error()` prints the kind only
        // (`relogin.go:53-58`); the fixed detail lives on the
        // typed blocker, so assert that, not the string.
        match err {
            KeeperError::Blocked(b) => assert_eq!(b.detail, "contract_mismatch"),
            other => panic!("expected Blocked, got {other:?}"),
        }
        snap.counts
            .insert("form button[type=\"submit\"]".to_string(), 2);
        assert!(match_contract(&c, &snap).is_err());
    }

    #[test]
    fn snapshot_decision_matches_match_contract() {
        // Go `TestSnapshotDecisionMatchesContract` pin: the two
        // paths agree on every input without bad selectors.
        let c = observed_contract();
        let mut counts = HashMap::new();
        counts.insert("form input[aria-label]".to_string(), 1);
        counts.insert("form button[type=\"submit\"]".to_string(), 1);
        let res = SnapshotResult {
            counts: counts.clone(),
            hits: HashMap::new(),
            bad_selectors: vec![],
        };
        assert!(snapshot_decision(&c, &res).is_ok());
        let mut snap = PageSnapshot {
            counts,
            visible_text: String::new(),
        };
        assert!(match_contract(&c, &snap).is_ok());
        // Mismatch on both paths.
        snap.counts.insert("form input[aria-label]".to_string(), 0);
        let res2 = SnapshotResult {
            counts: snap.counts.clone(),
            hits: HashMap::new(),
            bad_selectors: vec![],
        };
        assert!(matches!(
            snapshot_decision(&c, &res2),
            Err(SnapshotDecisionError::Blocker(ref b)) if b.detail == "contract_mismatch"
        ));
        assert!(match_contract(&c, &snap).is_err());
        // Bad selectors outrank everything on the snapshot path.
        let res3 = SnapshotResult {
            counts: snap.counts.clone(),
            hits: HashMap::new(),
            bad_selectors: vec!["form input[aria-label]".to_string()],
        };
        assert!(matches!(
            snapshot_decision(&c, &res3),
            Err(SnapshotDecisionError::Blocker(ref b)) if b.detail == "contract_bad_selector"
        ));
    }

    #[test]
    fn unobserved_contract_refuses() {
        let mut c = observed_contract();
        c.observed = false;
        let snap = PageSnapshot::default();
        assert!(matches!(
            match_contract(&c, &snap),
            Err(KeeperError::ContractNotEstablished)
        ));
        let res = SnapshotResult::default();
        assert!(matches!(
            snapshot_decision(&c, &res),
            Err(SnapshotDecisionError::NotEstablished)
        ));
    }

    #[test]
    fn validate_contract_details() {
        let mut c = observed_contract();
        c.version = 2;
        assert_eq!(
            validate_contract(&c).unwrap().detail,
            "contract_bad_version"
        );
        let mut c = observed_contract();
        c.steps[0].field = "email".to_string();
        assert_eq!(
            validate_contract(&c).unwrap().detail,
            "contract_unknown_field"
        );
        let mut c = observed_contract();
        c.steps[1].field = "username".to_string();
        assert_eq!(
            validate_contract(&c).unwrap().detail,
            "contract_click_field"
        );
        let mut c = observed_contract();
        c.steps[0].action = "hover".to_string();
        assert_eq!(
            validate_contract(&c).unwrap().detail,
            "contract_unknown_action"
        );
        let mut c = observed_contract();
        c.steps[0].selector = String::new();
        assert_eq!(
            validate_contract(&c).unwrap().detail,
            "contract_step_no_selector"
        );
    }

    #[test]
    fn blocker_signal_beats_mismatch() {
        let mut c = observed_contract();
        c.blockers = vec![LoginBlockerSignal {
            selector: "div.captcha".to_string(),
            keyword: String::new(),
            kind: NoticeKind::Captcha,
        }];
        let mut snap = PageSnapshot::default();
        snap.counts.insert("div.captcha".to_string(), 1);
        let err = match_contract(&c, &snap).unwrap_err();
        assert!(err.to_string().contains("captcha"));
        // Keyword hit.
        let mut c2 = observed_contract();
        c2.blockers = vec![LoginBlockerSignal {
            selector: String::new(),
            keyword: "verify you are human".to_string(),
            kind: NoticeKind::Captcha,
        }];
        let snap2 = PageSnapshot {
            counts: HashMap::new(),
            visible_text: "Please VERIFY YOU ARE HUMAN to continue".to_string(),
        };
        assert!(match_contract(&c2, &snap2).is_err());
    }
}
