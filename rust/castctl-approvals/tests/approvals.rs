// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Port of Go `internal/approvals/approvals_test.go` (17
//! test fns). One Go fn is half-ported:
//! `TestAutoApproverZeroAndNilGuards`' nil-receiver half
//! has no Rust equivalent (no null receivers); the
//! zero-value half is ported. See PORTING.md §M7a.

use std::sync::{Arc, Mutex};

use castctl_approvals::{
    ApprovalResult, AutoApprover, BoxError, DescribedApproval, FOREVER, ONCE, choose_auto_decision,
    describe_approval, offers_forever, offers_once,
};
use castctl_transport::TransportError;
use serde_json::json;

fn s(v: &str) -> Option<String> {
    Some(v.to_string())
}

fn f(v: f64) -> Option<f64> {
    Some(v)
}

/// Renders a `DescribedApproval` with values
/// dereferenced, for comparable assertions (Go
/// `flatDescribed`). Expires renders `<nil>` / `&7`;
/// options render `[a b]` / `[]`.
fn flat(d: &DescribedApproval) -> String {
    let exp = match d.expires_at_ms {
        Some(v) => format!("&{v}"),
        None => "<nil>".to_string(),
    };
    let opts = match &d.options {
        Some(o) => format!("[{}]", o.join(" ")),
        None => "[]".to_string(),
    };
    format!(
        "{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{}|{}",
        d.approval_id.as_deref().unwrap_or(""),
        d.title.as_deref().unwrap_or(""),
        d.question.as_deref().unwrap_or(""),
        d.kind.as_deref().unwrap_or(""),
        d.scope.as_deref().unwrap_or(""),
        d.why.as_deref().unwrap_or(""),
        exp,
        opts,
    )
}

fn item(id: &str, options: &[&str]) -> DescribedApproval {
    DescribedApproval {
        approval_id: s(id),
        options: Some(options.iter().map(|o| o.to_string()).collect()),
        ..Default::default()
    }
}

/// A `Connect` that always succeeds, returning the given
/// decider. The decider is shared (`Arc`): `Connect` is
/// `Fn`, called once per `Approve`, so it cannot move a
/// `Box` out.
fn connect_ok(decide: Arc<castctl_approvals::Decider>) -> Box<castctl_approvals::ConnectFn> {
    Box::new(move || {
        let d = Arc::clone(&decide);
        let decider: Box<castctl_approvals::Decider> = Box::new(move |a, decision| d(a, decision));
        Ok((decider, Box::new(|| {}) as Box<dyn FnOnce() + Send>))
    })
}

#[test]
fn describe_approval() {
    let cases: Vec<(&str, serde_json::Value, DescribedApproval)> = vec![
        (
            "full approval",
            json!({
                "approval_id": "ap1",
                "display": {
                    "summary_title": "Network",
                    "permission_question": {"text": "{assistant} wants net", "kind": "network_access", "scope": "x.com"},
                    "detail_rows": [{"label": "Host", "value": "h"}],
                },
                "payload": {"type": "p"},
                "decision_options": [{"kind": "allow_once"}, {"kind": "deny"}],
            }),
            DescribedApproval {
                approval_id: s("ap1"),
                title: s("Network"),
                question: s("Muse wants net"),
                kind: s("network_access"),
                scope: s("x.com"),
                options: Some(vec!["allow_once".to_string(), "deny".to_string()]),
                ..Default::default()
            },
        ),
        (
            "non-dict approval degrades",
            json!("junk"),
            DescribedApproval::default(),
        ),
        (
            "display name fallback and host scope fallback",
            json!({
                "display": {
                    "display_name": "Title2",
                    "detail_rows": [{"label": "Host", "value": "host.example"}],
                },
            }),
            DescribedApproval {
                title: s("Title2"),
                scope: s("host.example"),
                ..Default::default()
            },
        ),
        (
            "question scope wins over host row",
            json!({
                "display": {
                    "permission_question": {"scope": "qscope"},
                    "detail_rows": [{"label": "Host", "value": "h"}],
                },
            }),
            DescribedApproval {
                scope: s("qscope"),
                ..Default::default()
            },
        ),
        (
            "placeholder-only question text becomes Muse",
            json!({"display": {"permission_question": {"text": "{assistant}"}}}),
            DescribedApproval {
                question: s("Muse"),
                ..Default::default()
            },
        ),
        (
            "empty question text is nil",
            json!({"display": {"permission_question": {"text": ""}}}),
            DescribedApproval::default(),
        ),
        (
            "kind falls back to payload type",
            json!({"payload": {"type": "ptype"}}),
            DescribedApproval {
                kind: s("ptype"),
                ..Default::default()
            },
        ),
        (
            "why chain",
            json!({"display": {"reason": "dreason"}, "reason": "areason"}),
            DescribedApproval {
                why: s("dreason"),
                ..Default::default()
            },
        ),
        (
            "options drop non-dict and empty kinds, nil when empty",
            json!({"decision_options": [{"kind": ""}, "junk", {}]}),
            DescribedApproval::default(),
        ),
        (
            "non-dict detail rows skipped",
            json!({"display": {"detail_rows": ["junk", {"label": "Host", "value": "h2"}]}}),
            DescribedApproval {
                scope: s("h2"),
                ..Default::default()
            },
        ),
    ];
    for (name, input, want) in cases {
        let got = describe_approval(&input);
        assert_eq!(flat(&got), flat(&want), "case {name}");
    }
}

#[test]
fn describe_approval_non_finite_expiry_is_none() {
    // Red-team F11: Go's `expiresAtMS` returns nil for
    // an out-of-range `json.Number` (`1e999` fails
    // `Float64()`); Rust must not render it as `inf`.
    // Parsed from text so the number keeps its literal
    // (a `json!(1e999)` literal would already be
    // non-finite at construction time).
    let input: serde_json::Value =
        serde_json::from_str(r#"{"request_expires_at_ms": 1e999}"#).unwrap();
    let got = describe_approval(&input);
    assert_eq!(
        got.expires_at_ms, None,
        "1e999 expiry must be no expiry, not inf"
    );
}

#[test]
fn choose_auto_decision() {
    let with_opts = |opts: &[&str]| DescribedApproval {
        options: Some(opts.iter().map(|o| o.to_string()).collect()),
        ..Default::default()
    };
    let cases: Vec<(&str, DescribedApproval, bool, bool, &str, bool)> = vec![
        ("off", with_opts(&[FOREVER]), false, false, "", false),
        (
            "forever offered",
            with_opts(&[FOREVER, ONCE]),
            true,
            false,
            FOREVER,
            true,
        ),
        (
            "no options assumes forever",
            DescribedApproval::default(),
            true,
            false,
            FOREVER,
            true,
        ),
        (
            "once only, fallback off",
            with_opts(&[ONCE]),
            true,
            false,
            "",
            false,
        ),
        (
            "once only, fallback on",
            with_opts(&[ONCE]),
            true,
            true,
            ONCE,
            true,
        ),
        (
            "forever wins over once",
            with_opts(&[ONCE, FOREVER]),
            true,
            true,
            FOREVER,
            true,
        ),
        ("deny only", with_opts(&["deny"]), true, true, "", false),
        (
            "session never picked",
            with_opts(&["allow_session"]),
            true,
            true,
            "",
            false,
        ),
        (
            "today never picked",
            with_opts(&["allow_today"]),
            true,
            true,
            "",
            false,
        ),
        (
            "first option never picked blindly",
            with_opts(&["deny", "allow_session"]),
            true,
            true,
            "",
            false,
        ),
        (
            "no options not turned into once",
            DescribedApproval::default(),
            true,
            true,
            FOREVER,
            true,
        ),
    ];
    for (name, d, auto, once, want, want_ok) in cases {
        let (got, ok) = choose_auto_decision(&d, auto, once);
        assert_eq!((got.as_str(), ok), (want, want_ok), "case {name}");
    }
}

#[test]
fn offers_forever_and_once() {
    assert!(offers_forever(&DescribedApproval::default()));
    assert!(!offers_once(&DescribedApproval::default()));
    assert!(!offers_forever(&DescribedApproval {
        options: Some(vec!["deny".to_string()]),
        ..Default::default()
    }));
    assert!(offers_once(&DescribedApproval {
        options: Some(vec![ONCE.to_string()]),
        ..Default::default()
    }));
}

#[test]
fn auto_approver_decides_each_at_most_once() {
    let calls = Arc::new(Mutex::new(Vec::<String>::new()));
    let calls2 = Arc::clone(&calls);
    let decide: Arc<castctl_approvals::Decider> = Arc::new(move |a, _| {
        calls2.lock().unwrap().push(a.id_str().to_string());
        Ok(())
    });
    let aa = AutoApprover::new(Some(connect_ok(decide)), false);
    let items = vec![item("a1", &[FOREVER]), item("a2", &[ONCE])];
    let out = aa.approve(&items);
    assert_eq!(out.handled, vec!["a1".to_string()]);
    assert_eq!(out.approved.len(), 1);
    assert_eq!(out.approved[0].decision, FOREVER);
    assert_eq!(
        out.errors.len(),
        1,
        "want 1 skip error, got {:?}",
        out.errors
    );
    assert_eq!(*calls.lock().unwrap(), vec!["a1".to_string()]);
    // Second call: a1 is already claimed and the a2 skip
    // warning fired once already: no re-decide, no new errors.
    let out2 = aa.approve(&items);
    assert!(out2.handled.is_empty() && out2.errors.is_empty());
    assert_eq!(*calls.lock().unwrap(), vec!["a1".to_string()]);
}

#[test]
fn auto_approver_on_decided() {
    let got = Arc::new(Mutex::new(Vec::<String>::new()));
    let got2 = Arc::clone(&got);
    let decide: Arc<castctl_approvals::Decider> = Arc::new(move |a, _| {
        if a.id_str() == "bad" {
            return Err(Box::from("gateway down") as BoxError);
        }
        Ok(())
    });
    let aa = AutoApprover::new(Some(connect_ok(decide)), false);
    aa.set_on_decided(Box::new(move |id, decision| {
        got2.lock().unwrap().push(format!("{id}={decision}"));
    }));
    let out = aa.approve(&[item("a1", &[FOREVER]), item("bad", &[FOREVER])]);
    assert_eq!(out.handled, vec!["a1".to_string()]);
    assert_eq!(out.errors.len(), 1, "want 1 (the failed decide)");
    assert_eq!(
        *got.lock().unwrap(),
        vec![format!("a1={FOREVER}")],
        "OnDecided fires on success only, never on failure"
    );
}

#[test]
fn auto_approver_decide_failure_is_not_retried() {
    let calls = Arc::new(Mutex::new(0usize));
    let calls2 = Arc::clone(&calls);
    let decide: Arc<castctl_approvals::Decider> = Arc::new(move |_, _| {
        *calls2.lock().unwrap() += 1;
        Err(Box::from("gateway down") as BoxError)
    });
    let aa = AutoApprover::new(Some(connect_ok(decide)), false);
    let out = aa.approve(&[item("a1", &[FOREVER])]);
    assert!(out.handled.is_empty() && out.errors.len() == 1 && *calls.lock().unwrap() == 1);
    assert_eq!(out.errors[0].approval_id, "a1");
}

#[test]
fn auto_approver_connector_failure_errors_every_item() {
    let aa = AutoApprover::new(
        Some(Box::new(|| Err(Box::from("connect failed") as BoxError))),
        false,
    );
    let out = aa.approve(&[item("a1", &[]), item("a2", &[])]);
    assert!(out.handled.is_empty() && out.approved.is_empty() && out.errors.len() == 2);
}

#[test]
fn auto_approver_allow_once_fallback() {
    let decided = Arc::new(Mutex::new(Vec::<String>::new()));
    let decided2 = Arc::clone(&decided);
    let decide: Arc<castctl_approvals::Decider> = Arc::new(move |_, decision| {
        decided2.lock().unwrap().push(decision.to_string());
        Ok(())
    });
    let aa = AutoApprover::new(Some(connect_ok(decide)), true);
    let out = aa.approve(&[item("a1", &[ONCE])]);
    assert_eq!(out.handled, vec!["a1".to_string()]);
    assert_eq!(*decided.lock().unwrap(), vec![ONCE.to_string()]);
}

#[test]
fn auto_approver_concurrent_same_id_decides_once() {
    let calls = Arc::new(Mutex::new(0usize));
    let calls2 = Arc::clone(&calls);
    let decide: Arc<castctl_approvals::Decider> = Arc::new(move |_, _| {
        *calls2.lock().unwrap() += 1;
        std::thread::sleep(std::time::Duration::from_millis(50));
        Ok(())
    });
    let aa = Arc::new(AutoApprover::new(Some(connect_ok(decide)), false));
    let it = item("a1", &[FOREVER]);
    let a1 = Arc::clone(&aa);
    let i1 = it.clone();
    let h1 = std::thread::spawn(move || a1.approve(std::slice::from_ref(&i1)));
    let a2 = Arc::clone(&aa);
    let i2 = it.clone();
    let h2 = std::thread::spawn(move || a2.approve(std::slice::from_ref(&i2)));
    let _ = h1.join();
    let _ = h2.join();
    assert_eq!(
        *calls.lock().unwrap(),
        1,
        "concurrent decide calls must be 1"
    );
}

#[test]
fn auto_approver_duplicate_ids_in_one_call_decide_once() {
    let calls = Arc::new(Mutex::new(0usize));
    let calls2 = Arc::clone(&calls);
    let decide: Arc<castctl_approvals::Decider> = Arc::new(move |_, _| {
        *calls2.lock().unwrap() += 1;
        Ok(())
    });
    let aa = AutoApprover::new(Some(connect_ok(decide)), false);
    let it = item("a1", &[FOREVER]);
    let out = aa.approve(&[it.clone(), it]);
    assert_eq!(*calls.lock().unwrap(), 1);
    assert_eq!(out.handled, vec!["a1".to_string()]);
}

#[test]
fn auto_approver_sequential_second_call_skips_decided() {
    let calls = Arc::new(Mutex::new(0usize));
    let calls2 = Arc::clone(&calls);
    let decide: Arc<castctl_approvals::Decider> = Arc::new(move |_, _| {
        *calls2.lock().unwrap() += 1;
        Ok(())
    });
    let aa = AutoApprover::new(Some(connect_ok(decide)), false);
    let it = item("a1", &[FOREVER]);
    aa.approve(std::slice::from_ref(&it));
    let out = aa.approve(std::slice::from_ref(&it));
    assert_eq!(*calls.lock().unwrap(), 1);
    assert!(out.handled.is_empty() && out.errors.is_empty());
}

#[test]
fn auto_approver_failed_decide_claims_id() {
    let calls = Arc::new(Mutex::new(0usize));
    let calls2 = Arc::clone(&calls);
    let decide: Arc<castctl_approvals::Decider> = Arc::new(move |_, _| {
        *calls2.lock().unwrap() += 1;
        Err(Box::from("gateway down") as BoxError)
    });
    let aa = AutoApprover::new(Some(connect_ok(decide)), false);
    let it = item("a1", &[FOREVER]);
    aa.approve(std::slice::from_ref(&it));
    let out = aa.approve(std::slice::from_ref(&it));
    assert_eq!(
        *calls.lock().unwrap(),
        1,
        "a failed decide still claims the id"
    );
    assert!(
        out.errors.is_empty(),
        "second Approve errs must be none (claimed)"
    );
}

#[test]
fn auto_approver_auth_error_propagates_and_stops() {
    let auth_err = || TransportError::Auth {
        message: "expired".to_string(),
    };
    let decided = Arc::new(Mutex::new(Vec::<String>::new()));
    let decided2 = Arc::clone(&decided);
    let decide: Arc<castctl_approvals::Decider> = Arc::new(move |a, _| {
        decided2.lock().unwrap().push(a.id_str().to_string());
        Err(Box::new(auth_err()) as BoxError)
    });
    let aa = Arc::new(AutoApprover::new(Some(connect_ok(decide)), false));
    let items = vec![item("a1", &[FOREVER]), item("a2", &[FOREVER])];
    let out = aa.approve(&items);
    assert_eq!(*decided.lock().unwrap(), vec!["a1".to_string()]);
    assert_eq!(out.errors.len(), 1);
    assert!(out.errors[0].is_auth(), "err must wrap an AuthError");
    // AsApprover surfaces the AuthError unwrapped as the
    // fatal result error.
    let res: ApprovalResult = aa.as_approver()(&items);
    assert!(res.err_is_auth(), "AsApprover Err must be an AuthError");
    // A fresh approver whose Connect fails with AuthError
    // surfaces it the same way.
    let aa2 = Arc::new(AutoApprover::new(
        Some(Box::new(move || Err(Box::new(auth_err()) as BoxError))),
        false,
    ));
    let res2: ApprovalResult = aa2.as_approver()(&items);
    assert!(
        res2.err_is_auth(),
        "connect-AuthError Err must be an AuthError"
    );
    // The fatal error itself must BE the AuthError, not
    // a re-boxed copy of its text (red-team F1): the
    // adapter downcasts it to `BotError::Transport(Auth)`
    // and the CLI exits 2.
    let fatal = res2.err.as_ref().expect("connect auth must set res.err");
    assert!(
        matches!(
            fatal.downcast_ref::<TransportError>(),
            Some(TransportError::Auth { .. })
        ),
        "connect-AuthError res.err must downcast to TransportError::Auth"
    );
}

#[test]
fn auto_approver_empty_id_claimed_once() {
    let calls = Arc::new(Mutex::new(0usize));
    let calls2 = Arc::clone(&calls);
    let decide: Arc<castctl_approvals::Decider> = Arc::new(move |_, _| {
        *calls2.lock().unwrap() += 1;
        Ok(())
    });
    let aa = AutoApprover::new(Some(connect_ok(decide)), false);
    let it = item("", &[FOREVER]);
    let out = aa.approve(&[it.clone(), it]);
    assert_eq!(
        *calls.lock().unwrap(),
        1,
        "\"\" is a present id, claimed once"
    );
    assert_eq!(out.handled, vec![String::new()]);
}

#[test]
fn described_approval_clone() {
    // Clone deep-copies every field: mutating the clone
    // must not touch the original. (Rust values are owned,
    // so `Clone` is a deep copy by construction; this test
    // pins the behaviour Go's explicit Clone provides.)
    let orig = DescribedApproval {
        approval_id: s("A"),
        title: s("T"),
        question: s("Q"),
        kind: s("K"),
        scope: s("S"),
        why: s("W"),
        expires_at_ms: f(7.0),
        options: Some(vec![FOREVER.to_string()]),
    };
    let mut cp = orig.clone();
    cp.approval_id = s("m");
    cp.title = s("m");
    cp.question = s("m");
    cp.kind = s("m");
    cp.scope = s("m");
    cp.why = s("m");
    cp.expires_at_ms = f(0.0);
    cp.options.as_mut().unwrap()[0] = "m".to_string();
    assert_eq!(orig.approval_id.as_deref(), Some("A"));
    assert_eq!(orig.title.as_deref(), Some("T"));
    assert_eq!(orig.question.as_deref(), Some("Q"));
    assert_eq!(orig.kind.as_deref(), Some("K"));
    assert_eq!(orig.scope.as_deref(), Some("S"));
    assert_eq!(orig.why.as_deref(), Some("W"));
    assert_eq!(orig.expires_at_ms, Some(7.0));
    assert_eq!(
        orig.options.as_deref(),
        Some(vec![FOREVER.to_string()].as_slice())
    );
}

#[test]
fn auto_approver_zero_value_guard() {
    // Zero value with no Connect: errors, no panic. (Go's
    // nil-receiver half of TestAutoApproverZeroAndNilGuards
    // has no Rust equivalent: there are no null receivers.)
    let aa = AutoApprover::default();
    let out = aa.approve(&[item("a1", &[])]);
    assert_eq!(out.errors.len(), 1);
}

#[test]
fn auto_approver_warned_distinguishes_nil_and_empty_id() {
    // A skipped nil-id approval and a skipped "" approval
    // are different warnings: each keeps its own
    // auto_approve_errors entry.
    let nil_item = DescribedApproval {
        options: Some(vec!["deny".to_string()]),
        ..Default::default()
    };
    let empty_item = DescribedApproval {
        approval_id: s(""),
        options: Some(vec!["deny".to_string()]),
        ..Default::default()
    };
    let new_approver = || {
        let decide: Arc<castctl_approvals::Decider> =
            Arc::new(move |a, _| panic!("decide must never run for a skipped approval: {a:?}"));
        AutoApprover::new(Some(connect_ok(decide)), false)
    };
    let cases: Vec<(&str, Vec<Vec<DescribedApproval>>)> = vec![
        (
            "nil then empty in one call",
            vec![vec![nil_item.clone(), empty_item.clone()]],
        ),
        (
            "empty then nil in one call",
            vec![vec![empty_item.clone(), nil_item.clone()]],
        ),
        (
            "nil then empty across calls",
            vec![vec![nil_item.clone()], vec![empty_item.clone()]],
        ),
        (
            "empty then nil across calls",
            vec![vec![empty_item.clone()], vec![nil_item.clone()]],
        ),
    ];
    for (name, calls) in cases {
        let aa = new_approver();
        let mut total_errs = 0;
        for items in &calls {
            total_errs += aa.approve(items).errors.len();
        }
        assert_eq!(total_errs, 2, "case {name}: one warning per distinct id");
    }
}
