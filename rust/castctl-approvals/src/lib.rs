// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Auto-approval describing and deciding (M7a): pure port
//! of Go `internal/approvals` (`approvals.go`).
//!
//! No I/O, no clock, no network. The decide call itself
//! (`egress.approval.decide`) is transport and lives with
//! the caller: the caller supplies a `Decider`, and
//! `AutoApprover` calls it at most once per approval.
//! Decide is not idempotent, so a lost reply must never be
//! re-decided blindly; nothing in this crate retries it.
//!
//! Policy lives with the caller: `choose_auto_decision`
//! only reads the offered options. It never picks
//! `options[0]`, never picks `allow_session`/`allow_today`,
//! and never restricts by kind.
//!
//! Go notes carried over verbatim where they matter:
//! - `DescribedApproval` pointer fields mean "the source
//!   had no value" (`None` here); `Options` is `None` when
//!   the server listed none. The nil-vs-present-`""`
//!   distinction is load-bearing: a present `""` id claims
//!   and warns like any other id, a nil id never claims.
//! - `AutoApprover` is one per wait: `warned`/`decided`
//!   persist for its lifetime.
//! - The decide RPC runs detached from wait cancellation:
//!   Go runs it on `context.Background()`; here the
//!   `Decider` is a synchronous closure, so the caller's
//!   closure owns that detachment (the CLI runs the async
//!   RPC to completion with `block_in_place`).
//!
//! `DescribedApproval` is intentionally a second struct
//! next to `castctl_telegram::Approval` (the bot-side
//! normalisation, M5a): the telegram struct truncates
//! expiry to `i64` and flattens the id to `String`, so it
//! cannot carry the nil-vs-`""` distinction this crate's
//! keying depends on. The conversion lives on the
//! telegram side (`From<&DescribedApproval> for Approval`
//! in `castctl-telegram`), so this pure crate does not
//! depend on the bot crate.
//!
//! No `unsafe`, no `unwrap()`/`expect()` on external input.

use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fmt;
use std::sync::{Arc, Mutex};

use castctl_transport::TransportError;
use serde_json::Value;

/// A boxed error: every error this crate produces or
/// carries. `Arc` (not `Box`) on `ApproveError::err` so an
/// error record can be cloned into `ApprovalResult.err`
/// while staying in `errors` (Go keeps the same
/// `*ApproveError` pointer in both places).
pub type BoxError = Box<dyn Error + Send + Sync>;

/// Muse's "forever" / "Always allow" choice (Go
/// `approvals.go:18` `Forever`).
pub const FOREVER: &str = "allow_always";

/// Muse's "Allow once" choice (Go `approvals.go:21`
/// `Once`).
pub const ONCE: &str = "allow_once";

/// One pending approval, described for a human or an
/// auto-approver (Go `DescribedApproval`). `None` pointer
/// fields mean the source had no value; `Options` is
/// `None` when the server listed none.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DescribedApproval {
    /// Approval id (`None` = the source had no id).
    pub approval_id: Option<String>,
    /// Display title.
    pub title: Option<String>,
    /// Question text (`{assistant}` already replaced with
    /// `Muse`).
    pub question: Option<String>,
    /// Kind (`question.kind`, else `payload.type`).
    pub kind: Option<String>,
    /// Scope (`question.scope`, else the `Host` detail row).
    pub scope: Option<String>,
    /// Why (`short_explanation`, else `reason`, else the
    /// top-level `reason`).
    pub why: Option<String>,
    /// Expiry, unix milliseconds (`None` = no expiry).
    pub expires_at_ms: Option<f64>,
    /// Listed decision options (`None` = none listed).
    pub options: Option<Vec<String>>,
}

impl DescribedApproval {
    /// Dereference helpers, mirroring Go's `deref` at the
    /// use sites (empty string for a missing field).
    pub fn id_str(&self) -> &str {
        self.approval_id.as_deref().unwrap_or("")
    }

    pub fn title_str(&self) -> &str {
        self.title.as_deref().unwrap_or("")
    }

    pub fn question_str(&self) -> &str {
        self.question.as_deref().unwrap_or("")
    }

    pub fn kind_str(&self) -> &str {
        self.kind.as_deref().unwrap_or("")
    }

    pub fn scope_str(&self) -> &str {
        self.scope.as_deref().unwrap_or("")
    }
}

fn as_map(v: &Value) -> Option<&serde_json::Map<String, Value>> {
    v.as_object()
}

fn get<'a>(v: &'a Value, key: &str) -> Option<&'a Value> {
    as_map(v)?.get(key)
}

fn str_field(v: &Value, key: &str) -> Option<String> {
    get(v, key)?.as_str().map(str::to_string)
}

/// First non-empty string among the candidates, else
/// `None`. Non-string values are skipped (Go
/// `firstString`).
fn first_string(vs: &[Option<&Value>]) -> Option<String> {
    for v in vs {
        if let Some(s) = v.and_then(Value::as_str)
            && !s.is_empty()
        {
            return Some(s.to_string());
        }
    }
    None
}

fn question_text(v: Option<&Value>) -> Option<String> {
    let s = v?.as_str()?;
    let replaced = s.replace("{assistant}", "Muse");
    if replaced.is_empty() {
        None
    } else {
        Some(replaced)
    }
}

/// Expiry to milliseconds since the epoch (Go
/// `expiresAtMS`). Only numbers count; a bool is an int
/// in Python, so `true` counts as 1 and `false` as 0.
/// Numeric strings are not numbers (`None`). Any other
/// type means "no expiry". A non-finite float (e.g.
/// `1e999`, which parses to `inf`) is out of range for
/// Go's `json.Number.Float64()` and counts as no expiry
/// (red-team F11).
fn expires_at_ms(v: Option<&Value>) -> Option<f64> {
    match v? {
        Value::Number(n) => n.as_f64().filter(|f| f.is_finite()),
        Value::Bool(b) => Some(if *b { 1.0 } else { 0.0 }),
        _ => None,
    }
}

/// Describe one approval, never panicking on malformed
/// input (Go `DescribeApproval`): a non-map approval (or
/// non-map display / permission_question / payload)
/// degrades to empty fields with a nil id instead of
/// failing the wait.
pub fn describe_approval(a: &Value) -> DescribedApproval {
    let m = match as_map(a) {
        Some(m) => m,
        None => return DescribedApproval::default(),
    };
    let display = get(a, "display").and_then(as_map);
    let question = display
        .and_then(|d| d.get("permission_question"))
        .and_then(as_map);
    let payload = get(a, "payload").and_then(as_map);
    let mut rows: HashMap<&str, &Value> = HashMap::new();
    if let Some(list) = display
        .and_then(|d| d.get("detail_rows"))
        .and_then(Value::as_array)
    {
        for r in list {
            if let Some(rm) = as_map(r)
                && let Some(label) = rm.get("label").and_then(Value::as_str)
                && let Some(value) = rm.get("value")
            {
                rows.insert(label, value);
            }
        }
    }
    let mut options: Vec<String> = Vec::new();
    if let Some(list) = m.get("decision_options").and_then(Value::as_array) {
        for o in list {
            if let Some(kind) = as_map(o)
                .and_then(|om| om.get("kind"))
                .and_then(Value::as_str)
                && !kind.is_empty()
            {
                options.push(kind.to_string());
            }
        }
    }
    let options = if options.is_empty() {
        None
    } else {
        Some(options)
    };
    DescribedApproval {
        approval_id: str_field(a, "approval_id"),
        title: first_string(&[
            display.and_then(|d| d.get("summary_title")),
            display.and_then(|d| d.get("display_name")),
        ]),
        question: question_text(question.and_then(|q| q.get("text"))),
        kind: first_string(&[
            question.and_then(|q| q.get("kind")),
            payload.and_then(|p| p.get("type")),
        ]),
        scope: first_string(&[
            question.and_then(|q| q.get("scope")),
            rows.get("Host").copied(),
        ]),
        why: first_string(&[
            display.and_then(|d| d.get("short_explanation")),
            display.and_then(|d| d.get("reason")),
            m.get("reason"),
        ]),
        expires_at_ms: expires_at_ms(m.get("request_expires_at_ms")),
        options,
    }
}

/// Whether the forever choice is offered (Go
/// `OffersForever`): approvals that list no options (older
/// servers) are assumed to accept it.
pub fn offers_forever(d: &DescribedApproval) -> bool {
    match &d.options {
        None => true,
        Some(opts) => opts.is_empty() || opts.iter().any(|o| o == FOREVER),
    }
}

/// Whether `allow_once` is explicitly listed (Go
/// `OffersOnce`). False when no options are listed.
pub fn offers_once(d: &DescribedApproval) -> bool {
    match &d.options {
        Some(opts) => opts.iter().any(|o| o == ONCE),
        None => false,
    }
}

/// The decision an auto-approver may send, or
/// `("", false)` to leave the approval for a human (Go
/// `ChooseAutoDecision`). `allow_always` wins when
/// offered (or when no options are listed at all).
/// Otherwise `allow_once`, only when the caller
/// explicitly enabled the fallback (`allow_once`) and
/// auto-approve is on. An approval listing no options
/// keeps the offers-forever assumption; it is not turned
/// into `allow_once`.
pub fn choose_auto_decision(
    d: &DescribedApproval,
    auto_approve: bool,
    allow_once: bool,
) -> (String, bool) {
    if !auto_approve {
        return (String::new(), false);
    }
    if offers_forever(d) {
        return (FOREVER.to_string(), true);
    }
    if allow_once && offers_once(d) {
        return (ONCE.to_string(), true);
    }
    (String::new(), false)
}

/// A skipped approval: no forever option was offered (Go
/// `noForeverError`). `Display` preserves the offers list
/// verbatim — callers and the JSON data rendering keep the
/// exact pre-loop-8 text. `option_count` exposes ONLY the
/// number of offered options, for the structural stderr
/// rendering in `logAutoApproved` (loop 8): option labels
/// never reach stderr, only the count.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoForeverError {
    /// The offered option labels (never rendered to stderr).
    pub options: Vec<String>,
}

impl NoForeverError {
    /// How many decision options were offered.
    pub fn option_count(&self) -> usize {
        self.options.len()
    }
}

impl fmt::Display for NoForeverError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "no forever option (offers [{}])", self.options.join(" "))
    }
}

impl Error for NoForeverError {}

/// One successful auto-approval, in the shape the result
/// object reports (Go `ApprovedRecord`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ApprovedRecord {
    /// Approval id ("" when the source had none).
    pub approval_id: String,
    /// Display title.
    pub title: String,
    /// Kind.
    pub kind: String,
    /// Scope.
    pub scope: String,
    /// Decision sent (`allow_always` / `allow_once`).
    pub decision: String,
}

/// One approval the auto-approver could not decide: a
/// skipped approval (no decision), a failed decide, or a
/// connector failure before any decide (Go
/// `ApproveError`). `Display` is `auto-approve <id>: <err>`
/// and `source()` is the wrapped error, so
/// `errors.As`-style walks (see `is_auth_error`) see
/// through it.
#[derive(Clone)]
pub struct ApproveError {
    /// Approval id ("" when the source had none).
    pub approval_id: String,
    /// Display title.
    pub title: String,
    /// Kind.
    pub kind: String,
    /// Scope.
    pub scope: String,
    /// Decision attempted ("" when skipped).
    pub decision: String,
    /// The underlying error.
    pub err: Arc<BoxError>,
}

impl ApproveError {
    /// Whether this error wraps an auth failure anywhere
    /// in its chain.
    pub fn is_auth(&self) -> bool {
        is_auth_error(self)
    }
}

impl fmt::Debug for ApproveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApproveError")
            .field("approval_id", &self.approval_id)
            .field("title", &self.title)
            .field("kind", &self.kind)
            .field("scope", &self.scope)
            .field("decision", &self.decision)
            .field("err", &self.err.to_string())
            .finish()
    }
}

impl fmt::Display for ApproveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "auto-approve {}: {}", self.approval_id, self.err)
    }
}

impl Error for ApproveError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&**self.err)
    }
}

/// What an `Approver` returns (Go `ApprovalResult`): the
/// ids it handled, the approved records, the error records
/// (skips and failed decides, in item order), and a fatal
/// error. `err` is set only when the call failed as a
/// whole: an `Auth` error from any decide, or the first
/// error when nothing was handled. Approved and errors
/// are reported even when `err` is set.
#[derive(Default)]
pub struct ApprovalResult {
    /// Ids handled (bare strings, in item order).
    pub handled: Vec<String>,
    /// Successful auto-approvals.
    pub approved: Vec<ApprovedRecord>,
    /// Skips and failed decides, in item order.
    pub errors: Vec<ApproveError>,
    /// Fatal error, if the call failed as a whole.
    pub err: Option<BoxError>,
}

impl ApprovalResult {
    /// Whether the fatal error is an auth failure.
    pub fn err_is_auth(&self) -> bool {
        match &self.err {
            Some(e) => is_auth_error(e.as_ref()),
            None => false,
        }
    }
}

impl fmt::Debug for ApprovalResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApprovalResult")
            .field("handled", &self.handled)
            .field("approved", &self.approved)
            .field("errors", &self.errors)
            .field("err", &self.err.as_ref().map(|e| e.to_string()))
            .finish()
    }
}

/// Approver decides new pending approvals (Go `Approver`).
/// Called synchronously by the wait core.
pub type Approver = dyn Fn(&[DescribedApproval]) -> ApprovalResult + Send + Sync;

/// One `egress.approval.decide` call (Go `Decider`). Called
/// at most once per approval: `AutoApprover` never retries
/// it.
pub type Decider = dyn Fn(&DescribedApproval, &str) -> Result<(), BoxError> + Send + Sync;

/// Opens one fresh connection and returns its `Decider`
/// plus a close function (Go `AutoApprover.connect`). The
/// close function runs even when deciding fails, and is
/// never called when `Connect` itself fails.
pub type ConnectFn =
    dyn Fn() -> Result<(Box<Decider>, Box<dyn FnOnce() + Send>), BoxError> + Send + Sync;

/// Called after each successful decide with the approval
/// id and decision (Go `AutoApprover.OnDecided`).
pub type OnDecidedFn = dyn Fn(&str, &str) + Send + Sync;

/// Whether an error wraps a `TransportError::Auth`
/// anywhere in its chain (Go `isAuthError` /
/// `errors.As(err, &AuthError)`). Walks `source()`; the
/// error itself is checked first.
pub fn is_auth_error(err: &(dyn Error + 'static)) -> bool {
    find_auth_error(err).is_some()
}

/// The `TransportError::Auth` wrapped in an error chain,
/// if any (Go `authErrorOf` / `errors.As`).
pub fn find_auth_error(err: &(dyn Error + 'static)) -> Option<TransportError> {
    let mut current: Option<&(dyn Error + 'static)> = Some(err);
    while let Some(e) = current {
        if let Some(te) = e.downcast_ref::<TransportError>()
            && matches!(te, TransportError::Auth { .. })
        {
            return Some(te.clone());
        }
        current = e.source();
    }
    None
}

/// One `Approve` call's outcome: the handled ids, the
/// approved records, and the error records, in item order
/// (Go `AutoApprover.Approve`'s three return values).
#[derive(Debug, Default)]
pub struct ApproveOutcome {
    /// Ids handled (bare strings, in item order).
    pub handled: Vec<String>,
    /// Successful auto-approvals.
    pub approved: Vec<ApprovedRecord>,
    /// Skips and failed decides, in item order.
    pub errors: Vec<ApproveError>,
}

/// The wait core's approver (Go `AutoApprover`): it opens
/// one fresh connection per `Approve` call (through
/// `Connect`), decides each item once with
/// `choose_auto_decision`, records successes, and records
/// (but never retries) failures. A skipped approval is
/// warned about once per id: the warning is the
/// `ApproveError` entry, emitted only on the first skip;
/// later skips of the same id produce no entry but the
/// approval stays undecided.
///
/// A connector failure before any decide records an error
/// for every item and returns no handled ids.
///
/// Claim semantics: the first `Approve` call to present an
/// id claims it — the `Decider` runs at most once per id
/// for the `AutoApprover`'s lifetime, and a concurrent or
/// later presentation of the same id is skipped silently
/// (no re-decide, no warning). An id is present iff the
/// description's `approval_id` is `Some`: the empty string
/// claims like any other id. A failed decide still claims
/// the id — Decide is not idempotent, and a failed or lost
/// reply must never be re-decided blindly. The mutex
/// guards only the `warned`/`decided` sets and is never
/// held across a decide call, so unrelated ids still
/// decide in parallel.
///
/// Lifetime: `warned` and `decided` persist for the
/// `AutoApprover`'s lifetime. Create one `AutoApprover`
/// per wait, as the wait's caller does.
///
/// `AutoApprover` never writes to stderr. The caller owns
/// stderr and logs the `Approved`/`errors` records the
/// wait result carries.
pub struct AutoApprover {
    connect: Option<Box<ConnectFn>>,
    allow_once: bool,
    on_decided: Mutex<Option<Arc<OnDecidedFn>>>,
    warned: Mutex<HashMap<(bool, String), bool>>,
    decided: Mutex<HashSet<String>>,
}

impl Default for AutoApprover {
    /// The zero value: no `Connect`, so `Approve` records
    /// a connect error for every item instead of panicking
    /// (Go's zero-value guard).
    fn default() -> Self {
        AutoApprover {
            connect: None,
            allow_once: false,
            on_decided: Mutex::new(None),
            warned: Mutex::new(HashMap::new()),
            decided: Mutex::new(HashSet::new()),
        }
    }
}

impl AutoApprover {
    /// Build an `AutoApprover` (Go `NewAutoApprover`).
    /// `connect` is `None` for the zero value (no
    /// connection: `Approve` records a connect error for
    /// every item).
    pub fn new(connect: Option<Box<ConnectFn>>, allow_once: bool) -> Self {
        AutoApprover {
            connect,
            allow_once,
            on_decided: Mutex::new(None),
            warned: Mutex::new(HashMap::new()),
            decided: Mutex::new(HashSet::new()),
        }
    }

    /// Set the `OnDecided` callback (Go's `OnDecided`
    /// field). It runs on the approver's thread with no
    /// `AutoApprover` lock held, and must not call back
    /// into the `AutoApprover`.
    pub fn set_on_decided(&self, f: Box<OnDecidedFn>) {
        if let Ok(mut slot) = self.on_decided.lock() {
            *slot = Some(Arc::new(f));
        }
    }

    fn err_for(item: &DescribedApproval, decision: &str, err: BoxError) -> ApproveError {
        Self::err_for_shared(item, decision, Arc::new(err))
    }

    /// Like `err_for`, but the error value is already
    /// shared: every record carries the SAME error, not
    /// a copy (used for the connect failure, where one
    /// error object is recorded on every item — Go
    /// `errFor` with the same error object,
    /// `approvals.go:461-466`).
    fn err_for_shared(
        item: &DescribedApproval,
        decision: &str,
        err: Arc<BoxError>,
    ) -> ApproveError {
        ApproveError {
            approval_id: item.id_str().to_string(),
            title: item.title_str().to_string(),
            kind: item.kind_str().to_string(),
            scope: item.scope_str().to_string(),
            decision: decision.to_string(),
            err,
        }
    }

    /// Decide items, in item order (Go
    /// `AutoApprover.Approve`). A `Decider` is invoked at
    /// most once per id for the `AutoApprover`'s lifetime,
    /// and never for an item with no decision.
    pub fn approve(&self, items: &[DescribedApproval]) -> ApproveOutcome {
        let mut outcome = ApproveOutcome::default();
        let connect = match &self.connect {
            Some(c) => c,
            None => {
                for item in items {
                    outcome.errors.push(Self::err_for(
                        item,
                        "",
                        Box::from("approvals: no Connect"),
                    ));
                }
                return outcome;
            }
        };
        let (decide, close) = match connect() {
            Ok(pair) => pair,
            Err(e) => {
                // The connect error is shared behind one
                // `Arc`: every record carries the SAME
                // error value, so `as_approver` still
                // finds a `TransportError::Auth` in the
                // chain and the wait exits 2, as in Go
                // (`errFor` records the same error
                // object on every item). Re-boxing from
                // the error TEXT here used to lose the
                // type and turn a connect-time auth
                // failure into a synthetic 124
                // (red-team F1, fix loop 1).
                let shared: Arc<BoxError> = Arc::new(e);
                for item in items {
                    outcome
                        .errors
                        .push(Self::err_for_shared(item, "", Arc::clone(&shared)));
                }
                return outcome;
            }
        };
        for item in items {
            let (decision, ok) = choose_auto_decision(item, true, self.allow_once);
            let rec = ApprovedRecord {
                approval_id: item.id_str().to_string(),
                title: item.title_str().to_string(),
                kind: item.kind_str().to_string(),
                scope: item.scope_str().to_string(),
                decision: decision.clone(),
            };
            if !ok {
                let key = match &item.approval_id {
                    Some(id) => (true, id.clone()),
                    None => (false, String::new()),
                };
                // A poisoned mutex still holds the set:
                // recover it instead of falling back to
                // "not warned" (which would emit a
                // duplicate warning) — the fail-closed
                // direction (safety NIT-1).
                let already_warned = {
                    let mut warned = self.warned.lock().unwrap_or_else(|e| e.into_inner());
                    let already = warned.get(&key).copied().unwrap_or(false);
                    if !already {
                        warned.insert(key, true);
                    }
                    already
                };
                if !already_warned {
                    outcome.errors.push(Self::err_for(
                        item,
                        "",
                        Box::new(NoForeverError {
                            options: item.options.clone().unwrap_or_default(),
                        }),
                    ));
                }
                continue;
            }
            if let Some(id) = &item.approval_id {
                // A poisoned mutex still holds the set:
                // recover it instead of falling back to
                // "not claimed" (which would re-decide
                // the id) — the fail-closed direction
                // (safety NIT-1).
                let claimed = {
                    let mut decided = self.decided.lock().unwrap_or_else(|e| e.into_inner());
                    let claimed = decided.contains(id.as_str());
                    if !claimed {
                        decided.insert(id.clone());
                    }
                    claimed
                };
                if claimed {
                    continue;
                }
            }
            match decide(item, &decision) {
                Ok(()) => {
                    outcome.approved.push(rec);
                    if let Some(id) = &item.approval_id {
                        let cb = self.on_decided.lock().ok().and_then(|slot| slot.clone());
                        if let Some(cb) = cb {
                            cb(id, &decision);
                        }
                    }
                    outcome.handled.push(item.id_str().to_string());
                }
                Err(e) => {
                    let is_auth = is_auth_error(e.as_ref());
                    outcome.errors.push(Self::err_for(item, &decision, e));
                    if is_auth {
                        // Auth is gone: deciding further
                        // items on this connection is
                        // pointless, and the caller must
                        // surface the AuthError rather than
                        // collect more failures.
                        break;
                    }
                }
            }
        }
        close();
        outcome
    }

    /// Adapt this `AutoApprover` to the wait core's
    /// `Approver` shape (Go `AutoApprover.AsApprover`).
    ///
    /// An `Auth` error from any decide (or from Connect)
    /// is returned unwrapped as `ApprovalResult.err`, so
    /// the waiter ends the wait with it instead of
    /// converting it to an exit-4 approval result. Any
    /// other failure surfaces as `err` only when nothing
    /// was handled: the waiter then marks the offered ids
    /// approver-failed instead of silently leaving them
    /// undecided on every snapshot. Approved and error
    /// records are always carried in the result for the
    /// driver to report; nothing is logged here.
    pub fn as_approver(self: &Arc<Self>) -> Box<Approver> {
        let this = Arc::clone(self);
        Box::new(move |items: &[DescribedApproval]| {
            let outcome = this.approve(items);
            let mut res = ApprovalResult {
                handled: outcome.handled,
                approved: outcome.approved,
                errors: outcome.errors,
                err: None,
            };
            for e in &res.errors {
                if let Some(auth) = find_auth_error(e) {
                    res.err = Some(Box::new(auth));
                    return res;
                }
            }
            if !res.errors.is_empty() && res.handled.is_empty() && !items.is_empty() {
                res.err = Some(Box::new(res.errors[0].clone()));
            }
            res
        })
    }
}
