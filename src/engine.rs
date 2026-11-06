//! The decision. The order of checks is the security argument:
//!
//! 1. Rules are matched first, and `deny` and `ask` win in every mode.
//! 2. In rule and hybrid mode, ML only runs inside the allow/envelope ceiling
//!    set by those rules. No request without such a rule becomes Allow there,
//!    whatever the model says.
//! 3. ML-only mode (a preview) is the exception the operator opts into: the
//!    model alone may elevate a command that needs root and has no rule. It
//!    still never elevates opaque programs (shells, interpreters, kernel tools),
//!    and by default never a program it had too few training rows for.
//! 4. The guards, the TTY requirement and the network check can only turn
//!    Allow into Ask.

use crate::analyze::{hard_guard, ml_alone_guard, needs_root, network_reason};
use crate::policy::{Mode, Policy, Rule};
use crate::request::Request;
use crate::transformer::Score;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Elevate now.
    Allow,
    /// Elevate only after an approver authenticates.
    Ask,
    /// Do not run.
    Deny,
    /// Run with the caller's own privileges.
    User,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Allow => "allow",
            Verdict::Ask => "ask",
            Verdict::Deny => "deny",
            Verdict::User => "user",
        }
    }
}

/// What the engine needs from a risk model. Any implementation must leave the
/// security properties intact, which `tests/engine.rs` checks with models that
/// are maximally wrong.
pub trait Scorer {
    fn score(&self, req: &Request) -> Score;
    /// Scores below this may elevate.
    fn threshold(&self) -> f32;
}

impl Scorer for crate::risk::Risk {
    fn score(&self, req: &Request) -> Score {
        crate::risk::Risk::score(self, req)
    }

    fn threshold(&self) -> f32 {
        crate::risk::Risk::threshold(self)
    }
}

#[derive(Debug, Clone)]
pub struct Decision {
    pub verdict: Verdict,
    pub rule: Option<String>,
    pub ml: Option<f32>,
    pub reasons: Vec<String>,
}

impl Decision {
    fn new(verdict: Verdict, rule: Option<&Rule>, reason: String) -> Decision {
        Decision {
            verdict,
            rule: rule.map(|r| r.id.clone()),
            ml: None,
            reasons: vec![reason],
        }
    }
}

/// Whether `decide` would consult the model for this request. Loading the
/// machine facts costs tens of milliseconds, so callers skip it otherwise.
pub fn needs_model(policy: &Policy, req: &Request) -> bool {
    let m = policy.match_rules(req);
    if m.deny.is_some() || m.ask.is_some() {
        return false;
    }
    match policy.mode {
        Mode::Rule => false,
        Mode::Hybrid => m.allow.is_some() || m.envelope.is_some(),
        Mode::Ml => m.user.is_none() && needs_root(req),
    }
}

pub fn decide(policy: &Policy, model: Option<&dyn Scorer>, req: &Request) -> Decision {
    let m = policy.match_rules(req);

    if let Some(rule) = m.deny {
        return Decision::new(Verdict::Deny, Some(rule), format!("denied by rule `{}`", rule.id));
    }
    if let Some(rule) = m.ask {
        return Decision::new(
            Verdict::Ask,
            Some(rule),
            format!("rule `{}` requires approval", rule.id),
        );
    }

    let mut decision = match policy.mode {
        Mode::Rule => match (m.allow, m.envelope, m.user) {
            (Some(rule), _, _) => {
                Decision::new(Verdict::Allow, Some(rule), format!("allowed by rule `{}`", rule.id))
            }
            (None, Some(rule), _) => Decision::new(
                Verdict::Ask,
                Some(rule),
                format!("envelope `{}` needs ML, which rule mode does not use", rule.id),
            ),
            (None, None, Some(rule)) => no_elevation(rule),
            (None, None, None) => no_rule(),
        },
        Mode::Hybrid => match (m.allow, m.envelope, m.user) {
            (Some(rule), _, _) => ml_veto(policy, model, req, rule),
            (None, Some(rule), _) => ml_gate(policy, model, req, Some(rule), false),
            (None, None, Some(rule)) => no_elevation(rule),
            (None, None, None) => no_rule(),
        },
        Mode::Ml => match m.user {
            Some(rule) => no_elevation(rule),
            None if !needs_root(req) => Decision::new(
                Verdict::User,
                None,
                "nothing it names needs root, so it runs with normal rights".to_string(),
            ),
            None => ml_gate(policy, model, req, None, policy.ml.judge_unknown),
        },
    };

    if decision.verdict == Verdict::Allow {
        let guards = if policy.mode == Mode::Ml { ml_alone_guard(req) } else { hard_guard(req) };
        if !guards.is_empty() {
            decision.verdict = Verdict::Ask;
            decision.reasons.extend(guards);
        }
        if policy.network.ask {
            if let Some(reason) = network_reason(req) {
                decision.verdict = Verdict::Ask;
                decision.reasons.push(format!("{reason}; network.ask requires approval"));
            }
        }
        if policy.require_tty && !req.ctx.has_tty {
            decision.verdict = Verdict::Ask;
            decision.reasons.push("no terminal attached".to_string());
        }
    }
    decision
}

fn no_rule() -> Decision {
    Decision::new(Verdict::Ask, None, "no rule matches this command".to_string())
}

fn no_elevation(rule: &Rule) -> Decision {
    Decision::new(
        Verdict::User,
        Some(rule),
        format!("rule `{}` runs without privileges", rule.id),
    )
}

fn unavailable(rule: Option<&Rule>) -> Decision {
    Decision::new(
        Verdict::Ask,
        rule,
        "risk model or machine facts unavailable".to_string(),
    )
}

/// The score must be below the model's threshold (and the operator's stricter
/// cap, if set), and the program must be one the model knows unless the
/// operator chose otherwise for ML-only mode.
fn ml_gate(policy: &Policy, model: Option<&dyn Scorer>, req: &Request, rule: Option<&Rule>, judge_unknown: bool) -> Decision {
    let Some(model) = model else { return unavailable(rule) };
    let score = model.score(req);
    let limit = policy.ml.low.map_or(model.threshold(), |low| low.min(model.threshold()));
    let place = rule.map_or_else(|| "no rule".to_string(), |r| format!("inside `{}`", r.id));
    let p = score.risk;
    // Written so that a NaN score falls through to Ask.
    let (verdict, reason) = if !score.known && !judge_unknown {
        (
            Verdict::Ask,
            format!("{place}: the model had too few allowed examples of {} to judge it", req.basename()),
        )
    } else if p < limit {
        (Verdict::Allow, format!("{place} and ML risk {p:.4} < {limit:.4}"))
    } else {
        (Verdict::Ask, format!("{place} but ML risk {p:.4} is not below {limit:.4}"))
    };
    let mut decision = Decision::new(verdict, rule, reason);
    decision.ml = Some(p);
    decision
}

/// An explicit allow rule stands unless the model is clearly worried.
fn ml_veto(policy: &Policy, model: Option<&dyn Scorer>, req: &Request, rule: &Rule) -> Decision {
    let Some(model) = model else { return unavailable(Some(rule)) };
    let p = model.score(req).risk;
    let (verdict, reason) = if p < policy.ml.high {
        (
            Verdict::Allow,
            format!("allowed by rule `{}` (ML risk {p:.4})", rule.id),
        )
    } else {
        (
            Verdict::Ask,
            format!(
                "rule `{}` allows this, but ML risk {p:.4} is not below {:.3}",
                rule.id, policy.ml.high
            ),
        )
    };
    let mut decision = Decision::new(verdict, Some(rule), reason);
    decision.ml = Some(p);
    decision
}
