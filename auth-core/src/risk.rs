//! Risk-based adaptive authentication (Phase 4a, docs/auth-methods-landscape.md §5).
//!
//! Port of the Java `RiskCheckProcessor` logic as a pure, testable core: score
//! login signals into a risk level, then map it against tenant thresholds to a
//! decision. **Fail-open** — with no signals the level is the safe base (1), so
//! a missing/broken signal source never locks users out.
//!
//! The scoring is deliberately simple and explainable (weighted sum of boolean
//! signals). A remote fraud-alert service can override `base` when available;
//! the mapping to Allow/StepUp/Block stays here so policy is consistent.

/// Boolean login signals. Callers populate what they can observe; anything
/// unknown stays `false` (fail-open).
#[derive(Debug, Clone, Default)]
pub struct RiskSignals {
    /// No matching known-device marker for this user (first time on this device).
    pub new_device: bool,
    /// Source IP differs from the user's most recent session.
    pub ip_changed: bool,
    /// ASN / country changed vs recent history.
    pub asn_or_geo_changed: bool,
    /// Geographic velocity exceeds plausibility (two far-apart logins too close in time).
    pub impossible_travel: bool,
    /// Login outside the user's usual active hours.
    pub off_hours: bool,
    /// User-Agent family changed vs recent history.
    pub ua_changed: bool,
}

/// Per-tenant thresholds. Defaults mirror the Java policy (action 4, block 5).
#[derive(Debug, Clone, Copy)]
pub struct RiskThresholds {
    /// Level ≥ this → step up (require an additional factor).
    pub action: u8,
    /// Level ≥ this → block the login outright.
    pub block: u8,
}

impl Default for RiskThresholds {
    fn default() -> Self {
        Self {
            action: 4,
            block: 5,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RiskDecision {
    /// Proceed normally.
    Allow,
    /// Require an additional factor (MFA / passkey) before granting the session.
    StepUp,
    /// Deny the login.
    Block,
}

/// Maximum score the local signal sum can reach (keeps levels bounded and the
/// thresholds meaningful).
pub const MAX_LEVEL: u8 = 6;

/// Score signals into a risk level in `1..=MAX_LEVEL`. Base 1 = "safe" (matches
/// the Java fail-open default). `extra` lets a remote fraud service add points.
pub fn score(signals: &RiskSignals, extra: u8) -> u8 {
    let mut level: u8 = 1;
    if signals.new_device {
        level += 2;
    }
    if signals.impossible_travel {
        level += 3;
    }
    if signals.asn_or_geo_changed {
        level += 1;
    }
    if signals.ip_changed {
        level += 1;
    }
    if signals.ua_changed {
        level += 1;
    }
    if signals.off_hours {
        level += 1;
    }
    level = level.saturating_add(extra);
    level.min(MAX_LEVEL)
}

/// Map a level to a decision using the tenant thresholds.
pub fn decide(level: u8, t: &RiskThresholds) -> RiskDecision {
    if level >= t.block {
        RiskDecision::Block
    } else if level >= t.action {
        RiskDecision::StepUp
    } else {
        RiskDecision::Allow
    }
}

/// Convenience: score + decide in one call.
pub fn evaluate(
    signals: &RiskSignals,
    thresholds: &RiskThresholds,
    extra: u8,
) -> (u8, RiskDecision) {
    let level = score(signals, extra);
    (level, decide(level, thresholds))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_login_is_allowed() {
        let (level, d) = evaluate(&RiskSignals::default(), &RiskThresholds::default(), 0);
        assert_eq!(level, 1);
        assert_eq!(d, RiskDecision::Allow);
    }

    #[test]
    fn new_device_off_hours_steps_up() {
        // 1 + 2(new_device) + 1(off_hours) = 4 == action threshold
        let s = RiskSignals {
            new_device: true,
            off_hours: true,
            ..Default::default()
        };
        let (level, d) = evaluate(&s, &RiskThresholds::default(), 0);
        assert_eq!(level, 4);
        assert_eq!(d, RiskDecision::StepUp);
    }

    #[test]
    fn impossible_travel_plus_new_device_blocks() {
        // 1 + 3 + 2 = 6 >= block(5)
        let s = RiskSignals {
            impossible_travel: true,
            new_device: true,
            ..Default::default()
        };
        let (_l, d) = evaluate(&s, &RiskThresholds::default(), 0);
        assert_eq!(d, RiskDecision::Block);
    }

    #[test]
    fn fail_open_and_bounds() {
        // extra points from a remote service still cap at MAX_LEVEL
        assert_eq!(score(&RiskSignals::default(), 100), MAX_LEVEL);
        // custom lenient thresholds never block a base login
        let lenient = RiskThresholds {
            action: 5,
            block: 6,
        };
        assert_eq!(decide(1, &lenient), RiskDecision::Allow);
    }

    #[test]
    fn thresholds_are_inclusive() {
        let t = RiskThresholds {
            action: 3,
            block: 5,
        };
        assert_eq!(decide(2, &t), RiskDecision::Allow);
        assert_eq!(decide(3, &t), RiskDecision::StepUp);
        assert_eq!(decide(5, &t), RiskDecision::Block);
    }
}
