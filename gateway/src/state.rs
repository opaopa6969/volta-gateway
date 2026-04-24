use tramli::FlowState;

/// Proxy request lifecycle states — the SM "track" that every request rides on.
///
/// ```text
/// RECEIVED → VALIDATED → ROUTED → [auth] → AUTH_CHECKED → [forward] → FORWARDED → COMPLETED
///                                           ├── REDIRECT (401/302)
///                                           ├── DENIED (403)
///                                           └── BAD_GATEWAY (5xx)
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProxyState {
    // Happy path
    Received,
    Validated,
    Routed,
    AuthChecked,
    Forwarded,
    Completed,

    // Error terminals
    BadRequest,
    Redirect,
    Denied,
    BadGateway,
    GatewayTimeout,
}

impl FlowState for ProxyState {
    fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Completed
                | Self::BadRequest
                | Self::Redirect
                | Self::Denied
                | Self::BadGateway
                | Self::GatewayTimeout
        )
    }

    fn is_initial(&self) -> bool {
        matches!(self, Self::Received)
    }

    fn all_states() -> &'static [Self] {
        &[
            Self::Received, Self::Validated, Self::Routed,
            Self::AuthChecked, Self::Forwarded, Self::Completed,
            Self::BadRequest, Self::Redirect, Self::Denied,
            Self::BadGateway, Self::GatewayTimeout,
        ]
    }
}

impl ProxyState {
    #[allow(dead_code)]
    pub fn as_status_code(&self) -> u16 {
        match self {
            Self::Completed => 200,
            Self::BadRequest => 400,
            Self::Redirect => 302,
            Self::Denied => 403,
            Self::BadGateway => 502,
            Self::GatewayTimeout => 504,
            _ => 500,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tramli::FlowState;

    // ── is_terminal ─────────────────────────────────────────────

    #[test]
    fn terminal_states_are_marked_terminal() {
        let terminals = [
            ProxyState::Completed,
            ProxyState::BadRequest,
            ProxyState::Redirect,
            ProxyState::Denied,
            ProxyState::BadGateway,
            ProxyState::GatewayTimeout,
        ];
        for state in terminals {
            assert!(state.is_terminal(), "{:?} should be terminal", state);
        }
    }

    #[test]
    fn non_terminal_states_are_not_terminal() {
        let non_terminals = [
            ProxyState::Received,
            ProxyState::Validated,
            ProxyState::Routed,
            ProxyState::AuthChecked,
            ProxyState::Forwarded,
        ];
        for state in non_terminals {
            assert!(!state.is_terminal(), "{:?} should not be terminal", state);
        }
    }

    // ── is_initial ───────────────────────────────────────────────

    #[test]
    fn received_is_the_only_initial_state() {
        assert!(ProxyState::Received.is_initial());
    }

    #[test]
    fn non_initial_states_return_false_for_is_initial() {
        let others = [
            ProxyState::Validated,
            ProxyState::Routed,
            ProxyState::AuthChecked,
            ProxyState::Forwarded,
            ProxyState::Completed,
            ProxyState::BadRequest,
            ProxyState::Redirect,
            ProxyState::Denied,
            ProxyState::BadGateway,
            ProxyState::GatewayTimeout,
        ];
        for state in others {
            assert!(!state.is_initial(), "{:?} should not be initial", state);
        }
    }

    // ── all_states ───────────────────────────────────────────────

    #[test]
    fn all_states_contains_eleven_entries() {
        assert_eq!(ProxyState::all_states().len(), 11);
    }

    #[test]
    fn all_states_includes_every_variant() {
        let all = ProxyState::all_states();
        assert!(all.contains(&ProxyState::Received));
        assert!(all.contains(&ProxyState::Validated));
        assert!(all.contains(&ProxyState::Routed));
        assert!(all.contains(&ProxyState::AuthChecked));
        assert!(all.contains(&ProxyState::Forwarded));
        assert!(all.contains(&ProxyState::Completed));
        assert!(all.contains(&ProxyState::BadRequest));
        assert!(all.contains(&ProxyState::Redirect));
        assert!(all.contains(&ProxyState::Denied));
        assert!(all.contains(&ProxyState::BadGateway));
        assert!(all.contains(&ProxyState::GatewayTimeout));
    }

    // ── as_status_code ───────────────────────────────────────────

    #[test]
    fn status_codes_match_http_semantics() {
        assert_eq!(ProxyState::Completed.as_status_code(), 200);
        assert_eq!(ProxyState::BadRequest.as_status_code(), 400);
        assert_eq!(ProxyState::Redirect.as_status_code(), 302);
        assert_eq!(ProxyState::Denied.as_status_code(), 403);
        assert_eq!(ProxyState::BadGateway.as_status_code(), 502);
        assert_eq!(ProxyState::GatewayTimeout.as_status_code(), 504);
    }

    #[test]
    fn intermediate_states_return_500_status_code() {
        let intermediates = [
            ProxyState::Received,
            ProxyState::Validated,
            ProxyState::Routed,
            ProxyState::AuthChecked,
            ProxyState::Forwarded,
        ];
        for state in intermediates {
            assert_eq!(state.as_status_code(), 500, "{:?} should give 500", state);
        }
    }

    // ── equality + copy ──────────────────────────────────────────

    #[test]
    fn proxy_state_implements_eq_and_copy() {
        let a = ProxyState::Completed;
        let b = a; // Copy
        assert_eq!(a, b);
        assert_ne!(ProxyState::Completed, ProxyState::Denied);
    }
}
