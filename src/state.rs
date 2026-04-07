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
    ResponseReceived,
    Completed,

    // Error terminals
    BadRequest,
    Redirect,
    Denied,
    BadGateway,
    GatewayTimeout,
}

impl ProxyState {
    pub fn is_terminal(&self) -> bool {
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

    pub fn is_initial(&self) -> bool {
        matches!(self, Self::Received)
    }

    pub fn as_status_code(&self) -> u16 {
        match self {
            Self::Completed => 200, // actual status from backend
            Self::BadRequest => 400,
            Self::Redirect => 302,
            Self::Denied => 403,
            Self::BadGateway => 502,
            Self::GatewayTimeout => 504,
            _ => 500,
        }
    }
}
