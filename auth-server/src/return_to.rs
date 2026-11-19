//! Where browser redirects (`return_to`) are allowed to point.
//!
//! `/login?return_to=…` and `/auth/logout?return_to=…` both end in a browser
//! redirect to a caller-supplied URL. Without a check that is an open redirect
//! (and, for `/login`, a `javascript:` URL lands in the passkey script). The
//! allowed hosts used to be hardcoded to `*.unlaxer.org`; they now come from
//! configuration so the auth-server can run on any domain.
//!
//! Resolution order (first one that is set wins):
//!
//! 1. `ALLOWED_RETURN_TO_DOMAINS` — comma-separated. `example.com` allows that
//!    host only; `.example.com` or `*.example.com` allows it and every subdomain.
//! 2. `COOKIE_DOMAIN` — the domain the session cookie is shared with, so the
//!    same set of apps can receive the user back (apex + subdomains).
//! 3. Neither set → only the host of `BASE_URL`.
//!
//! The host of `BASE_URL` is always allowed. `https` is always accepted; `http`
//! only when `BASE_URL` itself is `http` (local development). Same-origin
//! relative paths (`/app/page`) are always accepted.
//!
//! With the production env (`COOKIE_DOMAIN=.unlaxer.org`, `BASE_URL=https://…`)
//! this resolves to "https on unlaxer.org or any subdomain" — the previous
//! hardcoded rule.

use url::Url;

/// Env var holding an explicit allow-list (see module docs).
pub const ALLOWED_RETURN_TO_DOMAINS_ENV: &str = "ALLOWED_RETURN_TO_DOMAINS";

#[derive(Debug, Clone, PartialEq, Eq)]
enum DomainRule {
    /// The host itself only.
    Exact(String),
    /// The host and any subdomain of it.
    WithSubdomains(String),
}

impl DomainRule {
    fn parse(entry: &str) -> Option<Self> {
        let entry = entry.trim().to_ascii_lowercase();
        if let Some(rest) = entry.strip_prefix("*.").or_else(|| entry.strip_prefix('.')) {
            let rest = rest.trim_matches('.');
            return (!rest.is_empty()).then(|| Self::WithSubdomains(rest.to_string()));
        }
        let entry = entry.trim_matches('.');
        (!entry.is_empty()).then(|| Self::Exact(entry.to_string()))
    }

    fn matches(&self, host: &str) -> bool {
        match self {
            Self::Exact(d) => host == d,
            Self::WithSubdomains(d) => {
                host == d
                    || host
                        .strip_suffix(d.as_str())
                        .is_some_and(|prefix| prefix.ends_with('.'))
            }
        }
    }
}

/// Which `return_to` values the auth-server will redirect a browser to.
#[derive(Debug, Clone)]
pub struct ReturnToPolicy {
    rules: Vec<DomainRule>,
    allow_http: bool,
}

impl ReturnToPolicy {
    /// Build from explicit settings. `allowed` is the raw
    /// `ALLOWED_RETURN_TO_DOMAINS` value (`None` / blank = unset).
    pub fn from_settings(allowed: Option<&str>, cookie_domain: &str, base_url: &str) -> Self {
        let base = Url::parse(base_url).ok();
        let allow_http = base.as_ref().is_some_and(|u| u.scheme() == "http");

        let mut rules: Vec<DomainRule> = match allowed.map(str::trim).filter(|s| !s.is_empty()) {
            Some(list) => list.split(',').filter_map(DomainRule::parse).collect(),
            None => {
                let cookie = cookie_domain.trim().trim_start_matches('.');
                if cookie.is_empty() {
                    vec![]
                } else {
                    DomainRule::parse(&format!(".{cookie}"))
                        .into_iter()
                        .collect()
                }
            }
        };
        if let Some(host) = base.as_ref().and_then(|u| u.host_str()) {
            let own = DomainRule::Exact(host.to_ascii_lowercase());
            if !rules.contains(&own) {
                rules.push(own);
            }
        }
        Self { rules, allow_http }
    }

    /// Build from the process environment (`ALLOWED_RETURN_TO_DOMAINS`).
    pub fn from_env(cookie_domain: &str, base_url: &str) -> Self {
        let allowed = std::env::var(ALLOWED_RETURN_TO_DOMAINS_ENV).ok();
        Self::from_settings(allowed.as_deref(), cookie_domain, base_url)
    }

    /// Whether the URL scheme may be redirected to.
    pub fn allows_scheme(&self, scheme: &str) -> bool {
        scheme == "https" || (self.allow_http && scheme == "http")
    }

    /// Whether `return_to` is a same-origin relative path or an absolute URL
    /// on an allowed host.
    pub fn allows(&self, return_to: &str) -> bool {
        if return_to.is_empty() || return_to.chars().any(|c| c.is_control()) {
            return false;
        }
        if return_to.starts_with('/') {
            // `//evil.com` and `/\evil.com` are protocol-relative in browsers.
            return !return_to.starts_with("//") && !return_to.starts_with("/\\");
        }
        Url::parse(return_to).is_ok_and(|u| self.allows_url(&u))
    }

    /// Whether an absolute URL may be redirected to.
    pub fn allows_url(&self, url: &Url) -> bool {
        if !self.allows_scheme(url.scheme()) {
            return false;
        }
        if !url.username().is_empty() || url.password().is_some() {
            return false;
        }
        let Some(host) = url.host_str() else {
            return false;
        };
        let host = host.to_ascii_lowercase();
        self.rules.iter().any(|r| r.matches(&host))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The production env: COOKIE_DOMAIN=.unlaxer.org, BASE_URL=https://auth.unlaxer.org,
    /// ALLOWED_RETURN_TO_DOMAINS unset.
    fn production() -> ReturnToPolicy {
        ReturnToPolicy::from_settings(None, ".unlaxer.org", "https://auth.unlaxer.org")
    }

    /// The rule that used to be hardcoded in handlers/auth.rs.
    fn legacy_rule(rt: &str) -> bool {
        let Some(rest) = rt.strip_prefix("https://") else {
            return false;
        };
        let host = rest.split('/').next().unwrap_or("");
        host == "unlaxer.org" || host.ends_with(".unlaxer.org")
    }

    #[test]
    fn production_env_matches_the_old_hardcoded_rule() {
        let p = production();
        for rt in [
            "https://unlaxer.org/",
            "https://console.unlaxer.org/",
            "https://a.b.unlaxer.org/path?q=1",
            "https://auth.unlaxer.org/login",
            "http://console.unlaxer.org/",
            "https://evil.com/",
            "https://unlaxer.org.evil.com/",
            "https://evilunlaxer.org/",
            "javascript:alert(1)",
            "ftp://console.unlaxer.org/",
        ] {
            assert_eq!(p.allows(rt), legacy_rule(rt), "{rt}");
        }
        assert!(!p.allows_scheme("http"));
    }

    #[test]
    fn relative_paths_are_allowed_but_protocol_relative_is_not() {
        let p = production();
        assert!(p.allows("/"));
        assert!(p.allows("/app/page?x=1"));
        assert!(!p.allows("//evil.com/"));
        assert!(!p.allows("/\\evil.com/"));
        assert!(!p.allows(""));
        assert!(!p.allows("/a\nb"));
    }

    #[test]
    fn userinfo_tricks_are_rejected() {
        let p = production();
        assert!(!p.allows("https://user@console.unlaxer.org/"));
        assert!(!p.allows("https://console.unlaxer.org@evil.com/"));
    }

    #[test]
    fn explicit_list_overrides_cookie_domain() {
        let p = ReturnToPolicy::from_settings(
            Some("scm-demo.example.net, .apps.example.com"),
            ".unlaxer.org",
            "https://auth.example.net",
        );
        assert!(p.allows("https://scm-demo.example.net/"));
        assert!(!p.allows("https://x.scm-demo.example.net/"), "exact entry");
        assert!(p.allows("https://apps.example.com/"));
        assert!(p.allows("https://a.apps.example.com/"));
        assert!(
            p.allows("https://auth.example.net/"),
            "BASE_URL host is implicit"
        );
        assert!(
            !p.allows("https://console.unlaxer.org/"),
            "cookie domain ignored"
        );
    }

    #[test]
    fn wildcard_entry_includes_subdomains() {
        let p = ReturnToPolicy::from_settings(Some("*.example.com"), "", "https://auth.x.org");
        assert!(p.allows("https://a.example.com/"));
        assert!(p.allows("https://example.com/"));
        assert!(!p.allows("https://badexample.com/"));
    }

    #[test]
    fn without_cookie_domain_only_the_base_url_host_is_allowed() {
        let p = ReturnToPolicy::from_settings(None, "", "https://auth.example.com");
        assert!(p.allows("https://auth.example.com/x"));
        assert!(!p.allows("https://app.example.com/"));
        assert!(!p.allows("https://example.com/"));
    }

    #[test]
    fn blank_explicit_list_counts_as_unset() {
        let p =
            ReturnToPolicy::from_settings(Some("  "), ".unlaxer.org", "https://auth.unlaxer.org");
        assert!(p.allows("https://console.unlaxer.org/"));
    }

    #[test]
    fn http_is_accepted_only_for_an_http_base_url() {
        let local = ReturnToPolicy::from_settings(None, "", "http://localhost:18080");
        assert!(local.allows_scheme("http"));
        assert!(local.allows("http://localhost:18080/whoami"));
        assert!(local.allows("http://localhost/"));
        assert!(!local.allows("http://evil.com/"));

        let https = ReturnToPolicy::from_settings(None, "", "https://localhost");
        assert!(!https.allows("http://localhost/"));
    }

    #[test]
    fn host_comparison_is_case_insensitive() {
        let p = production();
        assert!(p.allows("https://CONSOLE.Unlaxer.ORG/"));
    }
}
