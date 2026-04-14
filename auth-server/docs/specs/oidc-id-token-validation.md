# Spec: OIDC ID token validation (backlog P1 #4)

## Goal

After `exchange_code_pkce`, verify the `id_token` in the `TokenResponse`
before trusting the `userinfo` call. Covers Java issue #2 (nonce null
check) and the general OIDC Core §3.1.3.7 validation rules.

## Checks

| Check | Source |
|---|---|
| JWS signature valid | JWKS of the issuer (RS256 / ES256) |
| `iss` matches configured issuer | static config |
| `aud` contains `client_id` | static config |
| `exp` in the future (with 60 s skew) | clock |
| `iat` in the past (with 60 s skew) | clock |
| `nonce` equals the value stored in `oidc_flows.nonce` | flow |
| `at_hash` (when present) matches `SHA-256(access_token)` left half | token |

All checks are required for OIDC providers that declare RS256/ES256.
For providers that don't return `id_token` (GitHub, plain OAuth2),
validation is skipped and we fall through to the `userinfo` path (same
as today).

## API surface

New module: `auth-core/src/oidc.rs`.

```rust
pub struct IdTokenVerifier { /* JWKS cache + config */ }

impl IdTokenVerifier {
    pub fn new(issuer: String, client_id: String) -> Self;
    pub async fn verify(
        &self,
        id_token: &str,
        expected_nonce: &str,
        access_token: &str,
    ) -> Result<IdTokenClaims, VerifyError>;
}

pub struct IdTokenClaims {
    pub sub: String,
    pub email: Option<String>,
    pub email_verified: Option<bool>,
    pub name: Option<String>,
    pub iss: String,
    pub aud: Vec<String>,
    pub exp: u64,
    pub iat: u64,
}

pub enum VerifyError {
    MissingIdToken, BadFormat, SignatureInvalid,
    IssuerMismatch, AudienceMismatch, Expired, IssuedInFuture,
    NonceMismatch, AtHashMismatch, JwksFetchFailed(String),
}
```

JWKS fetch: lazy, cached in memory with a 5 min TTL. No cross-deploy
cache invalidation — key rotation is handled by the IdP honoring the
rotation window (keys overlap for the TTL).

## Integration

`handlers/oidc.rs::complete_oidc`:

```text
let tok = idp.exchange_code_pkce(...)?;
if let Some(id_token) = tok.id_token.as_deref() {
    let claims = id_verifier.verify(id_token, &flow.nonce, &tok.access_token).await?;
    // use claims.sub / claims.email etc. when present
}
// existing userinfo fallback for providers without id_token
```

## Provider handling

- **Google / Microsoft / Apple**: `id_token` present, JWKS at standard
  URL, verify.
- **GitHub**: no `id_token` in token response → skip verification (same
  as today). GitHub's security model relies on the access token alone.
- **Custom OIDC**: `issuer_url` in config drives the JWKS fetch; if
  absent, verification is skipped (caller opt-out).

## Security properties

- An `id_token` signed by the wrong issuer (stolen from another tenant)
  fails `iss` check.
- `nonce` check means a replayed `id_token` from a different flow is
  rejected — key defence alongside PKCE.
- `at_hash` check means a swapped `access_token` (attacker's vs user's)
  is detected.

## Success criteria

Unit tests:
- Valid id_token roundtrips.
- Signature tampered → `SignatureInvalid`.
- `iss` mismatch → `IssuerMismatch`.
- `aud` mismatch → `AudienceMismatch`.
- `nonce` mismatch → `NonceMismatch`.
- Expired → `Expired`.
- `at_hash` mismatch → `AtHashMismatch`.
