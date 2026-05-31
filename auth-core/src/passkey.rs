//! Passkey/WebAuthn service — wraps webauthn-rs for challenge generation and assertion verification.
//! Requires the `webauthn` feature.

#![cfg(feature = "webauthn")]

use url::Url;
use webauthn_rs::prelude::*;
use webauthn_rs::Webauthn;

use crate::error::AuthError;

/// Passkey service — manages WebAuthn ceremony lifecycle.
pub struct PasskeyService {
    webauthn: Webauthn,
}

impl PasskeyService {
    /// Create a new passkey service for the given Relying Party.
    ///
    /// - `rp_id`: The RP identifier (typically the domain, e.g. "example.com")
    /// - `rp_origin`: The RP origin URL (e.g. "https://example.com")
    pub fn new(rp_id: &str, rp_origin: &Url) -> Result<Self, AuthError> {
        let builder = WebauthnBuilder::new(rp_id, rp_origin)
            .map_err(|e| AuthError::Internal(format!("webauthn builder: {}", e)))?;
        let webauthn = builder.build()
            .map_err(|e| AuthError::Internal(format!("webauthn build: {}", e)))?;
        Ok(Self { webauthn })
    }

    /// Start passkey authentication: generate a challenge for the client.
    ///
    /// Returns `(challenge_response, server_state)`:
    /// - `challenge_response` is sent to the client (JSON)
    /// - `server_state` must be kept server-side until `finish_authentication`
    pub fn start_authentication(
        &self,
        credentials: &[Passkey],
    ) -> Result<(RequestChallengeResponse, PasskeyAuthentication), AuthError> {
        self.webauthn
            .start_passkey_authentication(credentials)
            .map_err(|e| AuthError::Internal(format!("passkey auth start: {}", e)))
    }

    /// Finish passkey authentication: verify the client's assertion response.
    ///
    /// Returns the `AuthenticationResult` with updated credential counter.
    pub fn finish_authentication(
        &self,
        response: &PublicKeyCredential,
        state: &PasskeyAuthentication,
    ) -> Result<AuthenticationResult, AuthError> {
        self.webauthn
            .finish_passkey_authentication(response, state)
            .map_err(|e| AuthError::Internal(format!("passkey auth finish: {}", e)))
    }

    /// Start passkey registration: generate a challenge for credential creation.
    pub fn start_registration(
        &self,
        user_unique_id: Uuid,
        user_name: &str,
        user_display_name: &str,
        existing_credentials: Option<Vec<CredentialID>>,
    ) -> Result<(CreationChallengeResponse, PasskeyRegistration), AuthError> {
        self.webauthn
            .start_passkey_registration(
                user_unique_id,
                user_name,
                user_display_name,
                existing_credentials,
            )
            .map_err(|e| AuthError::Internal(format!("passkey reg start: {}", e)))
    }

    /// Finish passkey registration: verify the client's attestation response.
    pub fn finish_registration(
        &self,
        response: &RegisterPublicKeyCredential,
        state: &PasskeyRegistration,
    ) -> Result<Passkey, AuthError> {
        self.webauthn
            .finish_passkey_registration(response, state)
            .map_err(|e| AuthError::Internal(format!("passkey reg finish: {}", e)))
    }

    /// Start discoverable-credential (username-less) authentication.
    ///
    /// Issues a challenge with an empty `allowCredentials` list and
    /// `userVerification=required`. The authenticator will present credentials
    /// it already holds for this RP and the user picks one.
    ///
    /// Returns `(challenge_response, server_state)`:
    /// - `challenge_response` is sent to the client (JSON)
    /// - `server_state` must be kept server-side until `finish_discoverable_authentication`
    pub fn start_discoverable_authentication(
        &self,
    ) -> Result<(RequestChallengeResponse, DiscoverableAuthentication), AuthError> {
        self.webauthn
            .start_discoverable_authentication()
            .map_err(|e| AuthError::Internal(format!("discoverable auth start: {}", e)))
    }

    /// Pre-process the client's response to extract the user UUID and credential ID.
    ///
    /// Call this before `finish_discoverable_authentication` to identify *which*
    /// user is authenticating (by `user_unique_id`) and load their credentials.
    pub fn identify_discoverable_authentication<'a>(
        &self,
        credential: &'a PublicKeyCredential,
    ) -> Result<(Uuid, &'a [u8]), AuthError> {
        self.webauthn
            .identify_discoverable_authentication(credential)
            .map_err(|e| AuthError::Internal(format!("discoverable auth identify: {}", e)))
    }

    /// Finish discoverable-credential authentication: verify the assertion.
    ///
    /// `creds` must be the passkeys belonging to the user identified via
    /// `identify_discoverable_authentication`.
    ///
    /// Returns the `AuthenticationResult` with updated credential counter.
    pub fn finish_discoverable_authentication(
        &self,
        credential: &PublicKeyCredential,
        state: DiscoverableAuthentication,
        creds: &[DiscoverableKey],
    ) -> Result<AuthenticationResult, AuthError> {
        self.webauthn
            .finish_discoverable_authentication(credential, state, creds)
            .map_err(|e| AuthError::Internal(format!("discoverable auth finish: {}", e)))
    }
}
