//! Symmetric encryption for at-rest secrets (PKCE verifiers, IdP client
//! secrets, signing key material, etc.).
//!
//! Counterpart of Java `KeyCipher.java`. Key properties:
//!
//! - **Key derivation**: PBKDF2-HMAC-SHA256, 100 000 iterations, 32-byte
//!   output. The master input (`KEY_CIPHER_MASTER_KEY` env or constructor
//!   argument) is stretched with a fixed application salt so that two
//!   deployments with the same master produce the same key (deterministic
//!   for DB portability). This matches Java's fix for #15 (raw SHA-256 →
//!   KDF).
//! - **Cipher**: AES-256-GCM. Per-message random 12-byte nonce is prepended
//!   to the ciphertext, then the whole blob is base64-encoded for storage
//!   in TEXT columns.
//! - **No silent plaintext fallback**: `decrypt()` returns an error on any
//!   format / tag mismatch (#16). Callers must treat decryption failure as
//!   "credential corrupt" and re-provision — never fall back to the raw
//!   bytes.
//!
//! Storage format of an encrypted payload:
//!
//! ```text
//! base64( nonce[12] || ciphertext || tag[16] )
//! ```
//!
//! aes-gcm produces `ciphertext || tag` together, so we only split the
//! 12-byte nonce ourselves.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use base64::Engine;
use pbkdf2::pbkdf2_hmac;
use rand::RngCore;
use sha2::Sha256;

/// Fixed application salt. Changing this invalidates all existing ciphertexts.
const SALT: &[u8] = b"volta-auth-kdf-v1";
const PBKDF2_ITERS: u32 = 100_000;
const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;

#[derive(Debug)]
pub enum CipherError {
    /// Ciphertext is too short / has bad format.
    MalformedInput,
    /// base64 decode failed.
    InvalidBase64,
    /// AES-GCM rejected the ciphertext (tag mismatch or wrong key).
    Authentication,
}

impl std::fmt::Display for CipherError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MalformedInput => write!(f, "malformed ciphertext"),
            Self::InvalidBase64 => write!(f, "invalid base64"),
            Self::Authentication => write!(f, "authentication failed"),
        }
    }
}

impl std::error::Error for CipherError {}

#[derive(Clone)]
pub struct KeyCipher {
    cipher: Aes256Gcm,
}

impl KeyCipher {
    /// Derive the encryption key from a master secret via PBKDF2.
    pub fn from_master(master: &[u8]) -> Self {
        let mut key_bytes = [0u8; KEY_LEN];
        pbkdf2_hmac::<Sha256>(master, SALT, PBKDF2_ITERS, &mut key_bytes);
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));
        Self { cipher }
    }

    /// Read the master secret from `KEY_CIPHER_MASTER_KEY` env var, falling
    /// back to `JWT_SECRET` when unset. Panics when neither is present — we
    /// do not want to boot with a silently-random key because that would
    /// invalidate existing ciphertexts on every restart.
    pub fn from_env() -> Self {
        let master = std::env::var("KEY_CIPHER_MASTER_KEY")
            .or_else(|_| std::env::var("JWT_SECRET"))
            .expect("KEY_CIPHER_MASTER_KEY (or JWT_SECRET) must be set");
        Self::from_master(master.as_bytes())
    }

    /// Encrypt `plaintext` and return a base64-encoded storage string.
    pub fn encrypt(&self, plaintext: &[u8]) -> String {
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = self
            .cipher
            .encrypt(nonce, plaintext)
            .expect("aes-gcm encrypt should never fail");
        let mut blob = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        blob.extend_from_slice(&nonce_bytes);
        blob.extend_from_slice(&ciphertext);
        base64::engine::general_purpose::STANDARD.encode(&blob)
    }

    /// Decrypt a storage string produced by [`KeyCipher::encrypt`].
    ///
    /// Returns a [`CipherError`] on any problem — **never** falls back to the
    /// raw input bytes (fix #16).
    pub fn decrypt(&self, stored: &str) -> Result<Vec<u8>, CipherError> {
        let blob = base64::engine::general_purpose::STANDARD
            .decode(stored)
            .map_err(|_| CipherError::InvalidBase64)?;
        if blob.len() <= NONCE_LEN {
            return Err(CipherError::MalformedInput);
        }
        let (nonce_bytes, ciphertext) = blob.split_at(NONCE_LEN);
        let nonce = Nonce::from_slice(nonce_bytes);
        self.cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| CipherError::Authentication)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> KeyCipher {
        KeyCipher::from_master(b"test-master")
    }

    #[test]
    fn roundtrip_utf8() {
        let c = fixture();
        let ct = c.encrypt(b"hello world");
        assert_eq!(c.decrypt(&ct).unwrap(), b"hello world");
    }

    #[test]
    fn roundtrip_binary() {
        let c = fixture();
        let plaintext = vec![0u8, 1, 2, 3, 255, 254];
        let ct = c.encrypt(&plaintext);
        assert_eq!(c.decrypt(&ct).unwrap(), plaintext);
    }

    #[test]
    fn each_encrypt_uses_fresh_nonce() {
        let c = fixture();
        let a = c.encrypt(b"same plaintext");
        let b = c.encrypt(b"same plaintext");
        assert_ne!(a, b, "nonces must be random");
    }

    #[test]
    fn different_master_keys_produce_different_ciphers() {
        let a = KeyCipher::from_master(b"master-a");
        let b = KeyCipher::from_master(b"master-b");
        let ct = a.encrypt(b"shared plaintext");
        assert!(b.decrypt(&ct).is_err(), "wrong key must not decrypt");
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let c = fixture();
        let ct = c.encrypt(b"payload");
        // Flip a bit in the middle of the blob.
        let mut blob = base64::engine::general_purpose::STANDARD.decode(&ct).unwrap();
        let mid = blob.len() / 2;
        blob[mid] ^= 0x01;
        let tampered = base64::engine::general_purpose::STANDARD.encode(&blob);
        assert!(matches!(c.decrypt(&tampered), Err(CipherError::Authentication)));
    }

    #[test]
    fn invalid_base64_is_error() {
        let c = fixture();
        assert!(matches!(c.decrypt("not-base64!!!"), Err(CipherError::InvalidBase64)));
    }

    #[test]
    fn too_short_ciphertext_is_error() {
        let c = fixture();
        // Base64 of 8 zero bytes — shorter than the 12-byte nonce.
        let short = base64::engine::general_purpose::STANDARD.encode([0u8; 8]);
        assert!(matches!(c.decrypt(&short), Err(CipherError::MalformedInput)));
    }

    #[test]
    fn same_master_produces_identical_key_across_constructs() {
        // Deterministic key material lets a restarted server decrypt rows
        // written by the previous process.
        let a = KeyCipher::from_master(b"stable-master");
        let b = KeyCipher::from_master(b"stable-master");
        let ct = a.encrypt(b"portable");
        assert_eq!(b.decrypt(&ct).unwrap(), b"portable");
    }
}
