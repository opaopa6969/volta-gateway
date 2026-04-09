//! TOTP verification for MFA.
//! 1:1 from Java MfaVerifyProcessor.

/// Verify a TOTP code against a shared secret.
pub fn verify_totp(secret: &[u8], code: &str, time_step: u64) -> bool {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Check current and ±1 time windows for clock skew
    for offset in [-1i64, 0, 1] {
        let time = ((now as i64 / time_step as i64) + offset) as u64;
        let expected = totp_lite::totp_custom::<totp_lite::Sha1>(time_step, 6, secret, time);
        if expected == code {
            return true;
        }
    }
    false
}

/// Generate a TOTP secret (base32 encoded).
pub fn generate_secret() -> String {
    use ring::rand::SecureRandom;
    let rng = ring::rand::SystemRandom::new();
    let mut bytes = [0u8; 20];
    rng.fill(&mut bytes).unwrap();
    base32_encode(&bytes)
}

fn base32_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut result = String::new();
    let mut bits = 0u32;
    let mut bit_count = 0;
    for &byte in data {
        bits = (bits << 8) | byte as u32;
        bit_count += 8;
        while bit_count >= 5 {
            bit_count -= 5;
            result.push(ALPHABET[((bits >> bit_count) & 0x1F) as usize] as char);
        }
    }
    if bit_count > 0 {
        result.push(ALPHABET[((bits << (5 - bit_count)) & 0x1F) as usize] as char);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_secret_is_base32() {
        let secret = generate_secret();
        assert!(secret.len() >= 16);
        assert!(secret.chars().all(|c| c.is_ascii_uppercase() || ('2'..='7').contains(&c)));
    }

    #[test]
    fn totp_verify_current_code() {
        let secret = b"12345678901234567890"; // standard test vector
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let time = now / 30;
        let code = totp_lite::totp_custom::<totp_lite::Sha1>(30, 6, secret, time);
        assert!(verify_totp(secret, &code, 30));
    }

    #[test]
    fn totp_reject_wrong_code() {
        let secret = b"12345678901234567890";
        assert!(!verify_totp(secret, "000000", 30));
    }
}
