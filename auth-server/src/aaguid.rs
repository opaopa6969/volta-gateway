//! AAGUID → authenticator model names (Phase 4b, docs/auth-methods-landscape.md §5).
//!
//! A passkey's AAGUID identifies the authenticator model. Showing "iCloud
//! Keychain" or "YubiKey 5 NFC" next to a credential (instead of an opaque UUID)
//! is a big passkey-UX win. This is a curated subset of the FIDO Metadata
//! Service (MDS) — the well-known platform & roaming authenticators. Unknown
//! AAGUIDs fall back to a generic label.

/// Friendly model name for a known AAGUID (lowercase hyphenated UUID string), or
/// `None` if unknown.
pub fn authenticator_name(aaguid: &str) -> Option<&'static str> {
    let name = match aaguid {
        // ── Platform / synced passkey providers ──
        "ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4" => "Google パスワード マネージャー",
        "adce0002-35bc-c60a-648b-0b25f1f05503" => "Chrome (macOS)",
        "fbfc3007-154e-4ecc-8c0b-6e020557d7bd" => "iCloud キーチェーン (Apple)",
        "dd4ec289-e01d-41c9-bb89-70fa845d4bf2" => "iCloud キーチェーン (管理対象)",
        "08987058-cadc-4b81-b6e1-30de50dcbe96" => "Windows Hello (ハードウェア)",
        "9ddd1817-af5a-4672-a2b9-3e3dd95000a9" => "Windows Hello (ソフトウェア)",
        "6028b017-b1d4-4c02-b4b3-afcdafc96bb2" => "Windows Hello",
        // ── Password managers ──
        "bada5566-a7aa-401f-bd96-45619a55120d" => "1Password",
        "b84e4048-15dc-4dd0-8640-f4f60813c8af" => "NordPass",
        "0ea242b4-43c4-4a1b-8b17-dd6d0b6baec6" => "Keeper",
        "531126d6-e717-415c-9320-3d9aa6981239" => "Dashlane",
        "d548826e-79b4-db40-a3d8-11116f7e8349" => "Bitwarden",
        "f3809540-7f14-49c1-a8b3-8f813b225541" => "Enpass",
        "891494da-2c90-4d31-a9cd-4eab0aed1309" => "Proton Pass",
        // ── YubiKey (Yubico) ──
        "ee882879-721c-4913-9775-3dfcce97072a" => "YubiKey 5 シリーズ",
        "fa2b99dc-9e39-4257-8f92-4a30d23c4118" => "YubiKey 5 NFC",
        "2fc0579f-8113-47ea-b116-bb5a8db9202a" => "YubiKey 5 NFC",
        "cb69481e-8ff7-4039-93ec-0a2729a154a8" => "YubiKey 5 シリーズ",
        "c5ef55ff-ad9a-4b9f-b580-adebafe026d0" => "YubiKey 5Ci",
        "73bb0cd4-e502-49b8-9c6f-b59445bf720b" => "YubiKey 5 シリーズ (FIPS)",
        "34f5766d-1536-4a24-9033-0e294e510fb0" => "YubiKey 5 シリーズ",
        // ── Other roaming keys ──
        "9c835346-796b-4c27-8898-d6032f515cc5" => "Feitian",
        "692db549-7ae5-44d5-a1a5-d4e3fb0a5e3d" => "SoloKeys",
        "b92c3f9a-c014-4056-887f-140a2501163b" => "SoloKeys",
        _ => return None,
    };
    Some(name)
}

/// Best-effort label: known model name, or a generic fallback (never empty).
pub fn label_for(aaguid: Option<&str>) -> &'static str {
    match aaguid {
        Some(a) if a == "00000000-0000-0000-0000-000000000000" => "セキュリティキー",
        Some(a) => authenticator_name(a).unwrap_or("パスキー認証器"),
        None => "パスキー認証器",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_and_unknown_aaguids() {
        assert_eq!(
            authenticator_name("fbfc3007-154e-4ecc-8c0b-6e020557d7bd"),
            Some("iCloud キーチェーン (Apple)")
        );
        assert!(authenticator_name("11111111-2222-3333-4444-555555555555").is_none());
    }

    #[test]
    fn label_never_empty() {
        assert_eq!(
            label_for(Some("ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4")),
            "Google パスワード マネージャー"
        );
        assert_eq!(
            label_for(Some("00000000-0000-0000-0000-000000000000")),
            "セキュリティキー"
        );
        assert_eq!(label_for(None), "パスキー認証器");
        assert_eq!(
            label_for(Some("deadbeef-0000-0000-0000-000000000000")),
            "パスキー認証器"
        );
    }
}
