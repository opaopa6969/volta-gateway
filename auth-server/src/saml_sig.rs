//! Structural defences against SAML signature-wrapping attacks.
//!
//! Backlog P0 #2 — first slice. This module implements the non-cryptographic
//! checks documented in
//! `auth-server/docs/specs/saml-signature-verification.md`:
//!
//! - exactly one `<Signature>` element (reject multiple — wrapping attack)
//! - no external `Reference URI="..."` (only local `#id` allowed)
//! - signature algorithm is on an allow-list (`rsa-sha256`, `rsa-sha1`)
//!
//! **Cryptographic** verification (C14N + digest + RSA verify against the
//! IdP cert) is still pending. The current code path therefore detects the
//! obvious forgery patterns but cannot prove the signature is valid — an
//! attacker with a legitimately-signed assertion from the correct IdP can
//! still replay it. That specific replay is mitigated by:
//!
//! - `InResponseTo` check in `saml::parse_identity` (one-shot per request id)
//! - `NotOnOrAfter` check (short freshness window)
//!
//! Full crypto verification is the outstanding P0 work — see the spec.

const ALLOWED_SIG_ALGS: &[&str] = &[
    // RSA-SHA256 — current best practice.
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
    // RSA-SHA1 — transitional; many IdPs still default here.
    "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
];

#[derive(Debug, PartialEq)]
pub enum SigStructureError {
    MultipleSignatures,
    ExternalReference,
    UnsupportedAlgorithm(String),
    SignatureMissing,
}

impl std::fmt::Display for SigStructureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MultipleSignatures => {
                write!(f, "multiple <Signature> elements — possible wrapping attack")
            }
            Self::ExternalReference => {
                write!(f, "external reference URI rejected (local #id only)")
            }
            Self::UnsupportedAlgorithm(a) => {
                write!(f, "signature algorithm not allow-listed: {}", a)
            }
            Self::SignatureMissing => write!(f, "no <Signature> element"),
        }
    }
}

impl std::error::Error for SigStructureError {}

/// Run the structural checks. Returns `Ok(())` when the XML's signature
/// layout is acceptable; callers still need cryptographic verification.
pub fn check_structure(xml: &str) -> Result<(), SigStructureError> {
    let sig_count = count_signatures(xml);
    match sig_count {
        0 => return Err(SigStructureError::SignatureMissing),
        1 => {}
        _ => return Err(SigStructureError::MultipleSignatures),
    }
    if has_external_reference(xml) {
        return Err(SigStructureError::ExternalReference);
    }
    if let Some(alg) = extract_sig_algorithm(xml) {
        if !ALLOWED_SIG_ALGS.iter().any(|a| *a == alg.as_str()) {
            return Err(SigStructureError::UnsupportedAlgorithm(alg));
        }
    }
    Ok(())
}

/// Count `<Signature` tag opens across common namespace prefixes. String
/// search rather than XML parsing; cheap and sufficient for structural
/// defence — a cryptographic parser runs later (when implemented).
fn count_signatures(xml: &str) -> usize {
    let mut n = 0;
    for prefix in ["<Signature", "<ds:Signature", "<dsig:Signature"] {
        let mut rest = xml;
        while let Some(pos) = rest.find(prefix) {
            let after = rest.as_bytes().get(pos + prefix.len()).copied();
            // Match only when the next char terminates the element name
            // (prevents <SignatureMethod> / <SignedInfo> false positives).
            if matches!(after, Some(b'>') | Some(b' ') | Some(b'\t') | Some(b'\r') | Some(b'\n')) {
                n += 1;
            }
            rest = &rest[pos + prefix.len()..];
        }
    }
    n
}

/// `Reference URI=""` (empty — self-ref) and `URI="#id"` are acceptable.
/// Any other non-empty URI is treated as external.
fn has_external_reference(xml: &str) -> bool {
    let needle = "Reference ";
    let mut rest = xml;
    while let Some(pos) = rest.find(needle) {
        rest = &rest[pos + needle.len()..];
        // Find URI=" attribute inside this tag (up to the next '>').
        let tag_end = rest.find('>').unwrap_or(rest.len());
        let tag = &rest[..tag_end];
        if let Some(uri_pos) = tag.find("URI=\"") {
            let after = &tag[uri_pos + 5..];
            let close = after.find('"').unwrap_or(after.len());
            let value = &after[..close];
            if !value.is_empty() && !value.starts_with('#') {
                return true;
            }
        }
        rest = &rest[tag_end..];
    }
    false
}

fn extract_sig_algorithm(xml: &str) -> Option<String> {
    let needle = "SignatureMethod ";
    let tag_start = xml.find(needle)?;
    let rest = &xml[tag_start..];
    let tag_end = rest.find('>')?;
    let tag = &rest[..tag_end];
    let alg_pos = tag.find("Algorithm=\"")?;
    let after = &tag[alg_pos + 11..];
    let close = after.find('"')?;
    Some(after[..close].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_signature_passes() {
        let xml = r##"<Response><Signature><SignedInfo>
            <Reference URI="#id1"/>
            <SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
        </SignedInfo></Signature></Response>"##;
        check_structure(xml).unwrap();
    }

    #[test]
    fn no_signature_rejected() {
        let xml = "<Response></Response>";
        assert_eq!(check_structure(xml), Err(SigStructureError::SignatureMissing));
    }

    #[test]
    fn two_signatures_rejected() {
        let xml = r##"<Response>
            <Signature><SignedInfo><Reference URI="#a"/>
                <SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
            </SignedInfo></Signature>
            <Assertion>
                <Signature><SignedInfo><Reference URI="#b"/>
                    <SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
                </SignedInfo></Signature>
            </Assertion>
        </Response>"##;
        assert_eq!(check_structure(xml), Err(SigStructureError::MultipleSignatures));
    }

    #[test]
    fn external_reference_rejected() {
        let xml = r##"<Response><Signature><SignedInfo>
            <Reference URI="http://evil/attack"/>
            <SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
        </SignedInfo></Signature></Response>"##;
        assert_eq!(check_structure(xml), Err(SigStructureError::ExternalReference));
    }

    #[test]
    fn empty_reference_uri_is_ok() {
        // Empty URI == same-document reference, allowed.
        let xml = r##"<Response><Signature><SignedInfo>
            <Reference URI=""/>
            <SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
        </SignedInfo></Signature></Response>"##;
        check_structure(xml).unwrap();
    }

    #[test]
    fn unsupported_algorithm_rejected() {
        let xml = r##"<Response><Signature><SignedInfo>
            <Reference URI="#id1"/>
            <SignatureMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#WithComments"/>
        </SignedInfo></Signature></Response>"##;
        assert!(matches!(
            check_structure(xml),
            Err(SigStructureError::UnsupportedAlgorithm(_))
        ));
    }

    #[test]
    fn sha1_is_accepted_transitional() {
        let xml = r##"<Response><Signature><SignedInfo>
            <Reference URI="#id1"/>
            <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
        </SignedInfo></Signature></Response>"##;
        check_structure(xml).unwrap();
    }

    #[test]
    fn namespaced_signature_tag_counted() {
        let xml = r##"<Response><ds:Signature><SignedInfo>
            <Reference URI="#id1"/>
            <SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
        </SignedInfo></ds:Signature></Response>"##;
        check_structure(xml).unwrap();
    }
}
