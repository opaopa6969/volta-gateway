//! Pure-Rust SAML XML-DSig cryptographic verification (backlog P0 #2 full).
//!
//! Verifies the RSA signature on the IdP-signed `<Assertion>` element using:
//!
//!   - byte-accurate extraction of `<SignedInfo>` and the referenced
//!     `<Assertion>` (via `quick-xml` to locate exact byte spans);
//!   - enveloped-signature transform (remove the `<Signature>` subtree);
//!   - SHA-256 digest compare against the `<DigestValue>`;
//!   - RSA-PKCS1v15 signature verify of `SignedInfo` bytes with the IdP's
//!     X.509 RSA public key (from PEM).
//!
//! ## Canonicalisation compromise
//!
//! We do **not** implement full exclusive-c14n. Instead we assume the IdP
//! emits XML in canonical form — true for Keycloak, ADFS, Shibboleth in
//! default configuration. Non-canonical inputs fail with a clear error
//! (`DigestMismatch`) so operators can open a fixture and look at the
//! actual bytes. Full exc-c14n is tracked as a follow-up when a tenant
//! running an exotic IdP needs it.
//!
//! The security guarantee is still strong: any tampering with the
//! assertion bytes (even within what would be c14n-equivalent whitespace)
//! changes the digest and fails verification. The risk is **false
//! negatives** (valid but non-canonical responses rejected), not false
//! positives.

use base64::Engine;
use quick_xml::events::Event;
use quick_xml::Reader;
use rsa::pkcs1v15::VerifyingKey;
use rsa::signature::Verifier;
use rsa::{pkcs1v15::Signature, RsaPublicKey};
use sha2::{Digest, Sha256};
use x509_cert::{der::Decode, Certificate};

const ALG_RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const ALG_SHA256: &str = "http://www.w3.org/2001/04/xmlenc#sha256";

#[derive(Debug, PartialEq)]
pub enum DsigError {
    MissingSignature,
    MissingSignedInfo,
    MissingSignatureValue,
    MissingReference,
    MissingDigestValue,
    MissingDigestMethod,
    UnsupportedSignatureAlgorithm(String),
    UnsupportedDigestAlgorithm(String),
    ReferencedElementNotFound(String),
    DigestMismatch,
    SignatureInvalid(String),
    CertificateInvalid(String),
    Base64(String),
    XmlParse(String),
}

impl std::fmt::Display for DsigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingSignature => write!(f, "no <Signature> element"),
            Self::MissingSignedInfo => write!(f, "missing <SignedInfo>"),
            Self::MissingSignatureValue => write!(f, "missing <SignatureValue>"),
            Self::MissingReference => write!(f, "missing <Reference>"),
            Self::MissingDigestValue => write!(f, "missing <DigestValue>"),
            Self::MissingDigestMethod => write!(f, "missing <DigestMethod>"),
            Self::UnsupportedSignatureAlgorithm(a) => write!(f, "unsupported SignatureMethod {}", a),
            Self::UnsupportedDigestAlgorithm(a) => write!(f, "unsupported DigestMethod {}", a),
            Self::ReferencedElementNotFound(id) => write!(f, "Reference URI #{} not found in document", id),
            Self::DigestMismatch => write!(f, "digest mismatch — referenced element has been tampered with"),
            Self::SignatureInvalid(m) => write!(f, "RSA signature verification failed: {}", m),
            Self::CertificateInvalid(m) => write!(f, "invalid X.509 certificate: {}", m),
            Self::Base64(m) => write!(f, "base64 decode failed: {}", m),
            Self::XmlParse(m) => write!(f, "XML parse failed: {}", m),
        }
    }
}

impl std::error::Error for DsigError {}

/// Verify the RSA signature over the SAML Response's signed Assertion.
///
/// `xml`: raw SAML Response XML (after base64 decode).
/// `pem_cert`: IdP X.509 certificate in PEM.
pub fn verify(xml: &str, pem_cert: &str) -> Result<(), DsigError> {
    let xml_bytes = xml.as_bytes();

    // 1. Locate the SignedInfo byte span.
    let signed_info = locate_element(xml_bytes, "SignedInfo")
        .ok_or(DsigError::MissingSignedInfo)?;

    // 2. Reject unsupported signature algorithm.
    let sig_alg = extract_algorithm(xml, "SignatureMethod")
        .ok_or(DsigError::MissingSignedInfo)?;
    if sig_alg != ALG_RSA_SHA256 {
        return Err(DsigError::UnsupportedSignatureAlgorithm(sig_alg));
    }

    // 3. Digest algorithm.
    let digest_alg = extract_algorithm(xml, "DigestMethod")
        .ok_or(DsigError::MissingDigestMethod)?;
    if digest_alg != ALG_SHA256 {
        return Err(DsigError::UnsupportedDigestAlgorithm(digest_alg));
    }

    // 4. Reference URI → referenced element span.
    let ref_uri = extract_reference_uri(xml).ok_or(DsigError::MissingReference)?;
    let ref_id = ref_uri
        .strip_prefix('#')
        .ok_or_else(|| DsigError::ReferencedElementNotFound(ref_uri.clone()))?
        .to_string();

    let referenced_span = locate_element_by_id(xml_bytes, &ref_id)
        .ok_or_else(|| DsigError::ReferencedElementNotFound(ref_id.clone()))?;

    // 5. Apply enveloped-signature transform (remove <Signature>…</Signature>
    // subtree from within the referenced element).
    let referenced_bytes = &xml_bytes[referenced_span.start..referenced_span.end];
    let stripped = strip_signature_subtree(referenced_bytes);

    // 6. Digest check.
    let digest = Sha256::digest(&stripped);
    let digest_b64 = base64::engine::general_purpose::STANDARD.encode(digest);
    let stored_digest = extract_text(xml, "DigestValue").ok_or(DsigError::MissingDigestValue)?;
    if digest_b64.trim() != stored_digest.trim() {
        return Err(DsigError::DigestMismatch);
    }

    // 7. Extract SignatureValue.
    let sig_b64 = extract_text(xml, "SignatureValue").ok_or(DsigError::MissingSignatureValue)?;
    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(sig_b64.split_whitespace().collect::<String>())
        .map_err(|e| DsigError::Base64(e.to_string()))?;

    // 8. RSA-verify SignedInfo (byte-accurate, no c14n reprocessing).
    let signed_info_bytes = &xml_bytes[signed_info.start..signed_info.end];
    let public_key = parse_rsa_from_pem(pem_cert)?;
    let verifying = VerifyingKey::<Sha256>::new(public_key);
    let signature = Signature::try_from(sig_bytes.as_slice())
        .map_err(|e| DsigError::SignatureInvalid(e.to_string()))?;
    verifying
        .verify(signed_info_bytes, &signature)
        .map_err(|e| DsigError::SignatureInvalid(e.to_string()))?;

    Ok(())
}

// ─── byte-span helpers ───────────────────────────────────────

#[derive(Debug, Clone, Copy)]
struct Span {
    start: usize,
    end: usize,
}

/// Locate the first `<LocalName …>…</LocalName>` span (ignoring prefix).
/// Returns byte offsets into `bytes`.
fn locate_element(bytes: &[u8], local_name: &str) -> Option<Span> {
    let mut reader = Reader::from_reader(bytes);
    reader.config_mut().trim_text(false);
    let mut depth = 0;
    let mut start: Option<usize> = None;
    loop {
        let pos_before = reader.buffer_position() as usize;
        let event = reader.read_event();
        let pos_after = reader.buffer_position() as usize;
        match event {
            Ok(Event::Start(e)) => {
                if local_eq(e.name().as_ref(), local_name) && start.is_none() {
                    start = Some(find_tag_open_from(bytes, pos_before));
                    depth = 1;
                } else if start.is_some() && local_eq(e.name().as_ref(), local_name) {
                    depth += 1;
                }
            }
            Ok(Event::End(e)) => {
                if local_eq(e.name().as_ref(), local_name) && start.is_some() {
                    depth -= 1;
                    if depth == 0 {
                        return Some(Span { start: start.unwrap(), end: pos_after });
                    }
                }
            }
            Ok(Event::Eof) => return None,
            Ok(Event::Empty(e)) => {
                if local_eq(e.name().as_ref(), local_name) && start.is_none() {
                    let s = find_tag_open_from(bytes, pos_before);
                    return Some(Span { start: s, end: pos_after });
                }
            }
            Ok(_) => {}
            Err(_) => return None,
        }
    }
}

/// Locate the first element with attribute `ID="<id>"` (SAML convention).
fn locate_element_by_id(bytes: &[u8], id: &str) -> Option<Span> {
    let mut reader = Reader::from_reader(bytes);
    reader.config_mut().trim_text(false);
    let mut depth = 0i32;
    let mut target: Option<(Vec<u8>, usize)> = None;
    loop {
        let pos_before = reader.buffer_position() as usize;
        let event = reader.read_event();
        let pos_after = reader.buffer_position() as usize;
        match event {
            Ok(Event::Start(e)) => {
                let has = attr_matches(&e, "ID", id);
                if has && target.is_none() {
                    let s = find_tag_open_from(bytes, pos_before);
                    target = Some((e.name().as_ref().to_vec(), s));
                    depth = 1;
                } else if let Some((ref name, _)) = target {
                    if e.name().as_ref() == name.as_slice() {
                        depth += 1;
                    }
                }
            }
            Ok(Event::End(e)) => {
                if let Some((ref name, start)) = target {
                    if e.name().as_ref() == name.as_slice() {
                        depth -= 1;
                        if depth == 0 {
                            return Some(Span { start, end: pos_after });
                        }
                    }
                }
            }
            Ok(Event::Empty(e)) => {
                if attr_matches(&e, "ID", id) && target.is_none() {
                    let s = find_tag_open_from(bytes, pos_before);
                    return Some(Span { start: s, end: pos_after });
                }
            }
            Ok(Event::Eof) => return None,
            Ok(_) => {}
            Err(_) => return None,
        }
    }
}

fn attr_matches(e: &quick_xml::events::BytesStart, attr_name: &str, value: &str) -> bool {
    for a in e.attributes().flatten() {
        if a.key.as_ref() == attr_name.as_bytes()
            && a.value.as_ref() == value.as_bytes()
        {
            return true;
        }
    }
    false
}

fn local_eq(qname: &[u8], local: &str) -> bool {
    match qname.iter().rposition(|b| *b == b':') {
        Some(p) => &qname[p + 1..] == local.as_bytes(),
        None => qname == local.as_bytes(),
    }
}

/// Locate the `<` that begins the tag at `pos`.
///
/// `quick_xml::Reader::buffer_position()` returns the position **before**
/// the next read, so when we capture it just before `read_event()` and an
/// `Event::Start` is returned, `bytes[pos]` is already the `<` that opens
/// the tag — we use it directly. Otherwise (e.g. when capture happens
/// after the read for an end-tag scan), we walk back to the nearest `<`.
fn find_tag_open_from(bytes: &[u8], pos: usize) -> usize {
    if pos < bytes.len() && bytes[pos] == b'<' {
        return pos;
    }
    let mut i = pos.saturating_sub(1);
    while i > 0 && bytes[i] != b'<' {
        i -= 1;
    }
    i
}

fn strip_signature_subtree(bytes: &[u8]) -> Vec<u8> {
    // Remove the first `<Signature …>…</Signature>` (or `<ds:Signature>` /
    // `<dsig:Signature>`) subtree from `bytes`.
    let span = match locate_element(bytes, "Signature") {
        Some(s) => s,
        None => return bytes.to_vec(),
    };
    let mut out = Vec::with_capacity(bytes.len());
    out.extend_from_slice(&bytes[..span.start]);
    out.extend_from_slice(&bytes[span.end..]);
    out
}

// ─── text & attribute extraction ─────────────────────────────

fn extract_algorithm(xml: &str, tag: &str) -> Option<String> {
    let open = find_tag_start(xml, tag)?;
    let close = xml[open..].find('>')? + open;
    let attrs = &xml[open..=close];
    let key = "Algorithm=\"";
    let kpos = attrs.find(key)?;
    let after = &attrs[kpos + key.len()..];
    let q = after.find('"')?;
    Some(after[..q].to_string())
}

fn extract_reference_uri(xml: &str) -> Option<String> {
    let open = find_tag_start(xml, "Reference")?;
    let close = xml[open..].find('>')? + open;
    let attrs = &xml[open..=close];
    let key = "URI=\"";
    let kpos = attrs.find(key)?;
    let after = &attrs[kpos + key.len()..];
    let q = after.find('"')?;
    Some(after[..q].to_string())
}

fn extract_text(xml: &str, local_name: &str) -> Option<String> {
    let bytes = xml.as_bytes();
    let span = locate_element(bytes, local_name)?;
    let inner = std::str::from_utf8(&bytes[span.start..span.end]).ok()?;
    // Strip opening / closing tags.
    let gt = inner.find('>')? + 1;
    let lt = inner.rfind('<')?;
    Some(inner[gt..lt].trim().to_string())
}

fn find_tag_start(xml: &str, local_name: &str) -> Option<usize> {
    for needle in [
        format!("<{} ", local_name),
        format!("<{}>", local_name),
        format!(":{} ", local_name),
        format!(":{}>", local_name),
    ] {
        if let Some(pos) = xml.find(&needle) {
            // Walk back to `<`.
            let mut i = pos;
            while i > 0 && xml.as_bytes()[i] != b'<' {
                i -= 1;
            }
            return Some(i);
        }
    }
    None
}

// ─── cert / RSA ──────────────────────────────────────────────

fn parse_rsa_from_pem(pem: &str) -> Result<RsaPublicKey, DsigError> {
    let der = pem_to_der(pem)?;
    let cert = Certificate::from_der(&der)
        .map_err(|e| DsigError::CertificateInvalid(e.to_string()))?;
    let spki = cert.tbs_certificate.subject_public_key_info;
    let der_bytes = spki
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| DsigError::CertificateInvalid("non-byte-aligned SPKI".into()))?;
    use rsa::pkcs1::DecodeRsaPublicKey;
    RsaPublicKey::from_pkcs1_der(der_bytes)
        .map_err(|e| DsigError::CertificateInvalid(format!("RSA SPKI parse: {}", e)))
}

fn pem_to_der(pem: &str) -> Result<Vec<u8>, DsigError> {
    let body: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect();
    base64::engine::general_purpose::STANDARD
        .decode(body.trim())
        .map_err(|e| DsigError::Base64(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_eq_matches_plain_and_prefixed() {
        assert!(local_eq(b"Signature", "Signature"));
        assert!(local_eq(b"ds:Signature", "Signature"));
        assert!(local_eq(b"dsig:Signature", "Signature"));
        assert!(!local_eq(b"SignatureMethod", "Signature"));
    }

    #[test]
    fn locate_simple_element() {
        let xml = b"<root><Foo>hi</Foo></root>";
        let span = locate_element(xml, "Foo").unwrap();
        assert_eq!(&xml[span.start..span.end], b"<Foo>hi</Foo>");
    }

    #[test]
    fn locate_prefixed_element() {
        let xml = b"<root><saml:Assertion>x</saml:Assertion></root>";
        let span = locate_element(xml, "Assertion").unwrap();
        assert!(std::str::from_utf8(&xml[span.start..span.end]).unwrap().contains("Assertion"));
    }

    #[test]
    fn locate_by_id_picks_right_element() {
        let xml = br#"<root><A ID="_1">one</A><A ID="_2">two</A></root>"#;
        let span = locate_element_by_id(xml, "_2").unwrap();
        assert!(std::str::from_utf8(&xml[span.start..span.end]).unwrap().contains("two"));
    }

    #[test]
    fn strip_signature_removes_subtree() {
        let xml = b"<Assertion>before<Signature>SIG</Signature>after</Assertion>";
        let stripped = strip_signature_subtree(xml);
        assert_eq!(std::str::from_utf8(&stripped).unwrap(), "<Assertion>beforeafter</Assertion>");
    }

    #[test]
    fn extract_algorithm_reads_attribute() {
        let xml = r#"<SignatureMethod Algorithm="http://x/rsa-sha256"/>"#;
        assert_eq!(extract_algorithm(xml, "SignatureMethod").as_deref(), Some("http://x/rsa-sha256"));
    }

    #[test]
    fn extract_text_reads_element_content() {
        let xml = "<root><SignatureValue>ABC==</SignatureValue></root>";
        assert_eq!(extract_text(xml, "SignatureValue").as_deref(), Some("ABC=="));
    }

    #[test]
    fn verify_rejects_missing_signature() {
        let xml = "<Assertion>no signature</Assertion>";
        let err = verify(xml, "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n").unwrap_err();
        assert!(matches!(err, DsigError::MissingSignedInfo | DsigError::CertificateInvalid(_) | DsigError::Base64(_)));
    }

    #[test]
    fn verify_rejects_unsupported_sig_algorithm() {
        let xml = r##"<Assertion ID="_1">body
          <Signature>
            <SignedInfo>
              <SignatureMethod Algorithm="http://x/ecdsa-sha256"/>
              <Reference URI="#_1">
                <DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                <DigestValue>X</DigestValue>
              </Reference>
            </SignedInfo>
            <SignatureValue>Y</SignatureValue>
          </Signature>
        </Assertion>"##;
        let err = verify(xml, "").unwrap_err();
        assert!(matches!(err, DsigError::UnsupportedSignatureAlgorithm(_)));
    }

    #[test]
    fn digest_mismatch_detected_after_tamper() {
        // Construct a minimally-valid-looking doc with a digest that doesn't
        // match the referenced element. Signature check is upstream of
        // digest check — we stop here at DigestMismatch.
        let xml = format!(
            r##"<Assertion ID="_a">tampered-content
              <Signature>
                <SignedInfo>
                  <SignatureMethod Algorithm="{alg_sig}"/>
                  <Reference URI="#_a">
                    <DigestMethod Algorithm="{alg_dig}"/>
                    <DigestValue>THIS_IS_NOT_THE_RIGHT_DIGEST</DigestValue>
                  </Reference>
                </SignedInfo>
                <SignatureValue>AAAA</SignatureValue>
              </Signature>
            </Assertion>"##,
            alg_sig = ALG_RSA_SHA256, alg_dig = ALG_SHA256,
        );
        let err = verify(&xml, "").unwrap_err();
        assert!(matches!(err, DsigError::DigestMismatch | DsigError::CertificateInvalid(_)));
    }
}
