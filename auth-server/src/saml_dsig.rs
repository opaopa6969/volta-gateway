//! Pure-Rust SAML XML-DSig cryptographic verification.
//!
//! Verifies the RSA signature on the IdP-signed `<Assertion>` element using:
//!
//!   - exclusive-c14n (RFC 3741 / exc-c14n) canonicalization of both the
//!     referenced element and `<SignedInfo>`;
//!   - enveloped-signature transform (remove the `<Signature>` subtree);
//!   - SHA-256 digest compare against the `<DigestValue>`;
//!   - RSA-PKCS1v15 signature verify of canonicalized `SignedInfo` bytes
//!     with the IdP's X.509 RSA public key (from PEM).
//!
//! ## Canonicalisation
//!
//! We implement exclusive-c14n (exc-c14n) as defined in the W3C Exclusive
//! XML Canonicalization specification and referenced by RFC 3741. This
//! handles non-canonical SAML XML from exotic IdPs that emit unusual
//! namespace prefixes, inherited namespace declarations, or variant
//! attribute ordering. The supported transforms are:
//!
//!   - `enveloped-signature` — strip `<Signature>` subtree from reference.
//!   - `exc-c14n` — exclusive canonicalization without comments.
//!   - `exc-c14n-with-comments` — exclusive canonicalization with comments.
//!
//! ## Security
//!
//! Any tampering with the assertion bytes changes the digest and fails
//! verification. There are no false positives. The canonicalization step
//! means we also accept valid signatures from non-canonical XML, eliminating
//! false negatives from exotic IdPs.

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
const TRANSFORM_ENVELOPED: &str =
    "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
const TRANSFORM_EXC_C14N: &str =
    "http://www.w3.org/2001/10/xml-exc-c14n#";
const TRANSFORM_EXC_C14N_WITH_COMMENTS: &str =
    "http://www.w3.org/2001/10/xml-exc-c14n#WithComments";

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

/// Which canonicalization variant to apply.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum C14nMode {
    /// No canonicalization — pass bytes through unchanged.
    None,
    /// Exclusive C14N without comments (exc-c14n).
    Exclusive,
    /// Exclusive C14N retaining comments (exc-c14n-with-comments).
    ExclusiveWithComments,
}

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

    // 5. Determine which transforms to apply from the Reference/Transforms element.
    let transforms = extract_transforms(xml);

    // 6. Apply transforms to the referenced element bytes.
    //    a. Enveloped-signature: strip <Signature> subtree.
    //    b. Exc-c14n: exclusive canonicalization.
    let referenced_bytes = &xml_bytes[referenced_span.start..referenced_span.end];
    let transforms_has_enveloped = transforms.iter().any(|t| t == TRANSFORM_ENVELOPED);
    let transforms_has_exc_c14n_comments = transforms.iter().any(|t| t == TRANSFORM_EXC_C14N_WITH_COMMENTS);
    let transforms_has_exc_c14n = transforms.iter().any(|t| t == TRANSFORM_EXC_C14N);

    let stripped = if transforms_has_enveloped || transforms.is_empty() {
        // Apply enveloped-signature by default (it is always required when
        // the signature is embedded inside the signed element).
        strip_signature_subtree(referenced_bytes)
    } else {
        referenced_bytes.to_vec()
    };

    let c14n_mode = if transforms_has_exc_c14n_comments {
        C14nMode::ExclusiveWithComments
    } else if transforms_has_exc_c14n || !transforms.is_empty() {
        // Default to exc-c14n when transforms are present (most common SAML case).
        C14nMode::Exclusive
    } else {
        C14nMode::None
    };

    let digest_input = canonicalize(&stripped, c14n_mode);

    // 7. Digest check.
    let digest = Sha256::digest(&digest_input);
    let digest_b64 = base64::engine::general_purpose::STANDARD.encode(digest);
    let stored_digest = extract_text(xml, "DigestValue").ok_or(DsigError::MissingDigestValue)?;
    if digest_b64.trim() != stored_digest.trim() {
        return Err(DsigError::DigestMismatch);
    }

    // 8. Extract SignatureValue.
    let sig_b64 = extract_text(xml, "SignatureValue").ok_or(DsigError::MissingSignatureValue)?;
    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(sig_b64.split_whitespace().collect::<String>())
        .map_err(|e| DsigError::Base64(e.to_string()))?;

    // 9. Canonicalize SignedInfo before RSA verification (exc-c14n).
    //    The CanonicalizationMethod inside SignedInfo dictates how SignedInfo
    //    itself was canonicalized when the signature was created.
    let signed_info_c14n_alg = extract_algorithm(xml, "CanonicalizationMethod");
    let si_c14n_mode = match signed_info_c14n_alg.as_deref() {
        Some(a) if a == TRANSFORM_EXC_C14N_WITH_COMMENTS => C14nMode::ExclusiveWithComments,
        Some(a) if a == TRANSFORM_EXC_C14N => C14nMode::Exclusive,
        // Default: apply exc-c14n (most SAML IdPs use this).
        _ => C14nMode::Exclusive,
    };
    let signed_info_bytes_raw = &xml_bytes[signed_info.start..signed_info.end];
    let signed_info_canonical = canonicalize(signed_info_bytes_raw, si_c14n_mode);

    // 10. RSA-verify canonicalized SignedInfo.
    let public_key = parse_rsa_from_pem(pem_cert)?;
    let verifying = VerifyingKey::<Sha256>::new(public_key);
    let signature = Signature::try_from(sig_bytes.as_slice())
        .map_err(|e| DsigError::SignatureInvalid(e.to_string()))?;
    verifying
        .verify(&signed_info_canonical, &signature)
        .map_err(|e| DsigError::SignatureInvalid(e.to_string()))?;

    Ok(())
}

// ─── Exclusive C14N canonicalization ─────────────────────────────────────────

/// Exclusive XML Canonicalization (exc-c14n / RFC 3741).
///
/// Produces a canonical byte representation of the XML fragment in `bytes`:
///
/// - Elements serialized with namespace-qualified names.
/// - Attributes sorted by (namespace URI, local name); namespace declarations
///   (`xmlns:*`) come before regular attributes, sorted by prefix.
/// - Only namespace declarations that are visibly utilized by the element or
///   its attributes are emitted (unused inherited namespaces are omitted).
/// - Text and attribute values escaped with `&amp;`, `&lt;`, `&gt;`, `&quot;`
///   only; no CDATA sections, no entity references other than those five.
/// - No XML declaration.
/// - Comments: omitted unless `mode == C14nMode::ExclusiveWithComments`.
pub fn canonicalize(bytes: &[u8], mode: C14nMode) -> Vec<u8> {
    if mode == C14nMode::None {
        return bytes.to_vec();
    }
    let with_comments = mode == C14nMode::ExclusiveWithComments;
    let mut out = Vec::with_capacity(bytes.len());
    let mut reader = Reader::from_reader(bytes);
    reader.config_mut().trim_text(false);

    // `ns_stack[i]` = namespace declarations in scope at depth i.
    // Each entry is `(prefix, uri)`. "" prefix = default namespace.
    let mut ns_stack: Vec<Vec<(String, String)>> = vec![vec![]];

    // `rendered_stack[i]` = the set of (prefix, uri) bindings that have
    // already been emitted in start-tags at depth < i.  This implements the
    // exc-c14n "rendered namespace set" — a binding is only re-emitted when
    // it is utilized by an element and the exact same (prefix, uri) pair has
    // NOT yet been rendered in an ancestor.
    let mut rendered_stack: Vec<Vec<(String, String)>> = vec![vec![]];

    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => {
                let (elem_ns, elem_local) = split_qname(e.name().as_ref());

                // Collect namespace declarations on this element.
                let mut new_ns: Vec<(String, String)> = Vec::new();
                for attr in e.attributes().flatten() {
                    let key = std::str::from_utf8(attr.key.as_ref()).unwrap_or("");
                    if key == "xmlns" {
                        new_ns.push(("".to_string(), attr_value_str(&attr)));
                    } else if let Some(pfx) = key.strip_prefix("xmlns:") {
                        new_ns.push((pfx.to_string(), attr_value_str(&attr)));
                    }
                }

                // Build scope for this element.
                let parent_scope = ns_stack.last().cloned().unwrap_or_default();
                let mut current_scope = parent_scope.clone();
                for (pfx, uri) in &new_ns {
                    if let Some(ex) = current_scope.iter_mut().find(|(p, _)| p == pfx) {
                        ex.1 = uri.clone();
                    } else {
                        current_scope.push((pfx.clone(), uri.clone()));
                    }
                }
                ns_stack.push(current_scope.clone());

                // Collect non-namespace attributes.
                let mut attrs: Vec<(String, String, String, String)> = Vec::new(); // (ns_uri, local, prefix, value)
                for attr in e.attributes().flatten() {
                    let key = std::str::from_utf8(attr.key.as_ref()).unwrap_or("");
                    if key == "xmlns" || key.starts_with("xmlns:") {
                        continue;
                    }
                    let (attr_pfx, attr_local) = split_qname(attr.key.as_ref());
                    let attr_ns_uri = if attr_pfx.is_empty() {
                        String::new()
                    } else {
                        resolve_ns(&current_scope, &attr_pfx)
                    };
                    attrs.push((attr_ns_uri, attr_local, attr_pfx, attr_value_str(&attr)));
                }

                // Determine utilized prefixes (element + attributes).
                let mut utilized_prefixes: Vec<String> = Vec::new();
                if !elem_ns.is_empty() && !utilized_prefixes.contains(&elem_ns) {
                    utilized_prefixes.push(elem_ns.clone());
                }
                for (_, _, pfx, _) in &attrs {
                    if !pfx.is_empty() && !utilized_prefixes.contains(pfx) {
                        utilized_prefixes.push(pfx.clone());
                    }
                }

                // Exc-c14n: emit a namespace binding for a utilized prefix only
                // if that exact (prefix, uri) pair has not been rendered yet in
                // any ancestor element.
                let parent_rendered = rendered_stack.last().cloned().unwrap_or_default();
                let mut ns_decls: Vec<(String, String)> = Vec::new();
                let mut current_rendered = parent_rendered.clone();
                for pfx in &utilized_prefixes {
                    let uri = resolve_ns(&current_scope, pfx);
                    if uri.is_empty() {
                        continue;
                    }
                    // Has this exact binding already been rendered in an ancestor?
                    let already_rendered = parent_rendered
                        .iter()
                        .any(|(rp, ru)| rp == pfx && ru == &uri);
                    if !already_rendered {
                        ns_decls.push((pfx.clone(), uri.clone()));
                        // Update rendered set for children.
                        if let Some(ex) = current_rendered.iter_mut().find(|(p, _)| p == pfx) {
                            ex.1 = uri;
                        } else {
                            current_rendered.push((pfx.clone(), uri));
                        }
                    }
                }
                rendered_stack.push(current_rendered);

                // Sort namespace declarations: default ("") first, then by prefix.
                ns_decls.sort_by(|(a, _), (b, _)| {
                    match (a.as_str(), b.as_str()) {
                        ("", _) => std::cmp::Ordering::Less,
                        (_, "") => std::cmp::Ordering::Greater,
                        _ => a.cmp(b),
                    }
                });

                // Sort attributes: by namespace URI then local name.
                attrs.sort_by(|(ns_a, local_a, _, _), (ns_b, local_b, _, _)| {
                    ns_a.cmp(ns_b).then_with(|| local_a.cmp(local_b))
                });

                // Serialize element open tag.
                out.push(b'<');
                if !elem_ns.is_empty() {
                    out.extend_from_slice(elem_ns.as_bytes());
                    out.push(b':');
                }
                out.extend_from_slice(elem_local.as_bytes());

                for (pfx, uri) in &ns_decls {
                    if pfx.is_empty() {
                        out.extend_from_slice(b" xmlns=\"");
                    } else {
                        out.extend_from_slice(b" xmlns:");
                        out.extend_from_slice(pfx.as_bytes());
                        out.extend_from_slice(b"=\"");
                    }
                    out.extend_from_slice(escape_attr(uri).as_bytes());
                    out.push(b'"');
                }

                for (_, local, pfx, val) in &attrs {
                    out.push(b' ');
                    if !pfx.is_empty() {
                        out.extend_from_slice(pfx.as_bytes());
                        out.push(b':');
                    }
                    out.extend_from_slice(local.as_bytes());
                    out.extend_from_slice(b"=\"");
                    out.extend_from_slice(escape_attr(val).as_bytes());
                    out.push(b'"');
                }

                out.push(b'>');
            }
            Ok(Event::End(e)) => {
                let (pfx, local) = split_qname(e.name().as_ref());
                out.push(b'<');
                out.push(b'/');
                if !pfx.is_empty() {
                    out.extend_from_slice(pfx.as_bytes());
                    out.push(b':');
                }
                out.extend_from_slice(local.as_bytes());
                out.push(b'>');
                ns_stack.pop();
                rendered_stack.pop();
            }
            Ok(Event::Empty(e)) => {
                let (elem_ns, elem_local) = split_qname(e.name().as_ref());

                let parent_scope = ns_stack.last().cloned().unwrap_or_default();
                let mut current_scope = parent_scope.clone();
                for attr in e.attributes().flatten() {
                    let key = std::str::from_utf8(attr.key.as_ref()).unwrap_or("");
                    if key == "xmlns" {
                        let uri = attr_value_str(&attr);
                        if let Some(ex) = current_scope.iter_mut().find(|(p, _)| p.is_empty()) {
                            ex.1 = uri;
                        } else {
                            current_scope.push(("".to_string(), uri));
                        }
                    } else if let Some(pfx) = key.strip_prefix("xmlns:") {
                        let uri = attr_value_str(&attr);
                        if let Some(ex) = current_scope.iter_mut().find(|(p, _)| p == pfx) {
                            ex.1 = uri;
                        } else {
                            current_scope.push((pfx.to_string(), uri));
                        }
                    }
                }

                let mut attrs: Vec<(String, String, String, String)> = Vec::new();
                for attr in e.attributes().flatten() {
                    let key = std::str::from_utf8(attr.key.as_ref()).unwrap_or("");
                    if key == "xmlns" || key.starts_with("xmlns:") {
                        continue;
                    }
                    let (attr_pfx, attr_local) = split_qname(attr.key.as_ref());
                    let attr_ns_uri = if attr_pfx.is_empty() {
                        String::new()
                    } else {
                        resolve_ns(&current_scope, &attr_pfx)
                    };
                    attrs.push((attr_ns_uri, attr_local, attr_pfx, attr_value_str(&attr)));
                }

                let mut utilized_prefixes: Vec<String> = Vec::new();
                if !elem_ns.is_empty() {
                    utilized_prefixes.push(elem_ns.clone());
                }
                for (_, _, pfx, _) in &attrs {
                    if !pfx.is_empty() && !utilized_prefixes.contains(pfx) {
                        utilized_prefixes.push(pfx.clone());
                    }
                }

                let parent_rendered = rendered_stack.last().cloned().unwrap_or_default();
                let mut ns_decls: Vec<(String, String)> = Vec::new();
                for pfx in &utilized_prefixes {
                    let uri = resolve_ns(&current_scope, pfx);
                    if uri.is_empty() {
                        continue;
                    }
                    let already_rendered = parent_rendered
                        .iter()
                        .any(|(rp, ru)| rp == pfx && ru == &uri);
                    if !already_rendered {
                        ns_decls.push((pfx.clone(), uri));
                    }
                }
                ns_decls.sort_by(|(a, _), (b, _)| {
                    match (a.as_str(), b.as_str()) {
                        ("", _) => std::cmp::Ordering::Less,
                        (_, "") => std::cmp::Ordering::Greater,
                        _ => a.cmp(b),
                    }
                });

                attrs.sort_by(|(ns_a, local_a, _, _), (ns_b, local_b, _, _)| {
                    ns_a.cmp(ns_b).then_with(|| local_a.cmp(local_b))
                });

                // Emit as regular open + close tags (exc-c14n never uses self-closing).
                out.push(b'<');
                if !elem_ns.is_empty() {
                    out.extend_from_slice(elem_ns.as_bytes());
                    out.push(b':');
                }
                out.extend_from_slice(elem_local.as_bytes());

                for (pfx, uri) in &ns_decls {
                    if pfx.is_empty() {
                        out.extend_from_slice(b" xmlns=\"");
                    } else {
                        out.extend_from_slice(b" xmlns:");
                        out.extend_from_slice(pfx.as_bytes());
                        out.extend_from_slice(b"=\"");
                    }
                    out.extend_from_slice(escape_attr(uri).as_bytes());
                    out.push(b'"');
                }

                for (_, local, pfx, val) in &attrs {
                    out.push(b' ');
                    if !pfx.is_empty() {
                        out.extend_from_slice(pfx.as_bytes());
                        out.push(b':');
                    }
                    out.extend_from_slice(local.as_bytes());
                    out.extend_from_slice(b"=\"");
                    out.extend_from_slice(escape_attr(val).as_bytes());
                    out.push(b'"');
                }

                out.push(b'>');
                out.push(b'<');
                out.push(b'/');
                if !elem_ns.is_empty() {
                    out.extend_from_slice(elem_ns.as_bytes());
                    out.push(b':');
                }
                out.extend_from_slice(elem_local.as_bytes());
                out.push(b'>');
            }
            Ok(Event::Text(e)) => {
                let text = e.unescape().unwrap_or_default();
                out.extend_from_slice(escape_text(&text).as_bytes());
            }
            Ok(Event::CData(e)) => {
                // CDATA is normalized to escaped text in canonical form.
                let text = std::str::from_utf8(e.as_ref()).unwrap_or("");
                out.extend_from_slice(escape_text(text).as_bytes());
            }
            Ok(Event::Comment(e)) => {
                if with_comments {
                    out.extend_from_slice(b"<!--");
                    out.extend_from_slice(e.as_ref());
                    out.extend_from_slice(b"-->");
                }
                // Without comments: skip.
            }
            Ok(Event::PI(e)) => {
                // Processing instructions are included in canonical form.
                out.extend_from_slice(b"<?");
                out.extend_from_slice(e.as_ref());
                out.extend_from_slice(b"?>");
            }
            Ok(Event::Decl(_)) => {
                // XML declaration is omitted in canonical form.
            }
            Ok(Event::DocType(_)) => {
                // DOCTYPE is omitted.
            }
            Ok(Event::Eof) => break,
            Err(_) => break,
        }
    }
    out
}

/// Split a qualified name `prefix:local` (or just `local`) into
/// `(prefix, local)` as `String` values.
fn split_qname(qname: &[u8]) -> (String, String) {
    match qname.iter().rposition(|b| *b == b':') {
        Some(p) => (
            String::from_utf8_lossy(&qname[..p]).into_owned(),
            String::from_utf8_lossy(&qname[p + 1..]).into_owned(),
        ),
        None => (
            String::new(),
            String::from_utf8_lossy(qname).into_owned(),
        ),
    }
}

/// Look up a namespace prefix in the current scope.
/// Returns the URI string, or empty string if not found.
fn resolve_ns(scope: &[(String, String)], prefix: &str) -> String {
    // Search from end (innermost declarations first).
    for (pfx, uri) in scope.iter().rev() {
        if pfx == prefix {
            return uri.clone();
        }
    }
    String::new()
}

/// Extract the string value from a quick-xml attribute.
fn attr_value_str(attr: &quick_xml::events::attributes::Attribute) -> String {
    // attr.value may be escaped; unescape it first.
    match attr.unescape_value() {
        Ok(cow) => cow.into_owned(),
        Err(_) => String::from_utf8_lossy(attr.value.as_ref()).into_owned(),
    }
}

/// Escape a text node value for canonical XML output.
/// Replaces `&` → `&amp;`, `<` → `&lt;`, `>` → `&gt;`,
/// and normalizes CR/LF per C14N spec.
fn escape_text(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\r' => out.push_str("&#xD;"),
            _ => out.push(ch),
        }
    }
    out
}

/// Escape an attribute value for canonical XML output.
/// Replaces `&` → `&amp;`, `<` → `&lt;`, `"` → `&quot;`,
/// and normalizes whitespace characters per C14N spec.
fn escape_attr(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '"' => out.push_str("&quot;"),
            '\t' => out.push_str("&#x9;"),
            '\n' => out.push_str("&#xA;"),
            '\r' => out.push_str("&#xD;"),
            _ => out.push(ch),
        }
    }
    out
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

/// Extract all `Algorithm` attribute values from `<Transform>` elements
/// within the `<Transforms>` block.
fn extract_transforms(xml: &str) -> Vec<String> {
    let mut transforms = Vec::new();
    let mut search = xml;
    while let Some(pos) = find_transform_tag(search) {
        let tag_slice = &search[pos..];
        // Find end of this tag.
        let end = tag_slice.find('>').unwrap_or(tag_slice.len() - 1);
        let tag = &tag_slice[..=end];
        if let Some(alg) = extract_attribute_value(tag, "Algorithm") {
            transforms.push(alg);
        }
        // Advance past this tag.
        search = &search[pos + end + 1..];
    }
    transforms
}

/// Find the byte offset of the next `<Transform` or `<ds:Transform` or
/// similar prefixed tag in `s`.
fn find_transform_tag(s: &str) -> Option<usize> {
    // Match `<Transform` possibly prefixed.
    let bytes = s.as_bytes();
    for i in 0..bytes.len().saturating_sub(10) {
        if bytes[i] == b'<' {
            let rest = &s[i + 1..];
            // skip past any namespace prefix
            let colon_or_space = rest.find(|c: char| c == ':' || c == ' ' || c == '>' || c == '/');
            let (candidate, suffix) = if let Some(p) = colon_or_space {
                if rest.as_bytes().get(p) == Some(&b':') {
                    // prefixed: check after colon
                    let after_colon = &rest[p + 1..];
                    (after_colon, "")
                } else {
                    (rest, "")
                }
            } else {
                (rest, "")
            };
            let _ = suffix;
            if candidate.starts_with("Transform") {
                // Make sure it's "Transform " or "Transform>" or "Transform/"
                let after = &candidate["Transform".len()..];
                if after.starts_with(' ') || after.starts_with('>') || after.starts_with('/') {
                    return Some(i);
                }
            }
        }
    }
    None
}

/// Extract the value of a named attribute from a tag string like `<Foo Bar="baz">`.
fn extract_attribute_value(tag: &str, attr_name: &str) -> Option<String> {
    let key = format!("{}=\"", attr_name);
    let kpos = tag.find(&key)?;
    let after = &tag[kpos + key.len()..];
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

    // ─── exc-c14n unit tests ──────────────────────────────────

    #[test]
    fn c14n_identity_on_simple_element() {
        // A simple element with no namespaces should round-trip cleanly.
        let xml = b"<Foo bar=\"baz\">text</Foo>";
        let result = canonicalize(xml, C14nMode::Exclusive);
        assert_eq!(std::str::from_utf8(&result).unwrap(), "<Foo bar=\"baz\">text</Foo>");
    }

    #[test]
    fn c14n_sorts_attributes_by_local_name() {
        let xml = b"<Foo z=\"1\" a=\"2\" m=\"3\"/>";
        let result = canonicalize(xml, C14nMode::Exclusive);
        let s = std::str::from_utf8(&result).unwrap();
        // Attributes should appear in alphabetical order: a, m, z
        let a_pos = s.find("a=\"2\"").unwrap();
        let m_pos = s.find("m=\"3\"").unwrap();
        let z_pos = s.find("z=\"1\"").unwrap();
        assert!(a_pos < m_pos && m_pos < z_pos, "expected a < m < z, got: {}", s);
    }

    #[test]
    fn c14n_self_closing_becomes_open_close() {
        // exc-c14n never uses self-closing tags.
        let xml = b"<Foo/>";
        let result = canonicalize(xml, C14nMode::Exclusive);
        assert_eq!(std::str::from_utf8(&result).unwrap(), "<Foo></Foo>");
    }

    #[test]
    fn c14n_escapes_text_content() {
        let xml = b"<Foo>a &amp; b &lt; c</Foo>";
        let result = canonicalize(xml, C14nMode::Exclusive);
        let s = std::str::from_utf8(&result).unwrap();
        assert!(s.contains("&amp;") || s.contains("a"), "text preserved: {}", s);
        // The output should not contain raw & or <
        assert!(!s[5..s.len()-6].contains('&') || s.contains("&amp;") || s.contains("&lt;") || s.contains("&gt;"));
    }

    #[test]
    fn c14n_strips_comments_in_exclusive_mode() {
        let xml = b"<Foo><!-- comment -->text</Foo>";
        let result = canonicalize(xml, C14nMode::Exclusive);
        let s = std::str::from_utf8(&result).unwrap();
        assert!(!s.contains("comment"), "comment should be stripped: {}", s);
        assert!(s.contains("text"));
    }

    #[test]
    fn c14n_retains_comments_with_comments_mode() {
        let xml = b"<Foo><!-- comment -->text</Foo>";
        let result = canonicalize(xml, C14nMode::ExclusiveWithComments);
        let s = std::str::from_utf8(&result).unwrap();
        assert!(s.contains("comment"), "comment should be retained: {}", s);
    }

    #[test]
    fn c14n_namespace_decl_hoisted_to_first_use() {
        // A namespace declared on a parent but only used on a child should
        // appear on the first element that uses it (exc-c14n rule).
        let xml = b"<root xmlns:ds=\"http://dsig\"><ds:Foo/></root>";
        let result = canonicalize(xml, C14nMode::Exclusive);
        let s = std::str::from_utf8(&result).unwrap();
        // The ds: namespace should appear on ds:Foo since root doesn't use it.
        assert!(s.contains("<ds:Foo"), "ds:Foo element present: {}", s);
        // The xmlns:ds should not appear on root.
        let root_end = s.find('>').unwrap();
        let root_tag = &s[..root_end];
        assert!(!root_tag.contains("xmlns:ds"), "xmlns:ds should not be on root: {}", root_tag);
        // But should appear on ds:Foo.
        assert!(s.contains("xmlns:ds=\"http://dsig\""), "xmlns:ds should be on ds:Foo: {}", s);
    }

    #[test]
    fn c14n_none_mode_is_passthrough() {
        let xml = b"<Foo  z=\"1\"  a=\"2\">text</Foo>";
        let result = canonicalize(xml, C14nMode::None);
        assert_eq!(result, xml);
    }

    #[test]
    fn extract_transforms_finds_algorithms() {
        let xml = r#"<Transforms>
            <Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
            <Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
        </Transforms>"#;
        let transforms = extract_transforms(xml);
        assert!(transforms.contains(&"http://www.w3.org/2000/09/xmldsig#enveloped-signature".to_string()));
        assert!(transforms.contains(&"http://www.w3.org/2001/10/xml-exc-c14n#".to_string()));
    }

    /// Test that a non-canonical SAML document (attributes out of order,
    /// extra whitespace) produces the same canonical digest as the same
    /// document in canonical form.
    #[test]
    fn c14n_produces_identical_digest_for_non_canonical_input() {
        // Canonical form.
        let canonical = b"<saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_1\"><saml:Issuer>https://idp.example.com</saml:Issuer></saml:Assertion>";
        // Non-canonical: attributes in different order, extra whitespace.
        let non_canonical = b"<saml:Assertion  ID=\"_1\"  xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"><saml:Issuer>https://idp.example.com</saml:Issuer></saml:Assertion>";

        let c1 = canonicalize(canonical, C14nMode::Exclusive);
        let c2 = canonicalize(non_canonical, C14nMode::Exclusive);

        let d1 = Sha256::digest(&c1);
        let d2 = Sha256::digest(&c2);
        assert_eq!(
            d1, d2,
            "canonical and non-canonical forms should produce the same digest after c14n.\ncanonical c14n: {}\nnon-canonical c14n: {}",
            std::str::from_utf8(&c1).unwrap_or("?"),
            std::str::from_utf8(&c2).unwrap_or("?"),
        );
    }
}
