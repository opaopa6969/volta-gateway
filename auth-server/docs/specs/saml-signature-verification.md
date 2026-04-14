# Spec: SAML signature verification (backlog P0 #2)

## Goal

`/auth/saml/callback` must cryptographically verify the IdP's
`<ds:Signature>` on either the Response or embedded Assertion before
trusting any claims. The current implementation checks only that a
`<ds:Signature>` tag **exists** — not that it's valid.

## Decision: no C library dependency

Integrating `samael` with its `xmlsec` feature requires system
`libxmlsec1-dev` — unacceptable for our Dockerfile sanity.

Instead we implement XML-DSig verification in pure Rust using:

- `rsa` / `sha2` / `x509-cert` (already in deps)
- `quick-xml` for canonicalisation (replaces the ad-hoc `str::find`
  XML scanner in `saml.rs`)

Scope of the pure-Rust verifier:

- **SignatureMethod**: `rsa-sha256` / `rsa-sha1` only (covers all
  production IdPs we target; GOV-SAML still requires sha256).
- **Canonicalisation**: `exc-c14n` / `exc-c14n-with-comments` only.
  `c14n` is rare enough that supporting it later suffices.
- **Reference URIs**: `#id` local references only (no external).
  External refs are rejected outright (defence-in-depth against
  signature wrapping).

## Signature validation algorithm

```text
1. Locate <ds:Signature> (fail if multiple — signature wrapping guard).
2. Parse SignedInfo, extract:
     - CanonicalizationMethod
     - SignatureMethod algorithm
     - Reference[0].URI (must be "#<xmlid>")
     - Reference[0].DigestMethod, DigestValue
     - Reference[0].Transforms (must include enveloped-signature +
       exc-c14n; reject otherwise)
3. Find referenced element by xml:id / ID attribute.
4. Apply transforms in order:
     a. Enveloped-signature transform (strip <ds:Signature>)
     b. Exc-C14N canonicalisation
5. SHA-256 the result → compare to DigestValue.
6. C14N-canonicalise <SignedInfo>.
7. Load IdP's X509 cert (from IdpConfigRecord.x509_cert PEM).
8. RSA-verify SignatureValue over the c14n(SignedInfo) with that cert's
   public key + SignatureMethod hash.
9. On any mismatch, fail.
```

## Multiple signatures / partial signing

SAML Response may sign:
- The Response (outer),
- The Assertion (inner),
- Both,
- Neither (attacker-forged).

We require **at least one valid signature on the Assertion**
(downstream claims all come from there). A signed Response without a
signed Assertion is rejected — that's the shape typical of signature
wrapping attacks.

## Error taxonomy

| Failure | HTTP | code |
|---|---|---|
| No signature found | 401 | SAML_SIGNATURE_MISSING |
| Unsupported algorithm | 401 | SAML_SIGNATURE_UNSUPPORTED |
| Digest mismatch | 401 | SAML_SIGNATURE_INVALID |
| RSA verify failed | 401 | SAML_SIGNATURE_INVALID |
| External reference | 401 | SAML_SIGNATURE_REJECTED |

All 401 with `SAML_SIGNATURE_*` so logs can be filtered uniformly.

## Success criteria

- Unit tests with OASIS interop SAML Response samples (Keycloak,
  AD FS, Shibboleth). We store 3 fixtures under
  `auth-server/tests/fixtures/saml/` and assert:
    - Good fixture → `Ok`.
    - Tampered assertion body → `SignatureInvalid`.
    - Swapped signature between 2 valid responses → `SignatureInvalid`.

## Out of scope

- Encrypted Assertions — follow-up when a tenant actually needs them.
- SAML-SLO (Single Log Out) — separate flow, minor.
- SAML metadata fetch / auto-rotation of IdP cert — today the cert is
  configured manually per tenant.
