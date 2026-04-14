# Arch: SAML signature verification

## Why not samael / libxmlsec1

Adding `libxmlsec1-dev` to our build pipeline:
- breaks minimal Alpine images
- pulls libxml2, openssl-dev, glib-dev transitively
- adds ~40 MB to the final image
- has a history of CVE advisories at roughly the cadence we'd have to
  roll the base image

The threat model for SAML is narrow (enterprise IdPs, low RPS, few
key rotations). Writing ~300 lines of pure-Rust XML-DSig covering the
actual algorithms used in production is a worthwhile exchange for
losing the C dependency.

## Signature wrapping defences

Three specific checks mitigate the 2012 XSW-attack class:

1. **Reject multiple `<Signature>` elements** — canonical SAML has
   exactly one per signed element. Attackers inject a second one with
   a valid signature over their forged assertion, then swap references.
2. **Reject external reference URIs** — only `#<id>` local refs
   allowed. External would trick us into hashing a document under the
   attacker's control.
3. **Require signature on Assertion** — the Response outer envelope is
   not trusted alone.

## Canonicalisation choice

We implement `exc-c14n` (RFC 3741). Plain `c14n` is barely used in
SAML in practice (exc-c14n was designed specifically for SAML's
namespace-embedded shape). Adding plain `c14n` is straightforward if
a tenant ever needs it.

## Algorithm allowlist

- `rsa-sha256` (required)
- `rsa-sha1` (transitional — most IdPs still default to this despite
  NIST deprecation)

Rejected:
- `dsa-sha1` (rare, insecure).
- `ecdsa-*` (rare in SAML, easy to add later).

The allowlist lives in a `const ALLOWED_SIG_ALGS: &[&str]` so expanding
is a one-line change + test.

## Interaction with existing `saml::parse_identity`

`parse_identity` currently does structural checks (issuer, audience,
expiry) via text scanning. The signature verifier sits **before**
those checks:

```text
bytes → reject_doctype → verify_signature → parse_identity (claims)
```

If signature fails, structural checks never run — no information
leakage about claim shape.

## Why `quick-xml` over `xmlparser`

`quick-xml` streams events with namespace-awareness, which we need for
canonicalisation. The existing `xmlparser` dep can be removed once the
new verifier lands (flagged as a follow-up).

## Fixture provenance

- `keycloak-response.xml` — generated with `kcadm.sh` against a local
  Keycloak 23. Cert checked in as `.pem`.
- `adfs-response.xml` — recorded from an ADFS 2016 capture.
- `shibboleth-response.xml` — OASIS interop test suite.

Each fixture has a companion `.expected.json` with the parsed
identity, enabling golden tests.
