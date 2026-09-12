---
status: current
canonicalFor: gateway-config-contract
lastVerified: 2026-09-12
language: en
supersedes: []
supersededBy: null
---

# Gateway configuration contract

The runtime owner of the gateway YAML format is `volta-gateway`. Its stable
contract ID is `volta-gateway:gateway-config`; the current version is integer
`3`, represented by top-level `config_version: 3`.

## Compatibility

- A missing `config_version` is interpreted as v3 only for configurations that
  predate the version field. New and generated files must write it explicitly.
- A value other than `3` fails validation with exit code `1`. It is never
  silently treated as the current shape.
- Additive, optional fields may be introduced within v3. Removing or changing
  the meaning/type of a field requires a new integer version and a reader that
  can support the migration window.

## Migration and revert

Deploy the reader that accepts both the versionless legacy shape and explicit
v3 first. Then update configuration writers and checked-in examples to emit
`config_version: 3`.

To revert this introduction, revert its PR and leave or remove the top-level
field. Older readers ignore unknown top-level fields under the current serde
configuration, and the remainder of the YAML is unchanged. For a future major
change, first deploy a dual-version reader, migrate writers, validate all
production candidates, and only then retire the old reader.
