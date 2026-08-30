# Frozen real-world case: hvac AppRole secret-id endpoint migration

This case is a narrow technical-feasibility fixture for the Migration Auditor.

Public upstream repository: `hvac/hvac`

- BEFORE: `97052b593fbeae4f4556789b03933d7a5be273df`
- AFTER: `7a06e627795dc4121eaaf0b1b75b517be8cdecfe`

The upstream commit explicitly changed AppRole secret-id access from the old direct secret-id endpoint to POST-based `lookup` / `destroy` endpoints. In the frozen Python source, the old endpoint is built as a relative `/v1/...` path and passed to `_get` / `_delete`; the migrated source builds the replacement relative paths and passes them to `_post`.

The OpenAPI files here are intentionally migration-focused slices, not a claim to reproduce the full Vault OpenAPI document. Their only purpose is to encode the exact old endpoint removal that the frozen upstream commit migrated.

Expected audit assertions:

1. BEFORE → BEFORE = `FAIL` because the old endpoint impact is still present.
2. BEFORE → AFTER = `PASS` because the baseline statically-provable endpoint usage disappears.
3. Both scans remain read-only.

This is deliberately different from the EvalView case: EvalView proves fail-closed behavior outside current static coverage; this hvac case tests a real migration inside the documented Python REST coverage boundary.
