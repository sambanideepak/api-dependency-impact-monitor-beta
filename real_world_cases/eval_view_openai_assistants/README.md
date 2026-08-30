# Real-world case: EvalView OpenAI Assistants -> Responses

This fixture validates a **coverage boundary**, not a successful migration PASS.

## Frozen upstream evidence

- Upstream repository: `hidai25/eval-view`
- BEFORE commit: `afbc7f6c715d7cd1ab1ea71aefd5e26a9bbcd767`
- AFTER commit: `27f7bc019cd3d41184411fc3802494f97a0c58e7`
- Migration commit message states that the OpenAI adapters moved from the removed Assistants API to the Responses + Conversations APIs and that the old `client.beta.threads.*` / `client.beta.assistants.*` call sites were removed.

The BEFORE revision contains SDK-style usages such as `client.beta.threads.create()`, `client.beta.threads.runs.create()` and `client.beta.assistants.create()`. The AFTER revision uses `client.conversations.create()` and `client.responses.create()`.

## Why this case exists

UpstreamSentry V1 currently maps OpenAPI/direct-HTTP-style consumer impacts. It does not yet claim complete semantic coverage of vendor SDK symbol migrations such as `client.beta.threads.*`.

The reduced specs in this directory model one removed Assistants endpoint solely to create a deterministic breaking-contract input for the auditor. They are **not** represented as a complete OpenAI provider specification.

## Expected decision

`REVIEW`

Reason: the API contract contains a breaking change, but the baseline scanner is expected to find zero supported consumer impacts in this SDK-symbol-shaped repository. The auditor must refuse to emit PASS rather than pretending that unsupported coverage proves migration completeness.

This is intentionally a real-world **negative/fail-closed proof**. A separate real-world direct REST/OpenAPI case is required before Migration Auditor V1 can claim positive migration-completeness proof.