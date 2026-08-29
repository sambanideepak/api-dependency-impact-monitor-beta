# Impact Monitor — README (Python-first, read-only GitHub MVP)

`impact_monitor` scans a **local Python repository** for code that depends on an API whose
contract changed. You give it two OpenAPI specs (the version you depend on, and the new
version) plus the repo path; it reports exactly which files, functions, and lines are
impacted, with explainable confidence, severity, reasoning, and deterministic remediation
guidance.

It is **local, private, and read-only**. It never modifies the repository it analyzes, never
contacts the network (except an optional unauthenticated public clone), never stores
credentials, and costs **$0**.

## Install / requirements

- Python 3.11+
- `PyYAML` (`pip install pyyaml` if not already present)

No other dependencies. No build step.

## Quick start

```bash
python3 -m github_mvp.cli scan \
    --repo ./demo-app \
    --old-spec ./demo-api/openapi-old.yaml \
    --new-spec ./demo-api/openapi-new.yaml \
    --output ./report
```

This writes:

- `./report/impact-report.json` — machine-readable (for CI / tooling)
- `./report/impact-report.md` — human-readable

and prints a summary to stdout.

## One-command demo

```bash
bash github_mvp/run_demo.sh
```

Runs the full pipeline on the bundled demo, verifies the repo is unchanged, runs the
5-repo validation harness, and prints `PASS` / `FAIL` (exit code 0 / 1).

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Success; repo unchanged; reports written |
| 2 | Invalid input / output-inside-repo / scan error (message on stderr) |
| 3 | **Repo was modified during scan** — safety gate tripped (reports NOT trusted) |

## What it detects

API breaking changes between the two specs (removed field, renamed property, newly required
field/param, incompatible type change, removed endpoint, enum value rename) and maps each to
Python code that: defines the affected model/field, deserializes the affected response,
serializes the affected request, references the removed endpoint, or uses the renamed enum
value — with SQL DDL column detection for DB-backed stores.

## How the impact engine works (reused, not rebuilt)

The mapping engine is the **verified hardening-stage `SemanticImpactMapper`**
(`semantic_impact_mapper.py`) that previously scored:

- Demo fixture: **Precision 100% / Recall 100% / F1 100%**
- Overall multi-repo: **Precision 81.8% / Recall 90.0% / F1 85.7%**

This MVP wraps it with a spec-diff module (`github_mvp/spec_diff.py`), deterministic
remediation text, repo fingerprinting for read-only safety, and report assembly.

## Limitations

- **Python / static analysis only.** No TypeScript/JS engine (see prior phase notes).
- No SaaS, no dashboard, no auth, no auto-PR (by design — see `MVP_SCOPE.md`).
- Spec diff is heuristic (OpenAPI 3.x structural diff). A managed tool (`oasdiff`) may be
  used as an optional upgrade, but the default path uses only stdlib + PyYAML.

## Safe clone of a public repo

```bash
python3 -m github_mvp.safe_clone \
    --repo https://github.com/owner/public-sdk.git \
    --old-spec old.yaml --new-spec new.yaml --output ./report
```

Clones read-only (no auth) into a temp dir, analyzes, then cleans up. Private repos and
credentialed clones are out of scope for v1.

## Read-only safety

The scanner fingerprints the repo before and after; if anything changed, it fails (exit 3).
It also refuses to write reports inside the analyzed repo. See `artifacts/read-only-safety-report.md`.

## Future (not in this MVP)

A minimal GitHub App with `contents: read` + `metadata: read` only — see
`research/github-readonly-integration-design.md`. No writes, no auto-PR.

See `GITHUB_MVP_REPORT.md` for the full readiness decision.
