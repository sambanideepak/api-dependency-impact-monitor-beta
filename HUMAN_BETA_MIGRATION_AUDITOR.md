# Migration Auditor V1 — Controlled Human Beta Gate

Status: PREP ONLY — no outreach has been sent from this branch.

## What we are validating

The question is not whether the static engine runs; that technical gate has already passed. The human-beta question is whether an independent post-migration audit is valuable enough that real developers would use it again and potentially pay for it.

Migration Auditor V1 takes:

- old OpenAPI spec
- new OpenAPI spec
- consumer repository BEFORE migration
- consumer repository AFTER migration

It returns a fail-closed `PASS`, `FAIL`, or `REVIEW` decision with per-impact evidence.

## Frozen product claim for this beta

> After a developer, AI coding agent, or vendor says an API migration is complete, UpstreamSentry independently checks the original affected usages against the migrated repository and reports what is still stale, what is statically resolved, and what still needs human/behavioral review.

Do not claim runtime or behavioral correctness when static evidence is insufficient.

## Tester profile

A relevant tester should have at least one of these:

1. Maintains a Python application or SDK that calls a third-party REST/OpenAPI API.
2. Has recently completed or is currently doing an API migration.
3. Reviews AI-generated migration PRs or dependency/API upgrade PRs.
4. Owns a codebase where missing one stale API call-site would be costly or risky.

Avoid counting generic curiosity installs as completed value tests.

## Controlled test protocol

1. Tester chooses one real API migration with old/new API contract evidence and a BEFORE/AFTER consumer repository snapshot.
2. Run `run_migration_audit.py` locally. Reports must be written outside both target repositories.
3. Confirm both repositories remain unchanged.
4. Review every baseline disposition:
   - `STILL_PRESENT`
   - `RESOLVED`
   - `CHANGED_BUT_UNVERIFIED`
   - `UNKNOWN`
5. Compare the output to the tester's own expected migration state.
6. Record usefulness, false positives, misses, setup friction, repeat-use intent, and willingness-to-pay range in `MIGRATION_AUDITOR_FEEDBACK.md` or the JSON schema.

Example command:

```bash
python run_migration_audit.py \
  --before-repo /path/to/repo-before \
  --after-repo /path/to/repo-after \
  --old-spec /path/to/openapi-old.yaml \
  --new-spec /path/to/openapi-new.yaml \
  --output /tmp/upstreamsentry-migration-audit
```

## Human-value gate

Do not call this commercially validated until all minimums are met:

- completed relevant real tests: >= 3
- testers saying the result was useful: >= 2
- testers saying they would use it again on a relevant migration: >= 2
- credible willingness-to-pay signal: >= 1
- serious security/privacy issue: 0

Track setup failures separately from product-value failures.

## Evidence to retain per test

- anonymized tester ID
- tester role / workflow
- API migration context
- scan completed: yes/no/with-help
- overall audit decision
- count of baseline impacts
- count of `STILL_PRESENT`, `RESOLVED`, `CHANGED_BUT_UNVERIFIED`, `UNKNOWN`
- tester-confirmed TP / FP / missed-impact examples where they can judge them
- setup difficulty
- report clarity
- time saved estimate
- would-use-again answer
- current workaround
- WTP range/model/objection
- no source code, secrets, or credentials in the feedback record

## Stop conditions

Pause the beta and fix before more outreach if any of these occur:

- repository mutation
- credentials or secret material surfaced
- repeatable false PASS on a supported case
- a common supported migration pattern produces materially misleading output
- setup is repeatedly impossible for relevant testers

Do not add random features during beta. Fix only evidence-backed bugs or clarity blockers.

## Commercial interpretation

A technically correct scan with no repeat-use or payment signal is not a winner. A few enthusiastic comments without completed real migration tests are also not sufficient. The decision after the gate is `SCALE`, `IMPROVE`, `PARK`, or `KILL` based on actual usage evidence.
