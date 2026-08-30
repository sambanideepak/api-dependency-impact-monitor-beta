#!/usr/bin/env python3
"""Standalone CLI for UpstreamSentry Migration Auditor V1."""
from __future__ import annotations

import argparse
from pathlib import Path

from github_mvp.migration_auditor import MigrationAuditor, write_audit_reports


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Independently audit whether a consumer API migration is complete."
    )
    ap.add_argument("--before-repo", required=True, help="Consumer repository before migration")
    ap.add_argument("--after-repo", required=True, help="Consumer repository after migration")
    ap.add_argument("--old-spec", required=True, help="Old OpenAPI spec")
    ap.add_argument("--new-spec", required=True, help="New OpenAPI spec")
    ap.add_argument("--output", required=True, help="Evidence directory outside target repositories")
    args = ap.parse_args()

    before_repo = Path(args.before_repo).expanduser().resolve()
    after_repo = Path(args.after_repo).expanduser().resolve()
    output = Path(args.output).expanduser().resolve()

    # Evidence must not be written into either target repository.
    for target in (before_repo, after_repo):
        try:
            output.relative_to(target)
            print(f"[ERROR] --output must be outside target repositories: {output}")
            return 2
        except ValueError:
            pass

    audit = MigrationAuditor(
        before_repo=before_repo,
        after_repo=after_repo,
        old_spec=Path(args.old_spec),
        new_spec=Path(args.new_spec),
    ).run()

    paths = write_audit_reports(audit, output)
    print(f"Decision: {audit.decision.value}")
    print(f"JSON evidence: {paths['json']}")
    print(f"Markdown evidence: {paths['md']}")

    if audit.error:
        print(f"[ERROR] {audit.error}")
        return 2
    if audit.decision.value == "FAIL":
        return 1
    # REVIEW is not process failure; callers can gate on the decision in JSON.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
