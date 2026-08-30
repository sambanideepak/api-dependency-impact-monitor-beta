#!/usr/bin/env python3
"""Independent post-migration acceptance auditor for UpstreamSentry.

The auditor reuses the existing deterministic ImpactPipeline twice:

1. Scan the consumer repository BEFORE migration.
2. Scan the consumer repository AFTER migration.
3. Compare the baseline impact inventory against the post-migration inventory.
4. Emit a fail-closed disposition for every baseline impact and an overall
   PASS / FAIL / REVIEW decision.

V1 intentionally does NOT modify customer code, does NOT run arbitrary target
code, and does NOT claim behavioral proof when static analysis cannot prove it.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from github_mvp.pipeline import ImpactPipeline, ScanResult


class Disposition(str, Enum):
    RESOLVED = "RESOLVED"
    STILL_PRESENT = "STILL_PRESENT"
    CHANGED_BUT_UNVERIFIED = "CHANGED_BUT_UNVERIFIED"
    UNKNOWN = "UNKNOWN"


class AuditDecision(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    REVIEW = "REVIEW"


STATICALLY_PROVABLE_TYPES = {
    "field_removed",
    "endpoint_removed",
}


@dataclass
class ImpactDisposition:
    breaking_change_id: str
    breaking_change_type: str
    api_path: str
    api_field: str
    before_file: str
    before_symbol: str
    before_line: int
    status: Disposition
    reason: str
    after_matches: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class MigrationAuditResult:
    before_repo: str
    after_repo: str
    old_spec: str
    new_spec: str
    decision: AuditDecision
    dispositions: List[ImpactDisposition] = field(default_factory=list)
    before_scan: Optional[Dict[str, Any]] = None
    after_scan: Optional[Dict[str, Any]] = None
    notes: List[str] = field(default_factory=list)
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["decision"] = self.decision.value
        for item in data["dispositions"]:
            item["status"] = item["status"].value if isinstance(item["status"], Enum) else item["status"]
        return data


class MigrationAuditor:
    """Compare BEFORE and AFTER consumer repos against the same API migration."""

    def __init__(
        self,
        before_repo: Path,
        after_repo: Path,
        old_spec: Path,
        new_spec: Path,
        exclude_patterns: Optional[List[str]] = None,
    ):
        self.before_repo = Path(before_repo).expanduser().resolve()
        self.after_repo = Path(after_repo).expanduser().resolve()
        self.old_spec = Path(old_spec).expanduser().resolve()
        self.new_spec = Path(new_spec).expanduser().resolve()
        self.exclude_patterns = exclude_patterns

    @staticmethod
    def _logical_key(impact: Dict[str, Any]) -> Tuple[str, str, str, str]:
        """Logical API-impact identity independent of source file movement."""
        return (
            str(impact.get("breaking_change_id", "")),
            str(impact.get("breaking_change_type", "")),
            str(impact.get("api_path", "")),
            str(impact.get("api_field", "")),
        )

    def _scan(self, repo: Path) -> ScanResult:
        return ImpactPipeline(
            repo_path=repo,
            old_spec=self.old_spec,
            new_spec=self.new_spec,
            exclude_patterns=self.exclude_patterns,
        ).run()

    def run(self) -> MigrationAuditResult:
        result = MigrationAuditResult(
            before_repo=str(self.before_repo),
            after_repo=str(self.after_repo),
            old_spec=str(self.old_spec),
            new_spec=str(self.new_spec),
            decision=AuditDecision.REVIEW,
        )

        before = self._scan(self.before_repo)
        after = self._scan(self.after_repo)
        result.before_scan = before.to_dict()
        result.after_scan = after.to_dict()

        if before.error or after.error:
            result.error = "; ".join(x for x in [before.error, after.error] if x)
            result.notes.append("Audit could not complete both deterministic scans.")
            result.decision = AuditDecision.REVIEW
            return result

        if not before.safety.get("read_only", False) or not after.safety.get("read_only", False):
            result.error = "read-only safety verification failed for one or both repositories"
            result.notes.append("No acceptance decision is trusted when repository mutation is observed.")
            result.decision = AuditDecision.REVIEW
            return result

        after_by_key: Dict[Tuple[str, str, str, str], List[Dict[str, Any]]] = {}
        for impact in after.impacts:
            after_by_key.setdefault(self._logical_key(impact), []).append(impact)

        for impact in before.impacts:
            key = self._logical_key(impact)
            matches = after_by_key.get(key, [])
            change_type = str(impact.get("breaking_change_type", ""))

            if matches:
                status = Disposition.STILL_PRESENT
                reason = "The same logical breaking-change impact is still detected in the migrated repository."
            elif change_type in STATICALLY_PROVABLE_TYPES:
                status = Disposition.RESOLVED
                reason = "The baseline old-contract usage is no longer detected; this change type is statically provable in V1."
            else:
                status = Disposition.CHANGED_BUT_UNVERIFIED
                reason = (
                    "The old impact disappeared, but V1 cannot prove replacement behavior from static absence alone. "
                    "Independent test/type/runtime evidence is required before PASS."
                )

            result.dispositions.append(
                ImpactDisposition(
                    breaking_change_id=str(impact.get("breaking_change_id", "")),
                    breaking_change_type=change_type,
                    api_path=str(impact.get("api_path", "")),
                    api_field=str(impact.get("api_field", "")),
                    before_file=str(impact.get("affected_file", "")),
                    before_symbol=str(impact.get("affected_symbol", "")),
                    before_line=int(impact.get("affected_line", 0) or 0),
                    status=status,
                    reason=reason,
                    after_matches=matches,
                )
            )

        if before.breaking_changes and not before.impacts:
            result.notes.append(
                "Breaking API changes exist, but no baseline consumer impacts were found. "
                "This may mean the API is unused or scanner coverage is insufficient; manual review is required."
            )
            result.decision = AuditDecision.REVIEW
            return result

        statuses = {d.status for d in result.dispositions}
        if Disposition.STILL_PRESENT in statuses:
            result.decision = AuditDecision.FAIL
        elif Disposition.CHANGED_BUT_UNVERIFIED in statuses or Disposition.UNKNOWN in statuses:
            result.decision = AuditDecision.REVIEW
        else:
            result.decision = AuditDecision.PASS

        if not result.dispositions and not before.breaking_changes:
            result.notes.append("No breaking API changes were detected; there is no migration acceptance case to audit.")
            result.decision = AuditDecision.REVIEW

        return result


def write_audit_reports(result: MigrationAuditResult, out_dir: Path) -> Dict[str, Path]:
    """Write deterministic machine + human evidence reports outside target repos."""
    out_dir = Path(out_dir).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    json_path = out_dir / "migration-audit.json"
    md_path = out_dir / "migration-audit.md"
    payload = result.to_dict()
    json_path.write_text(json.dumps(payload, indent=2) + "\n")

    lines = [
        "# UpstreamSentry Migration Audit",
        "",
        f"**Decision:** `{result.decision.value}`",
        f"**Before repository:** `{result.before_repo}`",
        f"**After repository:** `{result.after_repo}`",
        f"**Old API spec:** `{result.old_spec}`",
        f"**New API spec:** `{result.new_spec}`",
        "",
        "## Evidence boundary",
        "",
        "This report is an independent deterministic static audit. V1 does not run arbitrary target code and does not claim behavioral proof when static evidence is insufficient.",
        "",
    ]

    if result.error:
        lines += ["## Error", "", result.error, ""]

    lines += ["## Baseline impact dispositions", ""]
    if not result.dispositions:
        lines.append("No baseline impacts were dispositioned.")
    for i, d in enumerate(result.dispositions, 1):
        lines += [
            f"### {i}. {d.breaking_change_id} — {d.status.value}",
            f"- Change type: `{d.breaking_change_type}`",
            f"- API path: `{d.api_path}`",
            f"- API field: `{d.api_field}`",
            f"- Before location: `{d.before_file}:{d.before_line}` ({d.before_symbol})",
            f"- Reason: {d.reason}",
            f"- Post-migration matches: {len(d.after_matches)}",
            "",
        ]

    if result.notes:
        lines += ["## Notes", ""]
        lines.extend(f"- {note}" for note in result.notes)
        lines.append("")

    md_path.write_text("\n".join(lines) + "\n")
    return {"json": json_path, "md": md_path}
