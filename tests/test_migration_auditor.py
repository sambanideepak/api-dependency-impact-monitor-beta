from pathlib import Path

from github_mvp.migration_auditor import (
    AuditDecision,
    Disposition,
    MigrationAuditor,
)
from github_mvp.pipeline import ScanResult


def _scan(repo, impacts, breaking=True, safe=True, error=None):
    return ScanResult(
        repo_path=str(repo),
        old_spec="old.yaml",
        new_spec="new.yaml",
        breaking_changes=[{"type": "removed_field"}] if breaking else [],
        impacts=impacts,
        safety={
            "read_only": safe,
            "files_changed": [],
            "files_added": [],
            "files_removed": [],
        },
        error=error,
    )


def _impact(change_type="field_removed", file="client.py", line=10):
    return {
        "breaking_change_id": "BC001",
        "breaking_change_type": change_type,
        "api_path": "operations.GET /users.responses.200.schema.properties.legacy_name",
        "api_field": "legacy_name",
        "affected_file": file,
        "affected_symbol": "get_user",
        "affected_line": line,
        "confidence": "HIGH",
    }


class FakeAuditor(MigrationAuditor):
    def __init__(self, before_scan, after_scan):
        super().__init__(Path("before"), Path("after"), Path("old.yaml"), Path("new.yaml"))
        self._before_scan = before_scan
        self._after_scan = after_scan

    def _scan(self, repo):
        if repo == self.before_repo:
            return self._before_scan
        return self._after_scan


def test_fail_when_old_impact_still_present():
    before = _scan("before", [_impact()])
    after = _scan("after", [_impact(file="moved.py", line=99)])
    result = FakeAuditor(before, after).run()

    assert result.decision == AuditDecision.FAIL
    assert result.dispositions[0].status == Disposition.STILL_PRESENT


def test_pass_when_statically_provable_old_usage_disappears():
    before = _scan("before", [_impact("field_removed")])
    after = _scan("after", [])
    result = FakeAuditor(before, after).run()

    assert result.decision == AuditDecision.PASS
    assert result.dispositions[0].status == Disposition.RESOLVED


def test_review_when_behavioral_replacement_is_not_proven():
    before = _scan("before", [_impact("type_change")])
    after = _scan("after", [])
    result = FakeAuditor(before, after).run()

    assert result.decision == AuditDecision.REVIEW
    assert result.dispositions[0].status == Disposition.CHANGED_BUT_UNVERIFIED


def test_review_when_breaking_change_has_no_baseline_impacts():
    before = _scan("before", [], breaking=True)
    after = _scan("after", [], breaking=True)
    result = FakeAuditor(before, after).run()

    assert result.decision == AuditDecision.REVIEW
    assert "no baseline consumer impacts" in result.notes[0].lower()


def test_review_when_read_only_proof_fails():
    before = _scan("before", [_impact()], safe=False)
    after = _scan("after", [])
    result = FakeAuditor(before, after).run()

    assert result.decision == AuditDecision.REVIEW
    assert result.error is not None


def test_review_when_scan_errors():
    before = _scan("before", [], error="bad input")
    after = _scan("after", [])
    result = FakeAuditor(before, after).run()

    assert result.decision == AuditDecision.REVIEW
    assert "bad input" in result.error
