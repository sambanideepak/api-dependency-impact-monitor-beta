# Example Output (real tool output on the bundled `demo-app` + `demo-api` specs)

This is the **actual** JSON+MD the tool produces. Nothing here is from a private repo.

## Summary line (stdout)
```
Breaking changes: 20
Code impacts:     28
  HIGH=8 MEDIUM=8 LOW=12
Read-only safe:   YES (repo unchanged)
```

## `impact-report.json` shape
```json
{
  "repo_path": "/Users/deepaksambani/Projects/api-dependency-impact-monitor-beta/demo-app",
  "old_spec": "/Users/deepaksambani/Projects/api-dependency-impact-monitor-beta/demo-api/openapi-old.yaml",
  "new_spec": "/Users/deepaksambani/Projects/api-dependency-impact-monitor-beta/demo-api/openapi-new.yaml",
  "breaking_changes": [
    {
      "type": "endpoint_removed",
      "severity": "breaking",
      "path": "paths./comments/{comment_id}",
      "message": "Endpoint removed",
      "schema_object": "",
      "direction": "endpoint"
    },
    {
      "type": "removed_field",
      "severity": "breaking",
      "path": "operations.POST /projects.response.schema.properties.owner_id",
      "message": "Property 'owner_id' removed from response schema 'Project'",
      "schema_object": "Project",
      "direction": "response",
      "api_field": "owner_id"
    },
    {
      "type": "r
```

## One real impact object (excerpt, from the demo)
```json
{
  "breaking_change_id": "BC001",
  "breaking_change_type": "endpoint_removed",
  "api_path": "paths./comments/{comment_id}",
  "api_field": "N/A",
  "affected_file": "task_sync/client.py",
  "affected_symbol": "delete_comment",
  "affected_line": 103,
  "affected_code_snippet": "self._request(\"DELETE\", f\"/comments/{comment_id}\")",
  "why_impacted": "Client method builds/calls removed endpoint DELETE /comments/{comment_id}",
  "confidence": "HIGH",
  "risk_level": "CRITICAL",
  "confidence_score": 3.5,
  "evidence": [
    {
      "type": "exact_endpoint_match",
      "weight": 2.0,
      "description": "Inside matching client method: delete_comment (DELETE f\"/comments/{comment_id}\")",
      "location": "        self._request(\"DELETE\", f\"/comments/{comment_id}\")"
    },
    {
      "type": "exact_method_match",
      "weight": 1.5,
      "description": "HTTP method matches: DELETE",
      "location": "        self._request(\"DELETE\", f\"/comments/{comment_id}\")"
    }
  ],
  "remediation": "Remove or replace the call to removed endpoint DELETE /comments/{comment_id}. This endpoint no longer exists in the API.",
  "test_evidence": "deterministic static match: a contract test asserting the old API shape is expected to fail here"
}
```

> The Markdown report (`impact-report.md`) renders each impact with file / symbol / line,
> *why* it's impacted, a confidence (HIGH/MEDIUM/LOW), the supporting evidence, and a
> remediation suggestion. The scan leaves your repo byte-for-byte unchanged.