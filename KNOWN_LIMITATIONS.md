# Known Limitations — Human Beta (API Dependency Impact Monitor)

We'd rather you know the edges than be surprised. These are honest, current limits (2026-08-29).

## Language
- **Python only.** No JavaScript/TypeScript/Go/Java engine yet. A JS/TS repo will scan but find
  little. (This is a known roadmap gap; the architecture is language-portable.)

## Detection scope (what it catches well)
- Removed/renamed response fields read via models **or** dict deserialization
  (`attributes["field"]`, `response.get("field")`, `data["field"]`, etc.).
- Removed endpoints built literally (`self._request("GET", "/path")`) **or** via helpers
  (`utils.format_url("/v1/...")`, f-strings, `"/x/{}".format(y)`).
- Request-body fields serialized into a request.
- Incompatible type changes, newly-required fields, enum-value renames (model/param level).
- SQL DDL column detection for DB-backed stores.

## Detection scope (current limits — please report misses)
- **Field detection is scoped per resource class.** If the same field name is read by a class for a
  *different* resource that still returns it, detection may over-attribute. Conservative (recall-
  favoring) choice; correct on our frozen cases.
- **Whole-program data flow is out of scope.** If a path is built in one function and passed to a
  requester in another, across functions, it may be missed (we do same-function resolution only).
- **Custom deserializers** that rename the response variable away from `attributes`/`response`/`data`
  and out of any `_useAttributes`/`from_dict`/`deserialize` function may fall below threshold.
- **Generated clients** (e.g. from OpenAPI generators) vary; some map cleanly, some need tuning.
- **Very large specs** (multi-MB) are fine to diff but slower; keep specs focused on the changed API.

## Spec requirements
- Needs **two OpenAPI 3.x specs** (old/new). If you only have one, you must produce the other (even a
  minimal one focused on the changed part). The tool does **not** infer the old API from your code.
- Spec diff is heuristic (structural). Exotic OpenAPI constructs may be under-detected.

## Output
- **Guidance, not fixes.** The tool suggests remediation in words; it does not edit your code or open
  PRs (by design for v1).
- Confidence is **explainable** (each impact carries evidence) but not a guarantee; treat MEDIUM/LOW
  as "review", HIGH as "very likely".

## Performance
- Scans a typical client repo in seconds to a few minutes. Huge monorepos take longer but stay
  read-only.

## What we will NOT do with your run
- No upload, no telemetry, no auto-change. See `PRIVACY_FOR_TESTERS.md` / `SECURITY_FOR_TESTERS.md`.
