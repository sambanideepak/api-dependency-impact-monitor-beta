# Security for Testers — UpstreamSentry (beta)

**Short version:** local, static, read-only. No code execution of your repo, no network egress,
no writes into your repo, no credentials.

## Analysis model
- Pure **static analysis** (`ast` parse + pattern matching). We never `eval`/`exec`/`compile` your
  code and never run it.
- Endpoint/path resolution is **static** (reads literals/f-strings in your code); we never invoke
  your functions or any helper.

## Read-only guarantee (proven, not promised)
1. Before scanning, the tool records a content fingerprint (size + hash) of every file in the repo.
2. After scanning, it re-checks the fingerprint.
3. If anything changed/added/removed, the scan **fails** (exit 3) and the report is not trusted.
4. The tool also refuses to write its report **inside** the analyzed repo (exit 2).

## Isolation
- The temp workspace lives in your system temp dir, **outside** the repo, and is removed after the run.
- Output directory must be outside the repo.

## Secret handling
- Files matching `SECRET_EXCLUDE` (`.env`, `*.pem`, `*.key`, `id_rsa`, `token`, `service-account`, …)
  are excluded from both analysis and fingerprinting, so their contents are never read or surfaced.

## Network
- **No network calls during analysis.** (The optional `safe_clone` mode does one unauthenticated
  `git clone` of a *public* repo you name — only if you use `--repo <https URL>`; it needs no
  credentials and is cleaned up.)
- If you want a stronger proof: run the scan fully offline (airplane mode) — it still works.

## Supply chain
- **Only dependency: PyYAML** (MIT, pure Python). No native builds, no post-install scripts.
- No other third-party packages are imported by the tool.

## Error handling
- Bad input (missing repo/spec, output inside repo, malformed spec) → clear non-zero exit (2) with a
  message; no crash, no partial write into the repo.
- Path-traversal / symlink attempts are treated as normal files and never followed for writing.

## What you can check
- `human-beta/run_beta_scan.sh` is short and readable.
- `github_mvp/cli.py`, `github_mvp/pipeline.py`, `semantic_impact_mapper.py` are the engine.
- Grep the code for `requests.`/`urllib`/`socket`/`subprocess` — only a safe-clone `git` call exists
  (optional), no analysis-path egress.

## Responsible-use notes
- Run only on repos you are permitted to analyze.
- Keep your own secrets out of the scanned tree (the tool skips them, but don't commit them).
- This is a read-only analyzer; it will not modify, deploy, or publish anything.
