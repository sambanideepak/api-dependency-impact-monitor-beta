# Privacy for Testers — UpstreamSentry (beta)

**Short version:** the tool runs on your machine, reads your code locally, changes nothing, and
sends nothing anywhere. We never receive your source.

## What the tool accesses
- **Reads** the local repo you point it at (Python files), to find API-usage patterns.
- **Reads** the two spec files you provide (old/new OpenAPI).
- **Writes** reports only to the output directory you choose — which must be **outside** the repo
  (the tool refuses to write inside the repo).

## What the tool does NOT do
- **No network calls during analysis.** No API requests, no telemetry, no analytics, no beacons.
- **No upload of your source code or specs** to any server.
- **No execution of your code.** Analysis is static (AST only); we never run your repo.
- **No telemetry/phone-home.** There is no code that contacts us.
- **No credential access.** The tool needs no tokens. The optional public-clone mode uses `git clone`
  with no authentication.
- **No persistence of secrets.** Files matching secret patterns (`.env`, `*.pem`, `token`, …) are
  skipped from analysis and never surfaced.

## What WE (the owners) receive
- **Only** the structured feedback you choose to send us (via `FEEDBACK_SCHEMA.json` / form).
- That feedback is voluntary, can be anonymized, and you may redact anything.
- We will not publish your repo, your code, or your feedback without explicit permission.

## Temporary files
- A temp workspace is created **outside** your repo during the scan and is **deleted afterward**.
- Your repo is fingerprinted (hashes) before/after only to prove it was not modified; those
  fingerprints are local and not transmitted.

## If you use a private/internal repo
- Run the tool on a **local copy** you are allowed to scan.
- Do **not** point it at a repo you lack permission to analyze.
- We never see it regardless — analysis is local.

## How to verify for yourself
1. Run the scan; it prints `Read-only safe: YES`.
2. `git status` in the repo → clean.
3. Disconnect from the network and re-run → it still works (no egress needed).
4. Inspect `human-beta/run_beta_scan.sh` and `github_mvp/` — all open source, no network calls.

Questions? Send them through the agreed feedback channel. We will answer without asking for your code.
