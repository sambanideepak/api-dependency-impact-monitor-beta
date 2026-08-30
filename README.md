# UpstreamSentry

![CI](https://github.com/sambanideepak/upstream-sentry/actions/workflows/ci.yml/badge.svg)

> **Know what breaks before the API change reaches you.**

Read-only, local, Python-first scanner that tells you which parts of *your* Python API
client break when a third-party REST/OpenAPI API changes.

You point it at a Python repo (the client you depend on) plus the **old** and **new** OpenAPI
specs of the API it calls. It statically analyzes your code (no execution, no network, no upload)
and produces a report mapping each API breaking change to the exact file / symbol / line it affects,
with explainable confidence + evidence, all **without modifying your repo**.

> This is a **beta**. It is local, free, and requires no account. See
> [KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md) for what it does and does not catch yet.

---

## Why this exists

When an upstream API ships a breaking change (a removed response field, a removed endpoint, a
renamed enum, a newly-required body field), your client code can silently break at runtime.
Manually auditing a large SDK against a diff is slow and error-prone. This tool does the static
cross-reference for you, offline, in seconds to minutes.

---

## What it is / isn't

- **Is:** a static analyzer. Reads your Python source + two OpenAPI specs, writes reports *outside*
  your repo, and proves your repo was not modified.
- **Is not:** a runtime agent, a network proxy, a code editor, or an AI that rewrites your code.
  It does not open PRs or auto-remediate (v1 is guidance-only by design).

---

## Safety & privacy (read this)

- **Local only.** No network calls during analysis. No telemetry. No upload of your code or specs.
  You can run it fully offline (airplane mode) and it still works.
- **Read-only proven.** The tool fingerprints your repo before/after the scan; if anything changed,
  the scan fails and the report is not trusted. It also refuses to write its report *inside* your repo.
- **No credentials.** The only optional network action is a read-only `git clone` of a **public** repo
  *you* name (no auth attempted); that temp clone is deleted afterward.
- **Secrets skipped.** Files matching secret patterns (`.env`, `*.pem`, `id_rsa`, `token`, …) are
  excluded from analysis and never surfaced.

Full detail: [PRIVACY.md](PRIVACY.md) · [SECURITY.md](SECURITY.md)

---

## Quickstart (≈2 minutes, no account)

**Requires:** Python 3.10+ and `pip`.

```bash
# 1. Clone this repo (or download as ZIP) and cd in
git clone https://github.com/sambanideepak/upstream-sentry.git
cd upstream-sentry

# 2. Create an isolated env + install the ONLY dependency (PyYAML, MIT, free)
python3 -m venv .venv
. .venv/bin/activate
pip install pyyaml

# 3. Run the self-contained demo (no real API needed)
bash run_beta_scan.sh \
  --repo ./demo-app \
  --old-spec ./demo-api/openapi-old.yaml \
  --new-spec ./demo-api/openapi-new.yaml \
  --output ./beta-report
```

You'll see something like:

```
Breaking changes: 20
Code impacts:     28
  HIGH=8 MEDIUM=8 LOW=12
Read-only safe:   YES (repo unchanged)
Reports: ./beta-report/impact-report.json
         ./beta-report/impact-report.md
```

Open `./beta-report/impact-report.md` to review each impact (file / symbol / line, *why*, confidence,
evidence, and a remediation suggestion).

---

## Run it on YOUR code

Replace the demo paths with your real client:

```bash
bash run_beta_scan.sh \
  --repo /absolute/path/to/your-python-client \
  --old-spec /absolute/path/to/old-spec.yaml \
  --new-spec /absolute/path/to/new-spec.yaml \
  --output ./beta-report
```

- `--repo` can be a **local path** or a **public HTTPS URL** (cloned read-only to a temp dir, then deleted).
- `--output` **must be outside** the analyzed repo (the tool refuses otherwise).
- You need **two OpenAPI 3.x specs** (old/new). If you only have one, produce a minimal second spec
  focused on the changed part — see the tips in `run_beta_scan.sh` comments.

See `FEEDBACK_FORM.md` / `FEEDBACK_SCHEMA.json` to report results.

---

## Run the unit tests

```bash
pip install pyyaml pytest
python3 -m pytest tests/ -q
```

These use small, real-style code snippets (not any upstream vendor source) to prove the
dict-deserialization and helper-built-endpoint detectors work generically.

---

## How detection works (honest scope)

It catches well:
- Removed/renamed **response fields** read via Pydantic/DTO models **or** dict deserialization
  (`attributes["field"]`, `response.get("field")`, `data["field"]`, …).
- Removed **endpoints** built literally (`self._request("GET", "/path")`) **or** via helpers
  (`utils.format_url("/v1/...")`, f-strings, `"/x/{}".format(y)`).
- Request-body fields serialized into a request.
- Incompatible type changes, newly-required fields, enum-value renames.

Current limits (please report misses):
- **Python only** — no JS/TS/Go/Java engine yet.
- Field detection is scoped per resource class (conservative, recall-favoring).
- Whole-program data flow (path built in one function, passed to a requester elsewhere) is out of scope
  (same-function static resolution only).
- Confidence is explainable but not a guarantee; treat MEDIUM/LOW as "review", HIGH as "very likely".

Full list: [KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md)

---

## Repository layout

```
upstream-sentry/
├── semantic_impact_mapper.py      # core static impact mapper
├── github_mvp/                    # CLI + pipeline + spec diff + safe clone
├── demo-app/                      # self-contained example Python client
├── demo-api/                      # example old/new OpenAPI specs
├── run_beta_scan.sh               # one-command beta runner
├── tests/                         # generic unit tests (no vendor source)
├── FEEDBACK_FORM.md               # what to send back
├── FEEDBACK_SCHEMA.json           # structured feedback schema
├── PRIVACY.md  SECURITY.md  KNOWN_LIMITATIONS.md
└── README.md
```

---

## Cost

Free. Local Python + PyYAML only. No paid dependency, no hosting, no account, no network in analysis.

## License

MIT — see [LICENSE](LICENSE).

## Status

Public beta (self-serve). Feedback collected via the form; no account required.
