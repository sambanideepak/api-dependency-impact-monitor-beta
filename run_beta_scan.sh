#!/usr/bin/env bash
# Human-beta one-command runner for UpstreamSentry.
#
# Usage:
#   bash human-beta/run_beta_scan.sh \
#       --repo <local-path-or-public-https-url> \
#       --old-spec <path> --new-spec <path> \
#       --output <dir-outside-repo>
#
# What it does (honestly, no faking):
#   1. Validates inputs.
#   2. If --repo is a public https URL, clones read-only (no auth) to a temp dir, then scans that.
#   3. Runs the scan (CLI module).
#   4. Prints the report paths and the read-only safety line.
#   5. Cleans up any temp clone + temp workspace.
#
# Guarantees:
#   - No write into the analyzed repo (CLI refuses and exits 2 if --output is inside).
#   - No credentials required for public mode.
#   - Clear errors; never pretends success on failure.
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

PY="${PYTHON:-python3}"
REPO=""
OLD=""
NEW=""
OUT=""

while [ $# -gt 0 ]; do
  case "$1" in
    --repo)    REPO="$2"; shift 2 ;;
    --old-spec) OLD="$2"; shift 2 ;;
    --new-spec) NEW="$2"; shift 2 ;;
    --output)  OUT="$2"; shift 2 ;;
    --workdir) WORKDIR="$2"; shift 2 ;;
    -h|--help) echo "Usage: $0 --repo R --old-spec O --new-spec N --output OUT"; exit 0 ;;
    *) echo "[ERROR] unknown arg: $1" >&2; exit 2 ;;
  esac
done

[ -z "$REPO" ] && { echo "[ERROR] --repo is required" >&2; exit 2; }
[ -z "$OLD" ]  && { echo "[ERROR] --old-spec is required" >&2; exit 2; }
[ -z "$NEW" ]  && { echo "[ERROR] --new-spec is required" >&2; exit 2; }
[ -z "$OUT" ]  && { echo "[ERROR] --output is required" >&2; exit 2; }

# If --repo looks like a public https URL, clone read-only to a temp dir.
TMP_CLONE=""
if [[ "$REPO" == https://* ]]; then
  TMP_CLONE="$(mktemp -d -t impact_beta_clone_XXXXXX)"
  echo ">> read-only clone of public repo: $REPO"
  if ! git clone --depth 1 "$REPO" "$TMP_CLONE" >/dev/null 2>&1; then
    echo "[ERROR] public clone failed (no auth attempted). Use a local path or a public URL." >&2
    rm -rf "$TMP_CLONE"
    exit 2
  fi
  SCAN_REPO="$TMP_CLONE"
else
  SCAN_REPO="$REPO"
fi

# Run the scan via the CLI module (handles validation, read-only, cleanup).
set +e
"$PY" -m github_mvp.cli scan \
  --repo "$SCAN_REPO" \
  --old-spec "$OLD" \
  --new-spec "$NEW" \
  --output "$OUT" ${WORKDIR:+--workdir "$WORKDIR"}
RC=$?
set -e

# Clean up temp clone (never the tester's repo).
if [ -n "$TMP_CLONE" ]; then
  rm -rf "$TMP_CLONE"
fi

if [ $RC -eq 0 ]; then
  echo ""
  echo ">> DONE. Reports in: $OUT"
  echo ">> Next: open $OUT/impact-report.md and fill FEEDBACK_FORM.md"
  exit 0
else
  echo "[ERROR] scan exited with code $RC (see messages above). No report trusted." >&2
  exit $RC
fi
