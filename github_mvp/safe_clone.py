#!/usr/bin/env python3
"""
Phase 7 -- Safe clone / snapshot flow.

Supports analyzing either:
  * a LOCAL repository path (no network), or
  * a PUBLIC GitHub HTTPS URL, cloned READ-ONLY with no authentication into an
    isolated temporary workspace that is cleaned up afterwards.

Design rules (standing constraints):
  * No credentials are stored or requested. Only PUBLIC, unauthenticated clones are
    attempted (Private repos require a token and are intentionally NOT handled here;
    see research/github-readonly-integration-design.md).
  * The clone lands in a temp dir OUTSIDE the user's working directory.
  * The scanner never writes into the cloned repo (read-only safety enforced by the
    pipeline's fingerprint check).
  * The temp workspace is removed after analysis.

Usage:
    python3 -m github_mvp.safe_clone \
        --repo https://github.com/owner/public-repo \
        --old-spec specs/old.yaml --new-spec specs/new.yaml --output report/
    # or a local path:
    python3 -m github_mvp.safe_clone \
        --repo ./repos/py-inventory \
        --old-spec repos/py-inventory/openapi-old.yaml \
        --new-spec repos/py-inventory/openapi-new.yaml --output report/
"""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from github_mvp.pipeline import ImpactPipeline, write_reports  # noqa: E402


def is_github_https(url: str) -> bool:
    return url.startswith("https://github.com/") and url.endswith(".git") or (
        url.startswith("https://github.com/") and ("/" in url[len("https://github.com/"):])
    )


def clone_public(url: str, dest: Path) -> None:
    """Read-only, unauthenticated clone of a PUBLIC repo. Raises if it needs auth."""
    # Use a shallow clone; no credentials supplied.
    cmd = ["git", "clone", "--depth", "1", url, str(dest)]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(
            f"Public clone failed (no auth attempted): {r.stderr.strip()}. "
            f"Private repos / authenticated clones are out of scope for v1."
        )


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Safe read-only clone + scan")
    ap.add_argument("--repo", required=True, help="Local path or public GitHub HTTPS URL")
    ap.add_argument("--old-spec", required=True)
    ap.add_argument("--new-spec", required=True)
    ap.add_argument("--output", default="report")
    ap.add_argument("--keep", action="store_true", help="Keep the temp clone (debug)")
    args = ap.parse_args(argv)

    repo_arg = args.repo
    temp_dir = None
    try:
        if is_github_https(repo_arg):
            temp_dir = Path(tempfile.mkdtemp(prefix="impact_clone_"))
            clone_public(repo_arg, temp_dir)
            repo_path = temp_dir
            print(f"[safe-clone] cloned public repo into {temp_dir}")
        else:
            repo_path = Path(repo_arg).expanduser().resolve()
            if not repo_path.exists():
                print(f"[ERROR] repo path does not exist: {repo_path}", file=sys.stderr)
                return 2

        pipe = ImpactPipeline(repo_path, Path(args.old_spec), Path(args.new_spec))
        res = pipe.run()
        if res.error:
            print(f"[ERROR] {res.error}", file=sys.stderr)
            return 2
        paths = write_reports(res, Path(args.output))
        print(f"[safe-clone] impacts={len(res.impacts)} read_only_safe={res.safety.get('read_only')}")
        print(f"[safe-clone] JSON: {paths['json']}")
        print(f"[safe-clone] MD:   {paths['md']}")
        return 0
    except Exception as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        return 2
    finally:
        if temp_dir is not None and not args.keep:
            shutil.rmtree(temp_dir, ignore_errors=True)
            print(f"[safe-clone] cleaned up temp clone {temp_dir}")


if __name__ == "__main__":
    sys.exit(main())
