#!/usr/bin/env python3
"""
GitHub MVP - CLI entry point.

Usage:
    python3 -m github_mvp.cli scan --repo /path/to/repo \
        --old-spec old.yaml --new-spec new.yaml --output report/

Design:
  * Validates inputs; fails with a clear non-zero exit code on error.
  * Never writes to the analyzed repository (read-only safety verified by fingerprint).
  * Emits machine-readable JSON + human-readable Markdown.
  * Returns exit codes: 0 = success, 2 = invalid input, 3 = repo mutated during scan.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Dict, List

from github_mvp.pipeline import ImpactPipeline, write_reports, DEFAULT_EXCLUDE


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="impact_monitor",
        description="Python-first API dependency impact scanner (read-only, local).",
    )
    sub = p.add_subparsers(dest="command", required=True)

    sp = sub.add_parser("scan", help="Scan a repo for API breaking-change impacts")
    sp.add_argument("--repo", required=True, help="Path to the Python repository to analyze")
    sp.add_argument("--old-spec", required=True, help="Path to the OLD OpenAPI spec (YAML/JSON)")
    sp.add_argument("--new-spec", required=True, help="Path to the NEW OpenAPI spec (YAML/JSON)")
    sp.add_argument("--output", default="report", help="Output directory for reports")
    sp.add_argument("--workdir", default=None,
                    help="Isolated temp workspace (defaults to <repo>/.impact_tmp, cleaned up)")
    sp.add_argument("--exclude", nargs="*", default=None,
                    help=f"Extra exclude glob/prefix patterns (default: {DEFAULT_EXCLUDE})")
    return p


def cmd_scan(args: argparse.Namespace) -> int:
    repo = Path(args.repo).expanduser()
    old = Path(args.old_spec).expanduser()
    new = Path(args.new_spec).expanduser()
    out_dir = Path(args.output).expanduser()
    # Default workdir is None -> pipeline uses a system temp dir OUTSIDE the repo
    # (read-only guarantee). Only honor an explicit --workdir if the user sets one.
    workdir = Path(args.workdir).expanduser() if args.workdir else None

    exclude = DEFAULT_EXCLUDE + (args.exclude or [])

    # Input validation
    problems = []
    if not repo.exists() or not repo.is_dir():
        problems.append(f"--repo does not exist or is not a directory: {repo}")
    if not old.exists():
        problems.append(f"--old-spec not found: {old}")
    if not new.exists():
        problems.append(f"--new-spec not found: {new}")

    # Reject obviously unsafe paths (path traversal guard)
    for label, pth in (("repo", repo), ("old-spec", old), ("new-spec", new)):
        try:
            pth.resolve()
        except Exception as e:
            problems.append(f"{label} path could not be resolved: {e}")

    if problems:
        for msg in problems:
            print(f"[ERROR] {msg}", file=sys.stderr)
        return 2

    try:
        pipe = ImpactPipeline(
            repo, old, new,
            exclude_patterns=exclude,
            workdir=workdir,
        )
        result = pipe.run()
    except Exception as e:  # surface real errors, never pretend success
        print(f"[ERROR] scan failed: {e}", file=sys.stderr)
        return 2

    if result.error:
        print(f"[ERROR] {result.error}", file=sys.stderr)
        return 2

    # SECURITY: the report output dir must NOT live inside the analyzed repo.
    # Writing reports into the repo would mutate it and defeat the read-only guarantee.
    try:
        out_dir.resolve().relative_to(repo.resolve())
        print(f"[ERROR] --output '{out_dir}' is inside the analyzed repo '{repo}'. "
              f"Refusing to write reports inside the repo (read-only guarantee).", file=sys.stderr)
        _cleanup(workdir)
        return 2
    except Exception:
        pass  # output is outside the repo -> OK

    paths = write_reports(result, out_dir)

    # Read-only safety gate (covers the analysis phase)
    if not result.safety.get("read_only", False):
        print("[FAIL] Repository was modified during scan:", file=sys.stderr)
        print(f"  changed={result.safety.get('files_changed')}", file=sys.stderr)
        print(f"  added={result.safety.get('files_added')}", file=sys.stderr)
        print(f"  removed={result.safety.get('files_removed')}", file=sys.stderr)
        # clean temp workdir
        _cleanup(workdir)
        return 3

    # Belt-and-suspenders: re-fingerprint AFTER writing reports, in case --output
    # escaped the guard above or some other path wrote into the repo.
    from github_mvp.pipeline import fingerprint_repo, compare_fingerprints
    after_all = fingerprint_repo(repo)
    before_all = result._before if hasattr(result, "_before") else None
    if before_all is not None:
        d2 = compare_fingerprints(before_all, after_all)
        if d2["changed"] or d2["added"] or d2["removed"]:
            print("[FAIL] Repository changed after report write (read-only violated):",
                  file=sys.stderr)
            _cleanup(workdir)
            return 3

    # Human summary to stdout
    print(f"Breaking changes: {len(result.breaking_changes)}")
    print(f"Code impacts:     {len(result.impacts)}")
    from collections import Counter
    c = Counter(i["confidence"] for i in result.impacts)
    print(f"  HIGH={c.get('HIGH',0)} MEDIUM={c.get('MEDIUM',0)} LOW={c.get('LOW',0)}")
    print(f"Read-only safe:   YES (repo unchanged)")
    print(f"Reports: {paths['json']}")
    print(f"         {paths['md']}")

    _cleanup(workdir)
    return 0


def _cleanup(workdir: Path) -> None:
    """Remove the isolated temp workspace; never touches the analyzed repo."""
    try:
        import shutil
        if workdir.exists():
            shutil.rmtree(workdir, ignore_errors=True)
    except Exception:
        pass


def main(argv: List[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        return cmd_scan(args)
    parser.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
