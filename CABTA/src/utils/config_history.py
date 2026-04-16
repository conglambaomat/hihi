"""
Local git-backed history for sensitive CABTA configuration.

This keeps ``config.yaml`` restorable without pushing secrets into the main
repository or remote origins.
"""

from __future__ import annotations

import argparse
import logging
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

HISTORY_DIRNAME = ".config-history"
TRACKED_FILENAME = "config.yaml"


def history_repo_dir(config_file: str | Path) -> Path:
    """Return the local-only git history directory for a config file."""
    config_path = Path(config_file).resolve()
    return config_path.parent / HISTORY_DIRNAME


def _run_git(history_dir: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess:
    """Run a git command inside the local history repo."""
    return subprocess.run(
        ["git", *args],
        cwd=str(history_dir),
        check=check,
        capture_output=True,
        text=True,
    )


def ensure_history_repo(config_file: str | Path) -> Path:
    """Create and initialize the local history repo if missing."""
    config_path = Path(config_file).resolve()
    repo_dir = history_repo_dir(config_path)
    repo_dir.mkdir(parents=True, exist_ok=True)

    if not (repo_dir / ".git").exists():
        _run_git(repo_dir, "init", "-q")
        _run_git(repo_dir, "config", "user.name", "CABTA Local Config History")
        _run_git(repo_dir, "config", "user.email", "local@cabta.invalid")

        readme = repo_dir / "README.md"
        if not readme.exists():
            readme.write_text(
                "# CABTA Local Config History\n\n"
                "This nested git repository stores local-only snapshots of `config.yaml`.\n"
                "Do not publish or push it to public remotes.\n",
                encoding="utf-8",
            )
        _run_git(repo_dir, "add", "README.md")
        _run_git(repo_dir, "commit", "-q", "-m", "Initialize local config history")

    return repo_dir


def snapshot_config(
    config_file: str | Path,
    *,
    reason: str = "manual snapshot",
) -> Dict[str, Any]:
    """Commit the current config.yaml into the local history repo if changed."""
    config_path = Path(config_file).resolve()
    if not config_path.exists():
        return {
            "status": "missing",
            "config_file": str(config_path),
            "history_dir": str(history_repo_dir(config_path)),
        }

    repo_dir = ensure_history_repo(config_path)
    tracked_path = repo_dir / TRACKED_FILENAME
    shutil.copy2(config_path, tracked_path)

    _run_git(repo_dir, "add", TRACKED_FILENAME)
    diff = _run_git(repo_dir, "diff", "--cached", "--quiet", "--exit-code", check=False)
    if diff.returncode == 0:
        return {
            "status": "unchanged",
            "config_file": str(config_path),
            "history_dir": str(repo_dir),
        }

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
    message = f"{timestamp} {reason}".strip()
    _run_git(repo_dir, "commit", "-q", "-m", message)
    revision = _run_git(repo_dir, "rev-parse", "HEAD").stdout.strip()

    return {
        "status": "saved",
        "revision": revision,
        "message": message,
        "config_file": str(config_path),
        "history_dir": str(repo_dir),
    }


def list_history(config_file: str | Path, *, limit: int = 20) -> List[Dict[str, str]]:
    """Return recent history entries for config snapshots."""
    config_path = Path(config_file).resolve()
    repo_dir = ensure_history_repo(config_path)
    result = _run_git(
        repo_dir,
        "log",
        f"-n{max(limit, 1)}",
        "--pretty=format:%H%x09%ad%x09%s",
        "--date=iso-strict",
        "--",
        TRACKED_FILENAME,
        check=False,
    )

    entries: List[Dict[str, str]] = []
    for line in (result.stdout or "").splitlines():
        revision, commit_date, subject = (line.split("\t", 2) + ["", "", ""])[:3]
        if revision:
            entries.append(
                {
                    "revision": revision,
                    "date": commit_date,
                    "subject": subject,
                }
            )
    return entries


def restore_snapshot(
    config_file: str | Path,
    revision: str,
    *,
    reason: str = "manual restore",
) -> Dict[str, Any]:
    """Restore config.yaml from a saved revision and snapshot the restore."""
    config_path = Path(config_file).resolve()
    repo_dir = ensure_history_repo(config_path)

    if config_path.exists():
        snapshot_config(config_path, reason=f"pre-restore backup ({revision})")

    blob = _run_git(repo_dir, "show", f"{revision}:{TRACKED_FILENAME}")
    config_path.write_text(blob.stdout, encoding="utf-8")
    restored = snapshot_config(config_path, reason=f"{reason} ({revision})")

    return {
        "status": "restored",
        "revision": revision,
        "config_file": str(config_path),
        "history_dir": str(repo_dir),
        "post_restore_snapshot": restored,
    }


def _default_config_path() -> Path:
    project_root = Path(__file__).resolve().parents[2]
    return project_root / "config.yaml"


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entrypoint for local config history operations."""
    parser = argparse.ArgumentParser(description="Manage local git-backed history for CABTA config.yaml")
    parser.add_argument(
        "--config",
        default=str(_default_config_path()),
        help="Path to config.yaml (default: CABTA/config.yaml)",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("init", help="Initialize the local history repository")

    snapshot_parser = subparsers.add_parser("snapshot", help="Save a config snapshot if changed")
    snapshot_parser.add_argument("-m", "--message", default="manual snapshot", help="Commit message suffix")

    log_parser = subparsers.add_parser("log", help="Show recent config history")
    log_parser.add_argument("-n", "--limit", type=int, default=20, help="Maximum entries to show")

    restore_parser = subparsers.add_parser("restore", help="Restore config.yaml from a revision")
    restore_parser.add_argument("revision", help="Git revision or commit hash to restore")
    restore_parser.add_argument("-m", "--message", default="manual restore", help="Restore reason")

    args = parser.parse_args(argv)
    config_path = Path(args.config).resolve()

    if args.command == "init":
        repo_dir = ensure_history_repo(config_path)
        print(repo_dir)
        return 0

    if args.command == "snapshot":
        result = snapshot_config(config_path, reason=args.message)
        print(result)
        return 0

    if args.command == "log":
        for entry in list_history(config_path, limit=args.limit):
            print(f"{entry['revision'][:12]}  {entry['date']}  {entry['subject']}")
        return 0

    if args.command == "restore":
        result = restore_snapshot(config_path, args.revision, reason=args.message)
        print(result)
        return 0

    parser.error("Unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
