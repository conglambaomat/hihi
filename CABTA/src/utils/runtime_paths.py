"""Shared runtime path helpers for AISA local persistence with CABTA legacy compatibility."""

from __future__ import annotations

import os
from pathlib import Path


def runtime_home() -> Path:
    explicit = os.environ.get("AISA_HOME") or os.environ.get("CABTA_HOME")
    if explicit:
        return Path(explicit)
    return Path.home() / ".aisa-runtime"


def runtime_cache_dir() -> Path:
    return runtime_home() / "cache"


def legacy_home() -> Path:
    return Path.home() / ".cabta-runtime"


def legacy_blue_team_home() -> Path:
    return Path.home() / ".blue-team-assistant"
