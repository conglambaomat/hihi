"""Minimal entrypoint for the optional CABTA headless SOC daemon."""

from __future__ import annotations

import json
from pathlib import Path

from src.daemon.service import HeadlessSOCDaemon
from src.utils.config import load_config


def main() -> None:
    project_root = Path(__file__).resolve().parents[2]
    config_path = project_root / "config.yaml"
    config = load_config(str(config_path) if config_path.exists() else None)
    daemon = HeadlessSOCDaemon(config=config)
    print(json.dumps(daemon.build_status(), indent=2))


if __name__ == "__main__":
    main()
