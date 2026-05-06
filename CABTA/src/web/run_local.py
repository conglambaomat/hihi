"""
Stable local runner for AISA Web on Windows/PowerShell.

This avoids depending on ``python -m uvicorn`` CLI behavior in terminals where
stdin/signal handling can cause an immediate graceful shutdown after startup.
"""

from __future__ import annotations

import os

import uvicorn


def main() -> None:
    """Run AISA web with sensible localhost defaults."""
    host = os.environ.get("AISA_HOST") or os.environ.get("CABTA_HOST", "127.0.0.1")
    port = int(os.environ.get("AISA_PORT") or os.environ.get("CABTA_PORT", "3003"))

    uvicorn.run(
        "src.web.app:create_app",
        factory=True,
        host=host,
        port=port,
        log_level="info",
        access_log=True,
    )


if __name__ == "__main__":
    main()
