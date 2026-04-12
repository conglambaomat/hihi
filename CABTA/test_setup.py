#!/usr/bin/env python3
"""
CABTA setup verification script.

The goal of this script is to reflect the product's actual runtime model:
- core workflows must work locally with a minimal dependency set
- some advanced analyzers enrich results when extra packages are present
- missing optional packages should warn, not incorrectly fail installation
"""

from __future__ import annotations

import importlib
import sys
from typing import Iterable, Tuple


Dependency = Tuple[str, str | None]


def check_dependency(module_name: str) -> bool:
    """Return True when a Python module can be imported."""
    try:
        importlib.import_module(module_name)
        return True
    except ImportError:
        return False


def render_group(title: str, dependencies: Iterable[Dependency], missing_prefix: str) -> list[tuple[str, str | None]]:
    """Print a dependency group and return the missing items."""
    missing: list[tuple[str, str | None]] = []
    print(title)
    print("-" * 40)
    for module_name, package_name in dependencies:
        available = check_dependency(module_name)
        status = "[OK]" if available else missing_prefix
        print(f"  {status} {module_name}")
        if not available:
            missing.append((module_name, package_name))
    print()
    return missing


def main() -> None:
    print("=" * 60)
    print("CABTA - Setup Verification")
    print("=" * 60)
    print()

    core_dependencies: list[Dependency] = [
        ("requests", "requests"),
        ("yaml", "pyyaml"),
        ("pefile", "pefile"),
        ("yara", "yara-python"),
        ("oletools.olevba", "oletools"),
        ("email", None),
        ("zipfile", None),
    ]
    recommended_dependencies: list[Dependency] = [
        # CABTA has graceful fallbacks for both of these.
        ("ssdeep", "ssdeep"),
        ("magic", "python-magic"),
        ("mcp", "mcp"),
    ]
    optional_dependencies: list[Dependency] = [
        ("capa", "capa"),
        ("anthropic", "anthropic"),
        ("openai", "openai"),
    ]

    missing_core = render_group("Core Dependencies:", core_dependencies, "[MISSING]")
    missing_recommended = render_group(
        "Recommended Enhancements:",
        recommended_dependencies,
        "[WARN]",
    )
    missing_optional = render_group(
        "Optional Integrations:",
        optional_dependencies,
        "[WARN]",
    )

    print("=" * 60)

    if missing_core:
        print("[FAIL] CABTA is missing core dependencies.")
        print()
        print("Install with: pip install -r requirements.txt")
        sys.exit(1)

    print("[OK] CABTA core dependencies are installed.")

    if missing_recommended:
        names = ", ".join(module for module, _ in missing_recommended)
        print(f"[WARN] Advanced enrichment will be partially degraded: {names}")
        print(
            "       CABTA still runs, but fuzzy hashing, libmagic-backed detection, "
            "and built-in MCP playbook servers may be limited."
        )

    if missing_optional:
        names = ", ".join(module for module, _ in missing_optional)
        print(f"[WARN] Optional integrations not installed: {names}")

    print()
    print("Quick Start:")
    print("  python -m uvicorn src.web.app:create_app --factory --host 127.0.0.1 --port 3003")
    print("  python -m src.soc_agent ioc 8.8.8.8")
    print("  python -m src.soc_agent file malware.exe")
    print("  python -m src.soc_agent email suspicious.eml")


if __name__ == "__main__":
    main()
