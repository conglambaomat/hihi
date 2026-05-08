"""Runtime mode policy helpers for agent execution gates."""

from __future__ import annotations

from typing import Any, Dict


def truthy(value: Any) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on", "strict", "production", "prod"}


def runtime_mode(config: Dict[str, Any] | None) -> str:
    cfg = config if isinstance(config, dict) else {}
    return str(
        (cfg.get("runtime", {}) or {}).get("mode")
        or (cfg.get("agent", {}) or {}).get("runtime_mode")
        or ""
    ).strip().lower()


def is_production_mode(config: Dict[str, Any] | None) -> bool:
    """Runtime SOC is always production-grade for agentic execution gates."""
    return True


def is_strict_runtime(config: Dict[str, Any] | None, execution_cfg: Dict[str, Any] | None = None) -> bool:
    """Agentic strict DAG execution is mandatory and cannot be disabled by config/env."""
    return True


def legacy_runtime_allowed(config: Dict[str, Any] | None, execution_cfg: Dict[str, Any] | None = None) -> bool:
    """Legacy/non-agentic runtime fallbacks are removed from normal runtime policy."""
    return False


def strict_only_production(config: Dict[str, Any] | None, execution_cfg: Dict[str, Any] | None = None) -> bool:
    return True
