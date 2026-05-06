"""Runtime mode policy helpers for agent execution gates."""

from __future__ import annotations

import os
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
    env_value = os.getenv("AISA_RUNTIME_MODE")
    mode = str(env_value or runtime_mode(config)).strip().lower()
    return mode in {"production", "prod"}


def is_strict_runtime(config: Dict[str, Any] | None, execution_cfg: Dict[str, Any] | None = None) -> bool:
    env_value = os.getenv("AISA_STRICT_DAG_MODE")
    if env_value is not None:
        return truthy(env_value)
    exec_cfg = execution_cfg if isinstance(execution_cfg, dict) else dict(((config or {}).get("agent", {}) or {}).get("execution", {}) or {})
    if "strict_dag_mode" in exec_cfg:
        return truthy(exec_cfg.get("strict_dag_mode"))
    return is_production_mode(config) or runtime_mode(config) == "strict"


def legacy_runtime_allowed(config: Dict[str, Any] | None, execution_cfg: Dict[str, Any] | None = None) -> bool:
    env_value = os.getenv("AISA_ALLOW_LEGACY_RUNTIME_IN_PRODUCTION")
    if env_value is not None:
        return truthy(env_value)
    cfg = config if isinstance(config, dict) else {}
    exec_cfg = execution_cfg if isinstance(execution_cfg, dict) else dict((cfg.get("agent", {}) or {}).get("execution", {}) or {})
    return truthy(exec_cfg.get("allow_legacy_runtime_in_production"))


def strict_only_production(config: Dict[str, Any] | None, execution_cfg: Dict[str, Any] | None = None) -> bool:
    return (is_production_mode(config) or is_strict_runtime(config, execution_cfg)) and not legacy_runtime_allowed(config, execution_cfg)
