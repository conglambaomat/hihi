"""Budgeted retry policy for query coverage gaps."""

from __future__ import annotations

from typing import Any, Dict

_STOP_CLASSES = {"manual_required", "approval_required", "blocked_by_policy", "backend_unavailable", "schema_mismatch"}
_RETRY_CLASSES = {"empty_result", "success_partial", "low_quality_evidence", "transient_error"}


class RetryPolicy:
    def __init__(self, max_attempts_per_gap: int = 2, max_attempts_per_objective: int = 3, max_attempts_per_session: int = 6) -> None:
        self.max_attempts_per_gap = max(1, int(max_attempts_per_gap or 1))
        self.max_attempts_per_objective = max(1, int(max_attempts_per_objective or 1))
        self.max_attempts_per_session = max(1, int(max_attempts_per_session or 1))

    @classmethod
    def from_config(cls, config: Dict[str, Any] | None) -> "RetryPolicy":
        """Build runtime retry budgets from additive log_hunting config."""
        cfg = config if isinstance(config, dict) else {}
        hunting = cfg.get("log_hunting", {}) if isinstance(cfg.get("log_hunting", {}), dict) else {}
        legacy_max = hunting.get("max_retry_attempts")
        per_objective = hunting.get("max_attempts_per_objective", legacy_max if legacy_max is not None else 3)
        return cls(
            max_attempts_per_gap=int(hunting.get("max_attempts_per_gap", 2) or 2),
            max_attempts_per_objective=int(per_objective or 3),
            max_attempts_per_session=int(hunting.get("max_attempts_per_session", 6) or 6),
        )

    def decide(self, *, result_class: str, gap: str, objective: str, retry_state: Dict[str, Any] | None = None) -> Dict[str, Any]:
        state = retry_state if isinstance(retry_state, dict) else {}
        attempts = [item for item in state.get("attempts", []) if isinstance(item, dict)]
        if result_class in _STOP_CLASSES:
            return {"action": "stop", "stop_reason": result_class, "retry_allowed": False}
        if result_class == "success_sufficient":
            return {"action": "stop", "stop_reason": "coverage_sufficient", "retry_allowed": False}
        session_count = len(attempts)
        gap_count = sum(1 for item in attempts if item.get("gap") == gap)
        objective_count = sum(1 for item in attempts if item.get("objective") == objective)
        if session_count >= self.max_attempts_per_session:
            return {"action": "stop", "stop_reason": "session_retry_budget_exhausted", "retry_allowed": False}
        if gap_count >= self.max_attempts_per_gap:
            return {"action": "stop", "stop_reason": "gap_retry_budget_exhausted", "retry_allowed": False}
        if objective_count >= self.max_attempts_per_objective:
            return {"action": "stop", "stop_reason": "objective_retry_budget_exhausted", "retry_allowed": False}
        if result_class in _RETRY_CLASSES:
            return {"action": "retry", "retry_allowed": True, "retry_reason": f"{result_class} leaves coverage gap {gap}."}
        return {"action": "stop", "stop_reason": "unhandled_result_class", "retry_allowed": False}
