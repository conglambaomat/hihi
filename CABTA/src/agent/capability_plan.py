"""Capability-first plan contracts for AISA SOC orchestration."""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List

from .capability_actions import CapabilityAction, make_action


def _stable_id(prefix: str, *parts: Any) -> str:
    raw = "|".join(str(part) for part in parts if part is not None)
    return f"{prefix}-{hashlib.sha1(raw.encode('utf-8')).hexdigest()[:12]}"


@dataclass
class CapabilityPlan:
    schema_version: str = "capability-plan/v1"
    plan_id: str = ""
    objective_ref: str = ""
    compiled_input_ref: str = ""
    lane: str = "generic"
    actions: List[Dict[str, Any]] = field(default_factory=list)
    requires_evidence: bool = True
    evidence_scope: str = ""
    forbidden_fallbacks: List[str] = field(default_factory=list)
    status: str = "planned"

    def __post_init__(self) -> None:
        if not self.plan_id:
            self.plan_id = _stable_id("capplan", self.objective_ref, self.compiled_input_ref, self.lane, self.actions)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class CapabilityPlanBuilder:
    """Build ordered capabilities from compiled input/objective before legacy tool routing."""

    RAW_LOG_FORBIDDEN = ["email.parse.inline", "email.analyze", "ioc.enrich_as_primary", "file.analyze.static"]
    SOC_ALERT_TEXT_FORBIDDEN = ["file.analyze.static", "email.analyze", "email.parse.inline"]

    def _forbidden_fallbacks(self, compiled: Dict[str, Any]) -> List[str]:
        input_kind = str(compiled.get("input_kind") or "")
        if input_kind == "raw_log_artifact":
            return list(self.RAW_LOG_FORBIDDEN)
        if input_kind == "soc_alert_text":
            return list(dict.fromkeys([*self.SOC_ALERT_TEXT_FORBIDDEN, *self.RAW_LOG_FORBIDDEN]))
        return []

    def build(self, task_state: Any, objective_contract: Dict[str, Any] | None = None) -> CapabilityPlan:
        objective = objective_contract if isinstance(objective_contract, dict) else getattr(task_state, "objective_contract", {}) or {}
        compiled = getattr(task_state, "compiled_input", {}) or objective.get("compiled_input") or {}
        lane = str(compiled.get("lane") or getattr(task_state, "lane", "generic") or objective.get("coverage_lane") or "generic")
        capabilities = list(getattr(task_state, "required_capabilities", []) or objective.get("capabilities_required") or [])
        if not capabilities:
            capabilities = ["log.analyze.inline"] if compiled.get("input_kind") == "raw_log_artifact" else ["config.capability.explain"]
        if compiled.get("input_kind") == "raw_log_artifact" and capabilities[0] != "log.analyze.inline":
            capabilities = ["log.analyze.inline", *[cap for cap in capabilities if cap != "log.analyze.inline"]]
        actions: List[Dict[str, Any]] = []
        for capability in capabilities:
            action: CapabilityAction = make_action(task_state, capability, rationale=f"Capability {capability} selected from compiled input/objective contract.")
            action_payload = action.to_dict()
            action_payload["evidence_scope"] = "pasted_artifact_only" if capability == "log.analyze.inline" else "task_scope"
            action_payload["blocking_coverage"] = capability in {"log.analyze.inline", "log.search", "email.parse.inline", "file.analyze.static", "ioc.enrich"}
            action_payload["forbidden_fallbacks"] = self._forbidden_fallbacks(compiled)
            if capability == "log.analyze.inline":
                action_payload["allowed_tools"] = ["analyze_log_artifact"]
            actions.append(action_payload)
        plan = CapabilityPlan(
            objective_ref=str(objective.get("contract_id") or ""),
            compiled_input_ref=str(compiled.get("compiled_input_id") or ""),
            lane=lane,
            actions=actions,
            evidence_scope=str((compiled.get("evidence_scope") or {}).get("scope") or "task_scope"),
            forbidden_fallbacks=self._forbidden_fallbacks(compiled),
        )
        return plan
