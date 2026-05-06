"""Typed capability action contracts for AISA SOC orchestration."""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


def stable_action_id(*parts: Any) -> str:
    raw = "|".join(str(part) for part in parts if part is not None)
    return "action-" + hashlib.sha1(raw.encode("utf-8")).hexdigest()[:12]


@dataclass
class CapabilityAction:
    schema_version: str = "capability-action/v1"
    action_id: str = ""
    task_ref: str = ""
    objective_ref: str = ""
    capability_id: str = ""
    action_type: str = "collect_evidence"
    params_schema: str = ""
    bound_params: Dict[str, Any] = field(default_factory=dict)
    expected_evidence: List[Dict[str, Any]] = field(default_factory=list)
    preconditions: List[Dict[str, Any]] = field(default_factory=list)
    approval_policy: Dict[str, Any] = field(default_factory=dict)
    rationale: str = ""
    status: str = "planned"
    legacy_tool_hint: Optional[str] = None

    def __post_init__(self) -> None:
        if not self.action_id:
            self.action_id = stable_action_id(self.task_ref, self.objective_ref, self.capability_id, self.action_type, self.rationale)
        if not self.params_schema and self.capability_id:
            self.params_schema = f"{self.capability_id}.params/v1"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: Dict[str, Any]) -> "CapabilityAction":
        payload = dict(payload or {})
        valid = set(cls.__dataclass_fields__.keys())
        return cls(**{key: value for key, value in payload.items() if key in valid})


CAPABILITY_TO_LEGACY_TOOL = {
    "log.search": "search_logs",
    "log.analyze.inline": "analyze_log_artifact",
    "email.analyze": "analyze_email",
    "email.parse.inline": "analyze_email",
    "file.analyze.static": "analyze_malware",
    "ioc.enrich": "investigate_ioc",
    "ioc.extract": "extract_iocs",
    "case.summarize": None,
    "correlate.findings": "correlate_findings",
    "findings.correlate": "correlate_findings",
    "ir.approval.request": None,
    "ir.host.contain.propose": None,
    "ir.user.disable.propose": None,
    "ir.network.block.propose": None,
    "config.capability.explain": None,
    "clarification.request": None,
}


def action_type_for_capability(capability_id: str) -> str:
    capability_id = str(capability_id or "")
    if capability_id == "clarification.request":
        return "ask_clarification"
    if capability_id == "ir.approval.request":
        return "request_approval"
    if capability_id.startswith("ir."):
        return "propose_response_action"
    if capability_id in {"email.analyze", "email.parse.inline", "file.analyze.static", "log.analyze.inline"}:
        return "analyze_artifact"
    if capability_id.startswith("ioc."):
        return "enrich_ioc" if capability_id == "ioc.enrich" else "collect_evidence"
    if capability_id in {"case.summarize", "task.summarize"}:
        return "summarize"
    return "collect_evidence"


def make_action(task_state: Any, capability_id: str, *, rationale: str = "", status: str = "planned") -> CapabilityAction:
    objective = getattr(task_state, "objective_contract", {}) or {}
    return CapabilityAction(
        task_ref=getattr(task_state, "task_id", ""),
        objective_ref=str(objective.get("contract_id") or ""),
        capability_id=capability_id,
        action_type=action_type_for_capability(capability_id),
        expected_evidence=[{"capability_id": capability_id, "role": "primary"}],
        approval_policy={"approval_required": capability_id.startswith("ir.")},
        rationale=rationale or f"Capability {capability_id} required by SOC task state.",
        status=status,
        legacy_tool_hint=CAPABILITY_TO_LEGACY_TOOL.get(capability_id),
    )
