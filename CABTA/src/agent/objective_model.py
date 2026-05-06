"""Objective contract model for additive AISA orchestration metadata.

This module is intentionally lightweight and dependency-free so Phase 1 can
attach objective metadata without changing legacy planner or tool APIs.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_timerange(value: Any, default_effective: Any = "24h") -> Dict[str, Any]:
    """Return the contract-facing timerange object while preserving legacy values."""
    if isinstance(value, dict):
        requested = value.get("requested") or value.get("value") or value.get("effective") or default_effective or "24h"
        effective = value.get("effective") or value.get("value") or requested or default_effective or "24h"
        source = value.get("source") or "default"
        reason = value.get("normalization_reason") or (
            "none" if source in {"message", "analyst_request", "metadata"} else "default_timerange_applied"
        )
        out = dict(value)
        out.update({
            "requested": str(requested),
            "value": str(requested),
            "effective": str(effective),
            "source": str(source),
            "normalization_reason": str(reason),
        })
        return out
    requested = str(value or default_effective or "24h")
    return {
        "requested": requested,
        "value": requested,
        "effective": requested,
        "source": "default",
        "normalization_reason": "legacy_scalar_normalized",
    }


@dataclass
class EvidenceRequirement:
    requirement_id: str
    capability: str
    required_facets: List[str]
    min_quality: str = "typed_observation"
    blocking: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ObjectiveContract:
    contract_id: str
    objective_type: str
    lane: str
    summary: str
    evidence_requirements: List[EvidenceRequirement]
    success_criteria: List[str]
    analyst_objective: str = ""
    timerange: Dict[str, Any] = field(default_factory=dict)
    requested_backends: List[str] = field(default_factory=list)
    capabilities_required: List[str] = field(default_factory=list)
    constraints: Dict[str, Any] = field(default_factory=dict)
    entities: List[Dict[str, Any]] = field(default_factory=list)
    source_metadata: Dict[str, Any] = field(default_factory=dict)
    approval_requirements: List[str] = field(default_factory=list)
    final_answer_requirements: List[str] = field(default_factory=list)
    effective_timerange: str = "24h"
    degraded_allowed: bool = True
    generated_at: str = field(default_factory=utc_now_iso)
    schema_version: str = "objective-contract/v2"

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload["timerange"] = normalize_timerange(payload.get("timerange"), payload.get("effective_timerange"))
        payload["effective_timerange"] = payload["timerange"].get("effective") or payload.get("effective_timerange")
        payload["analyst_objective"] = self.analyst_objective or self.summary
        payload["evidence_requirements"] = [item.to_dict() for item in self.evidence_requirements]
        payload.setdefault("soc_task_ref", self.source_metadata.get("soc_task_ref", ""))
        payload.setdefault("capabilities_required", list(self.capabilities_required))
        payload.setdefault("action_requirements", [{"capability_id": capability, "required": True} for capability in self.capabilities_required])
        payload.setdefault("clarification_policy", {"ask_only_blocking_questions": True})
        payload.setdefault("approval_requirements", list(self.approval_requirements))
        payload.setdefault("timerange_policy", {"precedence": "analyst_request > follow_up > objective_default > tool_default", "timerange": payload["timerange"]})
        payload.setdefault("backend_policy", {"requested_backends": list(self.requested_backends), "no_unrelated_fallback": True})
        payload.setdefault("progress_requirements", ["emit_task_state", "emit_action", "emit_binding", "emit_preflight", "emit_final_gate"])
        payload["legacy_schema_version"] = "objective-contract/v1"
        return payload


@dataclass
class RequestUnderstanding:
    raw_text: str
    intent: str
    domain: str
    analyst_objective: str
    entities: List[Dict[str, Any]] = field(default_factory=list)
    requested_backends: List[str] = field(default_factory=list)
    timerange: Dict[str, Any] = field(default_factory=dict)
    output_preferences: List[str] = field(default_factory=list)
    uncertainty: List[str] = field(default_factory=list)
    safety_flags: List[str] = field(default_factory=list)
    capabilities_required: List[str] = field(default_factory=list)
    constraints: Dict[str, Any] = field(default_factory=dict)
    source_metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ObjectiveModelBuilder:
    """Build an ObjectiveContract from deterministic request understanding."""

    _FACETS_BY_CAPABILITY = {
        "log.search": ["timestamp", "source_ip", "destination_ip", "action", "device", "raw_event", "backend", "source", "destination", "query_scope"],
        "log.analyze.inline": ["timestamp", "source_ip", "destination_ip", "destination_port", "protocol_app", "host", "source_sourcetype", "certificate", "backend", "raw_event"],
        "email.analyze": ["sender", "recipient", "auth_results", "urls", "attachments"],
        "file.analyze.static": ["file_identity", "hashes", "file_type", "static_indicators"],
        "file.analyze.sandbox": ["behavior", "network", "process", "persistence"],
        "ioc.enrich": ["observable", "reputation", "ownership", "sightings"],
        "ioc.extract": ["observables", "observable_types", "source_artifact"],
        "findings.correlate": ["linked_entities", "timeline", "supporting_evidence"],
        "threat_intel.search": ["threat_context", "source", "confidence"],
        "rule.generate": ["rule_logic", "detection_scope", "test_notes"],
        "ir.approval.request": ["approval_scope", "risk", "requested_action"],
        "case.context.read": ["case_summary", "evidence_refs", "open_questions"],
        "config.capability.explain": ["capability", "availability", "configuration"],
        "email.parse.inline": ["sender", "recipient", "subject", "urls", "body", "headers"],
        "case.summarize": ["case_summary", "evidence_refs", "limitations"],
        "ir.host.contain.propose": ["target", "evidence_refs", "approval_status"],
        "ir.user.disable.propose": ["target", "evidence_refs", "approval_status"],
        "ir.network.block.propose": ["target", "evidence_refs", "approval_status"],
    }

    def build(self, understanding: RequestUnderstanding, runtime: Optional[Dict[str, Any]] = None) -> ObjectiveContract:
        runtime = dict(runtime or {})
        capabilities = list(dict.fromkeys(understanding.capabilities_required or ["ioc.enrich"]))
        timerange = normalize_timerange(understanding.timerange or {}, runtime.get("default_timerange") or "24h")
        effective_timerange = str(timerange.get("effective") or "24h")
        non_blocking_capabilities = {"findings.correlate", "rule.generate", "config.capability.explain"}
        requirements = [
            EvidenceRequirement(
                requirement_id=f"req-{idx + 1}-{capability.replace('.', '-')}",
                capability=capability,
                required_facets=list(self._FACETS_BY_CAPABILITY.get(capability, ["typed_observation"])),
                blocking=capability not in non_blocking_capabilities,
            )
            for idx, capability in enumerate(capabilities)
        ]
        return ObjectiveContract(
            contract_id=str(runtime.get("contract_id") or f"objective-{abs(hash((understanding.raw_text, effective_timerange))) % 10_000_000}"),
            objective_type=understanding.intent,
            lane=understanding.domain,
            summary=understanding.analyst_objective or understanding.raw_text,
            analyst_objective=understanding.analyst_objective or understanding.raw_text,
            timerange=timerange,
            effective_timerange=effective_timerange,
            requested_backends=list(understanding.requested_backends),
            evidence_requirements=requirements,
            success_criteria=self._success_criteria(capabilities),
            capabilities_required=capabilities,
            constraints=dict(understanding.constraints),
            entities=list(understanding.entities),
            source_metadata=dict(understanding.source_metadata),
            approval_requirements=list(understanding.safety_flags),
            final_answer_requirements=[
                "State deterministic evidence separately from interpretation.",
                "Call out degraded or missing capabilities explicitly.",
            ],
            degraded_allowed=True,
        )

    def _success_criteria(self, capabilities: List[str]) -> List[str]:
        criteria = ["Collect typed evidence for each blocking requirement before final claims."]
        if "log.search" in capabilities:
            criteria.append("Preserve analyst-requested timerange through log evidence collection.")
        if "log.analyze.inline" in capabilities:
            criteria.append("Analyze pasted log evidence locally before proposing external SIEM pivots.")
        if "ir.approval.request" in capabilities:
            criteria.append("Do not execute containment until approval is recorded.")
        return criteria
