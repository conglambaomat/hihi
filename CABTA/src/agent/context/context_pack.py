"""Dict-safe context pack models for AISA agent orchestration."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

AUTHORITY_POLICY = "deterministic_evidence_scoring_and_root_cause_remain_authoritative"


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _clean_dict(value: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    return dict(value or {}) if isinstance(value, dict) else {}


@dataclass
class ContextRequest:
    """Inputs used to build a model-call context pack."""

    session_id: str
    step_number: int
    objective: str = "decide_next_tool"
    model: str = ""
    prompt_mode: str = ""
    analyst_focus: str = ""
    tools_block: str = ""
    findings_block: str = ""
    reasoning_block: str = ""
    workflow_block: str = ""
    playbooks_block: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ContextBlock:
    """A selected or candidate context item with audit metadata."""

    block_id: str
    kind: str
    section: str
    content: Any
    token_estimate: int = 0
    score: float = 0.0
    authority: str = "agentic_explanation"
    authoritative_for_verdict: bool = False
    evidence_refs: List[Dict[str, Any]] = field(default_factory=list)
    reason: str = ""
    do_not_drop: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload["authoritative_for_verdict"] = bool(self.authoritative_for_verdict)
        payload["do_not_drop"] = bool(self.do_not_drop)
        payload["score"] = round(float(self.score or 0.0), 4)
        payload["token_estimate"] = int(self.token_estimate or 0)
        return payload


@dataclass
class SOCContextPack:
    """Prompt-ready context pack; orchestration metadata only."""

    pack_id: str
    session_id: str
    step_number: int
    objective: str
    sections: Dict[str, Any] = field(default_factory=dict)
    token_estimate: Dict[str, Any] = field(default_factory=dict)
    budget_report: Dict[str, Any] = field(default_factory=dict)
    ledger: Dict[str, Any] = field(default_factory=dict)
    ledger_id: str = ""
    context_map_summary: Dict[str, Any] = field(default_factory=dict)
    authority_policy: str = AUTHORITY_POLICY
    schema_version: str = "context-package/v1"
    objective_ref: str = ""
    selection_policy: Dict[str, Any] = field(default_factory=lambda: {"strategy": "relevance_budgeted", "include_raw_history": False})
    omitted_refs: List[str] = field(default_factory=list)
    created_at: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "pack_id": self.pack_id,
            "package_id": self.pack_id,
            "objective_ref": self.objective_ref,
            "session_id": self.session_id,
            "step_number": self.step_number,
            "objective": self.objective,
            "authority_policy": self.authority_policy,
            "sections": _clean_dict(self.sections),
            "token_estimate": _clean_dict(self.token_estimate),
            "budget_report": _clean_dict(self.budget_report),
            "budget": _clean_dict(self.budget_report),
            "selection_policy": _clean_dict(self.selection_policy),
            "omitted_refs": list(self.omitted_refs),
            "ledger_id": self.ledger_id,
            "ledger": _clean_dict(self.ledger),
            "context_map_summary": _clean_dict(self.context_map_summary),
            "created_at": self.created_at,
        }

    def summary(self) -> Dict[str, Any]:
        sections = _clean_dict(self.sections)
        return {
            "schema_version": "context-package-summary/v1",
            "pack_id": self.pack_id,
            "package_id": self.pack_id,
            "objective_ref": self.objective_ref,
            "session_id": self.session_id,
            "step_number": self.step_number,
            "objective": self.objective,
            "ledger_id": self.ledger_id,
            "authority_policy": self.authority_policy,
            "token_estimate": _clean_dict(self.token_estimate),
            "budget_report": {
                key: value
                for key, value in _clean_dict(self.budget_report).items()
                if key in {"model", "usable_tokens", "estimated_total", "over_budget", "compression_target_tokens"}
            },
            "section_counts": {
                "selected_findings": len(sections.get("selected_findings", []) or []),
                "evidence_briefs": len(sections.get("evidence_briefs", []) or []),
                "entities": len(sections.get("entities", []) or []),
                "hypotheses": len(sections.get("hypotheses", []) or []),
                "coverage_gaps": len(sections.get("coverage_gaps", []) or []),
            },
            "created_at": self.created_at,
            "authoritative_for_verdict": False,
        }
