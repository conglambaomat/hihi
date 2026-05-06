"""Sub-investigation context contracts for future bounded child tasks."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List


@dataclass
class SubInvestigationContext:
    parent_session_id: str
    child_objective: str
    allowed_tools: List[str] = field(default_factory=list)
    max_steps: int = 3
    inherited_evidence_refs: List[Dict[str, Any]] = field(default_factory=list)
    blocked_claims: List[str] = field(default_factory=lambda: ["final verdict", "numeric score", "deterministic root cause"])
    return_contract: Dict[str, Any] = field(default_factory=lambda: {
        "required_fields": ["summary", "new_evidence_refs", "missing_evidence", "confidence", "tool_results"],
        "authority": "non_authoritative_child_context",
        "authoritative_for_verdict": False,
    })
    schema_version: str = "sub-investigation-context/v1"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class SubInvestigationContextManager:
    """Build and merge non-authoritative child context contracts."""

    def build_child_context(
        self,
        *,
        parent_session_id: str,
        child_objective: str,
        allowed_tools: List[str] | None = None,
        inherited_evidence_refs: List[Dict[str, Any]] | None = None,
        max_steps: int = 3,
    ) -> Dict[str, Any]:
        return SubInvestigationContext(
            parent_session_id=parent_session_id,
            child_objective=child_objective,
            allowed_tools=[str(tool) for tool in (allowed_tools or []) if str(tool).strip()],
            inherited_evidence_refs=[ref for ref in (inherited_evidence_refs or []) if isinstance(ref, dict)][:20],
            max_steps=max(1, min(10, int(max_steps or 3))),
        ).to_dict()

    def build_handoff_packet(self, context_pack: Dict[str, Any], *, child_objective: str, allowed_tools: List[str] | None = None) -> Dict[str, Any]:
        sections = context_pack.get("sections", {}) if isinstance(context_pack, dict) else {}
        evidence_refs = []
        for brief in sections.get("evidence_briefs", []) if isinstance(sections, dict) else []:
            if isinstance(brief, dict) and isinstance(brief.get("evidence_ref"), dict):
                evidence_refs.append(brief["evidence_ref"])
        return self.build_child_context(
            parent_session_id=str(context_pack.get("session_id") or ""),
            child_objective=child_objective,
            allowed_tools=allowed_tools or [],
            inherited_evidence_refs=evidence_refs,
        )

    @staticmethod
    def build_child_result_contract(
        child_context: Dict[str, Any],
        *,
        summary: str = "",
        evidence_refs: List[Dict[str, Any]] | None = None,
        new_entities: List[Dict[str, Any]] | None = None,
        coverage_delta: Dict[str, Any] | None = None,
        hypothesis_updates: List[Dict[str, Any]] | None = None,
        confidence: float = 0.0,
        tool_results: List[Dict[str, Any]] | None = None,
    ) -> Dict[str, Any]:
        child_id = "child-" + str(abs(hash((child_context.get("parent_session_id"), child_context.get("child_objective")))) % 1000000)
        return {
            "schema_version": "sub-investigation-result/v1",
            "child_context_id": child_id,
            "parent_session_id": child_context.get("parent_session_id"),
            "summary": str(summary or ""),
            "evidence_refs": [ref for ref in (evidence_refs or []) if isinstance(ref, dict)][:24],
            "new_evidence_refs": [ref for ref in (evidence_refs or []) if isinstance(ref, dict)][:24],
            "new_entities": [item for item in (new_entities or []) if isinstance(item, dict)][:24],
            "coverage_delta": dict(coverage_delta or {}),
            "hypothesis_updates": [item for item in (hypothesis_updates or []) if isinstance(item, dict)][:12],
            "missing_evidence": [],
            "confidence": max(0.0, min(1.0, float(confidence or 0.0))),
            "tool_results": [item for item in (tool_results or []) if isinstance(item, dict)][:12],
            "authority": "non_authoritative_child_context",
            "authoritative_for_verdict": False,
            "blocked_claims": list(child_context.get("blocked_claims") or []),
            "return_contract": dict(child_context.get("return_contract") or {}),
        }

    @staticmethod
    def merge_child_result_into_reasoning_state(reasoning_state: Dict[str, Any], child_result: Dict[str, Any]) -> Dict[str, Any]:
        """Merge child output into parent reasoning metadata without verdict authority."""
        merged = dict(reasoning_state or {})
        summary = {
            "child_context_id": child_result.get("child_context_id"),
            "summary": child_result.get("summary"),
            "evidence_refs": list(child_result.get("evidence_refs") or [])[:12],
            "new_entities": list(child_result.get("new_entities") or [])[:12],
            "coverage_delta": dict(child_result.get("coverage_delta") or {}),
            "hypothesis_updates": list(child_result.get("hypothesis_updates") or [])[:8],
            "authority": "non_authoritative_child_context",
            "authoritative_for_verdict": False,
        }
        summaries = list(merged.get("sub_investigation_summaries", []) or [])
        summaries.append(summary)
        merged["sub_investigation_summaries"] = summaries[-12:]
        merge_metadata = {
            "schema_version": "sub-investigation-parent-merge/v1",
            "child_context_id": child_result.get("child_context_id"),
            "merged_as": "non_authoritative_reasoning_metadata",
            "evidence_refs_require_tool_origin": True,
            "authoritative_for_verdict": False,
        }
        return {"reasoning_state": merged, "merge_metadata": merge_metadata}

    @staticmethod
    def merge_child_return(parent_context_map: Dict[str, Any], child_return: Dict[str, Any]) -> Dict[str, Any]:
        """Merge child narrative as non-authoritative metadata only."""
        merged = dict(parent_context_map or {})
        child_summary = {
            "summary": child_return.get("summary") if isinstance(child_return, dict) else None,
            "new_evidence_refs": list((child_return or {}).get("new_evidence_refs", []) or []) if isinstance(child_return, dict) else [],
            "missing_evidence": list((child_return or {}).get("missing_evidence", []) or []) if isinstance(child_return, dict) else [],
            "confidence": (child_return or {}).get("confidence") if isinstance(child_return, dict) else None,
            "authority": "non_authoritative_child_context",
            "authoritative_for_verdict": False,
        }
        summaries = list(merged.get("sub_investigation_summaries", []) or [])
        summaries.append(child_summary)
        merged["sub_investigation_summaries"] = summaries[-12:]
        return merged
