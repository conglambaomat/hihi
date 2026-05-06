"""LLM-backed final review guard for SOC investigation answers.

The reviewer is intentionally safe-by-default: if no LLM callable is supplied it
falls back to deterministic completeness and rejects only clear gaps.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Dict, List, Optional

from .investigation_completeness import CompletionDecision, InvestigationState, NextActionSignal


REVIEWER_RESPONSE_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "required": ["approved", "rationale", "confidence", "required_followups"],
    "properties": {
        "approved": {"type": "boolean"},
        "rationale": {"type": "string"},
        "confidence": {"type": "string", "enum": ["low", "medium", "high"]},
        "required_followups": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "action_type": {"type": "string"},
                    "rationale": {"type": "string"},
                    "query_focus": {"type": "string"},
                },
            },
        },
        "gap_analysis": {"type": "array", "items": {"type": "string"}},
    },
}


@dataclass
class ReviewerDecision:
    approved: bool
    rationale: str
    required_followups: List[NextActionSignal] = field(default_factory=list)
    confidence: str = "medium"
    raw_response: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload["required_followups"] = [a.to_dict() if hasattr(a, "to_dict") else dict(a) for a in self.required_followups]
        return payload


class FinalInvestigationReviewer:
    """Reviews candidate finals for root-cause completeness and evidence grounding."""

    def __init__(self, llm_reviewer: Optional[Callable[[str], Any]] = None, *, strict_failure: bool = False) -> None:
        self.llm_reviewer = llm_reviewer
        self.strict_failure = strict_failure

    def review(self, *, investigation_state: InvestigationState, completion: CompletionDecision, candidate_answer: str) -> ReviewerDecision:
        if not completion.allowed or completion.budget_exhausted:
            return ReviewerDecision(
                approved=completion.budget_exhausted,
                rationale="Deterministic completeness gate has not approved a complete final answer.",
                required_followups=list(completion.pending_actions),
                confidence="high",
            )
        deterministic_reject = self._deterministic_review(investigation_state, candidate_answer)
        if deterministic_reject is not None:
            return deterministic_reject
        if self.llm_reviewer is None:
            return ReviewerDecision(True, "Deterministic reviewer found no remaining root-cause or evidence gaps.", confidence="medium")
        prompt = self._prompt(investigation_state, candidate_answer)
        try:
            raw = self.llm_reviewer(prompt)
            parsed = self._parse(raw)
        except Exception as exc:  # pragma: no cover - defensive safety path
            if self.strict_failure:
                return ReviewerDecision(False, f"Reviewer failed closed: {exc}", confidence="low")
            return ReviewerDecision(True, f"Reviewer unavailable; deterministic gate remains authoritative: {exc}", confidence="low")
        if parsed.get("approved") is False:
            followups = [
                NextActionSignal("", str(item.get("action_type") or "reviewer_followup"), str(item.get("rationale") or "Reviewer requested follow-up"), query_focus=str(item.get("query_focus") or ""), priority=20)
                for item in parsed.get("required_followups", [])
                if isinstance(item, dict)
            ]
            return ReviewerDecision(False, str(parsed.get("rationale") or "Reviewer rejected final answer."), followups, str(parsed.get("confidence") or "medium"), parsed)
        return ReviewerDecision(True, str(parsed.get("rationale") or "Reviewer approved final answer."), confidence=str(parsed.get("confidence") or "medium"), raw_response=parsed)

    def _deterministic_review(self, state: InvestigationState, answer: str) -> Optional[ReviewerDecision]:
        evidence_ids = {str(item.get("evidence_id")) for item in state.evidence_items if isinstance(item, dict) and item.get("evidence_id")}
        if evidence_ids and not re.search(r"\bE\d+\b|evidence", answer, flags=re.IGNORECASE):
            return ReviewerDecision(False, "Final answer must cite evidence IDs or explicit evidence references.", [NextActionSignal("", "cite_evidence", "Add evidence citations to final answer", tool_hint="none", required=True, priority=30)], "high")
        if state.input_type == "raw_log" and not re.search(r"root cause|threat story|timeline|coverage", answer, flags=re.IGNORECASE):
            return ReviewerDecision(False, "Raw-log final answer must include root cause/threat story and coverage.", [NextActionSignal("", "write_threat_story", "Summarize root cause, timeline and coverage", tool_hint="none", required=True, priority=25)], "high")
        return None

    @staticmethod
    def _prompt(state: InvestigationState, answer: str) -> str:
        return json.dumps(
            {
                "task": "review_soc_investigation_final",
                "response_schema": REVIEWER_RESPONSE_SCHEMA,
                "contract": "Reject unless root cause, threat story, coverage, limitations, and evidence citations are present.",
                "state": state.to_dict(),
                "candidate_answer": answer,
            },
            default=str,
        )

    @staticmethod
    def _parse(raw: Any) -> Dict[str, Any]:
        if isinstance(raw, dict):
            return raw
        text = str(raw or "").strip()
        if not text:
            return {"approved": True, "rationale": "Empty reviewer response ignored."}
        match = re.search(r"\{.*\}", text, flags=re.DOTALL)
        if match:
            return json.loads(match.group(0))
        return {"approved": "reject" not in text.lower(), "rationale": text[:500]}
