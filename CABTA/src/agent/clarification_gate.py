"""Clarification and approval gate helpers for AISA SOC chat."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List


@dataclass
class ClarificationGateDecision:
    status: str
    questions: List[str] = field(default_factory=list)
    payloads: List[Dict[str, Any]] = field(default_factory=list)
    schema_version: str = "clarification-gate-decision/v1"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ClarificationGate:
    """Turn blocking gaps into precise analyst questions."""

    def evaluate(self, task_state: Any, planned_actions: List[Dict[str, Any]]) -> ClarificationGateDecision:
        questions: List[str] = []
        payloads: List[Dict[str, Any]] = []
        for action in planned_actions or []:
            preflight = action.get("preflight") if isinstance(action, dict) else None
            binding = action.get("binding") if isinstance(action, dict) else None
            capability = str(action.get("capability_id") or action.get("capability") or "") if isinstance(action, dict) else ""
            if isinstance(binding, dict):
                questions.extend(str(q) for q in binding.get("clarification_questions", []) if str(q).strip())
            if isinstance(preflight, dict) and (preflight.get("clarification_required") or preflight.get("blocking_reasons")):
                if capability == "file.analyze.static":
                    questions.append("Upload/select the malware sample, or provide a hash so AISA can run IOC-only triage instead of fake file analysis.")
                elif capability == "email.parse.inline":
                    questions.append("Paste raw email headers/body if you need a fuller phishing verdict; AISA can still triage visible sender and URLs with limitations.")
                elif capability == "log.search" and not action.get("bound_params", {}).get("backend"):
                    questions.append("Which log backend or environment should AISA search for this hunt?")
                else:
                    questions.extend(str(r) for r in preflight.get("blocking_reasons", []) if str(r).strip())
            if questions:
                payloads.append({"capability_id": capability, "questions": list(dict.fromkeys(questions))})
        status = "clarify" if questions else "pass"
        return ClarificationGateDecision(status=status, questions=list(dict.fromkeys(questions)), payloads=payloads)
