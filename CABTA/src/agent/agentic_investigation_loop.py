"""Planner-executor-reflector primitives for agentic SOC investigations.

These small abstractions keep the legacy ReAct runtime compatible while giving
callers a typed contract for milestones, required pivots, and completion review.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

from .investigation_completeness import CompletionDecision, InvestigationCompletenessGate, InvestigationState, NextActionSignal


@dataclass
class PlannerExecutorReflectorResult:
    schema_version: str = "planner-executor-reflector-result/v1"
    investigation_state: Dict[str, Any] = field(default_factory=dict)
    planned_actions: List[Dict[str, Any]] = field(default_factory=list)
    executable_actions: List[Dict[str, Any]] = field(default_factory=list)
    reflection: Dict[str, Any] = field(default_factory=dict)
    completion: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class InvestigationPlannerExecutorReflector:
    """Builds a deterministic plan/reflection snapshot from current agent state."""

    def __init__(self, completeness_gate: Optional[InvestigationCompletenessGate] = None) -> None:
        self.completeness_gate = completeness_gate or InvestigationCompletenessGate()

    def plan(self, agent_state: Any, candidate_answer: str = "") -> PlannerExecutorReflectorResult:
        inv_state = self.completeness_gate.build_state(agent_state)
        completion = self.completeness_gate.evaluate(agent_state, candidate_answer)
        executable = self._select_executable(inv_state.next_actions)
        reflection = self.reflect(inv_state, completion)
        return PlannerExecutorReflectorResult(
            investigation_state=inv_state.to_dict(),
            planned_actions=[a.to_dict() for a in inv_state.next_actions],
            executable_actions=[a.to_dict() for a in executable],
            reflection=reflection,
            completion=completion.to_dict(),
        )

    def reflect(self, inv_state: InvestigationState, completion: CompletionDecision) -> Dict[str, Any]:
        completed = set(inv_state.completed_milestones)
        missing = [m for m in inv_state.milestones if m not in completed]
        return {
            "schema_version": "investigation-reflection/v1",
            "investigation_id": inv_state.investigation_id,
            "status": completion.status,
            "stop_reason": completion.stop_reason,
            "completed_milestones": sorted(completed),
            "missing_milestones": missing,
            "root_cause_ready": "root_cause" in completed,
            "threat_story_ready": bool(inv_state.threat_story) or "threat_story" in completed,
            "required_followups": [a.to_dict() for a in completion.pending_actions],
            "budget_exhausted": completion.budget_exhausted,
        }

    @staticmethod
    def _select_executable(actions: List[NextActionSignal]) -> List[NextActionSignal]:
        return [
            action
            for action in actions
            if action.required and action.status in {"pending", "planned"} and action.tool_hint not in {"", "none"}
        ]
