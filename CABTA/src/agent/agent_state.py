"""
Agent State Machine - Tracks the phase and context of an autonomous investigation.

Phases: IDLE -> THINKING -> ACTING -> OBSERVING -> REFLECTING -> COMPLETED/FAILED
        At any point the loop may enter WAITING_HUMAN when analyst approval is needed.
"""

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class AgentPhase(str, Enum):
    """Phases of the ReAct reasoning loop."""
    IDLE = "idle"
    THINKING = "thinking"
    ACTING = "acting"
    OBSERVING = "observing"
    REFLECTING = "reflecting"
    WAITING_HUMAN = "waiting_human"
    COMPLETED = "completed"
    FAILED = "failed"


# Allowed phase transitions (source -> set of valid targets)
_TRANSITIONS = {
    AgentPhase.IDLE:          {AgentPhase.THINKING, AgentPhase.FAILED},
    AgentPhase.THINKING:      {AgentPhase.ACTING, AgentPhase.COMPLETED, AgentPhase.FAILED, AgentPhase.WAITING_HUMAN},
    AgentPhase.ACTING:        {AgentPhase.OBSERVING, AgentPhase.FAILED, AgentPhase.WAITING_HUMAN},
    AgentPhase.OBSERVING:     {AgentPhase.REFLECTING, AgentPhase.THINKING, AgentPhase.COMPLETED, AgentPhase.FAILED},
    AgentPhase.REFLECTING:    {AgentPhase.THINKING, AgentPhase.COMPLETED, AgentPhase.FAILED},
    AgentPhase.WAITING_HUMAN: {AgentPhase.ACTING, AgentPhase.THINKING, AgentPhase.FAILED, AgentPhase.COMPLETED},
    AgentPhase.COMPLETED:     set(),
    AgentPhase.FAILED:        set(),
}


@dataclass
class AgentState:
    """Mutable state for a single investigation session."""

    session_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    phase: AgentPhase = AgentPhase.IDLE
    goal: str = ""
    current_tool: Optional[str] = None
    step_count: int = 0
    max_steps: int = 50
    findings: List[Dict[str, Any]] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    pending_approval: Optional[Dict[str, Any]] = field(default=None)
    agent_profile_id: Optional[str] = None
    workflow_id: Optional[str] = None
    specialist_team: List[str] = field(default_factory=list)
    active_specialist: Optional[str] = None
    specialist_index: int = 0
    specialist_handoffs: List[Dict[str, Any]] = field(default_factory=list)
    investigation_plan: Dict[str, Any] = field(default_factory=dict)
    session_snapshot_id: Optional[str] = None
    thread_id: Optional[str] = None
    snapshot_lifecycle: Optional[str] = None
    is_published: bool = False
    restored_memory_scope: Optional[str] = None
    chat_context_restored_memory_scope: Optional[str] = None
    active_observations: List[Dict[str, Any]] = field(default_factory=list)
    accepted_facts: List[Dict[str, Any]] = field(default_factory=list)
    unresolved_questions: List[str] = field(default_factory=list)
    evidence_quality_summary: Dict[str, Any] = field(default_factory=dict)
    fact_family_schemas: Dict[str, Any] = field(default_factory=dict)
    reasoning_state: Dict[str, Any] = field(default_factory=dict)
    entity_state: Dict[str, Any] = field(default_factory=dict)
    evidence_state: Dict[str, Any] = field(default_factory=dict)
    deterministic_decision: Dict[str, Any] = field(default_factory=dict)
    agentic_explanation: Dict[str, Any] = field(default_factory=dict)
    last_approval_outcome: Optional[Dict[str, Any]] = None
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    # ------------------------------------------------------------------ #
    # Phase transitions
    # ------------------------------------------------------------------ #

    def transition(self, new_phase: AgentPhase) -> None:
        """Transition to *new_phase*, raising ValueError on illegal moves."""
        allowed = _TRANSITIONS.get(self.phase, set())
        if new_phase not in allowed:
            raise ValueError(
                f"Invalid transition: {self.phase.value} -> {new_phase.value}. "
                f"Allowed targets: {[p.value for p in allowed]}"
            )
        self.phase = new_phase

    # ------------------------------------------------------------------ #
    # Findings & approval helpers
    # ------------------------------------------------------------------ #

    def add_finding(self, finding: Dict[str, Any]) -> None:
        """Append a tool result / observation to the findings list."""
        stamped = {
            "step": self.step_count,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            **finding,
        }
        self.findings.append(stamped)

    def request_approval(self, action: Dict[str, Any], reason: str, *, context: Optional[Dict[str, Any]] = None) -> None:
        """Park the loop until an analyst approves or rejects *action*."""
        self.pending_approval = {
            "action": action,
            "reason": reason,
            "requested_at": datetime.now(timezone.utc).isoformat(),
            "context": dict(context or {}),
            "status": "pending",
        }

    def clear_approval(self) -> Optional[Dict[str, Any]]:
        """Pop and return the pending approval (if any)."""
        approval = self.pending_approval
        self.pending_approval = None
        return approval

    def configure_specialist_team(self, team: List[str], active_specialist: Optional[str] = None) -> None:
        """Attach a specialist sequence to this session."""
        clean_team = [str(item).strip() for item in team if str(item).strip()]
        self.specialist_team = clean_team
        resolved = str(active_specialist or (clean_team[0] if clean_team else "")).strip() or None
        self.active_specialist = resolved
        if resolved and resolved in clean_team:
            self.specialist_index = clean_team.index(resolved)
        else:
            self.specialist_index = 0
        if resolved:
            self.agent_profile_id = resolved

    def record_specialist_handoff(self, from_profile: Optional[str], to_profile: str, reason: str) -> Dict[str, Any]:
        """Record a specialist handoff event."""
        handoff = {
            "step": self.step_count,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "from_profile": from_profile,
            "to_profile": to_profile,
            "reason": reason,
        }
        self.specialist_handoffs.append(handoff)
        self.active_specialist = to_profile
        self.agent_profile_id = to_profile
        if to_profile in self.specialist_team:
            self.specialist_index = self.specialist_team.index(to_profile)
        return handoff

    # ------------------------------------------------------------------ #
    # Status helpers
    # ------------------------------------------------------------------ #

    def is_terminal(self) -> bool:
        """Return True when the session cannot make further progress."""
        return self.phase in (AgentPhase.COMPLETED, AgentPhase.FAILED)

    def to_dict(self) -> Dict[str, Any]:
        """Serialise the entire state to a plain dict."""
        return {
            "session_id": self.session_id,
            "phase": self.phase.value,
            "goal": self.goal,
            "current_tool": self.current_tool,
            "step_count": self.step_count,
            "max_steps": self.max_steps,
            "findings": self.findings,
            "errors": self.errors,
            "pending_approval": self.pending_approval,
            "agent_profile_id": self.agent_profile_id,
            "workflow_id": self.workflow_id,
            "specialist_team": self.specialist_team,
            "active_specialist": self.active_specialist,
            "specialist_index": self.specialist_index,
            "specialist_handoffs": self.specialist_handoffs,
            "investigation_plan": self.investigation_plan,
            "session_snapshot_id": self.session_snapshot_id,
            "thread_id": self.thread_id,
            "snapshot_lifecycle": self.snapshot_lifecycle,
            "is_published": self.is_published,
            "restored_memory_scope": self.restored_memory_scope,
            "chat_context_restored_memory_scope": self.chat_context_restored_memory_scope,
            "active_observations": self.active_observations,
            "accepted_facts": self.accepted_facts,
            "unresolved_questions": self.unresolved_questions,
            "evidence_quality_summary": self.evidence_quality_summary,
            "fact_family_schemas": self.fact_family_schemas,
            "reasoning_state": self.reasoning_state,
            "entity_state": self.entity_state,
            "evidence_state": self.evidence_state,
            "deterministic_decision": self.deterministic_decision,
            "agentic_explanation": self.agentic_explanation,
            "collaboration_mode": "multi_agent" if len(self.specialist_team) > 1 else "single_agent",
            "created_at": self.created_at,
            "is_terminal": self.is_terminal(),
        }
