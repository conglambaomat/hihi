"""Persist specialist-team execution as explicit supervised task units."""

from __future__ import annotations

from typing import Any, Dict, List, Optional


class SpecialistSupervisor:
    """Bridge shared-loop orchestration into explicit specialist task records."""

    TERMINAL_MAP = {
        "completed": "completed",
        "failed": "failed",
        "cancelled": "failed",
    }

    def __init__(self, agent_store):
        self.agent_store = agent_store

    def sync_session(
        self,
        session_id: str,
        workflow_id: Optional[str],
        state: Any,
        *,
        reason: str = "",
        terminal_status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        if self.agent_store is None:
            return []

        team = list(getattr(state, "specialist_team", []) or [])
        if not team:
            active = str(getattr(state, "agent_profile_id", "") or "").strip()
            team = [active] if active else []
        if not team:
            return []

        active_specialist = getattr(state, "active_specialist", None) or team[0]
        active_index = team.index(active_specialist) if active_specialist in team else 0
        normalized_terminal = self.TERMINAL_MAP.get(str(terminal_status or "").lower())

        tasks: List[Dict[str, Any]] = []
        for phase_order, profile_id in enumerate(team):
            status = self._resolve_status(
                phase_order=phase_order,
                active_index=active_index,
                terminal_status=normalized_terminal,
            )
            tasks.append(
                self.agent_store.upsert_specialist_task(
                    session_id=session_id,
                    workflow_id=workflow_id,
                    profile_id=profile_id,
                    phase_order=phase_order,
                    status=status,
                    summary=self._build_summary(profile_id, status, reason),
                    metadata={
                        "reason": reason,
                        "active_specialist": active_specialist,
                        "specialist_index": getattr(state, "specialist_index", 0),
                        "step_count": getattr(state, "step_count", 0),
                        "handoff_count": len(getattr(state, "specialist_handoffs", []) or []),
                        "role": "lead" if phase_order == 0 else "supporting",
                    },
                )
            )
        return tasks

    @staticmethod
    def _resolve_status(
        *,
        phase_order: int,
        active_index: int,
        terminal_status: Optional[str],
    ) -> str:
        if terminal_status == "completed":
            return "completed" if phase_order <= active_index else "skipped"
        if terminal_status == "failed":
            if phase_order < active_index:
                return "completed"
            if phase_order == active_index:
                return "failed"
            return "skipped"
        if phase_order < active_index:
            return "completed"
        if phase_order == active_index:
            return "active"
        return "planned"

    @staticmethod
    def _build_summary(profile_id: str, status: str, reason: str) -> str:
        prefix = {
            "planned": "Queued specialist phase",
            "active": "Specialist currently owns the investigation phase",
            "completed": "Specialist phase completed",
            "failed": "Specialist phase ended in failure",
            "skipped": "Specialist phase was skipped after session termination",
        }.get(status, "Specialist phase updated")
        if reason:
            return f"{prefix}: {reason}"
        return f"{prefix}: {profile_id}"
