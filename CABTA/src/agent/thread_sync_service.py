"""Thread sync helpers for agent session snapshots and follow-up commands."""

from __future__ import annotations

import json
from typing import Any, Callable, Dict, List, Optional


class ThreadSyncService:
    """Encapsulate thread snapshot persistence and pending command application."""

    def __init__(self, *, thread_store=None, store=None, notify: Optional[Callable[[str, Dict[str, Any]], None]] = None):
        self.thread_store = thread_store
        self.store = store
        self.notify = notify

    @staticmethod
    def _snapshot_state_for(state: Any) -> str:
        if bool(getattr(state, "is_terminal", lambda: False)()):
            return "accepted"
        return "working"

    @staticmethod
    def _snapshot_lifecycle_for(state: Any) -> str:
        explicit = str(getattr(state, "snapshot_lifecycle", "") or "").strip().lower()
        if explicit in {"working", "candidate", "accepted", "published"}:
            return explicit
        if bool(getattr(state, "is_terminal", lambda: False)()):
            if bool(getattr(state, "is_published", False)):
                return "published"
            return "accepted"
        return "working"

    @staticmethod
    def get_working_memory(snapshot: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        snapshot = snapshot if isinstance(snapshot, dict) else {}
        working_memory = snapshot.get("working_memory", {})
        if isinstance(working_memory, dict) and working_memory:
            return working_memory
        return {
            "active_observations": list(snapshot.get("active_observations", []) or []),
            "unresolved_questions": list(snapshot.get("unresolved_questions", []) or []),
            "reasoning_state": snapshot.get("reasoning_state", {}) or {},
            "entity_state": snapshot.get("entity_state", {}) or {},
            "evidence_state": snapshot.get("evidence_state", {}) or {},
        }

    @staticmethod
    def get_accepted_memory(snapshot: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        snapshot = snapshot if isinstance(snapshot, dict) else {}
        accepted_memory = snapshot.get("accepted_memory", {})
        if isinstance(accepted_memory, dict) and accepted_memory:
            return accepted_memory
        return {
            "accepted_facts": list(snapshot.get("accepted_facts", []) or []),
            "deterministic_decision": snapshot.get("deterministic_decision", {}) or {},
            "agentic_explanation": snapshot.get("agentic_explanation", {}) or {},
            "root_cause_assessment": snapshot.get("root_cause_assessment", {}) or {},
            "evidence_quality_summary": snapshot.get("evidence_quality_summary", {}) or {},
        }

    def build_thread_snapshot(self, state: Any) -> Dict[str, Any]:
        active_observations = list(getattr(state, "active_observations", []))[-24:]
        accepted_facts = list(getattr(state, "accepted_facts", []))[-16:]
        unresolved_questions = list(getattr(state, "unresolved_questions", []))
        snapshot_state = self._snapshot_state_for(state)
        snapshot_lifecycle = self._snapshot_lifecycle_for(state)
        investigation_plan = getattr(state, "investigation_plan", {}) or {}
        reasoning_state = getattr(state, "reasoning_state", {}) or {}
        entity_state = getattr(state, "entity_state", {}) or {}
        evidence_state = getattr(state, "evidence_state", {}) or {}
        deterministic_decision = getattr(state, "deterministic_decision", {}) or {}
        agentic_explanation = getattr(state, "agentic_explanation", {}) or {}
        root_cause_assessment = (
            agentic_explanation.get("root_cause_assessment", {})
            if isinstance(agentic_explanation, dict)
            else {}
        )
        evidence_quality_summary = getattr(state, "evidence_quality_summary", {}) or {}
        thread_context = {
            "session_id": getattr(state, "session_id", None),
            "thread_id": getattr(state, "thread_id", None),
            "step_count": int(getattr(state, "step_count", 0) or 0),
            "memory_scope": snapshot_state,
        }
        return {
            "snapshot_state": snapshot_state,
            "snapshot_lifecycle": snapshot_lifecycle,
            "investigation_plan": investigation_plan,
            "reasoning_state": reasoning_state,
            "entity_state": entity_state,
            "evidence_state": evidence_state,
            "deterministic_decision": deterministic_decision,
            "agentic_explanation": agentic_explanation,
            "root_cause_assessment": root_cause_assessment,
            "active_observations": active_observations,
            "accepted_facts": accepted_facts,
            "unresolved_questions": unresolved_questions,
            "evidence_quality_summary": evidence_quality_summary,
            "snapshot_metrics": {
                "active_observation_count": len(active_observations),
                "accepted_fact_count": len(accepted_facts),
                "unresolved_question_count": len(unresolved_questions),
            },
            "memory_layers": {
                "working": "working_memory",
                "accepted": "accepted_memory",
            },
            "lifecycle_memory_layers": {
                "working": "working_memory",
                "candidate": "working_memory",
                "accepted": "accepted_memory",
                "published": "accepted_memory",
            },
            "snapshot_contract": {
                "state_version": "thread-snapshot-lifecycle/v1",
                "working_scope": "mutable_session_context",
                "accepted_scope": "stable_case_ready_context",
                "lifecycle": snapshot_lifecycle,
                "is_terminal": snapshot_lifecycle in {"accepted", "published"},
                "publication_ready": snapshot_lifecycle in {"accepted", "published"},
            },
            "thread_context": thread_context,
            "working_memory": {
                "active_observations": active_observations,
                "unresolved_questions": unresolved_questions,
                "reasoning_state": reasoning_state,
                "entity_state": entity_state,
                "evidence_state": evidence_state,
            },
            "accepted_memory": {
                "accepted_facts": accepted_facts,
                "deterministic_decision": deterministic_decision,
                "agentic_explanation": agentic_explanation,
                "root_cause_assessment": root_cause_assessment,
                "evidence_quality_summary": evidence_quality_summary,
            },
        }

    def sync_thread_snapshot(self, *, session_id: str, state: Any) -> Optional[str]:
        if self.thread_store is None or not getattr(state, "thread_id", None):
            return None
        root_cause = (
            state.agentic_explanation.get("root_cause_assessment", {})
            if isinstance(getattr(state, "agentic_explanation", None), dict)
            else {}
        )
        summary = str(root_cause.get("summary") or "").strip()
        entity_state = getattr(state, "entity_state", {})
        entities = entity_state.get("entities", {}) if isinstance(entity_state, dict) else {}
        pinned_entities = [
            str(entity.get("id") or "")
            for entity in list(entities.values())[:8]
            if isinstance(entity, dict) and str(entity.get("id") or "").strip()
        ]
        snapshot = self.build_thread_snapshot(state)
        return self.thread_store.update_thread_snapshot(
            thread_id=state.thread_id,
            snapshot=snapshot,
            last_session_id=session_id,
            thread_summary=summary or None,
            pinned_entities=pinned_entities,
            pinned_questions=list(getattr(state, "unresolved_questions", [])[:8]),
            status="active" if snapshot.get("snapshot_state") == "working" else "completed",
        )

    def consume_pending_thread_command(
        self,
        *,
        session_id: str,
        state: Any,
        dedupe_text: Callable[[List[str]], List[str]],
    ) -> bool:
        if self.thread_store is None or not getattr(state, "thread_id", None):
            return False
        command = self.thread_store.claim_next_command(state.thread_id)
        if not isinstance(command, dict):
            return False

        payload = command.get("payload", {}) if isinstance(command.get("payload"), dict) else {}
        content = str(command.get("content") or "").strip()
        intent = str(payload.get("intent") or command.get("intent") or "").strip()
        requires_fresh_evidence = bool(payload.get("requires_fresh_evidence"))
        metadata_update = {
            "chat_user_message": content,
            "chat_intent": intent or None,
            "chat_follow_up_requires_fresh_evidence": requires_fresh_evidence,
            "pending_thread_command_id": command.get("id"),
            "pending_thread_command_created_at": command.get("created_at"),
        }
        if self.store is not None:
            self.store.update_session_metadata(session_id, metadata_update, merge=True)

        if content:
            state.unresolved_questions = dedupe_text([content, *getattr(state, "unresolved_questions", [])])[:12]
            if isinstance(getattr(state, "reasoning_state", None), dict):
                existing_questions = [
                    str(item).strip()
                    for item in state.reasoning_state.get("open_questions", [])
                    if str(item).strip()
                ]
                state.reasoning_state["open_questions"] = dedupe_text([content, *existing_questions])[:12]

        if self.store is not None:
            self.store.add_step(
                session_id,
                state.step_count,
                "thread_command",
                json.dumps(
                    {
                        "command_id": command.get("id"),
                        "intent": intent,
                        "content": content,
                        "requires_fresh_evidence": requires_fresh_evidence,
                    },
                    default=str,
                ),
            )

        self.thread_store.complete_command(
            str(command.get("id") or ""),
            result={
                "consumed_by_session_id": session_id,
                "step_number": state.step_count,
                "intent": intent,
            },
        )
        if self.notify is not None:
            self.notify(
                session_id,
                {
                    "type": "thread_command_applied",
                    "step": state.step_count,
                    "thread_id": state.thread_id,
                    "command_id": command.get("id"),
                    "intent": intent,
                },
            )
        return True