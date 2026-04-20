"""Session context restore and thread message helpers for CABTA agent sessions."""

from __future__ import annotations

import copy
from typing import Any, Dict, Optional


class SessionContextService:
    """Own follow-up context restoration and thread message persistence helpers."""

    def __init__(self, *, store=None, thread_store=None):
        self.store = store
        self.thread_store = thread_store

    @staticmethod
    def _memory_scope_payload(snapshot: Dict[str, Any]) -> tuple[Dict[str, Any], Optional[str]]:
        if not isinstance(snapshot, dict):
            return {}, None

        memory = snapshot.get("memory", {})
        if isinstance(memory, dict):
            published = memory.get("published", {})
            if isinstance(published, dict) and published:
                return published, "published"
            accepted = memory.get("accepted", {})
            if isinstance(accepted, dict) and accepted:
                return accepted, "accepted"

        lifecycle = str(
            snapshot.get("snapshot_lifecycle")
            or (
                snapshot.get("snapshot_contract", {}).get("lifecycle")
                if isinstance(snapshot.get("snapshot_contract"), dict)
                else ""
            )
            or ""
        ).strip().lower()

        accepted_memory = snapshot.get("accepted_memory", {})
        working_memory = snapshot.get("working_memory", {})

        if lifecycle == "published" and isinstance(accepted_memory, dict) and accepted_memory:
            return accepted_memory, "published"
        if lifecycle == "accepted" and isinstance(accepted_memory, dict) and accepted_memory:
            return accepted_memory, "accepted"
        if lifecycle in {"candidate", "working"} and isinstance(working_memory, dict) and working_memory:
            return working_memory, lifecycle

        if isinstance(accepted_memory, dict) and accepted_memory and snapshot.get("snapshot_state") == "accepted":
            return accepted_memory, "accepted"
        if isinstance(working_memory, dict) and working_memory and snapshot.get("snapshot_state") == "working":
            return working_memory, "working"

        return snapshot, None

    @classmethod
    def restore_state_from_snapshot(cls, state: Any, snapshot: Dict[str, Any]) -> Optional[str]:
        if not isinstance(snapshot, dict):
            return None
        payload, memory_scope = cls._memory_scope_payload(snapshot)
        if not payload:
            payload = snapshot
        state.investigation_plan = copy.deepcopy(payload.get("investigation_plan") or state.investigation_plan)
        state.reasoning_state = copy.deepcopy(payload.get("reasoning_state") or {})
        state.entity_state = copy.deepcopy(payload.get("entity_state") or {})
        state.evidence_state = copy.deepcopy(payload.get("evidence_state") or {})
        state.active_observations = copy.deepcopy(
            payload.get("active_observations") or payload.get("normalized_observations") or []
        )
        state.accepted_facts = copy.deepcopy(
            payload.get("accepted_facts") or payload.get("accepted_facts_delta") or []
        )
        state.unresolved_questions = list(payload.get("unresolved_questions") or [])
        state.evidence_quality_summary = copy.deepcopy(payload.get("evidence_quality_summary") or {})
        return memory_scope

    def resolve_thread_id(
        self,
        *,
        session_id: str,
        case_id: Optional[str],
        metadata: Dict[str, Any],
    ) -> Optional[str]:
        requested = str(metadata.get("thread_id") or "").strip()
        if requested:
            return self.thread_store.ensure_thread(
                thread_id=requested,
                case_id=case_id,
                root_session_id=session_id,
            )

        parent_session_id = str(metadata.get("chat_parent_session_id") or "").strip()
        if parent_session_id and self.store is not None:
            parent_session = self.store.get_session(parent_session_id)
            if isinstance(parent_session, dict):
                parent_meta = parent_session.get("metadata", {}) if isinstance(parent_session.get("metadata"), dict) else {}
                parent_thread_id = str(parent_meta.get("thread_id") or "").strip()
                if parent_thread_id:
                    return self.thread_store.ensure_thread(
                        thread_id=parent_thread_id,
                        case_id=case_id or parent_session.get("case_id"),
                        root_session_id=str(parent_meta.get("chat_root_session_id") or parent_session_id),
                    )

        if self.thread_store is None:
            return None
        return self.thread_store.create_thread(
            case_id=case_id,
            root_session_id=session_id,
            status="active",
        )

    def maybe_record_thread_user_message(self, *, state: Any, metadata: Dict[str, Any]) -> None:
        if self.thread_store is None or not state.thread_id:
            return
        if not (
            metadata.get("chat_mode")
            or metadata.get("ui_mode") == "chat"
            or str(metadata.get("response_style") or "").strip().lower() == "conversational"
        ):
            return
        message = str(metadata.get("chat_user_message") or "").strip()
        if not message:
            return
        self.thread_store.append_message(
            thread_id=state.thread_id,
            role="user",
            content=message,
            session_id=state.session_id,
            metadata={
                "chat_parent_session_id": metadata.get("chat_parent_session_id"),
                "intent": metadata.get("chat_intent"),
            },
        )

    def record_thread_assistant_message(self, *, state: Any, content: str) -> None:
        if self.thread_store is None or not state.thread_id:
            return
        clean = str(content or "").strip()
        if not clean:
            return
        self.thread_store.append_message(
            thread_id=state.thread_id,
            role="assistant",
            content=clean,
            session_id=state.session_id,
            metadata={
                "root_cause_status": (
                    state.agentic_explanation.get("root_cause_assessment", {}).get("status")
                    if isinstance(state.agentic_explanation, dict)
                    else None
                ),
            },
        )

    @staticmethod
    def _build_restore_summary(
        *,
        state: Any,
        restored_any: bool,
        restored_source: str,
        restored_memory_scope: Optional[str],
        parent_session_id: str,
        thread_id: Optional[str],
        snapshot_id: Optional[str],
    ) -> Dict[str, Any]:
        active_observations = list(getattr(state, "active_observations", []) or [])
        accepted_facts = list(getattr(state, "accepted_facts", []) or [])
        unresolved_questions = list(getattr(state, "unresolved_questions", []) or [])
        reasoning_state = getattr(state, "reasoning_state", {}) or {}

        return {
            "chat_context_restored": restored_any,
            "chat_context_restored_from_session_id": parent_session_id,
            "chat_context_restored_from_thread_id": thread_id or None,
            "chat_context_restored_snapshot_id": snapshot_id,
            "chat_context_restored_source": restored_source,
            "chat_context_restored_memory_scope": restored_memory_scope,
            "chat_context_restored_findings": 0,
            "chat_context_restored_step_offset": state.step_count,
            "chat_context_restored_counts": {
                "active_observation_count": len(active_observations),
                "accepted_fact_count": len(accepted_facts),
                "unresolved_question_count": len(unresolved_questions),
            },
            "chat_context_restored_reasoning_status": (
                reasoning_state.get("status") if isinstance(reasoning_state, dict) else None
            ),
        }

    def restore_follow_up_context(
        self,
        *,
        session_id: str,
        state: Any,
        metadata: Optional[Dict[str, Any]],
    ) -> bool:
        parent_session_id = str((metadata or {}).get("chat_parent_session_id") or "").strip()
        if not parent_session_id or self.store is None:
            return False

        parent_session = self.store.get_session(parent_session_id)
        if not isinstance(parent_session, dict):
            return False

        parent_metadata = parent_session.get("metadata", {})
        if not isinstance(parent_metadata, dict):
            parent_metadata = {}

        restored = False
        restored_source = "none"
        restored_memory_scope = None
        snapshot_id = None
        thread_id = str((metadata or {}).get("thread_id") or parent_metadata.get("thread_id") or "").strip()
        if thread_id and self.thread_store is not None:
            accepted_snapshot = {}
            get_latest_accepted_snapshot = getattr(self.thread_store, "get_latest_accepted_snapshot", None)
            if callable(get_latest_accepted_snapshot):
                accepted_snapshot = get_latest_accepted_snapshot(thread_id) or {}

            latest_snapshot = accepted_snapshot or (self.thread_store.get_latest_snapshot(thread_id) or {})
            snapshot = latest_snapshot.get("snapshot", {}) if isinstance(latest_snapshot, dict) else {}
            if isinstance(snapshot, dict) and snapshot:
                snapshot_id = latest_snapshot.get("snapshot_id")
                restored_memory_scope = self.restore_state_from_snapshot(state, snapshot)
                restored = True
                restored_source = "thread_snapshot"

        if not restored:
            case_memory_context = (metadata or {}).get("case_memory_context")
            memory_snapshot = {}
            if isinstance(case_memory_context, dict):
                memory_snapshot = (
                    case_memory_context.get("memory_snapshot")
                    or case_memory_context.get("accepted_snapshot")
                    or {}
                )
            if isinstance(memory_snapshot, dict) and memory_snapshot:
                restored_memory_scope = self.restore_state_from_snapshot(state, memory_snapshot)
                snapshot_id = str(case_memory_context.get("latest_session_id") or "").strip() or None
                restored = True
                restored_source = "case_memory"

        if not restored:
            restored_memory_scope = self.restore_state_from_snapshot(
                state,
                {
                    "investigation_plan": parent_metadata.get("investigation_plan") or state.investigation_plan,
                    "reasoning_state": parent_metadata.get("reasoning_state") or {},
                    "entity_state": parent_metadata.get("entity_state") or {},
                    "evidence_state": parent_metadata.get("evidence_state") or {},
                    "normalized_observations": parent_metadata.get("normalized_observations") or [],
                    "accepted_facts": parent_metadata.get("accepted_facts_delta") or parent_metadata.get("accepted_facts") or [],
                    "unresolved_questions": parent_metadata.get("unresolved_questions") or [],
                    "evidence_quality_summary": parent_metadata.get("evidence_quality_summary") or {},
                },
            )
            if state.reasoning_state or state.entity_state or state.evidence_state or state.active_observations:
                restored_source = "parent_session"

        restored_any = bool(
            state.reasoning_state
            or state.entity_state
            or state.evidence_state
            or state.active_observations
            or state.accepted_facts
            or state.unresolved_questions
        )
        state.session_snapshot_id = snapshot_id
        self.store.update_session_metadata(
            session_id,
            self._build_restore_summary(
                state=state,
                restored_any=restored_any,
                restored_source=restored_source,
                restored_memory_scope=restored_memory_scope,
                parent_session_id=parent_session_id,
                thread_id=thread_id or None,
                snapshot_id=snapshot_id,
            ),
            merge=True,
        )
        return restored_any
