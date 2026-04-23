"""Thread sync helpers for agent session snapshots and follow-up commands."""

from __future__ import annotations

import json
from typing import Any, Callable, Dict, List, Optional


class ThreadSyncService:
    """Encapsulate thread snapshot persistence and pending command application."""

    VALID_LIFECYCLES = {"working", "candidate", "accepted", "published"}
    AUTHORITATIVE_LIFECYCLES = {"accepted", "published"}

    def __init__(self, *, thread_store=None, store=None, notify: Optional[Callable[[str, Dict[str, Any]], None]] = None):
        self.thread_store = thread_store
        self.store = store
        self.notify = notify

    @classmethod
    def normalize_lifecycle(cls, value: Any) -> Optional[str]:
        clean = str(value or "").strip().lower()
        if clean in cls.VALID_LIFECYCLES:
            return clean
        return None

    @classmethod
    def authoritative_memory_scope(cls, value: Any) -> Optional[str]:
        lifecycle = cls.normalize_lifecycle(value)
        if lifecycle in cls.AUTHORITATIVE_LIFECYCLES:
            return lifecycle
        return None

    @classmethod
    def memory_kind(cls, value: Any) -> str:
        return "authoritative_case_truth" if cls.authoritative_memory_scope(value) is not None else "working_context"

    @classmethod
    def memory_is_authoritative(cls, value: Any) -> bool:
        return cls.authoritative_memory_scope(value) is not None

    @classmethod
    def publication_scope(cls, value: Any, *, default: str = "working") -> str:
        lifecycle = cls.normalize_lifecycle(value)
        return cls.authoritative_memory_scope(lifecycle) or lifecycle or default

    @classmethod
    def resolve_memory_contract(
        cls,
        payload: Optional[Dict[str, Any]],
        *,
        default_publication_scope: str = "working",
    ) -> Dict[str, Any]:
        payload = payload if isinstance(payload, dict) else {}
        memory_boundary = payload.get("memory_boundary") if isinstance(payload.get("memory_boundary"), dict) else None
        normalized_memory_scope = cls.normalize_lifecycle(
            payload.get("memory_scope")
            or payload.get("authoritative_memory_scope")
        )
        normalized_publication_scope = cls.publication_scope(
            payload.get("publication_scope")
            or (memory_boundary or {}).get("publication_scope")
            or normalized_memory_scope,
            default=default_publication_scope,
        )
        normalized_authoritative_scope = cls.authoritative_memory_scope(
            payload.get("authoritative_memory_scope")
            or normalized_memory_scope
            or normalized_publication_scope
        )
        resolved_memory_scope = normalized_memory_scope or normalized_publication_scope
        memory_is_authoritative = payload.get("memory_is_authoritative")
        if memory_is_authoritative is None:
            memory_is_authoritative = cls.memory_is_authoritative(
                normalized_authoritative_scope or resolved_memory_scope or normalized_publication_scope
            )
        memory_kind = payload.get("memory_kind") or cls.memory_kind(
            normalized_authoritative_scope or resolved_memory_scope or normalized_publication_scope
        )
        return {
            "memory_scope": resolved_memory_scope,
            "authoritative_memory_scope": normalized_authoritative_scope,
            "publication_scope": normalized_publication_scope,
            "memory_kind": str(memory_kind or "").strip().lower() or cls.memory_kind(normalized_publication_scope),
            "memory_is_authoritative": bool(memory_is_authoritative),
            "memory_boundary": memory_boundary if isinstance(memory_boundary, dict) else {},
        }

    @classmethod
    def resolve_session_memory_contract(
        cls,
        payload: Optional[Dict[str, Any]],
        *,
        snapshot: Optional[Dict[str, Any]] = None,
        default_publication_scope: str = "working",
    ) -> Dict[str, Any]:
        payload = payload if isinstance(payload, dict) else {}
        contract = cls.resolve_memory_contract(
            payload,
            default_publication_scope=default_publication_scope,
        )
        has_explicit_contract = any(
            payload.get(key) is not None
            for key in (
                "memory_scope",
                "authoritative_memory_scope",
                "memory_kind",
                "memory_is_authoritative",
            )
        )
        if has_explicit_contract:
            return contract
        if isinstance(snapshot, dict) and snapshot:
            return cls.resolve_memory_contract_from_snapshot(
                snapshot,
                default_publication_scope=default_publication_scope,
            )
        return contract

    @classmethod
    def resolve_memory_contract_from_snapshot(
        cls,
        snapshot: Optional[Dict[str, Any]],
        *,
        default_publication_scope: str = "working",
    ) -> Dict[str, Any]:
        snapshot = snapshot if isinstance(snapshot, dict) else {}
        snapshot_contract = snapshot.get("snapshot_contract", {}) if isinstance(snapshot.get("snapshot_contract"), dict) else {}
        payload = {
            "memory_scope": snapshot.get("snapshot_lifecycle") or snapshot_contract.get("lifecycle"),
            "authoritative_memory_scope": snapshot_contract.get("authoritative_memory_scope"),
            "publication_scope": snapshot_contract.get("publication_scope"),
            "memory_kind": snapshot_contract.get("memory_kind"),
            "memory_is_authoritative": snapshot_contract.get("memory_is_authoritative"),
            "memory_boundary": snapshot.get("memory_boundary"),
        }
        return cls.resolve_memory_contract(payload, default_publication_scope=default_publication_scope)

    @classmethod
    def snapshot_lifecycle_for_state(cls, state: Any) -> str:
        explicit = cls.normalize_lifecycle(getattr(state, "snapshot_lifecycle", ""))
        if explicit:
            return explicit
        if bool(getattr(state, "is_terminal", lambda: False)()):
            if bool(getattr(state, "is_published", False)):
                return "published"
            return "candidate"
        return "working"

    @classmethod
    def finalize_lifecycle_for_state(cls, state: Any) -> str:
        lifecycle = cls.snapshot_lifecycle_for_state(state)
        if lifecycle in cls.VALID_LIFECYCLES:
            setattr(state, "snapshot_lifecycle", lifecycle)
        return lifecycle

    @staticmethod
    def _snapshot_state_for(state: Any) -> str:
        if bool(getattr(state, "is_terminal", lambda: False)()):
            return "accepted"
        return "working"

    @staticmethod
    def _normalized_scope_value(value: Any) -> Optional[str]:
        clean = str(value or "").strip()
        return clean or None

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
        snapshot_lifecycle = self.finalize_lifecycle_for_state(state)
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
            "memory_scope": snapshot_lifecycle,
        }
        fact_family_schemas = getattr(state, "fact_family_schemas", {}) or {}
        case_id = self._normalized_scope_value(getattr(state, "case_id", None))
        thread_id = self._normalized_scope_value(getattr(state, "thread_id", None))
        publication_scope = self.publication_scope(snapshot_lifecycle)
        authoritative_memory_scope = self.authoritative_memory_scope(snapshot_lifecycle)
        memory_kind = self.memory_kind(snapshot_lifecycle)
        memory_is_authoritative = self.memory_is_authoritative(snapshot_lifecycle)
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
            "fact_family_schemas": fact_family_schemas,
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
                "memory_kind": memory_kind,
                "memory_is_authoritative": memory_is_authoritative,
                "authoritative_memory_scope": authoritative_memory_scope,
                "publication_scope": publication_scope,
                "is_terminal": snapshot_lifecycle in {"accepted", "published"},
                "publication_ready": snapshot_lifecycle in {"accepted", "published"},
            },
            "thread_context": thread_context,
            "memory_boundary": {
                "case_id": case_id,
                "thread_id": thread_id,
                "session_id": self._normalized_scope_value(getattr(state, "session_id", None)),
                "snapshot_state": snapshot_state,
                "snapshot_lifecycle": snapshot_lifecycle,
                "publication_scope": publication_scope,
                "authoritative_memory_scope": authoritative_memory_scope,
                "memory_kind": memory_kind,
                "memory_is_authoritative": memory_is_authoritative,
            },
            "case_scope": {
                "case_id": case_id,
            },
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
                "fact_family_schemas": fact_family_schemas,
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
            "pending_thread_command_payload": payload,
            "pending_thread_command_intent": intent or None,
            "pending_thread_command_requires_fresh_evidence": requires_fresh_evidence,
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
            plan = getattr(state, "investigation_plan", {})
            if isinstance(plan, dict):
                resume_signals = plan.get("resume_signals", [])
                if not isinstance(resume_signals, list):
                    resume_signals = []
                resume_signals.append(
                    {
                        "command_id": command.get("id"),
                        "intent": intent or None,
                        "content": content,
                        "requires_fresh_evidence": requires_fresh_evidence,
                        "created_at": command.get("created_at"),
                    }
                )
                plan["resume_signals"] = resume_signals[-8:]
                if requires_fresh_evidence:
                    plan["resume_strategy"] = "fresh_evidence"
                elif content:
                    plan["resume_strategy"] = "answer_from_context"

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