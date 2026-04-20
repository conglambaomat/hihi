"""Case sync helpers for agentic reasoning checkpoints."""

from __future__ import annotations

from typing import Any, Dict, Optional


class CaseSyncService:
    """Persist case-facing reasoning checkpoints without changing verdict authority."""

    def __init__(self, *, case_store=None, case_memory_service=None, entity_resolver=None, evidence_graph=None):
        self.case_store = case_store
        self.case_memory_service = case_memory_service
        self.entity_resolver = entity_resolver
        self.evidence_graph = evidence_graph

    @staticmethod
    def _normalize_snapshot_lifecycle(state: Any) -> Optional[str]:
        snapshot_lifecycle = str(getattr(state, "snapshot_lifecycle", "") or "").strip().lower()
        if snapshot_lifecycle not in {"working", "candidate", "accepted", "published"}:
            return None
        return snapshot_lifecycle

    @staticmethod
    def _case_memory_scope_for_lifecycle(snapshot_lifecycle: Optional[str]) -> Optional[str]:
        if snapshot_lifecycle in {"accepted", "published"}:
            return snapshot_lifecycle
        return None

    def _build_checkpoint_payload(
        self,
        *,
        session_id: str,
        state: Any,
        terminal_status: Optional[str],
        entity_summary: Dict[str, Any],
        evidence_summary: Dict[str, Any],
        root_cause: Dict[str, Any],
    ) -> Dict[str, Any]:
        reasoning_state = getattr(state, "reasoning_state", {}) or {}
        accepted_facts = list(getattr(state, "accepted_facts", []))[-12:]
        unresolved_questions = list(getattr(state, "unresolved_questions", []))
        hypothesis_snapshot = reasoning_state.get("hypotheses", []) if isinstance(reasoning_state, dict) else []

        snapshot_lifecycle = self._normalize_snapshot_lifecycle(state)
        case_memory_scope = self._case_memory_scope_for_lifecycle(snapshot_lifecycle)

        return {
            "session_id": session_id,
            "terminal_status": terminal_status,
            "reasoning_status": reasoning_state.get("status") if isinstance(reasoning_state, dict) else None,
            "thread_id": getattr(state, "thread_id", None),
            "snapshot_lifecycle": snapshot_lifecycle,
            "case_memory_scope": case_memory_scope,
            "case_memory_publication_ready": bool(case_memory_scope),
            "investigation_plan": getattr(state, "investigation_plan", {}),
            "deterministic_decision": getattr(state, "deterministic_decision", {}),
            "root_cause_assessment": root_cause,
            "hypotheses": hypothesis_snapshot[:6],
            "accepted_facts": accepted_facts,
            "unresolved_questions": unresolved_questions,
            "entity_summary": entity_summary,
            "entity_relationships": entity_summary.get("relationships", []) if isinstance(entity_summary, dict) else [],
            "evidence_timeline": evidence_summary.get("timeline", []) if isinstance(evidence_summary, dict) else [],
            "evidence_edges": evidence_summary.get("edges", []) if isinstance(evidence_summary, dict) else [],
            "checkpoint_metrics": {
                "accepted_fact_count": len(accepted_facts),
                "unresolved_question_count": len(unresolved_questions),
                "hypothesis_count": len(hypothesis_snapshot[:6]),
                "entity_relationship_count": len(entity_summary.get("relationships", []) if isinstance(entity_summary, dict) else []),
                "evidence_timeline_count": len(evidence_summary.get("timeline", []) if isinstance(evidence_summary, dict) else []),
            },
            "checkpoint_summary": {
                "has_root_cause": bool(isinstance(root_cause, dict) and root_cause.get("primary_root_cause")),
                "reasoning_status": reasoning_state.get("status") if isinstance(reasoning_state, dict) else None,
                "terminal_status": terminal_status,
                "case_memory_scope": case_memory_scope,
                "case_memory_publication_ready": bool(case_memory_scope),
            },
        }

    def sync_reasoning_checkpoint(
        self,
        *,
        case_id: Optional[str],
        session_id: str,
        state: Any,
        terminal_status: Optional[str] = None,
    ) -> None:
        if not case_id:
            return

        root_cause = (
            state.agentic_explanation.get("root_cause_assessment", {})
            if isinstance(getattr(state, "agentic_explanation", None), dict)
            else {}
        )

        entity_summary = (
            self.entity_resolver.summarize_for_case_event(state.entity_state)
            if self.entity_resolver is not None
            else {}
        )
        evidence_summary = (
            self.evidence_graph.summarize_for_case_event(state.evidence_state)
            if self.evidence_graph is not None
            else {}
        )

        checkpoint_payload = self._build_checkpoint_payload(
            session_id=session_id,
            state=state,
            terminal_status=terminal_status,
            entity_summary=entity_summary,
            evidence_summary=evidence_summary,
            root_cause=root_cause,
        )

        if self.case_memory_service is not None:
            self.case_memory_service.record_reasoning_checkpoint(
                case_id=case_id,
                session_id=session_id,
                terminal_status=terminal_status,
                thread_id=getattr(state, "thread_id", None),
                investigation_plan=getattr(state, "investigation_plan", {}),
                deterministic_decision=getattr(state, "deterministic_decision", {}),
                reasoning_state=getattr(state, "reasoning_state", {}),
                entity_summary=entity_summary,
                evidence_summary=evidence_summary,
                root_cause_assessment=root_cause,
                accepted_facts=getattr(state, "accepted_facts", []),
                unresolved_questions=getattr(state, "unresolved_questions", []),
                snapshot_lifecycle=checkpoint_payload.get("snapshot_lifecycle"),
                checkpoint_metrics=checkpoint_payload["checkpoint_metrics"],
                checkpoint_summary=checkpoint_payload["checkpoint_summary"],
            )
            return

        if self.case_store is None:
            return

        self.case_store.add_event(
            case_id,
            event_type="agentic_reasoning_checkpoint",
            title="Agentic reasoning checkpoint recorded",
            payload=checkpoint_payload,
        )
        if (
            checkpoint_payload.get("case_memory_publication_ready")
            and isinstance(root_cause, dict)
            and root_cause.get("primary_root_cause")
        ):
            self.case_store.add_event(
                case_id,
                event_type="root_cause_assessment",
                title=root_cause.get("summary") or "Root cause assessment updated",
                payload={
                    "session_id": session_id,
                    "terminal_status": terminal_status,
                    "snapshot_lifecycle": checkpoint_payload.get("snapshot_lifecycle"),
                    "root_cause_assessment": root_cause,
                    "deterministic_decision": getattr(state, "deterministic_decision", {}),
                    "thread_id": getattr(state, "thread_id", None),
                    "investigation_plan": getattr(state, "investigation_plan", {}),
                    "accepted_facts": list(getattr(state, "accepted_facts", []))[-12:],
                    "unresolved_questions": getattr(state, "unresolved_questions", []),
                    "entity_summary": entity_summary,
                    "checkpoint_summary": checkpoint_payload["checkpoint_summary"],
                },
            )
