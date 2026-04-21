"""Case-level accepted memory built on top of CaseStore and AgentStore."""

from __future__ import annotations

from typing import Any, Dict, List, Optional


class CaseMemoryService:
    """Persist and retrieve accepted case memory without adding a new DB layer."""

    def __init__(self, *, case_store=None, agent_store=None):
        self.case_store = case_store
        self.agent_store = agent_store

    def record_reasoning_checkpoint(
        self,
        *,
        case_id: str,
        session_id: str,
        terminal_status: Optional[str],
        thread_id: Optional[str],
        investigation_plan: Dict[str, Any],
        deterministic_decision: Dict[str, Any],
        reasoning_state: Dict[str, Any],
        entity_summary: Dict[str, Any],
        evidence_summary: Dict[str, Any],
        root_cause_assessment: Dict[str, Any],
        accepted_facts: List[Dict[str, Any]],
        unresolved_questions: List[str],
        snapshot_lifecycle: Optional[str] = None,
        checkpoint_metrics: Optional[Dict[str, Any]] = None,
        checkpoint_summary: Optional[Dict[str, Any]] = None,
    ) -> None:
        if self.case_store is None or not case_id:
            return

        hypotheses = reasoning_state.get("hypotheses", []) if isinstance(reasoning_state, dict) else []
        normalized_lifecycle = str(snapshot_lifecycle or "").strip().lower()
        if normalized_lifecycle not in {"working", "candidate", "accepted", "published"}:
            normalized_lifecycle = ""

        payload = {
            "session_id": session_id,
            "terminal_status": terminal_status,
            "thread_id": thread_id,
            "snapshot_lifecycle": normalized_lifecycle or None,
            "memory_scope": normalized_lifecycle if normalized_lifecycle in {"accepted", "published"} else None,
            "memory_boundary": {
                "case_id": case_id,
                "thread_id": thread_id,
                "session_id": session_id,
                "publication_scope": normalized_lifecycle if normalized_lifecycle in {"accepted", "published"} else "working",
            },
            "case_scope": {
                "case_id": case_id,
            },
            "thread_context": {
                "thread_id": thread_id,
            },
            "investigation_plan": investigation_plan,
            "deterministic_decision": deterministic_decision,
            "reasoning_status": reasoning_state.get("status") if isinstance(reasoning_state, dict) else None,
            "root_cause_assessment": root_cause_assessment,
            "hypotheses": hypotheses[:6] if isinstance(hypotheses, list) else [],
            "accepted_facts": list(accepted_facts or [])[-12:],
            "unresolved_questions": list(unresolved_questions or [])[:12],
            "entity_summary": entity_summary,
            "entity_relationships": entity_summary.get("relationships", []) if isinstance(entity_summary, dict) else [],
            "evidence_timeline": evidence_summary.get("timeline", []) if isinstance(evidence_summary, dict) else [],
            "evidence_edges": evidence_summary.get("edges", []) if isinstance(evidence_summary, dict) else [],
            "checkpoint_metrics": dict(checkpoint_metrics or {}),
            "checkpoint_summary": dict(checkpoint_summary or {}),
        }
        publication_ready = normalized_lifecycle in {"accepted", "published"}
        root_cause_ready = publication_ready and isinstance(root_cause_assessment, dict) and bool(
            root_cause_assessment.get("primary_root_cause")
        )
        payload["checkpoint_contract"] = {
            "case_memory_scope": normalized_lifecycle if publication_ready else None,
            "case_memory_publication_ready": publication_ready,
            "root_cause_solidification_ready": root_cause_ready,
            "accepted_fact_solidification_ready": publication_ready,
            "thread_publication_allowed": publication_ready and bool(thread_id),
            "cross_thread_publication_blocked": not publication_ready,
        }
        if publication_ready:
            accepted_memory = {
                "case_id": case_id,
                "thread_id": thread_id,
                "memory_boundary": dict(payload["memory_boundary"]),
                "case_scope": {"case_id": case_id},
                "thread_context": {"thread_id": thread_id},
                "investigation_plan": investigation_plan,
                "deterministic_decision": deterministic_decision,
                "reasoning_state": reasoning_state,
                "root_cause_assessment": root_cause_assessment,
                "accepted_facts": list(accepted_facts or [])[-12:],
                "unresolved_questions": list(unresolved_questions or [])[:12],
                "entity_summary": entity_summary,
                "entity_relationships": entity_summary.get("relationships", []) if isinstance(entity_summary, dict) else [],
                "evidence_timeline": evidence_summary.get("timeline", []) if isinstance(evidence_summary, dict) else [],
                "evidence_edges": evidence_summary.get("edges", []) if isinstance(evidence_summary, dict) else [],
                "checkpoint_metrics": dict(checkpoint_metrics or {}),
                "checkpoint_summary": dict(checkpoint_summary or {}),
            }
            payload["accepted_memory"] = accepted_memory
            payload["memory"] = {"accepted": accepted_memory}
            if normalized_lifecycle == "published":
                payload["memory"]["published"] = accepted_memory

        self.case_store.add_event(
            case_id,
            event_type="agentic_reasoning_checkpoint",
            title="Agentic reasoning checkpoint recorded",
            payload=payload,
        )
        if root_cause_ready:
            self.case_store.add_event(
                case_id,
                event_type="root_cause_assessment",
                title=root_cause_assessment.get("summary") or "Root cause assessment updated",
                payload=payload,
            )

    def get_case_memory(self, case_id: str) -> Optional[Dict[str, Any]]:
        if self.case_store is None or self.agent_store is None or not case_id:
            return None

        case_payload = self.case_store.get_case(case_id)
        if not isinstance(case_payload, dict):
            return None

        selected_session = self._select_authoritative_session(case_payload)
        metadata = selected_session.get("metadata", {}) if isinstance(selected_session, dict) else {}
        if not isinstance(metadata, dict):
            metadata = {}

        payload, memory_scope = self._accepted_memory_payload(metadata)
        root_cause = payload.get("root_cause_assessment", {})
        if not isinstance(root_cause, dict) or not root_cause:
            root_cause = metadata.get("root_cause_assessment", {})
        if not isinstance(root_cause, dict) or not root_cause:
            root_cause = self._latest_root_cause_event(case_payload)

        entity_state = payload.get("entity_state", metadata.get("entity_state", {}))
        if not entity_state and isinstance(payload.get("entity_summary"), dict):
            entity_state = payload.get("entity_summary", {})
        evidence_state = payload.get("evidence_state", metadata.get("evidence_state", {}))
        if not evidence_state:
            evidence_timeline = payload.get("evidence_timeline")
            evidence_edges = payload.get("evidence_edges")
            if evidence_timeline is not None or evidence_edges is not None:
                evidence_state = {
                    "timeline": list(evidence_timeline or []),
                    "edges": list(evidence_edges or []),
                }

        authoritative_snapshot = {
            "investigation_plan": payload.get("investigation_plan", metadata.get("investigation_plan", {})),
            "reasoning_state": payload.get("reasoning_state", metadata.get("reasoning_state", {})),
            "entity_state": entity_state,
            "evidence_state": evidence_state,
            "deterministic_decision": payload.get("deterministic_decision", metadata.get("deterministic_decision", {})),
            "agentic_explanation": payload.get("agentic_explanation", metadata.get("agentic_explanation", {})),
            "root_cause_assessment": root_cause or {},
            "active_observations": payload.get(
                "active_observations",
                metadata.get("active_observations", metadata.get("normalized_observations", [])),
            ),
            "accepted_facts": payload.get("accepted_facts", metadata.get("accepted_facts", [])),
            "unresolved_questions": payload.get("unresolved_questions", metadata.get("unresolved_questions", [])),
            "evidence_quality_summary": payload.get(
                "evidence_quality_summary",
                metadata.get("evidence_quality_summary", {}),
            ),
        }
        summary = ""
        if isinstance(root_cause, dict):
            summary = str(root_cause.get("summary") or "").strip()
        if not summary:
            summary = str(selected_session.get("summary") or "").strip() if isinstance(selected_session, dict) else ""

        return {
            "case_id": case_id,
            "latest_session_id": selected_session.get("id") if isinstance(selected_session, dict) else None,
            "thread_id": metadata.get("thread_id"),
            "summary": summary,
            "authoritative_snapshot": authoritative_snapshot,
            "accepted_snapshot": authoritative_snapshot,
            "memory_scope": memory_scope,
            "memory_boundary": {
                "case_id": case_id,
                "thread_id": metadata.get("thread_id"),
                "session_id": selected_session.get("id") if isinstance(selected_session, dict) else None,
                "publication_scope": memory_scope or "legacy",
            },
        }

    @staticmethod
    def _accepted_memory_payload(metadata: Dict[str, Any]) -> tuple[Dict[str, Any], Optional[str]]:
        if not isinstance(metadata, dict):
            return {}, None

        memory = metadata.get("memory", {})
        if isinstance(memory, dict):
            published = memory.get("published", {})
            if isinstance(published, dict) and published:
                return published, "published"
            accepted = memory.get("accepted", {})
            if isinstance(accepted, dict) and accepted:
                return accepted, "accepted"

        snapshot_lifecycle = str(
            metadata.get("snapshot_lifecycle")
            or (
                metadata.get("snapshot_contract", {}).get("lifecycle")
                if isinstance(metadata.get("snapshot_contract"), dict)
                else ""
            )
            or ""
        ).strip().lower()

        accepted_memory = metadata.get("accepted_memory", {})
        if snapshot_lifecycle in {"published", "accepted"} and isinstance(accepted_memory, dict) and accepted_memory:
            return accepted_memory, snapshot_lifecycle

        if metadata.get("snapshot_state") == "accepted" and isinstance(accepted_memory, dict) and accepted_memory:
            return accepted_memory, "accepted"

        return metadata, None

    def _select_authoritative_session(self, case_payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        workflows = case_payload.get("workflows", []) if isinstance(case_payload, dict) else []
        sessions: List[Dict[str, Any]] = []
        for workflow in workflows if isinstance(workflows, list) else []:
            if not isinstance(workflow, dict):
                continue
            session_id = str(workflow.get("session_id") or "").strip()
            if not session_id:
                continue
            session = self.agent_store.get_session(session_id)
            if isinstance(session, dict):
                sessions.append(session)
        if not sessions:
            return None

        def _score(session: Dict[str, Any]) -> tuple[int, str]:
            metadata = session.get("metadata", {}) if isinstance(session.get("metadata"), dict) else {}
            payload, memory_scope = self._accepted_memory_payload(metadata)
            timestamp = str(session.get("completed_at") or session.get("created_at") or "")

            if memory_scope == "published":
                return (4, timestamp)
            if memory_scope == "accepted":
                return (3, timestamp)

            root_cause = payload.get("root_cause_assessment", metadata.get("root_cause_assessment", {}))
            if isinstance(root_cause, dict) and str(root_cause.get("primary_root_cause") or "").strip():
                return (2, timestamp)

            accepted = payload.get("accepted_facts", metadata.get("accepted_facts", []))
            if isinstance(accepted, list) and accepted:
                return (1, timestamp)

            return (0, timestamp)

        return sorted(sessions, key=_score, reverse=True)[0]

    @staticmethod
    def _latest_root_cause_event(case_payload: Dict[str, Any]) -> Dict[str, Any]:
        events = case_payload.get("events", []) if isinstance(case_payload, dict) else []
        for event in reversed(events if isinstance(events, list) else []):
            if not isinstance(event, dict):
                continue
            payload = event.get("payload", {})
            if not isinstance(payload, dict):
                continue
            root_cause = payload.get("root_cause_assessment", {})
            if isinstance(root_cause, dict) and str(root_cause.get("primary_root_cause") or "").strip():
                return root_cause
        return {}
