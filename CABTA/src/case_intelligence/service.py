"""Case intelligence: normalized entities, graph building, and timeline reconstruction."""

from __future__ import annotations

import json
import re
from collections import defaultdict
from typing import Any, Dict, Iterable, List, Optional, Tuple

from src.agent.thread_sync_service import ThreadSyncService
from src.utils.ioc_extractor import IOCExtractor
from src.web.normalizer import normalize_job


class CaseIntelligenceService:
    """Build case-centered graph and timeline views from real stored artifacts."""

    def __init__(self, analysis_manager, agent_store, case_store, governance_store=None):
        self.analysis_manager = analysis_manager
        self.agent_store = agent_store
        self.case_store = case_store
        self.governance_store = governance_store

    def build_case_snapshot(self, case_id: str) -> Optional[Dict[str, Any]]:
        case = self.case_store.get_case(case_id)
        if case is None:
            return None

        analyses = []
        for link in case.get("analyses", []):
            job = self.analysis_manager.get_job(link.get("analysis_id"))
            if job:
                normalized = normalize_job(job, mode=None, case_links=[])
                analyses.append({"link": link, "job": normalized})

        workflows = []
        for link in case.get("workflows", []):
            session = self.agent_store.get_session(link.get("session_id"))
            if session:
                steps = self.agent_store.get_steps(link.get("session_id"))
                workflows.append({"link": link, "session": session, "steps": steps})

        approvals = []
        decisions = []
        if self.governance_store is not None:
            approvals = self.governance_store.list_approvals(case_id=case_id, limit=500)
            decisions = self.governance_store.list_ai_decisions(case_id=case_id, limit=500)

        return {
            "case": case,
            "analyses": analyses,
            "workflows": workflows,
            "approvals": approvals,
            "ai_decisions": decisions,
        }

    def build_reasoning_summary(self, case_id: str) -> Optional[Dict[str, Any]]:
        snapshot = self.build_case_snapshot(case_id)
        if snapshot is None:
            return None

        workflow_rows = []
        workflow_meta_by_session: Dict[str, Dict[str, Any]] = {}
        for workflow in snapshot["workflows"]:
            session = workflow["session"]
            meta = session.get("metadata", {}) if isinstance(session.get("metadata"), dict) else {}
            workflow_rows.append({
                "session_id": session.get("id"),
                "workflow_id": workflow["link"].get("workflow_id") or meta.get("workflow_id") or session.get("playbook_id"),
                "status": session.get("status"),
                "created_at": session.get("created_at"),
                "completed_at": session.get("completed_at"),
                "summary": session.get("summary"),
                "reasoning_status": (meta.get("agentic_explanation", {}) or {}).get("reasoning_status"),
                "root_cause_assessment": meta.get("root_cause_assessment", {}),
                "deterministic_decision": meta.get("deterministic_decision", {}),
                "hypothesis_count": len(meta.get("reasoning_state", {}).get("hypotheses", [])) if isinstance(meta.get("reasoning_state"), dict) else 0,
                "entity_count": len(meta.get("entity_state", {}).get("entities", {})) if isinstance(meta.get("entity_state"), dict) else 0,
            })
            workflow_meta_by_session[str(session.get("id"))] = meta

        workflow_rows.sort(
            key=lambda item: item.get("completed_at") or item.get("created_at") or "",
        )

        latest_root_cause: Dict[str, Any] = {}
        latest_root_cause_session_id: Optional[str] = None
        latest_root_cause_payload: Dict[str, Any] = {}
        for event in reversed(snapshot["case"].get("events", [])):
            payload = event.get("payload", {}) if isinstance(event.get("payload"), dict) else {}
            candidate = payload.get("root_cause_assessment", {}) if isinstance(payload, dict) else {}
            if isinstance(candidate, dict) and candidate.get("primary_root_cause"):
                latest_root_cause = candidate
                latest_root_cause_session_id = payload.get("session_id")
                latest_root_cause_payload = payload
                break

        selected_workflow = None
        if latest_root_cause_session_id:
            for workflow in reversed(workflow_rows):
                if workflow.get("session_id") == latest_root_cause_session_id:
                    selected_workflow = workflow
                    break
        if selected_workflow is None:
            for workflow in reversed(workflow_rows):
                if workflow.get("root_cause_assessment") or workflow.get("deterministic_decision") or workflow.get("hypothesis_count") or workflow.get("entity_count"):
                    selected_workflow = workflow
                    break
        if selected_workflow is None:
            selected_workflow = workflow_rows[-1] if workflow_rows else None

        latest_meta: Dict[str, Any] = {}
        if selected_workflow is not None:
            latest_meta = workflow_meta_by_session.get(str(selected_workflow.get("session_id")), {})

        graph = self.build_graph(case_id) or {"node_count": 0, "edge_count": 0, "nodes": [], "edges": []}
        timeline = self.build_timeline(case_id) or {"event_count": 0, "events": []}

        root_cause_assessment = latest_meta.get("root_cause_assessment", {}) if isinstance(latest_meta, dict) else {}
        if not root_cause_assessment and latest_root_cause:
            root_cause_assessment = latest_root_cause

        reasoning_truth_source = "selected_workflow_metadata"
        if latest_root_cause and latest_root_cause_session_id and (
            not selected_workflow or str(selected_workflow.get("session_id") or "") != str(latest_root_cause_session_id)
        ):
            reasoning_truth_source = "case_event_root_cause_checkpoint"

        contract_source = dict(latest_meta) if isinstance(latest_meta, dict) else {}
        selected_session_id = str(selected_workflow.get("session_id") or "") if selected_workflow else ""
        if latest_root_cause_payload and latest_root_cause_session_id and (
            reasoning_truth_source == "case_event_root_cause_checkpoint"
            or selected_session_id == str(latest_root_cause_session_id)
        ):
            contract_source.update(latest_root_cause_payload)

        memory_contract = ThreadSyncService.resolve_session_memory_contract(
            contract_source,
            snapshot=contract_source,
            default_publication_scope="working",
        )
        if latest_root_cause_payload and memory_contract["memory_scope"] == "working":
            fallback_thread_id = (
                memory_contract["memory_boundary"].get("thread_id")
                or contract_source.get("thread_id")
                or latest_root_cause_payload.get("thread_id")
                or latest_root_cause_payload.get("thread_context", {}).get("thread_id")
                or latest_root_cause_payload.get("memory_boundary", {}).get("thread_id")
            )
            memory_contract = ThreadSyncService.resolve_memory_contract(
                {
                    "memory_scope": latest_root_cause_payload.get("publication_scope") or latest_root_cause_payload.get("memory_scope"),
                    "authoritative_memory_scope": latest_root_cause_payload.get("authoritative_memory_scope"),
                    "publication_scope": latest_root_cause_payload.get("publication_scope"),
                    "memory_kind": latest_root_cause_payload.get("memory_kind"),
                    "memory_is_authoritative": latest_root_cause_payload.get("memory_is_authoritative"),
                    "memory_boundary": {
                        key: value
                        for key, value in {
                            "case_id": snapshot["case"].get("id"),
                            "thread_id": fallback_thread_id,
                            "session_id": latest_root_cause_session_id,
                            **(
                                latest_root_cause_payload.get("memory_boundary")
                                if isinstance(latest_root_cause_payload.get("memory_boundary"), dict)
                                else {}
                            ),
                        }.items()
                        if value is not None and str(value).strip()
                    },
                },
                default_publication_scope="working",
            )

        resolved_thread_id = (
            memory_contract["memory_boundary"].get("thread_id")
            or (latest_meta.get("thread_id") if isinstance(latest_meta, dict) else None)
        )

        return {
            "case_id": case_id,
            "latest_session_id": selected_workflow.get("session_id") if selected_workflow else None,
            "latest_workflow_id": selected_workflow.get("workflow_id") if selected_workflow else None,
            "thread_id": resolved_thread_id,
            "investigation_plan": latest_meta.get("investigation_plan", {}) if isinstance(latest_meta, dict) else {},
            "deterministic_decision": latest_meta.get("deterministic_decision", {}) if isinstance(latest_meta, dict) else {},
            "agentic_explanation": latest_meta.get("agentic_explanation", {}) if isinstance(latest_meta, dict) else {},
            "reasoning_state": latest_meta.get("reasoning_state", {}) if isinstance(latest_meta, dict) else {},
            "entity_state": latest_meta.get("entity_state", {}) if isinstance(latest_meta, dict) else {},
            "evidence_state": latest_meta.get("evidence_state", {}) if isinstance(latest_meta, dict) else {},
            "active_observations": latest_meta.get("active_observations", []) if isinstance(latest_meta, dict) else [],
            "accepted_facts": latest_meta.get("accepted_facts", []) if isinstance(latest_meta, dict) else [],
            "unresolved_questions": latest_meta.get("unresolved_questions", []) if isinstance(latest_meta, dict) else [],
            "evidence_quality_summary": latest_meta.get("evidence_quality_summary", {}) if isinstance(latest_meta, dict) else {},
            "reasoning_truth": {
                "source": reasoning_truth_source,
                "selected_session_matches_root_cause_checkpoint": bool(
                    selected_workflow
                    and latest_root_cause_session_id
                    and str(selected_workflow.get("session_id") or "") == str(latest_root_cause_session_id)
                ),
                "root_cause_checkpoint_session_id": latest_root_cause_session_id,
                "memory_scope": memory_contract["memory_scope"],
                "memory_kind": memory_contract["memory_kind"],
                "publication_scope": memory_contract["publication_scope"],
                "authoritative_memory_scope": memory_contract["authoritative_memory_scope"],
                "memory_is_authoritative": memory_contract["memory_is_authoritative"],
                "memory_boundary": memory_contract["memory_boundary"],
            },
            "memory_kind": memory_contract["memory_kind"],
            "memory_is_authoritative": memory_contract["memory_is_authoritative"],
            "publication_scope": memory_contract["publication_scope"],
            "authoritative_memory_scope": memory_contract["authoritative_memory_scope"],
            "memory_boundary": memory_contract["memory_boundary"],
            "memory_scope": memory_contract["memory_scope"],
            "root_cause_assessment": root_cause_assessment,
            "workflow_sessions": workflow_rows,
            "graph_summary": {
                "node_count": graph.get("node_count", 0),
                "edge_count": graph.get("edge_count", 0),
                "nodes": graph.get("nodes", [])[:24],
                "edges": graph.get("edges", [])[:32],
            },
            "timeline_summary": {
                "event_count": timeline.get("event_count", 0),
                "events": timeline.get("events", [])[-18:],
            },
        }

    def build_graph(self, case_id: str) -> Optional[Dict[str, Any]]:
        snapshot = self.build_case_snapshot(case_id)
        if snapshot is None:
            return None

        nodes: Dict[str, Dict[str, Any]] = {}
        edges: List[Dict[str, Any]] = []

        def _node_id(kind: str, value: str) -> str:
            return f"{kind}:{value}".lower()

        def _ensure_node(kind: str, value: str, label: Optional[str] = None, **extra: Any) -> str:
            node_key = _node_id(kind, value)
            nodes.setdefault(
                node_key,
                {
                    "id": node_key,
                    "type": kind,
                    "value": value,
                    "label": label or value,
                    **extra,
                },
            )
            return node_key

        def _add_edge(source: str, target: str, relation: str, **extra: Any) -> None:
            edges.append(
                {
                    "source": source,
                    "target": target,
                    "relation": relation,
                    **extra,
                }
            )

        case = snapshot["case"]
        case_node = _ensure_node("case", case["id"], case.get("title", case["id"]), severity=case.get("severity"))

        for event in case.get("events", []):
            event_payload = event.get("payload", {}) if isinstance(event.get("payload"), dict) else {}
            event_node = _ensure_node(
                "case_event",
                event["id"],
                event.get("title", event["id"]),
                event_type=event.get("event_type"),
            )
            _add_edge(case_node, event_node, "contains_event", created_at=event.get("created_at"))
            for entity in self._extract_entities(event_payload):
                entity_node = _ensure_node(entity["type"], entity["value"], entity["label"])
                _add_edge(event_node, entity_node, "references")
            root_cause = event_payload.get("root_cause_assessment", {}) if isinstance(event_payload, dict) else {}
            if isinstance(root_cause, dict) and root_cause.get("primary_root_cause"):
                root_node = _ensure_node(
                    "root_cause",
                    f"{event['id']}:root_cause",
                    root_cause.get("primary_root_cause"),
                    status=root_cause.get("status"),
                    confidence=root_cause.get("confidence"),
                )
                _add_edge(event_node, root_node, "assesses")
            for hypothesis in event_payload.get("hypotheses", []) if isinstance(event_payload, dict) else []:
                if not isinstance(hypothesis, dict):
                    continue
                hypothesis_node = _ensure_node(
                    "hypothesis",
                    str(hypothesis.get("id") or hypothesis.get("statement") or event["id"]),
                    hypothesis.get("statement", "Hypothesis"),
                    status=hypothesis.get("status"),
                    confidence=hypothesis.get("confidence"),
                )
                _add_edge(event_node, hypothesis_node, "tracks")
            for relationship in event_payload.get("entity_relationships", []) if isinstance(event_payload, dict) else []:
                if not isinstance(relationship, dict):
                    continue
                source_id = relationship.get("source")
                target_id = relationship.get("target")
                if source_id:
                    source_kind, _, source_value = str(source_id).partition(":")
                    source_node = _ensure_node(
                        source_kind or "entity",
                        source_value or str(source_id),
                        source_value or str(source_id),
                    )
                else:
                    source_node = None
                if target_id:
                    target_kind, _, target_value = str(target_id).partition(":")
                    target_node = _ensure_node(
                        target_kind or "entity",
                        target_value or str(target_id),
                        target_value or str(target_id),
                    )
                else:
                    target_node = None
                if source_node and target_node:
                    _add_edge(source_node, target_node, relationship.get("relation", "linked_to"))

        for analysis in snapshot["analyses"]:
            job = analysis["job"]
            analysis_node = _ensure_node(
                "analysis",
                job["job_id"],
                job.get("target") or job["job_id"],
                job_type=job.get("job_type"),
                verdict=job.get("verdict"),
            )
            _add_edge(case_node, analysis_node, "contains_analysis", linked_at=analysis["link"].get("linked_at"))
            for entity in self._extract_entities(job):
                entity_node = _ensure_node(entity["type"], entity["value"], entity["label"])
                _add_edge(analysis_node, entity_node, "observed")

        for workflow in snapshot["workflows"]:
            session = workflow["session"]
            meta = session.get("metadata", {}) if isinstance(session.get("metadata"), dict) else {}
            workflow_id = workflow["link"].get("workflow_id") or meta.get("workflow_id") or session.get("playbook_id") or session["id"]
            workflow_node = _ensure_node(
                "workflow_run",
                session["id"],
                workflow_id,
                status=session.get("status"),
            )
            _add_edge(case_node, workflow_node, "contains_workflow", linked_at=workflow["link"].get("linked_at"))
            for entity in self._extract_entities(session):
                entity_node = _ensure_node(entity["type"], entity["value"], entity["label"])
                _add_edge(workflow_node, entity_node, "referenced")
            root_cause = meta.get("root_cause_assessment", {}) if isinstance(meta, dict) else {}
            if isinstance(root_cause, dict) and root_cause.get("primary_root_cause"):
                root_node = _ensure_node(
                    "root_cause",
                    f"{session['id']}:root_cause",
                    root_cause.get("primary_root_cause"),
                    status=root_cause.get("status"),
                    confidence=root_cause.get("confidence"),
                )
                _add_edge(workflow_node, root_node, "assesses")
            for hypothesis in meta.get("reasoning_state", {}).get("hypotheses", []) if isinstance(meta.get("reasoning_state"), dict) else []:
                if not isinstance(hypothesis, dict):
                    continue
                hypothesis_node = _ensure_node(
                    "hypothesis",
                    hypothesis.get("id", session["id"]),
                    hypothesis.get("statement", "Hypothesis"),
                    status=hypothesis.get("status"),
                    confidence=hypothesis.get("confidence"),
                )
                _add_edge(workflow_node, hypothesis_node, "tracks")
            entity_state = meta.get("entity_state", {}) if isinstance(meta, dict) else {}
            if isinstance(entity_state, dict):
                for entity_payload in entity_state.get("entities", {}).values() if isinstance(entity_state.get("entities"), dict) else []:
                    if not isinstance(entity_payload, dict):
                        continue
                    entity_node = _ensure_node(
                        entity_payload.get("type", "entity"),
                        entity_payload.get("value", entity_payload.get("id", "entity")),
                        entity_payload.get("label") or entity_payload.get("value") or entity_payload.get("id", "entity"),
                    )
                    _add_edge(workflow_node, entity_node, "normalized_entity")
                for relationship in entity_state.get("relationships", []) if isinstance(entity_state.get("relationships"), list) else []:
                    if not isinstance(relationship, dict):
                        continue
                    source = relationship.get("source")
                    target = relationship.get("target")
                    if not source or not target:
                        continue
                    source_kind, _, source_value = str(source).partition(":")
                    target_kind, _, target_value = str(target).partition(":")
                    source_node = _ensure_node(source_kind or "entity", source_value or str(source), source_value or str(source))
                    target_node = _ensure_node(target_kind or "entity", target_value or str(target), target_value or str(target))
                    _add_edge(source_node, target_node, relationship.get("relation", "linked_to"))

        for approval in snapshot["approvals"]:
            approval_node = _ensure_node(
                "approval",
                approval["id"],
                approval.get("action_type", approval["id"]),
                status=approval.get("status"),
            )
            _add_edge(case_node, approval_node, "contains_approval")
            for entity in self._extract_entities(approval.get("target", {})):
                entity_node = _ensure_node(entity["type"], entity["value"], entity["label"])
                _add_edge(approval_node, entity_node, "targets")

        for decision in snapshot["ai_decisions"]:
            decision_node = _ensure_node(
                "ai_decision",
                decision["id"],
                decision.get("decision_type", decision["id"]),
                profile_id=decision.get("profile_id"),
            )
            _add_edge(case_node, decision_node, "contains_decision")
            for entity in self._extract_entities(decision):
                entity_node = _ensure_node(entity["type"], entity["value"], entity["label"])
                _add_edge(decision_node, entity_node, "references")

        return {
            "case_id": case_id,
            "node_count": len(nodes),
            "edge_count": len(edges),
            "nodes": list(nodes.values()),
            "edges": edges,
        }

    def build_timeline(self, case_id: str) -> Optional[Dict[str, Any]]:
        snapshot = self.build_case_snapshot(case_id)
        if snapshot is None:
            return None

        case = snapshot["case"]
        events: List[Dict[str, Any]] = []
        for case_event in case.get("events", []):
            payload = case_event.get("payload", {}) if isinstance(case_event.get("payload"), dict) else {}
            events.append({
                "id": case_event.get("id"),
                "type": case_event.get("event_type"),
                "title": case_event.get("title"),
                "timestamp": case_event.get("created_at"),
                "source": "case_event",
                "payload": payload,
            })

        for analysis in snapshot["analyses"]:
            job = analysis["job"]
            events.append({
                "type": "analysis_linked",
                "title": f"Analysis linked: {job.get('target') or job['job_id']}",
                "timestamp": analysis["link"].get("linked_at"),
                "source": "analysis",
                "job_id": job["job_id"],
                "verdict": job.get("verdict"),
                "score": job.get("score"),
            })
            if job.get("started_at"):
                events.append({
                    "type": "analysis_started",
                    "title": f"{job.get('job_type', 'analysis').upper()} started",
                    "timestamp": job.get("started_at"),
                    "source": "analysis",
                    "job_id": job["job_id"],
                    "status": job.get("status"),
                })
            if job.get("completed_at"):
                events.append({
                    "type": "analysis_completed",
                    "title": f"{job.get('job_type', 'analysis').upper()} completed",
                    "timestamp": job.get("completed_at"),
                    "source": "analysis",
                    "job_id": job["job_id"],
                    "verdict": job.get("verdict"),
                    "score": job.get("score"),
                })

        for workflow in snapshot["workflows"]:
            session = workflow["session"]
            meta = session.get("metadata", {}) if isinstance(session.get("metadata"), dict) else {}
            workflow_name = workflow["link"].get("workflow_id") or meta.get("workflow_id") or session.get("playbook_id") or session["id"]
            events.append({
                "type": "workflow_linked",
                "title": f"Workflow linked: {workflow_name}",
                "timestamp": workflow["link"].get("linked_at"),
                "source": "workflow",
                "session_id": session["id"],
                "status": session.get("status"),
            })
            events.append({
                "type": "workflow_started",
                "title": f"Workflow started: {workflow_name}",
                "timestamp": session.get("created_at"),
                "source": "workflow",
                "session_id": session["id"],
                "status": session.get("status"),
            })
            if session.get("completed_at"):
                events.append({
                    "type": "workflow_completed",
                    "title": f"Workflow completed: {workflow_name}",
                    "timestamp": session.get("completed_at"),
                    "source": "workflow",
                    "session_id": session["id"],
                    "status": session.get("status"),
                    "summary": session.get("summary"),
                })
            for step in workflow["steps"]:
                events.append({
                    "type": f"workflow_step_{step.get('step_type', 'step')}",
                    "title": step.get("content")[:140],
                    "timestamp": step.get("created_at"),
                    "source": "workflow_step",
                    "session_id": session["id"],
                    "tool_name": step.get("tool_name"),
                    "step_number": step.get("step_number"),
                })
            root_cause = meta.get("root_cause_assessment", {}) if isinstance(meta, dict) else {}
            if isinstance(root_cause, dict) and root_cause.get("primary_root_cause"):
                events.append({
                    "type": "workflow_root_cause_assessed",
                    "title": root_cause.get("summary") or "Root cause assessment updated",
                    "timestamp": root_cause.get("assessed_at") or session.get("completed_at") or session.get("created_at"),
                    "source": "workflow_reasoning",
                    "session_id": session["id"],
                    "status": root_cause.get("status"),
                    "confidence": root_cause.get("confidence"),
                })
            evidence_state = meta.get("evidence_state", {}) if isinstance(meta, dict) else {}
            if isinstance(evidence_state, dict):
                for event in evidence_state.get("timeline", []) if isinstance(evidence_state.get("timeline"), list) else []:
                    if not isinstance(event, dict):
                        continue
                    events.append({
                        "type": f"workflow_{event.get('type', 'observation')}",
                        "title": event.get("title", "Workflow observation"),
                        "timestamp": event.get("timestamp"),
                        "source": "workflow_reasoning",
                        "session_id": session["id"],
                        "summary": event.get("summary"),
                        "tool_name": event.get("tool_name"),
                    })

        for approval in snapshot["approvals"]:
            events.append({
                "type": f"approval_{approval.get('status')}",
                "title": f"Approval {approval.get('status')}: {approval.get('tool_name')}",
                "timestamp": approval.get("reviewed_at") or approval.get("requested_at"),
                "source": "approval",
                "approval_id": approval.get("id"),
                "tool_name": approval.get("tool_name"),
                "status": approval.get("status"),
            })

        for decision in snapshot["ai_decisions"]:
            events.append({
                "type": "ai_decision",
                "title": decision.get("summary", "")[:140],
                "timestamp": decision.get("created_at"),
                "source": "ai_decision",
                "decision_id": decision.get("id"),
                "decision_type": decision.get("decision_type"),
                "profile_id": decision.get("profile_id"),
            })

        events = [event for event in events if event.get("timestamp")]
        events.sort(key=lambda item: item.get("timestamp") or "")

        return {
            "case_id": case_id,
            "event_count": len(events),
            "events": events,
        }

    def _extract_entities(self, value: Any) -> List[Dict[str, str]]:
        """Extract a normalized entity list from a nested structure."""
        text = self._stringify(value)
        extracted = IOCExtractor.extract_all(text)
        entities: List[Tuple[str, str]] = []

        for ip in extracted.get("ipv4", []):
            entities.append(("ip", ip))
        for ip in extracted.get("ipv6", []):
            entities.append(("ip", ip))
        for domain in extracted.get("domains", []):
            entities.append(("domain", domain))
        for url in extracted.get("urls", []):
            entities.append(("url", url))
        for email in extracted.get("emails", []):
            entities.append(("email", email))
        hashes = extracted.get("hashes", {}) if isinstance(extracted.get("hashes"), dict) else {}
        for bucket in ("md5", "sha1", "sha256"):
            for hash_value in hashes.get(bucket, []):
                entities.append(("hash", hash_value))

        for cve in re.findall(r"\bCVE-\d{4}-\d{4,7}\b", text, flags=re.IGNORECASE):
            entities.append(("cve", cve.upper()))
        for hostname in re.findall(r"\b(?:host|hostname|device|system)[\"'=:\s]+([A-Za-z0-9._-]{3,})", text, flags=re.IGNORECASE):
            entities.append(("host", hostname))
        for filename in re.findall(r"\b[A-Za-z0-9._-]+\.(?:exe|dll|docm|zip|pdf|js|ps1|eml)\b", text, flags=re.IGNORECASE):
            entities.append(("file", filename))

        deduped: Dict[Tuple[str, str], Dict[str, str]] = {}
        for kind, entity_value in entities:
            key = (kind, entity_value)
            deduped[key] = {
                "type": kind,
                "value": entity_value,
                "label": entity_value,
            }
        return list(deduped.values())

    @staticmethod
    def _stringify(value: Any) -> str:
        if value is None:
            return ""
        if isinstance(value, str):
            return value
        try:
            return json.dumps(value, default=str)
        except Exception:
            return str(value)
