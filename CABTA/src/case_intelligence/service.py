"""Case intelligence: normalized entities, graph building, and timeline reconstruction."""

from __future__ import annotations

import json
import re
from collections import defaultdict
from typing import Any, Dict, Iterable, List, Optional, Tuple

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
        events.extend(case.get("events", []))

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
