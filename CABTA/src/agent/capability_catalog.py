"""Capability catalog for the CABTA orchestration and analysis surface."""

from __future__ import annotations

from collections import Counter
from typing import Any, Dict, List


VERDICT_AUTHORITY = {
    "owner": "cabta_scoring",
    "display_name": "CABTA Scoring and Evidence Path",
    "description": (
        "Deterministic scoring, evidence correlation, and analyst-visible findings "
        "own the final verdict. Agent roles, workflows, MCP integrations, and LLMs "
        "may guide or summarize, but they cannot override this boundary."
    ),
    "agent_can_override": False,
    "workflow_can_override": False,
    "llm_can_override": False,
}


class CapabilityCatalog:
    """Build a machine-readable view of current platform capability."""

    @staticmethod
    def _readiness_label(*, available: bool, configured: bool = True, optional: bool = False) -> str:
        if available:
            return "ready"
        if configured:
            return "optional" if optional else "degraded"
        return "not_configured"

    @staticmethod
    def _empty_governance_summary() -> Dict[str, Any]:
        return {
            "scope": {
                "session_id": None,
                "case_id": None,
            },
            "approvals": {
                "total": 0,
                "by_status": {},
                "pending": 0,
            },
            "ai_decisions": {
                "total": 0,
                "by_type": {},
            },
            "decision_feedback": {
                "total": 0,
                "by_type": {},
                "by_verdict": {},
            },
        }

    def build_summary(self, app: Any) -> Dict[str, Any]:
        catalog = self.build_catalog(app)
        return {
            "verdict_authority_owner": catalog["verdict_authority"]["owner"],
            "tool_count": catalog["tools"]["total"],
            "local_tool_count": catalog["tools"]["local"],
            "mcp_tool_count": catalog["tools"]["mcp"],
            "agent_profile_count": catalog["agent_profiles"]["count"],
            "workflow_count": catalog["workflows"]["count"],
            "playbook_count": catalog["playbooks"]["count"],
            "approval_supported": catalog["orchestration_plane"]["approval_supported"],
            "headless_soc_ready": catalog["orchestration_plane"]["headless_soc_ready"],
            "decision_logging": catalog["orchestration_plane"]["decision_logging"],
            "analysis_core_ready": catalog["analysis_core"]["readiness"]["status"] == "ready",
            "mcp_ready": catalog["mcp"]["readiness"]["status"] == "ready",
            "daemon_runtime_status": catalog["orchestration_plane"]["daemon_runtime"]["status"],
        }

    def build_catalog(self, app: Any) -> Dict[str, Any]:
        tool_registry = getattr(app.state, "tool_registry", None)
        tools = tool_registry.list_tools() if tool_registry else []
        tools_payload = [tool.to_dict() for tool in tools]

        source_counts = Counter(tool.get("source", "unknown") for tool in tools_payload)
        category_counts = Counter(tool.get("category", "unknown") for tool in tools_payload)

        local_tool_count = int(source_counts.get("local", 0))
        mcp_tool_count = max(len(tools_payload) - local_tool_count, 0)

        agent_profiles = getattr(app.state, "agent_profiles", None)
        workflow_registry = getattr(app.state, "workflow_registry", None)
        workflow_service = getattr(app.state, "workflow_service", None)
        playbook_engine = getattr(app.state, "playbook_engine", None)
        mcp_client = getattr(app.state, "mcp_client", None)
        governance_store = getattr(app.state, "governance_store", None)
        daemon = getattr(app.state, "headless_soc_daemon", None)

        profile_items: List[Dict[str, Any]] = (
            agent_profiles.list_profiles() if agent_profiles else []
        )
        workflow_items: List[Dict[str, Any]] = (
            workflow_registry.list_workflows() if workflow_registry else []
        )
        playbook_items: List[Dict[str, Any]] = (
            playbook_engine.list_playbooks() if playbook_engine else []
        )

        mcp_status = mcp_client.get_connection_status() if mcp_client else {}
        connected_servers = [
            name
            for name, meta in (mcp_status or {}).items()
            if isinstance(meta, dict) and meta.get("connected")
        ]
        disconnected_servers = [
            name
            for name, meta in (mcp_status or {}).items()
            if not (isinstance(meta, dict) and meta.get("connected"))
        ]

        analysis_core_components = {
            "ioc_investigator": bool(getattr(app.state, "ioc_investigator", None)),
            "malware_analyzer": bool(getattr(app.state, "malware_analyzer", None)),
            "email_analyzer": bool(getattr(app.state, "email_analyzer", None)),
            "tool_registry": bool(tool_registry),
            "case_store": bool(getattr(app.state, "case_store", None)),
            "analysis_manager": bool(getattr(app.state, "analysis_manager", None)),
        }
        analysis_core_available = all(analysis_core_components.values())

        daemon_status = daemon.build_status(app) if daemon else {"enabled": False}
        daemon_enabled = bool(daemon_status.get("enabled"))
        daemon_runtime = {
            "enabled": daemon_enabled,
            "status": self._readiness_label(
                available=daemon_enabled,
                configured=bool(daemon),
                optional=True,
            ),
            "runtime_mode": daemon_status.get("runtime_mode", "disabled"),
            "queue_enabled": bool(daemon_status.get("queue_enabled", False)),
            "resumable_jobs": bool(daemon_status.get("resumable_jobs", False)),
            "resumable_job_model": dict(daemon_status.get("resumable_job_model") or {}),
            "bounded_concurrency": dict(daemon_status.get("bounded_concurrency") or {}),
            "lease_policy": dict(daemon_status.get("lease_policy") or {}),
            "migration_path": dict(daemon_status.get("migration_path") or {}),
            "worker_supervision": dict(daemon_status.get("worker_supervision") or {}),
        }
        governance_summary = (
            governance_store.governance_summary()
            if governance_store and hasattr(governance_store, "governance_summary")
            else (self._empty_governance_summary() if governance_store else {})
        )

        workflow_dependency_mode = (
            "validated" if workflow_service and workflow_items else "inventory_only"
        )

        return {
            "verdict_authority": dict(VERDICT_AUTHORITY),
            "analysis_core": {
                **analysis_core_components,
                "readiness": {
                    "status": self._readiness_label(
                        available=analysis_core_available,
                        configured=bool(analysis_core_components),
                    ),
                    "available_components": [
                        name for name, available in analysis_core_components.items() if available
                    ],
                    "missing_components": [
                        name for name, available in analysis_core_components.items() if not available
                    ],
                },
            },
            "tools": {
                "total": len(tools_payload),
                "local": local_tool_count,
                "mcp": mcp_tool_count,
                "by_source": dict(source_counts),
                "by_category": dict(category_counts),
                "truth": {
                    "status": self._readiness_label(
                        available=local_tool_count > 0 or mcp_tool_count > 0,
                        configured=bool(tool_registry),
                    ),
                    "local_available": local_tool_count,
                    "mcp_available": mcp_tool_count,
                    "tool_registry_present": bool(tool_registry),
                },
                "items": tools_payload,
            },
            "agent_profiles": {
                "count": len(profile_items),
                "items": profile_items,
            },
            "workflows": {
                "count": len(workflow_items),
                "dependency_mode": workflow_dependency_mode,
                "truth": {
                    "inventory_present": bool(workflow_registry),
                    "runtime_service_present": bool(workflow_service),
                    "validated_runtime": bool(workflow_items and workflow_service),
                    "workflow_count": len(workflow_items),
                },
                "readiness": {
                    "status": self._readiness_label(
                        available=bool(workflow_items and workflow_service),
                        configured=bool(workflow_registry),
                        optional=True,
                    ),
                    "registry_present": bool(workflow_registry),
                    "service_present": bool(workflow_service),
                },
                "items": workflow_items,
            },
            "playbooks": {
                "count": len(playbook_items),
                "readiness": {
                    "status": self._readiness_label(
                        available=bool(playbook_items),
                        configured=bool(playbook_engine),
                        optional=True,
                    ),
                },
                "items": playbook_items,
            },
            "mcp": {
                "configured": len(mcp_status or {}),
                "connected": len(connected_servers),
                "connected_servers": connected_servers,
                "disconnected_servers": disconnected_servers,
                "truth": {
                    "inventory_present": bool(mcp_status),
                    "configured_servers": len(mcp_status or {}),
                    "connected_servers": len(connected_servers),
                    "disconnected_servers": len(disconnected_servers),
                    "runtime_connected": bool(connected_servers),
                },
                "readiness": {
                    "status": self._readiness_label(
                        available=bool(connected_servers),
                        configured=bool(mcp_status),
                        optional=True,
                    ),
                    "configured_servers": len(mcp_status or {}),
                    "connected_servers": len(connected_servers),
                },
            },
            "orchestration_plane": {
                "profiles_ready": bool(profile_items),
                "workflows_ready": bool(workflow_items),
                "workflow_service_ready": bool(workflow_service),
                "playbooks_ready": bool(playbook_items),
                "approval_supported": bool(getattr(app.state, "playbook_engine", None))
                or bool(getattr(app.state, "agent_loop", None)),
                "decision_logging": bool(governance_store),
                "governance": {
                    "status": self._readiness_label(
                        available=bool(governance_store),
                        configured=bool(governance_store),
                        optional=True,
                    ),
                    "store_present": bool(governance_store),
                    "approval_logging": bool(governance_store),
                    "decision_feedback_logging": bool(governance_store),
                    "summary": governance_summary,
                },
                "headless_soc_ready": bool(daemon),
                "daemon_runtime": daemon_runtime,
                "control_plane": {
                    "status": self._readiness_label(
                        available=bool(profile_items) and bool(tool_registry),
                        configured=True,
                    ),
                    "tool_truth_explicit": True,
                    "workflow_dependency_mode": workflow_dependency_mode,
                    "workflow_truth_explicit": True,
                    "mcp_truth_explicit": True,
                    "daemon_runtime_truth_explicit": True,
                    "governance_truth_explicit": True,
                },
            },
        }
