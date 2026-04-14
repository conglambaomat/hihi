"""Capability catalog for the AISA orchestration and analysis surface."""

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
        }

    def build_catalog(self, app: Any) -> Dict[str, Any]:
        tool_registry = getattr(app.state, "tool_registry", None)
        tools = tool_registry.list_tools() if tool_registry else []
        tools_payload = [tool.to_dict() for tool in tools]

        source_counts = Counter(tool.get("source", "unknown") for tool in tools_payload)
        category_counts = Counter(tool.get("category", "unknown") for tool in tools_payload)

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
            name for name, meta in (mcp_status or {}).items()
            if meta.get("connected")
        ]

        return {
            "verdict_authority": dict(VERDICT_AUTHORITY),
            "analysis_core": {
                "ioc_investigator": bool(getattr(app.state, "ioc_investigator", None)),
                "malware_analyzer": bool(getattr(app.state, "malware_analyzer", None)),
                "email_analyzer": bool(getattr(app.state, "email_analyzer", None)),
                "tool_registry": bool(tool_registry),
                "case_store": bool(getattr(app.state, "case_store", None)),
                "analysis_manager": bool(getattr(app.state, "analysis_manager", None)),
            },
            "tools": {
                "total": len(tools_payload),
                "local": int(source_counts.get("local", 0)),
                "mcp": max(len(tools_payload) - int(source_counts.get("local", 0)), 0),
                "by_source": dict(source_counts),
                "by_category": dict(category_counts),
                "items": tools_payload,
            },
            "agent_profiles": {
                "count": len(profile_items),
                "items": profile_items,
            },
            "workflows": {
                "count": len(workflow_items),
                "items": workflow_items,
            },
            "playbooks": {
                "count": len(playbook_items),
                "items": playbook_items,
            },
            "mcp": {
                "configured": len(mcp_status or {}),
                "connected": len(connected_servers),
                "connected_servers": connected_servers,
            },
            "orchestration_plane": {
                "profiles_ready": bool(profile_items),
                "workflows_ready": bool(workflow_items),
                "workflow_service_ready": bool(workflow_service),
                "playbooks_ready": bool(playbook_items),
                "approval_supported": bool(getattr(app.state, "playbook_engine", None))
                or bool(getattr(app.state, "agent_loop", None)),
                "decision_logging": bool(governance_store),
                "headless_soc_ready": bool(daemon),
            },
        }
